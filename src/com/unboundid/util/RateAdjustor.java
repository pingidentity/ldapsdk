/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright (C) 2014-2021 Ping Identity Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (GPLv2 only)
 * or the terms of the GNU Lesser General Public License (LGPLv2.1 only)
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */
package com.unboundid.util;



import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.DurationArgument;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class allows a FixedRateBarrier to change dynamically.  The rate changes
 * are governed by lines read from a {@code Reader} (typically backed by a
 * file). The input starts with a header that provides some global options and
 * then has a list of lines, where each line contains a single rate per second,
 * a comma, and a duration to maintain that rate.  Rates are specified as an
 * absolute rate per second or as a rate relative to the base rate per second.
 * The duration is an integer followed by a time unit (ms=milliseconds,
 * s=seconds, m=minutes, h=hours, and d=days).
 * <BR><BR>
 * The following simple example will run at a target rate of 1000 per second
 * for one minute, and then 10000 per second for 10 seconds.
 * <pre>
 *   # format=rate-duration
 *   1000,1m
 *   10000,10s
 * </pre>
 * <BR>
 * The following example has a default duration of one minute, and will repeat
 * the two intervals until this RateAdjustor is shut down.  The first interval
 * is run for the default of 1 minute at two and half times the base rate, and
 * then run for 10 seconds at 10000 per second.
 * <pre>
 *   # format=rate-duration
 *   # default-duration=1m
 *   # repeat=true
 *   2.5X
 *   10000,10s
 * </pre>
 * A {@code RateAdjustor} is a daemon thread.  It is necessary to call the
 * {@code start()} method to start the thread and begin the rate changes.
 * Once this finished processing the rates, the thread will complete.
 * It can be stopped prematurely by calling {@code shutDown()}.
 * <BR><BR>
 * The header can contain the following options:
 * <UL>
 *   <LI>{@code format} (required):  This must currently have the value
 *       {@code rate-duration}.</LI>
 *   <LI>{@code default-duration} (optional):  This can specify a default
 *       duration for intervals that do not include a duration.  The format
 *       is an integer followed by a time unit as described above.</LI>
 *   <LI>{@code repeat} (optional):  If this has a value of {@code true}, then
 *       the rates in the input will be repeated until {@code shutDown()} is
 *       called.</LI>
 * </UL>
 */
@ThreadSafety(level = ThreadSafetyLevel.MOSTLY_THREADSAFE)
public final class RateAdjustor extends Thread
{
  /**
   * This starts a comment in the input.
   */
  public static final char COMMENT_START = '#';



  /**
   * The text that must appear on a line by itself in order to denote that the
   * end of the file header has been reached.
   */
  @NotNull public static final String END_HEADER_TEXT = "END HEADER";



  /**
   * The header key that represents the default duration.
   */
  @NotNull public static final String DEFAULT_DURATION_KEY = "default-duration";



  /**
   * The header key that represents the format of the file.
   */
  @NotNull public static final String FORMAT_KEY = "format";



  /**
   * The value of the format key that represents a list of rates and durations
   * within the input file.
   */
  @NotNull public static final String FORMAT_VALUE_RATE_DURATION =
       "rate-and-duration";



  /**
   * A list of all formats that we support.
   */
  @NotNull public static final List<String> FORMATS =
       Collections.singletonList(FORMAT_VALUE_RATE_DURATION);



  /**
   * The header key that represents whether the input should be repeated.
   */
  @NotNull public static final String REPEAT_KEY = "repeat";



  /**
   * A list of all header keys that we support.
   */
  @NotNull public static final List<String> KEYS =
       Arrays.asList(DEFAULT_DURATION_KEY, FORMAT_KEY, REPEAT_KEY);



  // Other headers to consider:
  // * rate-multiplier, so you can easily proportionally increase or decrease
  //   every target rate without changing all the target rates directly.
  // * duration-multiplier, so you can easily proportionally increase or
  //   decrease the length of time to spend at target rates.
  // * rate-change-behavior, so you can specify the behavior that should be
  //   exhibited when transitioning from one rate to another (e.g., instant
  //   jump, linear acceleration, sine-based acceleration, etc.).
  // * jitter, so we can introduce some amount of random jitter in the target
  //   rate (in which the actual target rate may be frequently adjusted to be
  //   slightly higher or lower than the designated target rate).
  // * spike, so we can introduce periodic, substantial increases in the target
  //   rate.



  // The barrier whose rate is adjusted.
  @NotNull private final FixedRateBarrier barrier;

  // A list of rates per second and the number of milliseconds that the
  // specified rate should be maintained.
  @NotNull private final List<ObjectPair<Double,Long>> ratesAndDurations;

  // If this is true, then the ratesAndDurations will be repeated until this is
  // shut down.
  private final boolean repeat;

  // Set to true when this should shut down.
  private volatile boolean shutDown = false;

  // This is used to make sure we set the initial rate before start() returns.
  @NotNull private final CountDownLatch initialRateSetLatch =
       new CountDownLatch(1);

  // This allows us to interrupt when we are sleeping.
  @NotNull private final WakeableSleeper sleeper = new WakeableSleeper();



  /**
   * Returns a new RateAdjustor with the specified parameters.  See the
   * class-level javadoc for more information.
   *
   * @param  barrier            The barrier to update based on the specified
   *                            rates.
   * @param  baseRatePerSecond  The baseline rate per second, or {@code null}
   *                            if none was specified.
   * @param  rates              A file containing a list of rates and durations
   *                            as described in the class-level javadoc.
   *
   * @return  A new RateAdjustor constructed from the specified parameters.
   *
   * @throws  IOException               If there is a problem reading from
   *                                    the rates Reader.
   * @throws  IllegalArgumentException  If there is a problem with the rates
   *                                    input.
   */
  @NotNull()
  public static RateAdjustor newInstance(
                                  @NotNull final FixedRateBarrier barrier,
                                  @Nullable final Integer baseRatePerSecond,
                                  @NotNull final File rates)
         throws IOException, IllegalArgumentException
  {
    final Reader reader = new FileReader(rates);
    return new RateAdjustor(
         barrier,
         (baseRatePerSecond == null) ? 0 : baseRatePerSecond,
         reader);
  }



  /**
   * Retrieves a string that may be used as the description of the argument that
   * specifies the path to a variable rate data file for use in conjunction with
   * this rate adjustor.
   *
   * @param  genArgName  The name of the argument that may be used to generate a
   *                     sample variable rate data file.
   *
   * @return   A string that may be used as the description of the argument that
   *           specifies the path to a variable rate data file for use in
   *           conjunction with this rate adjustor.
   */
  @Nullable()
  public static String getVariableRateDataArgumentDescription(
                            @NotNull final String genArgName)
  {
    return INFO_RATE_ADJUSTOR_VARIABLE_RATE_DATA_ARG_DESCRIPTION.get(
         genArgName);
  }



  /**
   * Retrieves a string that may be used as the description of the argument that
   * generates a sample variable rate data file that serves as documentation of
   * the variable rate data format.
   *
   * @param  dataFileArgName  The name of the argument that specifies the path
   *                          to a file
   *
   * @return   A string that may be used as the description of the argument that
   *           generates a sample variable rate data file that serves as
   *           documentation of the variable rate data format.
   */
  @Nullable()
  public static String getGenerateSampleVariableRateFileDescription(
                            @NotNull final String dataFileArgName)
  {
    return INFO_RATE_ADJUSTOR_GENERATE_SAMPLE_RATE_FILE_ARG_DESCRIPTION.get(
         dataFileArgName);
  }



  /**
   * Writes a sample variable write data file to the specified location.
   *
   * @param  f  The path to the file to be written.
   *
   * @throws  IOException  If a problem is encountered while writing to the
   *                       specified file.
   */
  public static void writeSampleVariableRateFile(@NotNull final File f)
         throws IOException
  {
    final PrintWriter w = new PrintWriter(f);
    try
    {
      w.println("# This is an example variable rate data file.  All blank " +
           "lines will be ignored.");
      w.println("# All lines starting with the '#' character are considered " +
           "comments and will");
      w.println("# also be ignored.");
      w.println();
      w.println("# The beginning of the file must be a header containing " +
           "properties pertaining");
      w.println("# to the variable rate data.  All headers must be in the " +
           "format 'name=value',");
      w.println("# in which any spaces surrounding the equal sign will be " +
           "ignored.");
      w.println();
      w.println("# The first header should be the 'format' header, which " +
           "specifies the format");
      w.println("# for the variable rate data file.  This header is " +
           "required.  At present, the");
      w.println("# only supported format is 'rate-and-duration', although " +
           "additional formats may");
      w.println("# be added in the future.");
      w.println("format = rate-and-duration");
      w.println();
      w.println("# The optional 'default-duration' header may be used to " +
           "specify a duration that");
      w.println("# will be used for any interval that does not explicitly " +
           "specify a duration.");
      w.println("# The duration must consist of a positive integer value " +
           "followed by a time");
      w.println("# unit (with zero or more spaces separating the integer " +
           "value from the unit).");
      w.println("# The supported time units are:");
      w.println("#");
      w.println("# - nanoseconds, nanosecond, nanos, nano, ns");
      w.println("# - microseconds, microseconds, micros, micro, us");
      w.println("# - milliseconds, millisecond, millis, milli, ms");
      w.println("# - seconds, second, secs, sec, s");
      w.println("# - minutes, minute, mins, min, m");
      w.println("# - hours, hour, hrs, hr, h");
      w.println("# - days, day, d");
      w.println("#");
      w.println("# If no 'default-duration' header is present, then every " +
           "data interval must");
      w.println("# include an explicitly-specified duration.");
      w.println("default-duration = 10 seconds");
      w.println();
      w.println("# The optional 'repeat' header may be used to indicate how " +
           "the tool should");
      w.println("# behave once the end of the variable rate data definitions " +
           "has been reached.");
      w.println("# If the 'repeat' header is present with a value of 'true', " +
           "then the tool will");
      w.println("# operate in an endless loop, returning to the beginning of " +
           "the variable rate");
      w.println("# definitions once the end has been reached.  If the " +
           "'repeat' header is present");
      w.println("# with a value of 'false', or if the 'repeat' header is " +
           "absent, then the tool");
      w.println("# will exit after it has processed all of the variable " +
           "rate definitions.");
      w.println("repeat = true");
      w.println();
      w.println("# After all header properties have been specified, the end " +
           "of the header must");
      w.println("# be signified with a line containing only the text 'END " +
           "HEADER'.");
      w.println("END HEADER");
      w.println();
      w.println();
      w.println("# After the header is complete, the variable rate " +
           "definitions should be");
      w.println("# provided.  Each definition should be given on a line by " +
           "itself, and should");
      w.println("# contain a target rate per second and an optional length " +
           "of time to maintain");
      w.println("# that rate.");
      w.println("#");
      w.println("# The target rate must always be present in a variable " +
           "rate definition.  It may");
      w.println("# be either a positive integer value that specifies the " +
           "absolute target rate");
      w.println("# per second (e.g., a value of '1000' indicates a target " +
           "rate of 1000");
      w.println("# operations per second), or it may be a floating-point " +
           "value followed by the");
      w.println("# letter 'x' to indicate that it is a multiplier of the " +
           "value specified by the");
      w.println("# '--ratePerSecond' argument (e.g., if the " +
           "'--ratePerSecond' argument is");
      w.println("# present with a value of 1000, then a target rate value " +
           "of '0.75x' indicates a");
      w.println("# target rate that is 75% of the '--ratePerSecond' value, " +
           "or 750 operations per");
      w.println("# second).  If the latter format is used, then the " +
           "'--ratePerSecond' argument");
      w.println("# must be provided.");
      w.println("#");
      w.println("# The duration may optionally be present in a variable " +
           "rate definition.  If");
      w.println("# present, it must be separated from the target rate by a " +
           "comma (and there may");
      w.println("# be zero or more spaces on either side of the comma).  " +
           "The duration must be in");
      w.println("# the same format as specified in the description of the " +
           "'default-duration'");
      w.println("# header above (i.e., a positive integer followed by a " +
           "time unit).  If a");
      w.println("# variable rate definition does not include a duration, " +
           "then the");
      w.println("# 'default-duration' header must have been specified, and " +
           "that default duration");
      w.println("# will be used for that variable rate definition.");
      w.println("#");
      w.println("# The following variable rate definitions may be used to " +
           "stairstep the target");
      w.println("# rate from 1000 operations per second to 10000 operations " +
           "per second, in");
      w.println("# increments of 1000 operations per second, spending one " +
           "minute at each level.");
      w.println("# If the 'repeat' header is present with a value of 'true', " +
           "then the process");
      w.println("# will start back over at 1000 operations per second after " +
           "completing one");
      w.println("# minute at 10000 operations per second.  Otherwise, the " +
           "tool will exit after");
      w.println("# completing the 10000 operation-per-second interval.");
      w.println("1000, 1 minute");
      w.println("2000, 1 minute");
      w.println("3000, 1 minute");
      w.println("4000, 1 minute");
      w.println("5000, 1 minute");
      w.println("6000, 1 minute");
      w.println("7000, 1 minute");
      w.println("8000, 1 minute");
      w.println("9000, 1 minute");
      w.println("10000, 1 minute");
      w.println();
      w.println();
      w.println("# Additional sample rate definitions that represent common " +
           "load patterns are");
      w.println("# provided below.  Each of these patterns makes use of the " +
           "relative format for");
      w.println("# the target rate and therefore require the " +
           "'--ratePerSecond' argument to");
      w.println("# specify the target rate.  These sample rate definitions " +
           "are commented out to");
      w.println("# prevent them from being interpreted by default.");
      w.println();
      w.println();
      w.println("# Example:  Square Rate");
      w.println("#");
      w.println("# This pattern starts with a rate of zero operations per " +
           "second, then");
      w.println("# immediately jumps to a rate of 100% of the target rate.  " +
           "A graph of the load");
      w.println("# generated by repeating iterations of this pattern " +
           "represents a series of");
      w.println("# squares that are alternately missing the top and bottom " +
           "edges.");
      w.println("#");
      w.println("#0.00x");
      w.println("#1.00x");
      w.println();
      w.println();
      w.println("# Example:  Stairstep Rate");
      w.println("#");
      w.println("# This pattern starts with a rate that is 10% of the target " +
           "rate, then jumps to");
      w.println("# 20% of the target rate, then 30%, 40%, 50%, etc. until it " +
           "reaches 100% of the");
      w.println("# target rate.  A graph of the load generated by a single " +
           "iteration of this");
      w.println("# pattern represents a series of stair steps.");
      w.println("#");
      w.println("#0.1x");
      w.println("#0.2x");
      w.println("#0.3x");
      w.println("#0.4x");
      w.println("#0.5x");
      w.println("#0.6x");
      w.println("#0.7x");
      w.println("#0.8x");
      w.println("#0.9x");
      w.println("#1.0x");
      w.println();
      w.println();
      w.println("# Example:  Sine Rate");
      w.println("#");
      w.println("# This pattern starts with a rate of zero operations per " +
           "second and increases");
      w.println("# to # 100% of the target rate in a pattern that is gradual " +
           "at first, rapid in");
      w.println("# the middle, and then gradual again at the end, and then " +
           "decreases back to");
      w.println("# zero in a mirror image of the ascent.  A graph of the " +
           "load generated by this");
      w.println("# pattern resembles a sine wave, but starting at the " +
           "lowest point in the trough");
      w.println("# of the wave (mathematically, represented by the function " +
           "'y=sin(x-pi/2)+1').");
      w.println("#");
      w.println("#0.000x");
      w.println("#0.001x");
      w.println("#0.002x");
      w.println("#0.004x");
      w.println("#0.006x");
      w.println("#0.009x");
      w.println("#0.012x");
      w.println("#0.016x");
      w.println("#0.020x");
      w.println("#0.024x");
      w.println("#0.030x");
      w.println("#0.035x");
      w.println("#0.041x");
      w.println("#0.048x");
      w.println("#0.054x");
      w.println("#0.062x");
      w.println("#0.070x");
      w.println("#0.078x");
      w.println("#0.086x");
      w.println("#0.095x");
      w.println("#0.105x");
      w.println("#0.115x");
      w.println("#0.125x");
      w.println("#0.136x");
      w.println("#0.146x");
      w.println("#0.158x");
      w.println("#0.169x");
      w.println("#0.181x");
      w.println("#0.194x");
      w.println("#0.206x");
      w.println("#0.219x");
      w.println("#0.232x");
      w.println("#0.245x");
      w.println("#0.259x");
      w.println("#0.273x");
      w.println("#0.287x");
      w.println("#0.301x");
      w.println("#0.316x");
      w.println("#0.331x");
      w.println("#0.345x");
      w.println("#0.361x");
      w.println("#0.376x");
      w.println("#0.391x");
      w.println("#0.406x");
      w.println("#0.422x");
      w.println("#0.437x");
      w.println("#0.453x");
      w.println("#0.469x");
      w.println("#0.484x");
      w.println("#0.500x");
      w.println("#0.500x");
      w.println("#0.516x");
      w.println("#0.531x");
      w.println("#0.547x");
      w.println("#0.563x");
      w.println("#0.578x");
      w.println("#0.594x");
      w.println("#0.609x");
      w.println("#0.624x");
      w.println("#0.639x");
      w.println("#0.655x");
      w.println("#0.669x");
      w.println("#0.684x");
      w.println("#0.699x");
      w.println("#0.713x");
      w.println("#0.727x");
      w.println("#0.741x");
      w.println("#0.755x");
      w.println("#0.768x");
      w.println("#0.781x");
      w.println("#0.794x");
      w.println("#0.806x");
      w.println("#0.819x");
      w.println("#0.831x");
      w.println("#0.842x");
      w.println("#0.854x");
      w.println("#0.864x");
      w.println("#0.875x");
      w.println("#0.885x");
      w.println("#0.895x");
      w.println("#0.905x");
      w.println("#0.914x");
      w.println("#0.922x");
      w.println("#0.930x");
      w.println("#0.938x");
      w.println("#0.946x");
      w.println("#0.952x");
      w.println("#0.959x");
      w.println("#0.965x");
      w.println("#0.970x");
      w.println("#0.976x");
      w.println("#0.980x");
      w.println("#0.984x");
      w.println("#0.988x");
      w.println("#0.991x");
      w.println("#0.994x");
      w.println("#0.996x");
      w.println("#0.998x");
      w.println("#0.999x");
      w.println("#1.000x");
      w.println("#1.000x");
      w.println("#1.000x");
      w.println("#0.999x");
      w.println("#0.998x");
      w.println("#0.996x");
      w.println("#0.994x");
      w.println("#0.991x");
      w.println("#0.988x");
      w.println("#0.984x");
      w.println("#0.980x");
      w.println("#0.976x");
      w.println("#0.970x");
      w.println("#0.965x");
      w.println("#0.959x");
      w.println("#0.952x");
      w.println("#0.946x");
      w.println("#0.938x");
      w.println("#0.930x");
      w.println("#0.922x");
      w.println("#0.914x");
      w.println("#0.905x");
      w.println("#0.895x");
      w.println("#0.885x");
      w.println("#0.875x");
      w.println("#0.864x");
      w.println("#0.854x");
      w.println("#0.842x");
      w.println("#0.831x");
      w.println("#0.819x");
      w.println("#0.806x");
      w.println("#0.794x");
      w.println("#0.781x");
      w.println("#0.768x");
      w.println("#0.755x");
      w.println("#0.741x");
      w.println("#0.727x");
      w.println("#0.713x");
      w.println("#0.699x");
      w.println("#0.684x");
      w.println("#0.669x");
      w.println("#0.655x");
      w.println("#0.639x");
      w.println("#0.624x");
      w.println("#0.609x");
      w.println("#0.594x");
      w.println("#0.578x");
      w.println("#0.563x");
      w.println("#0.547x");
      w.println("#0.531x");
      w.println("#0.516x");
      w.println("#0.500x");
      w.println("#0.484x");
      w.println("#0.469x");
      w.println("#0.453x");
      w.println("#0.437x");
      w.println("#0.422x");
      w.println("#0.406x");
      w.println("#0.391x");
      w.println("#0.376x");
      w.println("#0.361x");
      w.println("#0.345x");
      w.println("#0.331x");
      w.println("#0.316x");
      w.println("#0.301x");
      w.println("#0.287x");
      w.println("#0.273x");
      w.println("#0.259x");
      w.println("#0.245x");
      w.println("#0.232x");
      w.println("#0.219x");
      w.println("#0.206x");
      w.println("#0.194x");
      w.println("#0.181x");
      w.println("#0.169x");
      w.println("#0.158x");
      w.println("#0.146x");
      w.println("#0.136x");
      w.println("#0.125x");
      w.println("#0.115x");
      w.println("#0.105x");
      w.println("#0.095x");
      w.println("#0.086x");
      w.println("#0.078x");
      w.println("#0.070x");
      w.println("#0.062x");
      w.println("#0.054x");
      w.println("#0.048x");
      w.println("#0.041x");
      w.println("#0.035x");
      w.println("#0.030x");
      w.println("#0.024x");
      w.println("#0.020x");
      w.println("#0.016x");
      w.println("#0.012x");
      w.println("#0.009x");
      w.println("#0.006x");
      w.println("#0.004x");
      w.println("#0.002x");
      w.println("#0.001x");
      w.println("#0.000x");
      w.println();
      w.println();
      w.println("# Example:  Sawtooth Rate");
      w.println("#");
      w.println("# This pattern starts with a rate of zero operations per " +
           "second and increases");
      w.println("# linearly to 100% of the target rate.  A graph of the load " +
           "generated by a");
      w.println("# single iteration of this pattern resembles the hypotenuse " +
           "of a right");
      w.println("# triangle, and a graph of multiple iterations resembles " +
           "the teeth of a saw");
      w.println("# blade.");
      w.println("#");
      w.println("#0.00x");
      w.println("#0.01x");
      w.println("#0.02x");
      w.println("#0.03x");
      w.println("#0.04x");
      w.println("#0.05x");
      w.println("#0.06x");
      w.println("#0.07x");
      w.println("#0.08x");
      w.println("#0.09x");
      w.println("#0.10x");
      w.println("#0.11x");
      w.println("#0.12x");
      w.println("#0.13x");
      w.println("#0.14x");
      w.println("#0.15x");
      w.println("#0.16x");
      w.println("#0.17x");
      w.println("#0.18x");
      w.println("#0.19x");
      w.println("#0.20x");
      w.println("#0.21x");
      w.println("#0.22x");
      w.println("#0.23x");
      w.println("#0.24x");
      w.println("#0.25x");
      w.println("#0.26x");
      w.println("#0.27x");
      w.println("#0.28x");
      w.println("#0.29x");
      w.println("#0.30x");
      w.println("#0.31x");
      w.println("#0.32x");
      w.println("#0.33x");
      w.println("#0.34x");
      w.println("#0.35x");
      w.println("#0.36x");
      w.println("#0.37x");
      w.println("#0.38x");
      w.println("#0.39x");
      w.println("#0.40x");
      w.println("#0.41x");
      w.println("#0.42x");
      w.println("#0.43x");
      w.println("#0.44x");
      w.println("#0.45x");
      w.println("#0.46x");
      w.println("#0.47x");
      w.println("#0.48x");
      w.println("#0.49x");
      w.println("#0.50x");
      w.println("#0.51x");
      w.println("#0.52x");
      w.println("#0.53x");
      w.println("#0.54x");
      w.println("#0.55x");
      w.println("#0.56x");
      w.println("#0.57x");
      w.println("#0.58x");
      w.println("#0.59x");
      w.println("#0.60x");
      w.println("#0.61x");
      w.println("#0.62x");
      w.println("#0.63x");
      w.println("#0.64x");
      w.println("#0.65x");
      w.println("#0.66x");
      w.println("#0.67x");
      w.println("#0.68x");
      w.println("#0.69x");
      w.println("#0.70x");
      w.println("#0.71x");
      w.println("#0.72x");
      w.println("#0.73x");
      w.println("#0.74x");
      w.println("#0.75x");
      w.println("#0.76x");
      w.println("#0.77x");
      w.println("#0.78x");
      w.println("#0.79x");
      w.println("#0.80x");
      w.println("#0.81x");
      w.println("#0.82x");
      w.println("#0.83x");
      w.println("#0.84x");
      w.println("#0.85x");
      w.println("#0.86x");
      w.println("#0.87x");
      w.println("#0.88x");
      w.println("#0.89x");
      w.println("#0.90x");
      w.println("#0.91x");
      w.println("#0.92x");
      w.println("#0.93x");
      w.println("#0.94x");
      w.println("#0.95x");
      w.println("#0.96x");
      w.println("#0.97x");
      w.println("#0.98x");
      w.println("#0.99x");
      w.println("#1.00x");
      w.println();
      w.println();
      w.println("# Example:  Triangle Rate");
      w.println("#");
      w.println("# This pattern starts with a rate of zero operations per " +
           "second and increases");
      w.println("# linearly to 100% of the target rate before decreasing " +
           "linearly back to 0%.");
      w.println("# A graph of the load generated by a single iteration of " +
           "this tool is like that");
      w.println("# of the sawtooth pattern above followed immediately by its " +
           "mirror image.");
      w.println("#");
      w.println("#0.00x");
      w.println("#0.01x");
      w.println("#0.02x");
      w.println("#0.03x");
      w.println("#0.04x");
      w.println("#0.05x");
      w.println("#0.06x");
      w.println("#0.07x");
      w.println("#0.08x");
      w.println("#0.09x");
      w.println("#0.10x");
      w.println("#0.11x");
      w.println("#0.12x");
      w.println("#0.13x");
      w.println("#0.14x");
      w.println("#0.15x");
      w.println("#0.16x");
      w.println("#0.17x");
      w.println("#0.18x");
      w.println("#0.19x");
      w.println("#0.20x");
      w.println("#0.21x");
      w.println("#0.22x");
      w.println("#0.23x");
      w.println("#0.24x");
      w.println("#0.25x");
      w.println("#0.26x");
      w.println("#0.27x");
      w.println("#0.28x");
      w.println("#0.29x");
      w.println("#0.30x");
      w.println("#0.31x");
      w.println("#0.32x");
      w.println("#0.33x");
      w.println("#0.34x");
      w.println("#0.35x");
      w.println("#0.36x");
      w.println("#0.37x");
      w.println("#0.38x");
      w.println("#0.39x");
      w.println("#0.40x");
      w.println("#0.41x");
      w.println("#0.42x");
      w.println("#0.43x");
      w.println("#0.44x");
      w.println("#0.45x");
      w.println("#0.46x");
      w.println("#0.47x");
      w.println("#0.48x");
      w.println("#0.49x");
      w.println("#0.50x");
      w.println("#0.51x");
      w.println("#0.52x");
      w.println("#0.53x");
      w.println("#0.54x");
      w.println("#0.55x");
      w.println("#0.56x");
      w.println("#0.57x");
      w.println("#0.58x");
      w.println("#0.59x");
      w.println("#0.60x");
      w.println("#0.61x");
      w.println("#0.62x");
      w.println("#0.63x");
      w.println("#0.64x");
      w.println("#0.65x");
      w.println("#0.66x");
      w.println("#0.67x");
      w.println("#0.68x");
      w.println("#0.69x");
      w.println("#0.70x");
      w.println("#0.71x");
      w.println("#0.72x");
      w.println("#0.73x");
      w.println("#0.74x");
      w.println("#0.75x");
      w.println("#0.76x");
      w.println("#0.77x");
      w.println("#0.78x");
      w.println("#0.79x");
      w.println("#0.80x");
      w.println("#0.81x");
      w.println("#0.82x");
      w.println("#0.83x");
      w.println("#0.84x");
      w.println("#0.85x");
      w.println("#0.86x");
      w.println("#0.87x");
      w.println("#0.88x");
      w.println("#0.89x");
      w.println("#0.90x");
      w.println("#0.91x");
      w.println("#0.92x");
      w.println("#0.93x");
      w.println("#0.94x");
      w.println("#0.95x");
      w.println("#0.96x");
      w.println("#0.97x");
      w.println("#0.98x");
      w.println("#0.99x");
      w.println("#1.00x");
      w.println("#0.99x");
      w.println("#0.98x");
      w.println("#0.97x");
      w.println("#0.96x");
      w.println("#0.95x");
      w.println("#0.94x");
      w.println("#0.93x");
      w.println("#0.92x");
      w.println("#0.91x");
      w.println("#0.90x");
      w.println("#0.89x");
      w.println("#0.88x");
      w.println("#0.87x");
      w.println("#0.86x");
      w.println("#0.85x");
      w.println("#0.84x");
      w.println("#0.83x");
      w.println("#0.82x");
      w.println("#0.81x");
      w.println("#0.80x");
      w.println("#0.79x");
      w.println("#0.78x");
      w.println("#0.77x");
      w.println("#0.76x");
      w.println("#0.75x");
      w.println("#0.74x");
      w.println("#0.73x");
      w.println("#0.72x");
      w.println("#0.71x");
      w.println("#0.70x");
      w.println("#0.69x");
      w.println("#0.68x");
      w.println("#0.67x");
      w.println("#0.66x");
      w.println("#0.65x");
      w.println("#0.64x");
      w.println("#0.63x");
      w.println("#0.62x");
      w.println("#0.61x");
      w.println("#0.60x");
      w.println("#0.59x");
      w.println("#0.58x");
      w.println("#0.57x");
      w.println("#0.56x");
      w.println("#0.55x");
      w.println("#0.54x");
      w.println("#0.53x");
      w.println("#0.52x");
      w.println("#0.51x");
      w.println("#0.50x");
      w.println("#0.49x");
      w.println("#0.48x");
      w.println("#0.47x");
      w.println("#0.46x");
      w.println("#0.45x");
      w.println("#0.44x");
      w.println("#0.43x");
      w.println("#0.42x");
      w.println("#0.41x");
      w.println("#0.40x");
      w.println("#0.39x");
      w.println("#0.38x");
      w.println("#0.37x");
      w.println("#0.36x");
      w.println("#0.35x");
      w.println("#0.34x");
      w.println("#0.33x");
      w.println("#0.32x");
      w.println("#0.31x");
      w.println("#0.30x");
      w.println("#0.29x");
      w.println("#0.28x");
      w.println("#0.27x");
      w.println("#0.26x");
      w.println("#0.25x");
      w.println("#0.24x");
      w.println("#0.23x");
      w.println("#0.22x");
      w.println("#0.21x");
      w.println("#0.20x");
      w.println("#0.19x");
      w.println("#0.18x");
      w.println("#0.17x");
      w.println("#0.16x");
      w.println("#0.15x");
      w.println("#0.14x");
      w.println("#0.13x");
      w.println("#0.12x");
      w.println("#0.11x");
      w.println("#0.10x");
      w.println("#0.09x");
      w.println("#0.08x");
      w.println("#0.07x");
      w.println("#0.06x");
      w.println("#0.05x");
      w.println("#0.04x");
      w.println("#0.03x");
      w.println("#0.02x");
      w.println("#0.01x");
      w.println("#0.00x");
      w.println();
      w.println();
      w.println("# Example:  'Hockey Stick' Rate");
      w.println("#");
      w.println("# This pattern starts with a rate of zero operations per " +
           "second and increases");
      w.println("# slowly at first before ramping up much more quickly.  A " +
           "graph of the load");
      w.println("# generated by a single iteration of this pattern vaguely " +
           "resembles a hockey");
      w.println("# stick.");
      w.println("#");
      w.println("#0.000x");
      w.println("#0.000x");
      w.println("#0.000x");
      w.println("#0.000x");
      w.println("#0.000x");
      w.println("#0.000x");
      w.println("#0.000x");
      w.println("#0.000x");
      w.println("#0.001x");
      w.println("#0.001x");
      w.println("#0.001x");
      w.println("#0.001x");
      w.println("#0.002x");
      w.println("#0.002x");
      w.println("#0.003x");
      w.println("#0.003x");
      w.println("#0.004x");
      w.println("#0.005x");
      w.println("#0.006x");
      w.println("#0.007x");
      w.println("#0.008x");
      w.println("#0.009x");
      w.println("#0.011x");
      w.println("#0.012x");
      w.println("#0.014x");
      w.println("#0.016x");
      w.println("#0.018x");
      w.println("#0.020x");
      w.println("#0.022x");
      w.println("#0.024x");
      w.println("#0.027x");
      w.println("#0.030x");
      w.println("#0.033x");
      w.println("#0.036x");
      w.println("#0.039x");
      w.println("#0.043x");
      w.println("#0.047x");
      w.println("#0.051x");
      w.println("#0.055x");
      w.println("#0.059x");
      w.println("#0.064x");
      w.println("#0.069x");
      w.println("#0.074x");
      w.println("#0.080x");
      w.println("#0.085x");
      w.println("#0.091x");
      w.println("#0.097x");
      w.println("#0.104x");
      w.println("#0.111x");
      w.println("#0.118x");
      w.println("#0.125x");
      w.println("#0.133x");
      w.println("#0.141x");
      w.println("#0.149x");
      w.println("#0.157x");
      w.println("#0.166x");
      w.println("#0.176x");
      w.println("#0.185x");
      w.println("#0.195x");
      w.println("#0.205x");
      w.println("#0.216x");
      w.println("#0.227x");
      w.println("#0.238x");
      w.println("#0.250x");
      w.println("#0.262x");
      w.println("#0.275x");
      w.println("#0.287x");
      w.println("#0.301x");
      w.println("#0.314x");
      w.println("#0.329x");
      w.println("#0.343x");
      w.println("#0.358x");
      w.println("#0.373x");
      w.println("#0.389x");
      w.println("#0.405x");
      w.println("#0.422x");
      w.println("#0.439x");
      w.println("#0.457x");
      w.println("#0.475x");
      w.println("#0.493x");
      w.println("#0.512x");
      w.println("#0.531x");
      w.println("#0.551x");
      w.println("#0.572x");
      w.println("#0.593x");
      w.println("#0.614x");
      w.println("#0.636x");
      w.println("#0.659x");
      w.println("#0.681x");
      w.println("#0.705x");
      w.println("#0.729x");
      w.println("#0.754x");
      w.println("#0.779x");
      w.println("#0.804x");
      w.println("#0.831x");
      w.println("#0.857x");
      w.println("#0.885x");
      w.println("#0.913x");
      w.println("#0.941x");
      w.println("#0.970x");
      w.println("#1.000x");
      w.println();
    }
    finally
    {
      w.close();
    }
  }



  /**
   * Constructs a new RateAdjustor with the specified parameters.  See the
   * class-level javadoc for more information.
   *
   * @param  barrier            The barrier to update based on the specified
   *                            rates.
   * @param  baseRatePerSecond  The baseline rate per second, or 0 if none was
   *                            specified.
   * @param  rates              A list of rates and durations as described in
   *                            the class-level javadoc.  The reader will
   *                            always be closed before this method returns.
   *
   * @throws  IOException               If there is a problem reading from
   *                                    the rates Reader.
   * @throws  IllegalArgumentException  If there is a problem with the rates
   *                                    input.
   */
  public RateAdjustor(@NotNull final FixedRateBarrier barrier,
                      final long baseRatePerSecond,
                      @NotNull final Reader rates)
         throws IOException, IllegalArgumentException
  {
    // Read the header first.
    final List<String> lines;
    try
    {
      Validator.ensureNotNull(barrier, rates);
      setDaemon(true);
      this.barrier = barrier;

      lines = readLines(rates);
    }
    finally
    {
      rates.close();
    }

    final Map<String,String> header = consumeHeader(lines);

    final Set<String> invalidKeys = new LinkedHashSet<>(header.keySet());
    invalidKeys.removeAll(KEYS);
    if (! invalidKeys.isEmpty())
    {
      throw new IllegalArgumentException(
           ERR_RATE_ADJUSTOR_INVALID_KEYS.get(invalidKeys, KEYS));
    }

    final String format = header.get(FORMAT_KEY);
    if (format == null)
    {
      throw new IllegalArgumentException(ERR_RATE_ADJUSTOR_MISSING_FORMAT.get(
           FORMAT_KEY, FORMATS, COMMENT_START));
    }

    if (! format.equals(FORMAT_VALUE_RATE_DURATION))
    {
      // For now this is the only format that we support.
      throw new IllegalArgumentException(
           ERR_RATE_ADJUSTOR_INVALID_FORMAT.get(format, FORMAT_KEY, FORMATS));
    }

    repeat = Boolean.parseBoolean(header.get(REPEAT_KEY));

    // This will be non-zero if it's set in the input.
    long defaultDurationMillis = 0;
    final String defaultDurationStr = header.get(DEFAULT_DURATION_KEY);
    if (defaultDurationStr != null)
    {
      try
      {
        defaultDurationMillis = DurationArgument.parseDuration(
             defaultDurationStr, TimeUnit.MILLISECONDS);
      }
      catch (final ArgumentException e)
      {
        Debug.debugException(e);
        throw new IllegalArgumentException(
             ERR_RATE_ADJUSTOR_INVALID_DEFAULT_DURATION.get(
                        defaultDurationStr, e.getExceptionMessage()),
             e);
      }
    }

    // Now parse out the rates and durations, which will look like this:
    //  1000,1s
    //  1.5,1d
    //  0.5X, 1m
    //  # Duration can be omitted if default-duration header was included.
    //  1000
    final List<ObjectPair<Double,Long>> ratesAndDurationList =
         new ArrayList<>(10);
    final Pattern splitPattern = Pattern.compile("\\s*,\\s*");
    for (final String fullLine: lines)
    {
      // Strip out comments and white space.
      String line = fullLine;
      final int commentStart = fullLine.indexOf(COMMENT_START);
      if (commentStart >= 0)
      {
        line = line.substring(0, commentStart);
      }
      line = line.trim();

      if (line.isEmpty())
      {
        continue;
      }

      final String[] fields = splitPattern.split(line);
      if (!((fields.length == 2) ||
            ((fields.length == 1) && defaultDurationMillis != 0)))
      {
        throw new IllegalArgumentException(ERR_RATE_ADJUSTOR_INVALID_LINE.get(
             fullLine, DEFAULT_DURATION_KEY));
      }

      String rateStr = fields[0];

      boolean isRateMultiplier = false;
      if (rateStr.endsWith("X") || rateStr.endsWith("x"))
      {
        rateStr = rateStr.substring(0, rateStr.length() - 1).trim();
        isRateMultiplier = true;
      }

      double rate;
      try
      {
        rate = Double.parseDouble(rateStr);
      }
      catch (final NumberFormatException e)
      {
        Debug.debugException(e);
        throw new IllegalArgumentException(
             ERR_RATE_ADJUSTOR_INVALID_RATE.get(rateStr, fullLine), e);
      }

      // Values that look like 2X are a multiplier on the base rate.
      if (isRateMultiplier)
      {
        if (baseRatePerSecond <= 0)
        {
          throw new IllegalArgumentException(
                  ERR_RATE_ADJUSTOR_RELATIVE_RATE_WITHOUT_BASELINE.get(
                          rateStr, fullLine));
        }

        rate *= baseRatePerSecond;
      }

      final long durationMillis;
      if (fields.length < 2)
      {
        durationMillis = defaultDurationMillis;
      }
      else
      {
        final String duration = fields[1];
        try
        {
          durationMillis = DurationArgument.parseDuration(
                  duration, TimeUnit.MILLISECONDS);
        }
        catch (final ArgumentException e)
        {
          Debug.debugException(e);
          throw new IllegalArgumentException(
               ERR_RATE_ADJUSTOR_INVALID_DURATION.get(duration, fullLine,
                    e.getExceptionMessage()),
               e);
        }
      }

      ratesAndDurationList.add(new ObjectPair<>(rate, durationMillis));
    }
    ratesAndDurations = Collections.unmodifiableList(ratesAndDurationList);
  }



  /**
   * Starts this thread and waits for the initial rate to be set.
   */
  @Override
  public void start()
  {
    super.start();

    // Wait until the initial rate is set.  Assuming the caller starts this
    // RateAdjustor before the FixedRateBarrier is used by other threads,
    // this will guarantee that the initial rate is in place before the
    // barrier is used.
    try
    {
      initialRateSetLatch.await();
    }
    catch (final InterruptedException e)
    {
      Debug.debugException(e);
      Thread.currentThread().interrupt();
    }
  }



  /**
   * Adjusts the rate in FixedRateBarrier as described in the rates.
   */
  @Override
  public void run()
  {
    try
    {
      if (ratesAndDurations.isEmpty())
      {
        return;
      }

      do
      {
        final List<ObjectPair<Double,Long>> ratesAndEndTimes =
             new ArrayList<>(ratesAndDurations.size());
        long endTime = System.currentTimeMillis();
        for (final ObjectPair<Double,Long> rateAndDuration : ratesAndDurations)
        {
          endTime += rateAndDuration.getSecond();
          ratesAndEndTimes.add(new ObjectPair<>(rateAndDuration.getFirst(),
               endTime));
        }

        for (final ObjectPair<Double,Long> rateAndEndTime: ratesAndEndTimes)
        {
          if (shutDown)
          {
            return;
          }

          final double rate = rateAndEndTime.getFirst();
          final long intervalMillis = barrier.getTargetRate().getFirst();
          final int perInterval = calculatePerInterval(intervalMillis, rate);

          barrier.setRate(intervalMillis, perInterval);

          // Signal start() that we've set the initial rate.
          if (initialRateSetLatch.getCount() > 0)
          {
            initialRateSetLatch.countDown();
          }

          // Hold at this rate for the specified duration.
          final long durationMillis =
               rateAndEndTime.getSecond() - System.currentTimeMillis();
          if (durationMillis > 0L)
          {
            sleeper.sleep(durationMillis);
          }
        }
      }
      while (repeat);
    }
    finally
    {
      // Just in case we happened to be shutdown before we were started.
      // We still want start() to be able to return.
      if (initialRateSetLatch.getCount() > 0)
      {
        initialRateSetLatch.countDown();
      }
    }
  }



  /**
   * Signals this to shut down.
   */
  public void shutDown()
  {
    shutDown = true;
    sleeper.wakeup();
  }



  /**
   * Returns the of rates and durations.  This is primarily here for testing
   * purposes.
   *
   * @return  The list of rates and durations.
   */
  @NotNull()
  List<ObjectPair<Double,Long>> getRatesAndDurations()
  {
    return ratesAndDurations;
  }



  /**
   * Calculates the rate per interval given the specified interval width
   * and the target rate per second.  (This is static and non-private so that
   * it can be unit tested.)
   *
   * @param intervalDurationMillis  The duration of the interval in
   *                                milliseconds.
   * @param ratePerSecond           The target rate per second.
   *
   * @return  The rate per interval, which will be at least 1.
   */
  static int calculatePerInterval(final long intervalDurationMillis,
                                  final double ratePerSecond)
  {
    final double intervalDurationSeconds = intervalDurationMillis / 1000.0;
    final double ratePerInterval = ratePerSecond * intervalDurationSeconds;
    return (int)Math.max(1, Math.round(ratePerInterval));
  }



  /**
   * This reads the header at the start of the file.  All blank lines and
   * comment lines will be ignored.  The end of the header will be signified by
   * a line containing only the text "END HEADER".  All non-blank, non-comment
   * lines in the header must be in the format "name=value", where there may be
   * zero or more spaces on either side of the equal sign, the name must not
   * contain either the space or the equal sign character, and the value must
   * not begin or end with a space.  Header lines must not contain partial-line
   * comments.
   *
   * @param  lines  The lines of input that include the header.
   *
   * @return  A map of key/value pairs extracted from the header.
   *
   * @throws  IllegalArgumentException  If a problem is encountered while
   *                                    parsing the header (e.g., a malformed
   *                                    header line is encountered, multiple
   *                                    headers have the same key, there is no
   *                                    end of header marker, etc.).
   */
  @NotNull()
  static Map<String,String> consumeHeader(@NotNull final List<String> lines)
         throws IllegalArgumentException
  {
    // The header will look like this:
    // key1=value1
    // key2 = value2
    // END HEADER
    boolean endHeaderFound = false;
    final Map<String,String> headerMap = new
         LinkedHashMap<>(StaticUtils.computeMapCapacity(3));
    final Iterator<String> lineIter = lines.iterator();
    while (lineIter.hasNext())
    {
      final String line = lineIter.next().trim();
      lineIter.remove();

      if (line.isEmpty() || line.startsWith(String.valueOf(COMMENT_START)))
      {
        continue;
      }

      if (line.equalsIgnoreCase(END_HEADER_TEXT))
      {
        endHeaderFound = true;
        break;
      }

      final int equalPos = line.indexOf('=');
      if (equalPos < 0)
      {
        throw new IllegalArgumentException(
             ERR_RATE_ADJUSTOR_HEADER_NO_EQUAL.get(line));
      }

      final String key = line.substring(0, equalPos).trim();
      if (key.isEmpty())
      {
        throw new IllegalArgumentException(
             ERR_RATE_ADJUSTOR_HEADER_EMPTY_KEY.get(line));
      }

      final String newValue = line.substring(equalPos+1).trim();
      final String existingValue = headerMap.get(key);
      if (existingValue != null)
      {
        throw new IllegalArgumentException(
             ERR_RATE_ADJUSTOR_DUPLICATE_HEADER_KEY.get(key, existingValue,
                  newValue));
      }

      headerMap.put(key, newValue);
    }

    if (! endHeaderFound)
    {
      // This means we iterated across all lines without finding the end header
      // marker.
      throw new IllegalArgumentException(
           ERR_RATE_ADJUSTOR_NO_END_HEADER_FOUND.get(END_HEADER_TEXT));
    }

    return headerMap;
  }



  /**
   * Returns a list of the lines read from the specified Reader.
   *
   * @param  reader  The Reader to read from.
   *
   * @return  A list of the lines read from the specified Reader.
   *
   * @throws  IOException  If there is a problem reading from the Reader.
   */
  @NotNull()
  private static List<String> readLines(@NotNull final Reader reader)
          throws IOException
  {
    final BufferedReader bufferedReader = new BufferedReader(reader);

    // We remove items from the front of the list, so a linked list works best.
    final List<String> lines = new LinkedList<>();

    String line;
    while ((line = bufferedReader.readLine()) != null)
    {
      lines.add(line);
    }

    return lines;
  }
}

