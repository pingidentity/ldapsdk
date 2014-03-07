/*
 * Copyright 2014 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2014 UnboundID Corp.
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.DurationArgument;

import static com.unboundid.util.Debug.*;
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
   * The header key that represents the default duration.
   */
  public static final String DEFAULT_DURATION_KEY = "default-duration";



  /**
   * The header key that represents the format of the file.
   */
  public static final String FORMAT_KEY = "format";



  /**
   * The value of the format key that represents a list of rates and durations
   * within the input file.
   */
  public static final String FORMAT_VALUE_RATE_DURATION = "rate-duration";



  /**
   * A list of all formats that we support.
   */
  public static final List<String> FORMATS =
       Arrays.asList(FORMAT_VALUE_RATE_DURATION);



  /**
   * The header key that represents whether the input should be repeated.
   */
  public static final String REPEAT_KEY = "repeat";



  /**
   * A list of all header keys that we support.
   */
  public static final List<String> KEYS =
       Arrays.asList(DEFAULT_DURATION_KEY, FORMAT_KEY, REPEAT_KEY);



  // Other headers to consider:
  // * rate-multiplier, so you can easily proportionally increase or decrease
  //   every target rate without changing all the target rates directly.
  // * duration-multiplier, so you can easily proportionally increase or
  //   decrease the length of time to spend at target rates.
  // * rate-change-behavior, so you can specify the behavior that should be
  //   exhibited when transitioning from one rate to another (e.g., instant
  //   jump, linear acceleration, sine-based acceleration, etc.).



  // The barrier whose rate is adjusted.
  private final FixedRateBarrier barrier;

  // A list of rates per second and the number of milliseconds that the
  // specified rate should be maintained.
  private final List<ObjectPair<Double,Long>> ratesAndDurations;

  // If this is true, then the ratesAndDurations will be repeated until this is
  // shut down.
  private final boolean repeat;

  // Set to true when this should shut down.
  private volatile boolean shutDown = false;

  // This is used to make sure we set the initial rate before start() returns.
  private final CountDownLatch initialRateSetLatch = new CountDownLatch(1);

  // This allows us to interrupt when we are sleeping.
  private final WakeableSleeper sleeper = new WakeableSleeper();



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
  public static RateAdjustor newInstance(final FixedRateBarrier barrier,
                                         final Integer baseRatePerSecond,
                                         final File rates)
         throws IOException, IllegalArgumentException
  {
    final Reader reader = new FileReader(rates);
    return new RateAdjustor(
         barrier,
         (baseRatePerSecond == null) ? 0 : baseRatePerSecond,
         reader);
  }



  /**
   * Return a description for the format of the input file that is fit to
   * include in a command line tool argument description help.
   *
   * @return   A description for the format of the input file that is fit to
   * include in a command line tool argument description help.
   */
  public static String getInputDescription()
  {
    return INFO_RATE_ADJUSTOR_INPUT_DESCRIPTION.get(COMMENT_START);
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
  public RateAdjustor(final FixedRateBarrier barrier,
                      final long baseRatePerSecond,
                      final Reader rates)
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

    final Set<String> invalidKeys = new LinkedHashSet<String>(header.keySet());
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
        debugException(e);
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
            new ArrayList<ObjectPair<Double,Long>>(10);
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

      if (line.length() == 0)
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
        debugException(e);
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
          debugException(e);
          throw new IllegalArgumentException(
               ERR_RATE_ADJUSTOR_INVALID_DURATION.get(duration, fullLine,
                    e.getExceptionMessage()),
               e);
        }
      }

      ratesAndDurationList.add(
           new ObjectPair<Double,Long>(rate, durationMillis));
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
      debugException(e);
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
        for (final ObjectPair<Double,Long> rateAndDuration: ratesAndDurations)
        {
          if (shutDown)
          {
            return;
          }

          final double rate = rateAndDuration.getFirst();
          final long intervalMillis = barrier.getTargetRate().getFirst();
          final int perInterval = calculatePerInterval(intervalMillis, rate);

          barrier.setRate(intervalMillis, perInterval);

          // Signal start() that we've set the initial rate.
          if (initialRateSetLatch.getCount() > 0)
          {
            initialRateSetLatch.countDown();
          }

          // Hold at this rate for the specified duration.
          final long durationMillis = rateAndDuration.getSecond();
          sleeper.sleep(durationMillis);
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
   * This removes all comment lines from the start of the list of lines and
   * returns a map for lines that match key=value.  Each line can only have
   * a single key=value pair.  The key cannot include any white space.  The
   * value can include white space, but the white space at the beginning and
   * end is ignored.
   *
   * @param  lines  The lines of input that include the header.
   *
   * @return  A map of key/value pairs extracted from the header.
   *
   * @throws  IllegalArgumentException  If there are multiple values for the
   *                                    same key.
   */
  static Map<String,String> consumeHeader(final List<String> lines)
         throws IllegalArgumentException
  {
    // The header will look like this:
    //  # key1=value
    //  #key2 = value
    // The keys cannot have spaces, but the values could.
    final Map<String,String> headerMap = new LinkedHashMap<String,String>(3);
    final Pattern headerPattern =
         Pattern.compile(COMMENT_START + "+\\s*([^\\s=]+)\\s*=\\s*(.*)");
    final Iterator<String> lineIter = lines.iterator();
    while (lineIter.hasNext())
    {
      final String line = lineIter.next().trim();

      // Break after the first non-comment line.
      if (! line.startsWith(String.valueOf(COMMENT_START)))
      {
        break;
      }
      lineIter.remove();

      final Matcher matcher = headerPattern.matcher(line);
      if (matcher.matches())
      {
        final String key = matcher.group(1);
        final String value = matcher.group(2);

        final String existingValue = headerMap.get(key);
        if (existingValue != null)
        {
          throw new IllegalArgumentException(
               ERR_RATE_ADJUSTOR_DUPLICATE_HEADER_KEY.get(key, existingValue,
                    value));
        }

        headerMap.put(key, value);
      }
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
  private static List<String> readLines(final Reader reader) throws IOException
  {
    final BufferedReader bufferedReader = new BufferedReader(reader);

    // We remove items from the front of the list, so a linked list works best.
    final List<String> lines = new LinkedList<String>();

    String line;
    while ((line = bufferedReader.readLine()) != null)
    {
      lines.add(line);
    }

    return lines;
  }
}

