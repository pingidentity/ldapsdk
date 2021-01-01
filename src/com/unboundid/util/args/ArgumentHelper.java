/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
package com.unboundid.util.args;



import java.util.List;

import com.unboundid.util.Debug;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a set of helper methods that allow internal-only access
 * to various argument methods.
 */
@InternalUseOnly()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ArgumentHelper
{
  /**
   * Prevent this class from being instantiated.
   */
  private ArgumentHelper()
  {
    // No implementation is required.
  }



  /**
   * Resets the provided argument parser so that it behaves as if it had not
   * been used to parse a set of command-line arguments.
   *
   * @param  parser  The argument parser to be reset.
   */
  @InternalUseOnly()
  public static void reset(@NotNull final ArgumentParser parser)
  {
    parser.reset();
  }



  /**
   * Increments the number of occurrences for the argument in the provided set
   * of command line arguments.
   *
   * @param  argument  The argument for which to increment the number of
   *                   occurrences.
   *
   * @throws  ArgumentException  If incrementing the number of occurrences would
   *                             exceed the maximum allowed number.
   */
  @InternalUseOnly()
  public static void incrementOccurrences(@NotNull final Argument argument)
         throws ArgumentException
  {
    argument.incrementOccurrences();
  }



  /**
   * Increments the number of occurrences for the argument in the provided set
   * of command line arguments, suppressing any exception that may be thrown
   * while attempting to do so.
   *
   * @param  argument  The argument for which to increment the number of
   *                   occurrences.
   */
  @InternalUseOnly()
  public static void incrementOccurrencesSuppressException(
                          @NotNull final Argument argument)
  {
    try
    {
      argument.incrementOccurrences();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }
  }



  /**
   * Sets the selected subcommand for the argument parser.
   *
   * @param  parser      The argument parser for which to set the selected
   *                     subcommand.
   * @param  subcommand  The subcommand that has been selected.
   */
  @InternalUseOnly()
  public static void setSelectedSubCommand(@NotNull final ArgumentParser parser,
                                           @NotNull final SubCommand subcommand)
  {
    parser.setSelectedSubCommand(subcommand);
  }



  /**
   * Adds the provided value to the given argument.  This will also increment
   * the number of occurrences for the argument.
   *
   * @param  argument     The argument to which the value should be added.
   * @param  valueString  The string representation of the value.
   *
   * @throws  ArgumentException  If the provided value is not acceptable, if
   *                             the argument does not accept values, or if
   *                             the argument already has the maximum allowed
   *                             number of values.
   */
  @InternalUseOnly()
  public static void addValue(@NotNull final Argument argument,
                              @NotNull final String valueString)
            throws ArgumentException
  {
    argument.addValue(valueString);
    incrementOccurrencesSuppressException(argument);
  }



  /**
   * Adds the provided value to the given argument, suppressing any exception
   * that may be thrown while attempting to do so.  This will also increment
      * the number of occurrences for the argument.
   *
   * @param  argument     The argument to which the value should be added.
   * @param  valueString  The string representation of the value.
   */
  @InternalUseOnly()
  public static void addValueSuppressException(@NotNull final Argument argument,
                          @NotNull final String valueString)
  {
    try
    {
      argument.addValue(valueString);
      incrementOccurrencesSuppressException(argument);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }
  }



  /**
   * Indicates whether the provided argument has one or more default values that
   * will be used if it is not provided on the command line.
   *
   * @param  argument  The argument for which to make the determination.
   *
   * @return  {@code true} if the argument has one or more default values, or
   *          {@code false} if not.
   */
  @InternalUseOnly()
  public static boolean hasDefaultValue(@NotNull final Argument argument)
  {
    return argument.hasDefaultValue();
  }



  /**
   * Resets the provided argument so that it appears in the same form as before
   * it was used to parse arguments.  Subclasses that override this method must
   * call {@code super.reset()} to ensure that all necessary reset processing is
   * performed.
   *
   * @param  argument  The argument to reset.
   */
  @InternalUseOnly()
  public static void reset(@NotNull final Argument argument)
  {
    argument.reset();
  }



  /**
   * Updates the provided list to add any strings that should be included on the
   * command line in order to represent the argument's current state.
   *
   * @param  argument    The argument to process.
   * @param  argStrings  The list to update with the string representation of
   *                     the command-line arguments.
   */
  @InternalUseOnly()
  public static void addToCommandLine(@NotNull final Argument argument,
                                      @NotNull final List<String> argStrings)
  {
    argument.addToCommandLine(argStrings);
  }



  /**
   * Updates the argument parser to clear the set of trailing arguments.
   *
   * @param  parser  The argument parser whose trailing arguments should be
   *                 cleared.
   */
  @InternalUseOnly()
  public static void resetTrailingArguments(
                          @NotNull final ArgumentParser parser)
  {
    parser.resetTrailingArguments();
  }



  /**
   * Updates the argument parser to add the provided value to the set of
   * trailing arguments.
   *
   * @param  parser  The argument parser whose trailing arguments should be
   *                 cleared.
   * @param  value   The value to be added to the set of trailing arguments.
   *
   * @throws  ArgumentException  If the parser already has the maximum allowed
   *                             number of trailing arguments.
   */
  @InternalUseOnly()
  public static void addTrailingArgument(@NotNull final ArgumentParser parser,
                                         @NotNull final String value)
         throws ArgumentException
  {
    parser.addTrailingArgument(value);
  }
}
