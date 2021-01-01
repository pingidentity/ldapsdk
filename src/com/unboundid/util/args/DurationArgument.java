/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import com.unboundid.util.Debug;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.args.ArgsMessages.*;



/**
 * Creates a new argument that is intended to represent a duration.  Duration
 * values contain an integer portion and a unit portion which represents the
 * time unit.  The unit must be one of the following:
 * <UL>
 *   <LI>Nanoseconds -- ns, nano, nanos, nanosecond, nanoseconds</LI>
 *   <LI>Microseconds -- us, micro, micros, microsecond, microseconds</LI>
 *   <LI>Milliseconds -- ms, milli, millis, millisecond, milliseconds</LI>
 *   <LI>Seconds -- s, sec, secs, second, seconds</LI>
 *   <LI>Minutes -- m, min, mins, minute, minutes</LI>
 *   <LI>Hours -- h, hr, hrs, hour, hours</LI>
 *   <LI>Days -- d, day, days</LI>
 *   <LI>Weeks -- w, week, weeks</LI>
 * </UL>
 *
 * There may be zero or more spaces between the integer portion and the unit
 * portion.  However, if spaces are used in the command-line argument, then the
 * value must be enquoted or the spaces must be escaped so that the duration
 * is not seen as multiple arguments.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class DurationArgument
       extends Argument
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8824262632728709264L;



  // The argument value validators that have been registered for this argument.
  @NotNull private final List<ArgumentValueValidator> validators;

  // The default value for this argument, in nanoseconds.
  @Nullable private final Long defaultValueNanos;

  // The maximum allowed value for this argument, in nanoseconds.
  private final long maxValueNanos;

  // The minimum allowed value for this argument, in nanoseconds.
  private final long minValueNanos;

  // The provided value for this argument, in nanoseconds.
  @Nullable private Long valueNanos;

  // The string representation of the lower bound, using the user-supplied
  // value.
  @NotNull private final String lowerBoundStr;

  // The string representation of the upper bound, using the user-supplied
  // value.
  @NotNull private final String upperBoundStr;



  /**
   * Creates a new duration argument that will not be required, will use a
   * default placeholder, and will have no default value and no bounds on the
   * set of allowed values.
   *
   * @param  shortIdentifier   The short identifier for this argument.  It may
   *                           not be {@code null} if the long identifier is
   *                           {@code null}.
   * @param  longIdentifier    The long identifier for this argument.  It may
   *                           not be {@code null} if the short identifier is
   *                           {@code null}.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public DurationArgument(@Nullable final Character shortIdentifier,
                          @Nullable final String longIdentifier,
                          @NotNull final String description)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, false, null, description);
  }



  /**
   * Creates a new duration argument with no default value and no bounds on the
   * set of allowed values.
   *
   * @param  shortIdentifier   The short identifier for this argument.  It may
   *                           not be {@code null} if the long identifier is
   *                           {@code null}.
   * @param  longIdentifier    The long identifier for this argument.  It may
   *                           not be {@code null} if the short identifier is
   *                           {@code null}.
   * @param  isRequired        Indicates whether this argument is required to
   *                           be provided.
   * @param  valuePlaceholder  A placeholder to display in usage information to
   *                           indicate that a value must be provided.  It may
   *                           be {@code null} if a default placeholder should
   *                           be used.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public DurationArgument(@Nullable final Character shortIdentifier,
                          @Nullable final String longIdentifier,
                          final boolean isRequired,
                          @Nullable final String valuePlaceholder,
                          @NotNull final String description)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, isRequired, valuePlaceholder,
         description, null, null, null, null, null, null);
  }



  /**
   * Creates a new duration argument with the provided information.
   *
   * @param  shortIdentifier   The short identifier for this argument.  It may
   *                           not be {@code null} if the long identifier is
   *                           {@code null}.
   * @param  longIdentifier    The long identifier for this argument.  It may
   *                           not be {@code null} if the short identifier is
   *                           {@code null}.
   * @param  isRequired        Indicates whether this argument is required to
   *                           be provided.
   * @param  valuePlaceholder  A placeholder to display in usage information to
   *                           indicate that a value must be provided.  It may
   *                           be {@code null} if a default placeholder should
   *                           be used.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   * @param  defaultValue      The default value that will be used for this
   *                           argument if none is provided.  It may be
   *                           {@code null} if there should not be a default
   *                           value.
   * @param  defaultValueUnit  The time unit for the default value.  It may be
   *                           {@code null} only if the default value is also
   *                           {@code null}.
   * @param  lowerBound        The value for the minimum duration that may be
   *                           represented using this argument, in conjunction
   *                           with the {@code lowerBoundUnit} parameter to
   *                           specify the unit for this value.  If this is
   *                           {@code null}, then a lower bound of 0 nanoseconds
   *                           will be used.
   * @param  lowerBoundUnit    The time unit for the lower bound value.  It may
   *                           be {@code null} only if the lower bound is also
   *                           {@code null}.
   * @param  upperBound        The value for the maximum duration that may be
   *                           represented using this argument, in conjunction
   *                           with the {@code upperBoundUnit} parameter to
   *                           specify the unit for this value.  If this is
   *                           {@code null}, then an upper bound of
   *                           {@code Long.MAX_VALUE} nanoseconds will be used.
   * @param  upperBoundUnit    The time unit for the upper bound value.  It may
   *                           be {@code null} only if the upper bound is also
   *                           {@code null}.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public DurationArgument(@Nullable final Character shortIdentifier,
                          @Nullable final String longIdentifier,
                          final boolean isRequired,
                          @Nullable final String valuePlaceholder,
                          @NotNull final String description,
                          @Nullable final Long defaultValue,
                          @Nullable final TimeUnit defaultValueUnit,
                          @Nullable final Long lowerBound,
                          @Nullable final TimeUnit lowerBoundUnit,
                          @Nullable final Long upperBound,
                          @Nullable final TimeUnit upperBoundUnit)
         throws ArgumentException
  {
    super(shortIdentifier, longIdentifier, isRequired, 1,
         (valuePlaceholder == null)
              ? INFO_PLACEHOLDER_DURATION.get()
              : valuePlaceholder,
         description);

    if (defaultValue == null)
    {
      defaultValueNanos = null;
    }
    else
    {
      if (defaultValueUnit == null)
      {
        throw new ArgumentException(ERR_DURATION_DEFAULT_REQUIRES_UNIT.get(
             getIdentifierString()));
      }

      defaultValueNanos = defaultValueUnit.toNanos(defaultValue);
    }

    if (lowerBound == null)
    {
      minValueNanos = 0L;
      lowerBoundStr = "0ns";
    }
    else
    {
      if (lowerBoundUnit == null)
      {
        throw new ArgumentException(ERR_DURATION_LOWER_REQUIRES_UNIT.get(
             getIdentifierString()));
      }

      minValueNanos = lowerBoundUnit.toNanos(lowerBound);
      switch (lowerBoundUnit)
      {
        case NANOSECONDS:
          lowerBoundStr = minValueNanos + "ns";
          break;
        case MICROSECONDS:
          lowerBoundStr = lowerBound + "us";
          break;
        case MILLISECONDS:
          lowerBoundStr = lowerBound + "ms";
          break;
        case SECONDS:
          lowerBoundStr = lowerBound + "s";
          break;
        case MINUTES:
          lowerBoundStr = lowerBound + "m";
          break;
        case HOURS:
          lowerBoundStr = lowerBound + "h";
          break;
        case DAYS:
          lowerBoundStr = lowerBound + "d";
          break;
        default:
          throw new LDAPSDKUsageException(
               ERR_DURATION_UNSUPPORTED_LOWER_BOUND_UNIT.get(
                    lowerBoundUnit.name()));
      }
    }

    if (upperBound == null)
    {
      maxValueNanos = Long.MAX_VALUE;
      upperBoundStr = Long.MAX_VALUE + "ns";
    }
    else
    {
      if (upperBoundUnit == null)
      {
        throw new ArgumentException(ERR_DURATION_UPPER_REQUIRES_UNIT.get(
             getIdentifierString()));
      }

      maxValueNanos = upperBoundUnit.toNanos(upperBound);
      switch (upperBoundUnit)
      {
        case NANOSECONDS:
          upperBoundStr = minValueNanos + "ns";
          break;
        case MICROSECONDS:
          upperBoundStr = upperBound + "us";
          break;
        case MILLISECONDS:
          upperBoundStr = upperBound + "ms";
          break;
        case SECONDS:
          upperBoundStr = upperBound + "s";
          break;
        case MINUTES:
          upperBoundStr = upperBound + "m";
          break;
        case HOURS:
          upperBoundStr = upperBound + "h";
          break;
        case DAYS:
          upperBoundStr = upperBound + "d";
          break;
        default:
          throw new LDAPSDKUsageException(
               ERR_DURATION_UNSUPPORTED_UPPER_BOUND_UNIT.get(
                    upperBoundUnit.name()));
      }
    }

    if (minValueNanos > maxValueNanos)
    {
      throw new ArgumentException(ERR_DURATION_LOWER_GT_UPPER.get(
           getIdentifierString(), lowerBoundStr, upperBoundStr));
    }

    valueNanos = null;
    validators = new ArrayList<>(5);
  }



  /**
   * Creates a new duration argument that is a "clean" copy of the provided
   * source argument.
   *
   * @param  source  The source argument to use for this argument.
   */
  private DurationArgument(@NotNull final DurationArgument source)
  {
    super(source);

    defaultValueNanos = source.defaultValueNanos;
    maxValueNanos     = source.maxValueNanos;
    minValueNanos     = source.minValueNanos;
    lowerBoundStr     = source.lowerBoundStr;
    upperBoundStr     = source.upperBoundStr;
    validators        = new ArrayList<>(source.validators);
    valueNanos        = null;
  }



  /**
   * Retrieves the lower bound for this argument using the specified time unit.
   *
   * @param  unit  The time unit in which the lower bound value may be
   *               expressed.
   *
   * @return  The lower bound for this argument using the specified time unit.
   */
  public long getLowerBound(@NotNull final TimeUnit unit)
  {
    return unit.convert(minValueNanos, TimeUnit.NANOSECONDS);
  }



  /**
   * Retrieves the upper bound for this argument using the specified time unit.
   *
   * @param  unit  The time unit in which the upper bound value may be
   *               expressed.
   *
   * @return  The upper bound for this argument using the specified time unit.
   */
  public long getUpperBound(@NotNull final TimeUnit unit)
  {
    return unit.convert(maxValueNanos, TimeUnit.NANOSECONDS);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<String> getValueStringRepresentations(final boolean useDefault)
  {
    final long v;
    if (valueNanos != null)
    {
      v = valueNanos;
    }
    else if (useDefault && (defaultValueNanos != null))
    {
      v = defaultValueNanos;
    }
    else
    {
      return Collections.emptyList();
    }

    return Collections.singletonList(nanosToDuration(v));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean hasDefaultValue()
  {
    return (defaultValueNanos != null);
  }



  /**
   * Retrieves the default value for this argument using the specified time
   * unit, if defined.
   *
   * @param  unit  The time unit in which the default value should be expressed.
   *
   * @return  The default value for this argument using the specified time unit,
   *          or {@code null} if none is defined.
   */
  @Nullable()
  public Long getDefaultValue(@NotNull final TimeUnit unit)
  {
    if (defaultValueNanos == null)
    {
      return null;
    }

    return unit.convert(defaultValueNanos, TimeUnit.NANOSECONDS);
  }



  /**
   * Retrieves the value for this argument using the specified time unit, if one
   * was provided.
   *
   * @param  unit  The time unit in which to express the value for this
   *               argument.
   *
   * @return  The value for this argument using the specified time unit.  If no
   *          value was provided but a default value was defined, then the
   *          default value will be returned.  If no value was provided and no
   *          default value was defined, then {@code null} will be returned.
   */
  @Nullable()
  public Long getValue(@NotNull final TimeUnit unit)
  {
    if (valueNanos == null)
    {
      if (defaultValueNanos == null)
      {
        return null;
      }

      return unit.convert(defaultValueNanos, TimeUnit.NANOSECONDS);
    }
    else
    {
      return unit.convert(valueNanos, TimeUnit.NANOSECONDS);
    }
  }



  /**
   * Updates this argument to ensure that the provided validator will be invoked
   * for any values provided to this argument.  This validator will be invoked
   * after all other validation has been performed for this argument.
   *
   * @param  validator  The argument value validator to be invoked.  It must not
   *                    be {@code null}.
   */
  public void addValueValidator(@NotNull final ArgumentValueValidator validator)
  {
    validators.add(validator);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void addValue(@NotNull final String valueString)
            throws ArgumentException
  {
    if (valueNanos != null)
    {
      throw new ArgumentException(
           ERR_ARG_MAX_OCCURRENCES_EXCEEDED.get(getIdentifierString()));
    }

    final long proposedValueNanos;
    try
    {
      proposedValueNanos = parseDuration(valueString, TimeUnit.NANOSECONDS);
    }
    catch (final ArgumentException ae)
    {
      Debug.debugException(ae);
      throw new ArgumentException(
           ERR_DURATION_MALFORMED_VALUE.get(valueString, getIdentifierString(),
                ae.getMessage()),
           ae);
    }

    if (proposedValueNanos < minValueNanos)
    {
      throw new ArgumentException(ERR_DURATION_BELOW_LOWER_BOUND.get(
           getIdentifierString(), lowerBoundStr));
    }
    else if (proposedValueNanos > maxValueNanos)
    {
      throw new ArgumentException(ERR_DURATION_ABOVE_UPPER_BOUND.get(
           getIdentifierString(), upperBoundStr));
    }
    else
    {
      for (final ArgumentValueValidator v : validators)
      {
        v.validateArgumentValue(this, valueString);
      }

      valueNanos = proposedValueNanos;
    }
  }



  /**
   * Parses the provided string representation of a duration to a corresponding
   * numeric representation.
   *
   * @param  durationString  The string representation of the duration to be
   *                         parsed.
   * @param  timeUnit        The time unit to use for the return value.
   *
   * @return  The parsed duration as a count in the specified time unit.
   *
   * @throws  ArgumentException  If the provided string cannot be parsed as a
   *                             valid duration.
   */
  public static long parseDuration(@NotNull final String durationString,
                                   @NotNull final TimeUnit timeUnit)
         throws ArgumentException
  {
    // The string must not be empty.
    final String lowerStr = StaticUtils.toLowerCase(durationString);
    if (lowerStr.isEmpty())
    {
      throw new ArgumentException(ERR_DURATION_EMPTY_VALUE.get());
    }

    // Find the position of the first non-digit character.
    boolean digitFound    = false;
    boolean nonDigitFound = false;
    int     nonDigitPos   = -1;
    for (int i=0; i < lowerStr.length(); i++)
    {
      final char c = lowerStr.charAt(i);
      if (Character.isDigit(c))
      {
        digitFound = true;
      }
      else
      {
        nonDigitFound = true;
        nonDigitPos   = i;
        if (! digitFound)
        {
          throw new ArgumentException(ERR_DURATION_NO_DIGIT.get());
        }
        break;
      }
    }

    if (! nonDigitFound)
    {
      throw new ArgumentException(ERR_DURATION_NO_UNIT.get());
    }

    // Separate the integer portion from the unit.
    long integerPortion = Long.parseLong(lowerStr.substring(0, nonDigitPos));
    final String unitStr = lowerStr.substring(nonDigitPos).trim();

    // Parse the time unit.
    final TimeUnit unitFromString;
    if (unitStr.equals("ns") ||
        unitStr.equals("nano") ||
        unitStr.equals("nanos") ||
        unitStr.equals("nanosecond") ||
        unitStr.equals("nanoseconds"))
    {
      unitFromString = TimeUnit.NANOSECONDS;
    }
    else if (unitStr.equals("us") ||
             unitStr.equals("micro") ||
             unitStr.equals("micros") ||
             unitStr.equals("microsecond") ||
             unitStr.equals("microseconds"))
    {
      unitFromString = TimeUnit.MICROSECONDS;
    }
    else if (unitStr.equals("ms") ||
             unitStr.equals("milli") ||
             unitStr.equals("millis") ||
             unitStr.equals("millisecond") ||
             unitStr.equals("milliseconds"))
    {
      unitFromString = TimeUnit.MILLISECONDS;
    }
    else if (unitStr.equals("s") ||
             unitStr.equals("sec") ||
             unitStr.equals("secs") ||
             unitStr.equals("second") ||
             unitStr.equals("seconds"))
    {
      unitFromString = TimeUnit.SECONDS;
    }
    else if (unitStr.equals("m") ||
             unitStr.equals("min") ||
             unitStr.equals("mins") ||
             unitStr.equals("minute") ||
             unitStr.equals("minutes"))
    {
      integerPortion *= 60L;
      unitFromString = TimeUnit.SECONDS;
    }
    else if (unitStr.equals("h") ||
             unitStr.equals("hr") ||
             unitStr.equals("hrs") ||
             unitStr.equals("hour") ||
             unitStr.equals("hours"))
    {
      integerPortion *= 3600L;
      unitFromString = TimeUnit.SECONDS;
    }
    else if (unitStr.equals("d") ||
             unitStr.equals("day") ||
             unitStr.equals("days"))
    {
      integerPortion *= 86_400L;
      unitFromString = TimeUnit.SECONDS;
    }
    else if (unitStr.equals("w") ||
             unitStr.equals("week") ||
             unitStr.equals("weeks"))
    {
      integerPortion *= 604_800;
      unitFromString = TimeUnit.SECONDS;
    }
    else
    {
      throw new ArgumentException(ERR_DURATION_UNRECOGNIZED_UNIT.get(unitStr));
    }

    return timeUnit.convert(integerPortion, unitFromString);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getDataTypeName()
  {
    return INFO_DURATION_TYPE_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getValueConstraints()
  {
    final StringBuilder buffer = new StringBuilder();
    buffer.append(INFO_DURATION_CONSTRAINTS_FORMAT.get());
    buffer.append("  ");
    buffer.append(INFO_DURATION_CONSTRAINTS_LOWER_AND_UPPER_BOUND.get(
         lowerBoundStr, upperBoundStr));

    return buffer.toString();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void reset()
  {
    super.reset();
    valueNanos = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public DurationArgument getCleanCopy()
  {
    return new DurationArgument(this);
  }



  /**
   * Converts the specified number of nanoseconds into a duration string using
   * the largest possible whole unit (e.g., if the value represents a whole
   * number of seconds, then the returned string will be expressed in seconds).
   *
   * @param  nanos  The number of nanoseconds to convert to a duration string.
   *
   * @return  The duration string for the specified number of nanoseconds.
   */
  @NotNull()
  public static String nanosToDuration(final long nanos)
  {
    if (nanos == 0)
    {
      return "0 nanoseconds";
    }

    if (nanos == 604_800_000_000_000L)
    {
      return "1 week";
    }
    else if ((nanos % 604_800_000_000_000L) == 0L)
    {
      return (nanos / 604_800_000_000_000L) + " weeks";
    }
    else if (nanos == 86_400_000_000_000L)
    {
      return "1 day";
    }
    else if ((nanos % 86_400_000_000_000L) == 0L)
    {
      return (nanos / 86_400_000_000_000L) + " days";
    }
    else if (nanos == 3_600_000_000_000L)
    {
      return "1 hour";
    }
    else if ((nanos % 3_600_000_000_000L) == 0L)
    {
      return (nanos / 3_600_000_000_000L) + " hours";
    }
    else if (nanos == 60_000_000_000L)
    {
      return "1 minute";
    }
    else if ((nanos % 60_000_000_000L) == 0L)
    {
      return (nanos / 60_000_000_000L) + " minutes";
    }
    else if (nanos == 1_000_000_000L)
    {
      return "1 second";
    }
    else if ((nanos % 1_000_000_000L) == 0L)
    {
      return (nanos / 1_000_000_000L) + " seconds";
    }
    else if (nanos == 1_000_000L)
    {
      return "1 millisecond";
    }
    else if ((nanos % 1_000_000L) == 0L)
    {
     return (nanos / 1_000_000L) + " milliseconds";
    }
    else if (nanos == 1000L)
    {
      return "1 microsecond";
    }
    else if ((nanos % 1000L) == 0L)
    {
     return (nanos / 1000L) + " microseconds";
    }
    else if (nanos == 1L)
    {
      return "1 nanosecond";
    }
    else
    {
      return nanos + " nanoseconds";
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void addToCommandLine(@NotNull final List<String> argStrings)
  {
    if (valueNanos != null)
    {
      argStrings.add(getIdentifierString());
      if (isSensitive())
      {
        argStrings.add("***REDACTED***");
      }
      else
      {
        argStrings.add(nanosToDuration(valueNanos));
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("DurationArgument(");
    appendBasicToStringInfo(buffer);
    buffer.append(", lowerBound='");
    buffer.append(lowerBoundStr);
    buffer.append('\'');
    buffer.append(", upperBound='");
    buffer.append(upperBoundStr);
    buffer.append('\'');

    if (defaultValueNanos != null)
    {
      buffer.append(", defaultValueNanos=");
      buffer.append(defaultValueNanos);
    }

    buffer.append(')');
  }
}
