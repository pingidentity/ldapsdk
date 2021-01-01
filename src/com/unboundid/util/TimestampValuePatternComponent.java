/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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



import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class defines a value pattern component that will generate a timestamp.
 * It can be the current time or a randomly selected time within a given range,
 * and it supports a number of different formats.  The format of the output is
 * specified from the pattern used to create the component.  At its simplest,
 * the format can be just "timestamp", in which case the output will always be
 * the current time in generalized time format with millisecond precision.
 * However, the pattern can also contain the following additional components,
 * where each component is separated by colons:
 * <UL>
 *   <LI>min={minimumBoundInGeneralizedTime} -- Indicates that the generated
 *       timestamps should be randomly selected from a given range rather than
 *       using the current time, and that the specified time (which must be
 *       given in generalized time format) should be the minimum bound for that
 *       range.</LI>
 *   <LI>max={maximumBoundInGeneralizedTime} -- Indicates that the generated
 *       timestamps should be randomly selected from a given range rather than
 *       using the current time, and that the specified time (which must be
 *       given in generalized time format) should be the maximum bound for that
 *       range.</LI>
 *   <LI>format=milliseconds -- Indicates that the generated timestamp should
 *       represent the selected timestamp as the number of milliseconds since
 *       January 1, 1970 at midnight UTC.</LI>
 *   <LI>format=seconds -- Indicates that the generated timestamp should
 *       represent the selected timestamp as the number of seconds since
 *       January 1, 1970 at midnight UTC.</LI>
 *   <LI>format={formatString} -- Indicates that the generated timestamp should
 *       represent the selected timestamp using the {@code SimpleDateFormat}
 *       class created from the provided format string.</LI>
 * </UL>
 * Each of the min, max, and format elements can appear at most once in the
 * provided pattern, and they must appear in that order (that is, if a min
 * element is present, then it must be before the max element and the optional
 * format element, and if a format element is present, then it must be the last
 * element in the pattern).  If the min element is provided, then the max
 * element must also be given (and vice-versa, although the min element must
 * always be specified before the max), and both values must be expressed using
 * the generalized time format.  If the min and max elements are not provided,
 * then each generated timestamp will reflect the current time at the time that
 * timestamp was generated.  If the format element is not provided, then the
 * selected timestamps will be generated in the generalized time format with
 * millisecond precision (e.g., "20180102030405.678Z").
 */
final class TimestampValuePatternComponent
      extends ValuePatternComponent
{
  /**
   * The serial version uid for this serializable class.
   */
  private static final long serialVersionUID = 9209358760604151565L;



  // Indicates whether timestamp values should be expressed in generalized time
  // format.
  private final boolean expressAsGeneralizedTime;

  // Indicates whether timestamp values should be expressed in milliseconds
  // since the epoch.
  private final boolean expressAsMillisecondsSinceEpoch;

  // Indicates whether timestamp values should be expressed in seconds since the
  // epoch.
  private final boolean expressAsSecondsSinceEpoch;

  // The number of milliseconds between the upper and lower bounds, inclusive.
  private final long boundRange;

  // The lower bound for generated timestamp values.
  private final long lowerBound;

  // The random number generator that will be used to seed the thread-local
  // random number generators.
  @NotNull private final Random seedRandom;

  // The format string that will be used to format timestamps.
  @Nullable private final String dateFormatString;

  // The random-number generators that will be used by this class.
  @NotNull private final ThreadLocal<Random> threadLocalRandoms;

  // The date formatters that will be used by this class.
  @NotNull private final ThreadLocal<SimpleDateFormat>
       threadLocalDateFormatters;



  /**
   * Creates a new timestamp value pattern component that is parsed from the
   * given pattern string.
   *
   * @param  pattern     The pattern string that defines how timestamp values
   *                     will be generated.
   * @param  randomSeed  The value that will be used to seed the random number
   *                     generators.
   *
   * @throws  ParseException  If the provided pattern cannot be parsed to create
   *                          a valid timestamp value pattern component.
   */
  TimestampValuePatternComponent(@NotNull final String pattern,
                                 final long randomSeed)
       throws ParseException
  {
    seedRandom = new Random(randomSeed);
    threadLocalRandoms = new ThreadLocal<>();
    threadLocalDateFormatters = new ThreadLocal<>();

    if (pattern.equals("timestamp"))
    {
      expressAsGeneralizedTime = true;
      expressAsMillisecondsSinceEpoch = false;
      expressAsSecondsSinceEpoch = false;
      lowerBound = -1L;
      boundRange = -1L;
      dateFormatString = null;
      return;
    }

    if (pattern.startsWith("timestamp:min="))
    {
      final int maxPos = pattern.indexOf(":max=");
      if (maxPos < 0)
      {
        throw new ParseException(
             ERR_TIMESTAMP_VALUE_PATTERN_MIN_WITHOUT_MAX.get(pattern), 10);
      }

      final int formatPos = pattern.indexOf(":format");
      if ((formatPos > 0) && (formatPos < maxPos))
      {
        throw new ParseException(
             ERR_TIMESTAMP_VALUE_PATTERN_FORMAT_NOT_AT_END.get(pattern),
             formatPos);
      }

      final String lowerBoundString = pattern.substring(14, maxPos);
      try
      {
        lowerBound =
             StaticUtils.decodeGeneralizedTime(lowerBoundString).getTime();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new ParseException(
             ERR_TIMESTAMP_VALUE_PATTERN_CANNOT_PARSE_MIN.get(pattern,
                  lowerBoundString, StaticUtils.getExceptionMessage(e)),
             14);
      }

      final long upperBound;
      if (formatPos < 0)
      {
        final String upperBoundString = pattern.substring(maxPos + 5);
        try
        {
          upperBound =
               StaticUtils.decodeGeneralizedTime(upperBoundString).getTime();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new ParseException(
               ERR_TIMESTAMP_VALUE_PATTERN_CANNOT_PARSE_MAX.get(pattern,
                    upperBoundString, StaticUtils.getExceptionMessage(e)),
               maxPos+5);
        }

        if (upperBound <= lowerBound)
        {
          throw new ParseException(
               ERR_TIMESTAMP_VALUE_PATTERN_MIN_NOT_LT_MAX.get(pattern,
                    lowerBoundString, upperBoundString),
               maxPos+5);
        }
        else
        {
          boundRange = upperBound - lowerBound + 1L;
        }

        expressAsGeneralizedTime = true;
        expressAsMillisecondsSinceEpoch = false;
        expressAsSecondsSinceEpoch = false;
        dateFormatString = null;
      }
      else
      {
        final String upperBoundString = pattern.substring(maxPos+5, formatPos);
        try
        {
          upperBound =
               StaticUtils.decodeGeneralizedTime(upperBoundString).getTime();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new ParseException(
               ERR_TIMESTAMP_VALUE_PATTERN_CANNOT_PARSE_MAX.get(pattern,
                    upperBoundString, StaticUtils.getExceptionMessage(e)),
               maxPos+5);
        }

        if (upperBound <= lowerBound)
        {
          throw new ParseException(
               ERR_TIMESTAMP_VALUE_PATTERN_MIN_NOT_LT_MAX.get(pattern,
                    lowerBoundString, upperBoundString),
               maxPos+5);
        }
        else
        {
          boundRange = upperBound - lowerBound + 1L;
        }

        expressAsGeneralizedTime = false;

        final String formatString = pattern.substring(formatPos+8);
        if (formatString.equals("milliseconds"))
        {
          expressAsMillisecondsSinceEpoch = true;
          expressAsSecondsSinceEpoch = false;
          dateFormatString = null;
        }
        else if (formatString.equals("seconds"))
        {
          expressAsMillisecondsSinceEpoch = false;
          expressAsSecondsSinceEpoch = true;
          dateFormatString = null;
        }
        else
        {
          expressAsMillisecondsSinceEpoch = false;
          expressAsSecondsSinceEpoch = false;
          dateFormatString = formatString;

          try
          {
            new SimpleDateFormat(dateFormatString);
          }
          catch (final Exception e)
          {
            throw new ParseException(
                 ERR_TIMESTAMP_VALUE_PATTERN_CANNOT_PARSE_FORMAT_STRING.get(
                      pattern, dateFormatString),
                 formatPos+8);
          }
        }
      }
    }
    else if (pattern.startsWith("timestamp:format="))
    {
      if (pattern.contains(":min=") || pattern.contains(":max="))
      {
        throw new ParseException(
             ERR_TIMESTAMP_VALUE_PATTERN_FORMAT_NOT_AT_END.get(pattern), 17);
      }

      lowerBound = -1L;
      boundRange = -1L;
      expressAsGeneralizedTime = false;

      final String formatString = pattern.substring(17);
      if (formatString.equals("milliseconds"))
      {
        expressAsMillisecondsSinceEpoch = true;
        expressAsSecondsSinceEpoch = false;
        dateFormatString = null;
      }
      else if (formatString.equals("seconds"))
      {
        expressAsMillisecondsSinceEpoch = false;
        expressAsSecondsSinceEpoch = true;
        dateFormatString = null;
      }
      else
      {
        expressAsMillisecondsSinceEpoch = false;
        expressAsSecondsSinceEpoch = false;
        dateFormatString = formatString;

        try
        {
          new SimpleDateFormat(dateFormatString);
        }
        catch (final Exception e)
        {
          throw new ParseException(
               ERR_TIMESTAMP_VALUE_PATTERN_CANNOT_PARSE_FORMAT_STRING.get(
                    pattern, dateFormatString),
               17);
        }
      }
    }
    else
    {
      throw new ParseException(
           ERR_TIMESTAMP_VALUE_PATTERN_MALFORMED.get(pattern), 0);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  void append(@NotNull final StringBuilder buffer)
  {
    final long selectedTime;
    if (lowerBound == -1L)
    {
      selectedTime = System.currentTimeMillis();
    }
    else
    {
      final long positiveRandomValue =
           (getRandom().nextLong() & 0x7FFF_FFFF_FFFF_FFFFL);
      selectedTime = lowerBound + (positiveRandomValue % boundRange);
    }

    if (expressAsMillisecondsSinceEpoch)
    {
      buffer.append(selectedTime);
    }
    else if (expressAsSecondsSinceEpoch)
    {
      buffer.append(selectedTime / 1000L);
    }
    else if (expressAsGeneralizedTime)
    {
      buffer.append(StaticUtils.encodeGeneralizedTime(selectedTime));
    }
    else
    {
      buffer.append(getDateFormatter().format(new Date(selectedTime)));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  boolean supportsBackReference()
  {
    return true;
  }



  /**
   * Retrieves a random number generator for use by the current thread.
   *
   * @return  A random number generator for use by the current thread.
   */
  @NotNull()
  private Random getRandom()
  {
    Random random = threadLocalRandoms.get();
    if (random == null)
    {
      synchronized (seedRandom)
      {
        random = new Random(seedRandom.nextLong());
      }

      threadLocalRandoms.set(random);
    }

    return random;
  }



  /**
   * Retrieves a date formatter for use by the current thread.
   *
   * @return  A date formatter for use byt he current thread.
   */
  @NotNull()
  private SimpleDateFormat getDateFormatter()
  {
    SimpleDateFormat dateFormatter = threadLocalDateFormatters.get();
    if (dateFormatter == null)
    {
      dateFormatter = new SimpleDateFormat(dateFormatString);
      threadLocalDateFormatters.set(dateFormatter);
    }

    return dateFormatter;
  }
}
