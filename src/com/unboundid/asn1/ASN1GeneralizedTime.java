/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.asn1;



import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.TimeZone;

import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.StaticUtils;

import static com.unboundid.asn1.ASN1Messages.*;



/**
 * This class provides an ASN.1 generalized time element, which represents a
 * timestamp in the generalized time format.  The value is encoded as a string,
 * although the ASN.1 specification imposes a number of restrictions on that
 * string representation, including:
 * <UL>
 *   <LI>
 *     The generic generalized time specification allows you to specify the time
 *     zone either by ending the value with "Z" to indicate that the value is in
 *     the UTC time zone, or by ending it with a positive or negative offset
 *     (expressed in hours and minutes) from UTC time.  The ASN.1 specification
 *     only allows the "Z" option.
 *   </LI>
 *   <LI>
 *     The generic generalized time specification only requires generalized time
 *     values to include the year, month, day, and hour components of the
 *     timestamp, while the minute, second, and sub-second components are
 *     optional.  The ASN.1 specification requires that generalized time values
 *     always include the minute and second components.  Sub-second components
 *     are permitted, but with the restriction noted below.
 *   </LI>
 *   <LI>
 *     The ASN.1 specification for generalized time values does not allow the
 *     sub-second component to include any trailing zeroes.  If the sub-second
 *     component is all zeroes, then it will be omitted, along with the decimal
 *     point that would have separated the second and sub-second components.
 *   </LI>
 * </UL>
 * Note that this implementation only supports up to millisecond-level
 * precision.  It will never generate a value with a sub-second component that
 * contains more than three digits, and any value decoded from a string
 * representation that contains a sub-second component with more than three
 * digits will return a timestamp rounded to the nearest millisecond from the
 * {@link #getDate()} and {@link #getTime()} methods, although the original
 * string representation will be retained and will be used in the encoded
 * representation.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ASN1GeneralizedTime
       extends ASN1Element
{
  /**
   * The thread-local date formatters used to encode generalized time values
   * that do not include milliseconds.
   */
  @NotNull private static final ThreadLocal<SimpleDateFormat>
       DATE_FORMATTERS_WITHOUT_MILLIS = new ThreadLocal<>();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7215431927354583052L;



  // The timestamp represented by this generalized time value.
  private final long time;

  // The string representation of the generalized time value.
  @NotNull private final String stringRepresentation;



  /**
   * Creates a new generalized time element with the default BER type that
   * represents the current time.
   */
  public ASN1GeneralizedTime()
  {
    this(ASN1Constants.UNIVERSAL_GENERALIZED_TIME_TYPE);
  }



  /**
   * Creates a new generalized time element with the specified BER type that
   * represents the current time.
   *
   * @param  type  The BER type to use for this element.
   */
  public ASN1GeneralizedTime(final byte type)
  {
    this(type, System.currentTimeMillis());
  }



  /**
   * Creates a new generalized time element with the default BER type that
   * represents the indicated time.
   *
   * @param  date  The date value that specifies the time to represent.  This
   *               must not be {@code null}.
   */
  public ASN1GeneralizedTime(@NotNull final Date date)
  {
    this(ASN1Constants.UNIVERSAL_GENERALIZED_TIME_TYPE, date);
  }



  /**
   * Creates a new generalized time element with the specified BER type that
   * represents the indicated time.
   *
   * @param  type  The BER type to use for this element.
   * @param  date  The date value that specifies the time to represent.  This
   *               must not be {@code null}.
   */
  public ASN1GeneralizedTime(final byte type, @NotNull final Date date)
  {
    this(type, date.getTime());
  }



  /**
   * Creates a new generalized time element with the default BER type that
   * represents the indicated time.
   *
   * @param  time  The time to represent.  This must be expressed in
   *               milliseconds since the epoch (the same format used by
   *               {@code System.currentTimeMillis()} and
   *               {@code Date.getTime()}).
   */
  public ASN1GeneralizedTime(final long time)
  {
    this(ASN1Constants.UNIVERSAL_GENERALIZED_TIME_TYPE, time);
  }



  /**
   * Creates a new generalized time element with the specified BER type that
   * represents the indicated time.
   *
   * @param  type  The BER type to use for this element.
   * @param  time  The time to represent.  This must be expressed in
   *               milliseconds since the epoch (the same format used by
   *               {@code System.currentTimeMillis()} and
   *               {@code Date.getTime()}).
   */
  public ASN1GeneralizedTime(final byte type, final long time)
  {
    this(type, time, encodeTimestamp(time, true));
  }



  /**
   * Creates a new generalized time element with the default BER type and a
   * time decoded from the provided string representation.
   *
   * @param  timestamp  The string representation of the timestamp to represent.
   *                    This must not be {@code null}.
   *
   * @throws  ASN1Exception  If the provided timestamp does not represent a
   *                         valid ASN.1 generalized time string representation.
   */
  public ASN1GeneralizedTime(@NotNull final String timestamp)
         throws ASN1Exception
  {
    this(ASN1Constants.UNIVERSAL_GENERALIZED_TIME_TYPE, timestamp);
  }



  /**
   * Creates a new generalized time element with the specified BER type and a
   * time decoded from the provided string representation.
   *
   * @param  type       The BER type to use for this element.
   * @param  timestamp  The string representation of the timestamp to represent.
   *                    This must not be {@code null}.
   *
   * @throws  ASN1Exception  If the provided timestamp does not represent a
   *                         valid ASN.1 generalized time string representation.
   */
  public ASN1GeneralizedTime(final byte type, @NotNull final String timestamp)
         throws ASN1Exception
  {
    this(type, decodeTimestamp(timestamp), timestamp);
  }



  /**
   * Creates a new generalized time element with the provided information.
   *
   * @param  type                  The BER type to use for this element.
   * @param  time                  The time to represent.  This must be
   *                               expressed in milliseconds since the epoch
   *                               (the same format used by
   *                               {@code System.currentTimeMillis()} and
   *                               {@code Date.getTime()}).
   * @param  stringRepresentation  The string representation of the timestamp to
   *                               represent.  This must not be {@code null}.
   */
  private ASN1GeneralizedTime(final byte type, final long time,
                              @NotNull final String stringRepresentation)
  {
    super(type, StaticUtils.getBytes(stringRepresentation));

    this.time = time;
    this.stringRepresentation = stringRepresentation;
  }



  /**
   * Encodes the time represented by the provided date into the appropriate
   * ASN.1 generalized time format.
   *
   * @param  date                 The date value that specifies the time to
   *                              represent.  This must not be {@code null}.
   * @param  includeMilliseconds  Indicate whether the timestamp should include
   *                              a sub-second component representing a
   *                              precision of up to milliseconds.  Note that
   *                              even if this is {@code true}, the sub-second
   *                              component will only be included if it is not
   *                              all zeroes.  If this is {@code false}, then
   *                              the resulting timestamp will only use a
   *                              precision indicated in seconds, and the
   *                              sub-second portion will be truncated rather
   *                              than rounded to the nearest second (which is
   *                              the behavior that {@code SimpleDateFormat}
   *                              exhibits for formatting timestamps without a
   *                              sub-second component).
   *
   * @return  The encoded timestamp.
   */
  @NotNull()
  public static String encodeTimestamp(@NotNull final Date date,
                                       final boolean includeMilliseconds)
  {
    if (includeMilliseconds)
    {
      final String timestamp = StaticUtils.encodeGeneralizedTime(date);
      if (! timestamp.endsWith("0Z"))
      {
        return timestamp;
      }

      final StringBuilder buffer = new StringBuilder(timestamp);

      while (true)
      {
        final char c = buffer.charAt(buffer.length() - 2);

        if ((c == '0') || (c == '.'))
        {
          buffer.deleteCharAt(buffer.length() - 2);
        }

        if (c != '0')
        {
          break;
        }
      }

      return buffer.toString();
    }
    else
    {
      SimpleDateFormat dateFormat = DATE_FORMATTERS_WITHOUT_MILLIS.get();
      if (dateFormat == null)
      {
        dateFormat = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        DATE_FORMATTERS_WITHOUT_MILLIS.set(dateFormat);
      }

      return dateFormat.format(date);
    }
  }



  /**
   * Encodes the specified time into the appropriate ASN.1 generalized time
   * format.
   *
   * @param  time                 The time to represent.  This must be expressed
   *                              in milliseconds since the epoch (the same
   *                              format used by
   *                              {@code System.currentTimeMillis()} and
   *                              {@code Date.getTime()}).
   * @param  includeMilliseconds  Indicate whether the timestamp should include
   *                              a sub-second component representing a
   *                              precision of up to milliseconds.  Note that
   *                              even if this is {@code true}, the sub-second
   *                              component will only be included if it is not
   *                              all zeroes.
   *
   * @return  The encoded timestamp.
   */
  @NotNull()
  public static String encodeTimestamp(final long time,
                                       final boolean includeMilliseconds)
  {
    return encodeTimestamp(new Date(time), includeMilliseconds);
  }



  /**
   * Decodes the provided string as a timestamp in the generalized time format.
   *
   * @param  timestamp  The string representation of a generalized time to be
   *                    parsed as a timestamp.  It must not be {@code null}.
   *
   * @return  The decoded time, expressed in milliseconds since the epoch (the
   *          same format used by {@code System.currentTimeMillis()} and
   *          {@code Date.getTime()}).
   *
   * @throws  ASN1Exception  If the provided timestamp cannot be parsed as a
   *                         valid string representation of an ASN.1 generalized
   *                         time value.
   */
  public static long decodeTimestamp(@NotNull final String timestamp)
         throws ASN1Exception
  {
    if (timestamp.length() < 15)
    {
      throw new ASN1Exception(ERR_GENERALIZED_TIME_STRING_TOO_SHORT.get());
    }

    if (! (timestamp.endsWith("Z") || timestamp.endsWith("z")))
    {
      throw new ASN1Exception(
           ERR_GENERALIZED_TIME_STRING_DOES_NOT_END_WITH_Z.get());
    }

    boolean hasSubSecond = false;
    for (int i=0; i < (timestamp.length() - 1); i++)
    {
      final char c = timestamp.charAt(i);
      if (i == 14)
      {
        if (c != '.')
        {
          throw new ASN1Exception(
               ERR_GENERALIZED_TIME_STRING_CHAR_NOT_PERIOD.get(i + 1));
        }
        else
        {
          hasSubSecond = true;
        }
      }
      else
      {
        if ((c < '0') || (c > '9'))
        {
          throw new ASN1Exception(
               ERR_GENERALIZED_TIME_STRING_CHAR_NOT_DIGIT.get(i + 1));
        }
      }
    }

    final GregorianCalendar calendar =
         new GregorianCalendar(StaticUtils.getUTCTimeZone());

    final int year = Integer.parseInt(timestamp.substring(0, 4));
    calendar.set(Calendar.YEAR, year);

    final int month = Integer.parseInt(timestamp.substring(4, 6));
    if ((month < 1) || (month > 12))
    {
      throw new ASN1Exception(ERR_GENERALIZED_TIME_STRING_INVALID_MONTH.get());
    }
    else
    {
      calendar.set(Calendar.MONTH, (month - 1));
    }

    final int day = Integer.parseInt(timestamp.substring(6, 8));
    if ((day < 1) || (day > 31))
    {
      throw new ASN1Exception(ERR_GENERALIZED_TIME_STRING_INVALID_DAY.get());
    }
    else
    {
      calendar.set(Calendar.DAY_OF_MONTH, day);
    }

    final int hour = Integer.parseInt(timestamp.substring(8, 10));
    if (hour > 23)
    {
      throw new ASN1Exception(ERR_GENERALIZED_TIME_STRING_INVALID_HOUR.get());
    }
    else
    {
      calendar.set(Calendar.HOUR_OF_DAY, hour);
    }

    final int minute = Integer.parseInt(timestamp.substring(10, 12));
    if (minute > 59)
    {
      throw new ASN1Exception(ERR_GENERALIZED_TIME_STRING_INVALID_MINUTE.get());
    }
    else
    {
      calendar.set(Calendar.MINUTE, minute);
    }

    final int second = Integer.parseInt(timestamp.substring(12, 14));
    if (second > 60)
    {
      // In the case of a leap second, there can be 61 seconds in a minute.
      throw new ASN1Exception(ERR_GENERALIZED_TIME_STRING_INVALID_SECOND.get());
    }
    else
    {
      calendar.set(Calendar.SECOND, second);
    }

    if (hasSubSecond)
    {
      final StringBuilder subSecondString =
           new StringBuilder(timestamp.substring(15, timestamp.length() - 1));
      while (subSecondString.length() < 3)
      {
        subSecondString.append('0');
      }

      final boolean addOne;
      if (subSecondString.length() > 3)
      {
        final char charFour = subSecondString.charAt(3);
        addOne = ((charFour >= '5') && (charFour <= '9'));
        subSecondString.setLength(3);
      }
      else
      {
        addOne = false;
      }

      while (subSecondString.charAt(0) == '0')
      {
        subSecondString.deleteCharAt(0);
      }

      final int millisecond = Integer.parseInt(subSecondString.toString());
      if (addOne)
      {
        calendar.set(Calendar.MILLISECOND, (millisecond + 1));
      }
      else
      {
        calendar.set(Calendar.MILLISECOND, millisecond);
      }
    }
    else
    {
      calendar.set(Calendar.MILLISECOND, 0);
    }

    return calendar.getTimeInMillis();
  }



  /**
   * Retrieves the time represented by this generalized time element, expressed
   * as the number of milliseconds since the epoch (the same format used by
   * {@code System.currentTimeMillis()} and {@code Date.getTime()}).

   * @return  The time represented by this generalized time element.
   */
  public long getTime()
  {
    return time;
  }



  /**
   * Retrieves a {@code Date} object that is set to the time represented by this
   * generalized time element.
   *
   * @return  A {@code Date} object that is set ot the time represented by this
   *          generalized time element.
   */
  @NotNull()
  public Date getDate()
  {
    return new Date(time);
  }



  /**
   * Retrieves the string representation of the generalized time value contained
   * in this element.
   *
   * @return  The string representation of the generalized time value contained
   *          in this element.
   */
  @NotNull()
  public String getStringRepresentation()
  {
    return stringRepresentation;
  }



  /**
   * Decodes the contents of the provided byte array as a generalized time
   * element.
   *
   * @param  elementBytes  The byte array to decode as an ASN.1 generalized time
   *                       element.
   *
   * @return  The decoded ASN.1 generalized time element.
   *
   * @throws  ASN1Exception  If the provided array cannot be decoded as a
   *                         generalized time element.
   */
  @NotNull()
  public static ASN1GeneralizedTime decodeAsGeneralizedTime(
                                         @NotNull final byte[] elementBytes)
         throws ASN1Exception
  {
    try
    {
      int valueStartPos = 2;
      int length = (elementBytes[1] & 0x7F);
      if (length != elementBytes[1])
      {
        final int numLengthBytes = length;

        length = 0;
        for (int i=0; i < numLengthBytes; i++)
        {
          length <<= 8;
          length |= (elementBytes[valueStartPos++] & 0xFF);
        }
      }

      if ((elementBytes.length - valueStartPos) != length)
      {
        throw new ASN1Exception(ERR_ELEMENT_LENGTH_MISMATCH.get(length,
                                     (elementBytes.length - valueStartPos)));
      }

      final byte[] elementValue = new byte[length];
      System.arraycopy(elementBytes, valueStartPos, elementValue, 0, length);

      return new ASN1GeneralizedTime(elementBytes[0],
           StaticUtils.toUTF8String(elementValue));
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw ae;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new ASN1Exception(ERR_ELEMENT_DECODE_EXCEPTION.get(e), e);
    }
  }



  /**
   * Decodes the provided ASN.1 element as a generalized time element.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The decoded ASN.1 generalized time element.
   *
   * @throws  ASN1Exception  If the provided element cannot be decoded as a
   *                         generalized time element.
   */
  @NotNull()
  public static ASN1GeneralizedTime decodeAsGeneralizedTime(
                                         @NotNull final ASN1Element element)
         throws ASN1Exception
  {
    return new ASN1GeneralizedTime(element.getType(),
         StaticUtils.toUTF8String(element.getValue()));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append(stringRepresentation);
  }
}
