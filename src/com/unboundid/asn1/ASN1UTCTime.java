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
 * This class provides an ASN.1 UTC time element, which represents a timestamp
 * with a string representation in the format "YYMMDDhhmmssZ".  Although the
 * general UTC time format considers the seconds element to be optional, the
 * ASN.1 specification requires the element to be present.
 * <BR><BR>
 * Note that the UTC time format only allows two digits for the year, which is
 * obviously prone to causing problems when deciding which century is implied
 * by the timestamp.  The official specification does not indicate which
 * behavior should be used, so this implementation will use the same logic as
 * Java's {@code SimpleDateFormat} class, which infers the century using a
 * sliding window that assumes that the year is somewhere between 80 years
 * before and 20 years after the current time.  For example, if the current year
 * is 2017, the following values would be inferred:
 * <UL>
 *   <LI>A year of "40" would be interpreted as 1940.</LI>
 *   <LI>A year of "50" would be interpreted as 1950.</LI>
 *   <LI>A year of "60" would be interpreted as 1960.</LI>
 *   <LI>A year of "70" would be interpreted as 1970.</LI>
 *   <LI>A year of "80" would be interpreted as 1980.</LI>
 *   <LI>A year of "90" would be interpreted as 1990.</LI>
 *   <LI>A year of "00" would be interpreted as 2000.</LI>
 *   <LI>A year of "10" would be interpreted as 2010.</LI>
 *   <LI>A year of "20" would be interpreted as 2020.</LI>
 *   <LI>A year of "30" would be interpreted as 2030.</LI>
 * </UL>
 * <BR><BR>
 * UTC time elements should generally only be used for historical purposes in
 * encodings that require them.  For new cases in which a timestamp may be
 * required, you should use some other format to represent the timestamp.  The
 * {@link ASN1GeneralizedTime} element type does use a four-digit year (and also
 * allows for the possibility of sub-second values), so it may be a good fit.
 * You may also want to use a general-purpose string format like
 * {@link ASN1OctetString} that is flexible enough to support whatever encoding
 * you want.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ASN1UTCTime
       extends ASN1Element
{
  /**
   * The thread-local date formatter used to encode and decode UTC time values.
   */
  @NotNull private static final ThreadLocal<SimpleDateFormat> DATE_FORMATTERS =
       new ThreadLocal<>();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3107099228691194285L;



  // The timestamp represented by this UTC time value.
  private final long time;

  // The string representation of the UTC time value.
  @NotNull private final String stringRepresentation;



  /**
   * Creates a new UTC time element with the default BER type that represents
   * the current time.
   */
  public ASN1UTCTime()
  {
    this(ASN1Constants.UNIVERSAL_UTC_TIME_TYPE);
  }



  /**
   * Creates a new UTC time element with the specified BER type that represents
   * the current time.
   *
   * @param  type  The BER type to use for this element.
   */
  public ASN1UTCTime(final byte type)
  {
    this(type, System.currentTimeMillis());
  }



  /**
   * Creates a new UTC time element with the default BER type that represents
   * the indicated time.
   *
   * @param  date  The date value that specifies the time to represent.  This
   *               must not be {@code null}.  Note that the time that is
   *               actually represented by the element will have its
   *               milliseconds component set to zero.
   */
  public ASN1UTCTime(@NotNull final Date date)
  {
    this(ASN1Constants.UNIVERSAL_UTC_TIME_TYPE, date.getTime());
  }



  /**
   * Creates a new UTC time element with the specified BER type that represents
   * the indicated time.
   *
   * @param  type  The BER type to use for this element.
   * @param  date  The date value that specifies the time to represent.  This
   *               must not be {@code null}.  Note that the time that is
   *               actually represented by the element will have its
   *               milliseconds component set to zero.
   */
  public ASN1UTCTime(final byte type, @NotNull final Date date)
  {
    this(type, date.getTime());
  }



  /**
   * Creates a new UTC time element with the default BER type that represents
   * the indicated time.
   *
   * @param  time  The time to represent.  This must be expressed in
   *               milliseconds since the epoch (the same format used by
   *               {@code System.currentTimeMillis()} and
   *               {@code Date.getTime()}).  Note that the time that is actually
   *               represented by the element will have its milliseconds
   *               component set to zero.
   */
  public ASN1UTCTime(final long time)
  {
    this(ASN1Constants.UNIVERSAL_UTC_TIME_TYPE, time);
  }



  /**
   * Creates a new UTC time element with the specified BER type that represents
   * the indicated time.
   *
   * @param  type  The BER type to use for this element.
   * @param  time  The time to represent.  This must be expressed in
   *               milliseconds since the epoch (the same format used by
   *               {@code System.currentTimeMillis()} and
   *               {@code Date.getTime()}).  Note that the time that is actually
   *               represented by the element will have its milliseconds
   *               component set to zero.
   */
  public ASN1UTCTime(final byte type, final long time)
  {
    super(type, StaticUtils.getBytes(encodeTimestamp(time)));

    final GregorianCalendar calendar =
         new GregorianCalendar(StaticUtils.getUTCTimeZone());
    calendar.setTimeInMillis(time);
    calendar.set(Calendar.MILLISECOND, 0);

    this.time = calendar.getTimeInMillis();
    stringRepresentation = encodeTimestamp(time);
  }



  /**
   * Creates a new UTC time element with the default BER type and a time decoded
   * from the provided string representation.
   *
   * @param  timestamp  The string representation of the timestamp to represent.
   *                    This must not be {@code null}.
   *
   * @throws  ASN1Exception  If the provided timestamp does not represent a
   *                         valid ASN.1 UTC time string representation.
   */
  public ASN1UTCTime(@NotNull final String timestamp)
         throws ASN1Exception
  {
    this(ASN1Constants.UNIVERSAL_UTC_TIME_TYPE, timestamp);
  }



  /**
   * Creates a new UTC time element with the specified BER type and a time
   * decoded from the provided string representation.
   *
   * @param  type       The BER type to use for this element.
   * @param  timestamp  The string representation of the timestamp to represent.
   *                    This must not be {@code null}.
   *
   * @throws  ASN1Exception  If the provided timestamp does not represent a
   *                         valid ASN.1 UTC time string representation.
   */
  public ASN1UTCTime(final byte type, @NotNull final String timestamp)
         throws ASN1Exception
  {
    super(type, StaticUtils.getBytes(timestamp));

    time = decodeTimestamp(timestamp);
    stringRepresentation = timestamp;
  }



  /**
   * Encodes the time represented by the provided date into the appropriate
   * ASN.1 UTC time format.
   *
   * @param  date  The date value that specifies the time to represent.  This
   *               must not be {@code null}.
   *
   * @return  The encoded timestamp.
   */
  @NotNull()
  public static String encodeTimestamp(@NotNull final Date date)
  {
    return getDateFormatter().format(date);
  }



  /**
   * Gets a date formatter instance, using a thread-local instance if one
   * exists, or creating a new one if not.
   *
   * @return  A date formatter instance.
   */
  @NotNull()
  private static SimpleDateFormat getDateFormatter()
  {
    final SimpleDateFormat existingFormatter = DATE_FORMATTERS.get();
    if (existingFormatter != null)
    {
      return existingFormatter;
    }

    final SimpleDateFormat newFormatter
         = new SimpleDateFormat("yyMMddHHmmss'Z'");
    newFormatter.setTimeZone(TimeZone.getTimeZone("UTC"));
    newFormatter.setLenient(false);
    DATE_FORMATTERS.set(newFormatter);
    return newFormatter;
  }



  /**
   * Encodes the specified time into the appropriate ASN.1 UTC time format.
   *
   * @param  time  The time to represent.  This must be expressed in
   *               milliseconds since the epoch (the same format used by
   *               {@code System.currentTimeMillis()} and
   *               {@code Date.getTime()}).
   *
   * @return  The encoded timestamp.
   */
  @NotNull()
  public static String encodeTimestamp(final long time)
  {
    return encodeTimestamp(new Date(time));
  }



  /**
   * Decodes the provided string as a timestamp in the UTC time format.
   *
   * @param  timestamp  The string representation of a UTC time to be parsed as
   *                    a timestamp.  It must not be {@code null}.
   *
   * @return  The decoded time, expressed in milliseconds since the epoch (the
   *          same format used by {@code System.currentTimeMillis()} and
   *          {@code Date.getTime()}).
   *
   * @throws  ASN1Exception  If the provided timestamp cannot be parsed as a
   *                         valid string representation of an ASN.1 UTC time
   *                         value.
   */
  public static long decodeTimestamp(@NotNull final String timestamp)
         throws ASN1Exception
  {
    if (timestamp.length() != 13)
    {
      throw new ASN1Exception(ERR_UTC_TIME_STRING_INVALID_LENGTH.get());
    }

    if (! (timestamp.endsWith("Z") || timestamp.endsWith("z")))
    {
      throw new ASN1Exception(ERR_UTC_TIME_STRING_DOES_NOT_END_WITH_Z.get());
    }

    for (int i=0; i < (timestamp.length() - 1); i++)
    {
      final char c = timestamp.charAt(i);
      if ((c < '0') || (c > '9'))
      {
        throw new ASN1Exception(ERR_UTC_TIME_STRING_CHAR_NOT_DIGIT.get(i + 1));
      }
    }

    final int month = Integer.parseInt(timestamp.substring(2, 4));
    if ((month < 1) || (month > 12))
    {
      throw new ASN1Exception(ERR_UTC_TIME_STRING_INVALID_MONTH.get());
    }

    final int day = Integer.parseInt(timestamp.substring(4, 6));
    if ((day < 1) || (day > 31))
    {
      throw new ASN1Exception(ERR_UTC_TIME_STRING_INVALID_DAY.get());
    }

    final int hour = Integer.parseInt(timestamp.substring(6, 8));
    if (hour > 23)
    {
      throw new ASN1Exception(ERR_UTC_TIME_STRING_INVALID_HOUR.get());
    }

    final int minute = Integer.parseInt(timestamp.substring(8, 10));
    if (minute > 59)
    {
      throw new ASN1Exception(ERR_UTC_TIME_STRING_INVALID_MINUTE.get());
    }

    final int second = Integer.parseInt(timestamp.substring(10, 12));
    if (second > 60)
    {
      // In the case of a leap second, there can be 61 seconds in a minute.
      throw new ASN1Exception(ERR_UTC_TIME_STRING_INVALID_SECOND.get());
    }

    try
    {
      return getDateFormatter().parse(timestamp).getTime();
    }
    catch (final Exception e)
    {
      // Even though we've already done a lot of validation, this could still
      // happen if the timestamp isn't valid as a whole because one of the
      // components is out of a range implied by another component.  In the case
      // of UTC time values, this should only happen when trying to use a day
      // of the month that is not valid for the desired month (for example,
      // trying to use a date of September 31, when September only has 30 days).
      Debug.debugException(e);
      throw new ASN1Exception(
           ERR_UTC_TIME_STRING_CANNOT_PARSE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the time represented by this UTC time element, expressed as the
   * number of milliseconds since the epoch (the same format used by
   * {@code System.currentTimeMillis()} and {@code Date.getTime()}).

   * @return  The time represented by this UTC time element.
   */
  public long getTime()
  {
    return time;
  }



  /**
   * Retrieves a {@code Date} object that is set to the time represented by this
   * UTC time element.
   *
   * @return  A {@code Date} object that is set ot the time represented by this
   *          UTC time element.
   */
  @NotNull()
  public Date getDate()
  {
    return new Date(time);
  }



  /**
   * Retrieves the string representation of the UTC time value contained in this
   * element.
   *
   * @return  The string representation of the UTC time value contained in this
   *          element.
   */
  @NotNull()
  public String getStringRepresentation()
  {
    return stringRepresentation;
  }



  /**
   * Decodes the contents of the provided byte array as a UTC time element.
   *
   * @param  elementBytes  The byte array to decode as an ASN.1 UTC time
   *                       element.
   *
   * @return  The decoded ASN.1 UTC time element.
   *
   * @throws  ASN1Exception  If the provided array cannot be decoded as a UTC
   *                         time element.
   */
  @NotNull()
  public static ASN1UTCTime decodeAsUTCTime(@NotNull final byte[] elementBytes)
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

      return new ASN1UTCTime(elementBytes[0],
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
   * Decodes the provided ASN.1 element as a UTC time element.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The decoded ASN.1 UTC time element.
   *
   * @throws  ASN1Exception  If the provided element cannot be decoded as a UTC
   *                         time element.
   */
  @NotNull()
  public static ASN1UTCTime decodeAsUTCTime(@NotNull final ASN1Element element)
         throws ASN1Exception
  {
    return new ASN1UTCTime(element.getType(),
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
