/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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



import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Date;
import java.util.concurrent.atomic.AtomicBoolean;

import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.DebugType;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a mechanism for writing one or more ASN.1 elements into a
 * byte string buffer.  It may be cleared and re-used any number of times, and
 * the contents may be written to an {@code OutputStream} or {@code ByteBuffer},
 * or copied to a byte array.  {@code ASN1Buffer} instances are not threadsafe
 * and should not be accessed concurrently by multiple threads.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ASN1Buffer
       implements Serializable
{
  /**
   * The default maximum buffer size.
   */
  private static final int DEFAULT_MAX_BUFFER_SIZE = 1_048_576;



  /**
   * An array that will be inserted when completing a sequence whose
   * multi-byte length should be encoded with one byte for the header and one
   * byte for the number of value bytes.
   */
  @NotNull private static final byte[] MULTIBYTE_LENGTH_HEADER_PLUS_ONE =
       { (byte) 0x81, (byte) 0x00 };



  /**
   * An array that will be inserted when completing a sequence whose
   * multi-byte length should be encoded with one byte for the header and two
   * bytes for the number of value bytes.
   */
  @NotNull private static final byte[] MULTIBYTE_LENGTH_HEADER_PLUS_TWO =
       { (byte) 0x82, (byte) 0x00, (byte) 0x00 };



  /**
   * An array that will be inserted when completing a sequence whose
   * multi-byte length should be encoded with one byte for the header and three
   * bytes for the number of value bytes.
   */
  @NotNull private static final byte[] MULTIBYTE_LENGTH_HEADER_PLUS_THREE =
       { (byte) 0x83, (byte) 0x00, (byte) 0x00, (byte) 0x00 };



  /**
   * An array that will be inserted when completing a sequence whose
   * multi-byte length should be encoded with one byte for the header and four
   * bytes for the number of value bytes.
   */
  @NotNull private static final byte[] MULTIBYTE_LENGTH_HEADER_PLUS_FOUR =
       { (byte) 0x84, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4898230771376551562L;



  // Indicates whether to zero out the contents of the buffer the next time it
  // is cleared in order to wipe out any sensitive data it may contain.
  @NotNull private final AtomicBoolean zeroBufferOnClear;

  // The buffer to which all data will be written.
  @NotNull private final ByteStringBuffer buffer;

  // The maximum buffer size that should be retained.
  private final int maxBufferSize;



  /**
   * Creates a new instance of this ASN.1 buffer.
   */
  public ASN1Buffer()
  {
    this(DEFAULT_MAX_BUFFER_SIZE);
  }



  /**
   * Creates a new instance of this ASN.1 buffer with an optional maximum
   * retained size.  If a maximum size is defined, then this buffer may be used
   * to hold elements larger than that, but when the buffer is cleared it will
   * be shrunk to the maximum size.
   *
   * @param  maxBufferSize  The maximum buffer size that will be retained by
   *                        this ASN.1 buffer.  A value less than or equal to
   *                        zero indicates that no maximum size should be
   *                        enforced.
   */
  public ASN1Buffer(final int maxBufferSize)
  {
    this.maxBufferSize = maxBufferSize;

    buffer            = new ByteStringBuffer();
    zeroBufferOnClear = new AtomicBoolean(false);
  }



  /**
   * Indicates whether the content of the buffer should be zeroed out the next
   * time it is cleared in order to wipe any sensitive information it may
   * contain.
   *
   * @return  {@code true} if the content of the buffer should be zeroed out the
   *          next time it is cleared, or {@code false} if not.
   */
  public boolean zeroBufferOnClear()
  {
    return zeroBufferOnClear.get();
  }



  /**
   * Specifies that the content of the buffer should be zeroed out the next time
   * it is cleared in order to wipe any sensitive information it may contain.
   */
  public void setZeroBufferOnClear()
  {
    zeroBufferOnClear.set(true);
  }



  /**
   * Clears the contents of this buffer.  If there are any outstanding sequences
   * or sets that have been created but not closed, then they must no longer be
   * used and any attempt to do so may yield unpredictable results.
   */
  public void clear()
  {
    buffer.clear(zeroBufferOnClear.getAndSet(false));

    if ((maxBufferSize > 0) && (buffer.capacity() > maxBufferSize))
    {
      buffer.setCapacity(maxBufferSize);
    }
  }



  /**
   * Retrieves the current length of this buffer in bytes.
   *
   * @return  The current length of this buffer in bytes.
   */
  public int length()
  {
    return buffer.length();
  }



  /**
   * Adds the provided ASN.1 element to this ASN.1 buffer.
   *
   * @param  element  The element to be added.  It must not be {@code null}.
   */
  public void addElement(@NotNull final ASN1Element element)
  {
    element.encodeTo(buffer);
  }



  /**
   * Adds a Boolean element to this ASN.1 buffer using the default BER type.
   *
   * @param  booleanValue  The value to use for the Boolean element.
   */
  public void addBoolean(final boolean booleanValue)
  {
    addBoolean(ASN1Constants.UNIVERSAL_BOOLEAN_TYPE, booleanValue);
  }



  /**
   * Adds a Boolean element to this ASN.1 buffer using the provided BER type.
   *
   * @param  type          The BER type to use for the Boolean element.
   * @param  booleanValue  The value to use for the Boolean element.
   */
  public void addBoolean(final byte type, final boolean booleanValue)
  {
    buffer.append(type);
    buffer.append((byte) 0x01);

    if (booleanValue)
    {
      buffer.append((byte) 0xFF);
    }
    else
    {
      buffer.append((byte) 0x00);
    }
  }



  /**
   * Adds an enumerated element to this ASN.1 buffer using the default BER type.
   *
   * @param  intValue  The value to use for the enumerated element.
   */
  public void addEnumerated(final int intValue)
  {
    addInteger(ASN1Constants.UNIVERSAL_ENUMERATED_TYPE, intValue);
  }



  /**
   * Adds an enumerated element to this ASN.1 buffer using the provided BER
   * type.
   *
   * @param  type      The BER type to use for the enumerated element.
   * @param  intValue  The value to use for the enumerated element.
   */
  public void addEnumerated(final byte type, final int intValue)
  {
    addInteger(type, intValue);
  }



  /**
   * Adds a generalized time element to this ASN.1 buffer using the default BER
   * type.
   *
   * @param  date  The date value that specifies the time to represent.  This
   *               must not be {@code null}.
   */
  public void addGeneralizedTime(@NotNull final Date date)
  {
    addGeneralizedTime(date.getTime());
  }



  /**
   * Adds a generalized time element to this ASN.1 buffer using the provided BER
   * type.
   *
   * @param  type  The BER type to use for the generalized time element.
   * @param  date  The date value that specifies the time to represent.  This
   *               must not be {@code null}.
   */
  public void addGeneralizedTime(final byte type, @NotNull final Date date)
  {
    addGeneralizedTime(type, date.getTime());
  }



  /**
   * Adds a generalized time element to this ASN.1 buffer using the default BER
   * type.
   *
   * @param  time  The time to represent.  This must be expressed in
   *               milliseconds since the epoch (the same format used by
   *               {@code System.currentTimeMillis()} and
   *               {@code Date.getTime()}).
   */
  public void addGeneralizedTime(final long time)
  {
    addGeneralizedTime(ASN1Constants.UNIVERSAL_GENERALIZED_TIME_TYPE, time);
  }



  /**
   * Adds a generalized time element to this ASN.1 buffer using the provided BER
   * type.
   *
   * @param  type  The BER type to use for the generalized time element.
   * @param  time  The time to represent.  This must be expressed in
   *               milliseconds since the epoch (the same format used by
   *               {@code System.currentTimeMillis()} and
   *               {@code Date.getTime()}).
   */
  public void addGeneralizedTime(final byte type, final long time)
  {
    buffer.append(type);

    final String timestamp = ASN1GeneralizedTime.encodeTimestamp(time, true);
    ASN1Element.encodeLengthTo(timestamp.length(), buffer);
    buffer.append(timestamp);
  }



  /**
   * Adds an integer element to this ASN.1 buffer using the default BER type.
   *
   * @param  intValue  The value to use for the integer element.
   */
  public void addInteger(final int intValue)
  {
    addInteger(ASN1Constants.UNIVERSAL_INTEGER_TYPE, intValue);
  }



  /**
   * Adds an integer element to this ASN.1 buffer using the provided BER type.
   *
   * @param  type      The BER type to use for the integer element.
   * @param  intValue  The value to use for the integer element.
   */
  public void addInteger(final byte type, final int intValue)
  {
    buffer.append(type);

    if (intValue < 0)
    {
      if ((intValue & 0xFFFF_FF80) == 0xFFFF_FF80)
      {
        buffer.append((byte) 0x01);
        buffer.append((byte) (intValue & 0xFF));
      }
      else if ((intValue & 0xFFFF_8000) == 0xFFFF_8000)
      {
        buffer.append((byte) 0x02);
        buffer.append((byte) ((intValue >> 8) & 0xFF));
        buffer.append((byte) (intValue & 0xFF));
      }
      else if ((intValue & 0xFF80_0000) == 0xFF80_0000)
      {
        buffer.append((byte) 0x03);
        buffer.append((byte) ((intValue >> 16) & 0xFF));
        buffer.append((byte) ((intValue >> 8) & 0xFF));
        buffer.append((byte) (intValue & 0xFF));
      }
      else
      {
        buffer.append((byte) 0x04);
        buffer.append((byte) ((intValue >> 24) & 0xFF));
        buffer.append((byte) ((intValue >> 16) & 0xFF));
        buffer.append((byte) ((intValue >> 8) & 0xFF));
        buffer.append((byte) (intValue & 0xFF));
      }
    }
    else
    {
      if ((intValue & 0x0000_007F) == intValue)
      {
        buffer.append((byte) 0x01);
        buffer.append((byte) (intValue & 0x7F));
      }
      else if ((intValue & 0x0000_7FFF) == intValue)
      {
        buffer.append((byte) 0x02);
        buffer.append((byte) ((intValue >> 8) & 0x7F));
        buffer.append((byte) (intValue & 0xFF));
      }
      else if ((intValue & 0x007F_FFFF) == intValue)
      {
        buffer.append((byte) 0x03);
        buffer.append((byte) ((intValue >> 16) & 0x7F));
        buffer.append((byte) ((intValue >> 8) & 0xFF));
        buffer.append((byte) (intValue & 0xFF));
      }
      else
      {
        buffer.append((byte) 0x04);
        buffer.append((byte) ((intValue >> 24) & 0x7F));
        buffer.append((byte) ((intValue >> 16) & 0xFF));
        buffer.append((byte) ((intValue >> 8) & 0xFF));
        buffer.append((byte) (intValue & 0xFF));
      }
    }
  }



  /**
   * Adds an integer element to this ASN.1 buffer using the default BER type.
   *
   * @param  longValue  The value to use for the integer element.
   */
  public void addInteger(final long longValue)
  {
    addInteger(ASN1Constants.UNIVERSAL_INTEGER_TYPE, longValue);
  }



  /**
   * Adds an integer element to this ASN.1 buffer using the provided BER type.
   *
   * @param  type       The BER type to use for the integer element.
   * @param  longValue  The value to use for the integer element.
   */
  public void addInteger(final byte type, final long longValue)
  {
    buffer.append(type);

    if (longValue < 0)
    {
      if ((longValue & 0xFFFF_FFFF_FFFF_FF80L) == 0xFFFF_FFFF_FFFF_FF80L)
      {
        buffer.append((byte) 0x01);
        buffer.append((byte) (longValue & 0xFFL));
      }
      else if ((longValue & 0xFFFF_FFFF_FFFF_8000L) == 0xFFFF_FFFF_FFFF_8000L)
      {
        buffer.append((byte) 0x02);
        buffer.append((byte) ((longValue >> 8) & 0xFFL));
        buffer.append((byte) (longValue & 0xFFL));
      }
      else if ((longValue & 0xFFFF_FFFF_FF80_0000L) == 0xFFFF_FFFF_FF80_0000L)
      {
        buffer.append((byte) 0x03);
        buffer.append((byte) ((longValue >> 16) & 0xFFL));
        buffer.append((byte) ((longValue >> 8) & 0xFFL));
        buffer.append((byte) (longValue & 0xFFL));
      }
      else if ((longValue & 0xFFFF_FFFF_8000_0000L) == 0xFFFF_FFFF_8000_0000L)
      {
        buffer.append((byte) 0x04);
        buffer.append((byte) ((longValue >> 24) & 0xFFL));
        buffer.append((byte) ((longValue >> 16) & 0xFFL));
        buffer.append((byte) ((longValue >> 8) & 0xFFL));
        buffer.append((byte) (longValue & 0xFFL));
      }
      else if ((longValue & 0xFFFF_FF80_0000_0000L) == 0xFFFF_FF80_0000_0000L)
      {
        buffer.append((byte) 0x05);
        buffer.append((byte) ((longValue >> 32) & 0xFFL));
        buffer.append((byte) ((longValue >> 24) & 0xFFL));
        buffer.append((byte) ((longValue >> 16) & 0xFFL));
        buffer.append((byte) ((longValue >> 8) & 0xFFL));
        buffer.append((byte) (longValue & 0xFFL));
      }
      else if ((longValue & 0xFFFF_8000_0000_0000L) == 0xFFFF_8000_0000_0000L)
      {
        buffer.append((byte) 0x06);
        buffer.append((byte) ((longValue >> 40) & 0xFFL));
        buffer.append((byte) ((longValue >> 32) & 0xFFL));
        buffer.append((byte) ((longValue >> 24) & 0xFFL));
        buffer.append((byte) ((longValue >> 16) & 0xFFL));
        buffer.append((byte) ((longValue >> 8) & 0xFFL));
        buffer.append((byte) (longValue & 0xFFL));
      }
      else if ((longValue & 0xFF80_0000_0000_0000L) == 0xFF80_0000_0000_0000L)
      {
        buffer.append((byte) 0x07);
        buffer.append((byte) ((longValue >> 48) & 0xFFL));
        buffer.append((byte) ((longValue >> 40) & 0xFFL));
        buffer.append((byte) ((longValue >> 32) & 0xFFL));
        buffer.append((byte) ((longValue >> 24) & 0xFFL));
        buffer.append((byte) ((longValue >> 16) & 0xFFL));
        buffer.append((byte) ((longValue >> 8) & 0xFFL));
        buffer.append((byte) (longValue & 0xFFL));
      }
      else
      {
        buffer.append((byte) 0x08);
        buffer.append((byte) ((longValue >> 56) & 0xFFL));
        buffer.append((byte) ((longValue >> 48) & 0xFFL));
        buffer.append((byte) ((longValue >> 40) & 0xFFL));
        buffer.append((byte) ((longValue >> 32) & 0xFFL));
        buffer.append((byte) ((longValue >> 24) & 0xFFL));
        buffer.append((byte) ((longValue >> 16) & 0xFFL));
        buffer.append((byte) ((longValue >> 8) & 0xFFL));
        buffer.append((byte) (longValue & 0xFFL));
      }
    }
    else
    {
      if ((longValue & 0x0000_0000_0000_007FL) == longValue)
      {
        buffer.append((byte) 0x01);
        buffer.append((byte) (longValue & 0x7FL));
      }
      else if ((longValue & 0x0000_0000_0000_7FFFL) == longValue)
      {
        buffer.append((byte) 0x02);
        buffer.append((byte) ((longValue >> 8) & 0x7FL));
        buffer.append((byte) (longValue & 0xFFL));
      }
      else if ((longValue & 0x0000_0000_007F_FFFFL) == longValue)
      {
        buffer.append((byte) 0x03);
        buffer.append((byte) ((longValue >> 16) & 0x7FL));
        buffer.append((byte) ((longValue >> 8) & 0xFFL));
        buffer.append((byte) (longValue & 0xFFL));
      }
      else if ((longValue & 0x0000_0000_7FFF_FFFFL) == longValue)
      {
        buffer.append((byte) 0x04);
        buffer.append((byte) ((longValue >> 24) & 0x7FL));
        buffer.append((byte) ((longValue >> 16) & 0xFFL));
        buffer.append((byte) ((longValue >> 8) & 0xFFL));
        buffer.append((byte) (longValue & 0xFFL));
      }
      else if ((longValue & 0x0000_007F_FFFF_FFFFL) == longValue)
      {
        buffer.append((byte) 0x05);
        buffer.append((byte) ((longValue >> 32) & 0x7FL));
        buffer.append((byte) ((longValue >> 24) & 0xFFL));
        buffer.append((byte) ((longValue >> 16) & 0xFFL));
        buffer.append((byte) ((longValue >> 8) & 0xFFL));
        buffer.append((byte) (longValue & 0xFFL));
      }
      else if ((longValue & 0x0000_7FFF_FFFF_FFFFL) == longValue)
      {
        buffer.append((byte) 0x06);
        buffer.append((byte) ((longValue >> 40) & 0x7FL));
        buffer.append((byte) ((longValue >> 32) & 0xFFL));
        buffer.append((byte) ((longValue >> 24) & 0xFFL));
        buffer.append((byte) ((longValue >> 16) & 0xFFL));
        buffer.append((byte) ((longValue >> 8) & 0xFFL));
        buffer.append((byte) (longValue & 0xFFL));
      }
      else if ((longValue & 0x007F_FFFF_FFFF_FFFFL) == longValue)
      {
        buffer.append((byte) 0x07);
        buffer.append((byte) ((longValue >> 48) & 0x7FL));
        buffer.append((byte) ((longValue >> 40) & 0xFFL));
        buffer.append((byte) ((longValue >> 32) & 0xFFL));
        buffer.append((byte) ((longValue >> 24) & 0xFFL));
        buffer.append((byte) ((longValue >> 16) & 0xFFL));
        buffer.append((byte) ((longValue >> 8) & 0xFFL));
        buffer.append((byte) (longValue & 0xFFL));
      }
      else
      {
        buffer.append((byte) 0x08);
        buffer.append((byte) ((longValue >> 56) & 0x7FL));
        buffer.append((byte) ((longValue >> 48) & 0xFFL));
        buffer.append((byte) ((longValue >> 40) & 0xFFL));
        buffer.append((byte) ((longValue >> 32) & 0xFFL));
        buffer.append((byte) ((longValue >> 24) & 0xFFL));
        buffer.append((byte) ((longValue >> 16) & 0xFFL));
        buffer.append((byte) ((longValue >> 8) & 0xFFL));
        buffer.append((byte) (longValue & 0xFFL));
      }
    }
  }



  /**
   * Adds an integer element to this ASN.1 buffer using the default BER type.
   *
   * @param  value  The value to use for the integer element.  It must not be
   *                {@code null}.
   */
  public void addInteger(@NotNull final BigInteger value)
  {
    addInteger(ASN1Constants.UNIVERSAL_INTEGER_TYPE, value);
  }



  /**
   * Adds an integer element to this ASN.1 buffer using the provided BER type.
   *
   * @param  type   The BER type to use for the integer element.
   * @param  value  The value to use for the integer element.  It must not be
   *                {@code null}.
   */
  public void addInteger(final byte type, @NotNull final BigInteger value)
  {
    buffer.append(type);

    final byte[] valueBytes = value.toByteArray();
    ASN1Element.encodeLengthTo(valueBytes.length, buffer);
    buffer.append(valueBytes);
  }



  /**
   * Adds a null element to this ASN.1 buffer using the default BER type.
   */
  public void addNull()
  {
    addNull(ASN1Constants.UNIVERSAL_NULL_TYPE);
  }



  /**
   * Adds a null element to this ASN.1 buffer using the provided BER type.
   *
   * @param  type  The BER type to use for the null element.
   */
  public void addNull(final byte type)
  {
    buffer.append(type);
    buffer.append((byte) 0x00);
  }



  /**
   * Adds an octet string element to this ASN.1 buffer using the default BER
   * type and no value.
   */
  public void addOctetString()
  {
    addOctetString(ASN1Constants.UNIVERSAL_OCTET_STRING_TYPE);
  }



  /**
   * Adds an octet string element to this ASN.1 buffer using the provided BER
   * type and no value.
   *
   * @param  type  The BER type to use for the octet string element.
   */
  public void addOctetString(final byte type)
  {
    buffer.append(type);
    buffer.append((byte) 0x00);
  }



  /**
   * Adds an octet string element to this ASN.1 buffer using the default BER
   * type.
   *
   * @param  value  The value to use for the octet string element.
   */
  public void addOctetString(@Nullable final byte[] value)
  {
    addOctetString(ASN1Constants.UNIVERSAL_OCTET_STRING_TYPE, value);
  }



  /**
   * Adds an octet string element to this ASN.1 buffer using the default BER
   * type.
   *
   * @param  value  The value to use for the octet string element.
   */
  public void addOctetString(@Nullable final CharSequence value)
  {
    if (value == null)
    {
      addOctetString(ASN1Constants.UNIVERSAL_OCTET_STRING_TYPE);
    }
    else
    {
      addOctetString(ASN1Constants.UNIVERSAL_OCTET_STRING_TYPE,
                     value.toString());
    }
  }



  /**
   * Adds an octet string element to this ASN.1 buffer using the default BER
   * type.
   *
   * @param  value  The value to use for the octet string element.
   */
  public void addOctetString(@Nullable final String value)
  {
    addOctetString(ASN1Constants.UNIVERSAL_OCTET_STRING_TYPE, value);
  }



  /**
   * Adds an octet string element to this ASN.1 buffer using the provided BER
   * type.
   *
   * @param  type   The BER type to use for the octet string element.
   * @param  value  The value to use for the octet string element.
   */
  public void addOctetString(final byte type, @Nullable final byte[] value)
  {
    buffer.append(type);

    if (value == null)
    {
      buffer.append((byte) 0x00);
    }
    else
    {
      ASN1Element.encodeLengthTo(value.length, buffer);
      buffer.append(value);
    }
  }



  /**
   * Adds an octet string element to this ASN.1 buffer using the provided BER
   * type.
   *
   * @param  type   The BER type to use for the octet string element.
   * @param  value  The value to use for the octet string element.
   */
  public void addOctetString(final byte type,
                             @Nullable final CharSequence value)
  {
    if (value == null)
    {
      addOctetString(type);
    }
    else
    {
      addOctetString(type, value.toString());
    }
  }



  /**
   * Adds an octet string element to this ASN.1 buffer using the provided BER
   * type.
   *
   * @param  type   The BER type to use for the octet string element.
   * @param  value  The value to use for the octet string element.
   */
  public void addOctetString(final byte type, @Nullable final String value)
  {
    buffer.append(type);

    if (value == null)
    {
      buffer.append((byte) 0x00);
    }
    else
    {
      // We'll assume that the string contains only ASCII characters and
      // therefore the number of bytes will equal the number of characters.
      // However, save the position in case we're wrong and need to re-encode.
      final int lengthStartPos = buffer.length();
      ASN1Element.encodeLengthTo(value.length(), buffer);

      final int valueStartPos = buffer.length();
      buffer.append(value);

      if (buffer.length() != (valueStartPos + value.length()))
      {
        final byte[] valueBytes = new byte[buffer.length() - valueStartPos];
        System.arraycopy(buffer.getBackingArray(), valueStartPos, valueBytes, 0,
                         valueBytes.length);

        buffer.setLength(lengthStartPos);
        ASN1Element.encodeLengthTo(valueBytes.length, buffer);
        buffer.append(valueBytes);
      }
    }
  }



  /**
   * Adds a UTC time element to this ASN.1 buffer using the default BER type.
   *
   * @param  date  The date value that specifies the time to represent.  This
   *               must not be {@code null}.
   */
  public void addUTCTime(@NotNull final Date date)
  {
    addUTCTime(date.getTime());
  }



  /**
   * Adds a UTC time element to this ASN.1 buffer using the provided BER type.
   *
   * @param  type  The BER type to use for the UTC time element.
   * @param  date  The date value that specifies the time to represent.  This
   *               must not be {@code null}.
   */
  public void addUTCTime(final byte type, @NotNull final Date date)
  {
    addUTCTime(type, date.getTime());
  }



  /**
   * Adds a UTC time element to this ASN.1 buffer using the default BER type.
   *
   * @param  time  The time to represent.  This must be expressed in
   *               milliseconds since the epoch (the same format used by
   *               {@code System.currentTimeMillis()} and
   *               {@code Date.getTime()}).
   */
  public void addUTCTime(final long time)
  {
    addUTCTime(ASN1Constants.UNIVERSAL_UTC_TIME_TYPE, time);
  }



  /**
   * Adds a UTC time element to this ASN.1 buffer using the provided BER type.
   *
   * @param  type  The BER type to use for the UTC time element.
   * @param  time  The time to represent.  This must be expressed in
   *               milliseconds since the epoch (the same format used by
   *               {@code System.currentTimeMillis()} and
   *               {@code Date.getTime()}).
   */
  public void addUTCTime(final byte type, final long time)
  {
    buffer.append(type);

    final String timestamp = ASN1UTCTime.encodeTimestamp(time);
    ASN1Element.encodeLengthTo(timestamp.length(), buffer);
    buffer.append(timestamp);
  }



  /**
   * Begins adding elements to an ASN.1 sequence using the default BER type.
   *
   * @return  An object that may be used to indicate when the end of the
   *          sequence has been reached.  Once all embedded sequence elements
   *          have been added, then the {@link ASN1BufferSequence#end} method
   *          MUST be called to ensure that the sequence is properly encoded.
   */
  @NotNull()
  public ASN1BufferSequence beginSequence()
  {
    return beginSequence(ASN1Constants.UNIVERSAL_SEQUENCE_TYPE);
  }



  /**
   * Begins adding elements to an ASN.1 sequence using the provided BER type.
   *
   * @param  type  The BER type to use for the sequence.
   *
   * @return  An object that may be used to indicate when the end of the
   *          sequence has been reached.  Once all embedded sequence elements
   *          have been added, then the {@link ASN1BufferSequence#end} method
   *          MUST be called to ensure that the sequence is properly encoded.
   */
  @NotNull()
  public ASN1BufferSequence beginSequence(final byte type)
  {
    buffer.append(type);
    return new ASN1BufferSequence(this);
  }



  /**
   * Begins adding elements to an ASN.1 set using the default BER type.
   *
   * @return  An object that may be used to indicate when the end of the set has
   *          been reached.  Once all embedded set elements have been added,
   *          then the {@link ASN1BufferSet#end} method MUST be called to ensure
   *          that the set is properly encoded.
   */
  @NotNull()
  public ASN1BufferSet beginSet()
  {
    return beginSet(ASN1Constants.UNIVERSAL_SET_TYPE);
  }



  /**
   * Begins adding elements to an ASN.1 set using the provided BER type.
   *
   * @param  type  The BER type to use for the set.
   *
   * @return  An object that may be used to indicate when the end of the set has
   *          been reached.  Once all embedded set elements have been added,
   *          then the {@link ASN1BufferSet#end} method MUST be called to ensure
   *          that the set is properly encoded.
   */
  @NotNull()
  public ASN1BufferSet beginSet(final byte type)
  {
    buffer.append(type);
    return new ASN1BufferSet(this);
  }



  /**
   * Ensures that the appropriate length is inserted into the internal buffer
   * after all elements in a sequence or set have been added.
   *
   * @param  valueStartPos  The position in which the first value was added.
   */
  void endSequenceOrSet(final int valueStartPos)
  {
    final int length = buffer.length() - valueStartPos;
    if (length == 0)
    {
      buffer.append((byte) 0x00);
      return;
    }

    if ((length & 0x7F) == length)
    {
      buffer.insert(valueStartPos, (byte) length);
    }
    else if ((length & 0xFF) == length)
    {
      buffer.insert(valueStartPos, MULTIBYTE_LENGTH_HEADER_PLUS_ONE);

      final byte[] backingArray = buffer.getBackingArray();
      backingArray[valueStartPos+1] = (byte) (length & 0xFF);
    }
    else if ((length & 0xFFFF) == length)
    {
      buffer.insert(valueStartPos, MULTIBYTE_LENGTH_HEADER_PLUS_TWO);

      final byte[] backingArray = buffer.getBackingArray();
      backingArray[valueStartPos+1] = (byte) ((length >> 8) & 0xFF);
      backingArray[valueStartPos+2] = (byte) (length & 0xFF);
    }
    else if ((length & 0x00FF_FFFF) == length)
    {
      buffer.insert(valueStartPos, MULTIBYTE_LENGTH_HEADER_PLUS_THREE);

      final byte[] backingArray = buffer.getBackingArray();
      backingArray[valueStartPos+1] = (byte) ((length >> 16) & 0xFF);
      backingArray[valueStartPos+2] = (byte) ((length >> 8) & 0xFF);
      backingArray[valueStartPos+3] = (byte) (length & 0xFF);
    }
    else
    {
      buffer.insert(valueStartPos, MULTIBYTE_LENGTH_HEADER_PLUS_FOUR);

      final byte[] backingArray = buffer.getBackingArray();
      backingArray[valueStartPos+1] = (byte) ((length >> 24) & 0xFF);
      backingArray[valueStartPos+2] = (byte) ((length >> 16) & 0xFF);
      backingArray[valueStartPos+3] = (byte) ((length >> 8) & 0xFF);
      backingArray[valueStartPos+4] = (byte) (length & 0xFF);
    }
  }



  /**
   * Writes the contents of this buffer to the provided output stream.
   *
   * @param  outputStream  The output stream to which the data should be
   *                       written.
   *
   * @throws  IOException  If a problem occurs while writing to the provided
   *                       output stream.
   */
  public void writeTo(@NotNull final OutputStream outputStream)
         throws IOException
  {
    if (Debug.debugEnabled(DebugType.ASN1))
    {
      Debug.debugASN1Write(this);
    }

    buffer.write(outputStream);
  }



  /**
   * Retrieves a byte array containing the contents of this ASN.1 buffer.
   *
   * @return  A byte array containing the contents of this ASN.1 buffer.
   */
  @NotNull()
  public byte[] toByteArray()
  {
    return buffer.toByteArray();
  }



  /**
   * Retrieves a byte buffer that wraps the data associated with this ASN.1
   * buffer.  The position will be set to the beginning of the data, and the
   * limit will be set to one byte after the end of the data.  The contents
   * of the returned byte buffer must not be altered in any way, and the
   * contents of this ASN.1 buffer must not be altered until the
   * {@code ByteBuffer} is no longer needed.
   *
   * @return  A byte buffer that wraps the data associated with this ASN.1
   *          buffer.
   */
  @NotNull()
  public ByteBuffer asByteBuffer()
  {
    return ByteBuffer.wrap(buffer.getBackingArray(), 0, buffer.length());
  }
}
