/*
 * Copyright 2017-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2025 Ping Identity Corporation
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
 * Copyright (C) 2017-2025 Ping Identity Corporation
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



import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.asn1.ASN1Messages.*;



/**
 * This class provides an ASN.1 UTF-8 string element that can hold any string
 * value that can be represented in the UTF-8 encoding.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ASN1UTF8String
       extends ASN1Element
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2147537370903003997L;



  // The string value for this element.
  @NotNull private final String stringValue;



  /**
   * Creates a new ASN.1 UTF-8 string element with the default BER type and the
   * provided value.
   *
   * @param  stringValue  The string value to use for this element.  It may be
   *                      {@code null} or empty if the value should be empty.
   */
  public ASN1UTF8String(@Nullable final String stringValue)
  {
    this(ASN1Constants.UNIVERSAL_UTF_8_STRING_TYPE, stringValue);
  }



  /**
   * Creates a new ASN.1 UTF-8 string element with the specified BER type and
   * the provided value.
   *
   * @param  type         The BER type for this element.
   * @param  stringValue  The string value to use for this element.  It may be
   *                      {@code null} or empty if the value should be empty.
   */
  public ASN1UTF8String(final byte type, @Nullable final String stringValue)
  {
    this(type, stringValue, StaticUtils.getBytes(stringValue));
  }



  /**
   * Creates a new ASN.1 UTF-8 string element with the specified BER type and
   * the provided value.
   *
   * @param  type          The BER type for this element.
   * @param  stringValue   The string value to use for this element.  It may be
   *                       {@code null} or empty if the value should be empty.
   * @param  encodedValue  The encoded representation of the value.
   */
  private ASN1UTF8String(final byte type, @Nullable final String stringValue,
                         @NotNull final byte[] encodedValue)
  {
    super(type, encodedValue);

    if (stringValue == null)
    {
      this.stringValue = "";
    }
    else
    {
      this.stringValue = stringValue;
    }
  }



  /**
   * Retrieves the string value for this element.
   *
   * @return  The string value for this element.
   */
  @NotNull()
  public String stringValue()
  {
    return stringValue;
  }



  /**
   * Decodes the contents of the provided byte array as a UTF-8 string element.
   *
   * @param  elementBytes  The byte array to decode as an ASN.1 UTF-8 string
   *                       element.
   *
   * @return  The decoded ASN.1 UTF-8 string element.
   *
   * @throws  ASN1Exception  If the provided array cannot be decoded as a UTF-8
   *                         string element.
   */
  @NotNull()
  public static ASN1UTF8String decodeAsUTF8String(
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

      if (! StaticUtils.isValidUTF8(elementValue))
      {
        throw new ASN1Exception(ERR_UTF_8_STRING_DECODE_VALUE_NOT_UTF_8.get());
      }

      return new ASN1UTF8String(elementBytes[0],
           StaticUtils.toUTF8String(elementValue), elementValue);
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
   * Decodes the provided ASN.1 element as a UTF-8 string element.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The decoded ASN.1 UTF-8 string element.
   *
   * @throws  ASN1Exception  If the provided element cannot be decoded as a
   *                         UTF-8 string element.
   */
  @NotNull()
  public static ASN1UTF8String decodeAsUTF8String(
                                    @NotNull final ASN1Element element)
         throws ASN1Exception
  {
    final byte[] elementValue = element.getValue();
    if (! StaticUtils.isValidUTF8(elementValue))
    {
      throw new ASN1Exception(ERR_UTF_8_STRING_DECODE_VALUE_NOT_UTF_8.get());
    }

    return new ASN1UTF8String(element.getType(),
         StaticUtils.toUTF8String(elementValue), elementValue);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append(stringValue);
  }
}
