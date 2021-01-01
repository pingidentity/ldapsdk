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



import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.asn1.ASN1Messages.*;



/**
 * This class provides an ASN.1 printable string element that can hold any
 * empty or non-empty string comprised only of the characters listed below.
 * <UL>
 *   <LI>The uppercase ASCII letters A through Z.</LI>
 *   <LI>The lowercase ASCII letters a through z.</LI>
 *   <LI>The ASCII digits 0 through 9.</LI>
 *   <LI>The ASCII space.</LI>
 *   <LI>The ASCII apostrophe (aka single quote).</LI>
 *   <LI>The ASCII left parenthesis.</LI>
 *   <LI>The ASCII right parenthesis.</LI>
 *   <LI>The ASCII plus sign.</LI>
 *   <LI>The ASCII comma.</LI>
 *   <LI>The ASCII minus sign (aka hyphen).</LI>
 *   <LI>The ASCII period (aka full stop).</LI>
 *   <LI>The ASCII forward slash (aka solidus).</LI>
 *   <LI>The ASCII colon.</LI>
 *   <LI>The ASCII equal sign.</LI>
 *   <LI>The ASCII question mark.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ASN1PrintableString
       extends ASN1Element
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7489436088285132189L;



  // The string value for this element.
  @NotNull private final String stringValue;



  /**
   * Creates a new ASN.1 printable string element with the default BER type and
   * the provided value.
   *
   * @param  stringValue  The string value to use for this element.  It may be
   *                      {@code null} or empty if the value should be empty.
   *                      It must only contain characters allowed in printable
   *                      strings.
   *
   * @throws  ASN1Exception  If the provided string does not represent a valid
   *                         printable string.
   */
  public ASN1PrintableString(@Nullable final String stringValue)
         throws ASN1Exception
  {
    this(ASN1Constants.UNIVERSAL_PRINTABLE_STRING_TYPE, stringValue);
  }



  /**
   * Creates a new ASN.1 printable string element with the specified BER type
   * and the provided value.
   *
   * @param  type         The BER type for this element.
   * @param  stringValue  The string value to use for this element.  It may be
   *                      {@code null} or empty if the value should be empty.
   *                      It must only contain characters allowed in printable
   *                      strings.
   *
   * @throws  ASN1Exception  If the provided string does not represent a valid
   *                         printable string.
   */
  public ASN1PrintableString(final byte type,
                             @Nullable final String stringValue)
         throws ASN1Exception
  {
    this(type, stringValue, StaticUtils.getBytes(stringValue));
  }



  /**
   * Creates a new ASN.1 printable string element with the specified BER type
   * and the provided value.
   *
   * @param  type          The BER type for this element.
   * @param  stringValue   The string value to use for this element.  It may be
   *                       {@code null} or empty if the value should be empty.
   *                       It must only contain characters allowed in printable
   *                       strings.
   * @param  encodedValue  The bytes that comprise the encoded element value.
   *
   * @throws  ASN1Exception  If the provided string does not represent a valid
   *                         printable string.
   */
  private ASN1PrintableString(final byte type,
                              @Nullable final String stringValue,
                              @NotNull final byte[] encodedValue)
          throws ASN1Exception
  {
    super(type, encodedValue);

    if (stringValue == null)
    {
      this.stringValue = "";
    }
    else
    {
      this.stringValue = stringValue;
      if (! StaticUtils.isPrintableString(encodedValue))
      {
        throw new ASN1Exception(
             ERR_PRINTABLE_STRING_DECODE_VALUE_NOT_PRINTABLE.get());
      }
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
   * Decodes the contents of the provided byte array as a printable string
   * element.
   *
   * @param  elementBytes  The byte array to decode as an ASN.1 printable string
   *                       element.
   *
   * @return  The decoded ASN.1 printable string element.
   *
   * @throws  ASN1Exception  If the provided array cannot be decoded as a
   *                         printable string element.
   */
  @NotNull()
  public static ASN1PrintableString decodeAsPrintableString(
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

      return new ASN1PrintableString(elementBytes[0],
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
   * Decodes the provided ASN.1 element as a printable string element.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The decoded ASN.1 printable string element.
   *
   * @throws  ASN1Exception  If the provided element cannot be decoded as a
   *                         printable string element.
   */
  @NotNull()
  public static ASN1PrintableString decodeAsPrintableString(
                                         @NotNull final ASN1Element element)
         throws ASN1Exception
  {
    final byte[] elementValue = element.getValue();
    return new ASN1PrintableString(element.getType(),
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
