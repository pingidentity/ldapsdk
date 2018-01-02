/*
 * Copyright 2017-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017-2018 Ping Identity Corporation
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



import com.unboundid.util.NotMutable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.asn1.ASN1Constants.*;
import static com.unboundid.asn1.ASN1Messages.*;
import static com.unboundid.util.Debug.*;



/**
 * This class provides an ASN.1 numeric string element that can hold any
 * empty or non-empty string comprised only of the ASCII numeric digits '0'
 * through '9' and the ASCII space.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ASN1NumericString
       extends ASN1Element
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3972798266250943461L;



  // The string value for this element.
  private final String stringValue;



  /**
   * Creates a new ASN.1 numeric string element with the default BER type and
   * the provided value.
   *
   * @param  stringValue  The string value to use for this element.  It may be
   *                      {@code null} or empty if the value should be empty.
   *                      It must only contain ASCII digit and space characters.
   *
   * @throws  ASN1Exception  If the provided string does not represent a valid
   *                         numeric string.
   */
  public ASN1NumericString(final String stringValue)
         throws ASN1Exception
  {
    this(UNIVERSAL_NUMERIC_STRING_TYPE, stringValue);
  }



  /**
   * Creates a new ASN.1 numeric string element with the specified BER type
   * and the provided value.
   *
   * @param  type         The BER type for this element.
   * @param  stringValue  The string value to use for this element.  It may be
   *                      {@code null} or empty if the value should be empty.
   *                      It must only contain ASCII digit and space characters.
   *
   * @throws  ASN1Exception  If the provided string does not represent a valid
   *                         numeric string.
   */
  public ASN1NumericString(final byte type, final String stringValue)
         throws ASN1Exception
  {
    this(type, stringValue, StaticUtils.getBytes(stringValue));
  }



  /**
   * Creates a new ASN.1 numeric string element with the specified BER type
   * and the provided value.
   *
   * @param  type          The BER type for this element.
   * @param  stringValue   The string value to use for this element.  It may be
   *                       {@code null} or empty if the value should be empty.
   *                       It must only contain ASCII digit and space
   *                       characters.
   * @param  encodedValue  The bytes that comprise the encoded element value.
   *
   * @throws  ASN1Exception  If the provided string does not represent a valid
   *                         numeric string.
   */
  private ASN1NumericString(final byte type, final String stringValue,
                            final byte[] encodedValue)
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
      for (final char c : stringValue.toCharArray())
      {
        if ((c >= '0') && (c <= '9'))
        {
          // ASCII digits are allowed in numeric strings.
        }
        else if (c == ' ')
        {
          // The space is allowed in numeric strings.
        }
        else
        {
          throw new ASN1Exception(
               ERR_NUMERIC_STRING_DECODE_VALUE_NOT_NUMERIC.get());
        }
      }
    }
  }



  /**
   * Retrieves the string value for this element.
   *
   * @return  The string value for this element.
   */
  public String stringValue()
  {
    return stringValue;
  }



  /**
   * Decodes the contents of the provided byte array as a numeric string
   * element.
   *
   * @param  elementBytes  The byte array to decode as an ASN.1 numeric string
   *                       element.
   *
   * @return  The decoded ASN.1 numeric string element.
   *
   * @throws  ASN1Exception  If the provided array cannot be decoded as a
   *                         numeric string element.
   */
  public static ASN1NumericString decodeAsNumericString(
                                       final byte[] elementBytes)
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

      return new ASN1NumericString(elementBytes[0],
           StaticUtils.toUTF8String(elementValue), elementValue);
    }
    catch (final ASN1Exception ae)
    {
      debugException(ae);
      throw ae;
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new ASN1Exception(ERR_ELEMENT_DECODE_EXCEPTION.get(e), e);
    }
  }



  /**
   * Decodes the provided ASN.1 element as a numeric string element.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The decoded ASN.1 numeric string element.
   *
   * @throws  ASN1Exception  If the provided element cannot be decoded as a
   *                         numeric string element.
   */
  public static ASN1NumericString decodeAsNumericString(
                                       final ASN1Element element)
         throws ASN1Exception
  {
    final byte[] elementValue = element.getValue();
    return new ASN1NumericString(element.getType(),
         StaticUtils.toUTF8String(elementValue), elementValue);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append(stringValue);
  }
}
