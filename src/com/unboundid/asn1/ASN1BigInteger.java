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



import java.math.BigInteger;

import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.asn1.ASN1Messages.*;



/**
 * This class provides an ASN.1 integer element that is backed by a Java
 * {@code BigInteger} and whose value can be represented as an integer of any
 * magnitude.  For an ASN.1 integer implementation that is backed by a signed
 * 32-bit {@code int}, see {@link ASN1Integer}.  For an implementation that is
 * backed by a signed 64-bit {@code long}, see {@link ASN1Long}.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ASN1BigInteger
       extends ASN1Element
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2631806934961821260L;



  // The BigInteger value for this element.
  @NotNull private final BigInteger value;



  /**
   * Creates a new ASN.1 big integer element with the default BER type and the
   * provided value.
   *
   * @param  value  The value to use for this element.  It must not be
   *                {@code null}.
   */
  public ASN1BigInteger(@NotNull final BigInteger value)
  {
    this(ASN1Constants.UNIVERSAL_INTEGER_TYPE, value);
  }



  /**
   * Creates a new ASN.1 big integer element with the specified BER type and the
   * provided value.
   *
   * @param  type   The BER type to use for this element.
   * @param  value  The value to use for this element.  It must not be
   *                {@code null}.
   */
  public ASN1BigInteger(final byte type, @NotNull final BigInteger value)
  {
    super(type, value.toByteArray());

    this.value = value;
  }



  /**
   * Creates a new ASN.1 big integer element with the specified BER type and the
   * provided value.
   *
   * @param  type             The BER type to use for this element.
   * @param  bigIntegerValue  The value to use for this element.  It must not be
   *                          {@code null}.
   * @param  berValue         The encoded BER value for this element.  It must
   *                          not be {@code null} or empty.
   */
  private ASN1BigInteger(final byte type,
                         @NotNull final BigInteger bigIntegerValue,
                         @NotNull final byte[] berValue)
  {
    super(type, berValue);
    value = bigIntegerValue;
  }



  /**
   * Creates a new ASN.1 big integer element with the default BER type and the
   * provided long value.
   *
   * @param  value  The int value to use for this element.
   */
  public ASN1BigInteger(final long value)
  {
    this(ASN1Constants.UNIVERSAL_INTEGER_TYPE, BigInteger.valueOf(value));
  }



  /**
   * Creates a new ASN.1 big integer element with the specified BER type and the
   * provided long value.
   *
   * @param  type   The BER type to use for this element.
   * @param  value  The int value to use for this element.
   */
  public ASN1BigInteger(final byte type, final long value)
  {
    this(type, BigInteger.valueOf(value));
  }



  /**
   * Retrieves the value for this element as a Java {@code BigInteger}.
   *
   * @return  The value for this element as a Java {@code BigInteger}.
   */
  @NotNull()
  public BigInteger getBigIntegerValue()
  {
    return value;
  }



  /**
   * Decodes the contents of the provided byte array as a big integer element.
   *
   * @param  elementBytes  The byte array to decode as an ASN.1 big integer
   *                       element.
   *
   * @return  The decoded ASN.1 big integer element.
   *
   * @throws  ASN1Exception  If the provided array cannot be decoded as a big
   *                         integer element.
   */
  @NotNull()
  public static ASN1BigInteger decodeAsBigInteger(
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

      if (length == 0)
      {
        throw new ASN1Exception(ERR_BIG_INTEGER_DECODE_EMPTY_VALUE.get());
      }

      final byte[] elementValue = new byte[length];
      System.arraycopy(elementBytes, valueStartPos, elementValue, 0, length);

      final BigInteger bigIntegerValue = new BigInteger(elementValue);
      return new ASN1BigInteger(elementBytes[0], bigIntegerValue, elementValue);
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
   * Decodes the provided ASN.1 element as a big integer element.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The decoded ASN.1 big integer element.
   *
   * @throws  ASN1Exception  If the provided element cannot be decoded as a big
   *                         integer element.
   */
  @NotNull()
  public static ASN1BigInteger decodeAsBigInteger(
                                    @NotNull final ASN1Element element)
         throws ASN1Exception
  {
    final byte[] value = element.getValue();
    if (value.length == 0)
    {
      throw new ASN1Exception(ERR_BIG_INTEGER_DECODE_EMPTY_VALUE.get());
    }

    return new ASN1BigInteger(element.getType(), new BigInteger(value), value);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append(value);
  }
}
