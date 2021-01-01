/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.asn1.ASN1Messages.*;



/**
 * This class provides an ASN.1 integer element that is backed by a Java
 * {@code long}, which is a signed 64-bit value and can represent any integer
 * between -9223372036854775808 and 9223372036854775807.  If you need support
 * for integer values of arbitrary size, see the {@link ASN1BigInteger} class as
 * an alternative.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ASN1Long
       extends ASN1Element
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3445506299288414013L;



  // The long value for this element.
  private final long longValue;



  /**
   * Creates a new ASN.1 long element with the default BER type and the
   * provided long value.
   *
   * @param  longValue  The long value to use for this element.
   */
  public ASN1Long(final long longValue)
  {
    super(ASN1Constants.UNIVERSAL_INTEGER_TYPE, encodeLongValue(longValue));

    this.longValue = longValue;
  }



  /**
   * Creates a new ASN.1 long element with the specified BER type and the
   * provided long value.
   *
   * @param  type       The BER type to use for this element.
   * @param  longValue  The long value to use for this element.
   */
  public ASN1Long(final byte type, final long longValue)
  {
    super(type, encodeLongValue(longValue));

    this.longValue = longValue;
  }



  /**
   * Creates a new ASN.1 long element with the specified BER type and the
   * provided long and pre-encoded values.
   *
   * @param  type       The BER type to use for this element.
   * @param  longValue  The long value to use for this element.
   * @param  value      The pre-encoded value to use for this element.
   */
  private ASN1Long(final byte type, final long longValue,
                   @NotNull final byte[] value)
  {
    super(type, value);

    this.longValue = longValue;
  }



  /**
   * Encodes the provided long value to a byte array suitable for use as the
   * value of a long element.
   *
   * @param  longValue  The long value to be encoded.
   *
   * @return  A byte array containing the encoded value.
   */
  @NotNull()
  static byte[] encodeLongValue(final long longValue)
  {
    if (longValue < 0)
    {
      if ((longValue & 0xFFFF_FFFF_FFFF_FF80L) == 0xFFFF_FFFF_FFFF_FF80L)
      {
        return new byte[]
        {
          (byte) (longValue & 0xFFL)
        };
      }
      else if ((longValue & 0xFFFF_FFFF_FFFF_8000L) == 0xFFFF_FFFF_FFFF_8000L)
      {
        return new byte[]
        {
          (byte) ((longValue >> 8) & 0xFFL),
          (byte) (longValue & 0xFFL)
        };
      }
      else if ((longValue & 0xFFFF_FFFF_FF80_0000L) == 0xFFFF_FFFF_FF80_0000L)
      {
        return new byte[]
        {
          (byte) ((longValue >> 16) & 0xFFL),
          (byte) ((longValue >> 8) & 0xFFL),
          (byte) (longValue & 0xFFL)
        };
      }
      else if ((longValue & 0xFFFF_FFFF_8000_0000L) == 0xFFFF_FFFF_8000_0000L)
      {
        return new byte[]
        {
          (byte) ((longValue >> 24) & 0xFFL),
          (byte) ((longValue >> 16) & 0xFFL),
          (byte) ((longValue >> 8) & 0xFFL),
          (byte) (longValue & 0xFFL)
        };
      }
      else if ((longValue & 0xFFFF_FF80_0000_0000L) == 0xFFFF_FF80_0000_0000L)
      {
        return new byte[]
        {
          (byte) ((longValue >> 32) & 0xFFL),
          (byte) ((longValue >> 24) & 0xFFL),
          (byte) ((longValue >> 16) & 0xFFL),
          (byte) ((longValue >> 8) & 0xFFL),
          (byte) (longValue & 0xFFL)
        };
      }
      else if ((longValue & 0xFFFF_8000_0000_0000L) == 0xFFFF_8000_0000_0000L)
      {
        return new byte[]
        {
          (byte) ((longValue >> 40) & 0xFFL),
          (byte) ((longValue >> 32) & 0xFFL),
          (byte) ((longValue >> 24) & 0xFFL),
          (byte) ((longValue >> 16) & 0xFFL),
          (byte) ((longValue >> 8) & 0xFFL),
          (byte) (longValue & 0xFFL)
        };
      }
      else if ((longValue & 0xFF80_0000_0000_0000L) == 0xFF80_0000_0000_0000L)
      {
        return new byte[]
        {
          (byte) ((longValue >> 48) & 0xFFL),
          (byte) ((longValue >> 40) & 0xFFL),
          (byte) ((longValue >> 32) & 0xFFL),
          (byte) ((longValue >> 24) & 0xFFL),
          (byte) ((longValue >> 16) & 0xFFL),
          (byte) ((longValue >> 8) & 0xFFL),
          (byte) (longValue & 0xFFL)
        };
      }
      else
      {
        return new byte[]
        {
          (byte) ((longValue >> 56) & 0xFFL),
          (byte) ((longValue >> 48) & 0xFFL),
          (byte) ((longValue >> 40) & 0xFFL),
          (byte) ((longValue >> 32) & 0xFFL),
          (byte) ((longValue >> 24) & 0xFFL),
          (byte) ((longValue >> 16) & 0xFFL),
          (byte) ((longValue >> 8) & 0xFFL),
          (byte) (longValue & 0xFFL)
        };
      }
    }
    else
    {
      if ((longValue & 0x0000_0000_0000_007FL) == longValue)
      {
        return new byte[]
        {
          (byte) (longValue & 0x7FL)
        };
      }
      else if ((longValue & 0x0000_0000_0000_7FFFL) == longValue)
      {
        return new byte[]
        {
          (byte) ((longValue >> 8) & 0x7FL),
          (byte) (longValue & 0xFFL)
        };
      }
      else if ((longValue & 0x0000_0000_007F_FFFFL) == longValue)
      {
        return new byte[]
        {
          (byte) ((longValue >> 16) & 0x7FL),
          (byte) ((longValue >> 8) & 0xFFL),
          (byte) (longValue & 0xFFL)
        };
      }
      else if ((longValue & 0x0000_0000_7FFF_FFFFL) == longValue)
      {
        return new byte[]
        {
          (byte) ((longValue >> 24) & 0x7FL),
          (byte) ((longValue >> 16) & 0xFFL),
          (byte) ((longValue >> 8) & 0xFFL),
          (byte) (longValue & 0xFFL)
        };
      }
      else if ((longValue & 0x0000_007F_FFFF_FFFFL) == longValue)
      {
        return new byte[]
        {
          (byte) ((longValue >> 32) & 0x7FL),
          (byte) ((longValue >> 24) & 0xFFL),
          (byte) ((longValue >> 16) & 0xFFL),
          (byte) ((longValue >> 8) & 0xFFL),
          (byte) (longValue & 0xFFL)
        };
      }
      else if ((longValue & 0x0000_7FFF_FFFF_FFFFL) == longValue)
      {
        return new byte[]
        {
          (byte) ((longValue >> 40) & 0x7FL),
          (byte) ((longValue >> 32) & 0xFFL),
          (byte) ((longValue >> 24) & 0xFFL),
          (byte) ((longValue >> 16) & 0xFFL),
          (byte) ((longValue >> 8) & 0xFFL),
          (byte) (longValue & 0xFFL)
        };
      }
      else if ((longValue & 0x007F_FFFF_FFFF_FFFFL) == longValue)
      {
        return new byte[]
        {
          (byte) ((longValue >> 48) & 0x7FL),
          (byte) ((longValue >> 40) & 0xFFL),
          (byte) ((longValue >> 32) & 0xFFL),
          (byte) ((longValue >> 24) & 0xFFL),
          (byte) ((longValue >> 16) & 0xFFL),
          (byte) ((longValue >> 8) & 0xFFL),
          (byte) (longValue & 0xFFL)
        };
      }
      else
      {
        return new byte[]
        {
          (byte) ((longValue >> 56) & 0x7FL),
          (byte) ((longValue >> 48) & 0xFFL),
          (byte) ((longValue >> 40) & 0xFFL),
          (byte) ((longValue >> 32) & 0xFFL),
          (byte) ((longValue >> 24) & 0xFFL),
          (byte) ((longValue >> 16) & 0xFFL),
          (byte) ((longValue >> 8) & 0xFFL),
          (byte) (longValue & 0xFFL)
        };
      }
    }
  }



  /**
   * Retrieves the long value for this element.
   *
   * @return  The long value for this element.
   */
  public long longValue()
  {
    return longValue;
  }



  /**
   * Decodes the contents of the provided byte array as a long element.
   *
   * @param  elementBytes  The byte array to decode as an ASN.1 long element.
   *
   * @return  The decoded ASN.1 long element.
   *
   * @throws  ASN1Exception  If the provided array cannot be decoded as a long
   *                         element.
   */
  @NotNull()
  public static ASN1Long decodeAsLong(@NotNull final byte[] elementBytes)
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

      final byte[] value = new byte[length];
      System.arraycopy(elementBytes, valueStartPos, value, 0, length);

      long longValue;
      switch (value.length)
      {
        case 1:
          longValue = (value[0] & 0xFFL);
          if ((value[0] & 0x80L) != 0x00L)
          {
            longValue |= 0xFFFF_FFFF_FFFF_FF00L;
          }
          break;

        case 2:
          longValue = ((value[0] & 0xFFL) << 8) | (value[1] & 0xFFL);
          if ((value[0] & 0x80L) != 0x00L)
          {
            longValue |= 0xFFFF_FFFF_FFFF_0000L;
          }
          break;

        case 3:
          longValue = ((value[0] & 0xFFL) << 16) | ((value[1] & 0xFFL) << 8) |
                      (value[2] & 0xFFL);
          if ((value[0] & 0x80L) != 0x00L)
          {
            longValue |= 0xFFFF_FFFF_FF00_0000L;
          }
          break;

        case 4:
          longValue = ((value[0] & 0xFFL) << 24) | ((value[1] & 0xFFL) << 16) |
                      ((value[2] & 0xFFL) << 8) | (value[3] & 0xFFL);
          if ((value[0] & 0x80L) != 0x00L)
          {
            longValue |= 0xFFFF_FFFF_0000_0000L;
          }
          break;

        case 5:
          longValue = ((value[0] & 0xFFL) << 32) | ((value[1] & 0xFFL) << 24) |
                      ((value[2] & 0xFFL) << 16) | ((value[3] & 0xFFL) << 8) |
                      (value[4] & 0xFFL);
          if ((value[0] & 0x80L) != 0x00L)
          {
            longValue |= 0xFFFF_FF00_0000_0000L;
          }
          break;

        case 6:
          longValue = ((value[0] & 0xFFL) << 40) | ((value[1] & 0xFFL) << 32) |
                      ((value[2] & 0xFFL) << 24) | ((value[3] & 0xFFL) << 16) |
                      ((value[4] & 0xFFL) << 8) | (value[5] & 0xFFL);
          if ((value[0] & 0x80L) != 0x00L)
          {
            longValue |= 0xFFFF_0000_0000_0000L;
          }
          break;

        case 7:
          longValue = ((value[0] & 0xFFL) << 48) | ((value[1] & 0xFFL) << 40) |
                      ((value[2] & 0xFFL) << 32) | ((value[3] & 0xFFL) << 24) |
                      ((value[4] & 0xFFL) << 16) | ((value[5] & 0xFFL) << 8) |
                      (value[6] & 0xFFL);
          if ((value[0] & 0x80L) != 0x00L)
          {
            longValue |= 0xFF00_0000_0000_0000L;
          }
          break;

        case 8:
          longValue = ((value[0] & 0xFFL) << 56) | ((value[1] & 0xFFL) << 48) |
                      ((value[2] & 0xFFL) << 40) | ((value[3] & 0xFFL) << 32) |
                      ((value[4] & 0xFFL) << 24) | ((value[5] & 0xFFL) << 16) |
                      ((value[6] & 0xFFL) << 8) | (value[7] & 0xFFL);
          break;

        default:
          throw new ASN1Exception(ERR_LONG_INVALID_LENGTH.get(value.length));
      }

      return new ASN1Long(elementBytes[0], longValue, value);
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
   * Decodes the provided ASN.1 element as a long element.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The decoded ASN.1 long element.
   *
   * @throws  ASN1Exception  If the provided element cannot be decoded as a long
   *                         element.
   */
  @NotNull()
  public static ASN1Long decodeAsLong(@NotNull final ASN1Element element)
         throws ASN1Exception
  {
    long longValue;
    final byte[] value = element.getValue();
    switch (value.length)
    {
      case 1:
        longValue = (value[0] & 0xFFL);
        if ((value[0] & 0x80L) != 0x00L)
        {
          longValue |= 0xFFFF_FFFF_FFFF_FF00L;
        }
        break;

      case 2:
        longValue = ((value[0] & 0xFFL) << 8) | (value[1] & 0xFFL);
        if ((value[0] & 0x80L) != 0x00L)
        {
          longValue |= 0xFFFF_FFFF_FFFF_0000L;
        }
        break;

      case 3:
        longValue = ((value[0] & 0xFFL) << 16) | ((value[1] & 0xFFL) << 8) |
                    (value[2] & 0xFFL);
        if ((value[0] & 0x80L) != 0x00L)
        {
          longValue |= 0xFFFF_FFFF_FF00_0000L;
        }
        break;

      case 4:
        longValue = ((value[0] & 0xFFL) << 24) | ((value[1] & 0xFFL) << 16) |
                    ((value[2] & 0xFFL) << 8) | (value[3] & 0xFFL);
        if ((value[0] & 0x80L) != 0x00L)
        {
          longValue |= 0xFFFF_FFFF_0000_0000L;
        }
        break;

      case 5:
        longValue = ((value[0] & 0xFFL) << 32) | ((value[1] & 0xFFL) << 24) |
                    ((value[2] & 0xFFL) << 16) | ((value[3] & 0xFFL) << 8) |
                    (value[4] & 0xFFL);
        if ((value[0] & 0x80L) != 0x00L)
        {
          longValue |= 0xFFFF_FF00_0000_0000L;
        }
        break;

      case 6:
        longValue = ((value[0] & 0xFFL) << 40) | ((value[1] & 0xFFL) << 32) |
                    ((value[2] & 0xFFL) << 24) | ((value[3] & 0xFFL) << 16) |
                    ((value[4] & 0xFFL) << 8) | (value[5] & 0xFFL);
        if ((value[0] & 0x80L) != 0x00L)
        {
          longValue |= 0xFFFF_0000_0000_0000L;
        }
        break;

      case 7:
        longValue = ((value[0] & 0xFFL) << 48) | ((value[1] & 0xFFL) << 40) |
                    ((value[2] & 0xFFL) << 32) | ((value[3] & 0xFFL) << 24) |
                    ((value[4] & 0xFFL) << 16) | ((value[5] & 0xFFL) << 8) |
                    (value[6] & 0xFFL);
        if ((value[0] & 0x80L) != 0x00L)
        {
          longValue |= 0xFF00_0000_0000_0000L;
        }
        break;

      case 8:
        longValue = ((value[0] & 0xFFL) << 56) | ((value[1] & 0xFFL) << 48) |
                    ((value[2] & 0xFFL) << 40) | ((value[3] & 0xFFL) << 32) |
                    ((value[4] & 0xFFL) << 24) | ((value[5] & 0xFFL) << 16) |
                    ((value[6] & 0xFFL) << 8) | (value[7] & 0xFFL);
        break;

      default:
        throw new ASN1Exception(ERR_LONG_INVALID_LENGTH.get(value.length));
    }

    return new ASN1Long(element.getType(), longValue, value);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append(longValue);
  }
}
