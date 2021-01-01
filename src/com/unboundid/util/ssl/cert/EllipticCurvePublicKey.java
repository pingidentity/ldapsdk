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
package com.unboundid.util.ssl.cert;



import java.math.BigInteger;

import com.unboundid.asn1.ASN1BitString;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.cert.CertMessages.*;



/**
 * This class provides a data structure for representing the information
 * contained in an elliptic curve public key in an X.509 certificate.  As per
 * <A HREF="https://www.ietf.org/rfc/rfc5480.txt">RFC 5480</A> section 2.2,
 * and the Standards for Efficient Cryptography SEC 1 document.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class EllipticCurvePublicKey
       extends DecodedPublicKey
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7537378153089968013L;



  // Indicates whether the y coordinate is even or odd.
  private final boolean yCoordinateIsEven;

  // The x coordinate for the public key.
  @NotNull private final BigInteger xCoordinate;

  // The y coordinate for the public key.
  @Nullable private final BigInteger yCoordinate;



  /**
   * Creates a new elliptic curve public key with the provided information.
   *
   * @param  xCoordinate  The x coordinate for the public key.  This must not be
   *                      {@code null}.
   * @param  yCoordinate  The y coordinate for the public key.  This must not be
   *                      {@code null}.
   */
  EllipticCurvePublicKey(@NotNull final BigInteger xCoordinate,
                         @NotNull final BigInteger yCoordinate)
  {
    this.xCoordinate = xCoordinate;
    this.yCoordinate = yCoordinate;
    yCoordinateIsEven =
         yCoordinate.mod(BigInteger.valueOf(2L)).equals(BigInteger.ZERO);
  }



  /**
   * Creates a new elliptic curve public key with the provided information.
   *
   * @param  xCoordinate        The x coordinate for the public key.  This must
   *                            not be {@code null}.
   * @param  yCoordinateIsEven  Indicates whether the y coordinate for the
   *                            public key is even.
   */
  EllipticCurvePublicKey(@NotNull final BigInteger xCoordinate,
                         final boolean yCoordinateIsEven)
  {
    this.xCoordinate = xCoordinate;
    this.yCoordinateIsEven = yCoordinateIsEven;

    yCoordinate = null;
  }



  /**
   * Creates a new elliptic curve decoded public key from the provided bit
   * string.
   *
   * @param  subjectPublicKey  The bit string containing the encoded public key.
   *
   * @throws  CertException  If the provided public key cannot be decoded as an
   *                         elliptic curve public key.
   */
  EllipticCurvePublicKey(@NotNull final ASN1BitString subjectPublicKey)
       throws CertException
  {
    try
    {
      final byte[] xBytes;
      final byte[] yBytes;
      final byte[] keyBytes = subjectPublicKey.getBytes();
      switch (keyBytes.length)
      {
        case 33:
          yCoordinate = null;
          if (keyBytes[0] == 0x02)
          {
            yCoordinateIsEven = true;
          }
          else if (keyBytes[0] == 0x03)
          {
            yCoordinateIsEven = false;
          }
          else
          {
            throw new CertException(
                 ERR_EC_PUBLIC_KEY_PARSE_UNEXPECTED_COMPRESSED_FIRST_BYTE.get(
                      keyBytes.length, StaticUtils.toHex(keyBytes[0])));
          }

          xBytes = new byte[32];
          System.arraycopy(keyBytes, 1, xBytes, 0, 32);
          xCoordinate = new BigInteger(xBytes);
          break;

        case 49:
          yCoordinate = null;
          if (keyBytes[0] == 0x02)
          {
            yCoordinateIsEven = true;
          }
          else if (keyBytes[0] == 0x03)
          {
            yCoordinateIsEven = false;
          }
          else
          {
            throw new CertException(
                 ERR_EC_PUBLIC_KEY_PARSE_UNEXPECTED_COMPRESSED_FIRST_BYTE.get(
                      keyBytes.length, StaticUtils.toHex(keyBytes[0])));
          }

          xBytes = new byte[48];
          System.arraycopy(keyBytes, 1, xBytes, 0, 48);
          xCoordinate = new BigInteger(xBytes);
          break;

        case 65:
          if (keyBytes[0] != 0x04)
          {
            throw new CertException(
                 ERR_EC_PUBLIC_KEY_PARSE_UNEXPECTED_UNCOMPRESSED_FIRST_BYTE.get(
                      keyBytes.length, StaticUtils.toHex(keyBytes[0])));
          }

          xBytes = new byte[32];
          yBytes = new byte[32];
          System.arraycopy(keyBytes, 1, xBytes, 0, 32);
          System.arraycopy(keyBytes, 33, yBytes, 0, 32);
          xCoordinate = new BigInteger(xBytes);
          yCoordinate = new BigInteger(yBytes);
          yCoordinateIsEven = ((keyBytes[64] & 0x01) == 0x00);
          break;

        case 97:
          if (keyBytes[0] != 0x04)
          {
            throw new CertException(
                 ERR_EC_PUBLIC_KEY_PARSE_UNEXPECTED_UNCOMPRESSED_FIRST_BYTE.get(
                      keyBytes.length, StaticUtils.toHex(keyBytes[0])));
          }

          xBytes = new byte[48];
          yBytes = new byte[48];
          System.arraycopy(keyBytes, 1, xBytes, 0, 48);
          System.arraycopy(keyBytes, 49, yBytes, 0, 48);
          xCoordinate = new BigInteger(xBytes);
          yCoordinate = new BigInteger(yBytes);
          yCoordinateIsEven = ((keyBytes[96] & 0x01) == 0x00);
          break;

        default:
          throw new CertException(
               ERR_EC_PUBLIC_KEY_PARSE_UNEXPECTED_SIZE.get(keyBytes.length));
      }
    }
    catch (final CertException e)
    {
      Debug.debugException(e);
      throw e;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_EC_PUBLIC_KEY_PARSE_ERROR.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes this elliptic curve public key.
   *
   * @return  The encoded public key.
   *
   * @throws  CertException  If a problem is encountered while encoding this
   *                         public key.
   */
  @NotNull()
  ASN1BitString encode()
       throws CertException
  {
    final byte[] publicKeyBytes;
    if (yCoordinate == null)
    {
      publicKeyBytes = new byte[33];
      if (yCoordinateIsEven)
      {
        publicKeyBytes[0] = 0x02;
      }
      else
      {
        publicKeyBytes[0] = 0x03;
      }
    }
    else
    {
      publicKeyBytes = new byte[65];
      publicKeyBytes[0] = 0x04;
    }

    final byte[] xCoordinateBytes = xCoordinate.toByteArray();
    if (xCoordinateBytes.length > 32)
    {
      throw new CertException(ERR_EC_PUBLIC_KEY_ENCODE_X_TOO_LARGE.get(
           toString(), xCoordinateBytes.length));
    }

    final int xStartPos = 33 - xCoordinateBytes.length;
    System.arraycopy(xCoordinateBytes, 0, publicKeyBytes, xStartPos,
         xCoordinateBytes.length);

    if (yCoordinate != null)
    {
      final byte[] yCoordinateBytes = yCoordinate.toByteArray();
      if (yCoordinateBytes.length > 32)
      {
        throw new CertException(ERR_EC_PUBLIC_KEY_ENCODE_Y_TOO_LARGE.get(
             toString(), yCoordinateBytes.length));
      }

      final int yStartPos = 65 - yCoordinateBytes.length;
      System.arraycopy(yCoordinateBytes, 0, publicKeyBytes, yStartPos,
           yCoordinateBytes.length);
    }

    final boolean[] bits = ASN1BitString.getBitsForBytes(publicKeyBytes);
    return new ASN1BitString(bits);
  }



  /**
   * Indicates whether the public key uses the compressed form (which merely
   * contains the x coordinate and an indication as to whether the y coordinate
   * is even or odd) or the uncompressed form (which contains both the x and
   * y coordinate values).
   *
   * @return  {@code true} if the public key uses the compressed form, or
   *          {@code false} if it uses the uncompressed form.
   */
  public boolean usesCompressedForm()
  {
    return (yCoordinate == null);
  }



  /**
   * Retrieves the value of the x coordinate.  This will always be available.
   *
   * @return  The value of the x coordinate.
   */
  @NotNull()
  public BigInteger getXCoordinate()
  {
    return xCoordinate;
  }



  /**
   * Retrieves the value of the y coordinate.  This will only be available if
   * the key was encoded in the uncompressed form.
   *
   * @return  The value of the y coordinate, or {@code null} if the key was
   *          encoded in the compressed form.
   */
  @Nullable()
  public BigInteger getYCoordinate()
  {
    return yCoordinate;
  }



  /**
   * Indicates whether the y coordinate is even or odd.
   *
   * @return  {@code true} if the y coordinate is even, or {@code false} if the
   *          y coordinate is odd.
   */
  public boolean yCoordinateIsEven()
  {
    return yCoordinateIsEven;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("EllipticCurvePublicKey(usesCompressedForm=");
    buffer.append(yCoordinate == null);
    buffer.append(", xCoordinate=");
    buffer.append(xCoordinate);

    if (yCoordinate == null)
    {
      buffer.append(", yCoordinateIsEven=");
      buffer.append(yCoordinateIsEven);
    }
    else
    {
      buffer.append(", yCoordinate=");
      buffer.append(yCoordinate);
    }

    buffer.append(')');
  }
}
