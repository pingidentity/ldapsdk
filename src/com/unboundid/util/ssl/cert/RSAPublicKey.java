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

import com.unboundid.asn1.ASN1BigInteger;
import com.unboundid.asn1.ASN1BitString;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.cert.CertMessages.*;



/**
 * This class provides a data structure for representing the information
 * contained in an RSA public key in an X.509 certificate.  As per
 * <A HREF="https://www.ietf.org/rfc/rfc8017.txt">RFC 8017</A> section A.1.1,
 * an RSA public key is identified by OID 1.2.840.113549.1.1.1 and the value is
 * encoded as follows:
 * <PRE>
 *   RSAPublicKey ::= SEQUENCE {
 *      modulus            INTEGER,    -- n
 *      publicExponent     INTEGER  }  -- e
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RSAPublicKey
       extends DecodedPublicKey
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1837190736740174338L;



  // The modulus for the RSA public key.
  @NotNull private final BigInteger modulus;

  // The public exponent for the RSA public key.
  @NotNull private final BigInteger publicExponent;



  /**
   * Creates a new RSA public key with the provided information.
   *
   * @param  modulus         The modulus for this RSA public key.  It must not
   *                         be {@code null}.
   * @param  publicExponent  The public exponent for this RSA public key.  It
   *                         must not be {@code null}.
   */
  RSAPublicKey(@NotNull final BigInteger modulus,
               @NotNull final BigInteger publicExponent)
  {
    this.modulus = modulus;
    this.publicExponent = publicExponent;
  }



  /**
   * Creates a new RSA decoded public key from the provided bit string.
   *
   * @param  subjectPublicKey  The bit string containing the encoded public key.
   *
   * @throws  CertException  If the provided public key cannot be decoded as an
   *                         RSA public key.
   */
  RSAPublicKey(@NotNull final ASN1BitString subjectPublicKey)
       throws CertException
  {
    try
    {
      final byte[] keyBytes = subjectPublicKey.getBytes();
      final ASN1Element[] keyElements =
           ASN1Sequence.decodeAsSequence(keyBytes).elements();
      modulus = keyElements[0].decodeAsBigInteger().getBigIntegerValue();
      publicExponent = keyElements[1].decodeAsBigInteger().getBigIntegerValue();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_RSA_PUBLIC_KEY_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes this RSA public key.
   *
   * @return  The encoded representation of this RSA public key.
   */
  @NotNull()
  ASN1BitString encode()
  {
    final ASN1Sequence publicKeySequence = new ASN1Sequence(
         new ASN1BigInteger(modulus),
         new ASN1BigInteger(publicExponent));
    final boolean[] bits =
         ASN1BitString.getBitsForBytes(publicKeySequence.encode());
    return new ASN1BitString(bits);
  }



  /**
   * Retrieves the modulus (n) for the RSA public key.
   *
   * @return  The modulus for the RSA public key.
   */
  @NotNull()
  public BigInteger getModulus()
  {
    return modulus;
  }



  /**
   * Retrieves the public exponent (e) for the RSA public key.
   *
   * @return  The public exponent for the RSA public key.
   */
  @NotNull()
  public BigInteger getPublicExponent()
  {
    return publicExponent;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("RSAPublicKey(modulus=");
    StaticUtils.toHex(modulus.toByteArray(), ":", buffer);
    buffer.append(", publicExponent=");
    StaticUtils.toHex(publicExponent.toByteArray(), ":", buffer);
    buffer.append(')');
  }
}
