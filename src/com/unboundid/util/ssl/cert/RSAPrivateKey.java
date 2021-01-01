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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1BigInteger;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
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
 * contained in an RSA private key.  As per
 * <A HREF="https://www.ietf.org/rfc/rfc8017.txt">RFC 8017</A> section A.1.2,
 * an RSA private key is identified by OID 1.2.840.113549.1.1.1 and the value is
 * encoded as follows:
 * <PRE>
 *   RSAPrivateKey ::= SEQUENCE {
 *       version           Version,
 *       modulus           INTEGER,  -- n
 *       publicExponent    INTEGER,  -- e
 *       privateExponent   INTEGER,  -- d
 *       prime1            INTEGER,  -- p
 *       prime2            INTEGER,  -- q
 *       exponent1         INTEGER,  -- d mod (p-1)
 *       exponent2         INTEGER,  -- d mod (q-1)
 *       coefficient       INTEGER,  -- (inverse of q) mod p
 *       otherPrimeInfos   OtherPrimeInfos OPTIONAL
 *   }
 *
 *   OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
 *
 *   OtherPrimeInfo ::= SEQUENCE {
 *       prime             INTEGER,  -- ri
 *       exponent          INTEGER,  -- di
 *       coefficient       INTEGER   -- ti
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RSAPrivateKey
       extends DecodedPrivateKey
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7101141316095373904L;



  // The coefficient value for the RSA private key.
  @NotNull private final BigInteger coefficient;

  // The exponent1 value for the RSA private key.
  @NotNull private final BigInteger exponent1;

  // The exponent2 value for the RSA private key.
  @NotNull private final BigInteger exponent2;

  // The modulus for the RSA private key.
  @NotNull private final BigInteger modulus;

  // The prime1 value for the RSA private key.
  @NotNull private final BigInteger prime1;

  // The prime2 value for the RSA private key.
  @NotNull private final BigInteger prime2;

  // The private exponent for the RSA private key.
  @NotNull private final BigInteger privateExponent;

  // The public exponent for the RSA private key.
  @NotNull private final BigInteger publicExponent;

  // A list of information about additional primes used by the RSA private key.
  @NotNull private final List<BigInteger[]> otherPrimeInfos;

  // The private key version.
  @NotNull private final RSAPrivateKeyVersion version;



  /**
   * Creates a new RSA private key with the provided information.
   *
   * @param  version          The version for this private key.  It must not be
   *                          {@code null}.
   * @param  modulus          The modulus for this RSA private key.  It must not
   *                          be {@code null}.
   * @param  publicExponent   The public exponent for this RSA private key.  It
   *                          must not be {@code null}.
   * @param  privateExponent  The private exponent for this RSA private key.  It
   *                          must not be {@code null}.
   * @param  prime1           The prime1 value for this RSA private key.  It
   *                          must not be {@code null}.
   * @param  prime2           The prime2 value for this RSA private key.  It
   *                          must not be {@code null}.
   * @param  exponent1        The exponent1 value for this RSA private key.  It
   *                          must not be {@code null}.
   * @param  exponent2        The exponent2 value for this RSA private key.  It
   *                          must not be {@code null}.
   * @param  coefficient      The coefficient for this RSA private key. It must
   *                          not be {@code null}.
   * @param  otherPrimeInfos  A list of information about additional primes used
   *                          by the private key.  It must not be {@code null},
   *                          but may be empty.  If it is non-empty, then each
   *                          array must contain three items, which represent a
   *                          prime, an exponent, and a coefficient,
   *                          respectively.
   */
  RSAPrivateKey(@NotNull final RSAPrivateKeyVersion version,
                @NotNull final BigInteger modulus,
                @NotNull final BigInteger publicExponent,
                @NotNull final BigInteger privateExponent,
                @NotNull final BigInteger prime1,
                @NotNull final BigInteger prime2,
                @NotNull final BigInteger exponent1,
                @NotNull final BigInteger exponent2,
                @NotNull final BigInteger coefficient,
                @NotNull final List<BigInteger[]> otherPrimeInfos)
  {
    this.version = version;
    this.modulus = modulus;
    this.publicExponent = publicExponent;
    this.privateExponent = privateExponent;
    this.prime1 = prime1;
    this.prime2 = prime2;
    this.exponent1 = exponent1;
    this.exponent2 = exponent2;
    this.coefficient = coefficient;
    this.otherPrimeInfos = otherPrimeInfos;
  }



  /**
   * Creates a new RSA decoded private key from the provided octet string.
   *
   * @param  encodedPrivateKey  The encoded private key to be decoded as an RSA
   *                            private key.
   *
   * @throws  CertException  If the provided private key cannot be decoded as an
   *                         RSA private key.
   */
  RSAPrivateKey(@NotNull final ASN1OctetString encodedPrivateKey)
       throws CertException
  {
    try
    {
      final ASN1Element[] elements = ASN1Sequence.decodeAsSequence(
           encodedPrivateKey.getValue()).elements();
      final int versionIntValue = elements[0].decodeAsInteger().intValue();
      version = RSAPrivateKeyVersion.valueOf(versionIntValue);
      if (version == null)
      {
        throw new CertException(
             ERR_RSA_PRIVATE_KEY_UNSUPPORTED_VERSION.get(versionIntValue));
      }

      modulus = elements[1].decodeAsBigInteger().getBigIntegerValue();
      publicExponent = elements[2].decodeAsBigInteger().getBigIntegerValue();
      privateExponent = elements[3].decodeAsBigInteger().getBigIntegerValue();
      prime1 = elements[4].decodeAsBigInteger().getBigIntegerValue();
      prime2 = elements[5].decodeAsBigInteger().getBigIntegerValue();
      exponent1 = elements[6].decodeAsBigInteger().getBigIntegerValue();
      exponent2 = elements[7].decodeAsBigInteger().getBigIntegerValue();
      coefficient = elements[8].decodeAsBigInteger().getBigIntegerValue();

      if (elements.length == 9)
      {
        otherPrimeInfos = Collections.emptyList();
      }
      else
      {
        final ASN1Element[] otherPrimesElements =
             elements[9].decodeAsSequence().elements();
        final ArrayList<BigInteger[]> otherPrimes =
             new ArrayList<>(otherPrimesElements.length);
        for (final ASN1Element e : otherPrimesElements)
        {
          final ASN1Element[] primeElements = e.decodeAsSequence().elements();
          otherPrimes.add(
               new BigInteger[]
               {
                 primeElements[0].decodeAsBigInteger().getBigIntegerValue(),
                 primeElements[1].decodeAsBigInteger().getBigIntegerValue(),
                 primeElements[2].decodeAsBigInteger().getBigIntegerValue()
               });
        }

        otherPrimeInfos = Collections.unmodifiableList(otherPrimes);
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
           ERR_RSA_PRIVATE_KEY_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes this RSA private key to an ASN.1 octet string.
   *
   * @return  The ASN.1 octet string containing the encoded private key.
   */
  @NotNull()
  ASN1OctetString encode()
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(9);
    elements.add(new ASN1Integer(version.getIntValue()));
    elements.add(new ASN1BigInteger(modulus));
    elements.add(new ASN1BigInteger(publicExponent));
    elements.add(new ASN1BigInteger(privateExponent));
    elements.add(new ASN1BigInteger(prime1));
    elements.add(new ASN1BigInteger(prime2));
    elements.add(new ASN1BigInteger(exponent1));
    elements.add(new ASN1BigInteger(exponent2));
    elements.add(new ASN1BigInteger(coefficient));

    if (! otherPrimeInfos.isEmpty())
    {
      final ArrayList<ASN1Element> otherElements =
           new ArrayList<>(otherPrimeInfos.size());
      for (final BigInteger[] info : otherPrimeInfos)
      {
        otherElements.add(new ASN1Sequence(
             new ASN1BigInteger(info[0]),
             new ASN1BigInteger(info[1]),
             new ASN1BigInteger(info[2])));
      }

      elements.add(new ASN1Sequence(otherElements));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the version for the RSA private key.
   *
   * @return  The version for the RSA private key.
   */
  @NotNull()
  public RSAPrivateKeyVersion getVersion()
  {
    return version;
  }



  /**
   * Retrieves the modulus (n) for the RSA private key.
   *
   * @return  The modulus for the RSA private key.
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
   * Retrieves the private exponent (d) for the RSA private key.
   *
   * @return  The private exponent for the RSA private key.
   */
  @NotNull()
  public BigInteger getPrivateExponent()
  {
    return privateExponent;
  }



  /**
   * Retrieves the prime1 (p) value for the RSA private key.
   *
   * @return  The prime1 value for the RSA private key.
   */
  @NotNull()
  public BigInteger getPrime1()
  {
    return prime1;
  }



  /**
   * Retrieves the prime2 (q) value for the RSA private key.
   *
   * @return  The prime2 value for the RSA private key.
   */
  @NotNull()
  public BigInteger getPrime2()
  {
    return prime2;
  }



  /**
   * Retrieves the exponent1 value for the RSA private key.
   *
   * @return  The exponent1 value for the RSA private key.
   */
  @NotNull()
  public BigInteger getExponent1()
  {
    return exponent1;
  }



  /**
   * Retrieves the exponent2 value for the RSA private key.
   *
   * @return  The exponent2 value for the RSA private key.
   */
  @NotNull()
  public BigInteger getExponent2()
  {
    return exponent2;
  }



  /**
   * Retrieves the coefficient for the RSA private key.
   *
   * @return  The coefficient for the RSA private key.
   */
  @NotNull()
  public BigInteger getCoefficient()
  {
    return coefficient;
  }



  /**
   * Retrieves a list of information about other primes used by the private key.
   * If the list is non-empty, then each item will be an array of three
   * {@code BigInteger} values, which represent a prime, an exponent, and a
   * coefficient, respectively.
   *
   * @return  A list of information about other primes used by the private key.
   */
  @NotNull()
  public List<BigInteger[]> getOtherPrimeInfos()
  {
    return otherPrimeInfos;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("RSAPrivateKey(version='");
    buffer.append(version.getName());
    buffer.append("', modulus=");
    StaticUtils.toHex(modulus.toByteArray(), ":", buffer);
    buffer.append(", publicExponent=");
    StaticUtils.toHex(publicExponent.toByteArray(), ":", buffer);
    buffer.append(", privateExponent=");
    StaticUtils.toHex(privateExponent.toByteArray(), ":", buffer);
    buffer.append(", prime1=");
    StaticUtils.toHex(prime1.toByteArray(), ":", buffer);
    buffer.append(", prime2=");
    StaticUtils.toHex(prime2.toByteArray(), ":", buffer);
    buffer.append(", exponent1=");
    StaticUtils.toHex(exponent1.toByteArray(), ":", buffer);
    buffer.append(", exponent2=");
    StaticUtils.toHex(exponent2.toByteArray(), ":", buffer);
    buffer.append(", coefficient=");
    StaticUtils.toHex(coefficient.toByteArray(), ":", buffer);

    if (! otherPrimeInfos.isEmpty())
    {
      buffer.append(", otherPrimeInfos={");

      final Iterator<BigInteger[]> iterator = otherPrimeInfos.iterator();
      while (iterator.hasNext())
      {
        final BigInteger[] array = iterator.next();
        buffer.append("PrimeInfo(prime=");
        StaticUtils.toHex(array[0].toByteArray(), ":", buffer);
        buffer.append(", exponent=");
        StaticUtils.toHex(array[1].toByteArray(), ":", buffer);
        buffer.append(", coefficient=");
        StaticUtils.toHex(array[2].toByteArray(), ":", buffer);
        buffer.append(')');

        if (iterator.hasNext())
        {
          buffer.append(", ");
        }
      }

      buffer.append('}');
    }

    buffer.append(')');
  }
}
