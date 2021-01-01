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
import java.util.HashSet;
import java.util.Set;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1BigInteger;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the RSAPrivateKey class.
 */
public final class RSAPrivateKeyTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a two-prime RSA private key.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTwoPrimeKey()
         throws Exception
  {
    final byte[] modulusBytes = new byte[256];
    modulusBytes[0] = 0x40;
    modulusBytes[255] = 0x01;

    final BigInteger modulus = new BigInteger(modulusBytes);
    final BigInteger publicExponent = BigInteger.valueOf(65537L);
    final BigInteger privateExponent = modulus.add(BigInteger.ONE);

    final byte[] prime1Bytes = new byte[128];
    prime1Bytes[0] = 0x40;
    prime1Bytes[127] = 0x01;

    final BigInteger prime1 = new BigInteger(prime1Bytes);
    final BigInteger prime2 = prime1.add(BigInteger.ONE);
    final BigInteger exponent1 = prime2.add(BigInteger.ONE);
    final BigInteger exponent2 = exponent1.add(BigInteger.ONE);
    final BigInteger coefficient = exponent2.add(BigInteger.ONE);

    RSAPrivateKey privateKey = new RSAPrivateKey(RSAPrivateKeyVersion.TWO_PRIME,
         modulus, publicExponent, privateExponent, prime1, prime2, exponent1,
         exponent2, coefficient, Collections.<BigInteger[]>emptyList());

    privateKey = new RSAPrivateKey(privateKey.encode());

    assertNotNull(privateKey.getVersion());
    assertEquals(privateKey.getVersion(), RSAPrivateKeyVersion.TWO_PRIME);

    assertNotNull(privateKey.getModulus());
    assertEquals(privateKey.getModulus(), modulus);

    assertNotNull(privateKey.getPublicExponent());
    assertEquals(privateKey.getPublicExponent(), publicExponent);

    assertNotNull(privateKey.getPrivateExponent());
    assertEquals(privateKey.getPrivateExponent(), privateExponent);

    assertNotNull(privateKey.getPrime1());
    assertEquals(privateKey.getPrime1(), prime1);

    assertNotNull(privateKey.getPrime2());
    assertEquals(privateKey.getPrime2(), prime2);

    assertNotNull(privateKey.getExponent1());
    assertEquals(privateKey.getExponent1(), exponent1);

    assertNotNull(privateKey.getExponent2());
    assertEquals(privateKey.getExponent2(), exponent2);

    assertNotNull(privateKey.getCoefficient());
    assertEquals(privateKey.getCoefficient(), coefficient);

    assertNotNull(privateKey.getOtherPrimeInfos());
    assertTrue(privateKey.getOtherPrimeInfos().isEmpty());

    assertNotNull(privateKey.toString());
  }



  /**
   * Tests a multi-prime RSA private key.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultiPrimeKey()
         throws Exception
  {
    final byte[] modulusBytes = new byte[512];
    modulusBytes[0] = 0x40;
    modulusBytes[511] = 0x01;

    final BigInteger modulus = new BigInteger(modulusBytes);
    final BigInteger publicExponent = BigInteger.valueOf(12345L);
    final BigInteger privateExponent = modulus.add(BigInteger.ONE);

    final byte[] prime1Bytes = new byte[256];
    prime1Bytes[0] = 0x40;
    prime1Bytes[255] = 0x01;

    final BigInteger prime1 = new BigInteger(prime1Bytes);
    final BigInteger prime2 = prime1.add(BigInteger.ONE);
    final BigInteger exponent1 = prime2.add(BigInteger.ONE);
    final BigInteger exponent2 = exponent1.add(BigInteger.ONE);
    final BigInteger coefficient = exponent2.add(BigInteger.ONE);

    final ArrayList<BigInteger[]> otherPrimeInfos = new ArrayList<>(2);
    otherPrimeInfos.add(new BigInteger[]
         {
           coefficient.add(BigInteger.ONE),
           coefficient.add(BigInteger.valueOf(2L)),
           coefficient.add(BigInteger.valueOf(3L)),
         });
    otherPrimeInfos.add(new BigInteger[]
         {
           coefficient.add(BigInteger.valueOf(4L)),
           coefficient.add(BigInteger.valueOf(5L)),
           coefficient.add(BigInteger.valueOf(6L)),
         });

    RSAPrivateKey privateKey = new RSAPrivateKey(RSAPrivateKeyVersion.TWO_PRIME,
         modulus, publicExponent, privateExponent, prime1, prime2, exponent1,
         exponent2, coefficient, otherPrimeInfos);

    privateKey = new RSAPrivateKey(privateKey.encode());

    assertNotNull(privateKey.getVersion());
    assertEquals(privateKey.getVersion(), RSAPrivateKeyVersion.TWO_PRIME);

    assertNotNull(privateKey.getModulus());
    assertEquals(privateKey.getModulus(), modulus);

    assertNotNull(privateKey.getPublicExponent());
    assertEquals(privateKey.getPublicExponent(), publicExponent);

    assertNotNull(privateKey.getPrivateExponent());
    assertEquals(privateKey.getPrivateExponent(), privateExponent);

    assertNotNull(privateKey.getPrime1());
    assertEquals(privateKey.getPrime1(), prime1);

    assertNotNull(privateKey.getPrime2());
    assertEquals(privateKey.getPrime2(), prime2);

    assertNotNull(privateKey.getExponent1());
    assertEquals(privateKey.getExponent1(), exponent1);

    assertNotNull(privateKey.getExponent2());
    assertEquals(privateKey.getExponent2(), exponent2);

    assertNotNull(privateKey.getCoefficient());
    assertEquals(privateKey.getCoefficient(), coefficient);

    assertNotNull(privateKey.getOtherPrimeInfos());
    assertEquals(privateKey.getOtherPrimeInfos().size(), 2);

    assertNotNull(privateKey.toString());
  }



  /**
   * Tests the behavior when trying to decode a private key with an invalid
   * version.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeKeyInvalidVersion()
         throws Exception
  {
    final ASN1Sequence pkSequence = new ASN1Sequence(
         new ASN1Integer(123),
         new ASN1BigInteger(BigInteger.ONE),
         new ASN1BigInteger(BigInteger.ONE),
         new ASN1BigInteger(BigInteger.ONE),
         new ASN1BigInteger(BigInteger.ONE),
         new ASN1BigInteger(BigInteger.ONE),
         new ASN1BigInteger(BigInteger.ONE),
         new ASN1BigInteger(BigInteger.ONE),
         new ASN1BigInteger(BigInteger.ONE));

    new RSAPrivateKey(new ASN1OctetString(pkSequence.encode()));
  }



  /**
   * Tests the behavior when trying to decode a malformed private key.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedKey()
         throws Exception
  {
    new RSAPrivateKey(new ASN1OctetString("malformed"));
  }



  /**
   * Tests the {@code forName} method with automated tests based on the actual
   * name of the enum values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForNameAutomated()
         throws Exception
  {
    for (final RSAPrivateKeyVersion value :
         RSAPrivateKeyVersion.values())
    {
      for (final String name : getNames(value.name(), value.getName()))
      {
        assertNotNull(RSAPrivateKeyVersion.forName(name));
        assertEquals(RSAPrivateKeyVersion.forName(name), value);
      }
    }

    assertNull(RSAPrivateKeyVersion.forName("some undefined name"));
  }



  /**
   * Retrieves a set of names for testing the {@code forName} method based on
   * the provided set of names.
   *
   * @param  baseNames  The base set of names to use to generate the full set of
   *                    names.  It must not be {@code null} or empty.
   *
   * @return  The full set of names to use for testing.
   */
  private static Set<String> getNames(final String... baseNames)
  {
    final HashSet<String> nameSet = new HashSet<>(10);
    for (final String name : baseNames)
    {
      nameSet.add(name);
      nameSet.add(name.toLowerCase());
      nameSet.add(name.toUpperCase());

      final String nameWithDashesInsteadOfUnderscores = name.replace('_', '-');
      nameSet.add(nameWithDashesInsteadOfUnderscores);
      nameSet.add(nameWithDashesInsteadOfUnderscores.toLowerCase());
      nameSet.add(nameWithDashesInsteadOfUnderscores.toUpperCase());

      final String nameWithUnderscoresInsteadOfDashes = name.replace('-', '_');
      nameSet.add(nameWithUnderscoresInsteadOfDashes);
      nameSet.add(nameWithUnderscoresInsteadOfDashes.toLowerCase());
      nameSet.add(nameWithUnderscoresInsteadOfDashes.toUpperCase());

      final StringBuilder nameWithoutUnderscoresOrDashes = new StringBuilder();
      for (final char c : name.toCharArray())
      {
        if ((c != '-') && (c != '_'))
        {
          nameWithoutUnderscoresOrDashes.append(c);
        }
      }
      nameSet.add(nameWithoutUnderscoresOrDashes.toString());
      nameSet.add(nameWithoutUnderscoresOrDashes.toString().toLowerCase());
      nameSet.add(nameWithoutUnderscoresOrDashes.toString().toUpperCase());
    }

    return nameSet;
  }
}
