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



import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Collections;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1BitString;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1Null;
import com.unboundid.asn1.ASN1ObjectIdentifier;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.OID;



/**
 * This class provides a set of test cases for the PKCS8PrivateKey class.
 */
public final class PKCS8PrivateKeyTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a private key with a minimal set of elements that uses the RSA
   * algorithm.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalElementsRSA()
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

    final RSAPrivateKey rsaPrivateKey = new RSAPrivateKey(
         RSAPrivateKeyVersion.TWO_PRIME, modulus, publicExponent,
         privateExponent, prime1, prime2, exponent1, exponent2, coefficient,
         Collections.<BigInteger[]>emptyList());

    PKCS8PrivateKey privateKey = new PKCS8PrivateKey(
         PKCS8PrivateKeyVersion.V1, PublicKeyAlgorithmIdentifier.RSA.getOID(),
         null, rsaPrivateKey.encode(),  null, null, null);

    assertNotNull(privateKey.getPKCS8PrivateKeyBytes());

    privateKey = new PKCS8PrivateKey(privateKey.encode().encode());

    assertNotNull(privateKey.getVersion());
    assertEquals(privateKey.getVersion(), PKCS8PrivateKeyVersion.V1);

    assertNotNull(privateKey.getPrivateKeyAlgorithmOID());
    assertEquals(privateKey.getPrivateKeyAlgorithmOID(),
         PublicKeyAlgorithmIdentifier.RSA.getOID());

    assertNotNull(privateKey.getPrivateKeyAlgorithmName());
    assertEquals(privateKey.getPrivateKeyAlgorithmName(), "RSA");

    assertNotNull(privateKey.getPrivateKeyAlgorithmNameOrOID());
    assertEquals(privateKey.getPrivateKeyAlgorithmNameOrOID(), "RSA");

    assertNull(privateKey.getPrivateKeyAlgorithmParameters());

    assertNotNull(privateKey.getEncodedPrivateKey());
    assertEquals(privateKey.getEncodedPrivateKey().getValue(),
         rsaPrivateKey.encode().getValue());

    assertNotNull(privateKey.getDecodedPrivateKey());
    assertTrue(privateKey.getDecodedPrivateKey() instanceof RSAPrivateKey);

    final RSAPrivateKey decodedPrivateKey =
         (RSAPrivateKey) privateKey.getDecodedPrivateKey();
    assertEquals(decodedPrivateKey.getVersion(),
         RSAPrivateKeyVersion.TWO_PRIME);
    assertEquals(decodedPrivateKey.getModulus(), modulus);
    assertEquals(decodedPrivateKey.getPublicExponent(), publicExponent);
    assertEquals(decodedPrivateKey.getPrivateExponent(), privateExponent);
    assertEquals(decodedPrivateKey.getPrime1(), prime1);
    assertEquals(decodedPrivateKey.getPrime2(), prime2);
    assertEquals(decodedPrivateKey.getExponent1(), exponent1);
    assertEquals(decodedPrivateKey.getExponent2(), exponent2);
    assertEquals(decodedPrivateKey.getCoefficient(), coefficient);

    assertNull(privateKey.getAttributesElement());

    assertNull(privateKey.getPublicKey());

    assertNotNull(privateKey.toString());

    assertNotNull(privateKey.toPEM());
    assertFalse(privateKey.toPEM().isEmpty());

    assertNotNull(privateKey.toPEMString());

    assertNotNull(privateKey.getPKCS8PrivateKeyBytes());

    assertNotNull(privateKey.toPrivateKey());
  }



  /**
   * Tests a private key with a minimal set of elements that uses the elliptic
   * curve algorithm.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllElementsEC()
         throws Exception
  {
    final EllipticCurvePrivateKey ecPrivateKey = new EllipticCurvePrivateKey(1,
         new byte[32], NamedCurve.SECP256R1.getOID(),
         new ASN1BitString(new boolean[256]));

    PKCS8PrivateKey privateKey = new PKCS8PrivateKey(
         PKCS8PrivateKeyVersion.V2, PublicKeyAlgorithmIdentifier.EC.getOID(),
         new ASN1ObjectIdentifier(NamedCurve.SECP256R1.getOID()),
         ecPrivateKey.encode(), ecPrivateKey, new ASN1OctetString("attributes"),
         new ASN1BitString(new boolean[256]));

    assertNotNull(privateKey.getPKCS8PrivateKeyBytes());

    privateKey = new PKCS8PrivateKey(privateKey.encode().encode());

    assertNotNull(privateKey.getVersion());
    assertEquals(privateKey.getVersion(), PKCS8PrivateKeyVersion.V2);

    assertNotNull(privateKey.getPrivateKeyAlgorithmOID());
    assertEquals(privateKey.getPrivateKeyAlgorithmOID(),
         PublicKeyAlgorithmIdentifier.EC.getOID());

    assertNotNull(privateKey.getPrivateKeyAlgorithmName());
    assertEquals(privateKey.getPrivateKeyAlgorithmName(), "EC");

    assertNotNull(privateKey.getPrivateKeyAlgorithmNameOrOID());
    assertEquals(privateKey.getPrivateKeyAlgorithmNameOrOID(), "EC");

    assertNotNull(privateKey.getPrivateKeyAlgorithmParameters());
    assertEquals(
         privateKey.getPrivateKeyAlgorithmParameters().
              decodeAsObjectIdentifier().getOID(),
         NamedCurve.SECP256R1.getOID());

    assertNotNull(privateKey.getEncodedPrivateKey());
    assertEquals(privateKey.getEncodedPrivateKey().getValue(),
         ecPrivateKey.encode().getValue());

    assertNotNull(privateKey.getDecodedPrivateKey());
    assertTrue(
         privateKey.getDecodedPrivateKey() instanceof EllipticCurvePrivateKey);

    final EllipticCurvePrivateKey decodedPrivateKey =
         (EllipticCurvePrivateKey) privateKey.getDecodedPrivateKey();
    assertEquals(decodedPrivateKey.getVersion(), 1);
    assertEquals(decodedPrivateKey.getPrivateKeyBytes(), new byte[32]);
    assertEquals(decodedPrivateKey.getNamedCurveOID(),
         NamedCurve.SECP256R1.getOID());
    assertEquals(decodedPrivateKey.getPublicKey().getBytes(),
         new ASN1BitString(new boolean[256]).getBytes());

    assertNotNull(privateKey.getAttributesElement());
    assertEquals(privateKey.getAttributesElement().getValue(),
         new ASN1OctetString("attributes").getValue());

    assertNotNull(privateKey.getPublicKey());
    assertEquals(privateKey.getPublicKey().getBytes(),
         new ASN1BitString(new boolean[256]).getBytes());

    assertNotNull(privateKey.toString());

    assertNotNull(privateKey.toPEM());
    assertFalse(privateKey.toPEM().isEmpty());

    assertNotNull(privateKey.toPEMString());

    assertNotNull(privateKey.getPKCS8PrivateKeyBytes());
  }



  /**
   * Tests a private key with a minimal set of elements that uses an
   * unrecognized algorithm.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalElementsNotDecodeable()
         throws Exception
  {
    PKCS8PrivateKey privateKey = new PKCS8PrivateKey(
         PKCS8PrivateKeyVersion.V2, new OID("1.2.3.4"), new ASN1Null(),
         new ASN1OctetString("encoded-private-key"), null, null, null);

    assertNotNull(privateKey.getPKCS8PrivateKeyBytes());

    privateKey = new PKCS8PrivateKey(privateKey.encode().encode());

    assertNotNull(privateKey.getVersion());
    assertEquals(privateKey.getVersion(), PKCS8PrivateKeyVersion.V2);

    assertNotNull(privateKey.getPrivateKeyAlgorithmOID());
    assertEquals(privateKey.getPrivateKeyAlgorithmOID(), new OID("1.2.3.4"));

    assertNull(privateKey.getPrivateKeyAlgorithmName());

    assertNotNull(privateKey.getPrivateKeyAlgorithmNameOrOID());
    assertEquals(privateKey.getPrivateKeyAlgorithmNameOrOID(), "1.2.3.4");

    assertNotNull(privateKey.getPrivateKeyAlgorithmParameters());

    assertNotNull(privateKey.getEncodedPrivateKey());
    assertEquals(privateKey.getEncodedPrivateKey().getValue(),
         new ASN1OctetString("encoded-private-key").getValue());

    assertNull(privateKey.getDecodedPrivateKey());

    assertNotNull(privateKey.toString());

    assertNotNull(privateKey.toPEM());
    assertFalse(privateKey.toPEM().isEmpty());

    assertNotNull(privateKey.toPEMString());

    assertNotNull(privateKey.getPKCS8PrivateKeyBytes());
  }



  /**
   * Tests the behavior when trying to encode a private key with an algorithm
   * identifier that is not a valid OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testEncodeWithInvalidAlgorithmIdentifierOID()
         throws Exception
  {
    final PKCS8PrivateKey privateKey = new PKCS8PrivateKey(
         PKCS8PrivateKeyVersion.V2, new OID("1234.5678"), new ASN1Null(),
         new ASN1OctetString("encoded-private-key"), null, null, null);
    privateKey.encode();
  }



  /**
   * Tests the behavior when trying to decode a byte array that cannot be
   * parsed as a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeNotSequence()
         throws Exception
  {
    new PKCS8PrivateKey("not a sequence".getBytes("UTF-8"));
  }



  /**
   * Tests the behavior when trying to decode a byte array that represents a
   * sequence with fewer than three elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeSequenceTooFewElements()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Integer(0));
    new PKCS8PrivateKey(valueSequence.encode());
  }



  /**
   * Tests the behavior when trying to decode a byte array that represents a
   * sequence with an version element that cannot be parsed as an integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeVersionNotInteger()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString(),
         new ASN1Sequence(
              new ASN1ObjectIdentifier(new OID("1.2.3.4")),
              new ASN1Null()),
         new ASN1OctetString("encoded-private-key"));
    new PKCS8PrivateKey(valueSequence.encode());
  }



  /**
   * Tests the behavior when trying to decode a byte array that represents a
   * sequence with an invalid version number.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeInvalidVersionNumber()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Integer(999),
         new ASN1Sequence(
              new ASN1ObjectIdentifier(new OID("1.2.3.4")),
              new ASN1Null()),
         new ASN1OctetString("encoded-private-key"));
    new PKCS8PrivateKey(valueSequence.encode());
  }



  /**
   * Tests the behavior when trying to decode a byte array that represents a
   * sequence with an invalid algorithm identifier OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeInvalidAlgorithmIdentifier()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Integer(0),
         new ASN1Sequence(
              new ASN1OctetString(),
              new ASN1Null()),
         new ASN1OctetString("encoded-private-key"));
    new PKCS8PrivateKey(valueSequence.encode());
  }



  /**
   * Tests the behavior when trying to decode a byte array that represents a
   * sequence with a malformed public key.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedPublicKey()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Integer(0),
         new ASN1Sequence(
              new ASN1ObjectIdentifier(new OID("1.2.3.4")),
              new ASN1Null()),
         new ASN1OctetString("encoded-private-key"),
         new ASN1OctetString((byte) 0x81));
    new PKCS8PrivateKey(valueSequence.encode());
  }



  /**
   * Tests the behavior with a private key algorithm that indicates that it's an
   * RSA key, but with an encoded key that can't be parsed as an RSA private
   * key.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedRSAPrivateKey()
         throws Exception
  {
    PKCS8PrivateKey privateKey = new PKCS8PrivateKey(
         PKCS8PrivateKeyVersion.V1, PublicKeyAlgorithmIdentifier.RSA.getOID(),
         new ASN1Null(), new ASN1OctetString("malformed-rsa-private-key"),
         null, null, null);

    privateKey = new PKCS8PrivateKey(privateKey.encode().encode());

    assertNotNull(privateKey.getVersion());
    assertEquals(privateKey.getVersion(), PKCS8PrivateKeyVersion.V1);

    assertNotNull(privateKey.getPrivateKeyAlgorithmOID());
    assertEquals(privateKey.getPrivateKeyAlgorithmOID(),
         PublicKeyAlgorithmIdentifier.RSA.getOID());

    assertNotNull(privateKey.getPrivateKeyAlgorithmName());
    assertEquals(privateKey.getPrivateKeyAlgorithmName(), "RSA");

    assertNotNull(privateKey.getPrivateKeyAlgorithmNameOrOID());
    assertEquals(privateKey.getPrivateKeyAlgorithmNameOrOID(), "RSA");

    assertNotNull(privateKey.getPrivateKeyAlgorithmParameters());

    assertNotNull(privateKey.getEncodedPrivateKey());
    assertEquals(privateKey.getEncodedPrivateKey().getValue(),
         new ASN1OctetString("malformed-rsa-private-key").getValue());

    assertNull(privateKey.getDecodedPrivateKey());

    assertNull(privateKey.getAttributesElement());

    assertNull(privateKey.getPublicKey());

    assertNotNull(privateKey.toString());

    assertNotNull(privateKey.toPEM());
    assertFalse(privateKey.toPEM().isEmpty());

    assertNotNull(privateKey.toPEMString());
  }



  /**
   * Tests the behavior with a private key algorithm that indicates that it's an
   * elliptic curve key, but with an encoded key that can't be parsed as an
   * elliptic curve private key.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedEllipticCurvePrivateKey()
         throws Exception
  {
    PKCS8PrivateKey privateKey = new PKCS8PrivateKey(
         PKCS8PrivateKeyVersion.V1, PublicKeyAlgorithmIdentifier.EC.getOID(),
         new ASN1ObjectIdentifier(NamedCurve.SECP256R1.getOID()),
         new ASN1OctetString("malformed-ec-private-key"), null, null, null);

    assertNotNull(privateKey.getPKCS8PrivateKeyBytes());

    privateKey = new PKCS8PrivateKey(privateKey.encode().encode());

    assertNotNull(privateKey.getVersion());
    assertEquals(privateKey.getVersion(), PKCS8PrivateKeyVersion.V1);

    assertNotNull(privateKey.getPrivateKeyAlgorithmOID());
    assertEquals(privateKey.getPrivateKeyAlgorithmOID(),
         PublicKeyAlgorithmIdentifier.EC.getOID());

    assertNotNull(privateKey.getPrivateKeyAlgorithmName());
    assertEquals(privateKey.getPrivateKeyAlgorithmName(), "EC");

    assertNotNull(privateKey.getPrivateKeyAlgorithmNameOrOID());
    assertEquals(privateKey.getPrivateKeyAlgorithmNameOrOID(), "EC");

    assertNotNull(privateKey.getPrivateKeyAlgorithmParameters());

    assertNotNull(privateKey.getEncodedPrivateKey());
    assertEquals(privateKey.getEncodedPrivateKey().getValue(),
         new ASN1OctetString("malformed-ec-private-key").getValue());

    assertNull(privateKey.getDecodedPrivateKey());

    assertNull(privateKey.getAttributesElement());

    assertNull(privateKey.getPublicKey());

    assertNotNull(privateKey.toString());

    assertNotNull(privateKey.toPEM());
    assertFalse(privateKey.toPEM().isEmpty());

    assertNotNull(privateKey.toPEMString());

    assertNotNull(privateKey.getPKCS8PrivateKeyBytes());
  }



  /**
   * Tests the behavior with a private key created with a decoded elliptic curve
   * private key but without a named curve OID as the algorithm parameters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodedEllipticCurvePrivateKeyWithoutNamedCurveParameter()
         throws Exception
  {
    final EllipticCurvePrivateKey ecPrivateKey = new EllipticCurvePrivateKey(1,
         new byte[32], NamedCurve.SECP256R1.getOID(),
         new ASN1BitString(new boolean[256]));

    final PKCS8PrivateKey privateKey = new PKCS8PrivateKey(
         PKCS8PrivateKeyVersion.V1, PublicKeyAlgorithmIdentifier.EC.getOID(),
         new ASN1Null(), ecPrivateKey.encode(), ecPrivateKey, null, null);

    assertNotNull(privateKey.toString());

    assertNotNull(privateKey.toPEM());
    assertFalse(privateKey.toPEM().isEmpty());

    assertNotNull(privateKey.toPEMString());

    assertNotNull(privateKey.getPKCS8PrivateKeyBytes());
  }



  /**
   * Tests the ability to decode an actual PKCS#8 private key with an RSA key
   * read from a Java keystore.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeActualRSAPrivateKey()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File keyStoreFile = new File(resourceDir, "cert-test-keystore");

    final KeyStore keyStore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(keyStoreFile))
    {
      keyStore.load(inputStream, "password".toCharArray());
    }

    final PrivateKey privateKey =
         (PrivateKey) keyStore.getKey("rsa-cert", "password".toCharArray());
    final PKCS8PrivateKey pkcs8PrivateKey =
         new PKCS8PrivateKey(privateKey.getEncoded());

    assertNotNull(pkcs8PrivateKey.getVersion());
    assertEquals(pkcs8PrivateKey.getVersion(),
         PKCS8PrivateKeyVersion.V1);

    assertNotNull(pkcs8PrivateKey.getPrivateKeyAlgorithmOID());
    assertEquals(pkcs8PrivateKey.getPrivateKeyAlgorithmOID(),
         PublicKeyAlgorithmIdentifier.RSA.getOID());

    assertNotNull(pkcs8PrivateKey.getPrivateKeyAlgorithmName());
    assertEquals(pkcs8PrivateKey.getPrivateKeyAlgorithmName(), "RSA");

    assertNotNull(pkcs8PrivateKey.getPrivateKeyAlgorithmNameOrOID());
    assertEquals(pkcs8PrivateKey.getPrivateKeyAlgorithmNameOrOID(), "RSA");

    assertNotNull(pkcs8PrivateKey.getEncodedPrivateKey());

    assertNotNull(pkcs8PrivateKey.getDecodedPrivateKey());
    assertTrue(pkcs8PrivateKey.getDecodedPrivateKey() instanceof RSAPrivateKey);

    assertNotNull(pkcs8PrivateKey.getPKCS8PrivateKeyBytes());
  }



  /**
   * Tests the ability to decode an actual PKCS#8 private key with an elliptic
   * curve key read from a Java keystore.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeActualEllipticCurvePrivateKey()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File keyStoreFile = new File(resourceDir, "cert-test-keystore");

    final KeyStore keyStore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(keyStoreFile))
    {
      keyStore.load(inputStream, "password".toCharArray());
    }

    final PrivateKey privateKey =
         (PrivateKey) keyStore.getKey("ec-cert", "password".toCharArray());
    final PKCS8PrivateKey pkcs8PrivateKey =
         new PKCS8PrivateKey(privateKey.getEncoded());

    assertNotNull(pkcs8PrivateKey.getVersion());
    assertEquals(pkcs8PrivateKey.getVersion(),
         PKCS8PrivateKeyVersion.V1);

    assertNotNull(pkcs8PrivateKey.getPrivateKeyAlgorithmOID());
    assertEquals(pkcs8PrivateKey.getPrivateKeyAlgorithmOID(),
         PublicKeyAlgorithmIdentifier.EC.getOID());

    assertNotNull(pkcs8PrivateKey.getPrivateKeyAlgorithmName());
    assertEquals(pkcs8PrivateKey.getPrivateKeyAlgorithmName(), "EC");

    assertNotNull(pkcs8PrivateKey.getPrivateKeyAlgorithmNameOrOID());
    assertEquals(pkcs8PrivateKey.getPrivateKeyAlgorithmNameOrOID(), "EC");

    assertNotNull(pkcs8PrivateKey.getEncodedPrivateKey());

    assertNotNull(pkcs8PrivateKey.getDecodedPrivateKey());
    assertTrue(pkcs8PrivateKey.getDecodedPrivateKey() instanceof
         EllipticCurvePrivateKey);

    assertNotNull(pkcs8PrivateKey.getPKCS8PrivateKeyBytes());
  }



  /**
   * Tests the behavior when trying to wrap an RSA private key in a PKCS #8
   * private key envelope.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWrapRSAPrivateKey()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File keyStoreFile = new File(resourceDir, "cert-test-keystore");

    final KeyStore keyStore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(keyStoreFile))
    {
      keyStore.load(inputStream, "password".toCharArray());
    }

    final PrivateKey privateKey =
         (PrivateKey) keyStore.getKey("rsa-cert", "password".toCharArray());
    PKCS8PrivateKey pkcs8PrivateKey =
         new PKCS8PrivateKey(privateKey.getEncoded());
    final byte[] rsaPrivateKey =
         pkcs8PrivateKey.getEncodedPrivateKey().getValue();
    final byte[] wrappedRSAPrivateKey =
         PKCS8PrivateKey.wrapRSAPrivateKey(rsaPrivateKey);

    pkcs8PrivateKey = new PKCS8PrivateKey(wrappedRSAPrivateKey);

    assertNotNull(pkcs8PrivateKey.getVersion());
    assertEquals(pkcs8PrivateKey.getVersion(),
         PKCS8PrivateKeyVersion.V1);

    assertNotNull(pkcs8PrivateKey.getPrivateKeyAlgorithmOID());
    assertEquals(pkcs8PrivateKey.getPrivateKeyAlgorithmOID(),
         PublicKeyAlgorithmIdentifier.RSA.getOID());

    assertNotNull(pkcs8PrivateKey.getPrivateKeyAlgorithmName());
    assertEquals(pkcs8PrivateKey.getPrivateKeyAlgorithmName(), "RSA");

    assertNotNull(pkcs8PrivateKey.getPrivateKeyAlgorithmNameOrOID());
    assertEquals(pkcs8PrivateKey.getPrivateKeyAlgorithmNameOrOID(), "RSA");

    assertNotNull(pkcs8PrivateKey.getEncodedPrivateKey());
    assertEquals(pkcs8PrivateKey.getEncodedPrivateKey().getValue(),
         rsaPrivateKey);

    assertNotNull(pkcs8PrivateKey.getDecodedPrivateKey());
    assertTrue(pkcs8PrivateKey.getDecodedPrivateKey() instanceof RSAPrivateKey);

    assertNotNull(pkcs8PrivateKey.getPKCS8PrivateKeyBytes());
  }
}
