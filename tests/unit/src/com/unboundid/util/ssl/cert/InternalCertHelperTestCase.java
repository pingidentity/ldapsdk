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
import java.util.Collections;
import java.util.Date;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1BitString;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code InternalCertHelper}
 * class.
 */
public final class InternalCertHelperTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the {@code createX509Certificate} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateX509Certificate()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    final byte[] modulusBytes = new byte[256];
    modulusBytes[0] = 0x40;
    modulusBytes[255] = 0x01;
    final BigInteger modulus = new BigInteger(modulusBytes);

    final BigInteger exponent = BigInteger.valueOf(65537L);

    final RSAPublicKey publicKey = new RSAPublicKey(modulus, exponent);

    final X509Certificate c = InternalCertHelper.createX509Certificate(
         X509CertificateVersion.V1, BigInteger.valueOf(123456789L),
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getOID(), null,
         new ASN1BitString(new boolean[1024]),
         new DN("CN=Issuer,O=Example Corp,C=US"), notBefore, notAfter,
         new DN("CN=ldap.example.com,O=Example Corp,C=US"),
         PublicKeyAlgorithmIdentifier.RSA.getOID(), null,
         publicKey.encode(), publicKey, null, null);

    assertNotNull(c.getVersion());
    assertEquals(c.getVersion(), X509CertificateVersion.V1);

    assertNotNull(c.getSerialNumber());
    assertEquals(c.getSerialNumber(), BigInteger.valueOf(123456789L));

    assertNotNull(c.getSignatureAlgorithmOID());
    assertEquals(c.getSignatureAlgorithmOID(),
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getOID());

    assertNotNull(c.getSignatureAlgorithmName());
    assertEquals(c.getSignatureAlgorithmName(), "SHA-256 with RSA");

    assertNotNull(c.getSignatureAlgorithmNameOrOID());
    assertEquals(c.getSignatureAlgorithmNameOrOID(), "SHA-256 with RSA");

    assertNull(c.getSignatureAlgorithmParameters());

    assertNotNull(c.getIssuerDN());
    assertEquals(c.getIssuerDN(), new DN("CN=Issuer,O=Example Corp,C=US"));

    // NOTE:  For some moronic reasons, certificates tend to use UTCTime instead
    // of generalized time when encoding notBefore and notAfter values, despite
    // the spec allowing either one, and despite UTCTime only supporting a
    // two-digit year and no sub-second component.  So we can't check for
    // exact equivalence  of the notBefore and notAfter values.  Instead, just
    // make sure that the values are within 2000 milliseconds of the expected
    // value.
    assertTrue(Math.abs(c.getNotBeforeTime() - notBefore) < 2000L);

    assertNotNull(c.getNotBeforeDate());
    assertEquals(c.getNotBeforeDate(), new Date(c.getNotBeforeTime()));

    assertTrue(Math.abs(c.getNotAfterTime() - notAfter) < 2000L);

    assertNotNull(c.getNotAfterDate());
    assertEquals(c.getNotAfterDate(), new Date(c.getNotAfterTime()));

    assertNotNull(c.getSubjectDN());
    assertEquals(c.getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corp,C=US"));

    assertNotNull(c.getPublicKeyAlgorithmOID());
    assertEquals(c.getPublicKeyAlgorithmOID(),
         PublicKeyAlgorithmIdentifier.RSA.getOID());

    assertNotNull(c.getPublicKeyAlgorithmName());
    assertEquals(c.getPublicKeyAlgorithmName(), "RSA");

    assertNotNull(c.getPublicKeyAlgorithmNameOrOID());
    assertEquals(c.getPublicKeyAlgorithmNameOrOID(), "RSA");

    assertNull(c.getPublicKeyAlgorithmParameters());

    assertNotNull(c.getEncodedPublicKey());

    assertNotNull(c.getDecodedPublicKey());
    assertTrue(c.getDecodedPublicKey() instanceof RSAPublicKey);

    assertNull(c.getIssuerUniqueID());

    assertNull(c.getSubjectUniqueID());

    assertNotNull(c.getExtensions());
    assertTrue(c.getExtensions().isEmpty());

    assertNotNull(c.getSignatureValue());

    assertNotNull(c.toString());

    assertNotNull(c.toPEM());
    assertFalse(c.toPEM().isEmpty());

    assertNotNull(c.toPEMString());

    assertNotNull(c.getX509CertificateBytes());

    assertNotNull(c.getSHA1Fingerprint());

    assertNotNull(c.getSHA256Fingerprint());

    assertNotNull(c.toCertificate());
  }



  /**
   * Provides test coverage for the
   * {@code createPKCS10CertificateSigningRequest} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreatePKCS10CertificateSigningRequest()
         throws Exception
  {
    final byte[] modulusBytes = new byte[256];
    modulusBytes[0] = 0x40;
    modulusBytes[255] = 0x01;
    final BigInteger modulus = new BigInteger(modulusBytes);

    final BigInteger exponent = BigInteger.valueOf(65537L);

    final RSAPublicKey publicKey = new RSAPublicKey(modulus, exponent);

    final PKCS10CertificateSigningRequest csr =
         InternalCertHelper.createPKCS10CertificateSigningRequest(
              PKCS10CertificateSigningRequestVersion.V1,
              SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getOID(), null,
              new ASN1BitString(true, false, true, false, true),
              new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
              PublicKeyAlgorithmIdentifier.RSA.getOID(), null,
              publicKey.encode(), null, null);

    assertNotNull(csr.getVersion());
    assertEquals(csr.getVersion(), PKCS10CertificateSigningRequestVersion.V1);

    assertNotNull(csr.getSignatureAlgorithmOID());
    assertEquals(csr.getSignatureAlgorithmOID(),
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getOID());

    assertNotNull(csr.getSignatureAlgorithmName());
    assertEquals(csr.getSignatureAlgorithmName(), "SHA-256 with RSA");

    assertNotNull(csr.getSignatureAlgorithmNameOrOID());
    assertEquals(csr.getSignatureAlgorithmNameOrOID(), "SHA-256 with RSA");

    assertNull(csr.getSignatureAlgorithmParameters());

    assertNotNull(csr.getSubjectDN());
    assertEquals(csr.getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));

    assertNotNull(csr.getPublicKeyAlgorithmOID());
    assertEquals(csr.getPublicKeyAlgorithmOID(),
         PublicKeyAlgorithmIdentifier.RSA.getOID());

    assertNotNull(csr.getPublicKeyAlgorithmName());
    assertEquals(csr.getPublicKeyAlgorithmName(), "RSA");

    assertNotNull(csr.getPublicKeyAlgorithmNameOrOID());
    assertEquals(csr.getPublicKeyAlgorithmNameOrOID(), "RSA");

    assertNull(csr.getPublicKeyAlgorithmParameters());

    assertNotNull(csr.getEncodedPublicKey());

    assertNotNull(csr.getRequestAttributes());
    assertTrue(csr.getRequestAttributes().isEmpty());

    assertNotNull(csr.getExtensions());
    assertTrue(csr.getExtensions().isEmpty());

    assertNotNull(csr.getSignatureValue());

    assertNotNull(csr.toString());

    assertNotNull(csr.toPEM());
    assertFalse(csr.toPEM().isEmpty());

    assertNotNull(csr.toPEMString());
  }



  /**
   * Provides test coverage for the {@code createPKCS8PrivateKey} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreatePKCS8PrivateKey()
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

    final PKCS8PrivateKey privateKey = InternalCertHelper.createPKCS8PrivateKey(
         PKCS8PrivateKeyVersion.V1, PublicKeyAlgorithmIdentifier.RSA.getOID(),
         null, rsaPrivateKey.encode(),  null, null, null);

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

    assertNull(privateKey.getAttributesElement());

    assertNull(privateKey.getPublicKey());

    assertNotNull(privateKey.toString());

    assertNotNull(privateKey.toPEM());
    assertFalse(privateKey.toPEM().isEmpty());

    assertNotNull(privateKey.toPEMString());

    assertNotNull(privateKey.getPKCS8PrivateKeyBytes());

    assertNotNull(privateKey.toPrivateKey());
  }
}
