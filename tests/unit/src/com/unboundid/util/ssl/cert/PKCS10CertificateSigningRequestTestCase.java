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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1BitString;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1Null;
import com.unboundid.asn1.ASN1ObjectIdentifier;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Set;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.OID;
import com.unboundid.util.ObjectPair;



/**
 * This class provides a set of test cases for the
 * PKCS10CertificateSigningRequest class.
 */
public final class PKCS10CertificateSigningRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a valid PKCS#10 certificate signing request with an RSA public key
   * and no optional elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidCSRWithNoOptionalElements()
         throws Exception
  {
    final byte[] modulusBytes = new byte[256];
    modulusBytes[0] = 0x40;
    modulusBytes[255] = 0x01;
    final BigInteger modulus = new BigInteger(modulusBytes);

    final BigInteger exponent = BigInteger.valueOf(65537L);

    final RSAPublicKey publicKey = new RSAPublicKey(modulus, exponent);

    PKCS10CertificateSigningRequest csr = new PKCS10CertificateSigningRequest(
         PKCS10CertificateSigningRequestVersion.V1,
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getOID(), null,
         new ASN1BitString(true, false, true, false, true),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
         PublicKeyAlgorithmIdentifier.RSA.getOID(), null,
         publicKey.encode(), null,
         null);

    assertNotNull(csr.toString());

    assertNotNull(csr.toPEM());
    assertFalse(csr.toPEM().isEmpty());

    assertNotNull(csr.toPEMString());

    csr = new PKCS10CertificateSigningRequest(
         csr.getPKCS10CertificateSigningRequestBytes());

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

    assertNotNull(csr.getDecodedPublicKey());
    assertTrue(csr.getDecodedPublicKey() instanceof RSAPublicKey);

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
   * Tests a valid PKCS#10 certificate signing request with an EC public key
   * and all optional elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidCSRWithAllOptionalElements()
         throws Exception
  {
    final EllipticCurvePublicKey publicKey = new EllipticCurvePublicKey(
         BigInteger.valueOf(1234567890L), BigInteger.valueOf(9876543210L));

    final ArrayList<ObjectPair<OID,ASN1Set>> nonExtensionAttributes =
         new ArrayList<>(2);
    nonExtensionAttributes.add(
         new ObjectPair<>(new OID("1.2.3.4"), new ASN1Set()));
    nonExtensionAttributes.add(
         new ObjectPair<>(new OID("1.2.3.5"), new ASN1Set()));

    PKCS10CertificateSigningRequest csr = new PKCS10CertificateSigningRequest(
         PKCS10CertificateSigningRequestVersion.V1,
         SignatureAlgorithmIdentifier.SHA_256_WITH_ECDSA.getOID(),
         new ASN1Null(), new ASN1BitString(new boolean[2048]),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
         PublicKeyAlgorithmIdentifier.EC.getOID(),
         new ASN1ObjectIdentifier(NamedCurve.SECP256R1.getOID()),
         publicKey.encode(), publicKey, nonExtensionAttributes,
         new SubjectKeyIdentifierExtension(false,
              new ASN1OctetString("keyIdentifier")),
         new SubjectAlternativeNameExtension(false,
              new GeneralNamesBuilder().addDNSName(
                   "ldap.example.com").build()));

    assertNotNull(csr.toString());

    assertNotNull(csr.toPEM());
    assertFalse(csr.toPEM().isEmpty());

    assertNotNull(csr.toPEMString());

    csr = new PKCS10CertificateSigningRequest(
         csr.getPKCS10CertificateSigningRequestBytes());

    assertNotNull(csr.getVersion());
    assertEquals(csr.getVersion(), PKCS10CertificateSigningRequestVersion.V1);

    assertNotNull(csr.getSignatureAlgorithmOID());
    assertEquals(csr.getSignatureAlgorithmOID(),
         SignatureAlgorithmIdentifier.SHA_256_WITH_ECDSA.getOID());

    assertNotNull(csr.getSignatureAlgorithmName());
    assertEquals(csr.getSignatureAlgorithmName(), "SHA-256 with ECDSA");

    assertNotNull(csr.getSignatureAlgorithmNameOrOID());
    assertEquals(csr.getSignatureAlgorithmNameOrOID(), "SHA-256 with ECDSA");

    assertNotNull(csr.getSignatureAlgorithmParameters());

    assertNotNull(csr.getSubjectDN());
    assertEquals(csr.getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));

    assertNotNull(csr.getPublicKeyAlgorithmOID());
    assertEquals(csr.getPublicKeyAlgorithmOID(),
         PublicKeyAlgorithmIdentifier.EC.getOID());

    assertNotNull(csr.getPublicKeyAlgorithmName());
    assertEquals(csr.getPublicKeyAlgorithmName(), "EC");

    assertNotNull(csr.getPublicKeyAlgorithmNameOrOID());
    assertEquals(csr.getPublicKeyAlgorithmNameOrOID(), "EC");

    assertNotNull(csr.getPublicKeyAlgorithmParameters());

    assertNotNull(csr.getEncodedPublicKey());

    assertNotNull(csr.getDecodedPublicKey());
    assertTrue(csr.getDecodedPublicKey() instanceof EllipticCurvePublicKey);

    assertNotNull(csr.getRequestAttributes());
    assertFalse(csr.getRequestAttributes().isEmpty());
    assertEquals(csr.getRequestAttributes().size(), 3);

    assertNotNull(csr.getExtensions());
    assertFalse(csr.getExtensions().isEmpty());
    assertEquals(csr.getExtensions().size(), 2);

    assertNotNull(csr.getSignatureValue());

    assertNotNull(csr.toString());

    assertNotNull(csr.toPEM());
    assertFalse(csr.toPEM().isEmpty());

    assertNotNull(csr.toPEMString());
  }



  /**
   * Tests a certificate signing request with an unrecognized set of OIDs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCSRWithUnrecognizedOIDs()
         throws Exception
  {
    PKCS10CertificateSigningRequest csr = new PKCS10CertificateSigningRequest(
         PKCS10CertificateSigningRequestVersion.V1, new OID("1.2.3.4"), null,
         new ASN1BitString(true, false, true, false, true),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
         new OID("1.2.3.5"), null,
         new ASN1BitString(false, true, false, true, false), null, null);

    assertNotNull(csr.toString());

    assertNotNull(csr.toPEM());
    assertFalse(csr.toPEM().isEmpty());

    assertNotNull(csr.toPEMString());

    csr = new PKCS10CertificateSigningRequest(
         csr.getPKCS10CertificateSigningRequestBytes());

    assertNotNull(csr.getVersion());
    assertEquals(csr.getVersion(), PKCS10CertificateSigningRequestVersion.V1);

    assertNotNull(csr.getSignatureAlgorithmOID());
    assertEquals(csr.getSignatureAlgorithmOID(), new OID("1.2.3.4"));

    assertNull(csr.getSignatureAlgorithmName());

    assertNotNull(csr.getSignatureAlgorithmNameOrOID());
    assertEquals(csr.getSignatureAlgorithmNameOrOID(), "1.2.3.4");

    assertNull(csr.getSignatureAlgorithmParameters());

    assertNotNull(csr.getSubjectDN());
    assertEquals(csr.getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));

    assertNotNull(csr.getPublicKeyAlgorithmOID());
    assertEquals(csr.getPublicKeyAlgorithmOID(), new OID("1.2.3.5"));

    assertNull(csr.getPublicKeyAlgorithmName());

    assertNotNull(csr.getPublicKeyAlgorithmNameOrOID());
    assertEquals(csr.getPublicKeyAlgorithmNameOrOID(), "1.2.3.5");

    assertNull(csr.getPublicKeyAlgorithmParameters());

    assertNotNull(csr.getEncodedPublicKey());

    assertNull(csr.getDecodedPublicKey());

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
   * Tests a valid PKCS#10 certificate signing request with an EC public key
   * and a malformed named curve.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCSRWithECKeyMalformedNamedCurve()
         throws Exception
  {
    final EllipticCurvePublicKey publicKey = new EllipticCurvePublicKey(
         BigInteger.valueOf(1234567890L), BigInteger.valueOf(9876543210L));

    final ArrayList<ObjectPair<OID,ASN1Set>> nonExtensionAttributes =
         new ArrayList<>(2);
    nonExtensionAttributes.add(
         new ObjectPair<>(new OID("1.2.3.4"), new ASN1Set()));
    nonExtensionAttributes.add(
         new ObjectPair<>(new OID("1.2.3.5"), new ASN1Set()));

    PKCS10CertificateSigningRequest csr = new PKCS10CertificateSigningRequest(
         PKCS10CertificateSigningRequestVersion.V1,
         SignatureAlgorithmIdentifier.SHA_256_WITH_ECDSA.getOID(),
         new ASN1Null(), new ASN1BitString(new boolean[2048]),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
         PublicKeyAlgorithmIdentifier.EC.getOID(), new ASN1OctetString(),
         publicKey.encode(), publicKey, nonExtensionAttributes,
         new SubjectKeyIdentifierExtension(false,
              new ASN1OctetString("keyIdentifier")),
         new SubjectAlternativeNameExtension(false,
              new GeneralNamesBuilder().addDNSName(
                   "ldap.example.com").build()));

    assertNotNull(csr.toString());

    assertNotNull(csr.toPEM());
    assertFalse(csr.toPEM().isEmpty());

    assertNotNull(csr.toPEMString());
  }



  /**
   * Tests the behavior when trying to create a CSR with a malformed OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testEncodeWithMalformedOID()
         throws Exception
  {
    new PKCS10CertificateSigningRequest(
         PKCS10CertificateSigningRequestVersion.V1, new OID("malformed"), null,
         new ASN1BitString(true, false, true, false, true),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
         new OID("malformed"), null,
         new ASN1BitString(false, true, false, true, false), null, null);
  }



  /**
   * Tests the behavior when trying to decode a CSR with a byte array that can't
   * be parsed as a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeByteArrayNotSequence()
         throws Exception
  {
    new PKCS10CertificateSigningRequest("not a sequence".getBytes("UTF-8"));
  }



  /**
   * Tests the behavior when trying to decode a CSR from a byte array that is
   * a sequence, but not with three elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeByteArraySequenceInvalidElementCount()
         throws Exception
  {
    new PKCS10CertificateSigningRequest(
         new ASN1Sequence(
              new ASN1OctetString("first"),
              new ASN1OctetString("second")).encode());
  }



  /**
   * Tests the behavior when trying to decode a CSR from a byte array that is
   * a sequence, but whose requestInfo element is not a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeByteArraySequenceFirstElementNotSequence()
         throws Exception
  {
    new PKCS10CertificateSigningRequest(
         new ASN1Sequence(
              new ASN1OctetString("not a sequence"),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(
                        SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.
                             getOID())),
              new ASN1BitString(true, false, true, false, true)).encode());
  }



  /**
   * Tests the behavior when trying to decode a CSR with a malformed version.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedVersion()
         throws Exception
  {
    new PKCS10CertificateSigningRequest(
         new ASN1Sequence(
              new ASN1Sequence(
                   new ASN1OctetString(),
                   X509Certificate.encodeName(new DN("C=US")),
                   new ASN1Sequence(
                        new ASN1Sequence(
                             new ASN1ObjectIdentifier(
                                  PublicKeyAlgorithmIdentifier.RSA.getOID())),
                        new ASN1BitString(new boolean[2048]))),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(
                        SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.
                             getOID())),
              new ASN1BitString(true, false, true, false, true)).encode());
  }



  /**
   * Tests the behavior when trying to decode a CSR with an unrecognized
   * version.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeUnrecognizedVersion()
         throws Exception
  {
    new PKCS10CertificateSigningRequest(
         new ASN1Sequence(
              new ASN1Sequence(
                   new ASN1Integer(1234),
                   X509Certificate.encodeName(new DN("C=US")),
                   new ASN1Sequence(
                        new ASN1Sequence(
                             new ASN1ObjectIdentifier(
                                  PublicKeyAlgorithmIdentifier.RSA.getOID())),
                        new ASN1BitString(new boolean[2048]))),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(
                        SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.
                             getOID())),
              new ASN1BitString(true, false, true, false, true)).encode());
  }



  /**
   * Tests the behavior when trying to decode a CSR with a malformed subject DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedSubject()
         throws Exception
  {
    new PKCS10CertificateSigningRequest(
         new ASN1Sequence(
              new ASN1Sequence(
                   new ASN1Integer(0),
                   new ASN1OctetString("malformed subject DN"),
                   new ASN1Sequence(
                        new ASN1Sequence(
                             new ASN1ObjectIdentifier(
                                  PublicKeyAlgorithmIdentifier.RSA.getOID())),
                        new ASN1BitString(new boolean[2048]))),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(
                        SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.
                             getOID())),
              new ASN1BitString(true, false, true, false, true)).encode());
  }



  /**
   * Tests the behavior when trying to decode a CSR with a malformed public key
   * info object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedPublicKeyInfo()
         throws Exception
  {
    new PKCS10CertificateSigningRequest(
         new ASN1Sequence(
              new ASN1Sequence(
                   new ASN1Integer(0),
                   X509Certificate.encodeName(new DN("C=US")),
                   new ASN1OctetString("malformed public key info")),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(
                        SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.
                             getOID())),
              new ASN1BitString(true, false, true, false, true)).encode());
  }



  /**
   * Tests the behavior when trying to decode a CSR with a malformed set of
   * request attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedAttributes()
         throws Exception
  {
    new PKCS10CertificateSigningRequest(
         new ASN1Sequence(
              new ASN1Sequence(
                   new ASN1Integer(0),
                   X509Certificate.encodeName(new DN("C=US")),
                   new ASN1Sequence(
                        new ASN1Sequence(
                             new ASN1ObjectIdentifier(
                                  PublicKeyAlgorithmIdentifier.RSA.getOID())),
                        new ASN1BitString(new boolean[2048])),
                   new ASN1OctetString((byte) 0xA0, "not a valid set")),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(
                        SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.
                             getOID())),
              new ASN1BitString(true, false, true, false, true)).encode());
  }



  /**
   * Tests the behavior when trying to decode a CSR with a malformed extension
   * attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedExtensionAttribute()
         throws Exception
  {
    new PKCS10CertificateSigningRequest(
         new ASN1Sequence(
              new ASN1Sequence(
                   new ASN1Integer(0),
                   X509Certificate.encodeName(new DN("C=US")),
                   new ASN1Sequence(
                        new ASN1Sequence(
                             new ASN1ObjectIdentifier(
                                  PublicKeyAlgorithmIdentifier.EC.getOID())),
                        new ASN1BitString(new boolean[2048])),
                   new ASN1Set((byte) 0xA0,
                        new ASN1Sequence(
                             new ASN1ObjectIdentifier(
                                  new OID("1.2.840.113549.1.9.14")),
                             new ASN1Set(
                                  new ASN1OctetString("malformed value"))))),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(
                        SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.
                             getOID())),
              new ASN1BitString(true, false, true, false, true)).encode());
  }



  /**
   * Tests the behavior when trying to decode a CSR with a malformed signature
   * algorithm info object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedSignatureAlgorithmInfo()
         throws Exception
  {
    new PKCS10CertificateSigningRequest(
         new ASN1Sequence(
              new ASN1Sequence(
                   new ASN1Integer(0),
                   X509Certificate.encodeName(new DN("C=US")),
                   new ASN1Sequence(
                        new ASN1Sequence(
                             new ASN1ObjectIdentifier(
                                  PublicKeyAlgorithmIdentifier.RSA.getOID())),
                        new ASN1BitString(new boolean[2048]))),
              new ASN1OctetString("malformed signature algorithm info"),
              new ASN1BitString(true, false, true, false, true)).encode());
  }



  /**
   * Tests the behavior when trying to decode a CSR with a malformed signature
   * value object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedSignatureAlgorithmValue()
         throws Exception
  {
    new PKCS10CertificateSigningRequest(
         new ASN1Sequence(
              new ASN1Sequence(
                   new ASN1Integer(0),
                   X509Certificate.encodeName(new DN("C=US")),
                   new ASN1Sequence(
                        new ASN1Sequence(
                             new ASN1ObjectIdentifier(
                                  PublicKeyAlgorithmIdentifier.RSA.getOID())),
                        new ASN1BitString(new boolean[2048]))),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(
                        SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.
                             getOID())),
              new ASN1OctetString()).encode());
  }



  /**
   * Tests the {@code generateCertificateSigningRequest} method with an RSA key
   * pair.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateCertificateSigningRequestWithRSAPair()
         throws Exception
  {
    final KeyPairGenerator keyPairGenerator =
         CryptoHelper.getKeyPairGenerator("RSA");
    keyPairGenerator.initialize(2048);
    final KeyPair keyPair = keyPairGenerator.generateKeyPair();

    final PKCS10CertificateSigningRequest csr =
         PKCS10CertificateSigningRequest.generateCertificateSigningRequest(
              SignatureAlgorithmIdentifier.SHA_256_WITH_RSA, keyPair,
              new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
              new SubjectAlternativeNameExtension(false,
                   new GeneralNamesBuilder().addDNSName(
                        "ldap.example.com").build()));

    assertNotNull(csr);

    assertNotNull(csr.getVersion());
    assertEquals(csr.getVersion(), PKCS10CertificateSigningRequestVersion.V1);

    assertNotNull(csr.getSignatureAlgorithmOID());
    assertEquals(csr.getSignatureAlgorithmOID(),
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getOID());

    assertNotNull(csr.getSignatureAlgorithmName());
    assertEquals(csr.getSignatureAlgorithmName(),
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getUserFriendlyName());

    assertNotNull(csr.getSignatureAlgorithmNameOrOID());
    assertEquals(csr.getSignatureAlgorithmNameOrOID(),
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getUserFriendlyName());

    assertNull(csr.getSignatureAlgorithmParameters());

    assertNotNull(csr.getSignatureValue());

    assertNotNull(csr.getSubjectDN());
    assertEquals(csr.getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));

    assertNotNull(csr.getPublicKeyAlgorithmOID());
    assertEquals(csr.getPublicKeyAlgorithmOID(),
         PublicKeyAlgorithmIdentifier.RSA.getOID());

    assertNotNull(csr.getPublicKeyAlgorithmName());
    assertEquals(csr.getPublicKeyAlgorithmName(),
         PublicKeyAlgorithmIdentifier.RSA.getName());

    assertNotNull(csr.getPublicKeyAlgorithmNameOrOID());
    assertEquals(csr.getPublicKeyAlgorithmNameOrOID(),
         PublicKeyAlgorithmIdentifier.RSA.getName());

    assertNotNull(csr.getPublicKeyAlgorithmParameters());

    assertNotNull(csr.getEncodedPublicKey());

    assertNotNull(csr.getDecodedPublicKey());

    assertNotNull(csr.getRequestAttributes());
    assertFalse(csr.getRequestAttributes().isEmpty());

    assertNotNull(csr.getExtensions());
    assertFalse(csr.getExtensions().isEmpty());

    boolean sanFound = false;
    boolean skiFound = false;
    for (final X509CertificateExtension e : csr.getExtensions())
    {
      if (e instanceof SubjectAlternativeNameExtension)
      {
        assertFalse(sanFound);
        sanFound = true;
      }
      else if (e instanceof SubjectKeyIdentifierExtension)
      {
        assertFalse(skiFound);
        skiFound = true;
      }
      else
      {
        fail("Unexpected extension found in PKCS #10 certificate signing " +
             "request:  " + e);
      }
    }

    csr.verifySignature();

    assertNotNull(csr.toString());

    assertNotNull(csr.toPEM());
    assertFalse(csr.toPEM().isEmpty());

    assertNotNull(csr.toPEMString());
  }



  /**
   * Tests the {@code generateCertificateSigningRequest} method with an elliptic
   * curve key pair.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateCertificateSigningRequestWithECPair()
         throws Exception
  {
    final KeyPairGenerator keyPairGenerator =
         CryptoHelper.getKeyPairGenerator("EC");
    keyPairGenerator.initialize(256);
    final KeyPair keyPair = keyPairGenerator.generateKeyPair();

    final PKCS10CertificateSigningRequest csr =
         PKCS10CertificateSigningRequest.generateCertificateSigningRequest(
              SignatureAlgorithmIdentifier.SHA_256_WITH_ECDSA, keyPair,
              new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
              new SubjectAlternativeNameExtension(false,
                   new GeneralNamesBuilder().addDNSName(
                        "ldap.example.com").build()));

    assertNotNull(csr);

    assertNotNull(csr.getVersion());
    assertEquals(csr.getVersion(), PKCS10CertificateSigningRequestVersion.V1);

    assertNotNull(csr.getSignatureAlgorithmOID());
    assertEquals(csr.getSignatureAlgorithmOID(),
         SignatureAlgorithmIdentifier.SHA_256_WITH_ECDSA.getOID());

    assertNotNull(csr.getSignatureAlgorithmName());
    assertEquals(csr.getSignatureAlgorithmName(),
         SignatureAlgorithmIdentifier.SHA_256_WITH_ECDSA.getUserFriendlyName());

    assertNotNull(csr.getSignatureAlgorithmNameOrOID());
    assertEquals(csr.getSignatureAlgorithmNameOrOID(),
         SignatureAlgorithmIdentifier.SHA_256_WITH_ECDSA.getUserFriendlyName());

    assertNull(csr.getSignatureAlgorithmParameters());

    assertNotNull(csr.getSignatureValue());

    assertNotNull(csr.getSubjectDN());
    assertEquals(csr.getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));

    assertNotNull(csr.getPublicKeyAlgorithmOID());
    assertEquals(csr.getPublicKeyAlgorithmOID(),
         PublicKeyAlgorithmIdentifier.EC.getOID());

    assertNotNull(csr.getPublicKeyAlgorithmName());
    assertEquals(csr.getPublicKeyAlgorithmName(),
         PublicKeyAlgorithmIdentifier.EC.getName());

    assertNotNull(csr.getPublicKeyAlgorithmNameOrOID());
    assertEquals(csr.getPublicKeyAlgorithmNameOrOID(),
         PublicKeyAlgorithmIdentifier.EC.getName());

    assertNotNull(csr.getPublicKeyAlgorithmParameters());

    assertNotNull(csr.getEncodedPublicKey());

    assertNotNull(csr.getDecodedPublicKey());

    assertNotNull(csr.getRequestAttributes());
    assertFalse(csr.getRequestAttributes().isEmpty());

    assertNotNull(csr.getExtensions());
    assertFalse(csr.getExtensions().isEmpty());

    boolean sanFound = false;
    boolean skiFound = false;
    for (final X509CertificateExtension e : csr.getExtensions())
    {
      if (e instanceof SubjectAlternativeNameExtension)
      {
        assertFalse(sanFound);
        sanFound = true;
      }
      else if (e instanceof SubjectKeyIdentifierExtension)
      {
        assertFalse(skiFound);
        skiFound = true;
      }
      else
      {
        fail("Unexpected extension found in PKCS #10 certificate signing " +
             "request:  " + e);
      }
    }

    csr.verifySignature();

    assertNotNull(csr.toString());

    assertNotNull(csr.toPEM());
    assertFalse(csr.toPEM().isEmpty());

    assertNotNull(csr.toPEMString());
  }



  /**
   * Tests the behavior of the {@code verifySignature} method with a malformed
   * public key.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testVerifySignatureMalformedPublicKey()
         throws Exception
  {
    final PKCS10CertificateSigningRequest csr =
         new PKCS10CertificateSigningRequest(
              PKCS10CertificateSigningRequestVersion.V1,
              SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getOID(),
              new ASN1Null(), new ASN1BitString(true, false, true, false),
              new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
              PublicKeyAlgorithmIdentifier.RSA.getOID(), new ASN1Null(),
              new ASN1BitString(false, true, false, true), null, null);
    csr.verifySignature();
  }



  /**
   * Tests the behavior of the {@code verifySignature} method with an unknown
   * signature algorithm.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testVerifySignatureUnknownSignatureAlgorithm()
         throws Exception
  {
    final KeyPairGenerator keyPairGenerator =
         CryptoHelper.getKeyPairGenerator("RSA");
    keyPairGenerator.initialize(2048);
    final KeyPair keyPair = keyPairGenerator.generateKeyPair();

    PKCS10CertificateSigningRequest csr =
         PKCS10CertificateSigningRequest.generateCertificateSigningRequest(
              SignatureAlgorithmIdentifier.SHA_256_WITH_RSA, keyPair,
              new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
              new SubjectAlternativeNameExtension(false,
                   new GeneralNamesBuilder().addDNSName(
                        "ldap.example.com").build()));

    final X509CertificateExtension[] extensions =
         new X509CertificateExtension[csr.getExtensions().size()];
    csr.getExtensions().toArray(extensions);

    csr = new PKCS10CertificateSigningRequest(csr.getVersion(),
         new OID("1.2.3.4"), csr.getSignatureAlgorithmParameters(),
         csr.getSignatureValue(), csr.getSubjectDN(),
         csr.getPublicKeyAlgorithmOID(), csr.getPublicKeyAlgorithmParameters(),
         csr.getEncodedPublicKey(), csr.getDecodedPublicKey(), null,
         extensions);

    csr.verifySignature();
  }



  /**
   * Tests the behavior of the {@code verifySignature} method with a signature
   * that isn't formatted properly.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testVerifySignatureMalformedSignature()
         throws Exception
  {
    final KeyPairGenerator keyPairGenerator =
         CryptoHelper.getKeyPairGenerator("RSA");
    keyPairGenerator.initialize(2048);
    final KeyPair keyPair = keyPairGenerator.generateKeyPair();

    PKCS10CertificateSigningRequest csr =
         PKCS10CertificateSigningRequest.generateCertificateSigningRequest(
              SignatureAlgorithmIdentifier.SHA_256_WITH_RSA, keyPair,
              new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
              new SubjectAlternativeNameExtension(false,
                   new GeneralNamesBuilder().addDNSName(
                        "ldap.example.com").build()));

    final X509CertificateExtension[] extensions =
         new X509CertificateExtension[csr.getExtensions().size()];
    csr.getExtensions().toArray(extensions);

    csr = new PKCS10CertificateSigningRequest(csr.getVersion(),
         csr.getSignatureAlgorithmOID(), null,
         new ASN1BitString(true, false, true, false, true),
         csr.getSubjectDN(), csr.getPublicKeyAlgorithmOID(), null,
         csr.getEncodedPublicKey(), csr.getDecodedPublicKey(), null,
         extensions);

    csr.verifySignature();
  }



  /**
   * Tests the behavior of the {@code verifySignature} method with an invalid
   * signature.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testVerifySignatureInvalidSignature()
         throws Exception
  {
    final KeyPairGenerator keyPairGenerator =
         CryptoHelper.getKeyPairGenerator("RSA");
    keyPairGenerator.initialize(2048);
    final KeyPair keyPair = keyPairGenerator.generateKeyPair();

    PKCS10CertificateSigningRequest csr =
         PKCS10CertificateSigningRequest.generateCertificateSigningRequest(
              SignatureAlgorithmIdentifier.SHA_256_WITH_RSA, keyPair,
              new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
              new SubjectAlternativeNameExtension(false,
                   new GeneralNamesBuilder().addDNSName(
                        "ldap.example.com").build()));

    final X509CertificateExtension[] extensions =
         new X509CertificateExtension[csr.getExtensions().size()];
    csr.getExtensions().toArray(extensions);

    csr = new PKCS10CertificateSigningRequest(csr.getVersion(),
         csr.getSignatureAlgorithmOID(), null,
         new ASN1BitString(ASN1BitString.getBitsForBytes(new byte[256])),
         csr.getSubjectDN(), csr.getPublicKeyAlgorithmOID(),
         csr.getPublicKeyAlgorithmParameters(), csr.getEncodedPublicKey(),
         csr.getDecodedPublicKey(), null, extensions);

    csr.verifySignature();
  }
}
