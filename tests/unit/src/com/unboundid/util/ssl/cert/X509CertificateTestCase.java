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
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1BigInteger;
import com.unboundid.asn1.ASN1BitString;
import com.unboundid.asn1.ASN1Constants;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1GeneralizedTime;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1Null;
import com.unboundid.asn1.ASN1ObjectIdentifier;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Set;
import com.unboundid.asn1.ASN1UTCTime;
import com.unboundid.asn1.ASN1UTF8String;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.DebugType;
import com.unboundid.util.OID;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.TestLogHandler;
import com.unboundid.util.ssl.JVMDefaultTrustManager;



/**
 * This class provides a set of test cases for the X509Certificate class.
 */
public final class X509CertificateTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a valid X.509 certificate with an RSA public key and no optional
   * elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidCertificateWithRSAKeyNoOptionalElements()
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

    X509Certificate c = new X509Certificate(X509CertificateVersion.V1,
         BigInteger.valueOf(123456789L),
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getOID(), null,
         new ASN1BitString(new boolean[1024]),
         new DN("CN=Issuer,O=Example Corp,C=US"), notBefore, notAfter,
         new DN("CN=ldap.example.com,O=Example Corp,C=US"),
         PublicKeyAlgorithmIdentifier.RSA.getOID(), null,
         publicKey.encode(), publicKey, null, null);

    assertNotNull(c.getX509CertificateBytes());

    c = new X509Certificate(c.encode().encode());

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
   * Tests a valid X.509 certificate with an elliptic curve public key and all
   * optional elements, including all supported types of extensions (and an
   * unsupported type of extension).
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidCertificateWithECKeyAllOptionalElements()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    final EllipticCurvePublicKey publicKey = new EllipticCurvePublicKey(
         BigInteger.valueOf(1234567890L), BigInteger.valueOf(9876543210L));

    final boolean[] issuerUniqueIDBits = { true, false, true, false, true };
    final boolean[] subjectUniqueIDBits = { false, true, false, true, false};

    X509Certificate c = new X509Certificate(X509CertificateVersion.V3,
         BigInteger.valueOf(987654321L),
         SignatureAlgorithmIdentifier.SHA_256_WITH_ECDSA.getOID(),
         new ASN1Null(), new ASN1BitString(new boolean[256]),
         new DN("CN=Issuer,O=Example Corp,C=US"), notBefore, notAfter,
         new DN("CN=ldap.example.com,O=Example Corp,C=US"),
         PublicKeyAlgorithmIdentifier.EC.getOID(),
         new ASN1ObjectIdentifier(NamedCurve.SECP256R1.getOID()),
         publicKey.encode(), publicKey,
         new ASN1BitString(issuerUniqueIDBits),
         new ASN1BitString(subjectUniqueIDBits),
         new X509CertificateExtension(new OID("1.2.3.4"), true,
              "foo".getBytes("UTF-8")),
         new AuthorityKeyIdentifierExtension(false,
              new ASN1OctetString("authority-key-identifier"), null, null),
         new BasicConstraintsExtension(false, false, null),
         new CRLDistributionPointsExtension(false,
              Collections.singletonList(new CRLDistributionPoint(
                   new GeneralNamesBuilder().addDNSName(
                        "crl.example.com").build(),
                   null, null))),
         new ExtendedKeyUsageExtension(false,
              Arrays.asList(
                   ExtendedKeyUsageID.TLS_SERVER_AUTHENTICATION.getOID(),
                   ExtendedKeyUsageID.TLS_CLIENT_AUTHENTICATION.getOID())),
         new IssuerAlternativeNameExtension(false,
              new GeneralNamesBuilder().addDNSName(
                   "issuer.example.com").build()),
         new KeyUsageExtension(false, true, true, true, true, true, true, true,
              true, true),
         new SubjectAlternativeNameExtension(false,
              new GeneralNamesBuilder().addDNSName(
                   "ldap.example.com").build()),
         new SubjectKeyIdentifierExtension(false,
              new ASN1OctetString("subject-key-identifier")));

    assertNotNull(c.getX509CertificateBytes());

    c = new X509Certificate(c.encode().encode());

    assertNotNull(c.getVersion());
    assertEquals(c.getVersion(), X509CertificateVersion.V3);

    assertNotNull(c.getSerialNumber());
    assertEquals(c.getSerialNumber(), BigInteger.valueOf(987654321L));

    assertNotNull(c.getSignatureAlgorithmOID());
    assertEquals(c.getSignatureAlgorithmOID(),
         SignatureAlgorithmIdentifier.SHA_256_WITH_ECDSA.getOID());

    assertNotNull(c.getSignatureAlgorithmName());
    assertEquals(c.getSignatureAlgorithmName(), "SHA-256 with ECDSA");

    assertNotNull(c.getSignatureAlgorithmNameOrOID());
    assertEquals(c.getSignatureAlgorithmNameOrOID(), "SHA-256 with ECDSA");

    assertNotNull(c.getSignatureAlgorithmParameters());

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
         PublicKeyAlgorithmIdentifier.EC.getOID());

    assertNotNull(c.getPublicKeyAlgorithmName());
    assertEquals(c.getPublicKeyAlgorithmName(), "EC");

    assertNotNull(c.getPublicKeyAlgorithmNameOrOID());
    assertEquals(c.getPublicKeyAlgorithmNameOrOID(), "EC");

    assertNotNull(c.getPublicKeyAlgorithmParameters());
    assertEquals(
         c.getPublicKeyAlgorithmParameters().decodeAsObjectIdentifier().
              getOID(),
         NamedCurve.SECP256R1.getOID());

    assertNotNull(c.getEncodedPublicKey());

    assertNotNull(c.getDecodedPublicKey());
    assertTrue(c.getDecodedPublicKey() instanceof EllipticCurvePublicKey);

    assertNotNull(c.getIssuerUniqueID());
    assertTrue(Arrays.equals(c.getIssuerUniqueID().getBits(),
         issuerUniqueIDBits));

    assertNotNull(c.getSubjectUniqueID());
    assertTrue(Arrays.equals(c.getSubjectUniqueID().getBits(),
         subjectUniqueIDBits));

    final List<X509CertificateExtension> extensions = c.getExtensions();
    assertNotNull(extensions);
    assertFalse(extensions.isEmpty());
    assertEquals(extensions.size(), 9);

    assertEquals(extensions.get(0).getOID(), new OID("1.2.3.4"));
    assertTrue(extensions.get(1) instanceof AuthorityKeyIdentifierExtension);
    assertTrue(extensions.get(2) instanceof BasicConstraintsExtension);
    assertTrue(extensions.get(3) instanceof CRLDistributionPointsExtension);
    assertTrue(extensions.get(4) instanceof ExtendedKeyUsageExtension);
    assertTrue(extensions.get(5) instanceof IssuerAlternativeNameExtension);
    assertTrue(extensions.get(6) instanceof KeyUsageExtension);
    assertTrue(extensions.get(7) instanceof SubjectAlternativeNameExtension);
    assertTrue(extensions.get(8) instanceof SubjectKeyIdentifierExtension);

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
   * Tests a valid X.509 certificate with unknown signature and public key
   * algorithms.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidCertificateWithUnknownSignatureAndPublicKeyAlgorithms()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    X509Certificate c = new X509Certificate(X509CertificateVersion.V1,
         BigInteger.valueOf(123456789L), new OID("1.2.3.4"), new ASN1Null(),
         new ASN1BitString(new boolean[1235]),
         new DN("CN=Issuer,O=Example Corp,C=US"), notBefore, notAfter,
         new DN("CN=ldap.example.com,O=Example Corp,C=US"), new OID("1.2.3.5"),
         new ASN1Null(), new ASN1BitString(new boolean[123]), null, null, null);

    assertNotNull(c.getX509CertificateBytes());

    c = new X509Certificate(c.encode().encode());

    assertNotNull(c.getVersion());
    assertEquals(c.getVersion(), X509CertificateVersion.V1);

    assertNotNull(c.getSerialNumber());
    assertEquals(c.getSerialNumber(), BigInteger.valueOf(123456789L));

    assertNotNull(c.getSignatureAlgorithmOID());
    assertEquals(c.getSignatureAlgorithmOID(), new OID("1.2.3.4"));

    assertNull(c.getSignatureAlgorithmName());

    assertNotNull(c.getSignatureAlgorithmNameOrOID());
    assertEquals(c.getSignatureAlgorithmNameOrOID(), "1.2.3.4");

    assertNotNull(c.getSignatureAlgorithmParameters());

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
    assertEquals(c.getPublicKeyAlgorithmOID(), new OID("1.2.3.5"));

    assertNull(c.getPublicKeyAlgorithmName());

    assertNotNull(c.getPublicKeyAlgorithmNameOrOID());
    assertEquals(c.getPublicKeyAlgorithmNameOrOID(), "1.2.3.5");

    assertNotNull(c.getPublicKeyAlgorithmParameters());

    assertNotNull(c.getEncodedPublicKey());

    assertNull(c.getDecodedPublicKey());

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
   * Tests a valid X.509 certificate that claims to have an RSA public key, but
   * whose public key cannot actually be parsed as an RSA key.  This won't
   * cause an error, but will result in the public key not being available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCertificateWithInvalidRSAPublicKey()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    X509Certificate c = new X509Certificate(X509CertificateVersion.V1,
         BigInteger.valueOf(123456789L), new OID("1.2.3.4"), new ASN1Null(),
         new ASN1BitString(new boolean[1235]),
         new DN("CN=Issuer,O=Example Corp,C=US"), notBefore, notAfter,
         new DN("CN=ldap.example.com,O=Example Corp,C=US"),
         PublicKeyAlgorithmIdentifier.RSA.getOID(), new ASN1Null(),
         new ASN1BitString(new boolean[123]), null, null, null);

    assertNotNull(c.getX509CertificateBytes());

    c = new X509Certificate(c.encode().encode());

    assertNotNull(c.getVersion());
    assertEquals(c.getVersion(), X509CertificateVersion.V1);

    assertNotNull(c.getSerialNumber());
    assertEquals(c.getSerialNumber(), BigInteger.valueOf(123456789L));

    assertNotNull(c.getSignatureAlgorithmOID());
    assertEquals(c.getSignatureAlgorithmOID(), new OID("1.2.3.4"));

    assertNull(c.getSignatureAlgorithmName());

    assertNotNull(c.getSignatureAlgorithmNameOrOID());
    assertEquals(c.getSignatureAlgorithmNameOrOID(), "1.2.3.4");

    assertNotNull(c.getSignatureAlgorithmParameters());

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

    assertNotNull(c.getPublicKeyAlgorithmParameters());

    assertNotNull(c.getEncodedPublicKey());

    assertNull(c.getDecodedPublicKey());

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
  }



  /**
   * Tests a valid X.509 certificate that claims to have an elliptic curve
   * public key, but whose public key cannot actually be parsed as an RSA key.
   * This won't cause an error, but will result in the public key not being
   * available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCertificateWithInvalidEllipticCurvePublicKey()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    X509Certificate c = new X509Certificate(X509CertificateVersion.V1,
         BigInteger.valueOf(123456789L), new OID("1.2.3.4"), new ASN1Null(),
         new ASN1BitString(new boolean[1235]),
         new DN("CN=Issuer,O=Example Corp,C=US"), notBefore, notAfter,
         new DN("CN=ldap.example.com,O=Example Corp,C=US"),
         PublicKeyAlgorithmIdentifier.EC.getOID(), new ASN1Null(),
         new ASN1BitString(new boolean[123]), null, null, null);

    assertNotNull(c.getX509CertificateBytes());

    c = new X509Certificate(c.encode().encode());

    assertNotNull(c.getVersion());
    assertEquals(c.getVersion(), X509CertificateVersion.V1);

    assertNotNull(c.getSerialNumber());
    assertEquals(c.getSerialNumber(), BigInteger.valueOf(123456789L));

    assertNotNull(c.getSignatureAlgorithmOID());
    assertEquals(c.getSignatureAlgorithmOID(), new OID("1.2.3.4"));

    assertNull(c.getSignatureAlgorithmName());

    assertNotNull(c.getSignatureAlgorithmNameOrOID());
    assertEquals(c.getSignatureAlgorithmNameOrOID(), "1.2.3.4");

    assertNotNull(c.getSignatureAlgorithmParameters());

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
         PublicKeyAlgorithmIdentifier.EC.getOID());

    assertNotNull(c.getPublicKeyAlgorithmName());
    assertEquals(c.getPublicKeyAlgorithmName(), "EC");

    assertNotNull(c.getPublicKeyAlgorithmNameOrOID());
    assertEquals(c.getPublicKeyAlgorithmNameOrOID(), "EC");

    assertNotNull(c.getPublicKeyAlgorithmParameters());

    assertNotNull(c.getEncodedPublicKey());

    assertNull(c.getDecodedPublicKey());

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
  }



  /**
   * Tests a valid X.509 certificate with a bunch of malformed extensions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCertificateWithMalformedExtensions()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    X509Certificate c = new X509Certificate(X509CertificateVersion.V1,
         BigInteger.valueOf(123456789L), new OID("1.2.3.4"), new ASN1Null(),
         new ASN1BitString(new boolean[1235]),
         new DN("CN=Issuer,O=Example Corp,C=US"), notBefore, notAfter,
         new DN("CN=ldap.example.com,O=Example Corp,C=US"),
         PublicKeyAlgorithmIdentifier.EC.getOID(), new ASN1Null(),
         new ASN1BitString(new boolean[123]), null, null, null,
         new X509CertificateExtension(
              AuthorityKeyIdentifierExtension.AUTHORITY_KEY_IDENTIFIER_OID,
              true, StaticUtils.NO_BYTES),
         new X509CertificateExtension(
              BasicConstraintsExtension.BASIC_CONSTRAINTS_OID,
              true, StaticUtils.NO_BYTES),
         new X509CertificateExtension(
              CRLDistributionPointsExtension.CRL_DISTRIBUTION_POINTS_OID,
              true, StaticUtils.NO_BYTES),
         new X509CertificateExtension(
              ExtendedKeyUsageExtension.EXTENDED_KEY_USAGE_OID,
              true, StaticUtils.NO_BYTES),
         new X509CertificateExtension(
              IssuerAlternativeNameExtension.ISSUER_ALTERNATIVE_NAME_OID,
              true, StaticUtils.NO_BYTES),
         new X509CertificateExtension(KeyUsageExtension.KEY_USAGE_OID,
              true, StaticUtils.NO_BYTES),
         new X509CertificateExtension(
              SubjectAlternativeNameExtension.SUBJECT_ALTERNATIVE_NAME_OID,
              true, StaticUtils.NO_BYTES),
         new X509CertificateExtension(
              SubjectKeyIdentifierExtension.SUBJECT_KEY_IDENTIFIER_OID,
              true, StaticUtils.NO_BYTES));

    assertNotNull(c.getX509CertificateBytes());

    c = new X509Certificate(c.encode().encode());

    assertNotNull(c.getVersion());
    assertEquals(c.getVersion(), X509CertificateVersion.V1);

    assertNotNull(c.getSerialNumber());
    assertEquals(c.getSerialNumber(), BigInteger.valueOf(123456789L));

    assertNotNull(c.getSignatureAlgorithmOID());
    assertEquals(c.getSignatureAlgorithmOID(), new OID("1.2.3.4"));

    assertNull(c.getSignatureAlgorithmName());

    assertNotNull(c.getSignatureAlgorithmNameOrOID());
    assertEquals(c.getSignatureAlgorithmNameOrOID(), "1.2.3.4");

    assertNotNull(c.getSignatureAlgorithmParameters());

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
         PublicKeyAlgorithmIdentifier.EC.getOID());

    assertNotNull(c.getPublicKeyAlgorithmName());
    assertEquals(c.getPublicKeyAlgorithmName(), "EC");

    assertNotNull(c.getPublicKeyAlgorithmNameOrOID());
    assertEquals(c.getPublicKeyAlgorithmNameOrOID(), "EC");

    assertNotNull(c.getPublicKeyAlgorithmParameters());

    assertNotNull(c.getEncodedPublicKey());

    assertNull(c.getDecodedPublicKey());

    assertNull(c.getIssuerUniqueID());

    assertNull(c.getSubjectUniqueID());

    assertNotNull(c.getExtensions());
    assertFalse(c.getExtensions().isEmpty());
    assertEquals(c.getExtensions().size(), 8);

    assertNotNull(c.getSignatureValue());

    assertNotNull(c.toString());

    assertNotNull(c.toPEM());
    assertFalse(c.toPEM().isEmpty());

    assertNotNull(c.toPEMString());

    assertNotNull(c.getX509CertificateBytes());

    assertNotNull(c.getSHA1Fingerprint());

    assertNotNull(c.getSHA256Fingerprint());
  }



  /**
   * Tests the behavior when trying to encode a certificate that includes a
   * malformed OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testEncodeCertificateWithInvalidOID()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    final X509Certificate c = new X509Certificate(X509CertificateVersion.V1,
         BigInteger.valueOf(123456789L), new OID("1234.5678"), new ASN1Null(),
         new ASN1BitString(new boolean[1235]),
         new DN("CN=Issuer,O=Example Corp,C=US"), notBefore, notAfter,
         new DN("CN=ldap.example.com,O=Example Corp,C=US"), new OID("1.2.3.5"),
         new ASN1Null(), new ASN1BitString(new boolean[123]), null, null, null);

    c.encode();
  }


  /**
   * Tests the behavior when trying to decode a byte array whose contents cannot
   * be parsed as a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new X509Certificate("not a valid sequence".getBytes("UTF-8"));
  }



 /**
  * Tests the behavior when trying to decode a sequence that does not contain
  * exactly three elements.
  *
  * @throws  Exception  If an unexpected problem occurs.
  */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeValueSequenceInvalidNumberOfElements()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(
              new ASN1ObjectIdentifier(new OID("1.2.3.4")),
              new ASN1Null()),
         new ASN1BitString(new boolean[1024]));

    new X509Certificate(valueSequence.encode());
  }



 /**
  * Tests the behavior when trying to decode a sequence whose first element
  * cannot itself be parsed as a sequence.
  *
  * @throws  Exception  If an unexpected problem occurs.
  */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeValueSequenceFirstElementNotSequence()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString("not a sequence"),
         new ASN1Sequence(
              new ASN1ObjectIdentifier(new OID("1.2.3.4")),
              new ASN1Null()),
         new ASN1BitString(new boolean[1024]));

    new X509Certificate(valueSequence.encode());
  }



 /**
  * Tests the behavior when trying to decode a certificate with a version that
  * cannot be parsed as an integer.
  *
  * @throws  Exception  If an unexpected problem occurs.
  */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeVersionNotInteger()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(
              new ASN1Element((byte) 0xA0),
              new ASN1BigInteger(12435L),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(new OID("1.2.3.4")),
                   new ASN1Null()),
              X509Certificate.encodeName(new DN("CN=issuer")),
              new ASN1Sequence(
                   new ASN1UTCTime(notBefore),
                   new ASN1UTCTime(notAfter)),
              X509Certificate.encodeName(new DN("CN=ldap.example.com")),
              new ASN1Sequence(
                   new ASN1Sequence(
                        new ASN1ObjectIdentifier(new OID("1.2.3.5")),
                        new ASN1Null()),
                   new ASN1BitString(new boolean[1024]))),
         new ASN1Sequence(
              new ASN1ObjectIdentifier(new OID("1.2.3.4")),
              new ASN1Null()),
         new ASN1BitString(new boolean[1024]));

    new X509Certificate(valueSequence.encode());
  }



 /**
  * Tests the behavior when trying to decode a certificate with a version that
  * is out of the range of allowed values.
  *
  * @throws  Exception  If an unexpected problem occurs.
  */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeVersionOutOfRange()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(
              new ASN1Element((byte) 0xA0,
                   new ASN1Integer(999).encode()),
              new ASN1BigInteger(12435L),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(new OID("1.2.3.4")),
                   new ASN1Null()),
              X509Certificate.encodeName(new DN("CN=issuer")),
              new ASN1Sequence(
                   new ASN1UTCTime(notBefore),
                   new ASN1UTCTime(notAfter)),
              X509Certificate.encodeName(new DN("CN=ldap.example.com")),
              new ASN1Sequence(
                   new ASN1Sequence(
                        new ASN1ObjectIdentifier(new OID("1.2.3.5")),
                        new ASN1Null()),
                   new ASN1BitString(new boolean[1024]))),
         new ASN1Sequence(
              new ASN1ObjectIdentifier(new OID("1.2.3.4")),
              new ASN1Null()),
         new ASN1BitString(new boolean[1024]));

    new X509Certificate(valueSequence.encode());
  }



 /**
  * Tests the behavior when trying to decode a certificate with a serial number
  * that cannot be parsed as an integer.
  *
  * @throws  Exception  If an unexpected problem occurs.
  */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeSerialNumberNotInteger()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(
              new ASN1Element((byte) 0xA0,
                   new ASN1Integer(2).encode()),
              new ASN1OctetString(),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(new OID("1.2.3.4")),
                   new ASN1Null()),
              X509Certificate.encodeName(new DN("CN=issuer")),
              new ASN1Sequence(
                   new ASN1UTCTime(notBefore),
                   new ASN1UTCTime(notAfter)),
              X509Certificate.encodeName(new DN("CN=ldap.example.com")),
              new ASN1Sequence(
                   new ASN1Sequence(
                        new ASN1ObjectIdentifier(new OID("1.2.3.5")),
                        new ASN1Null()),
                   new ASN1BitString(new boolean[1024]))),
         new ASN1Sequence(
              new ASN1ObjectIdentifier(new OID("1.2.3.4")),
              new ASN1Null()),
         new ASN1BitString(new boolean[1024]));

    new X509Certificate(valueSequence.encode());
  }



 /**
  * Tests the behavior when trying to decode a certificate with a signature
  * algorithm element that is not a valid sequence.
  *
  * @throws  Exception  If an unexpected problem occurs.
  */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeSignatureAlgorithmElementNotSequence()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(
              new ASN1Element((byte) 0xA0,
                   new ASN1Integer(2).encode()),
              new ASN1BigInteger(12435L),
              new ASN1OctetString("not a valid sequence"),
              X509Certificate.encodeName(new DN("CN=issuer")),
              new ASN1Sequence(
                   new ASN1UTCTime(notBefore),
                   new ASN1UTCTime(notAfter)),
              X509Certificate.encodeName(new DN("CN=ldap.example.com")),
              new ASN1Sequence(
                   new ASN1Sequence(
                        new ASN1ObjectIdentifier(new OID("1.2.3.5")),
                        new ASN1Null()),
                   new ASN1BitString(new boolean[1024]))),
         new ASN1Sequence(
              new ASN1ObjectIdentifier(new OID("1.2.3.4")),
              new ASN1Null()),
         new ASN1BitString(new boolean[1024]));

    new X509Certificate(valueSequence.encode());
  }



 /**
  * Tests the behavior when trying to decode a certificate with a malformed
  * issuer DN element.
  *
  * @throws  Exception  If an unexpected problem occurs.
  */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedIssuerDN()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(
              new ASN1Element((byte) 0xA0,
                   new ASN1Integer(2).encode()),
              new ASN1BigInteger(12435L),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(new OID("1.2.3.4")),
                   new ASN1Null()),
              new ASN1OctetString("malformed issuer DN"),
              new ASN1Sequence(
                   new ASN1UTCTime(notBefore),
                   new ASN1UTCTime(notAfter)),
              X509Certificate.encodeName(new DN("CN=ldap.example.com")),
              new ASN1Sequence(
                   new ASN1Sequence(
                        new ASN1ObjectIdentifier(new OID("1.2.3.5")),
                        new ASN1Null()),
                   new ASN1BitString(new boolean[1024]))),
         new ASN1Sequence(
              new ASN1ObjectIdentifier(new OID("1.2.3.4")),
              new ASN1Null()),
         new ASN1BitString(new boolean[1024]));

    new X509Certificate(valueSequence.encode());
  }



 /**
  * Tests the behavior when trying to decode a certificate with a validity
  * element that cannot be parsed as a sequence.
  *
  * @throws  Exception  If an unexpected problem occurs.
  */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeValidityNotSequence()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(
              new ASN1Element((byte) 0xA0,
                   new ASN1Integer(2).encode()),
              new ASN1BigInteger(12435L),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(new OID("1.2.3.4")),
                   new ASN1Null()),
              X509Certificate.encodeName(new DN("CN=issuer")),
              new ASN1OctetString("not a valid sequence"),
              X509Certificate.encodeName(new DN("CN=ldap.example.com")),
              new ASN1Sequence(
                   new ASN1Sequence(
                        new ASN1ObjectIdentifier(new OID("1.2.3.5")),
                        new ASN1Null()),
                   new ASN1BitString(new boolean[1024]))),
         new ASN1Sequence(
              new ASN1ObjectIdentifier(new OID("1.2.3.4")),
              new ASN1Null()),
         new ASN1BitString(new boolean[1024]));

    new X509Certificate(valueSequence.encode());
  }



 /**
  * Tests the behavior when trying to decode a certificate with a validity
  * sequence whose first element is neither a UTCTime nor a GeneralizedTime.
  *
  * @throws  Exception  If an unexpected problem occurs.
  */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeValidityMalformedNotBefore()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(
              new ASN1Element((byte) 0xA0,
                   new ASN1Integer(2).encode()),
              new ASN1BigInteger(12435L),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(new OID("1.2.3.4")),
                   new ASN1Null()),
              X509Certificate.encodeName(new DN("CN=issuer")),
              new ASN1Sequence(
                   new ASN1OctetString("malformed notBefore"),
                   new ASN1UTCTime(notAfter)),
              X509Certificate.encodeName(new DN("CN=ldap.example.com")),
              new ASN1Sequence(
                   new ASN1Sequence(
                        new ASN1ObjectIdentifier(new OID("1.2.3.5")),
                        new ASN1Null()),
                   new ASN1BitString(new boolean[1024]))),
         new ASN1Sequence(
              new ASN1ObjectIdentifier(new OID("1.2.3.4")),
              new ASN1Null()),
         new ASN1BitString(new boolean[1024]));

    new X509Certificate(valueSequence.encode());
  }



 /**
  * Tests the behavior when trying to decode a certificate with a validity
  * sequence whose second element is neither a UTCTime nor a GeneralizedTime.
  *
  * @throws  Exception  If an unexpected problem occurs.
  */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeValidityMalformedNotAfter()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(
              new ASN1Element((byte) 0xA0,
                   new ASN1Integer(2).encode()),
              new ASN1BigInteger(12435L),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(new OID("1.2.3.4")),
                   new ASN1Null()),
              X509Certificate.encodeName(new DN("CN=issuer")),
              new ASN1Sequence(
                   new ASN1GeneralizedTime(notBefore),
                   new ASN1OctetString("malformed notAfter")),
              X509Certificate.encodeName(new DN("CN=ldap.example.com")),
              new ASN1Sequence(
                   new ASN1Sequence(
                        new ASN1ObjectIdentifier(new OID("1.2.3.5")),
                        new ASN1Null()),
                   new ASN1BitString(new boolean[1024]))),
         new ASN1Sequence(
              new ASN1ObjectIdentifier(new OID("1.2.3.4")),
              new ASN1Null()),
         new ASN1BitString(new boolean[1024]));

    new X509Certificate(valueSequence.encode());
  }



 /**
  * Tests the behavior when trying to decode a certificate with a malformed
  * subject DN.
  *
  * @throws  Exception  If an unexpected problem occurs.
  */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedSubjectDN()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(
              new ASN1Element((byte) 0xA0,
                   new ASN1Integer(2).encode()),
              new ASN1BigInteger(12435L),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(new OID("1.2.3.4")),
                   new ASN1Null()),
              X509Certificate.encodeName(new DN("CN=issuer")),
              new ASN1Sequence(
                   new ASN1GeneralizedTime(notBefore),
                   new ASN1GeneralizedTime(notAfter)),
              new ASN1OctetString("malformed subject DN"),
              new ASN1Sequence(
                   new ASN1Sequence(
                        new ASN1ObjectIdentifier(new OID("1.2.3.5")),
                        new ASN1Null()),
                   new ASN1BitString(new boolean[1024]))),
         new ASN1Sequence(
              new ASN1ObjectIdentifier(new OID("1.2.3.4")),
              new ASN1Null()),
         new ASN1BitString(new boolean[1024]));

    new X509Certificate(valueSequence.encode());
  }



 /**
  * Tests the behavior when trying to decode a certificate with a malformed
  * public key info structure.
  *
  * @throws  Exception  If an unexpected problem occurs.
  */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedPublicKey()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(
              new ASN1Element((byte) 0xA0,
                   new ASN1Integer(2).encode()),
              new ASN1BigInteger(12435L),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(new OID("1.2.3.4")),
                   new ASN1Null()),
              X509Certificate.encodeName(new DN("CN=issuer")),
              new ASN1Sequence(
                   new ASN1GeneralizedTime(notBefore),
                   new ASN1GeneralizedTime(notAfter)),
              X509Certificate.encodeName(new DN("CN=ldap.example.com")),
              new ASN1OctetString("not a valid sequence")),
         new ASN1Sequence(
              new ASN1ObjectIdentifier(new OID("1.2.3.4")),
              new ASN1Null()),
         new ASN1BitString(new boolean[1024]));

    new X509Certificate(valueSequence.encode());
  }



 /**
  * Tests the behavior when trying to decode a certificate with a malformed
  * issuer unique ID.
  *
  * @throws  Exception  If an unexpected problem occurs.
  */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedIssuerUniqueID()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(
              new ASN1Element((byte) 0xA0,
                   new ASN1Integer(2).encode()),
              new ASN1BigInteger(12435L),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(new OID("1.2.3.4")),
                   new ASN1Null()),
              X509Certificate.encodeName(new DN("CN=issuer")),
              new ASN1Sequence(
                   new ASN1GeneralizedTime(notBefore),
                   new ASN1GeneralizedTime(notAfter)),
              X509Certificate.encodeName(new DN("CN=ldap.example.com")),
              new ASN1Sequence(
                   new ASN1Sequence(
                        new ASN1ObjectIdentifier(new OID("1.2.3.5")),
                        new ASN1Null()),
                   new ASN1BitString(new boolean[1024])),
              new ASN1Element((byte) 0x81)),
         new ASN1Sequence(
              new ASN1ObjectIdentifier(new OID("1.2.3.4")),
              new ASN1Null()),
         new ASN1BitString(new boolean[1024]));

    new X509Certificate(valueSequence.encode());
  }



 /**
  * Tests the behavior when trying to decode a certificate with a malformed
  * subject unique ID.
  *
  * @throws  Exception  If an unexpected problem occurs.
  */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedSubjectUniqueID()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(
              new ASN1Element((byte) 0xA0,
                   new ASN1Integer(2).encode()),
              new ASN1BigInteger(12435L),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(new OID("1.2.3.4")),
                   new ASN1Null()),
              X509Certificate.encodeName(new DN("CN=issuer")),
              new ASN1Sequence(
                   new ASN1GeneralizedTime(notBefore),
                   new ASN1GeneralizedTime(notAfter)),
              X509Certificate.encodeName(new DN("CN=ldap.example.com")),
              new ASN1Sequence(
                   new ASN1Sequence(
                        new ASN1ObjectIdentifier(new OID("1.2.3.5")),
                        new ASN1Null()),
                   new ASN1BitString(new boolean[1024])),
              new ASN1Element((byte) 0x82)),
         new ASN1Sequence(
              new ASN1ObjectIdentifier(new OID("1.2.3.4")),
              new ASN1Null()),
         new ASN1BitString(new boolean[1024]));

    new X509Certificate(valueSequence.encode());
  }



 /**
  * Tests the behavior when trying to decode a certificate with a malformed
  * subject unique ID.
  *
  * @throws  Exception  If an unexpected problem occurs.
  */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedExtension()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(
              new ASN1Element((byte) 0xA0,
                   new ASN1Integer(2).encode()),
              new ASN1BigInteger(12435L),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(new OID("1.2.3.4")),
                   new ASN1Null()),
              X509Certificate.encodeName(new DN("CN=issuer")),
              new ASN1Sequence(
                   new ASN1GeneralizedTime(notBefore),
                   new ASN1GeneralizedTime(notAfter)),
              X509Certificate.encodeName(new DN("CN=ldap.example.com")),
              new ASN1Sequence(
                   new ASN1Sequence(
                        new ASN1ObjectIdentifier(new OID("1.2.3.5")),
                        new ASN1Null()),
                   new ASN1BitString(new boolean[1024])),
              new ASN1Element((byte) 0xA3)),
         new ASN1Sequence(
              new ASN1ObjectIdentifier(new OID("1.2.3.4")),
              new ASN1Null()),
         new ASN1BitString(new boolean[1024]));

    new X509Certificate(valueSequence.encode());
  }



 /**
  * Tests the behavior when trying to decode a certificate with a mismatch in
  * the signature algorithm between the TBSCertificate and Certificate
  * sequences.
  *
  * @throws  Exception  If an unexpected problem occurs.
  */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedCertSignatureAlgorithm()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(
              new ASN1Element((byte) 0xA0,
                   new ASN1Integer(2).encode()),
              new ASN1BigInteger(12435L),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(new OID("1.2.3.4")),
                   new ASN1Null()),
              X509Certificate.encodeName(new DN("CN=issuer")),
              new ASN1Sequence(
                   new ASN1GeneralizedTime(notBefore),
                   new ASN1GeneralizedTime(notAfter)),
              X509Certificate.encodeName(new DN("CN=ldap.example.com")),
              new ASN1Sequence(
                   new ASN1Sequence(
                        new ASN1ObjectIdentifier(new OID("1.2.3.5")),
                        new ASN1Null()),
                   new ASN1BitString(new boolean[1024]))),
         new ASN1OctetString("not a valid sequence"),
         new ASN1BitString(new boolean[1024]));

    new X509Certificate(valueSequence.encode());
  }



 /**
  * Tests the behavior when trying to decode a certificate with a mismatch in
  * the signature algorithm between the TBSCertificate and Certificate
  * sequences.
  *
  * @throws  Exception  If an unexpected problem occurs.
  */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeSignatureAlgorithmMismatch()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(
              new ASN1Element((byte) 0xA0,
                   new ASN1Integer(2).encode()),
              new ASN1BigInteger(12435L),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(new OID("1.2.3.4")),
                   new ASN1Null()),
              X509Certificate.encodeName(new DN("CN=issuer")),
              new ASN1Sequence(
                   new ASN1GeneralizedTime(notBefore),
                   new ASN1GeneralizedTime(notAfter)),
              X509Certificate.encodeName(new DN("CN=ldap.example.com")),
              new ASN1Sequence(
                   new ASN1Sequence(
                        new ASN1ObjectIdentifier(new OID("1.2.3.5")),
                        new ASN1Null()),
                   new ASN1BitString(new boolean[1024]))),
         new ASN1Sequence(
              new ASN1ObjectIdentifier(new OID("1.2.3.4")),
              new ASN1Null()),
         new ASN1OctetString());

    new X509Certificate(valueSequence.encode());
  }



 /**
  * Tests the behavior when trying to decode a certificate with a malformed
  * signature bit string.
  *
  * @throws  Exception  If an unexpected problem occurs.
  */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedSignatureBitString()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(
              new ASN1Element((byte) 0xA0,
                   new ASN1Integer(2).encode()),
              new ASN1BigInteger(12435L),
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(new OID("1.2.3.4")),
                   new ASN1Null()),
              X509Certificate.encodeName(new DN("CN=issuer")),
              new ASN1Sequence(
                   new ASN1GeneralizedTime(notBefore),
                   new ASN1GeneralizedTime(notAfter)),
              X509Certificate.encodeName(new DN("CN=ldap.example.com")),
              new ASN1Sequence(
                   new ASN1Sequence(
                        new ASN1ObjectIdentifier(new OID("1.2.3.5")),
                        new ASN1Null()),
                   new ASN1BitString(new boolean[1024]))),
         new ASN1Sequence(
              new ASN1ObjectIdentifier(new OID("1.2.3.5")),
              new ASN1Null()),
         new ASN1BitString(new boolean[1024]));

    new X509Certificate(valueSequence.encode());
  }



 /**
  * Tests the behavior when trying to decode a DN that includes a malformed RDN
  * element, as well as an attribute type OID that is not defined in the
  * schema.
  *
  * @throws  Exception  If an unexpected problem occurs.
  */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedName()
         throws Exception
  {
    final ASN1Sequence dnSequence = new ASN1Sequence(
         new ASN1Set(
              new ASN1Sequence(
                   new ASN1ObjectIdentifier(new OID("1.2.3.4.5.6.7.8")),
                   new ASN1UTF8String("value"))),
         new ASN1OctetString("not a valid set"));

    X509Certificate.decodeName(dnSequence);
  }



 /**
  * Tests the behavior when trying to encode a DN that includes an attribute
  * type that is not defined in the schema.
  *
  * @throws  Exception  If an unexpected problem occurs.
  */
  @Test(expectedExceptions = { CertException.class })
  public void testEncodeNameWithUndefinedAttributeType()
         throws Exception
  {
    X509Certificate.encodeName(new DN("undefinedAttributeType=foo"));
  }



  /**
   * Tests the behavior when trying to create the string representation of a
   * certificate with an unknown public key type and a public key whose number
   * of bits is a multiple of eight.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringRepresentationOfCertWithUnknownKeyEvenNumberOfBytes()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    final X509Certificate c = new X509Certificate(X509CertificateVersion.V3,
         BigInteger.valueOf(987654321L), new OID("1.2.3.4"), new ASN1Null(),
         new ASN1BitString(new boolean[256]),
         new DN("CN=Issuer,O=Example Corp,C=US"), notBefore, notAfter,
         new DN("CN=ldap.example.com,O=Example Corp,C=US"),
         new OID("1.2.3.5"), new ASN1Null(),
         new ASN1BitString(new boolean[256]), null, null, null);

    assertNotNull(c.toString());

    assertNotNull(c.toPEM());
    assertFalse(c.toPEM().isEmpty());

    assertNotNull(c.toPEMString());

    assertNotNull(c.getX509CertificateBytes());

    assertNotNull(c.getSHA1Fingerprint());

    assertNotNull(c.getSHA256Fingerprint());
  }



  /**
   * Tests the behavior when trying to create the string representation of a
   * certificate with an elliptic curve key that does not have a named curve OID
   * as the public key algorithm parameters element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringRepresentationOfECCertWithoutNamedCurve()
         throws Exception
  {
    final long notBefore = System.currentTimeMillis();
    final long notAfter = notBefore + (365L * 24L * 60L * 60L * 1000L);

    final EllipticCurvePublicKey publicKey = new EllipticCurvePublicKey(
         BigInteger.valueOf(1234567890L), BigInteger.valueOf(9876543210L));

    final X509Certificate c = new X509Certificate(X509CertificateVersion.V3,
         BigInteger.valueOf(987654321L),
         SignatureAlgorithmIdentifier.SHA_256_WITH_ECDSA.getOID(),
         new ASN1Null(), new ASN1BitString(new boolean[256]),
         new DN("CN=Issuer,O=Example Corp,C=US"), notBefore, notAfter,
         new DN("CN=ldap.example.com,O=Example Corp,C=US"),
         PublicKeyAlgorithmIdentifier.EC.getOID(), new ASN1Null(),
         publicKey.encode(), publicKey, null, null);

    assertNotNull(c.toString());

    assertNotNull(c.toPEM());
    assertFalse(c.toPEM().isEmpty());

    assertNotNull(c.toPEMString());

    assertNotNull(c.getX509CertificateBytes());

    assertNotNull(c.getSHA1Fingerprint());

    assertNotNull(c.getSHA256Fingerprint());
  }



  /**
   * Tests the ability to decode an actual X.509 certificate with an RSA key
   * read from a Java keystore.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeActualRSACertificate()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File keyStoreFile = new File(resourceDir, "cert-test-keystore");

    final KeyStore keyStore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(keyStoreFile))
    {
      keyStore.load(inputStream, "password".toCharArray());
    }

    final Certificate certificate = keyStore.getCertificate("rsa-cert");
    assertNotNull(certificate);

    final X509Certificate x509Certificate =
         new X509Certificate(certificate.getEncoded());

    assertNotNull(x509Certificate.getVersion());
    assertEquals(x509Certificate.getVersion(), X509CertificateVersion.V3);

    assertNotNull(x509Certificate.getSerialNumber());
    assertEquals(x509Certificate.getSerialNumber(),
         BigInteger.valueOf(1238209680L));

    assertNotNull(x509Certificate.getSignatureAlgorithmOID());
    assertEquals(x509Certificate.getSignatureAlgorithmOID(),
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getOID());

    assertNotNull(x509Certificate.getSignatureAlgorithmName());
    assertEquals(x509Certificate.getSignatureAlgorithmName(),
         "SHA-256 with RSA");

    assertNotNull(x509Certificate.getSignatureAlgorithmNameOrOID());
    assertEquals(x509Certificate.getSignatureAlgorithmNameOrOID(),
         "SHA-256 with RSA");

    assertNotNull(x509Certificate.getIssuerDN());
    assertEquals(x509Certificate.getIssuerDN(),
         new DN("CN=ldap.example.com,O=Example Corp,C=US"));

    assertNotNull(x509Certificate.getNotBeforeDate());

    assertNotNull(x509Certificate.getNotAfterDate());

    assertNotNull(x509Certificate.getSubjectDN());
    assertEquals(x509Certificate.getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corp,C=US"));

    assertNotNull(x509Certificate.getPublicKeyAlgorithmOID());
    assertEquals(x509Certificate.getPublicKeyAlgorithmOID(),
         PublicKeyAlgorithmIdentifier.RSA.getOID());

    assertNotNull(x509Certificate.getPublicKeyAlgorithmName());
    assertEquals(x509Certificate.getPublicKeyAlgorithmName(), "RSA");

    assertNotNull(x509Certificate.getPublicKeyAlgorithmNameOrOID());
    assertEquals(x509Certificate.getPublicKeyAlgorithmNameOrOID(), "RSA");

    assertNotNull(x509Certificate.getEncodedPublicKey());

    assertNotNull(x509Certificate.getDecodedPublicKey());
    assertTrue(x509Certificate.getDecodedPublicKey() instanceof RSAPublicKey);

    assertNotNull(x509Certificate.getExtensions());
    assertFalse(x509Certificate.getExtensions().isEmpty());
    assertEquals(x509Certificate.getExtensions().size(), 2);
    assertTrue(x509Certificate.getExtensions().get(0) instanceof
         SubjectAlternativeNameExtension);
    assertTrue(x509Certificate.getExtensions().get(1) instanceof
         SubjectKeyIdentifierExtension);

    final SubjectAlternativeNameExtension subjectAlternativeNameExtension =
         (SubjectAlternativeNameExtension)
         x509Certificate.getExtensions().get(0);
    assertEquals(subjectAlternativeNameExtension.getDNSNames().size(), 4);
    assertTrue(subjectAlternativeNameExtension.getDNSNames().contains("ldap"));
    assertTrue(subjectAlternativeNameExtension.getDNSNames().contains(
         "ds.example.com"));
    assertTrue(subjectAlternativeNameExtension.getDNSNames().contains("ds"));
    assertTrue(subjectAlternativeNameExtension.getDNSNames().contains(
         "localhost"));

    assertEquals(subjectAlternativeNameExtension.getIPAddresses().size(), 3);
    assertTrue(subjectAlternativeNameExtension.getIPAddresses().contains(
         InetAddress.getByName("1.2.3.4")));
    assertTrue(subjectAlternativeNameExtension.getIPAddresses().contains(
         InetAddress.getByName("127.0.0.1")));
    assertTrue(subjectAlternativeNameExtension.getIPAddresses().contains(
         InetAddress.getByName("::1")));

    assertNotNull(x509Certificate.getSignatureValue());

    assertNotNull(x509Certificate.getX509CertificateBytes());

    assertNotNull(x509Certificate.getSHA1Fingerprint());

    assertNotNull(x509Certificate.getSHA256Fingerprint());
  }



  /**
   * Tests the ability to decode an actual X.509 certificate with an elliptic
   * curve key read from a Java keystore.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeActualEllipticCurveCertificate()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File keyStoreFile = new File(resourceDir, "cert-test-keystore");

    final KeyStore keyStore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(keyStoreFile))
    {
      keyStore.load(inputStream, "password".toCharArray());
    }

    final Certificate certificate = keyStore.getCertificate("ec-cert");
    assertNotNull(certificate);

    final X509Certificate x509Certificate =
         new X509Certificate(certificate.getEncoded());

    assertNotNull(x509Certificate.getVersion());
    assertEquals(x509Certificate.getVersion(), X509CertificateVersion.V3);

    assertNotNull(x509Certificate.getSerialNumber());
    assertEquals(x509Certificate.getSerialNumber(),
         BigInteger.valueOf(1920939996L));

    assertNotNull(x509Certificate.getSignatureAlgorithmOID());
    assertEquals(x509Certificate.getSignatureAlgorithmOID(),
         SignatureAlgorithmIdentifier.SHA_256_WITH_ECDSA.getOID());

    assertNotNull(x509Certificate.getSignatureAlgorithmName());
    assertEquals(x509Certificate.getSignatureAlgorithmName(),
         "SHA-256 with ECDSA");

    assertNotNull(x509Certificate.getSignatureAlgorithmNameOrOID());
    assertEquals(x509Certificate.getSignatureAlgorithmNameOrOID(),
         "SHA-256 with ECDSA");

    assertNotNull(x509Certificate.getIssuerDN());
    assertEquals(x509Certificate.getIssuerDN(),
         new DN("CN=ldap.example.com,O=Example Corp,C=US"));

    assertNotNull(x509Certificate.getNotBeforeDate());

    assertNotNull(x509Certificate.getNotAfterDate());

    assertNotNull(x509Certificate.getSubjectDN());
    assertEquals(x509Certificate.getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corp,C=US"));

    assertNotNull(x509Certificate.getPublicKeyAlgorithmOID());
    assertEquals(x509Certificate.getPublicKeyAlgorithmOID(),
         PublicKeyAlgorithmIdentifier.EC.getOID());

    assertNotNull(x509Certificate.getPublicKeyAlgorithmName());
    assertEquals(x509Certificate.getPublicKeyAlgorithmName(), "EC");

    assertNotNull(x509Certificate.getPublicKeyAlgorithmNameOrOID());
    assertEquals(x509Certificate.getPublicKeyAlgorithmNameOrOID(), "EC");

    assertNotNull(x509Certificate.getEncodedPublicKey());

    assertNotNull(x509Certificate.getDecodedPublicKey());
    assertTrue(x509Certificate.getDecodedPublicKey() instanceof
         EllipticCurvePublicKey);

    assertNotNull(x509Certificate.getExtensions());
    assertFalse(x509Certificate.getExtensions().isEmpty());
    assertEquals(x509Certificate.getExtensions().size(), 2);
    assertTrue(x509Certificate.getExtensions().get(0) instanceof
         SubjectAlternativeNameExtension);
    assertTrue(x509Certificate.getExtensions().get(1) instanceof
         SubjectKeyIdentifierExtension);

    final SubjectAlternativeNameExtension subjectAlternativeNameExtension =
         (SubjectAlternativeNameExtension)
         x509Certificate.getExtensions().get(0);
    assertEquals(subjectAlternativeNameExtension.getDNSNames().size(), 4);
    assertTrue(subjectAlternativeNameExtension.getDNSNames().contains("ldap"));
    assertTrue(subjectAlternativeNameExtension.getDNSNames().contains(
         "ds.example.com"));
    assertTrue(subjectAlternativeNameExtension.getDNSNames().contains("ds"));
    assertTrue(subjectAlternativeNameExtension.getDNSNames().contains(
         "localhost"));

    assertEquals(subjectAlternativeNameExtension.getIPAddresses().size(), 3);
    assertTrue(subjectAlternativeNameExtension.getIPAddresses().contains(
         InetAddress.getByName("1.2.3.4")));
    assertTrue(subjectAlternativeNameExtension.getIPAddresses().contains(
         InetAddress.getByName("127.0.0.1")));
    assertTrue(subjectAlternativeNameExtension.getIPAddresses().contains(
         InetAddress.getByName("::1")));

    assertNotNull(x509Certificate.getSignatureValue());

    assertNotNull(x509Certificate.getX509CertificateBytes());

    assertNotNull(x509Certificate.getSHA1Fingerprint());

    assertNotNull(x509Certificate.getSHA256Fingerprint());
  }



  /**
   * Tests the ability to decode all of the certificates contained in the
   * JVM-default trust store.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeAllCertificatesInJVMDefaultTrustStore()
         throws Exception
  {
    final File caCertsFile =
         JVMDefaultTrustManager.getInstance().getCACertsFile();
    assertNotNull(caCertsFile);

    final KeyStore keyStore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(caCertsFile))
    {
      keyStore.load(inputStream, null);
    }

    final Enumeration<String> aliases = keyStore.aliases();
    while (aliases.hasMoreElements())
    {
      final String alias = aliases.nextElement();
      final Certificate cert = keyStore.getCertificate(alias);
      if (cert == null)
      {
        continue;
      }

      new X509Certificate(cert.getEncoded());
    }
  }



  /**
   * Provides test coverage for the {@code encodeValiditySequence} method.
   *
   * @param  notBeforeTime  The generalized time representation of the notBefore
   *                        value to use for testing.
   * @param  notAfterTime   The generalized time representation of the notAfter
   *                        value to use for testing.
   * @param  expectUTC      Indicates whether to expect the time values to be
   *                        encoded as UTC time elements (if {@code true}) or
   *                        generalized time elements (if {@code false}).
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "encodeValiditySequenceTestValues")
  public void testEncodeValiditySequence(final String notBeforeTime,
                                         final String notAfterTime,
                                         final boolean expectUTC)
         throws Exception
  {
    final long notBefore =
         StaticUtils.decodeGeneralizedTime(notBeforeTime).getTime();
    final long notAfter =
         StaticUtils.decodeGeneralizedTime(notAfterTime).getTime();

    final ASN1Sequence validitySequence =
         X509Certificate.encodeValiditySequence(notBefore, notAfter);

    assertTrue(validitySequence.elements().length == 2);
    if (expectUTC)
    {
      assertTrue(validitySequence.elements()[0].getType() ==
           ASN1Constants.UNIVERSAL_UTC_TIME_TYPE);
      assertTrue(validitySequence.elements()[1].getType() ==
           ASN1Constants.UNIVERSAL_UTC_TIME_TYPE);
    }
    else
    {
      assertTrue(validitySequence.elements()[0].getType() ==
           ASN1Constants.UNIVERSAL_GENERALIZED_TIME_TYPE);
      assertTrue(validitySequence.elements()[1].getType() ==
           ASN1Constants.UNIVERSAL_GENERALIZED_TIME_TYPE);
    }
  }



  /**
   * Retrieves a set of values that can be used for testing the
   * {@code encodeValiditySequence} method.
   *
   * @return  A set of values that can be used for testing the
   *         {@code encodeValiditySequence} method.
   */
  @DataProvider(name = "encodeValiditySequenceTestValues")
  public Object[][] getEncodeValiditySequenceTestValues()
  {
    return new Object[][]
    {
      new Object[]
      {
        "19000102123456.789Z",
        "19010102123456.789Z",
        false
      },

      new Object[]
      {
        "19090102123456.789Z",
        "19100102123456.789Z",
        false
      },

      new Object[]
      {
        "19100102123456.789Z",
        "19110102123456.789Z",
        false
      },

      new Object[]
      {
        "19190102123456.789Z",
        "19200102123456.789Z",
        false
      },

      new Object[]
      {
        "19200102123456.789Z",
        "19210102123456.789Z",
        false
      },

      new Object[]
      {
        "19290102123456.789Z",
        "19300102123456.789Z",
        false
      },

      new Object[]
      {
        "19300102123456.789Z",
        "19310102123456.789Z",
        false
      },

      new Object[]
      {
        "19390102123456.789Z",
        "19400102123456.789Z",
        false
      },

      new Object[]
      {
        "19400102123456.789Z",
        "19410102123456.789Z",
        false
      },

      new Object[]
      {
        "19490102123456.789Z",
        "19500102123456.789Z",
        false
      },

      new Object[]
      {
        "19500102123456.789Z",
        "19510102123456.789Z",
        true
      },

      new Object[]
      {
        "19590102123456.789Z",
        "19600102123456.789Z",
        true
      },

      new Object[]
      {
        "19600102123456.789Z",
        "19610102123456.789Z",
        true
      },

      new Object[]
      {
        "19690102123456.789Z",
        "19700102123456.789Z",
        true
      },

      new Object[]
      {
        "19700102123456.789Z",
        "19710102123456.789Z",
        true
      },

      new Object[]
      {
        "19790102123456.789Z",
        "19800102123456.789Z",
        true
      },

      new Object[]
      {
        "19800102123456.789Z",
        "19810102123456.789Z",
        true
      },

      new Object[]
      {
        "19890102123456.789Z",
        "19900102123456.789Z",
        true
      },

      new Object[]
      {
        "19900102123456.789Z",
        "19910102123456.789Z",
        true
      },

      new Object[]
      {
        "19990102123456.789Z",
        "20000102123456.789Z",
        true
      },

      new Object[]
      {
        "20000102123456.789Z",
        "20010102123456.789Z",
        true
      },

      new Object[]
      {
        "20090102123456.789Z",
        "20100102123456.789Z",
        true
      },

      new Object[]
      {
        "20100102123456.789Z",
        "20110102123456.789Z",
        true
      },

      new Object[]
      {
        "20190102123456.789Z",
        "20200102123456.789Z",
        true
      },

      new Object[]
      {
        "20200102123456.789Z",
        "20210102123456.789Z",
        true
      },

      new Object[]
      {
        "20290102123456.789Z",
        "20300102123456.789Z",
        true
      },

      new Object[]
      {
        "20300102123456.789Z",
        "20310102123456.789Z",
        true
      },

      new Object[]
      {
        "20390102123456.789Z",
        "20400102123456.789Z",
        true
      },

      new Object[]
      {
        "20400102123456.789Z",
        "20410102123456.789Z",
        true
      },

      new Object[]
      {
        "20490102123456.789Z",
        "20500102123456.789Z",
        false
      },

      new Object[]
      {
        "20500102123456.789Z",
        "20510102123456.789Z",
        false
      },

      new Object[]
      {
        "20590102123456.789Z",
        "20600102123456.789Z",
        false
      },

      new Object[]
      {
        "20600102123456.789Z",
        "20610102123456.789Z",
        false
      },

      new Object[]
      {
        "20690102123456.789Z",
        "20700102123456.789Z",
        false
      },

      new Object[]
      {
        "20700102123456.789Z",
        "20710102123456.789Z",
        false
      },

      new Object[]
      {
        "20790102123456.789Z",
        "20800102123456.789Z",
        false
      },

      new Object[]
      {
        "20800102123456.789Z",
        "20810102123456.789Z",
        false
      },

      new Object[]
      {
        "20890102123456.789Z",
        "20900102123456.789Z",
        false
      },

      new Object[]
      {
        "20900102123456.789Z",
        "20910102123456.789Z",
        false
      },

      new Object[]
      {
        "20990102123456.789Z",
        "21000102123456.789Z",
        false
      },
    };
  }



  /**
   * Tests the {@code isSelfSigned} method for a certificate that has both
   * subject key identifier and authority key identifier extensions with the
   * same value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIsSelfSignedWithSameAuthorityAndSubjectKeyIdentifiers()
         throws Exception
  {
    final X509Certificate c = new X509Certificate(X509CertificateVersion.V3,
         BigInteger.valueOf(12345L),
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getOID(),
         new ASN1Null(),
         new ASN1BitString(true, false, true, false, true),
         new DN("CN=Test,O=Example Corporation,C=US"),
         System.currentTimeMillis(),
         System.currentTimeMillis() + (365L * 86_400_000L),
         new DN("CN=Test,O=Example Corporation,C=US"),
         PublicKeyAlgorithmIdentifier.RSA.getOID(),
         new ASN1Null(),
         new ASN1BitString(false, true, false, true, false),
         null, null, null,
         new SubjectKeyIdentifierExtension(false,
              new ASN1OctetString("keyIdentifier")),
         new AuthorityKeyIdentifierExtension(false,
              new ASN1OctetString("keyIdentifier"), null, null));

    assertTrue(c.isSelfSigned());
  }



  /**
   * Tests the {@code isSelfSigned} method for a certificate that has both
   * subject key identifier and authority key identifier extensions with
   * different values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIsSelfSignedWithDifferentAuthorityAndSubjectKeyIdentifiers()
         throws Exception
  {
    final X509Certificate c = new X509Certificate(X509CertificateVersion.V3,
         BigInteger.valueOf(12345L),
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getOID(),
         new ASN1Null(),
         new ASN1BitString(true, false, true, false, true),
         new DN("CN=Test,O=Example Corporation,C=US"),
         System.currentTimeMillis(),
         System.currentTimeMillis() + (365L * 86_400_000L),
         new DN("CN=Test,O=Example Corporation,C=US"),
         PublicKeyAlgorithmIdentifier.RSA.getOID(),
         new ASN1Null(),
         new ASN1BitString(false, true, false, true, false),
         null, null, null,
         new SubjectKeyIdentifierExtension(false,
              new ASN1OctetString("keyIdentifier")),
         new AuthorityKeyIdentifierExtension(false,
              new ASN1OctetString("differentKeyIdentifier"), null, null));

    assertFalse(c.isSelfSigned());
  }



  /**
   * Tests the {@code isSelfSigned} method for a certificate that doesn't have
   * an authority key identifier and for which the subject DN matches the
   * issuer DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIsSelfSignedWithoutAuthorityKeyIdentifierSameDN()
         throws Exception
  {
    final X509Certificate c = new X509Certificate(X509CertificateVersion.V3,
         BigInteger.valueOf(12345L),
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getOID(),
         new ASN1Null(),
         new ASN1BitString(true, false, true, false, true),
         new DN("CN=Test,O=Example Corporation,C=US"),
         System.currentTimeMillis(),
         System.currentTimeMillis() + (365L * 86_400_000L),
         new DN("CN=Test,O=Example Corporation,C=US"),
         PublicKeyAlgorithmIdentifier.RSA.getOID(),
         new ASN1Null(),
         new ASN1BitString(false, true, false, true, false),
         null, null, null,
         new SubjectKeyIdentifierExtension(false,
              new ASN1OctetString("keyIdentifier")));

    assertTrue(c.isSelfSigned());
  }



  /**
   * Tests the {@code isSelfSigned} method for a certificate that doesn't have
   * an authority key identifier and for which the subject DN does not match the
   * issuer DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIsSelfSignedWithoutAuthorityKeyIdentifierDifferentDNs()
         throws Exception
  {
    final X509Certificate c = new X509Certificate(X509CertificateVersion.V3,
         BigInteger.valueOf(12345L),
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getOID(),
         new ASN1Null(),
         new ASN1BitString(true, false, true, false, true),
         new DN("CN=Test,O=Example Corporation,C=US"),
         System.currentTimeMillis(),
         System.currentTimeMillis() + (365L * 86_400_000L),
         new DN("CN=Different Test,O=Example Corporation,C=US"),
         PublicKeyAlgorithmIdentifier.RSA.getOID(),
         new ASN1Null(),
         new ASN1BitString(false, true, false, true, false),
         null, null, null,
         new SubjectKeyIdentifierExtension(false,
              new ASN1OctetString("keyIdentifier")));

    assertFalse(c.isSelfSigned());
  }



  /**
   * Tests the {@code isIssuerFor} methods for a case in which the relationship
   * can be established by key identifiers.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIsIssuerForVerifiedUsingKeyIDs()
         throws Exception
  {
    final X509Certificate serverCert = new X509Certificate(
         X509CertificateVersion.V3,
         BigInteger.valueOf(12345L),
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getOID(),
         new ASN1Null(),
         new ASN1BitString(true, false, true, false, true),
         new DN("CN=Example Issuer,O=Example Corporation,C=US"),
         System.currentTimeMillis(),
         System.currentTimeMillis() + (365L * 86_400_000L),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
         PublicKeyAlgorithmIdentifier.RSA.getOID(),
         new ASN1Null(),
         new ASN1BitString(false, true, false, true, false),
         null, null, null,
         new SubjectKeyIdentifierExtension(false,
              new ASN1OctetString("serverCertKeyIdentifier")),
         new AuthorityKeyIdentifierExtension(false,
              new ASN1OctetString("issuerCertKeyIdentifier"), null, null));

    final X509Certificate issuerCert = new X509Certificate(
         X509CertificateVersion.V3,
         BigInteger.valueOf(12345L),
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getOID(),
         new ASN1Null(),
         new ASN1BitString(true, false, true, false, true),
         new DN("CN=Example Issuer,O=Example Corporation,C=US"),
         System.currentTimeMillis(),
         System.currentTimeMillis() + (365L * 86_400_000L),
         new DN("CN=Example Issuer,O=Example Corporation,C=US"),
         PublicKeyAlgorithmIdentifier.RSA.getOID(),
         new ASN1Null(),
         new ASN1BitString(false, true, false, true, false),
         null, null, null,
         new SubjectAlternativeNameExtension(false,
              new GeneralNamesBuilder().addRFC822Name(
                   "ca@example.com").build()),
         new SubjectKeyIdentifierExtension(false,
              new ASN1OctetString("issuerCertKeyIdentifier")),
         new AuthorityKeyIdentifierExtension(false,
              new ASN1OctetString("issuerCertKeyIdentifier"), null, null));

    assertTrue(issuerCert.isIssuerFor(serverCert));
    assertTrue(issuerCert.isIssuerFor(serverCert, new StringBuilder()));

    assertFalse(serverCert.isIssuerFor(serverCert));
    assertFalse(serverCert.isIssuerFor(serverCert, new StringBuilder()));
  }



  /**
   * Tests the {@code isIssuerFor} methods for a case in which the relationship
   * can be disproved by key identifiers.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIsIssuerForDisprovedByUsingKeyIDs()
         throws Exception
  {
    final X509Certificate serverCert = new X509Certificate(
         X509CertificateVersion.V3,
         BigInteger.valueOf(12345L),
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getOID(),
         new ASN1Null(),
         new ASN1BitString(true, false, true, false, true),
         new DN("CN=Example Issuer,O=Example Corporation,C=US"),
         System.currentTimeMillis(),
         System.currentTimeMillis() + (365L * 86_400_000L),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
         PublicKeyAlgorithmIdentifier.RSA.getOID(),
         new ASN1Null(),
         new ASN1BitString(false, true, false, true, false),
         null, null, null,
         new SubjectKeyIdentifierExtension(false,
              new ASN1OctetString("serverCertKeyIdentifier")),
         new AuthorityKeyIdentifierExtension(false,
              new ASN1OctetString("issuerCertKeyIdentifier"), null, null));

    final X509Certificate issuerCert = new X509Certificate(
         X509CertificateVersion.V3,
         BigInteger.valueOf(12345L),
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getOID(),
         new ASN1Null(),
         new ASN1BitString(true, false, true, false, true),
         new DN("CN=Example Issuer,O=Example Corporation,C=US"),
         System.currentTimeMillis(),
         System.currentTimeMillis() + (365L * 86_400_000L),
         new DN("CN=Example Issuer,O=Example Corporation,C=US"),
         PublicKeyAlgorithmIdentifier.RSA.getOID(),
         new ASN1Null(),
         new ASN1BitString(false, true, false, true, false),
         null, null, null,
         new SubjectKeyIdentifierExtension(false,
              new ASN1OctetString("differentIssuerCertKeyIdentifier")),
         new AuthorityKeyIdentifierExtension(false,
              new ASN1OctetString("differentIssuerCertKeyIdentifier"), null,
              null));

    assertFalse(issuerCert.isIssuerFor(serverCert));
    assertFalse(issuerCert.isIssuerFor(serverCert, new StringBuilder()));

    assertFalse(serverCert.isIssuerFor(serverCert));
    assertFalse(serverCert.isIssuerFor(serverCert, new StringBuilder()));
  }



  /**
   * Tests the behavior when trying to create a valid self-signed RSA
   * certificate.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateSelfSignedRSACertificateValid()
         throws Exception
  {
    final ObjectPair<X509Certificate,KeyPair> p =
         X509Certificate.generateSelfSignedCertificate(
              SignatureAlgorithmIdentifier.SHA_256_WITH_RSA,
              PublicKeyAlgorithmIdentifier.RSA, 2048,
              new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
              System.currentTimeMillis(),
              System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365L),
              new SubjectAlternativeNameExtension(false,
                   new GeneralNamesBuilder().addDNSName(
                        "ldap.example.com").build()));

    assertNotNull(p);

    final X509Certificate c = p.getFirst();
    assertNotNull(c);

    c.verifySignature(null);

    final KeyPair kp = p.getSecond();
    assertNotNull(kp);
  }



  /**
   * Tests the behavior when trying to create a self-signed RSA certificate with
   * an invalid key size.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testGenerateSelfSignedRSACertificateInvalidKeySize()
         throws Exception
  {
    X509Certificate.generateSelfSignedCertificate(
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA,
         PublicKeyAlgorithmIdentifier.RSA, 1,
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
         System.currentTimeMillis(),
         System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365L),
         new SubjectAlternativeNameExtension(false,
              new GeneralNamesBuilder().addDNSName(
                   "ldap.example.com").build()));
  }



  /**
   * Tests the behavior when trying to create a valid self-signed elliptic curve
   * certificate.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateSelfSignedECCertificateValid()
         throws Exception
  {
    final ObjectPair<X509Certificate,KeyPair> p =
         X509Certificate.generateSelfSignedCertificate(
              SignatureAlgorithmIdentifier.SHA_256_WITH_ECDSA,
              PublicKeyAlgorithmIdentifier.EC, 256,
              new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
              System.currentTimeMillis(),
              System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365L),
              new SubjectAlternativeNameExtension(false,
                   new GeneralNamesBuilder().addDNSName(
                        "ldap.example.com").build()));

    assertNotNull(p);

    final X509Certificate c = p.getFirst();
    assertNotNull(c);

    c.verifySignature(null);

    final KeyPair kp = p.getSecond();
    assertNotNull(kp);
  }



  /**
   * Tests the behavior when trying to create a self-signed elliptic curve
   * certificate with an invalid key size.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testGenerateSelfSignedECCertificateInvalidKeySize()
         throws Exception
  {
    X509Certificate.generateSelfSignedCertificate(
         SignatureAlgorithmIdentifier.SHA_256_WITH_ECDSA,
         PublicKeyAlgorithmIdentifier.EC, -1234,
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
         System.currentTimeMillis(),
         System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365L),
         new SubjectAlternativeNameExtension(false,
              new GeneralNamesBuilder().addDNSName(
                   "ldap.example.com").build()));
  }



  /**
   * Tests the behavior of the {@code verifySignature} method with a self-signed
   * certificate when that certificate is provided as the issuer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testVerifySignatureSelfSignedNonNullIssuer()
         throws Exception
  {
    final ObjectPair<X509Certificate,KeyPair> p =
         X509Certificate.generateSelfSignedCertificate(
              SignatureAlgorithmIdentifier.SHA_256_WITH_RSA,
              PublicKeyAlgorithmIdentifier.RSA, 2048,
              new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
              System.currentTimeMillis(),
              System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365L),
              new SubjectAlternativeNameExtension(false,
                   new GeneralNamesBuilder().addDNSName(
                        "ldap.example.com").build()));

    final X509Certificate c = p.getFirst();
    c.verifySignature(c);
  }



  /**
   * Tests the behavior of the {@code verifySignature} method with a
   * {@code null} issuer for a non-self-signed certificate.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testVerifySignatureInvalidNullIssuer()
         throws Exception
  {
    final X509Certificate cert = new X509Certificate(
         X509CertificateVersion.V3, BigInteger.valueOf(12345L),
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getOID(), null,
         new ASN1BitString(true, false, true, false, true),
         new DN("CN=Example Issuer,O=Example Corporation,C=US"),
         System.currentTimeMillis(),
         System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365L),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
         PublicKeyAlgorithmIdentifier.RSA.getOID(), null,
         new ASN1BitString(false, true, false, true, false), null, null, null);
    cert.verifySignature(null);
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
    final X509Certificate cert = new X509Certificate(
         X509CertificateVersion.V3, BigInteger.valueOf(12345L),
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getOID(), null,
         new ASN1BitString(true, false, true, false, true),
         new DN("CN=Example Issuer,O=Example Corporation,C=US"),
         System.currentTimeMillis(),
         System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365L),
         new DN("CN=Example Issuer,O=Example Corporation,C=US"),
         PublicKeyAlgorithmIdentifier.RSA.getOID(), null,
         new ASN1BitString(false, true, false, true, false), null, null, null);
    cert.verifySignature(null);
  }



  /**
   * Tests the behavior of the {@code verifySignature} method with a signature
   * algorithm OID that isn't a valid OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testVerifySignatureInvalidSignatureAlgorithm()
         throws Exception
  {
    final ObjectPair<X509Certificate,KeyPair> p =
         X509Certificate.generateSelfSignedCertificate(
              SignatureAlgorithmIdentifier.SHA_256_WITH_RSA,
              PublicKeyAlgorithmIdentifier.RSA, 2048,
              new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
              System.currentTimeMillis(),
              System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365L),
              new SubjectAlternativeNameExtension(false,
                   new GeneralNamesBuilder().addDNSName(
                        "ldap.example.com").build()));
    final X509Certificate c = p.getFirst();
    final X509CertificateExtension[] extensions =
         new X509CertificateExtension[c.getExtensions().size()];
    c.getExtensions().toArray(extensions);

    final X509Certificate cert = new X509Certificate(c.getVersion(),
         c.getSerialNumber(), new OID("1234.5678"),
         c.getSignatureAlgorithmParameters(),
         new ASN1BitString(true, false, true, false, true),
         c.getIssuerDN(), c.getNotBeforeTime(), c.getNotAfterTime(),
         c.getSubjectDN(), c.getPublicKeyAlgorithmOID(), null,
         c.getEncodedPublicKey(), c.getDecodedPublicKey(),
         c.getIssuerUniqueID(), c.getSubjectUniqueID(), extensions);
    cert.verifySignature(null);
  }



  /**
   * Tests the behavior of the {@code verifySignature} method with an
   * unrecognized signature algorithm.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testVerifySignatureUnrecognizedSignatureAlgorithm()
         throws Exception
  {
    final ObjectPair<X509Certificate,KeyPair> p =
         X509Certificate.generateSelfSignedCertificate(
              SignatureAlgorithmIdentifier.SHA_256_WITH_RSA,
              PublicKeyAlgorithmIdentifier.RSA, 2048,
              new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
              System.currentTimeMillis(),
              System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365L),
              new SubjectAlternativeNameExtension(false,
                   new GeneralNamesBuilder().addDNSName(
                        "ldap.example.com").build()));
    final X509Certificate c = p.getFirst();
    final X509CertificateExtension[] extensions =
         new X509CertificateExtension[c.getExtensions().size()];
    c.getExtensions().toArray(extensions);

    final X509Certificate cert = new X509Certificate(c.getVersion(),
         c.getSerialNumber(), new OID("1.2.3.4.5.6.7.8"),
         c.getSignatureAlgorithmParameters(),
         new ASN1BitString(true, false, true, false, true),
         c.getIssuerDN(), c.getNotBeforeTime(), c.getNotAfterTime(),
         c.getSubjectDN(), c.getPublicKeyAlgorithmOID(), null,
         c.getEncodedPublicKey(), c.getDecodedPublicKey(),
         c.getIssuerUniqueID(), c.getSubjectUniqueID(), extensions);
    cert.verifySignature(null);
  }



  /**
   * Tests the behavior of the {@code verifySignature} method with a malformed
   * signature.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testVerifySignatureMalformedSignature()
         throws Exception
  {
    final ObjectPair<X509Certificate,KeyPair> p =
         X509Certificate.generateSelfSignedCertificate(
              SignatureAlgorithmIdentifier.SHA_256_WITH_RSA,
              PublicKeyAlgorithmIdentifier.RSA, 2048,
              new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
              System.currentTimeMillis(),
              System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365L),
              new SubjectAlternativeNameExtension(false,
                   new GeneralNamesBuilder().addDNSName(
                        "ldap.example.com").build()));
    final X509Certificate c = p.getFirst();
    final X509CertificateExtension[] extensions =
         new X509CertificateExtension[c.getExtensions().size()];
    c.getExtensions().toArray(extensions);

    final X509Certificate cert = new X509Certificate(c.getVersion(),
         c.getSerialNumber(), c.getSignatureAlgorithmOID(),
         c.getSignatureAlgorithmParameters(),
         new ASN1BitString(true, false, true, false, true),
         c.getIssuerDN(), c.getNotBeforeTime(), c.getNotAfterTime(),
         c.getSubjectDN(), c.getPublicKeyAlgorithmOID(), null,
         c.getEncodedPublicKey(), c.getDecodedPublicKey(),
         c.getIssuerUniqueID(), c.getSubjectUniqueID(), extensions);
    cert.verifySignature(null);
  }



  /**
   * Tests the behavior of the {@code verifySignature} method with an
   * invalid signature.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testVerifySignatureInvalidSignature()
         throws Exception
  {
    final ObjectPair<X509Certificate,KeyPair> p =
         X509Certificate.generateSelfSignedCertificate(
              SignatureAlgorithmIdentifier.SHA_256_WITH_RSA,
              PublicKeyAlgorithmIdentifier.RSA, 2048,
              new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
              System.currentTimeMillis(),
              System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365L),
              new SubjectAlternativeNameExtension(false,
                   new GeneralNamesBuilder().addDNSName(
                        "ldap.example.com").build()));
    final X509Certificate c = p.getFirst();
    final X509CertificateExtension[] extensions =
         new X509CertificateExtension[c.getExtensions().size()];
    c.getExtensions().toArray(extensions);

    final X509Certificate cert = new X509Certificate(c.getVersion(),
         c.getSerialNumber(), c.getSignatureAlgorithmOID(),
         c.getSignatureAlgorithmParameters(),
         new ASN1BitString(ASN1BitString.getBitsForBytes(new byte[256])),
         c.getIssuerDN(), c.getNotBeforeTime(), c.getNotAfterTime(),
         c.getSubjectDN(), c.getPublicKeyAlgorithmOID(), null,
         c.getEncodedPublicKey(), c.getDecodedPublicKey(),
         c.getIssuerUniqueID(), c.getSubjectUniqueID(), extensions);
    cert.verifySignature(null);
  }



  /**
   * Provides test coverage for the {@code isWithinValidityWindow} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIsWithinValidityWindow()
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

    final X509Certificate c = new X509Certificate(X509CertificateVersion.V1,
         BigInteger.valueOf(123456789L),
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getOID(), null,
         new ASN1BitString(new boolean[1024]),
         new DN("CN=Issuer,O=Example Corp,C=US"), notBefore, notAfter,
         new DN("CN=ldap.example.com,O=Example Corp,C=US"),
         PublicKeyAlgorithmIdentifier.RSA.getOID(), null,
         publicKey.encode(), publicKey, null, null);

    // NOTE:  For some moronic reasons, certificates tend to use UTCTime instead
    // of generalized time when encoding notBefore and notAfter values, despite
    // the spec allowing either one, and despite UTCTime only supporting a
    // two-digit year and no sub-second component.  So we can't check for
    // exact equivalence  of the notBefore and notAfter values.  Instead, we'll
    // test with values at least 2000 milliseconds away from those values.  And
    // just call the version that doesn't take any arguments to get coverage.
    c.isWithinValidityWindow();

    assertTrue(c.isWithinValidityWindow(c.getNotBeforeDate()));
    assertTrue(c.isWithinValidityWindow(c.getNotBeforeTime()));

    assertFalse(c.isWithinValidityWindow(c.getNotBeforeTime() - 2000L));

    assertTrue(c.isWithinValidityWindow(c.getNotBeforeTime() + 2000L));

    assertTrue(c.isWithinValidityWindow(c.getNotAfterDate()));
    assertTrue(c.isWithinValidityWindow(c.getNotAfterTime()));

    assertTrue(c.isWithinValidityWindow(c.getNotAfterTime() - 2000L));

    assertFalse(c.isWithinValidityWindow(c.getNotAfterTime() + 2000L));
  }



  /**
   * Tests to verify that all of the certificates in the JVM-default trust store
   * can be decoded without error.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodingAllJVMDefaultCertificates()
       throws Exception
  {
    final KeyStore keyStore = CryptoHelper.getKeyStore("JKS");

    final File caCertsFile =
         JVMDefaultTrustManager.getInstance().getCACertsFile();
    try (FileInputStream inputStream = new FileInputStream(caCertsFile))
    {
      keyStore.load(inputStream, null);
    }


    final boolean enabledBeforeStarting = Debug.debugEnabled();
    final Set<DebugType> debugTypesBeforeStarting = Debug.getDebugTypes();
    final Logger logger = Debug.getLogger();
    final Level levelBeforeStarting = logger.getLevel();
    final boolean useParentHandlersBeforeStarting =
         logger.getUseParentHandlers();
    final TestLogHandler testLogHandler = new TestLogHandler();

    try
    {
      Debug.setEnabled(true, EnumSet.allOf(DebugType.class));
      logger.setUseParentHandlers(false);

      testLogHandler.setFilter(null);
      testLogHandler.setLevel(Level.ALL);
      logger.addHandler(testLogHandler);


      final Enumeration<String> aliasEnumeration = keyStore.aliases();
      while (aliasEnumeration.hasMoreElements())
      {
        final String alias = aliasEnumeration.nextElement();
        final KeyStore.Entry entry = keyStore.getEntry(alias, null);
        if (entry instanceof KeyStore.TrustedCertificateEntry)
        {
          final KeyStore.TrustedCertificateEntry tce =
               (KeyStore.TrustedCertificateEntry) entry;
          new X509Certificate(tce.getTrustedCertificate().getEncoded());
        }
        else if (entry instanceof KeyStore.PrivateKeyEntry)
        {
          final KeyStore.PrivateKeyEntry pke =
               (KeyStore.PrivateKeyEntry) entry;
          for (final Certificate c : pke.getCertificateChain())
          {
            new X509Certificate(c.getEncoded());
          }
        }
      }
    }
    finally
    {
      logger.removeHandler(testLogHandler);
      Debug.setEnabled(enabledBeforeStarting, debugTypesBeforeStarting);
      logger.setLevel(levelBeforeStarting);
      logger.setUseParentHandlers(useParentHandlersBeforeStarting);
    }

    assertEquals(testLogHandler.getMessageCount(), 0,
         testLogHandler.getMessagesString());
  }
}
