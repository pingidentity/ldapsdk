/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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
package com.unboundid.util.ssl;



import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.SSLSession;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ssl.cert.ManageCertificates;



/**
 * This class provides a set of test cases for the HostNameSSLSocketVerifier
 * class.
 */
public final class HostNameSSLSocketVerifierTestCase
       extends LDAPSDKTestCase
{
  /**
   * The alias for certificates used for testing.
   */
  private static final String ALIAS = "server-cert";



  /**
   * The PIN used to protect the key stores and private keys used for testing.
   */
  private static final String PIN_STRING = "password";



  /**
   * The characters that make up the PIN used to protect the key stores and
   * private keys used for testing.
   */
  private static final char[] PIN_CHARS = PIN_STRING.toCharArray();



  /**
   * Tests the behavior for a certificate that does not have either a
   * subject alternative name extension or a CN attribute in the subject DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCertificateWithoutCNOrSubjectAltName()
         throws Exception
  {
    final File keyStore = generateCertificate("O=Example Corp,C=US");
    final X509Certificate certificate = getCertificate(keyStore);

    final StringBuilder buffer = new StringBuilder();
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname("ds.example.com",
              certificate, true, false, buffer),
         buffer.toString());
  }



  /**
   * Tests the behavior for a certificate that does not have a subject
   * alternative name extension but has CN in the subject DN that is a hostname
   * without a wildcard.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCertificateWithNonWildcardCNWithoutSubjectAltName()
         throws Exception
  {
    final File keyStore = generateCertificate(
         "CN=ds.example.com,O=Example Corp,C=US");
    final X509Certificate certificate = getCertificate(keyStore);

    // Match exactly.
    final StringBuilder buffer = new StringBuilder();
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds.example.com", certificate, true, false, buffer),
         buffer.toString());

    // Match ignoring case.
    buffer.setLength(0);
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "DS.EXAMPLE.COM", certificate, true, false, buffer),
         buffer.toString());

    // Don't match when omitting the domain.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds", certificate, true, false, buffer),
         buffer.toString());

    // Don't match with a different domain.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds.example.org", certificate, true, false, buffer),
         buffer.toString());

    // Don't match with a different leftmost component.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ldap.example.com", certificate, true, false, buffer),
         buffer.toString());

    // Don't match with more added on to the leftmost component.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds1.example.com", certificate, true, false, buffer),
         buffer.toString());

    // Don't match with an empty leftmost component.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              ".example.com", certificate, true, false, buffer),
         buffer.toString());

    // Don't match with a wildcard as the only thing in the leftmost component.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "*.example.com", certificate, true, false, buffer),
         buffer.toString());

    // Don't match with additional text and a wildcard in the leftmost
    // component.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds*.example.com", certificate, true, false, buffer),
         buffer.toString());
  }



  /**
   * Tests the behavior for a certificate that does not have a subject
   * alternative name extension but has CN in the subject DN that is a hostname
   * in which the leftmost component is comprised entirely of a wildcard.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCertificateWithWildcardOnlyCNWithoutSubjectAltName()
         throws Exception
  {
    final File keyStore = generateCertificate(
         "CN=*.example.com,O=Example Corp,C=US");
    final X509Certificate certificate = getCertificate(keyStore);

    // Match one value with the right domain.
    final StringBuilder buffer = new StringBuilder();
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds.example.com", certificate, true, false, buffer),
         buffer.toString());

    // Match the same value but ignoring differences in case.
    buffer.setLength(0);
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "DS.EXAMPLE.COM", certificate, true, false, buffer),
         buffer.toString());

    // Match a different value with the right domain.
    buffer.setLength(0);
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ldap.example.com", certificate, true, false, buffer),
         buffer.toString());

    // Don't match when a subdomain is added.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds.subdomain.example.com", certificate, true, false, buffer),
         buffer.toString());

    // Don't match when wildcard matching is disabled.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds.example.com", certificate, false, false, buffer),
         buffer.toString());

    // Don't match with a different domain.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds.example.org", certificate, true, false, buffer),
         buffer.toString());

    // Don't match when the wildcard isn't in the leftmost component.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds.*.com", certificate, true, false, buffer),
         buffer.toString());

    // Don't match when there's no domain.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds", certificate, true, false, buffer),
         buffer.toString());
  }



  /**
   * Tests the behavior for a certificate that does not have a subject
   * alternative name extension but has CN in the subject DN that is a hostname
   * in which the leftmost component has a wildcard that follows non-wildcard
   * text.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCertificateWithWildcardSubFinalCNWithoutSubjectAltName()
         throws Exception
  {
    final File keyStore = generateCertificate(
         "CN=ds*.example.com,O=Example Corp,C=US");
    final X509Certificate certificate = getCertificate(keyStore);

    // Match when the prefix matches and there is something to follow.
    final StringBuilder buffer = new StringBuilder();
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds1.example.com", certificate, true, false, buffer),
         buffer.toString());

    // Match when the prefix matches and there is something else to follow.
    buffer.setLength(0);
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds2345.example.com", certificate, true, false, buffer),
         buffer.toString());

    // Match when the prefix matches and there is nothing else to follow.
    buffer.setLength(0);
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds.example.com", certificate, true, false, buffer),
         buffer.toString());

    // Match when ignoring differences in capitalization.
    buffer.setLength(0);
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "DS1.EXAMPLE.COM", certificate, true, false, buffer),
         buffer.toString());

    // Don't match when the prefix is different.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ldap.example.com", certificate, true, false, buffer),
         buffer.toString());

    // Don't match when the prefix is different even when it would match if we
    // chopped off part of that prefix.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ads1.example.com", certificate, true, false, buffer),
         buffer.toString());

    // Don't match when there's a subdomain.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds1.subdomain.example.com", certificate, true, false, buffer),
         buffer.toString());

    // Don't match when wildcard matching is disabled.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds1.example.com", certificate, false, false, buffer),
         buffer.toString());

    // Don't match when there's no domain.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds1", certificate, true, false, buffer),
         buffer.toString());
  }



  /**
   * Tests the behavior for a certificate that does not have a subject
   * alternative name extension but has wildcard CN that is not in the leftmost
   * component.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCertificateWithNonLeftmostWildcardCNWithoutSubjectAltName()
         throws Exception
  {
    final File keyStore = generateCertificate(
         "CN=ds.*.example.com,O=Example Corp,C=US");
    final X509Certificate certificate = getCertificate(keyStore);

    // Don't match when there's no subdomain.
    final StringBuilder buffer = new StringBuilder();
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds.example.com", certificate, true, false, buffer),
         buffer.toString());

    // Don't match when there is a subdomain.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds.east.example.com", certificate, true, false, buffer),
         buffer.toString());

    // Don't even match when the provided hostname matches exactly.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds.*.example.com", certificate, true, false, buffer),
         buffer.toString());
  }



  /**
   * Tests the behavior for a certificate that does not have a subject
   * alternative name extension but has wildcard CN in conjunction with a
   * parenthesis (which is not allowed in certificate hostnames and will also
   * prevent the verifier from creating a valid substring filter).
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCertificateWithMalformedWildcardCNWithoutSubjectAltName()
         throws Exception
  {
    final File keyStore = generateCertificate(
         "CN=ds)*.example.com,O=Example Corp,C=US");
    final X509Certificate certificate = getCertificate(keyStore);

    // Don't match because it's invalid.  That's true of all of these.
    final StringBuilder buffer = new StringBuilder();
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds)1.example.com", certificate, true, false, buffer),
         buffer.toString());

    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds).example.com", certificate, true, false, buffer),
         buffer.toString());

    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds.example.com", certificate, true, false, buffer),
         buffer.toString());

    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds1.example.com", certificate, true, false, buffer),
         buffer.toString());
  }



  /**
   * Tests the behavior for a certificate that does not have a subject
   * alternative name extension but has CN in the subject DN that is an IPv4
   * address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCertificateWithIPv4AddressCNWithoutSubjectAltName()
         throws Exception
  {
    final File keyStore = generateCertificate(
         "CN=1.2.3.4,O=Example Corp,C=US");
    final X509Certificate certificate = getCertificate(keyStore);

    // Match when we provide the same IP address.
    final StringBuilder buffer = new StringBuilder();
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "1.2.3.4", certificate, true, false, buffer),
         buffer.toString());

    // Don't match when we provide a different IP address.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "1.2.3.5", certificate, true, false, buffer),
         buffer.toString());

    // Match when we use a loopback IP address.
    buffer.setLength(0);
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "127.0.0.1", certificate, true, false, buffer),
         buffer.toString());

    // Don't match when we provide something that's not an IP address.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds.example.com", certificate, true, false, buffer),
         buffer.toString());
  }



  /**
   * Tests the behavior for a certificate that does not have a subject
   * alternative name extension but has CN in the subject DN that is an IPv6
   * address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCertificateWithIPv6AddressCNWithoutSubjectAltName()
         throws Exception
  {
    final File keyStore = generateCertificate(
         "CN=0:0:0:0:0:0:0:1,O=Example Corp,C=US");
    final X509Certificate certificate = getCertificate(keyStore);

    // Match when we provide the same IP address.
    final StringBuilder buffer = new StringBuilder();
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "0:0:0:0:0:0:0:1", certificate, true, false, buffer),
         buffer.toString());

    // Match when we provide the same IP address written with a different
    // notation.
    buffer.setLength(0);
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "::1", certificate, true, false, buffer),
         buffer.toString());

    // Don't match with a different IP address.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "::2", certificate, true, false, buffer),
         buffer.toString());

    // Don't match when we provide something that's not an IP address.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds.example.com", certificate, true, false, buffer),
         buffer.toString());
  }



  /**
   * Tests the behavior for a certificate that has a subject alternative
   * name extension with lots of components that can be used for testing a
   * variety of things.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCertificateWithSubjectAltName()
         throws Exception
  {
    final File keyStore = generateCertificate(
         "CN=ds.domain6.com,O=Example Corp,C=US",
         "--subject-alternative-name-dns", "ds.example.com",
         "--subject-alternative-name-dns", "*.domain1.com",
         "--subject-alternative-name-dns", "ds*.domain2.com",
         "--subject-alternative-name-ip-address", "1.2.3.4",
         "--subject-alternative-name-ip-address", "::1",
         "--subject-alternative-name-uri", "ldaps://ds.domain3.com:636/",
         "--subject-alternative-name-uri", "ldaps://*.domain4.com:636/",
         "--subject-alternative-name-uri", "ldaps://ds*.domain5.com:636/",
         "--subject-alternative-name-uri", "ldaps://1.2.3.5:636/");
    final X509Certificate certificate = getCertificate(keyStore);

    // Match when we provide an exact match for a DNS name.
    final StringBuilder buffer = new StringBuilder();
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds.example.com", certificate, true, false, buffer),
         buffer.toString());

    // Match when we provide a value that matches a wildcard in a DNS name when
    // the leftmost component is just a wildcard.
    buffer.setLength(0);
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "anything.domain1.com", certificate, true, false, buffer),
         buffer.toString());

    // Match when we provide a value that matches a wildcard in a DNS name when
    // the leftmost component has text in addition to the wildcard.
    buffer.setLength(0);
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds1.domain2.com", certificate, true, false, buffer),
         buffer.toString());

    // Match when we provide a value that matches an IPv4 address.
    buffer.setLength(0);
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "1.2.3.4", certificate, true, false, buffer),
         buffer.toString());

    // Match when we provide a value that exactly matches an IPv6 address.
    buffer.setLength(0);
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "::1", certificate, true, false, buffer),
         buffer.toString());

    // Match when we provide a value that matches an IPv6 address with a
    // different notation
    buffer.setLength(0);
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "0:0:0:0:0:0:0:1", certificate, true, false, buffer),
         buffer.toString());

    // Match when we provide a value that exactly matches a hostname in a URI.
    buffer.setLength(0);
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds.domain3.com", certificate, true, false, buffer),
         buffer.toString());

    // Match when we provide a value that matches a wildcard in a URI when
    // the leftmost component is just a wildcard.
    buffer.setLength(0);
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "anything.domain4.com", certificate, true, false, buffer),
         buffer.toString());

    // Match when we provide a value that matches a wildcard in a URI when the
    // leftmost component has text in addition to the wildcard.
    buffer.setLength(0);
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds3.domain5.com", certificate, true, false, buffer),
         buffer.toString());

    // Match when we provide an IP address in the host portion of a URI.
    buffer.setLength(0);
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "1.2.3.5", certificate, true, false, buffer),
         buffer.toString());

    // Don't match when we provide a hostname that doesn't match anything.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "something.domain7.com", certificate, true, false, buffer),
         buffer.toString());

    // Don't match when we provide a hostname that matches only the CN attribute
    // in the subject DN when that matching is disabled.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds.domain6.com", certificate, true, false, buffer),
         buffer.toString());

    // Do match when we provide a hostname that matches only the CN attribute
    // in the subject DN when that matching is enabled.
    buffer.setLength(0);
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "ds.domain6.com", certificate, true, true, buffer),
         buffer.toString());

    // Don't match when we provide an IP address that doesn't match anything.
    buffer.setLength(0);
    assertFalse(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "1.2.3.6", certificate, true, false, buffer),
         buffer.toString());

    // Match when we provide a loopback address.
    buffer.setLength(0);
    assertTrue(
         HostNameSSLSocketVerifier.certificateIncludesHostname(
              "127.0.0.1", certificate, true, false, buffer),
         buffer.toString());
  }



  /**
   * Generates a self-signed certificate with the provided information.  By
   * default, only the keystore, keystore-password, alias, and subject-dn
   * arguments will be provided.
   *
   * @param  subjectDN       The subject DN to use for the certificate.  This
   *                         must not be {@code null} or empty.
   * @param  additionalArgs  An array of any additional arguments that should be
   *                         provided to manage-certificates when creating the
   *                         certificate.  It must not be {@code null} but may
   *                         be empty.
   *
   * @return  The path to the key store file that was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static File generateCertificate(final String subjectDN,
                                          final String... additionalArgs)
          throws Exception
  {
    final File keyStore = createTempFile();
    assertTrue(keyStore.delete());

    final List<String> argsList = new ArrayList<>(20);
    argsList.addAll(Arrays.asList(
         "generate-self-signed-certificate",
         "--keystore", keyStore.getAbsolutePath(),
         "--keystore-password", PIN_STRING,
         "--alias", ALIAS,
         "--subject-dn", subjectDN));
    argsList.addAll(Arrays.asList(additionalArgs));

    final String[] args = argsList.toArray(StaticUtils.NO_STRINGS);
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ResultCode resultCode = ManageCertificates.main(null, out, out, args);
    assertEquals(resultCode, ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    return keyStore;
  }



  /**
   * Retrieves the specified certificate from the given key store.
   *
   * @param  keyStoreFile  The path to the key store that contains the
   *                       certificate to retrieve.
   *
   * @return  The requested certificate from the key store.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static X509Certificate getCertificate(final File keyStoreFile)
          throws Exception
  {
    final KeyStore keyStore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(keyStoreFile))
    {
      keyStore.load(inputStream, PIN_CHARS);
    }

    final KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry)
         keyStore.getEntry(ALIAS, new KeyStore.PasswordProtection(PIN_CHARS));
    return (X509Certificate) entry.getCertificateChain()[0];
  }



  /**
   * Provides basic coverage for the SSL socket verifier as a hostname verifier.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHostnameVerifier()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDSWithSSL();
    try (LDAPConnection conn = ds.getConnection())
    {
      final SSLSession sslSession = conn.getSSLSession();
      assertNotNull(sslSession);

      final HostNameSSLSocketVerifier verifier =
           new HostNameSSLSocketVerifier(true);
      assertTrue(verifier.verify("127.0.0.1", sslSession));

      assertFalse(verifier.verify("disallowed.example.com", sslSession));
    }
  }
}
