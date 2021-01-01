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
package com.unboundid.util.ssl;



import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.util.NullOutputStream;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides test coverage for the PromptTrustManager class.
 */
public class PromptTrustManagerTestCase
       extends SSLTestCase
{
  /**
   * Tests the first constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    PromptTrustManager m = new PromptTrustManager();

    assertNotNull(m);

    assertTrue(m.examineValidityDates());

    assertNotNull(m.getExpectedAddresses());
    assertTrue(m.getExpectedAddresses().isEmpty());

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the second constructor with a null accepted certificates file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NullFile()
         throws Exception
  {
    PromptTrustManager m = new PromptTrustManager(null);

    assertNotNull(m);

    assertTrue(m.examineValidityDates());

    assertNotNull(m.getExpectedAddresses());
    assertTrue(m.getExpectedAddresses().isEmpty());

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the second constructor with a nonexistent accepted certificates file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NonexistentFile()
         throws Exception
  {
    File f = createTempFile();
    f.delete();

    PromptTrustManager m = new PromptTrustManager(f.getAbsolutePath());

    assertNotNull(m);

    assertTrue(m.examineValidityDates());

    assertNotNull(m.getExpectedAddresses());
    assertTrue(m.getExpectedAddresses().isEmpty());

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the second constructor with a valid, existing accepted certificates
   * file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2ValidFile()
         throws Exception
  {
    KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    X509Certificate[] chain =
         ksManager.getCertificateChain(getJKSKeyStoreAlias());
    String signature = toLowerCase(toHex(chain[0].getSignature()));

    File f = createTempFile(signature);

    PromptTrustManager m = new PromptTrustManager(f.getAbsolutePath());

    assertNotNull(m);

    assertTrue(m.examineValidityDates());

    assertNotNull(m.getExpectedAddresses());
    assertTrue(m.getExpectedAddresses().isEmpty());

    m.checkClientTrusted(chain, "RSA");

    m.checkServerTrusted(chain, "RSA");

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the third constructor with a null accepted certificates file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NullFile()
         throws Exception
  {
    PromptTrustManager m =
         new PromptTrustManager(null, false, System.in, System.out);

    assertNotNull(m);

    assertFalse(m.examineValidityDates());

    assertNotNull(m.getExpectedAddresses());
    assertTrue(m.getExpectedAddresses().isEmpty());

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the third constructor with a nonexistent accepted certificates file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NonexistentFile()
         throws Exception
  {
    File f = createTempFile();
    f.delete();

    PromptTrustManager m =
         new PromptTrustManager(f.getAbsolutePath(), false, System.in,
                                System.out);

    assertNotNull(m);

    assertFalse(m.examineValidityDates());

    assertNotNull(m.getExpectedAddresses());
    assertTrue(m.getExpectedAddresses().isEmpty());

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the third constructor with a valid, existing accepted certificates
   * file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3ValidFile()
         throws Exception
  {
    KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    X509Certificate[] chain =
         ksManager.getCertificateChain(getJKSKeyStoreAlias());
    String signature = toLowerCase(toHex(chain[0].getSignature()));

    File f = createTempFile(signature);

    PromptTrustManager m =
         new PromptTrustManager(f.getAbsolutePath(), false, System.in,
                                System.out);

    assertNotNull(m);

    assertFalse(m.examineValidityDates());

    assertNotNull(m.getExpectedAddresses());
    assertTrue(m.getExpectedAddresses().isEmpty());

    m.checkClientTrusted(chain, "RSA");

    m.checkServerTrusted(chain, "RSA");

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the fourth constructor with a {@code null} expected address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4NullExpectedAddress()
         throws Exception
  {
    final PromptTrustManager m =
         new PromptTrustManager(null, false, (String) null, System.in,
              System.out);

    assertNotNull(m);

    assertFalse(m.examineValidityDates());

    assertNotNull(m.getExpectedAddresses());
    assertTrue(m.getExpectedAddresses().isEmpty());

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the fourth constructor with a non-{@code null} expected address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4NonNullExpectedAddress()
         throws Exception
  {
    final PromptTrustManager m =
         new PromptTrustManager(null, false, "ldap.example.com", System.in,
              System.out);

    assertNotNull(m);

    assertFalse(m.examineValidityDates());

    assertNotNull(m.getExpectedAddresses());
    assertEquals(m.getExpectedAddresses().size(), 1);
    assertEquals(m.getExpectedAddresses(),
         Collections.singletonList("ldap.example.com"));

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the fifth constructor with a {@code null} collection of expected
   * addresses.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5NullExpectedAddresses()
         throws Exception
  {
    final PromptTrustManager m =
         new PromptTrustManager(null, false, (List<String>) null, System.in,
              System.out);

    assertNotNull(m);

    assertFalse(m.examineValidityDates());

    assertNotNull(m.getExpectedAddresses());
    assertTrue(m.getExpectedAddresses().isEmpty());

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the fourth constructor with an empty collection of expected address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5EmptyExpectedAddresses()
         throws Exception
  {
    final PromptTrustManager m =
         new PromptTrustManager(null, false, Collections.<String>emptyList(),
              System.in, System.out);

    assertNotNull(m);

    assertFalse(m.examineValidityDates());

    assertNotNull(m.getExpectedAddresses());
    assertTrue(m.getExpectedAddresses().isEmpty());

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the fourth constructor with a non-empty collection of expected
   * address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5NonEmptyExpectedAddresses()
         throws Exception
  {
    final PromptTrustManager m =
         new PromptTrustManager(null, false,
              Arrays.asList("ldap.example.com", "ldap1.example.com",
                   "ldap2.example.com"),
              System.in, System.out);

    assertNotNull(m);

    assertFalse(m.examineValidityDates());

    assertNotNull(m.getExpectedAddresses());
    assertEquals(m.getExpectedAddresses().size(), 3);
    assertEquals(m.getExpectedAddresses(),
         Arrays.asList("ldap.example.com", "ldap1.example.com",
              "ldap2.example.com"));

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the third constructor with an empty file.  When prompted, the
   * certificate will be trusted and the file should be updated.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testYesToPrompt()
         throws Exception
  {
    ByteArrayInputStream in = new ByteArrayInputStream(getBytes("y\n"));

    File f = createTempFile();

    PromptTrustManager m =
         new PromptTrustManager(f.getAbsolutePath(), false, in,
                                NullOutputStream.getPrintStream());

    assertNotNull(m);

    assertFalse(m.examineValidityDates());

    KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    X509Certificate[] chain =
         ksManager.getCertificateChain(getJKSKeyStoreAlias());

    assertTrue(m.wouldPrompt(chain));

    m.checkClientTrusted(chain, "RSA");

    m.checkServerTrusted(chain, "RSA");

    assertNotNull(m.getAcceptedIssuers());

    m = new PromptTrustManager(f.getAbsolutePath(), false, null, null);

    assertNotNull(m);

    assertFalse(m.examineValidityDates());

    assertFalse(m.wouldPrompt(chain));

    m.checkClientTrusted(chain, "RSA");

    m.checkServerTrusted(chain, "RSA");

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the third constructor with an empty file and a certificate that has
   * multiple issuers.  When prompted, the
   * certificate will be trusted and the file should be updated.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testYesToPromptWithMultiCertificateChain()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String rootCACertificateAlias = "root-ca";
    final String rootCAKeyStorePath =
         new File(tempDir,
              rootCACertificateAlias + "-keystore.jks").getAbsolutePath();
    final String rootCACertificatePath =
         new File(tempDir,
              rootCACertificateAlias + ".cert").getAbsolutePath();

    final String intermediateCACertificateAlias = "intermediate-ca";
    final String intermediateCAKeyStorePath =
         new File(tempDir,
              intermediateCACertificateAlias + "-keystore.jks").
              getAbsolutePath();
    final String intermediateCACSRPath =
         new File(tempDir,
              intermediateCACertificateAlias + ".csr").getAbsolutePath();
    final String intermediateCACertificatePath =
         new File(tempDir,
              intermediateCACertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath =
         new File(tempDir,
              serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath =
         new File(tempDir, serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();


    // Create a JKS keystore with just a root CA certificate.
    PromptTrustManagerProcessorTestCase.manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    PromptTrustManagerProcessorTestCase.manageCertificates(
         "export-certificate",
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--output-format", "PEM",
         "--output-file", rootCACertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with an intermediate CA certificate that is
    // signed by the root CA.
    PromptTrustManagerProcessorTestCase.manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", intermediateCACSRPath,
         "--keystore", intermediateCAKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", intermediateCACertificateAlias,
         "--subject-dn",
         "CN=Example Intermediate CA,O=Example Corporation,C=US",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--key-usage", "crl-sign",
         "--extended-key-usage", "ocsp-signing",
         "--display-keytool-command");
    PromptTrustManagerProcessorTestCase.manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", intermediateCACSRPath,
         "--certificate-output-file", intermediateCACertificatePath,
         "--output-format", "PEM",
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "3650",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    PromptTrustManagerProcessorTestCase.manageCertificates(
         "import-certificate",
         "--certificate-file", intermediateCACertificatePath,
         "--certificate-file", rootCACertificatePath,
         "--keystore", intermediateCAKeyStorePath,
         "--keystore-password", "password",
         "--alias", intermediateCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the
    // intermediate CA.
    PromptTrustManagerProcessorTestCase.manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", serverCSRPath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-dns", "ldap.example.com",
         "--subject-alternative-name-dns", "ldap",
         "--subject-alternative-name-dns", "ds.example.com",
         "--subject-alternative-name-dns", "ds",
         "--subject-alternative-name-dns", "localhost",
         "--subject-alternative-name-ip-address", "127.0.0.1",
         "--subject-alternative-name-ip-address", "::1",
         "--extended-key-usage", "email-protection",
         "--display-keytool-command");
    PromptTrustManagerProcessorTestCase.manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", intermediateCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", intermediateCACertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    PromptTrustManagerProcessorTestCase.manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", intermediateCACertificatePath,
         "--certificate-file", rootCACertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");
    ByteArrayInputStream in = new ByteArrayInputStream(getBytes("y\n"));

    File f = createTempFile();

    PromptTrustManager m =
         new PromptTrustManager(f.getAbsolutePath(), false, in,
                                NullOutputStream.getPrintStream());

    assertNotNull(m);

    assertFalse(m.examineValidityDates());

    KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(serverKeyStorePath, "password".toCharArray());
    X509Certificate[] chain =
         ksManager.getCertificateChain("server-cert");

    assertTrue(m.wouldPrompt(chain));

    m.checkClientTrusted(chain, "RSA");

    m.checkServerTrusted(chain, "RSA");

    assertNotNull(m.getAcceptedIssuers());

    m = new PromptTrustManager(f.getAbsolutePath(), false, null, null);

    assertNotNull(m);

    assertFalse(m.examineValidityDates());

    assertFalse(m.wouldPrompt(chain));

    m.checkClientTrusted(chain, "RSA");

    m.checkServerTrusted(chain, "RSA");

    assertNotNull(m.getAcceptedIssuers());
  }



  /**
   * Tests the third constructor with an empty file.  When prompted, the
   * certificate will not be trusted and the attempt should fail.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testNoToPrompt()
         throws Exception
  {
    ByteArrayInputStream in = new ByteArrayInputStream(getBytes("n\n"));

    File f = createTempFile();

    PromptTrustManager m =
         new PromptTrustManager(f.getAbsolutePath(), false, in,
                                NullOutputStream.getPrintStream());

    assertNotNull(m);

    assertFalse(m.examineValidityDates());

    KeyStoreKeyManager ksManager =
         new KeyStoreKeyManager(getJKSKeyStorePath(), getJKSKeyStorePIN());
    X509Certificate[] chain =
         ksManager.getCertificateChain(getJKSKeyStoreAlias());

    assertTrue(m.wouldPrompt(chain));

    m.checkClientTrusted(chain, "RSA");
  }
}
