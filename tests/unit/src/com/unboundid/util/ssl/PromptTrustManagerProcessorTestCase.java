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
package com.unboundid.util.ssl;



import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.KeyStore;

import java.security.cert.Certificate;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1BitString;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ssl.cert.InternalCertHelper;
import com.unboundid.util.ssl.cert.ManageCertificates;
import com.unboundid.util.ssl.cert.PublicKeyAlgorithmIdentifier;
import com.unboundid.util.ssl.cert.SignatureAlgorithmIdentifier;
import com.unboundid.util.ssl.cert.X509Certificate;
import com.unboundid.util.ssl.cert.X509CertificateExtension;



/**
 * This class provides a set of test cases for the PromptTrustManagerProcessor
 * class.
 */
public final class PromptTrustManagerProcessorTestCase
       extends SSLTestCase
{
  /**
   * Tests the behavior with a valid certificate chain that shouldn't trigger
   * any warnings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidCertificateChain()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ldap.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertTrue(promptResult.getSecond().isEmpty());
  }



  /**
   * Tests the behavior with a certificate chain in which the certificate at the
   * head of the chain is not yet valid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testServerCertificateNotYetValid()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--validity-start-time",
              getValidityStartTime(System.currentTimeMillis() + 86_400_000L),
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> serverPromptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ldap.example.com"));

    assertNotNull(serverPromptResult.getFirst());
    assertEquals(serverPromptResult.getFirst(), Boolean.TRUE);

    assertNotNull(serverPromptResult.getSecond());
    assertFalse(serverPromptResult.getSecond().isEmpty());
    assertEquals(serverPromptResult.getSecond().size(), 1);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> clientPromptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, false, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ldap.example.com"));

    assertNotNull(clientPromptResult.getFirst());
    assertEquals(clientPromptResult.getFirst(), Boolean.TRUE);

    assertNotNull(clientPromptResult.getSecond());
    assertFalse(clientPromptResult.getSecond().isEmpty());
    assertEquals(clientPromptResult.getSecond().size(), 1);
  }



  /**
   * Tests the behavior with a certificate chain in which an issuer certificate
   * is expired.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIssuerCertificateExpired()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--validity-start-time",
              getValidityStartTime(System.currentTimeMillis() -
                   (7500L * 86_400_000L)),
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, false, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ldap.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertFalse(promptResult.getSecond().isEmpty());
    assertEquals(promptResult.getSecond().size(), 1);
  }



  /**
   * Tests the behavior with a certificate chain in which a certificate has an
   * extended key usage extension that does not include the serverAuth or
   * clientAuth usages.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMissingServerAuthExtendedKeyUsage()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
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
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method for a server certificate and examine the
    // result.
    final ObjectPair<Boolean,List<String>> serverPromptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ldap.example.com"));

    assertNotNull(serverPromptResult.getFirst());
    assertEquals(serverPromptResult.getFirst(), Boolean.TRUE);

    assertNotNull(serverPromptResult.getSecond());
    assertFalse(serverPromptResult.getSecond().isEmpty());
    assertEquals(serverPromptResult.getSecond().size(), 1);


    // Invoke the shouldPrompt method for a client certificate and examine the
    // result.
    final ObjectPair<Boolean,List<String>> clientPromptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, false, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ldap.example.com"));

    assertNotNull(clientPromptResult.getFirst());
    assertEquals(clientPromptResult.getFirst(), Boolean.TRUE);

    assertNotNull(clientPromptResult.getSecond());
    assertFalse(clientPromptResult.getSecond().isEmpty());
    assertEquals(clientPromptResult.getSecond().size(), 1);
  }



  /**
   * Tests the behavior with a certificate chain in which the issuer certificate
   * does not have a basic constraints extension.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIssuerMissingBasicConstraintsExtension()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, false, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ldap.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertFalse(promptResult.getSecond().isEmpty());
    assertEquals(promptResult.getSecond().size(), 1);
  }



  /**
   * Tests the behavior with a certificate chain in which an issuer certificate
   * has a basic constraints extension that indicates that the certificate
   * should not be a CA.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIssuerBasicConstraintsNotCA()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "false",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ldap.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertFalse(promptResult.getSecond().isEmpty());
    assertEquals(promptResult.getSecond().size(), 1);
  }



  /**
   * Tests the behavior with a certificate chain in which an issuer certificate
   * has a basic constraints extension with a maximum path length that is
   * shorter than the length of the certificate chain.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIssuerBasicConstraintsPathLengthExceeded()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String rootCACertificateAlias = "root-ca-cert";
    final String rootCAKeyStorePath = new File(tempDir,
         rootCACertificateAlias + "-keystore.jks").getAbsolutePath();
    final String rootCACertificatePath =
         new File(tempDir, rootCACertificateAlias + ".cert").getAbsolutePath();

    final String intermediateCACertificateAlias = "intermediate-ca-cert";
    final String intermediateCAKeyStorePath = new File(tempDir,
         intermediateCACertificateAlias + "-keystore.jks").getAbsolutePath();
    final String intermediateCACSRPath = new File(tempDir,
         intermediateCACertificateAlias + ".csr").getAbsolutePath();
    final String intermediateCACertificatePath =
         new File(tempDir, intermediateCACertificateAlias + ".cert").
              getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a root CA certificate.
    manageCertificates(
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
         "--basic-constraints-maximum-path-length", "0",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--output-format", "PEM",
         "--output-file", rootCACertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the
    // root CA.
    manageCertificates(
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", rootCACertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    X509Certificate[] ldapSDKChain = PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ldap.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertTrue(promptResult.getSecond().isEmpty());


    // Create a JKS keystore with an intermediate CA certificate that is signed
    // by the root CA.
    manageCertificates(
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
         "--basic-constraints-is-ca", "true",
         "--basic-constraints-maximum-path-length", "0",
         "--subject-alternative-name-dns", "ldap.example.com",
         "--subject-alternative-name-dns", "ldap",
         "--subject-alternative-name-dns", "ds.example.com",
         "--subject-alternative-name-dns", "ds",
         "--subject-alternative-name-dns", "localhost",
         "--subject-alternative-name-ip-address", "127.0.0.1",
         "--subject-alternative-name-ip-address", "::1",
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", intermediateCACSRPath,
         "--certificate-output-file", intermediateCACertificatePath,
         "--output-format", "PEM",
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", intermediateCACertificatePath,
         "--certificate-file", rootCACertificatePath,
         "--keystore", intermediateCAKeyStorePath,
         "--keystore-password", "password",
         "--alias", intermediateCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Delete the server certificate keystore and recreate it with a server
    // certificate that is signed by the intermediate CA.
    assertTrue(new File(serverKeyStorePath).delete());
    assertTrue(new File(serverCertificatePath).delete());
    assertTrue(new File(serverCSRPath).delete());
    manageCertificates(
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
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
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", intermediateCACertificatePath,
         "--certificate-file", rootCACertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    javaChain = keystore.getCertificateChain(serverCertificateAlias);
    ldapSDKChain = PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    promptResult = PromptTrustManagerProcessor.shouldPrompt(
         PromptTrustManager.getCacheKey(javaChain[0]),
         ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
         Collections.singletonList("ldap.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertFalse(promptResult.getSecond().isEmpty());
    assertEquals(promptResult.getSecond().size(), 1);
  }



  /**
   * Tests the behavior with an issuer certificate that has a key usage
   * extension without the keyCertSign usage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIssuerHasKeyUsageWithoutKeyCertSign()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "digital-signature",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ldap.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertFalse(promptResult.getSecond().isEmpty());
    assertEquals(promptResult.getSecond().size(), 1);
  }



  /**
   * Tests the behavior with a self-signed certificate that has a valid
   * signature.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSelfSignedCertificateWithValidSignature()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ldap.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertFalse(promptResult.getSecond().isEmpty());
    assertEquals(promptResult.getSecond().size(), 1);
  }



  /**
   * Tests the behavior with a self-signed certificate that has an invalid
   * signature.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSelfSignedCertificateWithInvalidSignature()
         throws Exception
  {
    final ObjectPair<X509Certificate,KeyPair> p =
         X509Certificate.generateSelfSignedCertificate(
              SignatureAlgorithmIdentifier.SHA_256_WITH_RSA,
              PublicKeyAlgorithmIdentifier.RSA, 2048,
              new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
              System.currentTimeMillis(),
              System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365L));
    final X509Certificate c = p.getFirst();
    final X509CertificateExtension[] extensions =
         new X509CertificateExtension[c.getExtensions().size()];
    c.getExtensions().toArray(extensions);

    final X509Certificate cert = InternalCertHelper.createX509Certificate(
         c.getVersion(), c.getSerialNumber(), c.getSignatureAlgorithmOID(),
         c.getSignatureAlgorithmParameters(),
         new ASN1BitString(ASN1BitString.getBitsForBytes(new byte[256])),
         c.getIssuerDN(), c.getNotBeforeTime(), c.getNotAfterTime(),
         c.getSubjectDN(), c.getPublicKeyAlgorithmOID(), null,
         c.getEncodedPublicKey(), c.getDecodedPublicKey(),
         c.getIssuerUniqueID(), c.getSubjectUniqueID(), extensions);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(cert.toCertificate()),
              new X509Certificate[] { cert }, true, true,
              Collections.<String,Boolean>emptyMap(), null);

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertFalse(promptResult.getSecond().isEmpty());
    assertEquals(promptResult.getSecond().size(), 2);
  }



  /**
   * Tests the behavior with only the first certificate of a two-certificate
   * chain.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleCertificateIncompleteChain()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
    {
      PromptTrustManager.convertChain(javaChain)[0]
    };


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ldap.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertFalse(promptResult.getSecond().isEmpty());
    assertEquals(promptResult.getSecond().size(), 1);
  }



  /**
   * Tests the behavior with a two-certificate chain in which the subject
   * certificate has an invalid signature.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSubjectCertificateWithInvalidSignature()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);

    final List<X509CertificateExtension> extensionList =
         ldapSDKChain[0].getExtensions();
    final X509CertificateExtension[] extensionArray =
         new X509CertificateExtension[extensionList.size()];
    extensionList.toArray(extensionArray);

    final boolean[] validSignatureBits =
         ldapSDKChain[0].getSignatureValue().getBits();
    final boolean[] invalidSignatureBits =
         new boolean[validSignatureBits.length];
    final ASN1BitString invalidSignatureValue =
         new ASN1BitString(invalidSignatureBits);

    ldapSDKChain[0] = InternalCertHelper.createX509Certificate(
         ldapSDKChain[0].getVersion(), ldapSDKChain[0].getSerialNumber(),
         ldapSDKChain[0].getSignatureAlgorithmOID(),
         ldapSDKChain[0].getSignatureAlgorithmParameters(),
         invalidSignatureValue, ldapSDKChain[0].getIssuerDN(),
         ldapSDKChain[0].getNotBeforeTime(), ldapSDKChain[0].getNotAfterTime(),
         ldapSDKChain[0].getSubjectDN(),
         ldapSDKChain[0].getPublicKeyAlgorithmOID(),
         ldapSDKChain[0].getPublicKeyAlgorithmParameters(),
         ldapSDKChain[0].getEncodedPublicKey(),
         ldapSDKChain[0].getDecodedPublicKey(),
         ldapSDKChain[0].getIssuerUniqueID(),
         ldapSDKChain[0].getSubjectUniqueID(), extensionArray);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ldap.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertFalse(promptResult.getSecond().isEmpty());
    assertEquals(promptResult.getSecond().size(), 1);
  }



  /**
   * Tests the behavior with an issuer certificate that has an invalid
   * signature.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIssuerCertificateWithInvalidSignature()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);

    final List<X509CertificateExtension> extensionList =
         ldapSDKChain[1].getExtensions();
    final X509CertificateExtension[] extensionArray =
         new X509CertificateExtension[extensionList.size()];
    extensionList.toArray(extensionArray);

    final boolean[] validSignatureBits =
         ldapSDKChain[1].getSignatureValue().getBits();
    final boolean[] invalidSignatureBits =
         new boolean[validSignatureBits.length];
    final ASN1BitString invalidSignatureValue =
         new ASN1BitString(invalidSignatureBits);

    ldapSDKChain[1] = InternalCertHelper.createX509Certificate(
         ldapSDKChain[1].getVersion(), ldapSDKChain[1].getSerialNumber(),
         ldapSDKChain[1].getSignatureAlgorithmOID(),
         ldapSDKChain[1].getSignatureAlgorithmParameters(),
         invalidSignatureValue, ldapSDKChain[1].getIssuerDN(),
         ldapSDKChain[1].getNotBeforeTime(), ldapSDKChain[1].getNotAfterTime(),
         ldapSDKChain[1].getSubjectDN(),
         ldapSDKChain[1].getPublicKeyAlgorithmOID(),
         ldapSDKChain[1].getPublicKeyAlgorithmParameters(),
         ldapSDKChain[1].getEncodedPublicKey(),
         ldapSDKChain[1].getDecodedPublicKey(),
         ldapSDKChain[1].getIssuerUniqueID(),
         ldapSDKChain[1].getSubjectUniqueID(), extensionArray);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ldap.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertFalse(promptResult.getSecond().isEmpty());
    assertEquals(promptResult.getSecond().size(), 1);
  }



  /**
   * Tests the behavior with a certificate chain in which the second certificate
   * is not the issuer for the first.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCertificateChainIssuerMismatch()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
         "generate-self-signed-certificate",
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
    {
      keystore.getCertificateChain(serverCertificateAlias)[0],
      keystore.getCertificate(caCertificateAlias)
    };

    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ldap.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertFalse(promptResult.getSecond().isEmpty());
    assertEquals(promptResult.getSecond().size(), 1);
  }



  /**
   * Tests the behavior with a three-certificate chain in which the third
   * certificate is missing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultiCertificateIncompleteChain()
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
    manageCertificates(
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
    manageCertificates(
         "export-certificate",
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--output-format", "PEM",
         "--output-file", rootCACertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with an intermediate CA certificate that is
    // signed by the root CA.
    manageCertificates(
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
    manageCertificates(
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
    manageCertificates(
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
    manageCertificates(
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
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
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", intermediateCACertificatePath,
         "--certificate-file", rootCACertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] convertedChain =
         PromptTrustManager.convertChain(javaChain);
    final X509Certificate[] ldapSDKChain =
    {
      convertedChain[0],
      convertedChain[1]
    };


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ldap.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertFalse(promptResult.getSecond().isEmpty());
    assertEquals(promptResult.getSecond().size(), 1);
  }



  /**
   * Tests the behavior with a valid certificate chain that shouldn't trigger
   * any warnings.  The certificate won't have a subject alternative name
   * extension, but the CN attribute of the subject will match the expected
   * address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidCertificateChainMatchNameWithoutSAN()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ldap.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertTrue(promptResult.getSecond().isEmpty());
  }



  /**
   * Tests the behavior with a valid certificate chain that shouldn't trigger
   * any warnings.  The certificate won't have a subject alternative name
   * extension, but the CN attribute of the subject will include a wildcard and
   * will match the expected address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidCertificateChainMatchWildcardNameWithoutSAN()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", serverCSRPath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--subject-dn", "CN=*.example.com,O=Example Corporation,C=US",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ldap.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertTrue(promptResult.getSecond().isEmpty());
  }



  /**
   * Tests the behavior with a valid certificate chain that shouldn't trigger
   * any warnings.  The certificate won't have a subject alternative name
   * extension, but the CN attribute of the subject will match the expected
   * address when both are an IP address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidCertificateChainMatchIPWithoutSAN()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", serverCSRPath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--subject-dn", "CN=1.2.3.4,O=Example Corporation,C=US",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Arrays.asList("ldap.example.com", "1.2.3.4"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertTrue(promptResult.getSecond().isEmpty());
  }



  /**
   * Tests the behavior with a valid certificate chain that shouldn't trigger
   * any warnings.  The certificate won't have a subject alternative name
   * extension, and the CN attribute of the subject will not match the expected
   * address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidCertificateChainDoNotMatchNameWithoutSAN()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("nomatch.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertFalse(promptResult.getSecond().isEmpty());
    assertEquals(promptResult.getSecond().size(), 1);
  }



  /**
   * Tests the behavior with a valid certificate chain that shouldn't trigger
   * any warnings.  The certificate won't have a subject alternative name
   * extension, but the CN attribute of the subject will include a wildcard that
   * does not match the expected address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidCertificateChainDoesNotMatchWildcardNameWithoutSAN()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", serverCSRPath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--subject-dn", "CN=*.notexample.com,O=Example Corporation,C=US",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ldap.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertFalse(promptResult.getSecond().isEmpty());
    assertEquals(promptResult.getSecond().size(), 1);
  }



  /**
   * Tests the behavior with a valid certificate chain that shouldn't trigger
   * any warnings.  The certificate won't have a subject alternative name
   * extension, but the CN attribute of the subject will include a wildcard that
   * does not match the expected address because the number of components does
   * not match the FQDN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidCertificateChainDoesWildcardComponentMismatch()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", serverCSRPath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--subject-dn", "CN=*.extra.example.com,O=Example Corporation,C=US",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ldap.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertFalse(promptResult.getSecond().isEmpty());
    assertEquals(promptResult.getSecond().size(), 1);
  }



  /**
   * Tests the behavior with a valid certificate chain that shouldn't trigger
   * any warnings.  The certificate won't have a subject alternative name
   * extension, and also won't have a CN attribute in its subject.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidCertificateChainWithoutCNOrSAN()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", serverCSRPath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--subject-dn", "E=admin@example.com,O=Example Corporation,C=US",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ldap.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertTrue(promptResult.getSecond().isEmpty());
  }



  /**
   * Tests the behavior with a valid certificate chain that shouldn't trigger
   * any warnings.  The certificate will have a subject alternative name
   * extension, and the expected address does not match the value of the CN
   * attribute in the subject, but does match one of the DNS name values in the
   * extension.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidCertificateChainMatchNameWithSAN()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("ds.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertTrue(promptResult.getSecond().isEmpty());
  }



  /**
   * Tests the behavior with a valid certificate chain that shouldn't trigger
   * any warnings.  The certificate will have a subject alternative name
   * extension, and the expected address does not match the value of the CN
   * attribute in the subject, but does match one of the IP address values in
   * the extension.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidCertificateChainMatchIPWithSAN()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("127.0.0.1"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertTrue(promptResult.getSecond().isEmpty());
  }



  /**
   * Tests the behavior with a valid certificate chain that shouldn't trigger
   * any warnings.  The certificate will have a subject alternative name
   * extension, and the expected address does not match the value of the CN
   * attribute in the subject or any of the names or IP addresses in the
   * extension.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidCertificateChainDoesNotMatchNameWithSAN()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, Collections.<String,Boolean>emptyMap(),
              Collections.singletonList("nomatch.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertFalse(promptResult.getSecond().isEmpty());
    assertEquals(promptResult.getSecond().size(), 1);
  }



  /**
   * Tests the behavior with a valid certificate chain that shouldn't trigger
   * any warnings and that is already in the cache.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidCertificateChainAlreadyInCache()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    final Map<String,Boolean> acceptedCertificates =
         Collections.singletonMap(PromptTrustManager.getCacheKey(javaChain[0]),
              Boolean.FALSE);

    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, true, true, acceptedCertificates,
              Collections.singletonList("ldap.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.FALSE);

    assertNotNull(promptResult.getSecond());
    assertTrue(promptResult.getSecond().isEmpty());
  }



  /**
   * Tests the behavior with a certificate chain in which an issuer certificate
   * is expired.  The certificate will already be in the cache of accepted
   * certificates, but it will not have been explicitly accepted now that it is
   * expired.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIssuerCertificateExpiredInCacheNotAcceptedOutsideValidity()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--validity-start-time",
              getValidityStartTime(System.currentTimeMillis() -
                   (7500L * 86_400_000L)),
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    final Map<String,Boolean> acceptedCertificates =
         Collections.singletonMap(PromptTrustManager.getCacheKey(javaChain[0]),
              Boolean.FALSE);

    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, false, true, acceptedCertificates,
              Collections.singletonList("ldap.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.TRUE);

    assertNotNull(promptResult.getSecond());
    assertFalse(promptResult.getSecond().isEmpty());
    assertEquals(promptResult.getSecond().size(), 1);
  }



  /**
   * Tests the behavior with a certificate chain in which an issuer certificate
   * is expired.  The certificate will already be in the cache of accepted
   * certificates, and it will not have been explicitly accepted since it has
   * expired.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIssuerCertificateExpiredInCacheAcceptedOutsideValidity()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    final File tempDir = createTempDir();

    final String caCertificateAlias = "ca-cert";
    final String caKeyStorePath = new File(tempDir,
         caCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String caCertificatePath =
         new File(tempDir, caCertificateAlias + ".cert").getAbsolutePath();

    final String serverCertificateAlias = "server-cert";
    final String serverKeyStorePath = new File(tempDir,
         serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    final String serverCSRPath = new File(tempDir,
         serverCertificateAlias + ".csr").getAbsolutePath();
    final String serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();

    // Create a JKS keystore with just a CA certificate.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", caCertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--validity-start-time",
              getValidityStartTime(System.currentTimeMillis() -
                   (7500L * 86_400_000L)),
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--alias", caCertificateAlias,
         "--output-format", "PEM",
         "--output-file", caCertificatePath,
         "--display-keytool-command");


    // Create a JKS keystore with a server certificate that is signed by the CA.
    manageCertificates(
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
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", serverCSRPath,
         "--certificate-output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", caKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", caCertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--certificate-file", caCertificatePath,
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Load the keystore and get the certificate chain.
    final KeyStore keystore = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream = new FileInputStream(serverKeyStorePath))
    {
      keystore.load(inputStream, "password".toCharArray());
    }

    final Certificate[] javaChain =
         keystore.getCertificateChain(serverCertificateAlias);
    final X509Certificate[] ldapSDKChain =
         PromptTrustManager.convertChain(javaChain);


    // Invoke the shouldPrompt method and examine the result.
    final Map<String,Boolean> acceptedCertificates =
         Collections.singletonMap(PromptTrustManager.getCacheKey(javaChain[0]),
              Boolean.TRUE);

    final ObjectPair<Boolean,List<String>> promptResult =
         PromptTrustManagerProcessor.shouldPrompt(
              PromptTrustManager.getCacheKey(javaChain[0]),
              ldapSDKChain, false, true, acceptedCertificates,
              Collections.singletonList("ldap.example.com"));

    assertNotNull(promptResult.getFirst());
    assertEquals(promptResult.getFirst(), Boolean.FALSE);

    assertNotNull(promptResult.getSecond());
    assertFalse(promptResult.getSecond().isEmpty());
    assertEquals(promptResult.getSecond().size(), 1);
  }



  /**
   * Provides test coverage for the [@code isHostnameOrIPAddress} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIsHostnameOrIPAddress()
         throws Exception
  {
    // An empty string is not a valid hostname or IP address.
    assertFalse(PromptTrustManagerProcessor.isHostnameOrIPAddress(""));

    // IPv4 and IPv6 addresses should be accepted.
    assertTrue(PromptTrustManagerProcessor.isHostnameOrIPAddress("1.2.3.4"));
    assertTrue(PromptTrustManagerProcessor.isHostnameOrIPAddress("::1"));

    // A string with just ASCII letters should be accepted.
    assertTrue(PromptTrustManagerProcessor.isHostnameOrIPAddress("test"));

    // A string with just ASCII letters and digits should be accepted as long as
    // the first character is not a digit.
    assertTrue(PromptTrustManagerProcessor.isHostnameOrIPAddress("test1"));
    assertTrue(PromptTrustManagerProcessor.isHostnameOrIPAddress("t1est"));
    assertFalse(PromptTrustManagerProcessor.isHostnameOrIPAddress("1test"));

    // A string with just ASCII letters and periods should be accepted as long
    // as there aren't two consecutive periods and as long neither the first
    // nor last character is a period.
    assertTrue(PromptTrustManagerProcessor.isHostnameOrIPAddress("test.com"));
    assertFalse(PromptTrustManagerProcessor.isHostnameOrIPAddress("test..com"));
    assertFalse(PromptTrustManagerProcessor.isHostnameOrIPAddress(".test.com"));
    assertFalse(PromptTrustManagerProcessor.isHostnameOrIPAddress("test.com."));

    // A string with just ASCII letters and digits and periods should be
    // accepted as long as neither a period nor a digit follows a period or
    // appears at the beginning of the string.  Periods are also not allowed at
    // the end of the string
    assertTrue(PromptTrustManagerProcessor.isHostnameOrIPAddress("test1.com"));
    assertFalse(PromptTrustManagerProcessor.isHostnameOrIPAddress(
         "test1..com"));
    assertFalse(PromptTrustManagerProcessor.isHostnameOrIPAddress(
         ".test1.com"));
    assertFalse(PromptTrustManagerProcessor.isHostnameOrIPAddress("test.1com"));
    assertFalse(PromptTrustManagerProcessor.isHostnameOrIPAddress(
         "test.1com."));

    // An asterisk will only be accepted if it appears at the beginning of the
    // string and is immediately followed by a period and that is followed by
    // at least one other valid component.
    assertTrue(PromptTrustManagerProcessor.isHostnameOrIPAddress(
         "*.example.com"));
    assertFalse(PromptTrustManagerProcessor.isHostnameOrIPAddress(
         "test.*.example.com"));
    assertFalse(PromptTrustManagerProcessor.isHostnameOrIPAddress(
         "*test.example.com"));
    assertFalse(PromptTrustManagerProcessor.isHostnameOrIPAddress("*."));
    assertFalse(PromptTrustManagerProcessor.isHostnameOrIPAddress("*"));
  }



  /**
   * Runs the manage-certificates tool with the provided arguments and expects
   * a success result code.
   *
   * @param  args  The command-line arguments to provide when running the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  static void manageCertificates(final String... args)
         throws Exception
  {
    manageCertificates(ResultCode.SUCCESS, null, args);
  }



  /**
   * Runs the manage-certificates tool with the provided arguments and expects
   * a success result code.
   *
   * @param  expectedResultCode  The result code expected when running the tool.
   *                             This may be {@code null} if any result code
   *                             should be accepted.
   * @param  stdInString         A string whose contents will be used as
   *                             standard input for the tool.  It may be
   *                             {@code null} if no input should be available.
   * @param  args                The command-line arguments to provide when
   *                             running the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void manageCertificates(final ResultCode expectedResultCode,
                                         final String stdInString,
                                         final String... args)
          throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ByteArrayInputStream in;
    if (stdInString == null)
    {
      in = new ByteArrayInputStream(StaticUtils.NO_BYTES);
    }
    else
    {
      in = new ByteArrayInputStream(StaticUtils.getBytes(stdInString));
    }

    final ResultCode actualResultCode =
         ManageCertificates.main(in, out, out, args);

    if ((expectedResultCode != null) &&
        (actualResultCode != expectedResultCode))
    {
      final ByteStringBuffer buffer = new ByteStringBuffer();
      buffer.append("Running manage-certificates with arguments");
      buffer.append(StaticUtils.EOL);
      buffer.append(StaticUtils.EOL);
      buffer.append("    ");
      for (final String arg : args)
      {
        buffer.append(' ');
        buffer.append(StaticUtils.cleanExampleCommandLineArgument(arg));
      }
      buffer.append(StaticUtils.EOL);
      buffer.append(StaticUtils.EOL);
      buffer.append("exited with result code ");
      buffer.append(String.valueOf(actualResultCode));
      buffer.append(" instead of expected result code ");
      buffer.append(String.valueOf(expectedResultCode));
      buffer.append(".  The output obtained from the command is:");
      buffer.append(StaticUtils.EOL);
      buffer.append(StaticUtils.EOL);
      buffer.append(out.toByteArray());

      fail(buffer.toString());
    }
  }



  /**
   * Retrieves a formatted representation of a validity start time for the
   * specified timestamp.
   *
   * @param  time  The timestamp to format.
   *
   * @return  A formatted representation of the provided timestamp.
   */
  private static String getValidityStartTime(long time)
  {
    final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
    return dateFormat.format(new Date(time));
  }
}
