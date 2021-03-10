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



import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1BitString;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.OID;
import com.unboundid.util.PasswordReader;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ssl.JVMDefaultTrustManager;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;



/**
 * This class provides a set of test cases for the manage-certificates tool.
 */
public final class ManageCertificatesTestCase
       extends LDAPSDKTestCase
{
  /**
   * A result code value that indicates that any result code is acceptable.
   */
  private static final ResultCode ANY_RESULT_CODE = null;



  private volatile File tempDir = null;

  private volatile String intermediateCACertificateAlias = null;
  private volatile String intermediateCACertificatePath = null;
  private volatile String intermediateCACSRPath = null;
  private volatile String intermediateCAKeyPath = null;
  private volatile String intermediateCAKeyStorePath = null;

  private volatile String rootCACertificateAlias = null;
  private volatile String rootCACertificatePath = null;
  private volatile String rootCAKeyPath = null;
  private volatile String rootCAKeyStorePath = null;

  private volatile String serverCertificateAlias = null;
  private volatile String serverCertificateChainPath = null;
  private volatile String serverCertificatePath = null;
  private volatile String serverCSRPath = null;
  private volatile String serverKeyPath = null;
  private volatile String serverKeyStorePath = null;
  private volatile String serverTrustStorePath = null;

  private volatile String serverPKCS12KeyStorePath = null;

  private volatile String invalidKeyStorePath = null;

  private volatile String emptyKeyStorePath = null;
  private volatile String emptyPKCS12KeyStorePath = null;

  private volatile String correctPasswordFilePath = null;
  private volatile String emptyPasswordFilePath = null;
  private volatile String multiLinePasswordFilePath = null;
  private volatile String wrongPasswordFilePath = null;



  /**
   * Performs some initial setup before actually running the tests.  This
   * includes:
   * <UL>
   *   <LI>
   *     Create a root-ca-keystore with a self-signed signing certificate.
   *   </LI>
   *   <LI>
   *     Create an intermediate-ca-keystore with a signing certificate signed by
   *     the root CA certificate.
   *   </LI>
   *   <LI>
   *     Create a server-keystore with a server certificate signed by the
   *     intermediate CA.
   *   </LI>
   *   <LI>
   *     Exporting all of the above certificates, including a complete
   *     certificate chain, in both PEM and DER format.
   *   </LI>
   * </UL>
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    // Create a bunch of variables with file paths and other values to use
    // during testing.
    tempDir = createTempDir();

    rootCACertificateAlias = "root-ca";
    rootCAKeyStorePath =
         new File(tempDir,
              rootCACertificateAlias + "-keystore.jks").getAbsolutePath();
    rootCACertificatePath =
         new File(tempDir,
              rootCACertificateAlias + ".cert").getAbsolutePath();
    rootCAKeyPath =
         new File(tempDir, rootCACertificateAlias + ".key").getAbsolutePath();

    intermediateCACertificateAlias = "intermediate-ca";
    intermediateCAKeyStorePath =
         new File(tempDir,
              intermediateCACertificateAlias + "-keystore.jks").
              getAbsolutePath();
    intermediateCACSRPath =
         new File(tempDir,
              intermediateCACertificateAlias + ".csr").getAbsolutePath();
    intermediateCACertificatePath =
         new File(tempDir,
              intermediateCACertificateAlias + ".cert").getAbsolutePath();
    intermediateCAKeyPath =
         new File(tempDir,
              intermediateCACertificateAlias + ".key").getAbsolutePath();

    serverCertificateAlias = "server-cert";
    serverKeyStorePath =
         new File(tempDir,
              serverCertificateAlias + "-keystore.jks").getAbsolutePath();
    serverCSRPath =
         new File(tempDir, serverCertificateAlias + ".csr").getAbsolutePath();
    serverCertificatePath =
         new File(tempDir, serverCertificateAlias + ".cert").getAbsolutePath();
    serverCertificateChainPath =
         new File(tempDir, serverCertificateAlias + ".chain").getAbsolutePath();
    serverKeyPath =
         new File(tempDir, serverCertificateAlias + ".key").getAbsolutePath();
    serverTrustStorePath =
         new File(tempDir,
              serverCertificateAlias + "-trust-store.jks").getAbsolutePath();

    serverPKCS12KeyStorePath =
         new File(tempDir,
              serverCertificateAlias + "-keystore.p12").getAbsolutePath();

    invalidKeyStorePath =
         createTempFile("not a valid keystore").getAbsolutePath();

    correctPasswordFilePath = createTempFile("password").getAbsolutePath();
    emptyPasswordFilePath = createTempFile().getAbsolutePath();
    multiLinePasswordFilePath = createTempFile(
         "password",
         "another line").getAbsolutePath();
    wrongPasswordFilePath = createTempFile("wrong").getAbsolutePath();


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
    manageCertificates(
         "export-private-key",
         "--output-file", rootCAKeyPath,
         "--output-format", "PEM",
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias);

    // Make sure that the root CA keystore only has a single alias, and that it
    // is for a key entry.
    final KeyStore rootCAKeystore = getKeystore(rootCAKeyStorePath, "JKS");
    assertEquals(getAliases(rootCAKeystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(rootCAKeystore, true, false),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(rootCAKeystore, false, true),
         Collections.emptySet());

    // Make sure that the certificate chain for the root CA certificate has
    // exactly one entry, and that the entry has the expected subject.
    final X509Certificate[] rootCAChain =
         getCertificateChain(rootCAKeystore, rootCACertificateAlias);
    assertNotNull(rootCAChain);
    assertEquals(rootCAChain.length, 1);
    assertEquals(rootCAChain[0].getSubjectDN(),
         new DN("CN=Example Root CA,O=Example Corporation,C=US"));


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
    manageCertificates(
         "export-private-key",
         "--output-file", intermediateCAKeyPath,
         "--output-format", "PEM",
         "--keystore", intermediateCAKeyStorePath,
         "--keystore-password", "password",
         "--alias", intermediateCACertificateAlias);

    // Make sure that the intermediate CA keystore only has a single alias, and
    // that it is for a key entry.
    final KeyStore intermediateCAKeystore =
         getKeystore(intermediateCAKeyStorePath, "JKS");
    assertEquals(getAliases(intermediateCAKeystore, true, true),
         setOf(intermediateCACertificateAlias));
    assertEquals(getAliases(intermediateCAKeystore, true, false),
         setOf(intermediateCACertificateAlias));
    assertEquals(getAliases(intermediateCAKeystore, false, true),
         Collections.emptySet());

    // Make sure that the certificate chain for the intermediate CA certificate
    // has exactly two entries, and the entries are in the right order.
    final X509Certificate[] intermediateCAChain = getCertificateChain(
         intermediateCAKeystore, intermediateCACertificateAlias);
    assertNotNull(intermediateCAChain);
    assertEquals(intermediateCAChain.length, 2);
    assertEquals(intermediateCAChain[0].getSubjectDN(),
         new DN("CN=Example Intermediate CA,O=Example Corporation,C=US"));
    assertEquals(intermediateCAChain[1].getSubjectDN(),
         new DN("CN=Example Root CA,O=Example Corporation,C=US"));


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
    manageCertificates(
         "export-certificate",
         "--output-file", serverCertificatePath,
         "--output-format", "PEM",
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--display-keytool-command");
    manageCertificates(
         "export-certificate",
         "--output-file", serverCertificateChainPath,
         "--output-format", "PEM",
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--export-certificate-chain",
         "--display-keytool-command");
    manageCertificates(
         "export-private-key",
         "--output-file", serverKeyPath,
         "--output-format", "PEM",
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias);

    // Make sure that the server keystore only has a single alias, and that it
    // is for a key entry.
    KeyStore serverKeystore = getKeystore(serverKeyStorePath, "JKS");
    assertEquals(getAliases(serverKeystore, true, true),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(serverKeystore, true, false),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(serverKeystore, false, true),
         Collections.emptySet());

    // Make sure that the certificate chain for the server certificate has
    // exactly three entries, and the entries are in the right order.
    X509Certificate[] serverChain =
         getCertificateChain(serverKeystore, serverCertificateAlias);
    assertNotNull(serverChain);
    assertEquals(serverChain.length, 3);
    assertEquals(serverChain[0].getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));
    assertEquals(serverChain[1].getSubjectDN(),
         new DN("CN=Example Intermediate CA,O=Example Corporation,C=US"));
    assertEquals(serverChain[2].getSubjectDN(),
         new DN("CN=Example Root CA,O=Example Corporation,C=US"));


    // Create a JKS keystore by importing the server certificate chain
    // without the private key.
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificateChainPath,
         "--keystore", serverTrustStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    // Make sure that the server trust store has three aliases, and that they
    // are all for certificate entries.
    KeyStore serverTrustStore = getKeystore(serverTrustStorePath, "JKS");
    assertEquals(getAliases(serverTrustStore, true, true),
         setOf(serverCertificateAlias,
              serverCertificateAlias + "-issuer-1",
              serverCertificateAlias + "-issuer-2"));
    assertEquals(getAliases(serverTrustStore, true, false),
         Collections.emptySet());
    assertEquals(getAliases(serverTrustStore, false, true),
         setOf(serverCertificateAlias,
              serverCertificateAlias + "-issuer-1",
              serverCertificateAlias + "-issuer-2"));

    // Make sure that we can get all of the certificates and that they are the
    // expected values.
    X509Certificate serverEndCert =
         getCertificate(serverTrustStore, serverCertificateAlias);
    assertNotNull(serverEndCert);
    assertEquals(serverEndCert.getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));

    X509Certificate serverIntermediateCACert =
         getCertificate(serverTrustStore, serverCertificateAlias + "-issuer-1");
    assertNotNull(serverIntermediateCACert);
    assertEquals(serverIntermediateCACert.getSubjectDN(),
         new DN("CN=Example Intermediate CA,O=Example Corporation,C=US"));

    X509Certificate serverRootCACert =
         getCertificate(serverTrustStore, serverCertificateAlias + "-issuer-2");
    assertNotNull(serverRootCACert);
    assertEquals(serverRootCACert.getSubjectDN(),
         new DN("CN=Example Root CA,O=Example Corporation,C=US"));


    // Create a server PKCS #12 keystore with the same contents as the server
    // JKS keystore.
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificateChainPath,
         "--private-key-file", serverKeyPath,
         "--keystore", serverPKCS12KeyStorePath,
         "--keystore-type", "PKCS12",
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    // Make sure that the server PKCS #12 keystore only has a single alias, and
    // that it is for a key entry.
    serverKeystore = getKeystore(serverPKCS12KeyStorePath, "PKCS12");
    assertEquals(getAliases(serverKeystore, true, true),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(serverKeystore, true, false),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(serverKeystore, false, true),
         Collections.emptySet());

    // Make sure that the certificate chain for the server certificate has
    // exactly three entries, and the entries are in the right order.
    serverChain = getCertificateChain(serverKeystore, serverCertificateAlias);
    assertNotNull(serverChain);
    assertEquals(serverChain.length, 3);
    assertEquals(serverChain[0].getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));
    assertEquals(serverChain[1].getSubjectDN(),
         new DN("CN=Example Intermediate CA,O=Example Corporation,C=US"));
    assertEquals(serverChain[2].getSubjectDN(),
         new DN("CN=Example Root CA,O=Example Corporation,C=US"));

    // Make sure that we can get all of the certificates and that they are the
    // expected values.
    serverEndCert = getCertificate(serverTrustStore, serverCertificateAlias);
    assertNotNull(serverEndCert);
    assertEquals(serverEndCert.getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));

    serverIntermediateCACert =
         getCertificate(serverTrustStore, serverCertificateAlias + "-issuer-1");
    assertNotNull(serverIntermediateCACert);
    assertEquals(serverIntermediateCACert.getSubjectDN(),
         new DN("CN=Example Intermediate CA,O=Example Corporation,C=US"));

    serverRootCACert =
         getCertificate(serverTrustStore, serverCertificateAlias + "-issuer-2");
    assertNotNull(serverRootCACert);
    assertEquals(serverRootCACert.getSubjectDN(),
         new DN("CN=Example Root CA,O=Example Corporation,C=US"));


    // Create an empty JKS keystore by copying the server keystore and deleting
    // the existing entry.
    emptyKeyStorePath = copyFile(serverKeyStorePath).getAbsolutePath();
    manageCertificates(
         "delete-certificate",
         "--keystore", emptyKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    // Make sure that the empty keystore file exists, and that it doesn't
    // contain any entries.
    assertTrue(new File(emptyKeyStorePath).exists());
    final KeyStore emptyKeyStore = getKeystore(emptyKeyStorePath, "JKS");
    assertEquals(getAliases(emptyKeyStore, true, true), Collections.emptySet());



    // Create an empty PKCS #12 keystore the same way we created the empty JKS
    // keystore.
    emptyPKCS12KeyStorePath =
         copyFile(serverPKCS12KeyStorePath).getAbsolutePath();
    manageCertificates(
         "delete-certificate",
         "--keystore", emptyPKCS12KeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    // Make sure that the empty PKCS #12 keystore file exists, and that it
    // doesn't contain any entries.
    assertTrue(new File(emptyPKCS12KeyStorePath).exists());
    final KeyStore emptyJKSKeyStore =
         getKeystore(emptyPKCS12KeyStorePath, "PKCS12");
    assertEquals(getAliases(emptyJKSKeyStore, true, true),
         Collections.emptySet());
  }



  /**
   * Provides test coverage for a number of tool methods that can be invoked
   * without actually running the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMethodsWithoutRunning()
         throws Exception
  {
    final ManageCertificates manageCertificates =
         new ManageCertificates(null, null, null);

    assertNotNull(manageCertificates.getToolName());
    assertEquals(manageCertificates.getToolName(), "manage-certificates");

    assertNotNull(manageCertificates.getToolDescription());

    assertNotNull(manageCertificates.getToolVersion());

    assertTrue(manageCertificates.supportsInteractiveMode());
    assertTrue(manageCertificates.defaultsToInteractiveMode());

    assertTrue(manageCertificates.supportsPropertiesFile());

    assertFalse(manageCertificates.supportsOutputFile());

    assertTrue(manageCertificates.logToolInvocationByDefault());
  }



  /**
   * Tests the behavior when running the tool with the "--help" and
   * "--help-subcommands" methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsage()
         throws Exception
  {
    manageCertificates("--help");

    manageCertificates("--help-subcommands");

    final String[] subCommands =
    {
      "list-certificates",
      "export-certificate",
      "export-private-key",
      "import-certificate",
      "generate-self-signed-certificate",
      "generate-certificate-signing-request",
      "sign-certificate-signing-request",
      "delete-certificate",
      "change-certificate-alias",
      "retrieve-server-certificate",
      "trust-server-certificate",
      "check-certificate-usability",
      "display-certificate-file",
      "display-certificate-signing-request-file"
    };

    for (final String subCommand : subCommands)
    {
      manageCertificates(subCommand, "--help");
    }
  }



  /**
   * Provides test coverage for the list-certificates subcommand.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testListCertificates()
         throws Exception
  {
    // Run the tool with a minimal set of arguments.
    manageCertificates(
         "list-certificates",
         "--keystore", serverKeyStorePath);
    manageCertificates(
         "list-certificates",
         "--keystore", serverPKCS12KeyStorePath);

    // Run the tool with a more complete set of arguments.
    manageCertificates(
         "list-certificates",
         "--keystore", serverKeyStorePath,
         "--keystore-password-file", correctPasswordFilePath,
         "--alias", serverCertificateAlias,
         "--verbose",
         "--display-pem-certificate",
         "--display-keytool-command");
    manageCertificates(
         "list-certificates",
         "--keystore", serverPKCS12KeyStorePath,
         "--keystore-password-file", correctPasswordFilePath,
         "--alias", serverCertificateAlias,
         "--verbose",
         "--display-pem-certificate",
         "--display-keytool-command");

    // Make sure that we can list the JVM's default cacerts file.
    manageCertificates(
         "list-certificates",
         "--use-jvm-default-trust-store",
         "--verbose");

    // Test the behavior when specifying a keystore path that is neither a JKS
    // nor a PKCS #12 keystore.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "list-certificates",
         "--keystore", invalidKeyStorePath);

    // Test the behavior with an empty password file.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "list-certificates",
         "--keystore", serverKeyStorePath,
         "--keystore-password-file", emptyPasswordFilePath);

    // Test the behavior with a password file that has multiple lines.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "list-certificates",
         "--keystore", serverKeyStorePath,
         "--keystore-password-file", multiLinePasswordFilePath);

    // Test the behavior with a password file that contains the wrong password.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "list-certificates",
         "--keystore", serverKeyStorePath,
         "--keystore-password-file", wrongPasswordFilePath);

    // Test the behavior with an alias that doesn't exist.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "list-certificates",
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", "missing");
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "list-certificates",
         "--keystore", serverPKCS12KeyStorePath,
         "--keystore-password", "password",
         "--alias", "missing");

    // Test the behavior with a certificate entry rather than a key entry.
    manageCertificates(
         "list-certificates",
         "--keystore", serverTrustStorePath,
         "--keystore-password", "password",
         "--verbose",
         "--display-pem-certificate",
         "--display-keytool-command");

    // Test the behavior with an empty keystore.
    manageCertificates(
         "list-certificates",
         "--keystore", emptyKeyStorePath,
         "--keystore-password", "password",
         "--verbose",
         "--display-pem-certificate",
         "--display-keytool-command");
    manageCertificates(
         "list-certificates",
         "--keystore", emptyPKCS12KeyStorePath,
         "--keystore-password", "password",
         "--verbose",
         "--display-pem-certificate",
         "--display-keytool-command");
  }



  /**
   * Provides test coverage for the export-certificate subcommand.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExportCertificate()
         throws Exception
  {
    // Test exporting a single PEM certificate for a JKS keystore with just a
    // certificate entry.
    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());
    manageCertificates(
         "export-certificate",
         "--keystore", serverTrustStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--output-format", "PEM",
         "--output-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");
    assertTrue(outputFile.exists());
    assertEquals(countPEMEntries(outputFile.getAbsolutePath()), 1);


    // Make sure that we can export a certificate from the JVM's default cacerts
    // file.
    final JVMDefaultTrustManager jvmDefaultTrustManager =
         JVMDefaultTrustManager.getInstance();
    final KeyStore ks = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream inputStream =
              new FileInputStream(jvmDefaultTrustManager.getCACertsFile()))
    {
      ks.load(inputStream, null);
    }
    final Enumeration<String> aliases = ks.aliases();
    while (aliases.hasMoreElements())
    {
      final String alias = aliases.nextElement();
      if (ks.isCertificateEntry(alias))
      {
        assertTrue(outputFile.delete());
        assertFalse(outputFile.exists());
        manageCertificates(
             "export-certificate",
             "--use-jvm-default-trust-store",
             "--alias", alias,
             "--output-format", "PEM",
             "--output-file", outputFile.getAbsolutePath(),
             "--display-keytool-command");
        assertTrue(outputFile.exists());
        assertEquals(countPEMEntries(outputFile.getAbsolutePath()), 1);
        break;
      }
    }


    // Test exporting a single DER certificate for a JKS keystore with just a
    // certificate entry.
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());
    manageCertificates(
         "export-certificate",
         "--keystore", serverTrustStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--output-format", "DER",
         "--output-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");
    assertTrue(outputFile.exists());
    assertEquals(countDEREntries(outputFile.getAbsolutePath()), 1);


    // Test exporting a single PEM certificate for a JKS keystore with a private
    // key entry.
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());
    manageCertificates(
         "export-certificate",
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--output-format", "PEM",
         "--output-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");
    assertTrue(outputFile.exists());
    assertEquals(countPEMEntries(outputFile.getAbsolutePath()), 1);


    // Test exporting a single DER certificate for a JKS keystore with a private
    // key entry.
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());
    manageCertificates(
         "export-certificate",
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--output-format", "DER",
         "--output-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");
    assertTrue(outputFile.exists());
    assertEquals(countDEREntries(outputFile.getAbsolutePath()), 1);


    // Test exporting a single PEM certificate for a PKCS #12 keystore with a
    // private key entry.
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());
    manageCertificates(
         "export-certificate",
         "--keystore", serverPKCS12KeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--output-format", "PEM",
         "--output-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");
    assertTrue(outputFile.exists());
    assertEquals(countPEMEntries(outputFile.getAbsolutePath()), 1);


    // Test exporting a single DER certificate for a PKCS #12 keystore with a
    // private key entry.
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());
    manageCertificates(
         "export-certificate",
         "--keystore", serverPKCS12KeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--output-format", "DER",
         "--output-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");
    assertTrue(outputFile.exists());
    assertEquals(countDEREntries(outputFile.getAbsolutePath()), 1);


    // Test exporting a certificate chain for a JKS keystore with just a
    // certificate entry.
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());
    manageCertificates(
         "export-certificate",
         "--keystore", serverTrustStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--export-certificate-chain",
         "--output-format", "PEM",
         "--output-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");
    assertTrue(outputFile.exists());
    assertEquals(countPEMEntries(outputFile.getAbsolutePath()), 3);


    // Test exporting a PEM certificate chain for a JKS keystore with just
    // certificate entries.
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());
    manageCertificates(
         "export-certificate",
         "--keystore", serverTrustStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--export-certificate-chain",
         "--output-format", "PEM",
         "--output-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");
    assertTrue(outputFile.exists());
    assertEquals(countPEMEntries(outputFile.getAbsolutePath()), 3);


    // Test exporting a DER certificate chain for a JKS keystore with just
    // certificate entries.
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());
    manageCertificates(
         "export-certificate",
         "--keystore", serverTrustStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--export-certificate-chain",
         "--output-format", "DER",
         "--output-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");
    assertTrue(outputFile.exists());
    assertEquals(countDEREntries(outputFile.getAbsolutePath()), 3);


    // Test exporting a PEM certificate chain for a JKS keystore with a private
    // key entry.
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());
    manageCertificates(
         "export-certificate",
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--export-certificate-chain",
         "--output-format", "PEM",
         "--output-file", outputFile.getAbsolutePath(),
         "--separate-file-per-certificate",
         "--display-keytool-command");
    assertFalse(outputFile.exists());
    assertTrue(new File(outputFile.getAbsolutePath() + ".1").exists());
    assertTrue(new File(outputFile.getAbsolutePath() + ".2").exists());
    assertTrue(new File(outputFile.getAbsolutePath() + ".3").exists());


    // Test exporting a DER certificate chain for a JKS keystore with a private
    // key entry.
    assertTrue(new File(outputFile.getAbsolutePath() + ".1").delete());
    assertTrue(new File(outputFile.getAbsolutePath() + ".2").delete());
    assertTrue(new File(outputFile.getAbsolutePath() + ".3").delete());
    manageCertificates(
         "export-certificate",
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--export-certificate-chain",
         "--output-format", "DER",
         "--output-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");
    assertTrue(outputFile.exists());
    assertEquals(countDEREntries(outputFile.getAbsolutePath()), 3);


    // Test exporting a PEM certificate chain for a PKCS #12 keystore with a
    // private key entry.
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());
    manageCertificates(
         "export-certificate",
         "--keystore", serverPKCS12KeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--export-certificate-chain",
         "--output-format", "PEM",
         "--output-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");
    assertTrue(outputFile.exists());
    assertEquals(countPEMEntries(outputFile.getAbsolutePath()), 3);


    // Test exporting a DER certificate chain for a PKCS #12 keystore with a
    // private key entry.
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());
    manageCertificates(
         "export-certificate",
         "--keystore", serverPKCS12KeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--export-certificate-chain",
         "--output-format", "DER",
         "--output-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");
    assertTrue(outputFile.exists());
    assertEquals(countDEREntries(outputFile.getAbsolutePath()), 3);


    // Test exporting a chain from a JKS keystore without a complete chain.
    final File ksPath = createTempFile();
    assertTrue(ksPath.exists());
    assertTrue(ksPath.delete());
    assertFalse(ksPath.exists());
    manageCertificates(
         "import-certificate",
         "--certificate-file", serverCertificatePath,
         "--keystore", ksPath.getAbsolutePath(),
         "--keystore-type", "JKS",
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");
    assertTrue(ksPath.exists());

    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());
    manageCertificates(ResultCode.NO_SUCH_OBJECT, null,
         "export-certificate",
         "--keystore", ksPath.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--export-certificate-chain",
         "--output-format", "PEM",
         "--output-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");
    assertTrue(outputFile.exists());
    assertEquals(countPEMEntries(outputFile.getAbsolutePath()), 1);


    // Test exporting a nonexistent certificate.
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "export-certificate",
         "--keystore", serverTrustStorePath,
         "--keystore-password", "password",
         "--alias", "nonexistent",
         "--export-certificate-chain",
         "--output-format", "PEM",
         "--output-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");
    assertFalse(outputFile.exists());


    // Test exporting from a malformed keystore.
    final File malformedKSPath = createTempFile("this is not a valid keystore");
    assertTrue(malformedKSPath.exists());

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "export-certificate",
         "--keystore", malformedKSPath.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--export-certificate-chain",
         "--output-format", "PEM",
         "--output-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");
    assertFalse(outputFile.exists());


    // Test exporting PEM without an output file.
    manageCertificates(
         "export-certificate",
         "--keystore", serverTrustStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--output-format", "PEM",
         "--display-keytool-command");


    // Test exporting DER without an output file.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "export-certificate",
         "--keystore", serverTrustStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--output-format", "DER",
         "--display-keytool-command");


    // Test exporting a certificate when reading a password from a file with
    // multiple lines.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "export-certificate",
         "--keystore", serverTrustStorePath,
         "--keystore-password-file", multiLinePasswordFilePath,
         "--alias", serverCertificateAlias,
         "--display-keytool-command");


    // Test exporting a certificate with the wrong password.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "export-certificate",
         "--keystore", serverTrustStorePath,
         "--keystore-password", "wrong",
         "--alias", serverCertificateAlias,
         "--display-keytool-command");
  }



  /**
   * Provides test coverage for the export-private-key subcommand.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExportPrivateKey()
         throws Exception
  {
    // Test exporting a private key to a PEM file from a self-signed certificate
    // in a JKS keystore.
    final File outputFile = createTempFile();
    assertTrue(outputFile.exists());
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());
    manageCertificates(
         "export-private-key",
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--output-format", "PEM",
         "--output-file", outputFile.getAbsolutePath());
    assertTrue(outputFile.exists());

    assertEquals(countPEMEntries(outputFile.getAbsolutePath()), 1);


    // Test exporting a private key to a DER file from a self-signed certificate
    // in a JKS keystore.
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());
    manageCertificates(
         "export-private-key",
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--output-format", "DER",
         "--output-file", outputFile.getAbsolutePath());
    assertTrue(outputFile.exists());

    assertEquals(countDEREntries(outputFile.getAbsolutePath()), 1);


    // Test exporting a private key to a PEM file from an issuer-signed
    // certificate in a JKS keystore.
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());
    manageCertificates(
         "export-private-key",
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--output-format", "PEM",
         "--output-file", outputFile.getAbsolutePath());
    assertTrue(outputFile.exists());

    assertEquals(countPEMEntries(outputFile.getAbsolutePath()), 1);


    // Test exporting a private key to a DER file from an issuer-signed
    // certificate in a JKS keystore.
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());
    manageCertificates(
         "export-private-key",
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--output-format", "DER",
         "--output-file", outputFile.getAbsolutePath());
    assertTrue(outputFile.exists());

    assertEquals(countDEREntries(outputFile.getAbsolutePath()), 1);


    // Test exporting a private key to a PEM file from an issuer-signed
    // certificate in a PKCS #12 keystore.
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());
    manageCertificates(
         "export-private-key",
         "--keystore", serverPKCS12KeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--output-format", "PEM",
         "--output-file", outputFile.getAbsolutePath());
    assertTrue(outputFile.exists());

    assertEquals(countPEMEntries(outputFile.getAbsolutePath()), 1);


    // Test exporting a private key to PEM without specifying an output file.
    // certificate in a PKCS #12 keystore.
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());
    manageCertificates(
         "export-private-key",
         "--keystore", serverPKCS12KeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--output-format", "PEM");
    assertFalse(outputFile.exists());


    // Test exporting a private key to DER without specifying an output file.
    // certificate in a PKCS #12 keystore.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "export-private-key",
         "--keystore", serverPKCS12KeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--output-format", "DER");


    // Test exporting a private key from an alias that does not exist.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "export-private-key",
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", "missing",
         "--output-format", "PEM",
         "--output-file", outputFile.getAbsolutePath());


    // Test exporting a private key from a keystore that doesn't have a private
    // key for that alias.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "export-private-key",
         "--keystore", serverTrustStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--output-format", "PEM",
         "--output-file", outputFile.getAbsolutePath());


    // Test exporting a private key with a wrong keystore password.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "export-private-key",
         "--keystore", serverKeyStorePath,
         "--keystore-password", "wrong",
         "--alias", serverCertificateAlias,
         "--output-format", "PEM",
         "--output-file", outputFile.getAbsolutePath());


    // Test exporting a private key with a keystore password read from a file
    // with multiple lines.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "export-private-key",
         "--keystore", serverKeyStorePath,
         "--keystore-password-file", multiLinePasswordFilePath,
         "--alias", serverCertificateAlias,
         "--output-format", "PEM",
         "--output-file", outputFile.getAbsolutePath());


    // Test exporting a private key with a wrong private key password.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "export-private-key",
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--private-key-password", "wrong",
         "--alias", serverCertificateAlias,
         "--output-format", "PEM",
         "--output-file", outputFile.getAbsolutePath());


    // Test exporting a private key with a private key password read from a file
    // with multiple lines.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "export-private-key",
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--private-key-password-file", multiLinePasswordFilePath,
         "--alias", serverCertificateAlias,
         "--output-format", "PEM",
         "--output-file", outputFile.getAbsolutePath());


    // Test exporting a private key from a malformed keystore.
    final File malformedKSFile = createTempFile("not a valid keystore");
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "export-private-key",
         "--keystore", malformedKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--output-format", "PEM",
         "--output-file", outputFile.getAbsolutePath());
  }



  /**
   * Provides test coverage for the import-certificate subcommand.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testImportCertificate()
         throws Exception
  {
    // Import a single certificate with no private key into a JKS keystore
    // that doesn't already exist.  Do not prompt about whether to trust the
    // certificate.
    File ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificatePath,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    KeyStore keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf(serverCertificateAlias));


    // Import a certificate with no private key into a JKS keystore that
    // already exists.  Do not prompt about whether to trust the certificate.
    manageCertificates(
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--certificate-file", rootCACertificatePath,
         "--no-prompt",
         "--display-keytool-command");

    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(serverCertificateAlias, rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf(serverCertificateAlias, rootCACertificateAlias));


    // Import a certificate chain obtained from a single file into a JKS
    // keystore that doesn't already exist.  Do not prompt about whether to
    // trust the certificate.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificateChainPath,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(serverCertificateAlias,
              serverCertificateAlias + "-issuer-1",
              serverCertificateAlias + "-issuer-2"));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf(serverCertificateAlias,
              serverCertificateAlias + "-issuer-1",
              serverCertificateAlias + "-issuer-2"));


    // Import a certificate chain obtained from multiple files into a JKS
    // keystore that doesn't already exist.  Do not prompt about whether to
    // trust the certificate.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", intermediateCACertificateAlias,
         "--certificate-file", intermediateCACertificatePath,
         "--certificate-file", rootCACertificatePath,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(intermediateCACertificateAlias,
              intermediateCACertificateAlias + "-issuer"));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf(intermediateCACertificateAlias,
              intermediateCACertificateAlias + "-issuer"));


    // Import a single certificate and its private key into a JKS keystore
    // that doesn't already exist.  Do not prompt about whether to trust the
    // certificate.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--certificate-file", rootCACertificatePath,
         "--private-key-file", rootCAKeyPath,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());


    // Import a single certificate and its private key into a JKS keystore
    // that doesn't already exist.  Do not prompt about whether to trust the
    // certificate.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--certificate-file", rootCACertificatePath,
         "--private-key-file", rootCAKeyPath,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());


    // Import a single certificate and a raw RSA private key (not in a PKCS #8
    // envelope) into a JKS keystore that doesn't already exist.  Do not prompt
    // about whether to trust the certificate.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    final StringBuilder pkcs8Base64Buffer = new StringBuilder();
    try (BufferedReader reader =
              new BufferedReader(new FileReader(rootCAKeyPath)))
    {
      while (true)
      {
        final String line = reader.readLine();
        if (line == null)
        {
          fail("Found the end of the file before the end footer");
        }
        else if (line.startsWith("-----BEGIN"))
        {
          assertEquals(pkcs8Base64Buffer.length(), 0);
          continue;
        }
        else if (line.startsWith("-----END"))
        {
          assertTrue(pkcs8Base64Buffer.length() > 0);
          break;
        }
        else
        {
          pkcs8Base64Buffer.append(line);
        }
      }
    }

    final byte[] pkcs8PrivateKeyBytes =
         Base64.decode(pkcs8Base64Buffer.toString());
    final ASN1Sequence pkcs8PrivateKeySequence =
         ASN1Sequence.decodeAsSequence(pkcs8PrivateKeyBytes);

    final byte[] rsaPrivateKey =
         pkcs8PrivateKeySequence.elements()[2].getValue();
    final File rsaPrivateKeyFile = createTempFile();
    assertTrue(rsaPrivateKeyFile.delete());
    try (PrintWriter writer = new PrintWriter(rsaPrivateKeyFile))
    {
      writer.println("-----BEGIN RSA PRIVATE KEY-----");
      writer.println(Base64.encode(rsaPrivateKey));
      writer.println("-----END RSA PRIVATE KEY-----");
    }

    manageCertificates(
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--certificate-file", rootCACertificatePath,
         "--private-key-file", rsaPrivateKeyFile.getAbsolutePath(),
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());


    // Import a certificate chain and the corresponding private key into a JKS
    // keystore that doesn't already exist.  Do not prompt about whether to
    // trust the certificate.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificateChainPath,
         "--private-key-file", serverKeyPath,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());


    // Import a single certificate and its private key into a PKCS #12 keystore
    // that doesn't already exist.  Do not prompt about whether to trust the
    // certificate.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "PKCS12",
         "--alias", rootCACertificateAlias,
         "--certificate-file", rootCACertificatePath,
         "--private-key-file", rootCAKeyPath,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "PKCS12");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());


    // Import a certificate chain and the corresponding private key into a
    // PKCS #12 keystore that doesn't already exist.  Do not prompt about
    // whether to trust the certificate.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "PKCS12",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificateChainPath,
         "--private-key-file", serverKeyPath,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "PKCS12");
    assertEquals(getAliases(keystore, true, true),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());


    // Import a certificate without a private key into a JKS keystore file
    // that doesn't already exist.  Allow the tool to prompt for the password,
    // and accept the prompt after two invalid inputs.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(ResultCode.SUCCESS, "wrong1\nwrong2\r\nyes\n",
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificatePath,
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf(serverCertificateAlias));


    // Try to import a certificate without a private key into a JKS keystore
    // file that doesn't already exist.  Allow the tool to prompt for the
    // password, but do not accept that prompt.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(ResultCode.USER_CANCELED, "no",
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificatePath,
         "--display-keytool-command");

    assertFalse(ksFile.exists());


    // Try to import a certificate without a private key into a JKS keystore
    // file that doesn't already exist.  Allow the tool to prompt for the
    // password, but do not supply the input necessary to answer that prompt.
    manageCertificates(ResultCode.LOCAL_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificatePath,
         "--display-keytool-command");

    assertFalse(ksFile.exists());


    // Import a certificate with a private key into a JKS keystore file
    // that doesn't already exist.  Allow the tool to prompt for the password,
    // and accept the prompt.
    manageCertificates(ResultCode.SUCCESS, "y\r\n",
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificateChainPath,
         "--private-key-file", serverKeyPath,
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());


    // Try to import a certificate with a private key into a JKS keystore
    // file that doesn't already exist.  Allow the tool to prompt for the
    // password, but do not accept that prompt.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(ResultCode.USER_CANCELED, "n\n",
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificateChainPath,
         "--private-key-file", serverKeyPath,
         "--display-keytool-command");

    assertFalse(ksFile.exists());


    // Import a certificate without a private key into a JKS keystore file
    // that doesn't already exist.  Allow the tool to prompt for the password,
    // but don't provide any input so that an error will occur when trying to
    // read the data.
    manageCertificates(ResultCode.LOCAL_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificatePath,
         "--display-keytool-command");


    // Test importing into a keystore file that exists but is malformed.
    final File malformedKS = createTempFile("not a valid keystore");
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", malformedKS.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificatePath,
         "--no-prompt",
         "--display-keytool-command");


    // Test importing into an existing JKS keystore file but with the wrong
    // password.
    ksFile = copyFile(emptyKeyStorePath);
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "wrong",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificatePath,
         "--no-prompt",
         "--display-keytool-command");


    // Test importing into an existing JKS keystore file but with a password
    // read from a file with multiple lines.
    ksFile = copyFile(emptyKeyStorePath);
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password-file", multiLinePasswordFilePath,
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificatePath,
         "--no-prompt",
         "--display-keytool-command");


    // Test importing a certificate into a JKS keystore using an alias that
    // already has a certificate.
    ksFile = copyFile(serverTrustStorePath);
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificatePath,
         "--no-prompt",
         "--display-keytool-command");


    // Test importing a certificate chain and private key into a JKS keystore
    // using an alias that already has a certificate.
    ksFile = copyFile(serverTrustStorePath);
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificateChainPath,
         "--private-key-file", serverKeyPath,
         "--no-prompt",
         "--display-keytool-command");


    // Test importing a certificate into a JKS keystore using an alias that
    // already has a key entry, but that key entry uses a different key than the
    // certificate we're importing.
    ksFile = copyFile(rootCAKeyStorePath);
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--certificate-file", serverCertificateChainPath,
         "--no-prompt",
         "--display-keytool-command");


    // Test importing a certificate into a JKS keystore using an alias that
    // already has a key entry, and that key entry matches the key used to
    // generate the certificate.
    manageCertificates(
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--certificate-file", rootCACertificatePath,
         "--no-prompt",
         "--display-keytool-command");


    // Test importing a certificate into a JKS keystore using an alias that
    // already has a key entry, and that key entry matches the key used to
    // generate the certificate.  Prompt the user to confirm the import, and
    // accept the import after a failed attempt.
    manageCertificates(ResultCode.SUCCESS, "wrong\nyes\n",
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--certificate-file", rootCACertificatePath,
         "--display-keytool-command");


    // Test importing a certificate into a JKS keystore using an alias that
    // already has a key entry, and that key entry matches the key used to
    // generate the certificate.  Prompt the user to confirm the import, but
    // reject the confirmation.
    manageCertificates(ResultCode.USER_CANCELED, "no\n",
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--certificate-file", rootCACertificatePath,
         "--display-keytool-command");


    // Test importing a certificate into a JKS keystore using an alias that
    // already has a key entry, and that key entry matches the key used to
    // generate the certificate.  Prompt the user to confirm the import, don't
    // supply the input needed to accept the confirmation
    manageCertificates(ResultCode.LOCAL_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--certificate-file", rootCACertificatePath,
         "--display-keytool-command");


    // Test importing a certificate into a JKS keystore that has an existing key
    // entry, but provide the wrong private key password for that entry.
    manageCertificates(ResultCode.LOCAL_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--private-key-password", "wrong",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--certificate-file", rootCACertificatePath,
         "--no-prompt",
         "--display-keytool-command");


    // Test importing a certificate chain and private key into a JKS keystore
    // that already has a key in that alias.
    ksFile = copyFile(rootCAKeyStorePath);
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--certificate-file", serverCertificateChainPath,
         "--private-key-file", serverKeyPath,
         "--no-prompt",
         "--display-keytool-command");


    // Test importing a certificate into a JKS keystore that has an existing key
    // entry, but with a private key password supplied in an empty file.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--private-key-password-file", emptyPasswordFilePath,
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--certificate-file", rootCACertificatePath,
         "--no-prompt",
         "--display-keytool-command");


    // Test importing a certificate into a JKS keystore that has an existing key
    // entry, but with a private key password supplied in a file with multiple
    // lines.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--private-key-password-file", multiLinePasswordFilePath,
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--certificate-file", rootCACertificatePath,
         "--no-prompt",
         "--display-keytool-command");


    // Test importing a certificate contained in a malformed PEM file.
    ksFile = copyFile(emptyKeyStorePath);
    File malformedPEMFile = createTempFile(
         "-----BEGIN CERTIFICATE-----",
         "This file has invalid characters, and is missing the end footer.");
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", malformedPEMFile.getAbsolutePath(),
         "--no-prompt",
         "--display-keytool-command");


    // Test importing a certificate contained in a malformed DER file.
    final File malformedDERFile = createTempFile();
    assertTrue(malformedDERFile.delete());
    try (FileOutputStream outputStream = new FileOutputStream(malformedDERFile))
    {
      new ASN1Sequence(new ASN1OctetString(
           "Not a valid certificate")).writeTo(outputStream);
    }
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", malformedDERFile.getAbsolutePath(),
         "--no-prompt",
         "--display-keytool-command");


    // Test importing a valid certificate chain but a malformed private key file
    // contained in a malformed PEM file.
    malformedPEMFile = createTempFile(
         "-----BEGIN PRIVATE KEY-----",
         "This file has invalid characters, and is missing the end footer.");
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificateChainPath,
         "--private-key-file", malformedPEMFile.getAbsolutePath(),
         "--no-prompt",
         "--display-keytool-command");


    // Test importing a valid certificate chain but a malformed private key file
    // contained in a malformed DER file.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificateChainPath,
         "--private-key-file", malformedDERFile.getAbsolutePath(),
         "--no-prompt",
         "--display-keytool-command");


    // Test importing an incomplete certificate chain that does not include the
    // root certificate.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificatePath,
         "--certificate-file", intermediateCACertificatePath,
         "--private-key-file", serverKeyPath,
         "--no-prompt",
         "--display-keytool-command");


    // Test importing an incomplete certificate chain that does not include an
    // intermediate certificate.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificatePath,
         "--certificate-file", rootCACertificatePath,
         "--private-key-file", serverKeyPath,
         "--no-prompt",
         "--display-keytool-command");


    // Test importing a certificate chain that has a self-signed certificate at
    // the head of the chain, and then has other certificates after that.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", rootCACertificatePath,
         "--certificate-file", intermediateCACertificatePath,
         "--certificate-file", serverCertificatePath,
         "--private-key-file", rootCAKeyPath,
         "--no-prompt",
         "--display-keytool-command");


    // Test importing an empty certificate file.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", emptyPasswordFilePath,
         "--no-prompt",
         "--display-keytool-command");
  }



  /**
   * Provides test coverage for the delete-certificate subcommand.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteCertificate()
         throws Exception
  {
    // Test deleting an alias that exists in a JKS keystore and has a
    // certificate entry.  Don't let the tool prompt about performing the
    // delete.
    File ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", rootCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-type", "JKS",
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    KeyStore keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf(rootCACertificateAlias));

    manageCertificates(
         "delete-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         Collections.<String>emptySet());


    // Test deleting an alias that exists in a JKS keystore and has a private
    // key entry.  Don't let the tool prompt about performing the delete.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", rootCACertificatePath,
         "--private-key-file", rootCAKeyPath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-type", "JKS",
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());

    manageCertificates(
         "delete-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         Collections.<String>emptySet());


    // Test deleting an alias that exists in a PKCS #12 keystore and has a
    // private key entry.  Don't let the tool prompt about performing the
    // delete.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", rootCACertificatePath,
         "--private-key-file", rootCAKeyPath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-type", "PKCS12",
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "PKCS12");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());

    manageCertificates(
         "delete-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "PKCS12");
    assertEquals(getAliases(keystore, true, true),
         Collections.<String>emptySet());


    // Test deleting an entry that exists and has a private key.  Let the tool
    // prompt to confirm the delete.  Don't accept the prompt on the first
    // attempt.  Then try again with invalid input and no more data on the
    // stream.  Finally try with the right password.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", rootCACertificatePath,
         "--private-key-file", rootCAKeyPath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-type", "JKS",
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());

    manageCertificates(ResultCode.USER_CANCELED, "no\n",
         "delete-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());

    manageCertificates(ResultCode.LOCAL_ERROR, "invalid input\n",
         "delete-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());

    manageCertificates(ResultCode.SUCCESS, "yes\n",
         "delete-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         Collections.<String>emptySet());


    // Test deleting an entry that exists and does not have a private key.  Let
    // the tool prompt to confirm the delete.  Don't accept the prompt on the
    // first attempt.  Then try again with invalid input and no more data on the
    // stream.  Finally try with the right password.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", rootCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-type", "JKS",
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf(rootCACertificateAlias));

    manageCertificates(ResultCode.USER_CANCELED, "no\n",
         "delete-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf(rootCACertificateAlias));

    manageCertificates(ResultCode.LOCAL_ERROR, "invalid input\n",
         "delete-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf(rootCACertificateAlias));

    manageCertificates(ResultCode.SUCCESS, "yes\n",
         "delete-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         Collections.<String>emptySet());


    // Test trying to delete an entry that does not exist.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", rootCACertificatePath,
         "--private-key-file", rootCAKeyPath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-type", "JKS",
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "delete-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());


    // Test trying to delete an entry that exists, but supply the wrong keystore
    // password.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "delete-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "wrong",
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());


    // Test trying to delete an entry that exists, but supply the keystore
    // password in a file with multiple lines.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "delete-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password-file", multiLinePasswordFilePath,
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());


    // Test trying to delete an entry from a malformed keystore file.
    ksFile = createTempFile("malformed keystore");
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "delete-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password-file", multiLinePasswordFilePath,
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");
  }



  /**
   * Provides test coverage for the generate-self-signed-certificate subcommand.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateSelfSignedCertificate()
         throws Exception
  {
    // Tests with a minimal set of arguments for a new certificate using a
    // JKS keystore that doesn't already exist.
    File ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US");

    assertTrue(ksFile.exists());
    KeyStore keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true), setOf("server-cert"));
    assertEquals(getAliases(keystore, true, false), setOf("server-cert"));
    assertEquals(getAliases(keystore, false, true),
         Collections.emptySet());

    X509Certificate[] chain = getCertificateChain(keystore, "server-cert");
    assertNotNull(chain);
    assertEquals(chain.length, 1);
    assertEquals(chain[0].getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Tests with a minimal set of arguments for a replacement certificate in a
    // JKS keystore.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--replace-existing-certificate");

    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true), setOf("server-cert"));
    assertEquals(getAliases(keystore, true, false), setOf("server-cert"));
    assertEquals(getAliases(keystore, false, true),
         Collections.emptySet());

    chain = getCertificateChain(keystore, "server-cert");
    assertNotNull(chain);
    assertEquals(chain.length, 1);
    assertEquals(chain[0].getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Tests with a minimal set of arguments for a new certificate using a
    // PKCS #12 keystore that doesn't already exist.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "PKCS12",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "PKCS12");
    assertEquals(getAliases(keystore, true, true), setOf("server-cert"));
    assertEquals(getAliases(keystore, true, false), setOf("server-cert"));
    assertEquals(getAliases(keystore, false, true),
         Collections.emptySet());

    chain = getCertificateChain(keystore, "server-cert");
    assertNotNull(chain);
    assertEquals(chain.length, 1);
    assertEquals(chain[0].getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Tests with a minimal set of arguments for a replacement certificate in a
    // PKCS #12 keystore.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--replace-existing-certificate");

    keystore = getKeystore(ksFile.getAbsolutePath(), "PKCS12");
    assertEquals(getAliases(keystore, true, true), setOf("server-cert"));
    assertEquals(getAliases(keystore, true, false), setOf("server-cert"));
    assertEquals(getAliases(keystore, false, true),
         Collections.emptySet());

    chain = getCertificateChain(keystore, "server-cert");
    assertNotNull(chain);
    assertEquals(chain.length, 1);
    assertEquals(chain[0].getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Tests with a full set of arguments for a new certificate using a
    // keystore that doesn't already exist.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--validity-start-time", "20170101000000",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-dns", "ldap.example.com",
         "--subject-alternative-name-ip-address", "127.0.0.1",
         "--subject-alternative-name-email-address", "test@example.com",
         "--subject-alternative-name-uri", "https://www.example.com/",
         "--subject-alternative-name-oid", "1.2.3.4",
         "--basic-constraints-is-ca", "true",
         "--basic-constraints-maximum-path-length", "5",
         "--key-usage", "digital-signature",
         "--key-usage", "non-repudiation",
         "--key-usage", "key-encipherment",
         "--key-usage", "data-encipherment",
         "--key-usage", "key-agreement",
         "--key-usage", "key-cert-sign",
         "--key-usage", "crl-sign",
         "--key-usage", "encipher-only",
         "--key-usage", "decipher-only",
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--extended-key-usage", "code-signing",
         "--extended-key-usage", "email-protection",
         "--extended-key-usage", "time-stamping",
         "--extended-key-usage", "ocsp-signing",
         "--extended-key-usage", "1.2.3.5",
         "--extension", "1.2.3.6:false:1234567890",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true), setOf("server-cert"));
    assertEquals(getAliases(keystore, true, false), setOf("server-cert"));
    assertEquals(getAliases(keystore, false, true),
         Collections.emptySet());

    chain = getCertificateChain(keystore, "server-cert");
    assertNotNull(chain);
    assertEquals(chain.length, 1);
    assertEquals(chain[0].getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));

    boolean hasBasicConstraintsExtension = false;
    boolean hasExtendedKeyUsageConstraintsExtension = false;
    boolean hasGenericExtension = false;
    boolean hasKeyUsageExtension = false;
    boolean hasSubjectAlternativeNameExtension = false;
    boolean hasSubjectKeyIdentifierExtension = false;
    for (final X509CertificateExtension extension : chain[0].getExtensions())
    {
      if (extension instanceof BasicConstraintsExtension)
      {
        hasBasicConstraintsExtension = true;

        final BasicConstraintsExtension e =
             (BasicConstraintsExtension) extension;
        assertTrue(e.isCA());
        assertNotNull(e.getPathLengthConstraint());
        assertEquals(e.getPathLengthConstraint().intValue(), 5);
      }
      else if (extension instanceof ExtendedKeyUsageExtension)
      {
        hasExtendedKeyUsageConstraintsExtension = true;

        final ExtendedKeyUsageExtension e =
             (ExtendedKeyUsageExtension) extension;
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.TLS_SERVER_AUTHENTICATION.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.TLS_CLIENT_AUTHENTICATION.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.CODE_SIGNING.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.EMAIL_PROTECTION.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.TIME_STAMPING.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.OCSP_SIGNING.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(new OID("1.2.3.5")));
      }
      else if (extension instanceof KeyUsageExtension)
      {
        hasKeyUsageExtension = true;

        final KeyUsageExtension e = (KeyUsageExtension) extension;
        assertTrue(e.isDigitalSignatureBitSet());
        assertTrue(e.isNonRepudiationBitSet());
        assertTrue(e.isKeyEnciphermentBitSet());
        assertTrue(e.isDataEnciphermentBitSet());
        assertTrue(e.isKeyAgreementBitSet());
        assertTrue(e.isKeyCertSignBitSet());
        assertTrue(e.isCRLSignBitSet());
        assertTrue(e.isEncipherOnlyBitSet());
        assertTrue(e.isDecipherOnlyBitSet());
      }
      else if (extension instanceof SubjectAlternativeNameExtension)
      {
        hasSubjectAlternativeNameExtension = true;

        final SubjectAlternativeNameExtension e =
             (SubjectAlternativeNameExtension) extension;
        assertEquals(e.getDNSNames(),
             Collections.singletonList("ldap.example.com"));
        assertEquals(e.getIPAddresses(),
             Collections.singletonList(InetAddress.getByName("127.0.0.1")));
        assertEquals(e.getRFC822Names(),
             Collections.singletonList("test@example.com"));
        assertEquals(e.getUniformResourceIdentifiers(),
             Collections.singletonList("https://www.example.com/"));
        assertEquals(e.getRegisteredIDs(),
             Collections.singletonList(new OID("1.2.3.4")));
      }
      else if (extension instanceof SubjectKeyIdentifierExtension)
      {
        hasSubjectKeyIdentifierExtension = true;
      }
      else if (extension.getOID().equals(new OID("1.2.3.6")))
      {
        hasGenericExtension = true;
        assertFalse(extension.isCritical());
        assertNotNull(extension.getValue());
        assertEquals(extension.getValue(),
             StaticUtils.byteArray(0x12, 0x34, 0x56, 0x78, 0x90));
      }
    }

    assertTrue(hasBasicConstraintsExtension);
    assertTrue(hasExtendedKeyUsageConstraintsExtension);
    assertTrue(hasGenericExtension);
    assertTrue(hasKeyUsageExtension);
    assertTrue(hasSubjectAlternativeNameExtension);
    assertTrue(hasSubjectKeyIdentifierExtension);

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Tests with a full set of arguments intended to replace the existing
    // certificate, except that we'll inherit the existing extensions rather
    // than explicitly specifying them.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", "server-cert",
         "--replace-existing-certificate",
         "--days-valid", "7300",
         "--validity-start-time", "20170101000000",
         "--inherit-extensions",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true), setOf("server-cert"));
    assertEquals(getAliases(keystore, true, false), setOf("server-cert"));
    assertEquals(getAliases(keystore, false, true),
         Collections.emptySet());

    chain = getCertificateChain(keystore, "server-cert");
    assertNotNull(chain);
    assertEquals(chain.length, 1);
    assertEquals(chain[0].getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));

    hasBasicConstraintsExtension = false;
    hasExtendedKeyUsageConstraintsExtension = false;
    hasGenericExtension = false;
    hasKeyUsageExtension = false;
    hasSubjectAlternativeNameExtension = false;
    hasSubjectKeyIdentifierExtension = false;
    for (final X509CertificateExtension extension : chain[0].getExtensions())
    {
      if (extension instanceof BasicConstraintsExtension)
      {
        hasBasicConstraintsExtension = true;

        final BasicConstraintsExtension e =
             (BasicConstraintsExtension) extension;
        assertTrue(e.isCA());
        assertNotNull(e.getPathLengthConstraint());
        assertEquals(e.getPathLengthConstraint().intValue(), 5);
      }
      else if (extension instanceof ExtendedKeyUsageExtension)
      {
        hasExtendedKeyUsageConstraintsExtension = true;

        final ExtendedKeyUsageExtension e =
             (ExtendedKeyUsageExtension) extension;
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.TLS_SERVER_AUTHENTICATION.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.TLS_CLIENT_AUTHENTICATION.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.CODE_SIGNING.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.EMAIL_PROTECTION.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.TIME_STAMPING.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.OCSP_SIGNING.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(new OID("1.2.3.5")));
      }
      else if (extension instanceof KeyUsageExtension)
      {
        hasKeyUsageExtension = true;

        final KeyUsageExtension e = (KeyUsageExtension) extension;
        assertTrue(e.isDigitalSignatureBitSet());
        assertTrue(e.isNonRepudiationBitSet());
        assertTrue(e.isKeyEnciphermentBitSet());
        assertTrue(e.isDataEnciphermentBitSet());
        assertTrue(e.isKeyAgreementBitSet());
        assertTrue(e.isKeyCertSignBitSet());
        assertTrue(e.isCRLSignBitSet());
        assertTrue(e.isEncipherOnlyBitSet());
        assertTrue(e.isDecipherOnlyBitSet());
      }
      else if (extension instanceof SubjectAlternativeNameExtension)
      {
        hasSubjectAlternativeNameExtension = true;

        final SubjectAlternativeNameExtension e =
             (SubjectAlternativeNameExtension) extension;
        assertEquals(e.getDNSNames(),
             Collections.singletonList("ldap.example.com"));
        assertEquals(e.getIPAddresses(),
             Collections.singletonList(InetAddress.getByName("127.0.0.1")));
        assertEquals(e.getRFC822Names(),
             Collections.singletonList("test@example.com"));
        assertEquals(e.getUniformResourceIdentifiers(),
             Collections.singletonList("https://www.example.com/"));
        assertEquals(e.getRegisteredIDs(),
             Collections.singletonList(new OID("1.2.3.4")));
      }
      else if (extension instanceof SubjectKeyIdentifierExtension)
      {
        hasSubjectKeyIdentifierExtension = true;
      }
      else if (extension.getOID().equals(new OID("1.2.3.6")))
      {
        hasGenericExtension = true;
        assertFalse(extension.isCritical());
        assertNotNull(extension.getValue());
        assertEquals(extension.getValue(),
             StaticUtils.byteArray(0x12, 0x34, 0x56, 0x78, 0x90));
      }
    }

    assertTrue(hasBasicConstraintsExtension);
    assertTrue(hasExtendedKeyUsageConstraintsExtension);
    assertTrue(hasGenericExtension);
    assertTrue(hasKeyUsageExtension);
    assertTrue(hasSubjectAlternativeNameExtension);
    assertTrue(hasSubjectKeyIdentifierExtension);

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Test the behavior when trying to replace an existing certificate while
    // trying to inherit extensions but also specifying extensions on the
    // command line.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", "server-cert",
         "--replace-existing-certificate",
         "--days-valid", "7300",
         "--validity-start-time", "20170101000000",
         "--inherit-extensions",
         "--subject-alternative-name-dns", "ds.example.com",
         "--subject-alternative-name-ip-address", "::1",
         "--subject-alternative-name-email-address", "other@example.com",
         "--subject-alternative-name-uri", "https://www2.example.com/",
         "--subject-alternative-name-oid", "1.2.3.5",
         "--basic-constraints-is-ca", "false",
         "--key-usage", "digital-signature",
         "--extended-key-usage", "server-auth",
         "--extension", "1.2.3.7:true:0987654321",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true), setOf("server-cert"));
    assertEquals(getAliases(keystore, true, false), setOf("server-cert"));
    assertEquals(getAliases(keystore, false, true),
         Collections.emptySet());

    chain = getCertificateChain(keystore, "server-cert");
    assertNotNull(chain);
    assertEquals(chain.length, 1);
    assertEquals(chain[0].getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));

    hasBasicConstraintsExtension = false;
    hasExtendedKeyUsageConstraintsExtension = false;
    hasKeyUsageExtension = false;
    hasSubjectAlternativeNameExtension = false;
    hasSubjectKeyIdentifierExtension = false;
    boolean hasOriginalGenericExtension = false;
    boolean hasNewGenericExtension = false;
    for (final X509CertificateExtension extension : chain[0].getExtensions())
    {
      if (extension instanceof BasicConstraintsExtension)
      {
        hasBasicConstraintsExtension = true;

        final BasicConstraintsExtension e =
             (BasicConstraintsExtension) extension;
        assertFalse(e.isCA());
        assertNull(e.getPathLengthConstraint());
      }
      else if (extension instanceof ExtendedKeyUsageExtension)
      {
        hasExtendedKeyUsageConstraintsExtension = true;

        final ExtendedKeyUsageExtension e =
             (ExtendedKeyUsageExtension) extension;
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.TLS_SERVER_AUTHENTICATION.getOID()));
        assertFalse(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.TLS_CLIENT_AUTHENTICATION.getOID()));
        assertFalse(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.CODE_SIGNING.getOID()));
        assertFalse(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.EMAIL_PROTECTION.getOID()));
        assertFalse(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.TIME_STAMPING.getOID()));
        assertFalse(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.OCSP_SIGNING.getOID()));
        assertFalse(e.getKeyPurposeIDs().contains(new OID("1.2.3.5")));
      }
      else if (extension instanceof KeyUsageExtension)
      {
        hasKeyUsageExtension = true;

        final KeyUsageExtension e = (KeyUsageExtension) extension;
        assertTrue(e.isDigitalSignatureBitSet());
        assertFalse(e.isNonRepudiationBitSet());
        assertFalse(e.isKeyEnciphermentBitSet());
        assertFalse(e.isDataEnciphermentBitSet());
        assertFalse(e.isKeyAgreementBitSet());
        assertFalse(e.isKeyCertSignBitSet());
        assertFalse(e.isCRLSignBitSet());
        assertFalse(e.isEncipherOnlyBitSet());
        assertFalse(e.isDecipherOnlyBitSet());
      }
      else if (extension instanceof SubjectAlternativeNameExtension)
      {
        hasSubjectAlternativeNameExtension = true;

        final SubjectAlternativeNameExtension e =
             (SubjectAlternativeNameExtension) extension;
        assertEquals(e.getDNSNames(),
             Collections.singletonList("ds.example.com"));
        assertEquals(e.getIPAddresses(),
             Collections.singletonList(InetAddress.getByName("::1")));
        assertEquals(e.getRFC822Names(),
             Collections.singletonList("other@example.com"));
        assertEquals(e.getUniformResourceIdentifiers(),
             Collections.singletonList("https://www2.example.com/"));
        assertEquals(e.getRegisteredIDs(),
             Collections.singletonList(new OID("1.2.3.5")));
      }
      else if (extension instanceof SubjectKeyIdentifierExtension)
      {
        hasSubjectKeyIdentifierExtension = true;
      }
      else if (extension.getOID().equals(new OID("1.2.3.6")))
      {
        hasOriginalGenericExtension = true;

        assertFalse(extension.isCritical());
        assertNotNull(extension.getValue());
        assertEquals(extension.getValue(),
             StaticUtils.byteArray(0x12, 0x34, 0x56, 0x78, 0x90));
      }
      else if (extension.getOID().equals(new OID("1.2.3.7")))
      {
        hasNewGenericExtension = true;

        assertTrue(extension.isCritical());
        assertNotNull(extension.getValue());
        assertEquals(extension.getValue(),
             StaticUtils.byteArray(0x09, 0x87, 0x65, 0x43, 0x21));
      }
    }

    assertTrue(hasBasicConstraintsExtension);
    assertTrue(hasExtendedKeyUsageConstraintsExtension);
    assertTrue(hasKeyUsageExtension);
    assertTrue(hasNewGenericExtension);
    assertTrue(hasOriginalGenericExtension);
    assertTrue(hasSubjectAlternativeNameExtension);
    assertTrue(hasSubjectKeyIdentifierExtension);

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Make sure that we can generate a certificate that uses an elliptic
    // curve key.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--key-algorithm", "EC",
         "--key-size-bits", "256",
         "--signature-algorithm", "SHA256withECDSA");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true), setOf("server-cert"));
    assertEquals(getAliases(keystore, true, false), setOf("server-cert"));
    assertEquals(getAliases(keystore, false, true),
         Collections.emptySet());

    chain = getCertificateChain(keystore, "server-cert");
    assertNotNull(chain);
    assertEquals(chain.length, 1);
    assertEquals(chain[0].getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));
    assertEquals(chain[0].getPublicKeyAlgorithmName(), "EC");
    assertEquals(chain[0].getSignatureAlgorithmName(), "SHA-256 with ECDSA");

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Make sure that we can generate a replacement for a certificate with an
    // elliptic curve key.
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--replace-existing-certificate");

    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true), setOf("server-cert"));
    assertEquals(getAliases(keystore, true, false), setOf("server-cert"));
    assertEquals(getAliases(keystore, false, true),
         Collections.emptySet());

    chain = getCertificateChain(keystore, "server-cert");
    assertNotNull(chain);
    assertEquals(chain.length, 1);
    assertEquals(chain[0].getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));
    assertEquals(chain[0].getPublicKeyAlgorithmName(), "EC");
    assertEquals(chain[0].getSignatureAlgorithmName(), "SHA-256 with ECDSA");

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Test the behavior when trying to replace a certificate with an alias
    // that doesn't exist.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "nonexistent",
         "--replace-existing-certificate");


    // Test the behavior when trying to replace a certificate with an alias
    // that doesn't have a private key.
    ksFile = copyFile(serverTrustStorePath);

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--replace-existing-certificate");


    // Test the behavior when trying to replace a certificate in a keystore that
    // doesn't exist.
    assertTrue(ksFile.delete());

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--replace-existing-certificate");


    // Test the behavior when trying to an unrecognized key algorithm.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--key-algorithm", "unrecognized",
         "--signature-algorithm", "SHA256withECDSA");


    // Test the behavior when trying to an unrecognized signature algorithm.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--key-algorithm", "RSA",
         "--signature-algorithm", "unrecognized");


    // Test the behavior when trying to use a non-RSA key without specifying
    // the key size.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--key-algorithm", "EC",
         "--signature-algorithm", "SHA256withECDSA");


    // Test the behavior when trying to use a non-RSA key without specifying
    // the signature algorithm.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--key-algorithm", "EC",
         "--key-size-bits", "256");


    // Test the behavior when trying to use a basic constraints extension with
    // a maximum path length but with isCA=false.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--basic-constraints-is-ca", "false",
         "--basic-constraints-maximum-path-length", "5");


    // Test the behavior when trying to use an invalid key usage string.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--key-usage", "invalid");


    // Test the behavior when trying to use an malformed extended key usage OID.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--extended-key-usage", "invalid");


    // Test the behavior when trying to use a generic extension with a malformed
    // OID.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--extension", "1234.5678:false:1234567890");


    // Test the behavior when trying to use a generic extension with a malformed
    // criticality.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--extension", "1.2.3.4:invalid:1234567890");


    // Test the behavior when trying to use a generic extension with a malformed
    // value.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--extension", "1.2.3.4:true:invalid");


    // Test the behavior when trying to use a generic extension with a really
    // malformed value that doesn't even have any colons.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--extension", "invalid");


    // Test the behavior when trying to generate a certificate in a malformed
    // keystore.
    ksFile = createTempFile("malformed keystore");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US");


    // Test the behavior when trying to generate a certificate when supplying
    // the wrong keystore password.
    ksFile = copyFile(emptyKeyStorePath);

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "wrong",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US");


    // Test the behavior when trying to generate a certificate when supplying
    // a keystore password in a file with multiple lines.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password-file", multiLinePasswordFilePath,
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US");


    // Test the behavior when trying to generate a certificate when supplying
    // a private key password in a file with multiple lines.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--private-key-password-file", multiLinePasswordFilePath,
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US");


    // Test the behavior when not replacing an existing certificate and not
    // specifying a subject DN.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");


    // Test the behavior when trying to generate a new certificate with an alias
    // that already exists as a certificate entry.
    ksFile = copyFile(serverTrustStorePath);

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", serverCertificateAlias,
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US");


    // Test the behavior when trying to generate a new certificate with an alias
    // that already exists as a key entry.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US");
  }



  /**
   * Provides test coverage for the generate-certificate-signing-request and
   * sign-certificate-signing-request subcommands.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateAndSignCertificateSigningRequest()
         throws Exception
  {
    // Tests with a minimal set of arguments for generating a certificate
    // signing request for a certificate that doesn't exist.
    File ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    File csrFile = createTempFile();
    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--display-keytool-command");

    assertTrue(ksFile.exists());

    assertTrue(csrFile.exists());
    PKCS10CertificateSigningRequest csr =
         ManageCertificates.readCertificateSigningRequestFromFile(csrFile);
    assertEquals(csr.getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));

    File certFile = createTempFile();
    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(certFile.exists());

    List<X509Certificate> certs =
         ManageCertificates.readCertificatesFromFile(certFile);
    assertFalse(certs.isEmpty());
    assertEquals(certs.size(), 1);
    assertEquals(certs.get(0).getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));


    // Tests with a minimal set of arguments for generating a certificate
    // signing request to replace an existing certificate.
    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--replace-existing-certificate",
         "--display-keytool-command");

    assertTrue(csrFile.exists());
    csr = ManageCertificates.readCertificateSigningRequestFromFile(csrFile);
    assertEquals(csr.getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));


    // Do the same but using the DER output format.
    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-format", "DER",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--replace-existing-certificate",
         "--display-keytool-command");

    assertTrue(csrFile.exists());
    csr = ManageCertificates.readCertificateSigningRequestFromFile(csrFile);
    assertEquals(csr.getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));


    // Tests with a full set of arguments for a new certificate using a JKS
    // keystore that doesn't already exist.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-format", "DER",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-dns", "ldap.example.com",
         "--subject-alternative-name-ip-address", "127.0.0.1",
         "--subject-alternative-name-email-address", "test@example.com",
         "--subject-alternative-name-uri", "https://www.example.com/",
         "--subject-alternative-name-oid", "1.2.3.4",
         "--basic-constraints-is-ca", "true",
         "--basic-constraints-maximum-path-length", "5",
         "--key-usage", "digital-signature",
         "--key-usage", "non-repudiation",
         "--key-usage", "key-encipherment",
         "--key-usage", "data-encipherment",
         "--key-usage", "key-agreement",
         "--key-usage", "key-cert-sign",
         "--key-usage", "crl-sign",
         "--key-usage", "encipher-only",
         "--key-usage", "decipher-only",
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--extended-key-usage", "code-signing",
         "--extended-key-usage", "email-protection",
         "--extended-key-usage", "time-stamping",
         "--extended-key-usage", "ocsp-signing",
         "--extended-key-usage", "1.2.3.5",
         "--extension", "1.2.3.6:false:1234567890",
         "--display-keytool-command");

    assertTrue(csrFile.exists());
    csr = ManageCertificates.readCertificateSigningRequestFromFile(csrFile);
    assertEquals(csr.getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));
    assertEquals(csr.getPublicKeyAlgorithmName(), "RSA");
    assertEquals(csr.getSignatureAlgorithmName(), "SHA-256 with RSA");

    boolean hasBasicConstraintsExtension = false;
    boolean hasExtendedKeyUsageConstraintsExtension = false;
    boolean hasGenericExtension = false;
    boolean hasKeyUsageExtension = false;
    boolean hasSubjectAlternativeNameExtension = false;
    boolean hasSubjectKeyIdentifierExtension = false;
    for (final X509CertificateExtension extension : csr.getExtensions())
    {
      if (extension instanceof BasicConstraintsExtension)
      {
        hasBasicConstraintsExtension = true;

        final BasicConstraintsExtension e =
             (BasicConstraintsExtension) extension;
        assertTrue(e.isCA());
        assertNotNull(e.getPathLengthConstraint());
        assertEquals(e.getPathLengthConstraint().intValue(), 5);
      }
      else if (extension instanceof ExtendedKeyUsageExtension)
      {
        hasExtendedKeyUsageConstraintsExtension = true;

        final ExtendedKeyUsageExtension e =
             (ExtendedKeyUsageExtension) extension;
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.TLS_SERVER_AUTHENTICATION.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.TLS_CLIENT_AUTHENTICATION.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.CODE_SIGNING.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.EMAIL_PROTECTION.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.TIME_STAMPING.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.OCSP_SIGNING.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(new OID("1.2.3.5")));
      }
      else if (extension instanceof KeyUsageExtension)
      {
        hasKeyUsageExtension = true;

        final KeyUsageExtension e = (KeyUsageExtension) extension;
        assertTrue(e.isDigitalSignatureBitSet());
        assertTrue(e.isNonRepudiationBitSet());
        assertTrue(e.isKeyEnciphermentBitSet());
        assertTrue(e.isDataEnciphermentBitSet());
        assertTrue(e.isKeyAgreementBitSet());
        assertTrue(e.isKeyCertSignBitSet());
        assertTrue(e.isCRLSignBitSet());
        assertTrue(e.isEncipherOnlyBitSet());
        assertTrue(e.isDecipherOnlyBitSet());
      }
      else if (extension instanceof SubjectAlternativeNameExtension)
      {
        hasSubjectAlternativeNameExtension = true;

        final SubjectAlternativeNameExtension e =
             (SubjectAlternativeNameExtension) extension;
        assertEquals(e.getDNSNames(),
             Collections.singletonList("ldap.example.com"));
        assertEquals(e.getIPAddresses(),
             Collections.singletonList(InetAddress.getByName("127.0.0.1")));
        assertEquals(e.getRFC822Names(),
             Collections.singletonList("test@example.com"));
        assertEquals(e.getUniformResourceIdentifiers(),
             Collections.singletonList("https://www.example.com/"));
        assertEquals(e.getRegisteredIDs(),
             Collections.singletonList(new OID("1.2.3.4")));
      }
      else if (extension instanceof SubjectKeyIdentifierExtension)
      {
        hasSubjectKeyIdentifierExtension = true;
      }
      else if (extension.getOID().equals(new OID("1.2.3.6")))
      {
        hasGenericExtension = true;
        assertFalse(extension.isCritical());
        assertNotNull(extension.getValue());
        assertEquals(extension.getValue(),
             StaticUtils.byteArray(0x12, 0x34, 0x56, 0x78, 0x90));
      }
    }

    assertTrue(hasBasicConstraintsExtension);
    assertTrue(hasExtendedKeyUsageConstraintsExtension);
    assertTrue(hasGenericExtension);
    assertTrue(hasKeyUsageExtension);
    assertTrue(hasSubjectAlternativeNameExtension);
    assertTrue(hasSubjectKeyIdentifierExtension);


    // Sign the CSR with a full set of arguments.
    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--output-format", "DER",
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "7300",
         "--validity-start-time", "20170101000000",
         "--include-requested-extensions",
         "--issuer-alternative-name-dns", "issuer.example.com",
         "--issuer-alternative-name-ip-address", "::1",
         "--issuer-alternative-name-email-address", "issuer@example.com",
         "--issuer-alternative-name-uri", "https://issuer.example.com/",
         "--issuer-alternative-name-oid", "1.2.3.7",
         "--extension", "1.2.3.8:true:0987654321",
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(certFile.exists());

    certs = ManageCertificates.readCertificatesFromFile(certFile);
    assertFalse(certs.isEmpty());
    assertEquals(certs.size(), 1);
    assertEquals(certs.get(0).getSubjectDN(),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"));
    assertEquals(certs.get(0).getPublicKeyAlgorithmName(), "RSA");
    assertEquals(certs.get(0).getSignatureAlgorithmName(), "SHA-256 with RSA");

    hasBasicConstraintsExtension = false;
    hasExtendedKeyUsageConstraintsExtension = false;
    hasKeyUsageExtension = false;
    hasSubjectAlternativeNameExtension = false;
    hasSubjectKeyIdentifierExtension = false;
    boolean hasAuthorityKeyIdentifierExtension = false;
    boolean hasIssuerAlternativeNameExtension = false;
    boolean hasOldGenericExtension = false;
    boolean hasNewGenericExtension = false;
    for (final X509CertificateExtension extension :
         certs.get(0).getExtensions())
    {
      if (extension instanceof AuthorityKeyIdentifierExtension)
      {
        hasAuthorityKeyIdentifierExtension = true;
      }
      else if (extension instanceof BasicConstraintsExtension)
      {
        hasBasicConstraintsExtension = true;

        final BasicConstraintsExtension e =
             (BasicConstraintsExtension) extension;
        assertTrue(e.isCA());
        assertNotNull(e.getPathLengthConstraint());
        assertEquals(e.getPathLengthConstraint().intValue(), 5);
      }
      else if (extension instanceof ExtendedKeyUsageExtension)
      {
        hasExtendedKeyUsageConstraintsExtension = true;

        final ExtendedKeyUsageExtension e =
             (ExtendedKeyUsageExtension) extension;
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.TLS_SERVER_AUTHENTICATION.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.TLS_CLIENT_AUTHENTICATION.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.CODE_SIGNING.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.EMAIL_PROTECTION.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.TIME_STAMPING.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(
             ExtendedKeyUsageID.OCSP_SIGNING.getOID()));
        assertTrue(e.getKeyPurposeIDs().contains(new OID("1.2.3.5")));
      }
      else if (extension instanceof IssuerAlternativeNameExtension)
      {
        hasIssuerAlternativeNameExtension = true;

        final IssuerAlternativeNameExtension e =
             (IssuerAlternativeNameExtension) extension;
        assertEquals(e.getDNSNames(),
             Collections.singletonList("issuer.example.com"));
        assertEquals(e.getIPAddresses(),
             Collections.singletonList(InetAddress.getByName("::1")));
        assertEquals(e.getRFC822Names(),
             Collections.singletonList("issuer@example.com"));
        assertEquals(e.getUniformResourceIdentifiers(),
             Collections.singletonList("https://issuer.example.com/"));
        assertEquals(e.getRegisteredIDs(),
             Collections.singletonList(new OID("1.2.3.7")));
      }
      else if (extension instanceof KeyUsageExtension)
      {
        hasKeyUsageExtension = true;

        final KeyUsageExtension e = (KeyUsageExtension) extension;
        assertTrue(e.isDigitalSignatureBitSet());
        assertTrue(e.isNonRepudiationBitSet());
        assertTrue(e.isKeyEnciphermentBitSet());
        assertTrue(e.isDataEnciphermentBitSet());
        assertTrue(e.isKeyAgreementBitSet());
        assertTrue(e.isKeyCertSignBitSet());
        assertTrue(e.isCRLSignBitSet());
        assertTrue(e.isEncipherOnlyBitSet());
        assertTrue(e.isDecipherOnlyBitSet());
      }
      else if (extension instanceof SubjectAlternativeNameExtension)
      {
        hasSubjectAlternativeNameExtension = true;

        final SubjectAlternativeNameExtension e =
             (SubjectAlternativeNameExtension) extension;
        assertEquals(e.getDNSNames(),
             Collections.singletonList("ldap.example.com"));
        assertEquals(e.getIPAddresses(),
             Collections.singletonList(InetAddress.getByName("127.0.0.1")));
        assertEquals(e.getRFC822Names(),
             Collections.singletonList("test@example.com"));
        assertEquals(e.getUniformResourceIdentifiers(),
             Collections.singletonList("https://www.example.com/"));
        assertEquals(e.getRegisteredIDs(),
             Collections.singletonList(new OID("1.2.3.4")));
      }
      else if (extension instanceof SubjectKeyIdentifierExtension)
      {
        hasSubjectKeyIdentifierExtension = true;
      }
      else if (extension.getOID().equals(new OID("1.2.3.6")))
      {
        hasOldGenericExtension = true;
        assertFalse(extension.isCritical());
        assertNotNull(extension.getValue());
        assertEquals(extension.getValue(),
             StaticUtils.byteArray(0x12, 0x34, 0x56, 0x78, 0x90));
      }
      else if (extension.getOID().equals(new OID("1.2.3.8")))
      {
        hasNewGenericExtension = true;
        assertTrue(extension.isCritical());
        assertNotNull(extension.getValue());
        assertEquals(extension.getValue(),
             StaticUtils.byteArray(0x09, 0x87, 0x65, 0x43, 0x21));
      }
    }

    assertTrue(hasAuthorityKeyIdentifierExtension);
    assertTrue(hasBasicConstraintsExtension);
    assertTrue(hasExtendedKeyUsageConstraintsExtension);
    assertTrue(hasIssuerAlternativeNameExtension);
    assertTrue(hasKeyUsageExtension);
    assertTrue(hasNewGenericExtension);
    assertTrue(hasOldGenericExtension);
    assertTrue(hasSubjectAlternativeNameExtension);
    assertTrue(hasSubjectKeyIdentifierExtension);


    // Tests the behavior when prompting about whether to sign a certificate
    // signing request.  First, reject the request.  Next, fail with invalid
    // input.  Finally, approve the request.
    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(ResultCode.USER_CANCELED, "no\n",
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--output-format", "DER",
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--display-keytool-command");
    assertFalse(certFile.exists());

    manageCertificates(ResultCode.LOCAL_ERROR, "invalid input\n",
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--output-format", "DER",
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--display-keytool-command");
    assertFalse(certFile.exists());

    manageCertificates(ResultCode.SUCCESS, "yes\n",
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--output-format", "DER",
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--display-keytool-command");
    assertTrue(certFile.exists());


    // Tests the behavior when trying to sign a certificate signing request with
    // the signed certificate being written to standard output instead of to a
    // file.
    manageCertificates(ResultCode.SUCCESS, null,
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--output-format", "PEM",
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");
    assertTrue(certFile.exists());


    // Tests the behavior when trying to sign a certificate signing request with
    // the signed certificate being written to standard output instead of to a
    // file and using the DER output format.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--output-format", "DER",
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");
    assertTrue(certFile.exists());


    // Tests the behavior when trying to sign a certificate signing request with
    // a keystore that doesn't have an entry with the specified alias.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--output-format", "DER",
         "--keystore", emptyKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Tests the behavior when trying to sign a certificate signing request with
    // a keystore for which the specified alias is a certificate entry rather
    // than a key entry.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--output-format", "DER",
         "--keystore", serverTrustStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", serverCertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Tests the behavior when trying to sign a malformed certificate signing
    // request.
    csrFile = createTempFile(
         "-----BEGIN NEW CERTIFICATE REQUEST-----",
         "This isn't a valid CSR.",
         "-----END NEW CERTIFICATE REQUEST-----");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--output-format", "DER",
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Tests the behavior when trying to sign a certificate signing request with
    // an invalid signature.
    csr = new PKCS10CertificateSigningRequest(
         PKCS10CertificateSigningRequestVersion.V1,
         SignatureAlgorithmIdentifier.SHA_256_WITH_RSA.getOID(), null,
         new ASN1BitString(true, true, true, true, true, true, true, true),
         new DN("CN=ldap.example.com,O=Example Corporation,C=US"),
         PublicKeyAlgorithmIdentifier.RSA.getOID(), null,
         new ASN1BitString(true, true, true, true, true, true, true, true),
         null, null);
    csrFile = createTempFile(csr.toPEMString());

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--output-format", "DER",
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");


    // Tests the behavior when writing a certificate signing request to standard
    // output.
    manageCertificates(
         "generate-certificate-signing-request",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--replace-existing-certificate",
         "--display-keytool-command");
  }



  /**
   * Provides test coverage for the change-certificate-alias subcommand.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testChangeCertificateAlias()
         throws Exception
  {
    // Tests changing the alias for a certificate entry in a JKS keystore.
    File ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", rootCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    KeyStore keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf(rootCACertificateAlias));

    manageCertificates(
         "change-certificate-alias",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--current-alias", rootCACertificateAlias,
         "--new-alias", "new-" + rootCACertificateAlias,
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf("new-" + rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf("new-" + rootCACertificateAlias));


    // Tests changing the alias for a key entry in a JKS keystore.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", rootCACertificatePath,
         "--private-key-file", rootCAKeyPath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());

    manageCertificates(
         "change-certificate-alias",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--current-alias", rootCACertificateAlias,
         "--new-alias", "new-" + rootCACertificateAlias,
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf("new-" + rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf("new-" + rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());


    // Tests changing the alias for a key entry in a PKCS #12 keystore.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", rootCACertificatePath,
         "--private-key-file", rootCAKeyPath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "PKCS12",
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "PKCS12");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());

    manageCertificates(
         "change-certificate-alias",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--current-alias", rootCACertificateAlias,
         "--new-alias", "new-" + rootCACertificateAlias,
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "PKCS12");
    assertEquals(getAliases(keystore, true, true),
         setOf("new-" + rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf("new-" + rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());


    // Tests changing the alias for an entry that doesn't exist in the keystore.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", rootCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf(rootCACertificateAlias));

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "change-certificate-alias",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--current-alias", "wrong",
         "--new-alias", "new-" + rootCACertificateAlias,
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf(rootCACertificateAlias));


    // Tests changing the alias for an entry in a keystore in a way that would
    // conflict with another entry that already exists in that keystore.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", rootCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", intermediateCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", intermediateCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias, intermediateCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf(rootCACertificateAlias, intermediateCACertificateAlias));

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "change-certificate-alias",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--current-alias", rootCACertificateAlias,
         "--new-alias", intermediateCACertificateAlias,
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias, intermediateCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf(rootCACertificateAlias, intermediateCACertificateAlias));


    // Tests the behavior when trying to change an alias when the wrong keystore
    // password is provided.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", rootCACertificatePath,
         "--private-key-file", rootCAKeyPath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "change-certificate-alias",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "wrong",
         "--current-alias", rootCACertificateAlias,
         "--new-alias", "new-" + rootCACertificateAlias,
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());


    // Tests the behavior when trying to change an alias using a keystore
    // password read from a file with multiple lines.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "change-certificate-alias",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password-file", multiLinePasswordFilePath,
         "--current-alias", rootCACertificateAlias,
         "--new-alias", "new-" + rootCACertificateAlias,
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());


    // Tests the behavior when trying to change an alias using a private key
    // password file with multiple lines.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "change-certificate-alias",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--private-key-password-file", multiLinePasswordFilePath,
         "--current-alias", rootCACertificateAlias,
         "--new-alias", "new-" + rootCACertificateAlias,
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());


    // Tests the behavior when trying to change an alias in a malformed
    // keystore.
    ksFile = createTempFile("malformed keystore");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "change-certificate-alias",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--current-alias", rootCACertificateAlias,
         "--new-alias", "new-" + rootCACertificateAlias,
         "--display-keytool-command");
  }



  /**
   * Provides test coverage for the change-keystore-password subcommand.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testChangeKeystorePassword()
         throws Exception
  {
    // Tests changing the keystore password for a JKS keystore.
    File ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", rootCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    KeyStore keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf(rootCACertificateAlias));

    manageCertificates(
         "change-keystore-password",
         "--keystore", ksFile.getAbsolutePath(),
         "--current-keystore-password", "password",
         "--new-keystore-password", "new-password",
         "--display-keytool-command");

    assertTrue(ksFile.exists());

    try
    {
      keystore = getKeystore(ksFile.getAbsolutePath(), "JKS", "password");
      fail("Expected an exception when trying to open a keystore with the " +
           "wrong password");
    }
    catch (final Exception e)
    {
      // This was expected.
    }

    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS", "new-password");


    // Tests changing the keystore password for a PKCS #12 keystore.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", rootCACertificatePath,
         "--private-key-file", rootCAKeyPath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "PKCS12",
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "PKCS12");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());

    manageCertificates(
         "change-keystore-password",
         "--keystore", ksFile.getAbsolutePath(),
         "--current-keystore-password", "password",
         "--new-keystore-password", "new-password",
         "--display-keytool-command");

    assertTrue(ksFile.exists());

    try
    {
      keystore = getKeystore(ksFile.getAbsolutePath(), "PKCS12", "password");
      fail("Expected an exception when trying to open a keystore with the " +
           "wrong password");
    }
    catch (final Exception e)
    {
      // This was expected.
    }

    keystore = getKeystore(ksFile.getAbsolutePath(), "PKCS12", "new-password");


    // Tests with the current and new passwords read from files.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", rootCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf(rootCACertificateAlias));

    final String newPasswordFilePath =
         createTempFile("new-password").getAbsolutePath();
    manageCertificates(
         "change-keystore-password",
         "--keystore", ksFile.getAbsolutePath(),
         "--current-keystore-password-file", correctPasswordFilePath,
         "--new-keystore-password-file", newPasswordFilePath,
         "--display-keytool-command");

    assertTrue(ksFile.exists());

    try
    {
      keystore = getKeystore(ksFile.getAbsolutePath(), "JKS", "password");
      fail("Expected an exception when trying to open a keystore with the " +
           "wrong password");
    }
    catch (final Exception e)
    {
      // This was expected.
    }

    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS", "new-password");


    // Tests with the current and new passwords obtained interactively.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", rootCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf(rootCACertificateAlias));

    PasswordReader.setTestReader(new BufferedReader(new InputStreamReader(
         new ByteArrayInputStream(StaticUtils.getBytes(
              "\npassword\nnew-password\nwrong\nshort\nnew-password\n" +
                   "new-password\n")))));

    try
    {
      manageCertificates(
           "change-keystore-password",
           "--keystore", ksFile.getAbsolutePath(),
           "--prompt-for-current-keystore-password",
           "--prompt-for-new-keystore-password",
           "--display-keytool-command");
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }

    assertTrue(ksFile.exists());

    try
    {
      keystore = getKeystore(ksFile.getAbsolutePath(), "JKS", "password");
      fail("Expected an exception when trying to open a keystore with the " +
           "wrong password");
    }
    catch (final Exception e)
    {
      // This was expected.
    }

    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS", "new-password");


    // Tests with the wrong current password.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", rootCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(rootCACertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf(rootCACertificateAlias));

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "change-keystore-password",
         "--keystore", ksFile.getAbsolutePath(),
         "--current-keystore-password", "wrong",
         "--new-keystore-password", "new-password",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS", "password");


    // Tests with the current password read from an empty file.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "change-keystore-password",
         "--keystore", ksFile.getAbsolutePath(),
         "--current-keystore-password-file", emptyPasswordFilePath,
         "--new-keystore-password", "new-password",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS", "password");


    // Tests with the new password read from an empty file.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "change-keystore-password",
         "--keystore", ksFile.getAbsolutePath(),
         "--current-keystore-password-file", correctPasswordFilePath,
         "--new-keystore-password-file", emptyPasswordFilePath,
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS", "password");


    // Tests with a malformed keystore.
    ksFile = createTempFile("this is not a valid keystore");
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "change-keystore-password",
         "--keystore", ksFile.getAbsolutePath(),
         "--current-keystore-password", "password",
         "--new-keystore-password", "new-password",
         "--display-keytool-command");
  }



  /**
   * Provides test coverage for the change-private-key-password subcommand.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testChangePrivateKeyPassword()
         throws Exception
  {
    // Tests changing the private key password for a certificate in a JKS
    // keystore.
    File ksFile = copyFile(serverKeyStorePath);

    assertTrue(ksFile.exists());
    KeyStore keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());

    manageCertificates(
         "change-private-key-password",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--current-private-key-password", "password",
         "--new-private-key-password", "new-password",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS", "password");
    assertNotNull(keystore.getKey("server-cert", "new-password".toCharArray()));

    try
    {
      keystore.getKey("server-cert", "password".toCharArray());
      fail("Expected an exception when trying to get a key with the wrong " +
           "password");
    }
    catch (final Exception e)
    {
      // This was expected.
    }


    // Tests changing the private key password for a certificate in a PKCS #12
    // keystore.
    ksFile = copyFile(serverPKCS12KeyStorePath);

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "PKCS12");
    assertEquals(getAliases(keystore, true, true),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());

    manageCertificates(
         "change-private-key-password",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--current-private-key-password", "password",
         "--new-private-key-password", "new-password",
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "PKCS12", "password");
    assertNotNull(keystore.getKey("server-cert", "new-password".toCharArray()));

    try
    {
      keystore.getKey("server-cert", "password".toCharArray());
      fail("Expected an exception when trying to get a key with the wrong " +
           "password");
    }
    catch (final Exception e)
    {
      // This was expected.
    }


    // Tests changing the private key password using passwords read from files.
    ksFile = copyFile(serverKeyStorePath);

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());

    final String newPasswordFilePath =
         createTempFile("new-password").getAbsolutePath();
    manageCertificates(
         "change-private-key-password",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--current-private-key-password-file", correctPasswordFilePath,
         "--new-private-key-password-file", newPasswordFilePath,
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS", "password");
    assertNotNull(keystore.getKey("server-cert", "new-password".toCharArray()));

    try
    {
      keystore.getKey("server-cert", "password".toCharArray());
      fail("Expected an exception when trying to get a key with the wrong " +
           "password");
    }
    catch (final Exception e)
    {
      // This was expected.
    }


    // Tests changing the private key password using passwords read
    // interactively.
    ksFile = copyFile(serverKeyStorePath);

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());

    PasswordReader.setTestReader(new BufferedReader(new InputStreamReader(
         new ByteArrayInputStream(StaticUtils.getBytes(
              "\npassword\nnew-password\nwrong\nshort\nnew-password\n" +
                   "new-password\n")))));
    try
    {
      manageCertificates(
           "change-private-key-password",
           "--keystore", ksFile.getAbsolutePath(),
           "--keystore-password", "password",
           "--alias", "server-cert",
           "--prompt-for-current-private-key-password",
           "--prompt-for-new-private-key-password",
           "--display-keytool-command");
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS", "password");
    assertNotNull(keystore.getKey("server-cert", "new-password".toCharArray()));

    try
    {
      keystore.getKey("server-cert", "password".toCharArray());
      fail("Expected an exception when trying to get a key with the wrong " +
           "password");
    }
    catch (final Exception e)
    {
      // This was expected.
    }


    // Tests with an alias that doesn't exist in the keystore.
    ksFile = copyFile(serverKeyStorePath);

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "change-private-key-password",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "nonexistent",
         "--current-private-key-password", "password",
         "--new-private-key-password", "new-password",
         "--display-keytool-command");


    // Tests with an alias that is associated with a trusted certificate entry
    // rather than a private key entry.
    ksFile = copyFile(serverTrustStorePath);

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(serverCertificateAlias, serverCertificateAlias + "-issuer-1",
              serverCertificateAlias + "-issuer-2"));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf(serverCertificateAlias, serverCertificateAlias + "-issuer-1",
              serverCertificateAlias + "-issuer-2"));

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "change-private-key-password",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--current-private-key-password", "password",
         "--new-private-key-password", "new-password",
         "--display-keytool-command");


    // Tests with a wrong keystore password.
    ksFile = copyFile(serverKeyStorePath);

    assertTrue(ksFile.exists());
    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(keystore, true, false),
         setOf(serverCertificateAlias));
    assertEquals(getAliases(keystore, false, true),
         Collections.<String>emptySet());

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "change-private-key-password",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "wrong",
         "--alias", "server-cert",
         "--current-private-key-password", "password",
         "--new-private-key-password", "new-password",
         "--display-keytool-command");


    // Tests with a keystore password read from an empty file.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "change-private-key-password",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password-file", emptyPasswordFilePath,
         "--alias", "server-cert",
         "--current-private-key-password", "password",
         "--new-private-key-password", "new-password",
         "--display-keytool-command");


    // Tests with a wrong current private key password.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "change-private-key-password",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--current-private-key-password", "wrong",
         "--new-private-key-password", "new-password",
         "--display-keytool-command");


    // Tests with a current private key password read from an empty file.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "change-private-key-password",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--current-private-key-password-file", emptyPasswordFilePath,
         "--new-private-key-password", "new-password",
         "--display-keytool-command");


    // Tests with a new private key password read from an empty file.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "change-private-key-password",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--current-private-key-password", "password",
         "--new-private-key-password-file", emptyPasswordFilePath,
         "--display-keytool-command");


    // Tests with a malformed keystore.
    ksFile = createTempFile("this is not a valid keystore");
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "change-private-key-password",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--current-private-key-password", "password",
         "--new-private-key-password", "new-password",
         "--display-keytool-command");
  }



  /**
   * Provides test coverage for the retrieve-server-certificate subcommand.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRetrieveServerCertificate()
         throws Exception
  {
    // Tests the behavior when retrieving a self-signed certificate when not
    // using StartTLS, not using only-peer-certificate, not using an output
    // file, and not using verbose.
    File ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-dns", "ldap.example.com",
         "--subject-alternative-name-dns", "localhost",
         "--subject-alternative-name-ip-address", "127.0.0.1",
         "--subject-alternative-name-ip-address", "::1",
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");

    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(ksFile.getAbsolutePath(),
              "password".toCharArray(), "JKS", "server-cert"),
         new TrustAllTrustManager());
    final SSLUtil clientSSLUtil = new SSLUtil(new TrustAllTrustManager());

    cfg.setListenerConfigs(InMemoryListenerConfig.createLDAPSConfig("LDAPS",
         null, 0, serverSSLUtil.createSSLServerSocketFactory(),
         clientSSLUtil.createSSLSocketFactory()));

    InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();
    String portStr = String.valueOf(ds.getListenPort("LDAPS"));

    ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "retrieve-server-certificate",
         "--hostname", "localhost",
         "--port", portStr);


    // Tests the above configuration, but when using only-peer-certificate,
    // verbose mode, and an output file with the PEM format.
    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    manageCertificates(
         "retrieve-server-certificate",
         "--hostname", "localhost",
         "--port", portStr,
         "--only-peer-certificate",
         "--output-file", outputFile.getAbsolutePath(),
         "--output-format", "PEM",
         "--verbose");

    assertTrue(outputFile.exists());
    assertTrue(outputFile.length() > 0L);

    ds.shutDown(true);


    // Test with a keystore with a certificate signed by a root certificate.
    ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    File csrFile = createTempFile();
    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    File certFile = createTempFile();
    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-dns", "ldap.example.com",
         "--subject-alternative-name-dns", "localhost",
         "--subject-alternative-name-ip-address", "127.0.0.1",
         "--subject-alternative-name-ip-address", "::1",
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
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
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", rootCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--no-prompt",
         "--display-keytool-command");

    serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(ksFile.getAbsolutePath(),
              "password".toCharArray(), "JKS", "server-cert"),
         new TrustAllTrustManager());

    cfg.setListenerConfigs(InMemoryListenerConfig.createLDAPSConfig("LDAPS",
         null, 0, serverSSLUtil.createSSLServerSocketFactory(),
         clientSSLUtil.createSSLSocketFactory()));

    ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();
    portStr = String.valueOf(ds.getListenPort("LDAPS"));

    ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    assertTrue(outputFile.delete());

    manageCertificates(
         "retrieve-server-certificate",
         "--hostname", "localhost",
         "--port", portStr,
         "--output-file", outputFile.getAbsolutePath(),
         "--output-format", "DER",
         "--verbose");

    assertTrue(outputFile.exists());
    assertTrue(outputFile.length() > 0L);

    ds.shutDown(true);
  }



  /**
   * Provides test coverage for the trust-server-certificate subcommand.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTrustServerCertificate()
         throws Exception
  {
    // Tests the behavior when trusting a self-signed certificate when not using
    // StartTLS, not using issuers-only, using verbose mode, and using
    // no-prompt.
    File ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-dns", "ldap.example.com",
         "--subject-alternative-name-dns", "localhost",
         "--subject-alternative-name-ip-address", "127.0.0.1",
         "--subject-alternative-name-ip-address", "::1",
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");

    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(ksFile.getAbsolutePath(),
              "password".toCharArray(), "JKS", "server-cert"),
         new TrustAllTrustManager());
    final SSLUtil clientSSLUtil = new SSLUtil(new TrustAllTrustManager());

    cfg.setListenerConfigs(InMemoryListenerConfig.createLDAPSConfig("LDAPS",
         null, 0, serverSSLUtil.createSSLServerSocketFactory(),
         clientSSLUtil.createSSLSocketFactory()));

    InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();
    String portStr = String.valueOf(ds.getListenPort("LDAPS"));

    ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "trust-server-certificate",
         "--hostname", "localhost",
         "--port", portStr,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", "server-cert",
         "--verbose",
         "--no-prompt");

    KeyStore keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true), setOf("server-cert"));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true), setOf("server-cert"));


    // Tests the above configuration, but with issuers-only.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "trust-server-certificate",
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort("LDAPS")),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", "server-cert",
         "--issuers-only",
         "--verbose",
         "--no-prompt");

    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true), setOf("server-cert"));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true), setOf("server-cert"));


    // Tests the above configuration, but without the no-prompt option.  The
    // first attempt will be canceled because the user did not confirm the
    // prompt.  The second will fail because the end of the input stream was
    // reached after some invalid input.  And the third attempt will succeed
    // because the prompt is confirmed.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(ResultCode.USER_CANCELED, "no\n",
         "trust-server-certificate",
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort("LDAPS")),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", "server-cert",
         "--issuers-only",
         "--verbose");

    manageCertificates(ResultCode.LOCAL_ERROR, "invalid input\n",
         "trust-server-certificate",
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort("LDAPS")),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", "server-cert",
         "--issuers-only",
         "--verbose");

    manageCertificates(ResultCode.SUCCESS, "yes\n",
         "trust-server-certificate",
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort("LDAPS")),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", "server-cert",
         "--issuers-only",
         "--verbose");

    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true), setOf("server-cert"));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true), setOf("server-cert"));


    // Test with a keystore with a certificate signed by the root certificate.
    ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    File csrFile = createTempFile();
    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    File certFile = createTempFile();
    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-dns", "ldap.example.com",
         "--subject-alternative-name-dns", "localhost",
         "--subject-alternative-name-ip-address", "127.0.0.1",
         "--subject-alternative-name-ip-address", "::1",
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
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
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", rootCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--no-prompt",
         "--display-keytool-command");

    serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(ksFile.getAbsolutePath(),
              "password".toCharArray(), "JKS", "server-cert"),
         new TrustAllTrustManager());

    cfg.setListenerConfigs(InMemoryListenerConfig.createLDAPSConfig("LDAPS",
         null, 0, serverSSLUtil.createSSLServerSocketFactory(),
         clientSSLUtil.createSSLSocketFactory()));

    ds.shutDown(true);
    ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();
    portStr = String.valueOf(ds.getListenPort("LDAPS"));

    ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "trust-server-certificate",
         "--hostname", "localhost",
         "--port", portStr,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", "server-cert",
         "--verbose",
         "--no-prompt");

    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf("server-cert", "server-cert-issuer"));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf("server-cert", "server-cert-issuer"));


    // Test with a keystore with a certificate signed by the intermediate
    // certificate.
    ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-dns", "ldap.example.com",
         "--subject-alternative-name-dns", "localhost",
         "--subject-alternative-name-ip-address", "127.0.0.1",
         "--subject-alternative-name-ip-address", "::1",
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth",
         "--display-keytool-command");
    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--output-format", "PEM",
         "--keystore", intermediateCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", intermediateCACertificateAlias,
         "--days-valid", "3650",
         "--include-requested-extensions",
         "--no-prompt",
         "--display-keytool-command");
    manageCertificates(
         "import-certificate",
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", intermediateCACertificatePath,
         "--certificate-file", rootCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--no-prompt",
         "--display-keytool-command");

    serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(ksFile.getAbsolutePath(),
              "password".toCharArray(), "JKS", "server-cert"),
         new TrustAllTrustManager());

    cfg.setListenerConfigs(InMemoryListenerConfig.createLDAPSConfig("LDAPS",
         null, 0, serverSSLUtil.createSSLServerSocketFactory(),
         clientSSLUtil.createSSLSocketFactory()));

    ds.shutDown(true);
    ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();
    portStr = String.valueOf(ds.getListenPort("LDAPS"));

    ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "trust-server-certificate",
         "--hostname", "localhost",
         "--port", portStr,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", "server-cert",
         "--verbose",
         "--no-prompt");

    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf("server-cert", "server-cert-issuer-1", "server-cert-issuer-2"));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf("server-cert", "server-cert-issuer-1", "server-cert-issuer-2"));


    // Test the above, but with the --issuers-only argument.
    ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(ResultCode.SUCCESS, "yes\n",
         "trust-server-certificate",
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort("LDAPS")),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", "server-cert",
         "--verbose",
         "--issuers-only");

    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf("server-cert-issuer-1", "server-cert-issuer-2"));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf("server-cert-issuer-1", "server-cert-issuer-2"));


    // Test with StartTLS with a directory server that doesn't support it.
    cfg.setListenerConfigs(
         InMemoryListenerConfig.createLDAPConfig("LDAP-with-StartTLS", null,
              0, serverSSLUtil.createSSLSocketFactory()));

    final InMemoryDirectoryServer testDS = getTestDS();

    ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(ResultCode.LOCAL_ERROR, null,
         "trust-server-certificate",
         "--hostname", "localhost",
         "--port", String.valueOf(testDS.getListenPort()),
         "--use-ldap-start-tls",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", "server-cert",
         "--verbose",
         "--no-prompt");


    // Test with StartTLS.
    cfg.setListenerConfigs(
         InMemoryListenerConfig.createLDAPConfig("LDAP-with-StartTLS", null,
              0, serverSSLUtil.createSSLSocketFactory()));

    ds.shutDown(true);
    ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();
    portStr = String.valueOf(ds.getListenPort("LDAP-with-StartTLS"));

    ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "trust-server-certificate",
         "--hostname", "localhost",
         "--port", portStr,
         "--use-ldap-start-tls",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", "server-cert",
         "--verbose",
         "--no-prompt");

    keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    assertEquals(getAliases(keystore, true, true),
         setOf("server-cert", "server-cert-issuer-1", "server-cert-issuer-2"));
    assertEquals(getAliases(keystore, true, false),
         Collections.<String>emptySet());
    assertEquals(getAliases(keystore, false, true),
         setOf("server-cert", "server-cert-issuer-1", "server-cert-issuer-2"));


    // Test with an alias that is already in use.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "trust-server-certificate",
         "--hostname", "localhost",
         "--port", portStr,
         "--use-ldap-start-tls",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", "server-cert",
         "--verbose",
         "--no-prompt");


    // Test with the server shut down so that it's not possible to connect.
    ds.shutDown(true);

    ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(ResultCode.LOCAL_ERROR, null,
         "trust-server-certificate",
         "--hostname", "localhost",
         "--port", portStr,
         "--use-ldap-start-tls",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--verbose",
         "--no-prompt");


    // Test with an existing keystore when providing the wrong password.
    ds.startListening();

    ksFile = copyFile(emptyKeyStorePath);

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "trust-server-certificate",
         "--hostname", "localhost",
         "--port", portStr,
         "--use-ldap-start-tls",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "wrong",
         "--keystore-type", "JKS",
         "--no-prompt");


    // Test with a keystore password read from a multi-line file.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "trust-server-certificate",
         "--hostname", "localhost",
         "--port", portStr,
         "--use-ldap-start-tls",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password-file", multiLinePasswordFilePath,
         "--keystore-type", "JKS",
         "--no-prompt");


    // Test with a malformed keystore.
    ksFile = createTempFile("malformed keystore");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "trust-server-certificate",
         "--hostname", "localhost",
         "--port", portStr,
         "--use-ldap-start-tls",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--no-prompt");

    ds.shutDown(true);
  }



  /**
   * Provides test coverage for the check-certificate-usability subcommand.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCheckCertificateUsability()
         throws Exception
  {
    // Check the usability of the generated server certificate.
    manageCertificates(
         "check-certificate-usability",
         "--keystore", serverKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias);


    // Check the usability with a malformed keystore.
    File ksFile = createTempFile("malformed keystore");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");


    // Check the usability with the wrong keystore password.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", serverKeyStorePath,
         "--keystore-password", "wrong",
         "--alias", "server-cert");


    // Check the usability with a keystore password read from a file with
    // multiple lines.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", serverKeyStorePath,
         "--keystore-password-file", multiLinePasswordFilePath,
         "--alias", "server-cert");


    // Check the usability for a certificate that doesn't exist.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", emptyKeyStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias);


    // Check the usability for a certificate that doesn't have a private key.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", serverTrustStorePath,
         "--keystore-password", "password",
         "--alias", serverCertificateAlias);


    // Check the usability for a self-signed certificate.  Technically, this
    // isn't an error, but we generate a warning for it and that's enough to
    // trigger a non-success result code.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");


    // Check the usability for a certificate with an incomplete chain that
    // doesn't end with a self-signed certificate.
    //
    // NOTE:  Java will allow creating an incomplete chain that stops before it
    // should, but it won't allow creating an incomplete chain that is missing a
    // certificate in the middle, so we can't test that case.
    ksFile = copyFile(serverKeyStorePath);

    KeyStore keystore = getKeystore(ksFile.getAbsolutePath(), "JKS");
    X509Certificate[] chain = getCertificateChain(keystore, "server-cert");
    Certificate[] javaChain = { chain[0].toCertificate() };

    PKCS8PrivateKey privateKey = getPrivateKey(keystore, "server-cert");

    keystore.setKeyEntry("server-cert", privateKey.toPrivateKey(),
         "password".toCharArray(), javaChain);
    ManageCertificates.writeKeystore(keystore, ksFile,
         "password".toCharArray());

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Check the usability for an end certificate that is not yet valid.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    File csrFile = createTempFile();
    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US");

    assertTrue(ksFile.exists());

    assertTrue(csrFile.exists());

    File certFile = createTempFile();
    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "365",
         "--validity-start-time",
              formatValidityStartTime(System.currentTimeMillis() + 86_400_000L),
         "--no-prompt");
    assertTrue(certFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", rootCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--no-prompt",
         "--display-keytool-command");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Check the usability for an end certificate that is expired.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US");

    assertTrue(ksFile.exists());

    assertTrue(csrFile.exists());

    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "365",
         "--validity-start-time",
              formatValidityStartTime(
                   System.currentTimeMillis() - (370L * 86_400_000L)),
         "--no-prompt");
    assertTrue(certFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", rootCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--no-prompt",
         "--display-keytool-command");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Check the usability for an end certificate that is about to expire.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US");

    assertTrue(ksFile.exists());

    assertTrue(csrFile.exists());

    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "365",
         "--validity-start-time",
              formatValidityStartTime(
                   System.currentTimeMillis() - (350L * 86_400_000L)),
         "--no-prompt");
    assertTrue(certFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", rootCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--no-prompt",
         "--display-keytool-command");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Check the usability for an issuer certificate that is not yet valid.
    final File issuerKSFile = createTempFile();
    assertTrue(issuerKSFile.exists());
    assertTrue(issuerKSFile.delete());
    assertFalse(issuerKSFile.exists());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--validity-start-time",
              formatValidityStartTime(System.currentTimeMillis() + 86_400_000L),
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");

    final File issuerCertFile = createTempFile();
    assertTrue(issuerCertFile.exists());
    assertTrue(issuerCertFile.delete());
    assertFalse(issuerCertFile.exists());

    manageCertificates(
         "export-certificate",
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--output-format", "PEM",
         "--output-file", issuerCertFile.getAbsolutePath(),
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US");

    assertTrue(ksFile.exists());

    assertTrue(csrFile.exists());

    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "365",
         "--no-prompt");
    assertTrue(certFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", issuerCertFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--no-prompt",
         "--display-keytool-command");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Check the usability for an issuer certificate that is expired.
    assertTrue(issuerKSFile.exists());
    assertTrue(issuerKSFile.delete());
    assertFalse(issuerKSFile.exists());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "365",
         "--validity-start-time",
              formatValidityStartTime(
                   System.currentTimeMillis() - (370L * 86_400_000L)),
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");

    assertTrue(issuerCertFile.exists());
    assertTrue(issuerCertFile.delete());
    assertFalse(issuerCertFile.exists());

    manageCertificates(
         "export-certificate",
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--output-format", "PEM",
         "--output-file", issuerCertFile.getAbsolutePath(),
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US");

    assertTrue(ksFile.exists());

    assertTrue(csrFile.exists());

    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "365",
         "--no-prompt");
    assertTrue(certFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", issuerCertFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--no-prompt",
         "--display-keytool-command");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Check the usability for an issuer certificate that is about to expire.
    assertTrue(issuerKSFile.exists());
    assertTrue(issuerKSFile.delete());
    assertFalse(issuerKSFile.exists());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "365",
         "--validity-start-time",
              formatValidityStartTime(
                   System.currentTimeMillis() - (350L * 86_400_000L)),
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");

    assertTrue(issuerCertFile.exists());
    assertTrue(issuerCertFile.delete());
    assertFalse(issuerCertFile.exists());

    manageCertificates(
         "export-certificate",
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--output-format", "PEM",
         "--output-file", issuerCertFile.getAbsolutePath(),
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US");

    assertTrue(ksFile.exists());

    assertTrue(csrFile.exists());

    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "365",
         "--no-prompt");
    assertTrue(certFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", issuerCertFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--no-prompt",
         "--display-keytool-command");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Check the usability for an end certificate that has an extended key
    // usage extension without the serverAuth usage.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--extended-key-usage", "client-auth");

    assertTrue(ksFile.exists());

    assertTrue(csrFile.exists());

    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt");
    assertTrue(certFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", rootCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--no-prompt",
         "--display-keytool-command");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Check the usability for an end certificate that does not have an extended
    // key usage extension.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US");

    assertTrue(ksFile.exists());

    assertTrue(csrFile.exists());

    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt");
    assertTrue(certFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", rootCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--no-prompt",
         "--display-keytool-command");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Check the usability for an issuer certificate that has a basic
    // constraints extension with isCA=false.
    assertTrue(issuerKSFile.exists());
    assertTrue(issuerKSFile.delete());
    assertFalse(issuerKSFile.exists());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "365",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "false",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");

    assertTrue(issuerCertFile.exists());
    assertTrue(issuerCertFile.delete());
    assertFalse(issuerCertFile.exists());

    manageCertificates(
         "export-certificate",
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--output-format", "PEM",
         "--output-file", issuerCertFile.getAbsolutePath(),
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US");

    assertTrue(ksFile.exists());

    assertTrue(csrFile.exists());

    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "365",
         "--no-prompt");
    assertTrue(certFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", issuerCertFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--no-prompt",
         "--display-keytool-command");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Check the usability for an issuer certificate that has a basic
    // constraints extension with isCA=true and a path length constraint that
    // has been violated.
    assertTrue(issuerKSFile.exists());
    assertTrue(issuerKSFile.delete());
    assertFalse(issuerKSFile.exists());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "365",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--basic-constraints-maximum-path-length", "0",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");

    assertTrue(issuerCertFile.exists());
    assertTrue(issuerCertFile.delete());
    assertFalse(issuerCertFile.exists());

    manageCertificates(
         "export-certificate",
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--output-format", "PEM",
         "--output-file", issuerCertFile.getAbsolutePath(),
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", intermediateCACertificateAlias,
         "--subject-dn",
              "CN=Example Intermediate CA,O=Example Corporation,C=US",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "digital-signature",
         "--key-usage", "key-encipherment",
         "--key-usage", "key-cert-sign",
         "--key-usage", "crl-sign",
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth");

    assertTrue(ksFile.exists());

    assertTrue(csrFile.exists());

    final File intermediateCertFile = createTempFile();
    assertTrue(intermediateCertFile.exists());
    assertTrue(intermediateCertFile.delete());
    assertFalse(intermediateCertFile.exists());

    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", intermediateCertFile.getAbsolutePath(),
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt");
    assertTrue(intermediateCertFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", intermediateCertFile.getAbsolutePath(),
         "--certificate-file", issuerCertFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", intermediateCACertificateAlias,
         "--no-prompt",
         "--display-keytool-command");

    manageCertificates(
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", intermediateCACertificateAlias);

    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--key-usage", "digital-signature",
         "--key-usage", "key-encipherment",
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth");

    assertTrue(csrFile.exists());

    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--signing-certificate-alias", intermediateCACertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt");
    assertTrue(certFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", intermediateCertFile.getAbsolutePath(),
         "--certificate-file", issuerCertFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--no-prompt",
         "--display-keytool-command");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Check the usability for an issuer certificate that does not have a basic
    // constraints extension.
    assertTrue(issuerKSFile.exists());
    assertTrue(issuerKSFile.delete());
    assertFalse(issuerKSFile.exists());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "365",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");

    assertTrue(issuerCertFile.exists());
    assertTrue(issuerCertFile.delete());
    assertFalse(issuerCertFile.exists());

    manageCertificates(
         "export-certificate",
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--output-format", "PEM",
         "--output-file", issuerCertFile.getAbsolutePath(),
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US");

    assertTrue(ksFile.exists());

    assertTrue(csrFile.exists());

    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "365",
         "--no-prompt");
    assertTrue(certFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", issuerCertFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--no-prompt",
         "--display-keytool-command");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Check the usability for an issuer certificate that has a key usage
    // extension with the keyCertSign bit set to false.
    assertTrue(issuerKSFile.exists());
    assertTrue(issuerKSFile.delete());
    assertFalse(issuerKSFile.exists());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "365",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "crl-sign",
         "--display-keytool-command");

    assertTrue(issuerCertFile.exists());
    assertTrue(issuerCertFile.delete());
    assertFalse(issuerCertFile.exists());

    manageCertificates(
         "export-certificate",
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--output-format", "PEM",
         "--output-file", issuerCertFile.getAbsolutePath(),
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US");

    assertTrue(ksFile.exists());

    assertTrue(csrFile.exists());

    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "365",
         "--no-prompt");
    assertTrue(certFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", issuerCertFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--no-prompt",
         "--display-keytool-command");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Check the usability for an issuer certificate that does not have a key
    // usage extension.
    assertTrue(issuerKSFile.exists());
    assertTrue(issuerKSFile.delete());
    assertFalse(issuerKSFile.exists());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "365",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--display-keytool-command");

    assertTrue(issuerCertFile.exists());
    assertTrue(issuerCertFile.delete());
    assertFalse(issuerCertFile.exists());

    manageCertificates(
         "export-certificate",
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", rootCACertificateAlias,
         "--output-format", "PEM",
         "--output-file", issuerCertFile.getAbsolutePath(),
         "--display-keytool-command");

    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US");

    assertTrue(ksFile.exists());

    assertTrue(csrFile.exists());

    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--keystore", issuerKSFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "365",
         "--no-prompt");
    assertTrue(certFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", issuerCertFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--no-prompt",
         "--display-keytool-command");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Check the usability for a certificate that has a signature algorithm that
    // uses MD5.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--signature-algorithm", "MD5withRSA");

    assertTrue(ksFile.exists());

    assertTrue(csrFile.exists());

    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "365",
         "--no-prompt");
    assertTrue(certFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", rootCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--no-prompt",
         "--display-keytool-command");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Check the usability for a certificate that has a signature algorithm that
    // uses SHA-1.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--signature-algorithm", "SHA1withRSA");

    assertTrue(ksFile.exists());

    assertTrue(csrFile.exists());

    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "365",
         "--no-prompt");
    assertTrue(certFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", rootCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--no-prompt",
         "--display-keytool-command");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Check the usability for a certificate that has a signature algorithm that
    // uses SHA-256, but that was issued by a certificate with a signature
    // algorithm that uses SHA-1.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--keystore-type", "JKS",
         "--alias", rootCACertificateAlias,
         "--subject-dn", "CN=Example Root CA,O=Example Corporation,C=US",
         "--days-valid", "7300",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA1withRSA",
         "--subject-alternative-name-email-address", "ca@example.com",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--display-keytool-command");

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--signature-algorithm", "SHA256withRSA",
         "--key-usage", "digital-signature",
         "--key-usage", "key-encipherment",
         "--extended-key-usage", "server-auth",
         "--extended-key-usage", "client-auth");

    assertTrue(ksFile.exists());

    assertTrue(csrFile.exists());

    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "365",
         "--include-requested-extensions",
         "--no-prompt");
    assertTrue(certFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", certFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--no-prompt",
         "--display-keytool-command");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");

    manageCertificates(
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--allow-sha-1-signature-for-issuer-certificates");

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Check the usability for a certificate that has an RSA key with a modulus
    // that is smaller than 2048 bits.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--key-algorithm", "RSA",
         "--key-size-bits", "1024",
         "--signature-algorithm", "SHA256withRSA");

    assertTrue(ksFile.exists());

    assertTrue(csrFile.exists());

    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "365",
         "--no-prompt");
    assertTrue(certFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", rootCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--no-prompt",
         "--display-keytool-command");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Check the usability for a certificate with multiple errors.  This
    // certificate will use both a SHA-1 signature and a 1024-bit RSA key.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    manageCertificates(
         "generate-certificate-signing-request",
         "--output-file", csrFile.getAbsolutePath(),
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--key-algorithm", "RSA",
         "--key-size-bits", "1024",
         "--signature-algorithm", "SHA1withRSA");

    assertTrue(ksFile.exists());

    assertTrue(csrFile.exists());

    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    manageCertificates(
         "sign-certificate-signing-request",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--keystore", rootCAKeyStorePath,
         "--keystore-password", "password",
         "--signing-certificate-alias", rootCACertificateAlias,
         "--days-valid", "365",
         "--no-prompt");
    assertTrue(certFile.exists());

    manageCertificates(
         "import-certificate",
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", rootCACertificatePath,
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--no-prompt",
         "--display-keytool-command");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");

    manageCertificates(
         "list-certificates",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--verbose");


    // Check the usability for a certificate with multiple warnings.  This
    // certificate will be both self-signed and about to expire.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--days-valid", "10");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "check-certificate-usability",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert");
  }



  /**
   * Provides test coverage for the display-certificate-file subcommand.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDisplayCertificateFile()
         throws Exception
  {
    // Test with a valid PEM file that contains a single certificate using
    // non-verbose mode.
    manageCertificates(
         "display-certificate-file",
         "--certificate-file", serverCertificatePath,
         "--display-keytool-command");


    // Test with a valid PEM file that contains a single certificate using
    // verbose mode.
    manageCertificates(
         "display-certificate-file",
         "--certificate-file", serverCertificatePath,
         "--verbose",
         "--display-keytool-command");


    // Test with a valid PEM file that contains multiple certificates using
    // non-verbose mode.
    manageCertificates(
         "display-certificate-file",
         "--certificate-file", serverCertificateChainPath,
         "--display-keytool-command");


    // Test with a valid PEM file that contains multiple certificates using
    // verbose mode.
    manageCertificates(
         "display-certificate-file",
         "--certificate-file", serverCertificateChainPath,
         "--verbose",
         "--display-keytool-command");


    // Test with a valid DER file that contains a single certificate using
    // non-verbose mode.
    final List<X509Certificate> certList = ManageCertificates.
         readCertificatesFromFile(new File(serverCertificateChainPath));

    File outputFile = createTempFile();
    assertTrue(outputFile.exists());
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());

    try (FileOutputStream outputStream = new FileOutputStream(outputFile))
    {
      outputStream.write(certList.get(0).getX509CertificateBytes());
    }

    manageCertificates(
         "display-certificate-file",
         "--certificate-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");


    // Test with a valid DER file that contains a single certificate using
    // verbose mode.
    manageCertificates(
         "display-certificate-file",
         "--certificate-file", outputFile.getAbsolutePath(),
         "--verbose",
         "--display-keytool-command");


    // Test with a valid DER file that contains multiple certificates using
    // non-verbose mode.
    outputFile = createTempFile();
    assertTrue(outputFile.exists());
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());

    try (FileOutputStream outputStream = new FileOutputStream(outputFile))
    {
      for (final X509Certificate c : certList)
      {
        outputStream.write(c.getX509CertificateBytes());
      }
    }

    manageCertificates(
         "display-certificate-file",
         "--certificate-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");


    // Test with a valid DER file that contains multiple certificates using
    // verbose mode.
    manageCertificates(
         "display-certificate-file",
         "--certificate-file", outputFile.getAbsolutePath(),
         "--verbose",
         "--display-keytool-command");


    // Test with an empty file in non-verbose mode.
    manageCertificates(
         "display-certificate-file",
         "--certificate-file", emptyPasswordFilePath,
         "--display-keytool-command");


    // Test with an empty file in verbose mode.
    manageCertificates(
         "display-certificate-file",
         "--certificate-file", emptyPasswordFilePath,
         "--verbose",
         "--display-keytool-command");


    // Test with a file that has a malformed PEM-formatted certificate.
    outputFile = createTempFile(
         "-----BEGIN CERTIFICATE -----",
         "This isn't a valid certificate.",
         "-----END CERTIFICATE-----");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "display-certificate-file",
         "--certificate-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");


    // Test with a file that has a malformed DER-formatted certificate signing
    // request.
    assertTrue(outputFile.exists());
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());

    try (FileOutputStream outputStream = new FileOutputStream(outputFile))
    {
      new ASN1Sequence(
           new ASN1OctetString("This isn't a valid certificate")).writeTo(
                outputStream);
    }

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "display-certificate-file",
         "--certificate-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");
  }



  /**
   * Provides test coverage for the display-certificate-signing-request-file
   * subcommand.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDisplayCertificateSigningRequestFile()
         throws Exception
  {
    // Test with a valid, PEM-formatted CSR file.
    manageCertificates(
         "display-certificate-signing-request-file",
         "--certificate-signing-request-file", serverCSRPath,
         "--verbose",
         "--display-keytool-command");


    // Test with a valid, DER-formatted CSR file.
    PKCS10CertificateSigningRequest csr =
         ManageCertificates.readCertificateSigningRequestFromFile(
              new File(serverCSRPath));

    File outputFile = createTempFile();
    assertTrue(outputFile.exists());
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());

    try (FileOutputStream outputStream = new FileOutputStream(outputFile))
    {
      outputStream.write(csr.getPKCS10CertificateSigningRequestBytes());
    }

    manageCertificates(
         "display-certificate-signing-request-file",
         "--certificate-signing-request-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");


    // Test with a file that has a malformed PEM-formatted certificate signing
    // request.
    outputFile = createTempFile(
         "-----BEGIN NEW CERTIFICATE REQUEST-----",
         "This isn't a valid CSR.",
         "-----END NEW CERTIFICATE REQUEST-----");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "display-certificate-signing-request-file",
         "--certificate-signing-request-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");


    // Test with a file that has a malformed DER-formatted certificate signing
    // request.
    assertTrue(outputFile.exists());
    assertTrue(outputFile.delete());
    assertFalse(outputFile.exists());

    try (FileOutputStream outputStream = new FileOutputStream(outputFile))
    {
      new ASN1Sequence(
           new ASN1OctetString("This isn't a valid CSR")).writeTo(outputStream);
    }

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "display-certificate-signing-request-file",
         "--certificate-signing-request-file", outputFile.getAbsolutePath(),
         "--display-keytool-command");
  }



  /**
   * Provides test coverage for the {@code printExtensions} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPrintExtensions()
         throws Exception
  {
    final ManageCertificates tool = new ManageCertificates(null, null, null);

    tool.printExtensions(Collections.<X509CertificateExtension>emptyList(), "");

    final List<X509CertificateExtension> extensions = Arrays.asList(
         new AuthorityKeyIdentifierExtension(false,
              new ASN1OctetString("keyIdentifier"),
              new GeneralNamesBuilder().addDNSName("ca.example.com").build(),
              BigInteger.valueOf(12345L)),
        new CRLDistributionPointsExtension(false,
             Arrays.asList(
                  new CRLDistributionPoint(
                       new GeneralNamesBuilder().addDNSName(
                            "fullName.example.com").build(),
                       null,
                       new GeneralNamesBuilder().addDNSName(
                            "crlIssuer.example.com").build()),
                  new CRLDistributionPoint(
                       new RDN("CN=nameRelativeToCRLIssuer"),
                       null,
                       new GeneralNamesBuilder().addDNSName(
                            "crlIssuer.example.com").build()))),
         new IssuerAlternativeNameExtension(false,
              new GeneralNamesBuilder().
                   addOtherName(new OID("1.2.3.4"),
                        new ASN1OctetString("otherName1")).
                   addOtherName(new OID("1.2.3.5"),
                        new ASN1OctetString("otherName2")).
                   addRFC822Name("email1@example.com").
                   addRFC822Name("email2@example.com").
                   addDNSName("dns1.example.com").
                   addDNSName("dns2.example.com").
                   addX400Address(new ASN1OctetString("x400Address1")).
                   addX400Address(new ASN1OctetString("x400Address2")).
                   addDirectoryName(new DN("CN=Directory Name 1")).
                   addDirectoryName(new DN("CN=Directory Name 2")).
                   addEDIPartyName(new ASN1OctetString("ediPartyName1")).
                   addEDIPartyName(new ASN1OctetString("ediPartyName2")).
                   addUniformResourceIdentifier("https://uri1.example.com/").
                   addUniformResourceIdentifier("https://uri2.example.com/").
                   addIPAddress(InetAddress.getByName("127.0.0.1")).
                   addIPAddress(InetAddress.getByName("::1")).
                   addRegisteredID(new OID("1.2.3.6")).
                   addRegisteredID(new OID("1.2.3.7")).build()));
    tool.printExtensions(extensions, "");
  }



  /**
   * Provides test coverage for the {@code getKeystorePassword} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetKeystorePassword()
         throws Exception
  {
    // Test with a directly provided password that is too short.
    File ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "short",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificatePath,
         "--no-prompt",
         "--display-keytool-command");


    // Test with a password file that contains a single empty line.
    File passwordFile = createTempFile("");
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password-file", passwordFile.getAbsolutePath(),
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificatePath,
         "--no-prompt",
         "--display-keytool-command");


    // Test with a password file that contains a password that is too short.
    passwordFile = createTempFile("short");
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password-file", passwordFile.getAbsolutePath(),
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificatePath,
         "--no-prompt",
         "--display-keytool-command");


    // Test with prompting for a password when the keystore doesn't exist.
    // We'll cover a number of cases:
    // - An attempt with a password that is an empty string.
    // - An attempt with a password that is too short.
    // - An attempt in which the confirmation password doesn't match the
    //   first one that was provided.
    // - An attempt in which both passwords match.
    PasswordReader.setTestReader(new BufferedReader(new InputStreamReader(
         new ByteArrayInputStream(StaticUtils.getBytes(
              "\nshort\npassword\npasswodr\npassword\npassword\n")))));

    try
    {
      manageCertificates(
           "import-certificate",
           "--keystore", ksFile.getAbsolutePath(),
           "--prompt-for-keystore-password",
           "--keystore-type", "JKS",
           "--alias", serverCertificateAlias,
           "--certificate-file", serverCertificatePath,
           "--no-prompt",
           "--display-keytool-command");
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }


    // Test with prompting for a password when the keystore does exist.
    PasswordReader.setTestReader(new BufferedReader(new InputStreamReader(
         new ByteArrayInputStream(StaticUtils.getBytes("password\n")))));

    try
    {
      manageCertificates(
           "list-certificates",
           "--keystore", ksFile.getAbsolutePath(),
           "--prompt-for-keystore-password",
           "--display-keytool-command");
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Provides test coverage for the {@code getPrivateKeyPassword} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetPrivateKeyPassword()
         throws Exception
  {
    // Test with a directly provided password that is too short.
    File ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--private-key-password", "short",
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificatePath,
         "--no-prompt",
         "--display-keytool-command");


    // Test with a password file that contains a single empty line.
    File passwordFile = createTempFile("");
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--private-key-password-file", passwordFile.getAbsolutePath(),
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificatePath,
         "--no-prompt",
         "--display-keytool-command");


    // Test with a password file that contains a password that is too short.
    passwordFile = createTempFile("short");
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "import-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--private-key-password-file", passwordFile.getAbsolutePath(),
         "--keystore-type", "JKS",
         "--alias", serverCertificateAlias,
         "--certificate-file", serverCertificatePath,
         "--no-prompt",
         "--display-keytool-command");


    // Test with prompting for a password when the keystore (and therefore
    // private key) doesn't exist.  We'll cover a number of cases:
    // - An attempt with a password that is an empty string.
    // - An attempt with a password that is too short.
    // - An attempt in which the confirmation password doesn't match the
    //   first one that was provided.
    // - An attempt in which both passwords match.
    PasswordReader.setTestReader(new BufferedReader(new InputStreamReader(
         new ByteArrayInputStream(StaticUtils.getBytes(
              "\nshort\npassword\npasswodr\npassword\npassword\n")))));

    try
    {
      manageCertificates(
           "import-certificate",
           "--keystore", ksFile.getAbsolutePath(),
           "--keystore-password", "password",
           "--prompt-for-private-key-password",
           "--keystore-type", "JKS",
           "--alias", serverCertificateAlias,
           "--certificate-file", serverCertificatePath,
           "--no-prompt",
           "--display-keytool-command");
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }


    // Test with prompting for a password when the private key does exist.
    ksFile = copyFile(serverKeyStorePath);
    PasswordReader.setTestReader(new BufferedReader(new InputStreamReader(
         new ByteArrayInputStream(StaticUtils.getBytes("password\n")))));

    try
    {
      manageCertificates(
           "import-certificate",
           "--keystore", ksFile.getAbsolutePath(),
           "--keystore-password", "password",
           "--prompt-for-private-key-password",
           "--keystore-type", "JKS",
           "--alias", serverCertificateAlias,
           "--certificate-file", serverCertificateChainPath,
           "--no-prompt",
           "--display-keytool-command");
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Provides test coverage for the {@code inferKeystoreType} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInferKeystoreType()
         throws Exception
  {
    // Test the behavior with an empty file.
    manageCertificates(ResultCode.PARAM_ERROR, null,
         "list-certificates",
         "--keystore", emptyPasswordFilePath,
         "--keystore-password", "password",
         "--verbose",
         "--display-pem-certificate",
         "--display-keytool-command");
  }



  /**
   * Provides test coverage for the {@code getKeystore} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetKeystore()
         throws Exception
  {
    // Test the behavior with an unsupported keystore type.
    try
    {
      ManageCertificates.getKeystore("unsupported", new File(emptyKeyStorePath),
           "password".toCharArray());
      fail("Expected an exception when trying to instantiate a keystore of " +
           "an unsupported type.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test the behavior with a file that the server believes to be a PKCS #12
    // keystore, but isn't valid.
    File ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    try (FileOutputStream outputStream = new FileOutputStream(ksFile))
    {
      new ASN1Sequence(
           new ASN1OctetString("Not a valid PKCS #12 keystore")).writeTo(
                outputStream);
    }

    try
    {
      ManageCertificates.getKeystore("PKCS12", ksFile,
           "password".toCharArray());
      fail("Expected an exception when trying to load a keystore from a " +
           "malformed PKCS #12 file.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test the behavior with a file that the server believes to be a JKS
    // keystore, but isn't valid.
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    try (FileOutputStream outputStream = new FileOutputStream(ksFile))
    {
      final ByteStringBuffer buffer = new ByteStringBuffer();
      buffer.append(StaticUtils.byteArray(0xFE, 0xED, 0xFE, 0xED));
      buffer.append("This is not a valid JKS keystore.");

      buffer.write(outputStream);
    }

    try
    {
      ManageCertificates.getKeystore("JKS", ksFile,
           "password".toCharArray());
      fail("Expected an exception when trying to load a keystore from a " +
           "malformed JKS file.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the {@code readCertificatesFromFile} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadCertificatesFromFile()
         throws Exception
  {
    // Test with a file that is inferred to be in the DER format but isn't valid
    // DER.
    File certFile = createTempFile();
    assertTrue(certFile.exists());
    assertTrue(certFile.delete());
    assertFalse(certFile.exists());

    try (FileOutputStream outputStream = new FileOutputStream(certFile))
    {
      outputStream.write(0x30);
      outputStream.write(0x7F);
    }

    try
    {
      ManageCertificates.readCertificatesFromFile(certFile);
      fail("Expected an exception when trying to read a malformed DER file");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a PEM file that contains multiple consecutive begin headers.
    // For coverage, also include blank lines and comment lines.
    certFile = createTempFile(
         "# The next line is intentionally left blank",
         "",
         "-----BEGIN CERTIFICATE-----",
         "-----BEGIN CERTIFICATE-----",
         "-----END CERTIFICATE-----",
         "-----END CERTIFICATE-----");

    try
    {
      ManageCertificates.readCertificatesFromFile(certFile);
      fail("Expected an exception when trying to read a PEM file with " +
           "consecutive begin headers");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a PEM file that contains an end footer before a begin header.
    certFile = createTempFile(
         "-----END CERTIFICATE-----");

    try
    {
      ManageCertificates.readCertificatesFromFile(certFile);
      fail("Expected an exception when trying to read a PEM file that starts " +
           "with an end footer");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a PEM file that contains non-base64 data between the begin
    // header and end footer.
    certFile = createTempFile(
         "-----BEGIN CERTIFICATE-----",
         "This is not valid base64-encoded data",
         "-----END CERTIFICATE-----");

    try
    {
      ManageCertificates.readCertificatesFromFile(certFile);
      fail("Expected an exception when trying to read a PEM file without " +
           "valid base64 data");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a PEM file that contains base64-encoded data between the begin
    // header and end footer, but that data doesn't represent a valid
    // certificate.
    certFile = createTempFile(
         "-----BEGIN CERTIFICATE-----",
         Base64.encode("This is not a valid X.509 certificate"),
         "-----END CERTIFICATE-----");

    try
    {
      ManageCertificates.readCertificatesFromFile(certFile);
      fail("Expected an exception when trying to read a PEM file whose " +
           "base64-encoded data does not represent a valid certificate");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the {@code readPrivateKeyFromFile} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadPrivateKeyFromFile()
         throws Exception
  {
    // Test with an empty file.
    try
    {
      ManageCertificates.readPrivateKeyFromFile(
           new File(emptyPasswordFilePath));
      fail("Expected an exception when trying to read an empty file");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a valid DER-encoded private key.
    final PKCS8PrivateKey validPrivateKey =
         ManageCertificates.readPrivateKeyFromFile(new File(rootCAKeyPath));

    File keyFile = createTempFile();
    assertTrue(keyFile.exists());
    assertTrue(keyFile.delete());
    assertFalse(keyFile.exists());

    try (FileOutputStream outputStream = new FileOutputStream(keyFile))
    {
      outputStream.write(validPrivateKey.getPKCS8PrivateKeyBytes());
    }

    ManageCertificates.readPrivateKeyFromFile(keyFile);


    // Test with a file that contains multiple DER-encoded private keys (or
    // really just the same key twice).
    assertTrue(keyFile.exists());
    assertTrue(keyFile.delete());
    assertFalse(keyFile.exists());

    try (FileOutputStream outputStream = new FileOutputStream(keyFile))
    {
      outputStream.write(validPrivateKey.getPKCS8PrivateKeyBytes());
      outputStream.write(validPrivateKey.getPKCS8PrivateKeyBytes());
    }

    try
    {
      ManageCertificates.readPrivateKeyFromFile(keyFile);
      fail("Expected an exception when trying to read a DER file with " +
           "multiple private keys");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // Test with a file that is inferred to be in the DER format but isn't valid
    // DER.
    assertTrue(keyFile.exists());
    assertTrue(keyFile.delete());
    assertFalse(keyFile.exists());

    try (FileOutputStream outputStream = new FileOutputStream(keyFile))
    {
      outputStream.write(0x30);
      outputStream.write(0x7F);
    }

    try
    {
      ManageCertificates.readPrivateKeyFromFile(keyFile);
      fail("Expected an exception when trying to read a malformed DER file");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a PEM file that just contains comment lines and blank lines.
    keyFile = createTempFile(
         "# The next line is intentionally left blank",
         "",
         "# The previous line was blank.");

    try
    {
      ManageCertificates.readPrivateKeyFromFile(keyFile);
      fail("Expected an exception when trying to read a PEM file with " +
           "only comment lines and blank lines");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a PEM file that contains multiple private keys (or just two
    // copies of the same key).
    keyFile = createTempFile(
         "-----BEGIN PRIVATE KEY-----",
         Base64.encode(validPrivateKey.getPKCS8PrivateKeyBytes()),
         "-----END PRIVATE KEY-----",
         "-----BEGIN PRIVATE KEY-----",
         Base64.encode(validPrivateKey.getPKCS8PrivateKeyBytes()),
         "-----END PRIVATE KEY-----");

    try
    {
      ManageCertificates.readPrivateKeyFromFile(keyFile);
      fail("Expected an exception when trying to read a PEM file with " +
           "multiple private keys.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a PEM file that contains multiple consecutive begin headers.
    // For coverage, also include blank lines and comment lines.
    keyFile = createTempFile(
         "-----BEGIN PRIVATE KEY-----",
         "-----BEGIN PRIVATE KEY-----",
         "-----END PRIVATE KEY-----",
         "-----END PRIVATE KEY-----");

    try
    {
      ManageCertificates.readPrivateKeyFromFile(keyFile);
      fail("Expected an exception when trying to read a PEM file with " +
           "consecutive begin headers");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a PEM file that contains data before the begin header.
    keyFile = createTempFile(
         Base64.encode(validPrivateKey.getPKCS8PrivateKeyBytes()),
         "-----END PRIVATE KEY-----");

    try
    {
      ManageCertificates.readPrivateKeyFromFile(keyFile);
      fail("Expected an exception when trying to read a PEM file that starts " +
           "with data before a begin header.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a PEM file that contains an end footer before a begin header.
    keyFile = createTempFile(
         "-----END PRIVATE KEY-----");

    try
    {
      ManageCertificates.readPrivateKeyFromFile(keyFile);
      fail("Expected an exception when trying to read a PEM file that starts " +
           "with an end footer");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a PEM file that contains non-base64 data between the begin
    // header and end footer.
    keyFile = createTempFile(
         "-----BEGIN PRIVATE KEY-----",
         "This is not valid base64-encoded data",
         "-----END PRIVATE KEY-----");

    try
    {
      ManageCertificates.readPrivateKeyFromFile(keyFile);
      fail("Expected an exception when trying to read a PEM file without " +
           "valid base64 data");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a PEM file that contains base64-encoded data between the begin
    // header and end footer, but that data doesn't represent a valid PKCS #8
    // private key.
    keyFile = createTempFile(
         "-----BEGIN PRIVATE KEY-----",
         Base64.encode("This is not a valid PKCS #8 private key"),
         "-----END PRIVATE KEY-----");

    try
    {
      ManageCertificates.readPrivateKeyFromFile(keyFile);
      fail("Expected an exception when trying to read a PEM file whose " +
           "base64-encoded data does not represent a valid private key");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the
   * {@code readCertificateSigningRequestFromFile} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadCertificateSigningRequestFromFile()
         throws Exception
  {
    // Test with an empty file.
    try
    {
      ManageCertificates.readCertificateSigningRequestFromFile(
           new File(emptyPasswordFilePath));
      fail("Expected an exception when trying to read an empty file");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a valid DER-encoded CSR.
    final PKCS10CertificateSigningRequest validCSR =
         ManageCertificates.readCertificateSigningRequestFromFile(
              new File(intermediateCACSRPath));

    File csrFile = createTempFile();
    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    try (FileOutputStream outputStream = new FileOutputStream(csrFile))
    {
      outputStream.write(validCSR.getPKCS10CertificateSigningRequestBytes());
    }

    ManageCertificates.readCertificateSigningRequestFromFile(csrFile);


    // Test with a file that contains multiple DER-encoded CSRs (or really just
    // the same CSR twice).
    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    try (FileOutputStream outputStream = new FileOutputStream(csrFile))
    {
      outputStream.write(validCSR.getPKCS10CertificateSigningRequestBytes());
      outputStream.write(validCSR.getPKCS10CertificateSigningRequestBytes());
    }

    try
    {
      ManageCertificates.readCertificateSigningRequestFromFile(csrFile);
      fail("Expected an exception when trying to read a DER file with " +
           "multiple CSRs");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a file that is inferred to be in the DER format but isn't valid
    // DER.
    assertTrue(csrFile.exists());
    assertTrue(csrFile.delete());
    assertFalse(csrFile.exists());

    try (FileOutputStream outputStream = new FileOutputStream(csrFile))
    {
      outputStream.write(0x30);
      outputStream.write(0x7F);
    }

    try
    {
      ManageCertificates.readCertificateSigningRequestFromFile(csrFile);
      fail("Expected an exception when trying to read a malformed DER file");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a PEM file that just contains comment lines and blank lines.
    csrFile = createTempFile(
         "# The next line is intentionally left blank",
         "",
         "# The previous line was blank.");

    try
    {
      ManageCertificates.readCertificateSigningRequestFromFile(csrFile);
      fail("Expected an exception when trying to read a PEM file with " +
           "only comment lines and blank lines");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a PEM file that contains multiple CSRs (or just two copies of
    // the same CSR).
    csrFile = createTempFile(
         "-----BEGIN CERTIFICATE REQUEST-----",
         Base64.encode(validCSR.getPKCS10CertificateSigningRequestBytes()),
         "-----END CERTIFICATE REQUEST-----",
         "-----BEGIN CERTIFICATE REQUEST-----",
         Base64.encode(validCSR.getPKCS10CertificateSigningRequestBytes()),
         "-----END CERTIFICATE REQUEST-----");

    try
    {
      ManageCertificates.readCertificateSigningRequestFromFile(csrFile);
      fail("Expected an exception when trying to read a PEM file with " +
           "multiple CSRs.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a PEM file that contains multiple consecutive begin headers.
    // For coverage, also include blank lines and comment lines.
    csrFile = createTempFile(
         "-----BEGIN CERTIFICATE REQUEST-----",
         "-----BEGIN CERTIFICATE REQUEST-----",
         "-----END CERTIFICATE REQUEST-----",
         "-----END CERTIFICATE REQUEST-----");

    try
    {
      ManageCertificates.readCertificateSigningRequestFromFile(csrFile);
      fail("Expected an exception when trying to read a PEM file with " +
           "consecutive begin headers");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a PEM file that is missing the end footer.
    csrFile = createTempFile(
         "-----BEGIN CERTIFICATE REQUEST-----",
         Base64.encode(validCSR.getPKCS10CertificateSigningRequestBytes()));

    try
    {
      ManageCertificates.readCertificateSigningRequestFromFile(csrFile);
      fail("Expected an exception when trying to read a PEM file that is " +
           "missing the end footer.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a PEM file that contains data before the begin header.
    csrFile = createTempFile(
         Base64.encode(validCSR.getPKCS10CertificateSigningRequestBytes()),
         "-----END CERTIFICATE REQUEST-----");

    try
    {
      ManageCertificates.readCertificateSigningRequestFromFile(csrFile);
      fail("Expected an exception when trying to read a PEM file that starts " +
           "with data before a begin header.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a PEM file that contains an end footer before a begin header.
    csrFile = createTempFile(
         "-----END CERTIFICATE REQUEST-----");

    try
    {
      ManageCertificates.readCertificateSigningRequestFromFile(csrFile);
      fail("Expected an exception when trying to read a PEM file that starts " +
           "with an end footer");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a PEM file that contains non-base64 data between the begin
    // header and end footer.
    csrFile = createTempFile(
         "-----BEGIN CERTIFICATE REQUEST-----",
         "This is not valid base64-encoded data",
         "-----END CERTIFICATE REQUEST-----");

    try
    {
      ManageCertificates.readCertificateSigningRequestFromFile(csrFile);
      fail("Expected an exception when trying to read a PEM file without " +
           "valid base64 data");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Test with a PEM file that contains base64-encoded data between the begin
    // header and end footer, but that data doesn't represent a valid PKCS #10
    // CSR.
    csrFile = createTempFile(
         "-----BEGIN CERTIFICATE REQUEST-----",
         Base64.encode("This is not a valid PKCS #10 CSR"),
         "-----END CERTIFICATE REQUEST-----");

    try
    {
      ManageCertificates.readCertificateSigningRequestFromFile(csrFile);
      fail("Expected an exception when trying to read a PEM file whose " +
           "base64-encoded data does not represent a valid CSR");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the {@code getUserFriendlyKeystoreType} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetUserFriendlyKeystoreType()
         throws Exception
  {
    assertEquals(ManageCertificates.getUserFriendlyKeystoreType("JKS"), "JKS");

    assertEquals(ManageCertificates.getUserFriendlyKeystoreType("jks"), "JKS");

    assertEquals(
         ManageCertificates.getUserFriendlyKeystoreType("PKCS12"),
         "PKCS #12");

    assertEquals(
         ManageCertificates.getUserFriendlyKeystoreType("pkcs12"),
         "PKCS #12");

    assertEquals(
         ManageCertificates.getUserFriendlyKeystoreType("PKCS 12"),
         "PKCS #12");

    assertEquals(
         ManageCertificates.getUserFriendlyKeystoreType("pkcs12"),
         "PKCS #12");

    assertEquals(
         ManageCertificates.getUserFriendlyKeystoreType("PKCS#12"),
         "PKCS #12");

    assertEquals(
         ManageCertificates.getUserFriendlyKeystoreType("pkcs#12"),
         "PKCS #12");

    assertEquals(
         ManageCertificates.getUserFriendlyKeystoreType("PKCS #12"),
         "PKCS #12");

    assertEquals(
         ManageCertificates.getUserFriendlyKeystoreType("pkcs #12"),
         "PKCS #12");
  }



  /**
   * Tests to ensure that the manage-certificates tool will properly reject
   * subject alternative name values that are DNS names and IP addresses if they
   * are not valid IA5 strings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSubjectAlternativeNameIA5Validation()
         throws Exception
  {
    // Tests with a minimal set of arguments for a new certificate using a
    // JKS keystore that doesn't already exist.
    File ksFile = createTempFile();
    assertTrue(ksFile.exists());
    assertTrue(ksFile.delete());
    assertFalse(ksFile.exists());

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--subject-alternative-name-dns", "");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--subject-alternative-name-email-address", "");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--subject-alternative-name-dns", "jalape\u00f1o.example.com");

    manageCertificates(ResultCode.PARAM_ERROR, null,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corporation,C=US",
         "--subject-alternative-name-email-address",
         "jalape\u00f1o@example.com");
  }



  /**
   * Runs the manage-certificates tool with the provided arguments and expects
   * a success result code.
   *
   * @param  args  The command-line arguments to provide when running the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void manageCertificates(final String... args)
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
   * Retrieves a copy of the keystore loaded from the specified file.
   *
   * @param  path  The path to the keystore file.  It must not be {@code null}.
   * @param  type  The keystore type.  It must not be {@code null}.
   *
   * @return  The keystore loaded from the specified file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static KeyStore getKeystore(final String path, final String type)
          throws Exception
  {
    return getKeystore(path, type, "password");
  }



  /**
   * Retrieves a copy of the keystore loaded from the specified file.
   *
   * @param  path      The path to the keystore file.  It must not be
   *                   {@code null}.
   * @param  type      The keystore type.  It must not be {@code null}.
   * @param  password  The password for the keystore.  It must not be
   *                   {@code null}.
   *
   * @return  The keystore loaded from the specified file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static KeyStore getKeystore(final String path, final String type,
                                      final String password)
          throws Exception
  {
    final KeyStore keystore = CryptoHelper.getKeyStore(type);

    try (FileInputStream inputStream = new FileInputStream(path))
    {
      keystore.load(inputStream, password.toCharArray());
    }

    return keystore;
  }



  /**
   * Retrieves a set containing all of the aliases in the provided keystore.
   *
   * @param  keystore            The keystore for which to get the aliases.
   * @param  includeKeyAliases   Indicates whether to include aliases that are
   *                             associated with key entries.
   * @param  includeCertAliases  Indicates whether to include aliases that are
   *                             associated with certificate entries.
   *
   * @return  A set containing all of the aliases in the provided keystore.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static Set<String> getAliases(final KeyStore keystore,
                                        final boolean includeKeyAliases,
                                        final boolean includeCertAliases)
          throws Exception
  {
    final HashSet<String> aliases = new HashSet<>(10);
    final Enumeration<String> aliasEnumeration = keystore.aliases();
    while (aliasEnumeration.hasMoreElements())
    {
      final String alias = aliasEnumeration.nextElement();
      if (includeKeyAliases && keystore.isKeyEntry(alias))
      {
        aliases.add(alias);
      }
      else if (includeCertAliases && keystore.isCertificateEntry(alias))
      {
        aliases.add(alias);
      }
    }

    return aliases;
  }



  /**
   * Retrieves the certificate stored in the specified certificate entry in the
   * keystore.
   *
   * @param  keystore  The keystore containing the certificate to retrieve.
   * @param  alias     The alias of the certificate entry to retrieve.
   *
   * @return  The requested certificate, or {@code null} if the certificate
   *          entry does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static X509Certificate getCertificate(final KeyStore keystore,
                                                final String alias)
          throws Exception
  {
    final Certificate c = keystore.getCertificate(alias);
    if (c == null)
    {
      return null;
    }

    return new X509Certificate(c.getEncoded());
  }



  /**
   * Retrieves the certificate chain in the specified key entry in the keystore.
   *
   * @param  keystore  The keystore containing the certificate chain to
   *                   retrieve.
   * @param  alias     The alias of the key entry to retrieve.
   *
   * @return  The requested certificate chain, or {@code null} if the
   *          key entry does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static X509Certificate[] getCertificateChain(final KeyStore keystore,
                                                       final String alias)
          throws Exception
  {
    final Certificate[] chain = keystore.getCertificateChain(alias);
    if (chain == null)
    {
      return null;
    }

    final X509Certificate[] x509Chain = new X509Certificate[chain.length];
    for (int i=0; i < chain.length; i++)
    {
      x509Chain[i] = new X509Certificate(chain[i].getEncoded());
    }

    return x509Chain;
  }



  /**
   * Retrieves the private key in the specified key entry in the keystore.
   *
   * @param  keystore  The keystore containing the private key to retrieve.
   * @param  alias     The alias of the key entry to retrieve.
   *
   * @return  The requested private key, or {@code null} if the key entry does
   *          not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static PKCS8PrivateKey getPrivateKey(final KeyStore keystore,
                                               final String alias)
          throws Exception
  {
    final Key key = keystore.getKey(alias, "password".toCharArray());
    if (key == null)
    {
      return null;
    }

    return new PKCS8PrivateKey(key.getEncoded());
  }



  /**
   * Retrieves a set containing the specified items.
   *
   * @param  items  The items to include in the set.
   *
   * @return  The set that was created.
   */
  private static Set<String> setOf(final String... items)
  {
    return new HashSet<>(Arrays.asList(items));
  }



  /**
   * Counts the number of PEM-formatted entries in the specified file.
   *
   * @param  path  The path to the file to examine.
   *
   * @return  The number of PEM-formatted entries in the specified file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static int countPEMEntries(final String path)
          throws Exception
  {
    int numBegin = 0;
    int numEnd = 0;
    try (BufferedReader reader = new BufferedReader(new FileReader(path)))
    {
      while (true)
      {
        final String line = reader.readLine();
        if (line == null)
        {
          break;
        }

        if (line.startsWith("-----BEGIN"))
        {
          numBegin++;
        }
        else if (line.startsWith("-----END"))
        {
          numEnd++;
        }
        else
        {
          assertEquals(numBegin, (numEnd + 1));
        }
      }
    }

    assertEquals(numBegin, numEnd);
    return numBegin;
  }



  /**
   * Counts the number of DER-formatted entries in the specified file.
   *
   * @param  path  The path to the file to examine.
   *
   * @return  The number of DER-formatted entries in the specified file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static int countDEREntries(final String path)
          throws Exception
  {
    try (FileInputStream inputStream = new FileInputStream(path))
    {
      int numElements = 0;
      while (true)
      {
        final ASN1Element element = ASN1Element.readFrom(inputStream);
        if (element == null)
        {
          return numElements;
        }
        else
        {
          numElements++;
        }
      }
    }
  }



  /**
   * Creates a copy of the specified file.
   *
   * @param  f  The file to copy.
   *
   * @return  A handle to the file that was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static File copyFile(final String f)
          throws Exception
  {
    final File n = createTempFile();
    assertTrue(n.delete());

    try (FileInputStream inputStream = new FileInputStream(f))
    {
      try (FileOutputStream outputStream = new FileOutputStream(n))
      {
        final byte[] buffer = new byte[8192];
        while (true)
        {
          final int bytesRead = inputStream.read(buffer);
          if (bytesRead < 0)
          {
            break;
          }

          outputStream.write(buffer, 0, bytesRead);
        }
      }
    }

    return n;
  }



  /**
   * Formats the provided timestamp in a format that is appropriate for use as
   * a validity start time value provided to the manage-certificates tool.
   *
   * @param  time  The timestamp to be formatted.
   *
   * @return  The formatted timestamp.
   */
  private static String formatValidityStartTime(final long time)
  {
    final String dateFormatString = "yyyyMMddHHmmss";
    return new SimpleDateFormat(dateFormatString).format(new Date(time));
  }
}
