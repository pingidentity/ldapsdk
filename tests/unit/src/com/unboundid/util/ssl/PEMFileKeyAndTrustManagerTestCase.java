/*
 * Copyright 2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021 Ping Identity Corporation
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
 * Copyright (C) 2021 Ping Identity Corporation
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
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import javax.security.auth.x500.X500Principal;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ssl.cert.ManageCertificates;



/**
 * This class provides a set of test cases for the PEM file key and trust
 * managers.
 */
public final class PEMFileKeyAndTrustManagerTestCase
       extends LDAPSDKTestCase
{
  /**
   * The subject DN for the end entity certificate.
   */
  private static final String END_ENTITY_CERT_SUBJECT_DN =
       "CN=End Entity,O=Example Corp,C=US";



  /**
   * The subject DN for the intermediate CA certificate.
   */
  private static final String INTERMEDIATE_CA_CERT_SUBJECT_DN =
       "CN=Intermediate CA,O=Example Corp,C=US";



  /**
   * The subject DN for a nonexistent certificate.
   */
  private static final String NONEXISTENT_CERT_SUBJECT_DN =
       "CN=Nonexistent,O=Example Corp,C=US";



  /**
   * The subject DN for the root CA certificate.
   */
  private static final String ROOT_CA_CERT_SUBJECT_DN =
       "CN=Intermediate CA,O=Example Corp,C=US";



  /**
   * The subject DN for the self-signed certificate.
   */
  private static final String SELF_SIGNED_CERT_SUBJECT_DN =
       "CN=Self Signed,O=Example Corp,C=US";



  /**
   * An array of key types containing both elliptic curve and RSA key types.
   */
  private static final String[] EC_AND_RSA_KEY_TYPES =
  {
    "EC",
    "RSA"
  };



  /**
   * An array of key types containing only the elliptic curve key type.
   */
  private static final String[] ONLY_EC_KEY_TYPE =
  {
    "EC"
  };



  /**
   * An array of key types containing only the RSA key type.
   */
  private static final String[] ONLY_RSA_KEY_TYPE =
  {
    "RSA"
  };



  // A file containing the PEM representation of an end entity X.509
  // certificate.
  private File endEntityCertPEMFile = null;

  // A file containing the PEM representation of the PKCS #8 private key for the
  // end entity certificate.
  private File endEntityKeyPEMFile = null;

  // A file containing the PEM representation of an intermediate CA X.509
  // certificate.
  private File intermediateCACertPEMFile = null;

  // A file containing the PEM representation of a root CA X.509 certificate.
  private File rootCACertPEMFile = null;

  // A file containing the PEM representation of a self-signed X.509
  // certificate.
  private File selfSignedCertPEMFile = null;

  // A file containing the PEM representation of the PKCS #8 private key for the
  // self-signed certificate.
  private File selfSignedKeyPEMFile = null;



  /**
   * Sets up a number of PEM files for use in testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    // Generate a key store with a self-signed RSA certificate, and export both
    // the certificate and the private key to PEM files.
    final File selfSignedKeyStoreFile = createTempFile();
    assertTrue(selfSignedKeyStoreFile.delete());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", selfSignedKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "cert",
         "--subject-dn", SELF_SIGNED_CERT_SUBJECT_DN,
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA");

    selfSignedCertPEMFile = createTempFile();
    assertTrue(selfSignedCertPEMFile.delete());

    manageCertificates(
         "export-certificate",
         "--keystore", selfSignedKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "cert",
         "--output-format", "PEM",
         "--output-file", selfSignedCertPEMFile.getAbsolutePath());

    selfSignedKeyPEMFile = createTempFile();
    assertTrue(selfSignedKeyPEMFile.delete());

    manageCertificates(
         "export-private-key",
         "--keystore", selfSignedKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "cert",
         "--output-format", "PEM",
         "--output-file", selfSignedKeyPEMFile.getAbsolutePath());


    // Generate a key store for a self-signed root CA certificate and export
    // that certificate to a PEM file.
    final File rootCAKeyStoreFile = createTempFile();
    assertTrue(rootCAKeyStoreFile.delete());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", rootCAKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "root-ca-cert",
         "--subject-dn", ROOT_CA_CERT_SUBJECT_DN,
         "--key-algorithm", "EC",
         "--key-size-bits", "256",
         "--signature-algorithm", "SHA256withECDSA");

    rootCACertPEMFile = createTempFile();
    assertTrue(rootCACertPEMFile.delete());

    manageCertificates(
         "export-certificate",
         "--keystore", rootCAKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "root-ca-cert",
         "--output-format", "PEM",
         "--output-file", rootCACertPEMFile.getAbsolutePath());


    // Generate a key store for an intermediate CA certificate that is signed by
    // the root CA.  Export the intermediate CA certificate to a PEM file.
    final File intermediateCAKeyStoreFile = createTempFile();
    assertTrue(intermediateCAKeyStoreFile.delete());

    final File intermediateCACertCSRFile = createTempFile();
    assertTrue(intermediateCACertCSRFile.delete());

    manageCertificates(
         "generate-certificate-signing-request",
         "--keystore", intermediateCAKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "intermediate-ca-cert",
         "--subject-dn", INTERMEDIATE_CA_CERT_SUBJECT_DN,
         "--key-algorithm", "EC",
         "--key-size-bits", "256",
         "--signature-algorithm", "SHA256withECDSA",
         "--output-format", "PEM",
         "--output-file", intermediateCACertCSRFile.getAbsolutePath());

    intermediateCACertPEMFile = createTempFile();
    assertTrue(intermediateCACertPEMFile.delete());

    manageCertificates(
         "sign-certificate-signing-request",
         "--keystore", rootCAKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--request-input-file", intermediateCACertCSRFile.getAbsolutePath(),
         "--certificate-output-file",
              intermediateCACertPEMFile.getAbsolutePath(),
         "--output-format", "PEM",
         "--signing-certificate-alias", "root-ca-cert",
         "--include-requested-extensions",
         "--no-prompt");

    manageCertificates(
         "import-certificate",
         "--keystore", intermediateCAKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "intermediate-ca-cert",
         "--certificate-file", intermediateCACertPEMFile.getAbsolutePath(),
         "--certificate-file", rootCACertPEMFile.getAbsolutePath(),
         "--no-prompt");


    // Generate a key store for an end entity certificate that is signed by the
    // intermediate CA.  Export the end entity certificate and private key to
    // PEM files.
    final File endEntityKeyStoreFile = createTempFile();
    assertTrue(endEntityKeyStoreFile.delete());

    final File endEntityCertCSRFile = createTempFile();
    assertTrue(endEntityCertCSRFile.delete());

    manageCertificates(
         "generate-certificate-signing-request",
         "--keystore", endEntityKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "end-entity-cert",
         "--subject-dn", END_ENTITY_CERT_SUBJECT_DN,
         "--key-algorithm", "EC",
         "--key-size-bits", "256",
         "--signature-algorithm", "SHA256withECDSA",
         "--output-format", "PEM",
         "--output-file", endEntityCertCSRFile.getAbsolutePath());

    endEntityCertPEMFile = createTempFile();
    assertTrue(endEntityCertPEMFile.delete());

    manageCertificates(
         "sign-certificate-signing-request",
         "--keystore", intermediateCAKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--request-input-file", endEntityCertCSRFile.getAbsolutePath(),
         "--certificate-output-file",
              endEntityCertPEMFile.getAbsolutePath(),
         "--output-format", "PEM",
         "--signing-certificate-alias", "intermediate-ca-cert",
         "--include-requested-extensions",
         "--no-prompt");

    manageCertificates(
         "import-certificate",
         "--keystore", endEntityKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "end-entity-cert",
         "--certificate-file", endEntityCertPEMFile.getAbsolutePath(),
         "--certificate-file", intermediateCACertPEMFile.getAbsolutePath(),
         "--certificate-file", rootCACertPEMFile.getAbsolutePath(),
         "--no-prompt");

    endEntityKeyPEMFile = createTempFile();
    assertTrue(endEntityKeyPEMFile.delete());

    manageCertificates(
         "export-private-key",
         "--keystore", endEntityKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "end-entity-cert",
         "--output-format", "PEM",
         "--output-file", endEntityKeyPEMFile.getAbsolutePath());
  }



  /**
   * Tests with a key and trust manager created for a single self-signed
   * certificate.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleFileSingleCertificate()
         throws Exception
  {
    // Create a key manager from the PEM files.
    final PEMFileKeyManager keyManager =
         new PEMFileKeyManager(selfSignedCertPEMFile, selfSignedKeyPEMFile);


    // Create some principals to use for testing.
    final Principal matchingPrincipal =
         new X500Principal(SELF_SIGNED_CERT_SUBJECT_DN);
    final Principal nonMatchingPrincipal =
         new X500Principal(NONEXISTENT_CERT_SUBJECT_DN);

    final Principal[] onlyMatchingPrincipal =
    {
      matchingPrincipal
    };

    final Principal[] onlyNonMatchingPrincipal =
    {
      nonMatchingPrincipal
    };

    final Principal[] matchingAndNonMatchingPrincipals =
    {
      matchingPrincipal,
      nonMatchingPrincipal
    };

    final Principal[] nonMatchingAndMatchingPrincipals =
    {
      nonMatchingPrincipal,
      matchingPrincipal
    };


    // Test the key manager methods for choosing an alias.
    final String alias = keyManager.chooseClientAlias(null, null, null);
    assertNotNull(alias);

    assertNotNull(keyManager.chooseClientAlias(ONLY_RSA_KEY_TYPE, null, null));
    assertEquals(keyManager.chooseClientAlias(ONLY_RSA_KEY_TYPE, null, null),
         alias);

    assertNull(keyManager.chooseClientAlias(ONLY_EC_KEY_TYPE, null, null));

    assertNotNull(
         keyManager.chooseClientAlias(EC_AND_RSA_KEY_TYPES, null, null));
    assertEquals(
         keyManager.chooseClientAlias(EC_AND_RSA_KEY_TYPES, null, null),
         alias);

    assertNotNull(keyManager.chooseServerAlias(null, null, null));
    assertEquals(keyManager.chooseServerAlias(null, null, null), alias);

    assertNotNull(keyManager.chooseServerAlias("RSA", null, null));
    assertEquals(keyManager.chooseServerAlias("RSA", null, null),
         alias);

    assertNull(keyManager.chooseServerAlias("EC", null, null));

    assertNotNull(
         keyManager.chooseClientAlias(null, onlyMatchingPrincipal, null));
    assertEquals(
         keyManager.chooseClientAlias(null, onlyMatchingPrincipal, null),
         alias);

    assertNull(
         keyManager.chooseClientAlias(null, onlyNonMatchingPrincipal, null));

    assertNotNull(
         keyManager.chooseClientAlias(null, matchingAndNonMatchingPrincipals,
              null));
    assertEquals(
         keyManager.chooseClientAlias(null, matchingAndNonMatchingPrincipals,
              null),
         alias);

    assertNotNull(
         keyManager.chooseClientAlias(null, nonMatchingAndMatchingPrincipals,
              null));
    assertEquals(
         keyManager.chooseClientAlias(null, nonMatchingAndMatchingPrincipals,
              null),
         alias);

    assertNotNull(
         keyManager.chooseServerAlias(null, onlyMatchingPrincipal, null));
    assertEquals(
         keyManager.chooseServerAlias(null, onlyMatchingPrincipal, null),
         alias);

    assertNull(
         keyManager.chooseServerAlias(null, onlyNonMatchingPrincipal, null));

    assertNotNull(
         keyManager.chooseServerAlias(null, matchingAndNonMatchingPrincipals,
              null));
    assertEquals(
         keyManager.chooseServerAlias(null, matchingAndNonMatchingPrincipals,
              null),
         alias);

    assertNotNull(
         keyManager.chooseServerAlias(null, nonMatchingAndMatchingPrincipals,
              null));
    assertEquals(
         keyManager.chooseServerAlias(null, nonMatchingAndMatchingPrincipals,
              null),
         alias);


    // Test the key manager methods for getting applicable aliases.
    final String[] aliasArray = new String[] { alias };

    assertNotNull(keyManager.getClientAliases(null, null));
    assertEquals(keyManager.getClientAliases(null, null), aliasArray);

    assertNotNull(keyManager.getClientAliases("RSA", null));
    assertEquals(keyManager.getClientAliases("RSA", null), aliasArray);

    assertNull(keyManager.getClientAliases("EC", null));

    assertNotNull(keyManager.getServerAliases(null, onlyMatchingPrincipal));
    assertEquals(keyManager.getServerAliases(null, onlyMatchingPrincipal),
         aliasArray);

    assertNull(keyManager.getServerAliases(null, onlyNonMatchingPrincipal));

    assertNotNull(
         keyManager.getServerAliases(null, matchingAndNonMatchingPrincipals));
    assertEquals(
         keyManager.getServerAliases(null, matchingAndNonMatchingPrincipals),
         aliasArray);

    assertNotNull(
         keyManager.getServerAliases(null, nonMatchingAndMatchingPrincipals));
    assertEquals(
         keyManager.getServerAliases(null, nonMatchingAndMatchingPrincipals),
         aliasArray);


    // Test the methods for getting the certificate chain.
    assertNotNull(keyManager.getCertificateChain(alias));
    assertEquals(keyManager.getCertificateChain(alias).length, 1);

    assertNotNull(keyManager.getCertificateChain(null));
    assertEquals(keyManager.getCertificateChain(null).length, 1);

    assertNotNull(keyManager.getCertificateChain("arbitrary string"));
    assertEquals(keyManager.getCertificateChain("arbitrary string").length, 1);


    // Test the methods for getting the private key.
    assertNotNull(keyManager.getPrivateKey(alias));

    assertNotNull(keyManager.getPrivateKey(null));

    assertNotNull(keyManager.getPrivateKey("arbitrary string"));


    // Create a trust manager from the certificate PEM file.
    final PEMFileTrustManager trustManager =
         new PEMFileTrustManager(selfSignedCertPEMFile);


    // Test the checkClientTrusted and checkServerTrusted methods.
    trustManager.checkClientTrusted(keyManager.getCertificateChain(null),
         "RSA");

    trustManager.checkServerTrusted(keyManager.getCertificateChain(null),
         "ECDHE_RSA");


    // Test the getAcceptedIssuers method.
    assertNotNull(trustManager.getAcceptedIssuers());
    assertEquals(trustManager.getAcceptedIssuers().length, 1);


    // Create an SSLUtil instance that uses the key and trust manager.  Use that
    // to create an in-memory directory server instance and verify that we can
    // establish a secure connection to it.
    final SSLUtil sslUtil = new SSLUtil(keyManager, trustManager);

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0,
              sslUtil.createSSLServerSocketFactory(),
              sslUtil.createSSLSocketFactory(),
              null));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();

    try (LDAPConnection conn = new LDAPConnection(
              sslUtil.createSSLSocketFactory(), "127.0.0.1",
              ds.getListenPort("LDAPS")))
    {
      assertNotNull(conn.getRootDSE());
    }

    ds.shutDown(true);
  }



  /**
   * Tests with a key and trust manager created for a certificate chain
   * containing end entity, intermediate CA, and root CA certificates.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCertificateChain()
         throws Exception
  {
    // Create a PEM file that combines the contents of the intermediate CA and
    // root CA certificates.
    final File combinedCACertsPEMFile = createTempFile();
    assertTrue(combinedCACertsPEMFile.delete());

    try (PrintWriter w = new PrintWriter(combinedCACertsPEMFile))
    {
      for (final String line :
           StaticUtils.readFileLines(intermediateCACertPEMFile))
      {
        w.println(line);
      }

      for (final String line :
           StaticUtils.readFileLines(rootCACertPEMFile))
      {
        w.println(line);
      }
    }


    // Create a key manager from the PEM files.  Use the end entity certificate
    // by itself and the intermediate and root CA certificates in a combined
    // file.
    final PEMFileKeyManager keyManager = new PEMFileKeyManager(
         new File[]
         {
           endEntityCertPEMFile,
           combinedCACertsPEMFile
         },
         endEntityKeyPEMFile);


    // Create some principals to use for testing.
    final Principal endEntityPrincipal =
         new X500Principal(END_ENTITY_CERT_SUBJECT_DN);
    final Principal intermediateCAPrincipal =
         new X500Principal(INTERMEDIATE_CA_CERT_SUBJECT_DN);
    final Principal rootCAPrincipal =
         new X500Principal(ROOT_CA_CERT_SUBJECT_DN);
    final Principal nonMatchingPrincipal =
         new X500Principal(NONEXISTENT_CERT_SUBJECT_DN);

    final Principal[] onlyEndEntityPrincipal =
    {
      endEntityPrincipal
    };

    final Principal[] onlyIntermediateCAPrincipal =
    {
      intermediateCAPrincipal
    };

    final Principal[] onlyRootCAPrincipal =
    {
      rootCAPrincipal
    };

    final Principal[] onlyCAPrincipals =
    {
      intermediateCAPrincipal,
      rootCAPrincipal
    };

    final Principal[] onlyNonMatchingPrincipal =
    {
      nonMatchingPrincipal
    };

    final Principal[] matchingAndNonMatchingPrincipals =
    {
      nonMatchingPrincipal,
      rootCAPrincipal
    };


    // Test the key manager methods for choosing an alias.
    final String alias = keyManager.chooseClientAlias(null, null, null);
    assertNotNull(alias);

    assertNull(keyManager.chooseClientAlias(ONLY_RSA_KEY_TYPE, null, null));

    assertNotNull(keyManager.chooseClientAlias(ONLY_EC_KEY_TYPE, null, null));
    assertEquals(keyManager.chooseClientAlias(ONLY_EC_KEY_TYPE, null, null),
         alias);

    assertNotNull(
         keyManager.chooseClientAlias(EC_AND_RSA_KEY_TYPES, null, null));
    assertEquals(
         keyManager.chooseClientAlias(EC_AND_RSA_KEY_TYPES, null, null),
         alias);

    assertNotNull(keyManager.chooseServerAlias(null, null, null));
    assertEquals(keyManager.chooseServerAlias(null, null, null), alias);

    assertNull(keyManager.chooseServerAlias("RSA", null, null));

    assertNotNull(keyManager.chooseServerAlias("EC", null, null));
    assertEquals(keyManager.chooseServerAlias("EC", null, null),
         alias);

    assertNotNull(
         keyManager.chooseClientAlias(null, onlyEndEntityPrincipal, null));
    assertEquals(
         keyManager.chooseClientAlias(null, onlyEndEntityPrincipal, null),
         alias);

    assertNotNull(
         keyManager.chooseClientAlias(null, onlyIntermediateCAPrincipal, null));
    assertEquals(
         keyManager.chooseClientAlias(null, onlyIntermediateCAPrincipal, null),
         alias);

    assertNotNull(
         keyManager.chooseClientAlias(null, onlyRootCAPrincipal, null));
    assertEquals(
         keyManager.chooseClientAlias(null, onlyRootCAPrincipal, null),
         alias);

    assertNotNull(
         keyManager.chooseClientAlias(null, onlyCAPrincipals, null));
    assertEquals(
         keyManager.chooseClientAlias(null, onlyCAPrincipals, null),
         alias);

    assertNull(
         keyManager.chooseClientAlias(null, onlyNonMatchingPrincipal, null));

    assertNotNull(
         keyManager.chooseClientAlias(null, matchingAndNonMatchingPrincipals,
              null));
    assertEquals(
         keyManager.chooseClientAlias(null, matchingAndNonMatchingPrincipals,
              null),
         alias);

    assertNotNull(
         keyManager.chooseServerAlias(null, onlyEndEntityPrincipal, null));
    assertEquals(
         keyManager.chooseServerAlias(null, onlyEndEntityPrincipal, null),
         alias);

    assertNotNull(
         keyManager.chooseServerAlias(null, onlyIntermediateCAPrincipal, null));
    assertEquals(
         keyManager.chooseServerAlias(null, onlyIntermediateCAPrincipal, null),
         alias);

    assertNotNull(
         keyManager.chooseServerAlias(null, onlyRootCAPrincipal, null));
    assertEquals(
         keyManager.chooseServerAlias(null, onlyRootCAPrincipal, null),
         alias);

    assertNotNull(
         keyManager.chooseServerAlias(null, onlyCAPrincipals, null));
    assertEquals(
         keyManager.chooseServerAlias(null, onlyCAPrincipals, null),
         alias);

    assertNull(
         keyManager.chooseServerAlias(null, onlyNonMatchingPrincipal, null));

    assertNotNull(
         keyManager.chooseServerAlias(null, matchingAndNonMatchingPrincipals,
              null));
    assertEquals(
         keyManager.chooseServerAlias(null, matchingAndNonMatchingPrincipals,
              null),
         alias);


    // Test the key manager methods for getting applicable aliases.
    final String[] aliasArray = new String[] { alias };

    assertNotNull(keyManager.getClientAliases(null, null));
    assertEquals(keyManager.getClientAliases(null, null), aliasArray);

    assertNull(keyManager.getClientAliases("RSA", null));

    assertNotNull(keyManager.getClientAliases("EC", null));
    assertEquals(keyManager.getClientAliases("EC", null), aliasArray);

    assertNotNull(keyManager.getServerAliases(null, onlyEndEntityPrincipal));
    assertEquals(keyManager.getServerAliases(null, onlyEndEntityPrincipal),
         aliasArray);

    assertNotNull(
         keyManager.getServerAliases(null, onlyIntermediateCAPrincipal));
    assertEquals(keyManager.getServerAliases(null, onlyIntermediateCAPrincipal),
         aliasArray);

    assertNotNull(
         keyManager.getServerAliases(null, onlyRootCAPrincipal));
    assertEquals(keyManager.getServerAliases(null, onlyRootCAPrincipal),
         aliasArray);

    assertNotNull(keyManager.getServerAliases(null, onlyCAPrincipals));
    assertEquals(keyManager.getServerAliases(null, onlyCAPrincipals),
         aliasArray);

    assertNull(keyManager.getServerAliases(null, onlyNonMatchingPrincipal));

    assertNotNull(
         keyManager.getServerAliases(null, matchingAndNonMatchingPrincipals));
    assertEquals(
         keyManager.getServerAliases(null, matchingAndNonMatchingPrincipals),
         aliasArray);


    // Test the methods for getting the certificate chain.
    assertNotNull(keyManager.getCertificateChain(alias));
    assertEquals(keyManager.getCertificateChain(alias).length, 3);

    assertNotNull(keyManager.getCertificateChain(null));
    assertEquals(keyManager.getCertificateChain(null).length, 3);

    assertNotNull(keyManager.getCertificateChain("arbitrary string"));
    assertEquals(keyManager.getCertificateChain("arbitrary string").length, 3);


    // Test the methods for getting the private key.
    assertNotNull(keyManager.getPrivateKey(alias));

    assertNotNull(keyManager.getPrivateKey(null));

    assertNotNull(keyManager.getPrivateKey("arbitrary string"));


    // Create a trust manager from the certificate PEM file.
    final PEMFileTrustManager trustManager =
         new PEMFileTrustManager(combinedCACertsPEMFile);


    // Test the checkClientTrusted and checkServerTrusted methods.
    trustManager.checkClientTrusted(keyManager.getCertificateChain(null),
         "ECDSA");

    trustManager.checkServerTrusted(keyManager.getCertificateChain(null),
         "ECDSA");


    // Test the getAcceptedIssuers method.
    assertNotNull(trustManager.getAcceptedIssuers());
    assertEquals(trustManager.getAcceptedIssuers().length, 2);


    // Create an SSLUtil instance that uses the key and trust manager.  Use that
    // to create an in-memory directory server instance and verify that we can
    // establish a secure connection to it.
    final SSLUtil sslUtil = new SSLUtil(keyManager, trustManager);

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0,
              sslUtil.createSSLServerSocketFactory(),
              sslUtil.createSSLSocketFactory(),
              null));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();

    try (LDAPConnection conn = new LDAPConnection(
              sslUtil.createSSLSocketFactory(), "127.0.0.1",
              ds.getListenPort("LDAPS")))
    {
      assertNotNull(conn.getRootDSE());
    }

    ds.shutDown(true);
  }



  /**
   * Tests the behavior when creating a trust manager that has the PEM files in
   * subdirectories.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTrustManagerPEMFilesInSubdirectories()
         throws Exception
  {
    // Create a directory structure that has the trusted certificates in
    // subdirectories below a common top-level directory.
    final File topDirectory = createTempDir();

    final File endEntityDirectory = new File(topDirectory, "end-entity-dir");
    assertTrue(endEntityDirectory.mkdir());

    final File intermediateCADirectory =
         new File(topDirectory, "intermediate-ca-dir");
    assertTrue(intermediateCADirectory.mkdir());

    final File rootCADirectory = new File(topDirectory, "root-ca-dir");
    assertTrue(rootCADirectory.mkdir());

    final File endEntityFile =
         new File(endEntityDirectory, "end-entity-cert.pem");
    copyFile(endEntityCertPEMFile, endEntityFile);

    final File intermediateCAFile =
         new File(intermediateCADirectory, "intermediate-ca-cert.pem");
    copyFile(intermediateCACertPEMFile, intermediateCAFile);

    final File rootCAFile = new File(rootCADirectory, "root-ca-cert.pem");
    copyFile(rootCACertPEMFile, rootCAFile);


    // Create a key manager for the certificate chain.
    final PEMFileKeyManager keyManager = new PEMFileKeyManager(
         Arrays.asList(
              endEntityCertPEMFile,
              intermediateCACertPEMFile,
              rootCACertPEMFile),
         endEntityKeyPEMFile);


    // Create a trust manager with the top-level subdirectory.
    final PEMFileTrustManager trustManager =
         new PEMFileTrustManager(topDirectory);


    // Test the checkClientTrusted and checkServerTrusted methods.
    trustManager.checkClientTrusted(keyManager.getCertificateChain(null),
         "ECDSA");

    trustManager.checkServerTrusted(keyManager.getCertificateChain(null),
         "ECDSA");


    // Test the getAcceptedIssuers method.
    assertNotNull(trustManager.getAcceptedIssuers());
    assertEquals(trustManager.getAcceptedIssuers().length, 3);


    // Create an SSLUtil instance that uses the key and trust manager.  Use that
    // to create an in-memory directory server instance and verify that we can
    // establish a secure connection to it.
    final SSLUtil sslUtil = new SSLUtil(keyManager, trustManager);

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0,
              sslUtil.createSSLServerSocketFactory(),
              sslUtil.createSSLSocketFactory(),
              null));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();

    try (LDAPConnection conn = new LDAPConnection(
              sslUtil.createSSLSocketFactory(), "127.0.0.1",
              ds.getListenPort("LDAPS")))
    {
      assertNotNull(conn.getRootDSE());
    }

    ds.shutDown(true);
  }



  /**
   * Tests the behavior when using a trust manager that only has the issuer
   * certificates for a chain but not the end entity certificate.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCertificateChainOnlyIssuerCertificates()
         throws Exception
  {
    // Create a key manager for the certificate chain.
    final PEMFileKeyManager keyManager = new PEMFileKeyManager(
         Arrays.asList(
              endEntityCertPEMFile,
              intermediateCACertPEMFile,
              rootCACertPEMFile),
         endEntityKeyPEMFile);

    // Create a trust manager with PEM files for just the intermediate and root
    // CA certificates.
    final PEMFileTrustManager trustManager = new PEMFileTrustManager(
         intermediateCACertPEMFile,
         rootCACertPEMFile);


    // Test the checkClientTrusted and checkServerTrusted methods.
    trustManager.checkClientTrusted(keyManager.getCertificateChain(null),
         "ECDSA");

    trustManager.checkServerTrusted(keyManager.getCertificateChain(null),
         "ECDSA");


    // Test the getAcceptedIssuers method.
    assertNotNull(trustManager.getAcceptedIssuers());
    assertEquals(trustManager.getAcceptedIssuers().length, 2);


    // Create an SSLUtil instance that uses the key and trust manager.  Use that
    // to create an in-memory directory server instance and verify that we can
    // establish a secure connection to it.
    final SSLUtil sslUtil = new SSLUtil(keyManager, trustManager);

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0,
              sslUtil.createSSLServerSocketFactory(),
              sslUtil.createSSLSocketFactory(),
              null));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();

    try (LDAPConnection conn = new LDAPConnection(
              sslUtil.createSSLSocketFactory(), "127.0.0.1",
              ds.getListenPort("LDAPS")))
    {
      assertNotNull(conn.getRootDSE());
    }

    ds.shutDown(true);
  }



  /**
   * Tests the behavior when using a trust manager that only has the root CA
   * certificate for a chain, but not the end entity or intermediate CA
   * certificates.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCertificateChainOnlyRootCACertificate()
         throws Exception
  {
    // Create a key manager for the certificate chain.
    final PEMFileKeyManager keyManager = new PEMFileKeyManager(
         Arrays.asList(
              endEntityCertPEMFile,
              intermediateCACertPEMFile,
              rootCACertPEMFile),
         endEntityKeyPEMFile);

    // Create a trust manager with PEM files for just the intermediate and root
    // CA certificates.
    final PEMFileTrustManager trustManager =
         new PEMFileTrustManager(rootCACertPEMFile);


    // Test the checkClientTrusted and checkServerTrusted methods.
    trustManager.checkClientTrusted(keyManager.getCertificateChain(null),
         "ECDSA");

    trustManager.checkServerTrusted(keyManager.getCertificateChain(null),
         "ECDSA");


    // Test the getAcceptedIssuers method.
    assertNotNull(trustManager.getAcceptedIssuers());
    assertEquals(trustManager.getAcceptedIssuers().length, 1);


    // Create an SSLUtil instance that uses the key and trust manager.  Use that
    // to create an in-memory directory server instance and verify that we can
    // establish a secure connection to it.
    final SSLUtil sslUtil = new SSLUtil(keyManager, trustManager);

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0,
              sslUtil.createSSLServerSocketFactory(),
              sslUtil.createSSLSocketFactory(),
              null));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();

    try (LDAPConnection conn = new LDAPConnection(
              sslUtil.createSSLSocketFactory(), "127.0.0.1",
              ds.getListenPort("LDAPS")))
    {
      assertNotNull(conn.getRootDSE());
    }

    ds.shutDown(true);
  }



  /**
   * Tests the behavior when using a trust manager that only has the end entity
   * certificate for a chain, but not any of the issuer certificates.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCertificateChainOnlyEndEnttiyCertificate()
         throws Exception
  {
    // Create a key manager for the certificate chain.
    final PEMFileKeyManager keyManager = new PEMFileKeyManager(
         Arrays.asList(
              endEntityCertPEMFile,
              intermediateCACertPEMFile,
              rootCACertPEMFile),
         endEntityKeyPEMFile);

    // Create a trust manager with PEM files for just the intermediate and root
    // CA certificates.
    final PEMFileTrustManager trustManager =
         new PEMFileTrustManager(endEntityCertPEMFile);


    // Test the checkClientTrusted and checkServerTrusted methods.
    trustManager.checkClientTrusted(keyManager.getCertificateChain(null),
         "ECDSA");

    trustManager.checkServerTrusted(keyManager.getCertificateChain(null),
         "ECDSA");


    // Test the getAcceptedIssuers method.
    assertNotNull(trustManager.getAcceptedIssuers());
    assertEquals(trustManager.getAcceptedIssuers().length, 1);


    // Create an SSLUtil instance that uses the key and trust manager.  Use that
    // to create an in-memory directory server instance and verify that we can
    // establish a secure connection to it.
    final SSLUtil sslUtil = new SSLUtil(keyManager, trustManager);

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0,
              sslUtil.createSSLServerSocketFactory(),
              sslUtil.createSSLSocketFactory(),
              null));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();

    try (LDAPConnection conn = new LDAPConnection(
              sslUtil.createSSLSocketFactory(), "127.0.0.1",
              ds.getListenPort("LDAPS")))
    {
      assertNotNull(conn.getRootDSE());
    }

    ds.shutDown(true);
  }



  /**
   * Tests the behavior when trying to create a key manager with a nonexistent
   * certificate PEM file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { KeyStoreException.class })
  public void testKeyManagerMissingCertificatePEMFile()
         throws Exception
  {
    final File certPEMFile = createTempFile();
    assertTrue(certPEMFile.delete());

    new PEMFileKeyManager(certPEMFile, selfSignedKeyPEMFile);
  }



  /**
   * Tests the behavior when trying to create a key manager with a nonexistent
   * private key PEM file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { KeyStoreException.class })
  public void testKeyManagerMissingKEYPEMFile()
         throws Exception
  {
    final File keyPEMFile = createTempFile();
    assertTrue(keyPEMFile.delete());

    new PEMFileKeyManager(selfSignedCertPEMFile, keyPEMFile);
  }



  /**
   * Tests the behavior when trying to create a key manager with an empty
   * certificate PEM file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { KeyStoreException.class })
  public void testKeyManagerEmptyCertificatePEMFile()
         throws Exception
  {
    new PEMFileKeyManager(createTempFile(), selfSignedKeyPEMFile);
  }



  /**
   * Tests the behavior when trying to create a key manager with an empty
   * private key PEM file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { KeyStoreException.class })
  public void testKeyManagerEmptyPrivateKeyPEMFile()
         throws Exception
  {
    new PEMFileKeyManager(selfSignedCertPEMFile, createTempFile());
  }



  /**
   * Tests the behavior when trying to create a key manager with a key file that
   * has multiple private keys.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { KeyStoreException.class })
  public void testKeyManagerMultiplePrivateKeysPEMFile()
         throws Exception
  {
    final File keyPEMFile = createTempFile();
    try (PrintWriter w = new PrintWriter(keyPEMFile))
    {
      for (final String line : StaticUtils.readFileLines(selfSignedKeyPEMFile))
      {
        w.println(line);
      }

      for (final String line : StaticUtils.readFileLines(endEntityKeyPEMFile))
      {
        w.println(line);
      }
    }

    new PEMFileKeyManager(selfSignedCertPEMFile, keyPEMFile);
  }



  /**
   * Tests the behavior when trying to create a key manager with an empty
   * private key PEM file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { KeyStoreException.class })
  public void testKeyManagerEmptyPrivateKeyPEMFiles()
         throws Exception
  {
    new PEMFileKeyManager(selfSignedCertPEMFile, createTempFile());
  }



  /**
   * Tests the behavior when trying to create a key manager with a certificate
   * PEM file that does not contain a valid certificate.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { KeyStoreException.class })
  public void testKeyManagerInvalidCertPEMFile()
         throws Exception
  {
    final File invalidCertPEMFile = createTempFile(
         "This is not a valid PEM file");


    new PEMFileKeyManager(invalidCertPEMFile, selfSignedKeyPEMFile);
  }



  /**
   * Tests the behavior when trying to create a key manager with a private key
   * PEM file that does not contain a valid certificate.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { KeyStoreException.class })
  public void testKeyManagerInvalidKeyPEMFile()
         throws Exception
  {
    final File invalidKeyPEMFile = createTempFile(
         "This is not a valid PEM file");


    new PEMFileKeyManager(selfSignedCertPEMFile, invalidKeyPEMFile);
  }



  /**
   * Tests the behavior when trying to create a key manager with a certificate
   * chain in which the end entity certificate was not issued by the next
   * certificate in the chain.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { KeyStoreException.class })
  public void testKeyManagerInvalidIssuerChain()
         throws Exception
  {
    final File[] invalidChain =
    {
      endEntityCertPEMFile,
      rootCACertPEMFile
    };

    new PEMFileKeyManager(invalidChain, rootCACertPEMFile);
  }



  /**
   * Tests the behavior when trying to create a trust manager with a nonexistent
   * PEM file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { KeyStoreException.class })
  public void testTrustManagerNonexistentPEMFile()
         throws Exception
  {
    final File pemFile = createTempFile();
    assertTrue(pemFile.delete());

    new PEMFileTrustManager(pemFile);
  }



  /**
   * Tests the behavior when trying to create a trust manager with an empty PEM
   * file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { KeyStoreException.class })
  public void testTrustManagerEmptyPEMFile()
         throws Exception
  {
    new PEMFileTrustManager(createTempFile());
  }



  /**
   * Tests the behavior when trying to create a trust manager with an invalid
   * PEM file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { KeyStoreException.class })
  public void testTrustManagerInvalidPEMFile()
         throws Exception
  {
    new PEMFileTrustManager(createTempFile("This is not a valid PEM file."));
  }



  /**
   * Tests the behavior when presenting a null certificate chain to the trust
   * manager.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testTrustManagerNullCertificateChain()
         throws Exception
  {
    final PEMFileTrustManager trustManager =
         new PEMFileTrustManager(rootCACertPEMFile);
    trustManager.checkClientTrusted(null, "RSA");
  }



  /**
   * Tests the behavior when presenting an empty certificate chain to the trust
   * manager.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testTrustManagerEmptyCertificateChain()
         throws Exception
  {
    final PEMFileTrustManager trustManager =
         new PEMFileTrustManager(rootCACertPEMFile);
    trustManager.checkClientTrusted(new X509Certificate[0], "RSA");
  }



  /**
   * Tests the behavior when using a trust manager for the case in which the
   * presented certificate chain is not trusted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTrustManagerCertificateNotTrusted()
         throws Exception
  {
    // Create a key manager for the certificate chain.
    final PEMFileKeyManager keyManager = new PEMFileKeyManager(
         Arrays.asList(
              endEntityCertPEMFile,
              intermediateCACertPEMFile,
              rootCACertPEMFile),
         endEntityKeyPEMFile);

    // Create a trust manager with PEM files for just the intermediate and root
    // CA certificates.
    final PEMFileTrustManager trustManager =
         new PEMFileTrustManager(selfSignedCertPEMFile);


    // Test the checkClientTrusted and checkServerTrusted methods.
    try
    {
      trustManager.checkClientTrusted(keyManager.getCertificateChain(null),
           "ECDSA");
      fail("Expected an exception from checkClientTrusted with a non-trusted " +
           "chain");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }

    try
    {
      trustManager.checkServerTrusted(keyManager.getCertificateChain(null),
           "ECDSA");
      fail("Expected an exception from checkServerTrusted with a non-trusted " +
           "chain");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }


    // Test the getAcceptedIssuers method.
    assertNotNull(trustManager.getAcceptedIssuers());
    assertEquals(trustManager.getAcceptedIssuers().length, 1);


    // Create an SSLUtil instance that uses the key and trust manager.  Use that
    // to create an in-memory directory server instance and verify that we
    // cannot establish a secure connection to it.
    final SSLUtil sslUtil = new SSLUtil(keyManager, trustManager);

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0,
              sslUtil.createSSLServerSocketFactory(),
              sslUtil.createSSLSocketFactory(),
              null));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();

    try (LDAPConnection conn = new LDAPConnection(
              sslUtil.createSSLSocketFactory(), "127.0.0.1",
              ds.getListenPort("LDAPS")))
    {
      assertNotNull(conn.getRootDSE());
      fail("Expected an exception when trying to create a secure connection " +
           "to a server with an untrusted certificate chain");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }

    ds.shutDown(true);
  }



  /**
   * Tests the behavior when trying to create key and trust managers with an
   * expired end entity certificate.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExpiredEndEntityCertificate()
         throws Exception
  {
    // Create an expired self-signed certificate.
    final File keyStoreFile = createTempFile();
    assertTrue(keyStoreFile.delete());

    final long currentTime = System.currentTimeMillis();
    final long twoYearsAgo = currentTime -TimeUnit.DAYS.toMillis(2L * 365L);

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", keyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "cert",
         "--subject-dn", SELF_SIGNED_CERT_SUBJECT_DN,
         "--validity-start-time",
              StaticUtils.encodeGeneralizedTime(twoYearsAgo),
         "--daysValid", "365");

    final File certPEMFile = createTempFile();
    assertTrue(certPEMFile.delete());

    manageCertificates(
         "export-certificate",
         "--keystore", keyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "cert",
         "--output-format", "PEM",
         "--output-file", certPEMFile.getAbsolutePath());

    final File keyPEMFile = createTempFile();
    assertTrue(keyPEMFile.delete());

    manageCertificates(
         "export-private-key",
         "--keystore", keyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "cert",
         "--output-format", "PEM",
         "--output-file", keyPEMFile.getAbsolutePath());


    // Create key and trust managers for testing.
    final PEMFileKeyManager keyManager =
         new PEMFileKeyManager(certPEMFile, keyPEMFile);
    final PEMFileTrustManager trustManager =
         new PEMFileTrustManager(certPEMFile);


    // Make sure that the certificate chain is not considered trusted for client
    // use.
    try
    {
      trustManager.checkClientTrusted(keyManager.getCertificateChain(null),
           "RSA");
      fail("Expected an exception from checkClientTrusted");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }


    // Make sure that the certificate chain is not considered trusted for server
    // use.
    try
    {
      trustManager.checkServerTrusted(keyManager.getCertificateChain(null),
           "RSA");
      fail("Expected an exception from checkClientTrusted");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }


    // Create an SSLUtil instance that uses the key and trust manager.  Use that
    // to create an in-memory directory server instance and verify that we
    // cannot establish a secure connection to it.
    final SSLUtil sslUtil = new SSLUtil(keyManager, trustManager);

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0,
              sslUtil.createSSLServerSocketFactory(),
              sslUtil.createSSLSocketFactory(),
              null));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();

    try (LDAPConnection conn = new LDAPConnection(
              sslUtil.createSSLSocketFactory(), "127.0.0.1",
              ds.getListenPort("LDAPS")))
    {
      assertNotNull(conn.getRootDSE());
      fail("Expected an exception when trying to create a secure connection " +
           "to a server with an expired end entity certificate");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }

    ds.shutDown(true);
  }



  /**
   * Tests the behavior when trying to create key and trust managers with an
   * expired issuer certificate.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExpiredIssuerCertificate()
         throws Exception
  {
    // Create an expired CA certificate.
    final File caKeyStoreFile = createTempFile();
    assertTrue(caKeyStoreFile.delete());

    final long currentTime = System.currentTimeMillis();
    final long twoYearsAgo = currentTime -TimeUnit.DAYS.toMillis(2L * 365L);

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", caKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "ca-cert",
         "--subject-dn", ROOT_CA_CERT_SUBJECT_DN,
         "--validity-start-time",
              StaticUtils.encodeGeneralizedTime(twoYearsAgo),
         "--daysValid", "365");

    final File caCertPEMFile = createTempFile();
    assertTrue(caCertPEMFile.delete());

    manageCertificates(
         "export-certificate",
         "--keystore", caKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "ca-cert",
         "--output-format", "PEM",
         "--output-file", caCertPEMFile.getAbsolutePath());


    // Create a non-expired end entity certificate that is signed by the expired
    // CA certificate.
    final File endKeyStoreFile = createTempFile();
    assertTrue(endKeyStoreFile.delete());

    final File endCSRFile = createTempFile();
    assertTrue(endCSRFile.delete());

    manageCertificates(
         "generate-certificate-signing-request",
         "--keystore", endKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "end-entity-cert",
         "--subject-dn", END_ENTITY_CERT_SUBJECT_DN,
         "--output-format", "PEM",
         "--output-file", endCSRFile.getAbsolutePath());

    final File endCertPEMFile = createTempFile();
    assertTrue(endCertPEMFile.delete());

    manageCertificates(
         "sign-certificate-signing-request",
         "--keystore", caKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--request-input-file", endCSRFile.getAbsolutePath(),
         "--certificate-output-file",
              endCertPEMFile.getAbsolutePath(),
         "--output-format", "PEM",
         "--signing-certificate-alias", "ca-cert",
         "--include-requested-extensions",
         "--no-prompt");

    manageCertificates(
         "import-certificate",
         "--keystore", endKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "end-entity-cert",
         "--certificate-file", endCertPEMFile.getAbsolutePath(),
         "--certificate-file", caCertPEMFile.getAbsolutePath(),
         "--no-prompt");

    final File endKeyPEMFile = createTempFile();
    assertTrue(endKeyPEMFile.delete());

    manageCertificates(
         "export-private-key",
         "--keystore", endKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "end-entity-cert",
         "--output-format", "PEM",
         "--output-file", endKeyPEMFile.getAbsolutePath());


    // Create key and trust managers for testing.
    final PEMFileKeyManager keyManager = new PEMFileKeyManager(
         new File[]
         {
           endCertPEMFile,
           caCertPEMFile
         },
         endKeyPEMFile);

    final PEMFileTrustManager trustManager = new PEMFileTrustManager(
         endCertPEMFile, caCertPEMFile);


    // Make sure that the certificate chain is not considered trusted for client
    // use.
    try
    {
      trustManager.checkClientTrusted(keyManager.getCertificateChain(null),
           "RSA");
      fail("Expected an exception from checkClientTrusted");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }


    // Make sure that the certificate chain is not considered trusted for server
    // use.
    try
    {
      trustManager.checkServerTrusted(keyManager.getCertificateChain(null),
           "RSA");
      fail("Expected an exception from checkClientTrusted");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }


    // Create an SSLUtil instance that uses the key and trust manager.  Use that
    // to create an in-memory directory server instance and verify that we
    // cannot establish a secure connection to it.
    final SSLUtil sslUtil = new SSLUtil(keyManager, trustManager);

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0,
              sslUtil.createSSLServerSocketFactory(),
              sslUtil.createSSLSocketFactory(),
              null));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();

    try (LDAPConnection conn = new LDAPConnection(
              sslUtil.createSSLSocketFactory(), "127.0.0.1",
              ds.getListenPort("LDAPS")))
    {
      assertNotNull(conn.getRootDSE());
      fail("Expected an exception when trying to create a secure connection " +
           "to a server with an expired end entity certificate");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }

    ds.shutDown(true);
  }



  /**
   * Tests the trust manager behavior when presented with an incomplete chain
   * that doesn't contain any certificate trusted by the trust manager but whose
   * issuer is trusted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncompleteButValidChain()
         throws Exception
  {
    final PEMFileKeyManager keyManager =
         new PEMFileKeyManager(endEntityCertPEMFile, endEntityKeyPEMFile);
    final PEMFileTrustManager trustManager =
         new PEMFileTrustManager(intermediateCACertPEMFile, rootCACertPEMFile);

    trustManager.checkClientTrusted(keyManager.getCertificateChain(null),
         "ECDSA");

    trustManager.checkServerTrusted(keyManager.getCertificateChain(null),
         "ECDSA");


    // Create an SSLUtil instance that uses the key and trust manager.  Use that
    // to create an in-memory directory server instance and verify that we can
    // establish a secure connection to it.
    final SSLUtil sslUtil = new SSLUtil(keyManager, trustManager);

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0,
              sslUtil.createSSLServerSocketFactory(),
              sslUtil.createSSLSocketFactory(),
              null));
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();

    try (LDAPConnection conn = new LDAPConnection(
              sslUtil.createSSLSocketFactory(), "127.0.0.1",
              ds.getListenPort("LDAPS")))
    {
      assertNotNull(conn.getRootDSE());
    }

    ds.shutDown(true);
  }



  /**
   * Tests the trust manager behavior when presented with a certificate chain in
   * which the second certificate is not the issuer for the first.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testChainWithSecondNotIssuerOfFirst()
         throws Exception
  {
    final PEMFileKeyManager keyManager = new PEMFileKeyManager(
         new File[]
         {
           endEntityCertPEMFile,
           intermediateCACertPEMFile,
           rootCACertPEMFile
         },
         endEntityKeyPEMFile);

    final PEMFileTrustManager trustManager =  new PEMFileTrustManager(
         endEntityCertPEMFile, intermediateCACertPEMFile, rootCACertPEMFile);


    final X509Certificate[] validChain = keyManager.getCertificateChain(null);
    assertNotNull(validChain);
    assertEquals(validChain.length, 3);


    final X509Certificate[] invalidChain =
    {
      validChain[0],
      validChain[2]
    };


    // Make sure that the valid chain is trusted.
    trustManager.checkClientTrusted(validChain, "ECDSA");

    trustManager.checkServerTrusted(validChain, "ECDSA");


    // Make sure that the invalid chain is not trusted.
    try
    {
      trustManager.checkClientTrusted(invalidChain, "ECDSA");
      fail("Expected an exception from an invalid client chain");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }

    try
    {
      trustManager.checkServerTrusted(invalidChain, "ECDSA");
      fail("Expected an exception from an invalid server chain");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }
  }



  /**
   * Invokes the manage-certificates tool with the provided set of arguments.
   *
   * @param  args  The arguments to provide to the manage-certificates tool.
   *
   * @throws  Exception  If a problem occurs while running the tool.
   */
  private static void manageCertificates(final String... args)
          throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ResultCode resultCode = ManageCertificates.main((InputStream) null,
         out, out, args);

    if (resultCode != ResultCode.SUCCESS)
    {
      fail("manage-certificates returned error result code " +
           resultCode + " when invoked with arguments " +
           Arrays.toString(args) + StaticUtils.EOL + StaticUtils.EOL +
           "The manage-certificates output was:"  +
           StaticUtils.EOL + StaticUtils.EOL +
           StaticUtils.toUTF8String(out.toByteArray()) +
           StaticUtils.EOL);
    }
  }



  /**
   * Copies the contents of the specified file.
   *
   * @param  from  The source file to be copied.
   * @param  to    The file to be populated with the source file contents.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void copyFile(final File from, final File to)
          throws Exception
  {
    try (FileInputStream inputStream = new FileInputStream(from);
         FileOutputStream outputStream = new FileOutputStream(to))
    {
      final byte[] buffer = new byte[8192];
      while (true)
      {
        final int bytesRead = inputStream.read(buffer);
        if (bytesRead < 0)
        {
          return;
        }

        outputStream.write(buffer, 0, bytesRead);
      }
    }
  }
}
