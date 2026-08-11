/*
 * Copyright 2026 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2026 Ping Identity Corporation
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
 * Copyright (C) 2026 Ping Identity Corporation
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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1BitString;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ssl.cert.ManageCertificates;
import com.unboundid.util.ssl.cert.X509PEMFileReader;



/**
 * This class provides a set of test cases for the
 * {@code VerifyChainSignaturesTrustManager} class.
 */
public final class VerifyChainSignaturesTrustManagerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the trust manager behavior for a self-signed certificate.  This
   * includes actually communicating with a server over a TLS-secured
   * connection.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithSelfSignedCertificate()
         throws Exception
  {
    // Generate a self-signed certificate in its own keystore.
    final File selfSignedCerteyStoreFile = createTempFile();
    assertTrue(selfSignedCerteyStoreFile.delete());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", selfSignedCerteyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corp,C=US");


    // Create an in-memory directory server instance with the new key store.
    try (InMemoryDirectoryServer ds = createServer(selfSignedCerteyStoreFile))
    {
      final SSLUtil sslUtil =
           new SSLUtil(VerifyChainSignaturesTrustManager.getInstance());
      try (LDAPConnection conn = new LDAPConnection(
                sslUtil.createSSLSocketFactory(), "127.0.0.1",
                ds.getListenPort()))
      {
        // Make sure that we can successfully communicate with the server.
        assertNotNull(conn.getRootDSE());
      }
    }
  }



  /**
   * Tests the trust manager behavior for a two-certificate chain.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithTwoCertificateChain()
         throws Exception
  {
    // Generate a self-signed certificate to be an issuer certificate.
    final File rootCACertKeyStoreFile = createTempFile();
    assertTrue(rootCACertKeyStoreFile.delete());

    final File rootCACertPEMFile = createTempFile();
    assertTrue(rootCACertPEMFile.delete());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", rootCACertKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "root-ca-cert",
         "--subject-dn", "CN=Root CA,O=Example Corp,C=US",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--key-usage", "crl-sign",
         "--output-file", rootCACertPEMFile.getAbsolutePath(),
         "--output-format", "PEM");


    // Generate a certificate signing request for a new end-entity certificate
    // in a different key store.
    final File endEntityCertKeyStoreFile = createTempFile();
    assertTrue(endEntityCertKeyStoreFile.delete());

    final File endEntityCertRequestPEMFile = createTempFile();
    assertTrue(endEntityCertRequestPEMFile.delete());

    manageCertificates(
         "generate-certificate-signing-request",
         "--keystore", endEntityCertKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corp,C=US",
         "--output-file", endEntityCertRequestPEMFile.getAbsolutePath(),
         "--output-format", "PEM");


    // Sign the CSR with the root CA certificate.
    final File endEntityCertPEMFile = createTempFile();
    assertTrue(endEntityCertPEMFile.delete());

    manageCertificates(
         "sign-certificate-signing-request",
         "--keystore", rootCACertKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--signing-certificate-alias", "root-ca-cert",
         "--request-input-file", endEntityCertRequestPEMFile.getAbsolutePath(),
         "--certificate-output-file", endEntityCertPEMFile.getAbsolutePath(),
         "--include-requested-extensions",
         "--issuer-alternative-name-email-address", "root-ca@example.com",
         "--no-prompt");


    // Create a certificate chain with the end-entity certificate and the root
    // CA certificate.
    final X509Certificate[] chain =
         createCertificateChain(endEntityCertPEMFile, rootCACertPEMFile);


    // Ensure that the trust manager considers the chain valid when it contains
    // both certificates.
    final VerifyChainSignaturesTrustManager trustManager =
         VerifyChainSignaturesTrustManager.getInstance();
    trustManager.checkClientTrusted(chain, null);
    trustManager.checkServerTrusted(chain, null);


    // Ensure that the trust manager considers the chain valid when it contains
    // only the end-entity certificate.
    final X509Certificate[] endEntityOnlyChain =
    {
      chain[0]
    };

    trustManager.checkClientTrusted(endEntityOnlyChain, null);
    trustManager.checkServerTrusted(endEntityOnlyChain, null);


    // Ensure that the trust manager considers the chain valid when it contains
    // only the root CA certificate.
    final X509Certificate[] rootCAOnlyChain =
    {
      chain[1]
    };

    trustManager.checkClientTrusted(rootCAOnlyChain, null);
    trustManager.checkServerTrusted(rootCAOnlyChain, null);


    // Ensure that the trust manager does not consider the chain valid when it
    // contains both certificates, but in the wrong order.
    final X509Certificate[] misorderedChain =
    {
      chain[1],
      chain[0]
    };

    try
    {
      trustManager.checkClientTrusted(misorderedChain, null);
      fail("Expected a checkClientTrusted failure from a misordered chain");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }

    try
    {
      trustManager.checkServerTrusted(misorderedChain, null);
      fail("Expected a checkServerTrusted failure from a misordered chain");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }


    // Generate an alternative root CA certificate using all of the same
    // settings as the original one.  The new certificate will have a different
    // key pair.
    final File differentRootCACertKeyStoreFile = createTempFile();
    assertTrue(differentRootCACertKeyStoreFile.delete());

    final File differentRootCACertPEMFile = createTempFile();
    assertTrue(differentRootCACertPEMFile.delete());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", differentRootCACertKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "root-ca-cert",
         "--subject-dn", "CN=Root CA,O=Example Corp,C=US",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--key-usage", "crl-sign",
         "--output-file", differentRootCACertPEMFile.getAbsolutePath(),
         "--output-format", "PEM");


    // Create a certificate chain with the end-entity certificate and the new
    // root CA certificate.  Since the new root isn't the issuer of the
    // end-entity certificate, it's not a valid chain.
    final X509Certificate[] invalidChain = createCertificateChain(
         endEntityCertPEMFile, differentRootCACertPEMFile);


    // Ensure that the trust manager does not consider this chain valid.
    try
    {
      trustManager.checkClientTrusted(invalidChain, null);
      fail("Expected a checkClientTrusted failure from a chain where the " +
           "second certificate is not the issuer of the first.");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }

    try
    {
      trustManager.checkServerTrusted(invalidChain, null);
      fail("Expected a checkServerTrusted failure from a chain where the " +
           "second certificate is not the issuer of the first.");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the trust manager behavior for a three-certificate chain.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithThreeCertificateChain()
         throws Exception
  {
    // Generate a self-signed certificate to be the root CA certificate.
    final File rootCACertKeyStoreFile = createTempFile();
    assertTrue(rootCACertKeyStoreFile.delete());

    final File rootCACertPEMFile = createTempFile();
    assertTrue(rootCACertPEMFile.delete());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", rootCACertKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "root-ca-cert",
         "--subject-dn", "CN=Root CA,O=Example Corp,C=US",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--key-usage", "crl-sign",
         "--output-file", rootCACertPEMFile.getAbsolutePath(),
         "--output-format", "PEM");


    // Generate a certificate signing request for an intermediate CA
    // certificate.
    final File intermediateCACertKeyStoreFile = createTempFile();
    assertTrue(intermediateCACertKeyStoreFile.delete());

    final File intermediateCACertRequestPEMFile = createTempFile();
    assertTrue(intermediateCACertRequestPEMFile.delete());

    manageCertificates(
         "generate-certificate-signing-request",
         "--keystore", intermediateCACertKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "intermediate-ca-cert",
         "--subject-dn", "CN=Intermediate CA,O=Example Corp,C=US",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--key-usage", "crl-sign",
         "--output-file", intermediateCACertRequestPEMFile.getAbsolutePath(),
         "--output-format", "PEM");


    // Sign the intermediate CA certificate's CSR with the root CA certificate.
    final File intermediateCACertPEMFile = createTempFile();
    assertTrue(intermediateCACertPEMFile.delete());

    manageCertificates(
         "sign-certificate-signing-request",
         "--keystore", rootCACertKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--signing-certificate-alias", "root-ca-cert",
         "--request-input-file",
              intermediateCACertRequestPEMFile.getAbsolutePath(),
         "--certificate-output-file",
              intermediateCACertPEMFile.getAbsolutePath(),
         "--include-requested-extensions",
         "--issuer-alternative-name-email-address", "roo-ca@example.com",
         "--no-prompt");


    // Import the signed intermediate CA certificate into its key store.
    manageCertificates(
         "import-certificate",
         "--keystore", intermediateCACertKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "intermediate-ca-cert",
         "--certificate-file", intermediateCACertPEMFile.getAbsolutePath(),
         "--certificate-file", rootCACertPEMFile.getAbsolutePath(),
         "--no-prompt");


    // Generate a certificate signing request for a new end-entity certificate
    // in a third key store.
    final File endEntityCertKeyStoreFile = createTempFile();
    assertTrue(endEntityCertKeyStoreFile.delete());

    final File endEntityCertRequestPEMFile = createTempFile();
    assertTrue(endEntityCertRequestPEMFile.delete());

    manageCertificates(
         "generate-certificate-signing-request",
         "--keystore", endEntityCertKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corp,C=US",
         "--output-file", endEntityCertRequestPEMFile.getAbsolutePath(),
         "--output-format", "PEM");


    // Sign the CSR with the intermediate CA certificate.
    final File endEntityCertPEMFile = createTempFile();
    assertTrue(endEntityCertPEMFile.delete());

    manageCertificates(
         "sign-certificate-signing-request",
         "--keystore", intermediateCACertKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--signing-certificate-alias", "intermediate-ca-cert",
         "--request-input-file", endEntityCertRequestPEMFile.getAbsolutePath(),
         "--certificate-output-file", endEntityCertPEMFile.getAbsolutePath(),
         "--include-requested-extensions",
         "--issuer-alternative-name-email-address",
              "intermediate-ca@example.com",
         "--no-prompt");


    // Create a certificate chain with the all three certificates in the correct
    // order.
    final X509Certificate[] fullChain = createCertificateChain(
         endEntityCertPEMFile, intermediateCACertPEMFile, rootCACertPEMFile);


    // Ensure that the trust manager considers the chain valid when it contains
    // all three certificates.
    final VerifyChainSignaturesTrustManager trustManager =
         VerifyChainSignaturesTrustManager.getInstance();
    trustManager.checkClientTrusted(fullChain, null);
    trustManager.checkServerTrusted(fullChain, null);


    // Ensure that the trust manager considers the chain valid when it contains
    // only the end-entity certificate.
    final X509Certificate[] endEntityOnlyChain =
    {
      fullChain[0]
    };

    trustManager.checkClientTrusted(endEntityOnlyChain, null);
    trustManager.checkServerTrusted(endEntityOnlyChain, null);


    // Ensure that the trust manager considers the chain valid when it contains
    // only the intermediate CA certificate.
    final X509Certificate[] intermediateCAOnlyChain =
    {
      fullChain[1]
    };

    trustManager.checkClientTrusted(intermediateCAOnlyChain, null);
    trustManager.checkServerTrusted(intermediateCAOnlyChain, null);


    // Ensure that the trust manager considers the chain valid when it contains
    // only the root CA certificate.
    final X509Certificate[] rootCAOnlyChain =
    {
      fullChain[2]
    };

    trustManager.checkClientTrusted(rootCAOnlyChain, null);
    trustManager.checkServerTrusted(rootCAOnlyChain, null);


    // Ensure that the trust manager considers the chain valid when it contains
    // only the end-entity and intermediate CA certificates.
    final X509Certificate[] endEntitytAndIntermediateCAChain =
    {
      fullChain[0],
      fullChain[1]
    };

    trustManager.checkClientTrusted(endEntitytAndIntermediateCAChain, null);
    trustManager.checkServerTrusted(endEntitytAndIntermediateCAChain, null);


    // Ensure that the trust manager considers the chain valid when it contains
    // only the and intermediate and root CA certificates.
    final X509Certificate[] intermediateAndRootCAChain =
    {
      fullChain[1],
      fullChain[2]
    };

    trustManager.checkClientTrusted(intermediateAndRootCAChain, null);
    trustManager.checkServerTrusted(intermediateAndRootCAChain, null);


    // Ensure that the trust manager does not consider the chain valid when it
    // contains only the end-entity and root CA certificates.
    final X509Certificate[] endEntityAndRootCAChain =
    {
      fullChain[0],
      fullChain[2]
    };

    try
    {
      trustManager.checkClientTrusted(endEntityAndRootCAChain, null);
      fail("Expected a checkClientTrusted failure from a misordered chain");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }

    try
    {
      trustManager.checkServerTrusted(endEntityAndRootCAChain, null);
      fail("Expected a checkServerTrusted failure from a misordered chain");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the trust manager behavior for a self-signed certificate with an
   * invalid signature.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithSelfSignedInvalidSignature()
         throws Exception
  {
    // Generate a self-signed certificate to be an issuer certificate.
    final File rootCACertKeyStoreFile = createTempFile();
    assertTrue(rootCACertKeyStoreFile.delete());

    final File rootCACertPEMFile = createTempFile();
    assertTrue(rootCACertPEMFile.delete());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", rootCACertKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "root-ca-cert",
         "--subject-dn", "CN=Root CA,O=Example Corp,C=US",
         "--basic-constraints-is-ca", "true",
         "--key-usage", "key-cert-sign",
         "--key-usage", "crl-sign",
         "--output-file", rootCACertPEMFile.getAbsolutePath(),
         "--output-format", "PEM");


    // Generate a certificate signing request for a new end-entity certificate
    // in a different key store.
    final File endEntityCertKeyStoreFile = createTempFile();
    assertTrue(endEntityCertKeyStoreFile.delete());

    final File endEntityCertRequestPEMFile = createTempFile();
    assertTrue(endEntityCertRequestPEMFile.delete());

    manageCertificates(
         "generate-certificate-signing-request",
         "--keystore", endEntityCertKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ldap.example.com,O=Example Corp,C=US",
         "--output-file", endEntityCertRequestPEMFile.getAbsolutePath(),
         "--output-format", "PEM");


    // Sign the CSR with the root CA certificate.
    final File endEntityCertPEMFile = createTempFile();
    assertTrue(endEntityCertPEMFile.delete());

    manageCertificates(
         "sign-certificate-signing-request",
         "--keystore", rootCACertKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--signing-certificate-alias", "root-ca-cert",
         "--request-input-file", endEntityCertRequestPEMFile.getAbsolutePath(),
         "--certificate-output-file", endEntityCertPEMFile.getAbsolutePath(),
         "--include-requested-extensions",
         "--issuer-alternative-name-email-address", "root-ca@example.com",
         "--no-prompt");


    // Create a certificate chain with the end-entity certificate and the root
    // CA certificate.
    final X509Certificate[] chain =
         createCertificateChain(endEntityCertPEMFile, rootCACertPEMFile);


    // Ensure that the trust manager considers the chain valid when it contains
    // both certificates.
    final VerifyChainSignaturesTrustManager trustManager =
         VerifyChainSignaturesTrustManager.getInstance();
    trustManager.checkClientTrusted(chain, null);
    trustManager.checkServerTrusted(chain, null);


    // Ensure that the trust manager considers the chain valid when it contains
    // only the root CA certificate.
    final X509Certificate[] rootCAOnlyChain =
    {
      chain[1]
    };

    trustManager.checkClientTrusted(rootCAOnlyChain, null);
    trustManager.checkServerTrusted(rootCAOnlyChain, null);


    // Create an alternative version of the root CA certificate with an invalid
    // signature.
    final X509Certificate rootCAWithInvalidSignature =
         invalidateSignature(chain[1]);


    // Create a certificate chain containing only the invalid certificate, and
    // verify that the trust manager does not consider it valid.
    final X509Certificate[] onlyInvalidCertChain =
    {
      rootCAWithInvalidSignature
    };

    try
    {
      trustManager.checkClientTrusted(onlyInvalidCertChain, null);
      fail("Expected a checkClientTrusted failure from a single-certificate " +
           "chain when that certificate is a self-signed certificate with an " +
           "invalid signature.");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }

    try
    {
      trustManager.checkServerTrusted(onlyInvalidCertChain, null);
      fail("Expected a checkServerTrusted failure from a single-certificate " +
           "chain when that certificate is a self-signed certificate with an " +
           "invalid signature.");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }


    // Create a certificate chain containing the end-entity certificate and the
    // root CA certificate with the invalid signature.  Verify that the trust
    // manager does not consider that chain valid.
    final X509Certificate[] endEntityAndInvalidCACertChain =
    {
      chain[0],
      rootCAWithInvalidSignature
    };

    try
    {
      trustManager.checkClientTrusted(endEntityAndInvalidCACertChain, null);
      fail("Expected a checkClientTrusted failure from a two-certificate " +
           "chain when the second is a self-signed certificate with an " +
           "invalid signature.");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }

    try
    {
      trustManager.checkServerTrusted(endEntityAndInvalidCACertChain, null);
      fail("Expected a checkServerTrusted failure from a two-certificate " +
           "chain when the second is a self-signed certificate with an " +
           "invalid signature.");
    }
    catch (final CertificateException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests to ensure that the trust manager will accept a null certificate
   * chain.  A null chain shouldn't happen under normal circumstances, but the
   * validator can't operate on it.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithNullCertificateChain()
         throws Exception
  {
    final VerifyChainSignaturesTrustManager trustManager =
         VerifyChainSignaturesTrustManager.getInstance();
    trustManager.checkClientTrusted(null, null);
    trustManager.checkServerTrusted(null, null);
  }



  /**
   * Tests to ensure that the trust manager will accept an empty certificate
   * chain.  An empty chain shouldn't happen under normal circumstances, but the
   * validator can't operate on it.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithEmptyCertificateChain()
         throws Exception
  {
    final X509Certificate[] emptyChain = new X509Certificate[0];

    final VerifyChainSignaturesTrustManager trustManager =
         VerifyChainSignaturesTrustManager.getInstance();
    trustManager.checkClientTrusted(emptyChain, null);
    trustManager.checkServerTrusted(emptyChain, null);
  }



  /**
   * Provides test coverage for the {@code getAcceptedIssuers} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAcceptedIssuers()
         throws Exception
  {
    final VerifyChainSignaturesTrustManager trustManager =
         VerifyChainSignaturesTrustManager.getInstance();
    assertNotNull(trustManager.getAcceptedIssuers());
    assertEquals(trustManager.getAcceptedIssuers().length, 0);
  }



  /**
   * Invokes the {@code manage-profile} tool with the provided set of arguments.
   *
   * @param  args  The command-line arguments provided to this program.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void manageCertificates(final String... args)
          throws Exception
  {
    final ByteArrayOutputStream output = new ByteArrayOutputStream();
    final ResultCode resultCode =
         ManageCertificates.main(null, output, output, args);

    if (resultCode != ResultCode.SUCCESS)
    {
      final StringBuilder b = new StringBuilder();
      b.append("Command:");
      b.append(StaticUtils.EOL);
      b.append(StaticUtils.EOL);
      b.append("     manage-certificates");

      for (final String arg : args)
      {
        b.append(' ');
        b.append(StaticUtils.cleanExampleCommandLineArgument(arg));
      }

      b.append(StaticUtils.EOL);
      b.append(StaticUtils.EOL);

      b.append("failed with result code ");
      b.append(resultCode);
      b.append(" and the following output:");
      b.append(StaticUtils.EOL);
      b.append(StaticUtils.EOL);

      b.append(StaticUtils.toUTF8String(output.toByteArray()));
      b.append(StaticUtils.EOL);
      b.append(StaticUtils.EOL);

      fail(b.toString());
    }
  }



  /**
   * Creates a new in-memory directory server that supports TLS-secured
   * communication using the specified key store.
   *
   * @param  keyStoreFile  The path to the key store containing the server
   *                       certificate.
   *
   * @return  The in-memory directory server instance that was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static InMemoryDirectoryServer createServer(final File keyStoreFile)
          throws Exception
  {
    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    final SSLUtil sslUtil = new SSLUtil(
         new KeyStoreKeyManager(keyStoreFile, "password".toCharArray()),
         new TrustAllTrustManager());
    dsCfg.setListenerConfigs(
         InMemoryListenerConfig.createLDAPSConfig("LDAPS",
              sslUtil.createSSLServerSocketFactory()));

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.startListening();

    return ds;
  }



  /**
   * Creates a certificate chain with the certificates in the specified set of
   * PEM files.
   *
   * @param  pemFiles  The PEM files containing the certificates to include in
   *                   the chain, in the order they are provided.  Each PEM file
   *                   must have exactly one certificate.
   *
   * @return  The certificate chain that was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static X509Certificate[] createCertificateChain(
               final File... pemFiles)
          throws Exception
  {
    final X509Certificate[] chain = new X509Certificate[pemFiles.length];
    for (int i=0; i < pemFiles.length; i++)
    {
      try (X509PEMFileReader r = new X509PEMFileReader(pemFiles[i]))
      {
        chain[i] = (X509Certificate) r.readCertificate().toCertificate();
      }
    }

    return chain;
  }



  /**
   * Creates a version of the provided certificate with an invalid signature.
   *
   * @param  cert  The certificate whose signature should be invalidated.
   *
   * @return  The certificate with an invalid signature.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static X509Certificate invalidateSignature(final X509Certificate cert)
          throws Exception
  {
    // Get the raw bytes of the certificate and decode it as an ASN.1 sequence.
    final byte[] certBytes = cert.getEncoded();
    final ASN1Element[] certElements =
         ASN1Sequence.decodeAsSequence(certBytes).elements();


    // The sequence should have exactly three elements.
    assertEquals(certElements.length, 3);


    // The third element of the sequence should be a bit string that represents
    // the signature.
    final ASN1BitString signatureBitString =
         certElements[2].decodeAsBitString();


    // Flip the first bit of the bit string
    final boolean[] signatureBits = signatureBitString.getBits();
    final boolean[] invalidSignatureBits =
         Arrays.copyOf(signatureBits, signatureBits.length);
    invalidSignatureBits[0] = (! signatureBits[0]);


    // Encode a new ASN.1 sequence with the invalidated signature.
    final ASN1Sequence invalidatedCertSequence = new ASN1Sequence(
         certElements[0],
         certElements[1],
         new ASN1BitString(signatureBitString.getType(), invalidSignatureBits));
    final byte[] invalidCertBytes = invalidatedCertSequence.encode();


    // Decode and return the resulting bytes as an X.509 certificate.
    final com.unboundid.util.ssl.cert.X509Certificate invalidCert =
         new com.unboundid.util.ssl.cert.X509Certificate(invalidCertBytes);
    return (X509Certificate) invalidCert.toCertificate();
  }
}
