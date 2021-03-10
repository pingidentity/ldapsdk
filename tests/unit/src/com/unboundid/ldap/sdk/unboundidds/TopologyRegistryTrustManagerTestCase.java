/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldif.LDIFWriter;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;
import com.unboundid.util.ssl.cert.ManageCertificates;



/**
 * This class provides a set of test cases for the topology registry trust
 * manager.
 */
public final class TopologyRegistryTrustManagerTestCase
       extends LDAPSDKTestCase
{
  // A key store file that contains a self-signed certificate for use across a
  // variety of tests.
  private File keyStoreFile = null;

  // The lines that comprise the PEM representation of the certificate in the
  // key store file, including the BEGIN and END wrapper lines.
  private List<String> pemCertificateLines = null;



  /**
   * Creates a self-signed certificate to use for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    keyStoreFile = createTempFile();
    assertTrue(keyStoreFile.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    ResultCode resultCode = ManageCertificates.main(null, out, out,
         "generate-self-signed-certificate",
         "--keystore", keyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ds.example.com,O=Example Corp,C=US");
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to generate a self-signed certificate:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));

    final File pemFile = createTempFile();
    assertTrue(pemFile.delete());

    out.reset();
    resultCode = ManageCertificates.main(null, out, out,
         "export-certificate",
         "--keystore", keyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--output-format", "PEM",
         "--output-file", pemFile.getAbsolutePath());
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to export the self-signed certificate:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));

    pemCertificateLines = StaticUtils.readFileLines(pemFile);
  }



  /**
   * Tests to ensure that the trust manager can trust a certificate if it is
   * found in a server instance entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleInterServerCertificate()
         throws Exception
  {
    try (InMemoryDirectoryServer ds = getDS(keyStoreFile))
    {
      // Create a configuration file to use for the test.
      final File configFile = generateConfigFile(pemCertificateLines, null);

      // Create a trust manager and SSL util configuration.
      final TopologyRegistryTrustManager trustManager =
           new TopologyRegistryTrustManager(configFile, 300_000L);
      final SSLUtil sslUtil = new SSLUtil(null, trustManager);

      // Perform an initial test to ensure that the connection succeeds when
      // the configuration is not cached.
      try (LDAPConnection conn = new LDAPConnection(
           sslUtil.createSSLSocketFactory(), "localhost", ds.getListenPort()))
      {
        assertNotNull(conn.getRootDSE());
      }

      // Perform another test to ensure that the connection succeeds when the
      // configuration is cached.
      try (LDAPConnection conn = new LDAPConnection(
           sslUtil.createSSLSocketFactory(), "localhost", ds.getListenPort()))
      {
        assertNotNull(conn.getRootDSE());
      }
    }
  }



  /**
   * Tests to ensure that the trust manager can trust a certificate if it is
   * found in a listener entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleListenerCertificate()
         throws Exception
  {
    try (InMemoryDirectoryServer ds = getDS(keyStoreFile))
    {
      // Create a configuration file to use for the test.
      final File configFile = generateConfigFile(null, pemCertificateLines);

      // Create a trust manager and SSL util configuration.
      final TopologyRegistryTrustManager trustManager =
           new TopologyRegistryTrustManager(configFile, 300_000L);
      final SSLUtil sslUtil = new SSLUtil(null, trustManager);

      // Perform an initial test to ensure that the connection succeeds when
      // the configuration is not cached.
      try (LDAPConnection conn = new LDAPConnection(
           sslUtil.createSSLSocketFactory(), "localhost", ds.getListenPort()))
      {
        assertNotNull(conn.getRootDSE());
      }

      // Perform another test to ensure that the connection succeeds when the
      // configuration is cached.
      try (LDAPConnection conn = new LDAPConnection(
           sslUtil.createSSLSocketFactory(), "localhost", ds.getListenPort()))
      {
        assertNotNull(conn.getRootDSE());
      }
    }
  }



  /**
   * Tests to ensure that a trust manager will not trust a certificate if the
   * topology registry does not have any certificate information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoCertificatesInConfig()
         throws Exception
  {
    try (InMemoryDirectoryServer ds = getDS(keyStoreFile))
    {
      // Create a configuration file to use for the test.
      final File configFile = generateConfigFile(null, null);

      // Create a trust manager and SSL util configuration.
      final TopologyRegistryTrustManager trustManager =
           new TopologyRegistryTrustManager(configFile, 300_000L);
      final SSLUtil sslUtil = new SSLUtil(null, trustManager);

      // Verify that the connection attempt fails.
      try (LDAPConnection conn = new LDAPConnection(
           sslUtil.createSSLSocketFactory(), "localhost", ds.getListenPort()))
      {
        fail("Expected an exception when trying to establish " + conn);
      }
      catch (final LDAPException e)
      {
        assertEquals(e.getResultCode(), ResultCode.CONNECT_ERROR);
      }
    }
  }



  /**
   * Tests to ensure that a trust manager will not trust a certificate if the
   * server uses a certificate that does not match any of the ones in the
   * topology registry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testServerCertNotInTopologyRegistry()
         throws Exception
  {
    // Create a key store with a certificate to use for the test instance.
    final File ksFile = createTempFile();
    assertTrue(ksFile.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ResultCode resultCode = ManageCertificates.main(null, out, out,
         "generate-self-signed-certificate",
         "--keystore", ksFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ds.example.com,O=Example Corp,C=US");
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to generate a self-signed certificate:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));


    try (InMemoryDirectoryServer ds = getDS(ksFile))
    {
      // Create a configuration file to use for the test.
      final File configFile = generateConfigFile(pemCertificateLines, null);

      // Create a trust manager and SSL util configuration.
      final TopologyRegistryTrustManager trustManager =
           new TopologyRegistryTrustManager(configFile, 300_000L);
      final SSLUtil sslUtil = new SSLUtil(null, trustManager);

      // Verify that the connection attempt fails.
      try (LDAPConnection conn = new LDAPConnection(
           sslUtil.createSSLSocketFactory(), "localhost", ds.getListenPort()))
      {
        fail("Expected an exception when trying to establish " + conn);
      }
      catch (final LDAPException e)
      {
        assertEquals(e.getResultCode(), ResultCode.CONNECT_ERROR);
      }
    }
  }



  /**
   * Tests to ensure that a trust manager will not trust a certificate if the
   * topology registry has malformed certificate information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedCertificatesInConfig()
         throws Exception
  {
    try (InMemoryDirectoryServer ds = getDS(keyStoreFile))
    {
      // Create a configuration file to use for the test.
      final File configFile = generateConfigFile(
           Arrays.asList(
                "-----BEGIN CERTIFICATE-----",
                "Malformed inter-server certificate",
                "-----END CERTIFICATE-----"),
           Arrays.asList(
                "-----BEGIN CERTIFICATE-----",
                "Malformed listener certificate",
                "-----END CERTIFICATE-----"));

      // Create a trust manager and SSL util configuration.
      final TopologyRegistryTrustManager trustManager =
           new TopologyRegistryTrustManager(configFile, 300_000L);
      final SSLUtil sslUtil = new SSLUtil(null, trustManager);

      // Verify that the connection attempt fails.
      try (LDAPConnection conn = new LDAPConnection(
           sslUtil.createSSLSocketFactory(), "localhost", ds.getListenPort()))
      {
        fail("Expected an exception when trying to establish " + conn);
      }
      catch (final LDAPException e)
      {
        assertEquals(e.getResultCode(), ResultCode.CONNECT_ERROR);
      }
    }
  }



  /**
   * Tests to ensure that a trust manager can trust a certificate even if the
   * config file has one or more malformed entries, as long as the failure is
   * recoverable and does not affect the entry with the expected certificate
   * information.
   *
   * topology registry has malformed certificate information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRecoverableMalformedEntry()
         throws Exception
  {
    try (InMemoryDirectoryServer ds = getDS(keyStoreFile))
    {
      // Create a configuration file to use for the test.
      final File validConfigFile =
           generateConfigFile(pemCertificateLines, null);

      // Create a copy of the config file with a recoverably malformed entry
      // at the beginning of the file.
      final List<String> malformedConfigFileLines = new ArrayList<>(100);
      malformedConfigFileLines.add("this is a malformed entry");
      malformedConfigFileLines.add("");
      malformedConfigFileLines.addAll(readFileLines(validConfigFile));
      final File malformedConfigFile = createTempFile(
           malformedConfigFileLines.toArray(StaticUtils.NO_STRINGS));

      // Create a trust manager and SSL util configuration.
      final TopologyRegistryTrustManager trustManager =
           new TopologyRegistryTrustManager(malformedConfigFile, 300_000L);
      final SSLUtil sslUtil = new SSLUtil(null, trustManager);

      // Perform an initial test to ensure that the connection succeeds when
      // the configuration is not cached.
      try (LDAPConnection conn = new LDAPConnection(
           sslUtil.createSSLSocketFactory(), "localhost", ds.getListenPort()))
      {
        assertNotNull(conn.getRootDSE());
      }

      // Perform another test to ensure that the connection succeeds when the
      // configuration is cached.
      try (LDAPConnection conn = new LDAPConnection(
           sslUtil.createSSLSocketFactory(), "localhost", ds.getListenPort()))
      {
        assertNotNull(conn.getRootDSE());
      }
    }
  }



  /**
   * Tests to ensure that a trust manager will not be able to trust a
   * certificate if the config file contains a malformed entry that prevents
   * the file from being successfully read.
   *
   * topology registry has malformed certificate information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnrecoverableMalformedEntry()
         throws Exception
  {
    try (InMemoryDirectoryServer ds = getDS(keyStoreFile))
    {
      // Create a configuration file to use for the test.
      final File validConfigFile =
           generateConfigFile(pemCertificateLines, null);

      // Create a copy of the config file with an unrecoverably malformed entry
      // at the beginning of the file.  If a line starts with a space but does
      // not follow a non-blank line, then it suggests that it's a continuation
      // of a line that doesn't exist, and we have to fail.
      final List<String> malformedConfigFileLines = new ArrayList<>(100);
      malformedConfigFileLines.add(" this is an unrecoverably malformed entry");
      malformedConfigFileLines.add("");
      malformedConfigFileLines.addAll(readFileLines(validConfigFile));
      final File malformedConfigFile = createTempFile(
           malformedConfigFileLines.toArray(StaticUtils.NO_STRINGS));

      // Create a trust manager and SSL util configuration.
      final TopologyRegistryTrustManager trustManager =
           new TopologyRegistryTrustManager(malformedConfigFile, 300_000L);
      final SSLUtil sslUtil = new SSLUtil(null, trustManager);

      // Verify that the connection attempt fails.
      try (LDAPConnection conn = new LDAPConnection(
           sslUtil.createSSLSocketFactory(), "localhost", ds.getListenPort()))
      {
        fail("Expected an exception when trying to establish " + conn);
      }
      catch (final LDAPException e)
      {
        assertEquals(e.getResultCode(), ResultCode.CONNECT_ERROR);
      }
    }
  }



  /**
   * Tests the case in which the client is presented with a peer certificate
   * that is not yet valid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPeerCertificateNotYetValid()
         throws Exception
  {
    final File keyStore = createTempFile();
    assertTrue(keyStore.delete());

    final long tomorrowTimeMillis =
         System.currentTimeMillis() + TimeUnit.DAYS.toMillis(1L);
    final String tomorrowTimestamp =
         StaticUtils.encodeGeneralizedTime(tomorrowTimeMillis);

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    ResultCode resultCode = ManageCertificates.main(null, out, out,
         "generate-self-signed-certificate",
         "--keystore", keyStore.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ds.example.com,O=Example Corp,C=US",
         "--validity-start-time", tomorrowTimestamp);
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to generate a self-signed certificate:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));

    final File pemFile = createTempFile();
    assertTrue(pemFile.delete());

    out.reset();
    resultCode = ManageCertificates.main(null, out, out,
         "export-certificate",
         "--keystore", keyStore.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--output-format", "PEM",
         "--output-file", pemFile.getAbsolutePath());
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to export the self-signed certificate:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));

    final List<String> certLines = StaticUtils.readFileLines(pemFile);

    try (InMemoryDirectoryServer ds = getDS(keyStore))
    {
      // Create a configuration file to use for the test.
      final File configFile = generateConfigFile(certLines, null);

      // Create a trust manager and SSL util configuration.
      final TopologyRegistryTrustManager trustManager =
           new TopologyRegistryTrustManager(configFile, 300_000L);
      final SSLUtil sslUtil = new SSLUtil(null, trustManager);

      // Verify that the connection attempt fails.
      try (LDAPConnection conn = new LDAPConnection(
           sslUtil.createSSLSocketFactory(), "localhost", ds.getListenPort()))
      {
        fail("Expected an exception when trying to establish " + conn);
      }
      catch (final LDAPException e)
      {
        assertEquals(e.getResultCode(), ResultCode.CONNECT_ERROR);
      }
    }
  }



  /**
   * Tests the case in which the client is presented with a peer certificate
   * that is expired.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPeerCertificateExpired()
         throws Exception
  {
    final File keyStore = createTempFile();
    assertTrue(keyStore.delete());

    final long twoYearsAgoTimeMillis =
         System.currentTimeMillis() - TimeUnit.DAYS.toMillis(730L);
    final String twoYearsAgoTimestamp =
         StaticUtils.encodeGeneralizedTime(twoYearsAgoTimeMillis);

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    ResultCode resultCode = ManageCertificates.main(null, out, out,
         "generate-self-signed-certificate",
         "--keystore", keyStore.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ds.example.com,O=Example Corp,C=US",
         "--validity-start-time", twoYearsAgoTimestamp,
         "--days-valid", "365");
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to generate a self-signed certificate:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));

    final File pemFile = createTempFile();
    assertTrue(pemFile.delete());

    out.reset();
    resultCode = ManageCertificates.main(null, out, out,
         "export-certificate",
         "--keystore", keyStore.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--output-format", "PEM",
         "--output-file", pemFile.getAbsolutePath());
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to export the self-signed certificate:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));

    final List<String> certLines = StaticUtils.readFileLines(pemFile);

    try (InMemoryDirectoryServer ds = getDS(keyStore))
    {
      // Create a configuration file to use for the test.
      final File configFile = generateConfigFile(certLines, null);

      // Create a trust manager and SSL util configuration.
      final TopologyRegistryTrustManager trustManager =
           new TopologyRegistryTrustManager(configFile, 300_000L);
      final SSLUtil sslUtil = new SSLUtil(null, trustManager);

      // Verify that the connection attempt fails.
      try (LDAPConnection conn = new LDAPConnection(
           sslUtil.createSSLSocketFactory(), "localhost", ds.getListenPort()))
      {
        fail("Expected an exception when trying to establish " + conn);
      }
      catch (final LDAPException e)
      {
        assertEquals(e.getResultCode(), ResultCode.CONNECT_ERROR);
      }
    }
  }



  /**
   * Tests the case in which the client is presented with a certificate chain
   * that contains valid peer and issuer certifictes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIssuerCertificateValid()
         throws Exception
  {
    final File caKeyStore = createTempFile();
    assertTrue(caKeyStore.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    ResultCode resultCode = ManageCertificates.main(null, out, out,
         "generate-self-signed-certificate",
         "--keystore", caKeyStore.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "ca-cert",
         "--subject-dn", "CN=CA,O=Example Corp,C=US");
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to generate a self-signed CA certificate:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));

    final File caCertFile = createTempFile();
    assertTrue(caCertFile.delete());

    out.reset();
    resultCode = ManageCertificates.main(null, out, out,
         "export-certificate",
         "--keystore", caKeyStore.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "ca-cert",
         "--output-format", "PEM",
         "--output-file", caCertFile.getAbsolutePath());
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to export the CA certificate:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));

    final File serverKeyStore = createTempFile();
    assertTrue(serverKeyStore.delete());

    final File csrFile = createTempFile();
    assertTrue(csrFile.delete());

    out.reset();
    resultCode = ManageCertificates.main(null, out, out,
         "generate-certificate-signing-request",
         "--keystore", serverKeyStore.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-DN", "CN=ds.example.com,O=Example Corp,C=US",
         "--output-file", csrFile.getAbsolutePath(),
         "--output-format", "PEM");
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to generate a certificate signing request:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));

    final File certFile = createTempFile();
    assertTrue(certFile.delete());

    out.reset();
    resultCode = ManageCertificates.main(null, out, out,
         "sign-certificate-signing-request",
         "--keystore", caKeyStore.getAbsolutePath(),
         "--keystore-password", "password",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--signing-certificate-alias", "ca-cert",
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--output-format", "PEM",
         "--no-prompt");
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to sign a certificate signing request:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));

    out.reset();
    resultCode = ManageCertificates.main(null, out, out,
         "import-certificate",
         "--keystore", serverKeyStore.getAbsolutePath(),
         "--keystore-password", "password",
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", caCertFile.getAbsolutePath(),
         "--alias", "server-cert",
         "--no-prompt");
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to import the signed certificate:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));

    final List<String> certLines = StaticUtils.readFileLines(certFile);

    try (InMemoryDirectoryServer ds = getDS(serverKeyStore))
    {
      // Create a configuration file to use for the test.
      final File configFile = generateConfigFile(certLines, null);

      // Create a trust manager and SSL util configuration.
      final TopologyRegistryTrustManager trustManager =
           new TopologyRegistryTrustManager(configFile, 300_000L);
      final SSLUtil sslUtil = new SSLUtil(null, trustManager);

      // Perform an initial test to ensure that the connection succeeds when
      // the configuration is not cached.
      try (LDAPConnection conn = new LDAPConnection(
           sslUtil.createSSLSocketFactory(), "localhost", ds.getListenPort()))
      {
        assertNotNull(conn.getRootDSE());
      }

      // Perform another test to ensure that the connection succeeds when the
      // configuration is cached.
      try (LDAPConnection conn = new LDAPConnection(
           sslUtil.createSSLSocketFactory(), "localhost", ds.getListenPort()))
      {
        assertNotNull(conn.getRootDSE());
      }
    }
  }



  /**
   * Tests the case in which the client is presented with an issuer certificate
   * that is not yet valid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIssuerCertificateNotYetValid()
         throws Exception
  {
    final File caKeyStore = createTempFile();
    assertTrue(caKeyStore.delete());

    final long tomorrowTimeMillis =
         System.currentTimeMillis() + TimeUnit.DAYS.toMillis(1L);
    final String tomorrowTimestamp =
         StaticUtils.encodeGeneralizedTime(tomorrowTimeMillis);

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    ResultCode resultCode = ManageCertificates.main(null, out, out,
         "generate-self-signed-certificate",
         "--keystore", caKeyStore.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "ca-cert",
         "--subject-dn", "CN=CA,O=Example Corp,C=US",
         "--validity-start-time", tomorrowTimestamp);
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to generate a self-signed CA certificate:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));

    final File caCertFile = createTempFile();
    assertTrue(caCertFile.delete());

    out.reset();
    resultCode = ManageCertificates.main(null, out, out,
         "export-certificate",
         "--keystore", caKeyStore.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "ca-cert",
         "--output-format", "PEM",
         "--output-file", caCertFile.getAbsolutePath());
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to export the CA certificate:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));

    final File serverKeyStore = createTempFile();
    assertTrue(serverKeyStore.delete());

    final File csrFile = createTempFile();
    assertTrue(csrFile.delete());

    out.reset();
    resultCode = ManageCertificates.main(null, out, out,
         "generate-certificate-signing-request",
         "--keystore", serverKeyStore.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-DN", "CN=ds.example.com,O=Example Corp,C=US",
         "--output-file", csrFile.getAbsolutePath(),
         "--output-format", "PEM");
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to generate a certificate signing request:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));

    final File certFile = createTempFile();
    assertTrue(certFile.delete());

    out.reset();
    resultCode = ManageCertificates.main(null, out, out,
         "sign-certificate-signing-request",
         "--keystore", caKeyStore.getAbsolutePath(),
         "--keystore-password", "password",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--signing-certificate-alias", "ca-cert",
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--output-format", "PEM",
         "--no-prompt");
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to sign a certificate signing request:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));

    out.reset();
    resultCode = ManageCertificates.main(null, out, out,
         "import-certificate",
         "--keystore", serverKeyStore.getAbsolutePath(),
         "--keystore-password", "password",
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", caCertFile.getAbsolutePath(),
         "--alias", "server-cert",
         "--no-prompt");
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to import the signed certificate:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));

    final List<String> certLines = StaticUtils.readFileLines(certFile);

    try (InMemoryDirectoryServer ds = getDS(serverKeyStore))
    {
      // Create a configuration file to use for the test.
      final File configFile = generateConfigFile(certLines, null);

      // Create a trust manager and SSL util configuration.
      final TopologyRegistryTrustManager trustManager =
           new TopologyRegistryTrustManager(configFile, 300_000L);
      final SSLUtil sslUtil = new SSLUtil(null, trustManager);

      // Verify that the connection attempt fails.
      try (LDAPConnection conn = new LDAPConnection(
           sslUtil.createSSLSocketFactory(), "localhost", ds.getListenPort()))
      {
        fail("Expected an exception when trying to establish " + conn);
      }
      catch (final LDAPException e)
      {
        assertEquals(e.getResultCode(), ResultCode.CONNECT_ERROR);
      }
    }
  }



  /**
   * Tests the case in which the client is presented with an issuer certificate
   * that is expired.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIssuerCertificateExpired()
         throws Exception
  {
    final File caKeyStore = createTempFile();
    assertTrue(caKeyStore.delete());

    final long twoYearsAgoTimeMillis =
         System.currentTimeMillis() - TimeUnit.DAYS.toMillis(730L);
    final String twoYearsAgoTimestamp =
         StaticUtils.encodeGeneralizedTime(twoYearsAgoTimeMillis);

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    ResultCode resultCode = ManageCertificates.main(null, out, out,
         "generate-self-signed-certificate",
         "--keystore", caKeyStore.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "ca-cert",
         "--subject-dn", "CN=CA,O=Example Corp,C=US",
         "--validity-start-time", twoYearsAgoTimestamp,
         "--days-valid", "365");
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to generate a self-signed CA certificate:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));

    final File caCertFile = createTempFile();
    assertTrue(caCertFile.delete());

    out.reset();
    resultCode = ManageCertificates.main(null, out, out,
         "export-certificate",
         "--keystore", caKeyStore.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "ca-cert",
         "--output-format", "PEM",
         "--output-file", caCertFile.getAbsolutePath());
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to export the CA certificate:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));

    final File serverKeyStore = createTempFile();
    assertTrue(serverKeyStore.delete());

    final File csrFile = createTempFile();
    assertTrue(csrFile.delete());

    out.reset();
    resultCode = ManageCertificates.main(null, out, out,
         "generate-certificate-signing-request",
         "--keystore", serverKeyStore.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-DN", "CN=ds.example.com,O=Example Corp,C=US",
         "--output-file", csrFile.getAbsolutePath(),
         "--output-format", "PEM");
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to generate a certificate signing request:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));

    final File certFile = createTempFile();
    assertTrue(certFile.delete());

    out.reset();
    resultCode = ManageCertificates.main(null, out, out,
         "sign-certificate-signing-request",
         "--keystore", caKeyStore.getAbsolutePath(),
         "--keystore-password", "password",
         "--request-input-file", csrFile.getAbsolutePath(),
         "--signing-certificate-alias", "ca-cert",
         "--certificate-output-file", certFile.getAbsolutePath(),
         "--output-format", "PEM",
         "--no-prompt");
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to sign a certificate signing request:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));

    out.reset();
    resultCode = ManageCertificates.main(null, out, out,
         "import-certificate",
         "--keystore", serverKeyStore.getAbsolutePath(),
         "--keystore-password", "password",
         "--certificate-file", certFile.getAbsolutePath(),
         "--certificate-file", caCertFile.getAbsolutePath(),
         "--alias", "server-cert",
         "--no-prompt");
    assertEquals(resultCode, ResultCode.SUCCESS,
         "Failed to import the signed certificate:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(out.toByteArray()));

    final List<String> certLines = StaticUtils.readFileLines(certFile);

    try (InMemoryDirectoryServer ds = getDS(serverKeyStore))
    {
      // Create a configuration file to use for the test.
      final File configFile = generateConfigFile(certLines, null);

      // Create a trust manager and SSL util configuration.
      final TopologyRegistryTrustManager trustManager =
           new TopologyRegistryTrustManager(configFile, 300_000L);
      final SSLUtil sslUtil = new SSLUtil(null, trustManager);

      // Verify that the connection attempt fails.
      try (LDAPConnection conn = new LDAPConnection(
           sslUtil.createSSLSocketFactory(), "localhost", ds.getListenPort()))
      {
        fail("Expected an exception when trying to establish " + conn);
      }
      catch (final LDAPException e)
      {
        assertEquals(e.getResultCode(), ResultCode.CONNECT_ERROR);
      }
    }
  }



  /**
   * Tests the behavior when calling the {@code checkClientTrusted} method with
   * a valid certificate chain.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCheckClientTrustedValidCertificateChain()
         throws Exception
  {
    final X509Certificate[] chain;
    final KeyStore ks = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream is = new FileInputStream(keyStoreFile))
    {
      ks.load(is, "password".toCharArray());
    }

    final Certificate[] certChain = ks.getCertificateChain("server-cert");
    final X509Certificate[] x509CertChain =
         new X509Certificate[certChain.length];
    for (int i=0; i < certChain.length; i++)
    {
      x509CertChain[i] = (X509Certificate) certChain[i];
    }

    final File configFile = generateConfigFile(pemCertificateLines, null);
    final TopologyRegistryTrustManager trustManager =
         new TopologyRegistryTrustManager(configFile, 300_000L);
    trustManager.checkClientTrusted(x509CertChain, "RSA");
  }



  /**
   * Tests the behavior when calling the {@code checkClientTrusted} method with
   * a {@code null} certificate chain.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testClientTrustedNullCertificateChain()
         throws Exception
  {
    final File configFile = generateConfigFile(pemCertificateLines, null);
    final TopologyRegistryTrustManager trustManager =
         new TopologyRegistryTrustManager(configFile, 300_000L);
    trustManager.checkClientTrusted(null, "RSA");
  }



  /**
   * Tests the behavior when calling the {@code checkClientTrusted} method with
   * an empty certificate chain.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testClientTrustedEmptyCertificateChain()
         throws Exception
  {
    final File configFile = generateConfigFile(pemCertificateLines, null);
    final TopologyRegistryTrustManager trustManager =
         new TopologyRegistryTrustManager(configFile, 300_000L);
    trustManager.checkClientTrusted(
         TopologyRegistryTrustManager.NO_CERTIFICATES, "RSA");
  }



  /**
   * Tests the behavior when calling the {@code checkServerTrusted} method with
   * a valid certificate chain.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testServerTrustedValidCertificateChain()
         throws Exception
  {
    final X509Certificate[] chain;
    final KeyStore ks = CryptoHelper.getKeyStore("JKS");
    try (FileInputStream is = new FileInputStream(keyStoreFile))
    {
      ks.load(is, "password".toCharArray());
    }

    final Certificate[] certChain = ks.getCertificateChain("server-cert");
    final X509Certificate[] x509CertChain =
         new X509Certificate[certChain.length];
    for (int i=0; i < certChain.length; i++)
    {
      x509CertChain[i] = (X509Certificate) certChain[i];
    }


    final File configFile = generateConfigFile(pemCertificateLines, null);
    final TopologyRegistryTrustManager trustManager =
         new TopologyRegistryTrustManager(configFile, 300_000L);
    trustManager.checkServerTrusted(x509CertChain, "RSA");
  }



  /**
   * Tests the behavior when calling the {@code checkServerTrusted} method with
   * a {@code null} certificate chain.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testServerTrustedNullCertificateChain()
         throws Exception
  {
    final File configFile = generateConfigFile(pemCertificateLines, null);
    final TopologyRegistryTrustManager trustManager =
         new TopologyRegistryTrustManager(configFile, 300_000L);
    trustManager.checkServerTrusted(null, "RSA");
  }



  /**
   * Tests the behavior when calling the {@code checkServerTrusted} method with
   * an empty certificate chain.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertificateException.class })
  public void testServerTrustedEmptyCertificateChain()
         throws Exception
  {
    final File configFile = generateConfigFile(pemCertificateLines, null);
    final TopologyRegistryTrustManager trustManager =
         new TopologyRegistryTrustManager(configFile, 300_000L);
    trustManager.checkServerTrusted(
         TopologyRegistryTrustManager.NO_CERTIFICATES, "RSA");
  }



  /**
   * Retrieves an in-memory directory server instance that will accept secure
   * communication using the certificate in the provided key store.
   *
   * @param  keyStoreFile  The key store file containing the certificate to use.
   *
   * @return  The in-memory directory server instance that was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static InMemoryDirectoryServer getDS(final File keyStoreFile)
          throws Exception
  {
    final SSLUtil sslUtil = new SSLUtil(
         new KeyStoreKeyManager(keyStoreFile, "password".toCharArray()),
         new TrustAllTrustManager());

    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    dsCfg.setListenerConfigs(
         new InMemoryListenerConfig("LDAPS", null, 0,
              sslUtil.createSSLServerSocketFactory(),
              sslUtil.createSSLSocketFactory(), null));

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    ds.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");
    ds.add(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password");

    ds.startListening();

    return ds;
  }



  /**
   * Generates a sample configuration file that may be used for testing.
   *
   * @param  interServerCertLines  A list of the lines that comprise the
   *                               inter-server certificate content to include.
   *                               It may be {@code null} or empty if no
   *                               inter-server certificate information should
   *                               be included in the generated configuration.
   * @param  listenerCertLines     A lines of the lines that comprise the
   *                               listener certificate content to include.  It
   *                               may be {@code null} or empty if no listener
   *                               certificate information should be included in
   *                               the generated configuration.
   *
   * @return  The configuration file that was generated.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static File generateConfigFile(
                           final List<String> interServerCertLines,
                           final List<String> listenerCertLines)
          throws Exception
  {
    final File configFile = createTempFile();
    assertTrue(configFile.delete());

    try (LDIFWriter ldifWriter = new LDIFWriter(configFile))
    {
      ldifWriter.writeEntry(new Entry(
           "dn: cn=config",
           "objectClass: top",
           "objectClass: ds-cfg-root-config",
           "cn: config"));

      ldifWriter.writeEntry(new Entry(
           "dn: cn=Topology,cn=config",
           "objectClass: top",
           "objectClass: ds-cfg-branch",
           "objectClass: ds-mirrored-object",
           "cn: Topology"));

      ldifWriter.writeEntry(new Entry(
           "dn: cn=Server Instances,cn=Topology,cn=config",
           "objectClass: top",
           "objectClass: ds-cfg-branch",
           "objectClass: ds-mirrored-object",
           "cn: Server Instances"));

      final Entry instanceEntry = new Entry(
           "dn: cn=testInstance,cn=Server Instances,cn=Topology,cn=config",
           "objectClass: top",
           "objectClass: ds-cfg-branch",
           "objectClass: ds-cfg-server-instance",
           "objectClass: ds-cfg-data-store-server-instance",
           "objectClass: ds-mirrored-object",
           "cn: testInstance");
      if ((interServerCertLines != null) && (! interServerCertLines.isEmpty()))
      {
        instanceEntry.addAttribute("ds-cfg-inter-server-certificate",
             StaticUtils.linesToString(interServerCertLines));
      }
      ldifWriter.writeEntry(instanceEntry);

      ldifWriter.writeEntry(new Entry(
           "dn: cn=Server Instance Listeners,cn=testInstance,cn=Server " +
                "Instances,cn=Topology,cn=config",
           "objectClass: top",
           "objectClass: ds-cfg-branch",
           "objectClass: ds-mirrored-object",
           "cn: Server Instance Listeners"));

      final Entry listenerEntry = new Entry(
           "dn: cn=ldap-listener-mirrored-config,cn=Server Instance " +
                "Listeners,cn=testInstance,cn=Server " +
                "Instances,cn=Topology,cn=config",
           "objectClass: top",
           "objectClass: ds-cfg-branch",
           "objectClass: ds-cfg-server-instance-listener",
           "objectClass: ds-cfg-ldap-server-instance-listener",
           "objectClass: ds-mirrored-object",
           "cn: ldap-listener-mirrored-config");
      if ((listenerCertLines != null) && (! listenerCertLines.isEmpty()))
      {
        listenerEntry.addAttribute("ds-cfg-listener-certificate",
             StaticUtils.linesToString(listenerCertLines));
      }
      ldifWriter.writeEntry(listenerEntry);
    }

    return configFile;
  }
}
