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
package com.unboundid.util.ssl.cert;



import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the X.509 PEM file reader.
 */
public final class X509PEMFileReaderTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with a file that contains a single X.509 certificate.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleCertificate()
         throws Exception
  {
    // Generate a key store.
    final File keyStoreFile = createTempFile();
    assertTrue(keyStoreFile.delete());

    final String keyStorePath = keyStoreFile.getAbsolutePath();
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", keyStorePath,
         "--keystore-password", "password",
         "--alias", "cert",
         "--subject-dn", "CN=Test Cert");


    // Export the certificate to a PEM file.
    final File pemFile = createTempFile();
    assertTrue(pemFile.delete());

    final String pemFilePath = pemFile.getAbsolutePath();
    manageCertificates(
         "export-certificate",
         "--keystore", keyStorePath,
         "--keystore-password", "password",
         "--alias", "cert",
         "--output-format", "PEM",
         "--output-file", pemFilePath);


    // Read the contents of the PEM file.
    final List<String> fileLines = StaticUtils.readFileLines(pemFile);
    assertTrue(fileLines.contains("-----BEGIN CERTIFICATE-----"));
    assertTrue(fileLines.contains("-----END CERTIFICATE-----"));


    // Make sure that we can read the certificate from the file.
    try (X509PEMFileReader r = new X509PEMFileReader(pemFilePath))
    {
      final X509Certificate cert = r.readCertificate();
      assertNotNull(cert);

      assertNotNull(cert.toCertificate());
      assertTrue(
           cert.toCertificate() instanceof java.security.cert.X509Certificate);
      assertEquals(cert.toCertificate().getType(), "X.509");

      assertNull(r.readCertificate());
    }


    // Create a mew file with comments and blank lines that should be ignored.
    // Also, include leading and trailing spaces around all the lines.
    final List<String> linesWithCommentsAndBlanks =
         new ArrayList<>(Arrays.asList(
              "",
              "# This is a comment.",
              "# The next line is blank.",
              "",
              "",
              "# The previous line was blank"));
    for (final String line : fileLines)
    {
      linesWithCommentsAndBlanks.add(" " + line + " ");
    }

    final File alternativePEMFile = createTempFile(
         linesWithCommentsAndBlanks.toArray(StaticUtils.NO_STRINGS));


    // Make sure that we can read the certificate from the file even with all
    // the extra stuff in it.
    try (X509PEMFileReader r = new X509PEMFileReader(alternativePEMFile))
    {
      final X509Certificate cert = r.readCertificate();
      assertNotNull(cert);

      assertNotNull(cert.toCertificate());
      assertTrue(
           cert.toCertificate() instanceof java.security.cert.X509Certificate);
      assertEquals(cert.toCertificate().getType(), "X.509");

      assertNull(r.readCertificate());
    }


    // Create a new file with all of the base64-encoded data on a single line.
    final StringBuilder base64Data = new StringBuilder();
    for (final String line : fileLines)
    {
      if (line.equals("-----BEGIN CERTIFICATE-----") ||
           line.equals("-----END CERTIFICATE-----"))
      {
        continue;
      }

      base64Data.append(line);
    }

    final File pemFileWithSingleLineCert = createTempFile(
         "-----BEGIN CERTIFICATE-----",
         base64Data.toString(),
         "-----END CERTIFICATE-----");


    // Make sure that we can read the certificate from the file.
    try (X509PEMFileReader r =
              new X509PEMFileReader(pemFileWithSingleLineCert))
    {
      final X509Certificate cert = r.readCertificate();
      assertNotNull(cert);

      assertNotNull(cert.toCertificate());
      assertTrue(
           cert.toCertificate() instanceof java.security.cert.X509Certificate);
      assertEquals(cert.toCertificate().getType(), "X.509");

      assertNull(r.readCertificate());
    }
  }



  /**
   * Tests the behavior with a file that contains a certificate chain consisting
   * of multiple certificates.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCertificateChain()
         throws Exception
  {
    // Create a key store with a self-signed root CA certificate.  Export that
    // certificate to a file.
    final File rootCAKeyStoreFile = createTempFile();
    assertTrue(rootCAKeyStoreFile.delete());

    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", rootCAKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "root-ca-cert",
         "--subject-dn", "CN=Test Root CA Cert");

    final File rootCACertificatePEMFile = createTempFile();
    assertTrue(rootCACertificatePEMFile.delete());

    manageCertificates(
         "export-certificate",
         "--keystore", rootCAKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "root-ca-cert",
         "--output-format", "PEM",
         "--output-file", rootCACertificatePEMFile.getAbsolutePath());


    // Create a key store with an intermediate CA certificate that has been
    // signed by the root CA.
    final File intermediateCAKeyStoreFile = createTempFile();
    assertTrue(intermediateCAKeyStoreFile.delete());

    final File intermediateCACSRFile = createTempFile();
    assertTrue(intermediateCACSRFile.delete());

    manageCertificates(
         "generate-certificate-signing-request",
         "--keystore", intermediateCAKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "intermediate-ca-cert",
         "--subject-dn", "CN=Test Intermediate CA Cert",
         "--output-format", "PEM",
         "--output-file", intermediateCACSRFile.getAbsolutePath());

    final File intermediateCACertificatePEMFile = createTempFile();
    assertTrue(intermediateCACertificatePEMFile.delete());

    manageCertificates(
         "sign-certificate-signing-request",
         "--keystore", rootCAKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--request-input-file", intermediateCACSRFile.getAbsolutePath(),
         "--certificate-output-file",
              intermediateCACertificatePEMFile.getAbsolutePath(),
         "--output-format", "PEM",
         "--signing-certificate-alias", "root-ca-cert",
         "--include-requested-extensions",
         "--no-prompt");

    manageCertificates(
         "import-certificate",
         "--keystore", intermediateCAKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "intermediate-ca-cert",
         "--certificate-file",
              intermediateCACertificatePEMFile.getAbsolutePath(),
         "--certificate-file", rootCACertificatePEMFile.getAbsolutePath(),
         "--no-prompt");


    // Create a key store with an end entity certificate that has been signed
    //  by the intermediate CA.
    final File serverCertificateKeyStoreFile = createTempFile();
    assertTrue(serverCertificateKeyStoreFile.delete());

    final File serverCertificateCSRFile = createTempFile();
    assertTrue(serverCertificateCSRFile.delete());

    manageCertificates(
         "generate-certificate-signing-request",
         "--keystore", serverCertificateKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=Test Server Cert",
         "--output-format", "PEM",
         "--output-file", serverCertificateCSRFile.getAbsolutePath());

    final File serverCertificatePEMFile = createTempFile();
    assertTrue(serverCertificatePEMFile.delete());

    manageCertificates(
         "sign-certificate-signing-request",
         "--keystore", intermediateCAKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--request-input-file", serverCertificateCSRFile.getAbsolutePath(),
         "--certificate-output-file",
              serverCertificatePEMFile.getAbsolutePath(),
         "--output-format", "PEM",
         "--signing-certificate-alias", "intermediate-ca-cert",
         "--include-requested-extensions",
         "--no-prompt");

    manageCertificates(
         "import-certificate",
         "--keystore", serverCertificateKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--certificate-file", serverCertificatePEMFile.getAbsolutePath(),
         "--certificate-file",
              intermediateCACertificatePEMFile.getAbsolutePath(),
         "--certificate-file", rootCACertificatePEMFile.getAbsolutePath(),
         "--no-prompt");


    // Export the server certificate chain.
    final File certificateChainPEMFile = createTempFile();
    assertTrue(certificateChainPEMFile.delete());

    manageCertificates(
         "export-certificate",
         "--keystore", serverCertificateKeyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--export-certificate-chain",
         "--output-format", "PEM",
         "--output-file", certificateChainPEMFile.getAbsolutePath());


    // Make sure that we can read all three of the certificates from the PEM
    // file.
    try (X509PEMFileReader r =
              new X509PEMFileReader(certificateChainPEMFile.getAbsolutePath()))
    {
      final X509Certificate serverCert = r.readCertificate();
      assertNotNull(serverCert);
      assertEquals(serverCert.getSubjectDN(), new DN("CN=Test Server Cert"));

      final X509Certificate intermediateCACert = r.readCertificate();
      assertNotNull(intermediateCACert);
      assertEquals(intermediateCACert.getSubjectDN(),
           new DN("CN=Test Intermediate CA Cert"));

      final X509Certificate rootCACert = r.readCertificate();
      assertNotNull(rootCACert);
      assertEquals(rootCACert.getSubjectDN(), new DN("CN=Test Root CA Cert"));
    }
  }



  /**
   * Tests the behavior when trying to read a certificate from an empty file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyFile()
         throws Exception
  {
    final File emptyFile = createTempFile();
    try (X509PEMFileReader r = new X509PEMFileReader(emptyFile))
    {
      assertNull(r.readCertificate());
    }
  }



  /**
   * Tests the behavior when trying to read a certificate from a file that
   * contains only comments and blank lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFileWithOnlyCommentsAndBlankLines()
         throws Exception
  {
    final File f = createTempFile(
         "# Comment",
         "");
    try (X509PEMFileReader r = new X509PEMFileReader(f))
    {
      assertNull(r.readCertificate());
    }
  }



  /**
   * Tests the behavior for files with begin header and end footer issues.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHeaderAndFooterIssues()
         throws Exception
  {
    // Generate a test key store.
    final File keyStoreFile = createTempFile();
    assertTrue(keyStoreFile.delete());

    final String keyStorePath = keyStoreFile.getAbsolutePath();
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", keyStorePath,
         "--keystore-password", "password",
         "--alias", "cert",
         "--subject-dn", "CN=Test Cert");


    // Export the certificate to a PEM file.
    final File pemFile = createTempFile();
    assertTrue(pemFile.delete());

    final String pemFilePath = pemFile.getAbsolutePath();
    manageCertificates(
         "export-certificate",
         "--keystore", keyStorePath,
         "--keystore-password", "password",
         "--alias", "cert",
         "--output-format", "PEM",
         "--output-file", pemFilePath);


    // Read the contents of the certificate file.
    final List<String> fileLines = StaticUtils.readFileLines(pemFile);


    // Make sure that we can read the certificate from the file.
    try (X509PEMFileReader r = new X509PEMFileReader(pemFilePath))
    {
      final X509Certificate cert = r.readCertificate();
      assertNotNull(cert);
    }


    // Test with a PEM file that is missing the begin header.
    final File pemFileWithoutBeginHeader = createTempFile();
    try (PrintWriter w = new PrintWriter(pemFileWithoutBeginHeader))
    {
      for (final String line : fileLines)
      {
        if (! line.equals("-----BEGIN CERTIFICATE-----"))
        {
          w.println(line);
        }
      }
    }

    try (X509PEMFileReader r =
              new X509PEMFileReader(pemFileWithoutBeginHeader))
    {
      try
      {
        r.readCertificate();
        fail("Expected an exception because of a missing begin header.");
      }
      catch (final CertException e)
      {
        // This was expected.
      }
    }


    // Test with a PEM file that has a duplicate begin header.
    final File pemFileWithDuplicateBeginHeader = createTempFile();
    try (PrintWriter w = new PrintWriter(pemFileWithDuplicateBeginHeader))
    {
      w.println("-----BEGIN CERTIFICATE-----");
      for (final String line : fileLines)
      {
        w.println(line);
      }
    }

    try (X509PEMFileReader r =
              new X509PEMFileReader(pemFileWithDuplicateBeginHeader))
    {
      try
      {
        r.readCertificate();
        fail("Expected an exception because of a duplicate begin header.");
      }
      catch (final CertException e)
      {
        // This was expected.
      }
    }


    // Test with a PEM file that is missing the end footer.
    final File pemFileWithoutEndFooter = createTempFile();
    try (PrintWriter w = new PrintWriter(pemFileWithoutEndFooter))
    {
      for (final String line : fileLines)
      {
        if (! line.equals("-----END CERTIFICATE-----"))
        {
          w.println(line);
        }
      }
    }

    try (X509PEMFileReader r =
              new X509PEMFileReader(pemFileWithoutEndFooter))
    {
      try
      {
        r.readCertificate();
        fail("Expected an exception because of a missing end footer.");
      }
      catch (final CertException e)
      {
        // This was expected.
      }
    }


    // Test with a PEM file that has a duplicate end footer.
    final File pemFileWithDuplicateEndFooter = createTempFile();
    try (PrintWriter w = new PrintWriter(pemFileWithDuplicateEndFooter))
    {
      for (final String line : fileLines)
      {
        w.println(line);
      }
      w.println("-----END CERTIFICATE-----");
    }

    try (X509PEMFileReader r =
              new X509PEMFileReader(pemFileWithDuplicateEndFooter))
    {
      assertNotNull(r.readCertificate());

      try
      {
        r.readCertificate();
        fail("Expected an exception because of a duplicate end footer.");
      }
      catch (final CertException e)
      {
        // This was expected.
      }
    }


    // Test with a PEM file that has an end footer immediately after the begin
    // header without any intervening base64-encoded data.
    final File pemFileWithoutBase64Data = createTempFile(
         "-----BEGIN CERTIFICATE-----",
         "-----END CERTIFICATE-----");

    try (X509PEMFileReader r =
              new X509PEMFileReader(pemFileWithoutBase64Data))
    {
      try
      {
        r.readCertificate();
        fail("Expected an exception because of no base64 data.");
      }
      catch (final CertException e)
      {
        // This was expected.
      }
    }
  }



  /**
   * Tests the behavior when trying to read a certificate from a file without
   * valid base64-encoded data.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFileWithInvalidBase64()
         throws Exception
  {
    final File f = createTempFile(
         "-----BEGIN CERTIFICATE-----",
         "This is not valid base64-encoded data.",
         "-----END CERTIFICATE-----");
    try (X509PEMFileReader r = new X509PEMFileReader(f))
    {
      try
      {
        r.readCertificate();
        fail("Expected an exception because of invalid base64 data.");
      }
      catch (final CertException e)
      {
        // This was expected.
      }
    }
  }



  /**
   * Tests the behavior when trying to read a certificate from a file in which
   * the base64-encoded data cannot be parsed as a valid X.509 certificate.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFileWithInvalidCertificate()
         throws Exception
  {
    final File f = createTempFile(
         "-----BEGIN CERTIFICATE-----",
         Base64.encode("This is not a valid X.509 certificate."),
         "-----END CERTIFICATE-----");
    try (X509PEMFileReader r = new X509PEMFileReader(f))
    {
      try
      {
        r.readCertificate();
        fail("Expected an exception because of invalid certificate data.");
      }
      catch (final CertException e)
      {
        // This was expected.
      }
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
}
