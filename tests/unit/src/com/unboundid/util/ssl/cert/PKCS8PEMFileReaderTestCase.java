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

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the PKCS #8 PEM file reader.
 */
public final class PKCS8PEMFileReaderTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with a file that contains a single RSA private key.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidRSAPrivateKey()
         throws Exception
  {
    // Generate a key store with an RSA key.
    final File keyStoreFile = createTempFile();
    assertTrue(keyStoreFile.delete());

    final String keyStorePath = keyStoreFile.getAbsolutePath();
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", keyStorePath,
         "--keystore-password", "password",
         "--alias", "cert",
         "--subject-dn", "CN=Test Cert",
         "--key-algorithm", "RSA",
         "--key-size-bits", "2048",
         "--signature-algorithm", "SHA256withRSA");


    // Export the private key to a PEM file.
    final File pemFile = createTempFile();
    assertTrue(pemFile.delete());

    final String pemFilePath = pemFile.getAbsolutePath();
    manageCertificates(
         "export-private-key",
         "--keystore", keyStorePath,
         "--keystore-password", "password",
         "--alias", "cert",
         "--output-format", "PEM",
         "--output-file", pemFilePath);


    // Read the contents of the private key file and verify that it uses the
    // generic "-----BEGIN PRIVATE KEY-----" header and the
    // "-----END PRIVATE KEY-----" footer.
    final List<String> fileLines = StaticUtils.readFileLines(pemFile);
    assertTrue(fileLines.contains("-----BEGIN PRIVATE KEY-----"));
    assertTrue(fileLines.contains("-----END PRIVATE KEY-----"));


    // Make sure that we can read the private key from the file.
    try (PKCS8PEMFileReader r = new PKCS8PEMFileReader(pemFilePath))
    {
      final PKCS8PrivateKey privateKey = r.readPrivateKey();
      assertNotNull(privateKey);

      assertNotNull(privateKey.getPrivateKeyAlgorithmName());
      assertEquals(privateKey.getPrivateKeyAlgorithmName(), "RSA");

      assertEquals(privateKey.toPrivateKey().getAlgorithm(), "RSA");

      assertNull(r.readPrivateKey());
    }


    // Create a mew file with comments and blank lines that should be ignored.
    // Also, include leading and trailing spaces around the private key lines,
    // and replace the header and footer lines with RSA-specific values.
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
      if (line.equals("-----BEGIN PRIVATE KEY-----"))
      {
        linesWithCommentsAndBlanks.add("  -----begin rsa private key-----  ");
      }
      else if (line.equals("-----END PRIVATE KEY-----"))
      {
        linesWithCommentsAndBlanks.add("  -----End RSA Private Key-----  ");
      }
      else
      {
        linesWithCommentsAndBlanks.add(" " + line + " ");
      }
    }

    final File alternativePEMFile = createTempFile(
         linesWithCommentsAndBlanks.toArray(StaticUtils.NO_STRINGS));


    // Make sure that we can read the private key from the file even with all
    // the extra stuff in it.
    try (PKCS8PEMFileReader r = new PKCS8PEMFileReader(alternativePEMFile))
    {
      final PKCS8PrivateKey privateKey = r.readPrivateKey();
      assertNotNull(privateKey);

      assertNotNull(privateKey.getPrivateKeyAlgorithmName());
      assertEquals(privateKey.getPrivateKeyAlgorithmName(), "RSA");

      assertEquals(privateKey.toPrivateKey().getAlgorithm(), "RSA");

      assertNull(r.readPrivateKey());
    }


    // Create a new file with all of the base64-encoded data on a single line.
    final StringBuilder base64Data = new StringBuilder();
    for (final String line : fileLines)
    {
      if (line.equals("-----BEGIN PRIVATE KEY-----") ||
           line.equals("-----END PRIVATE KEY-----"))
      {
        continue;
      }

      base64Data.append(line);
    }

    final File pemFileWithSingleLineKey = createTempFile(
         "-----BEGIN PRIVATE KEY-----",
         base64Data.toString(),
         "-----END PRIVATE KEY-----");


    // Make sure that we can read the private key from the file.
    try (PKCS8PEMFileReader r =
              new PKCS8PEMFileReader(pemFileWithSingleLineKey))
    {
      final PKCS8PrivateKey privateKey = r.readPrivateKey();
      assertNotNull(privateKey);

      assertNotNull(privateKey.getPrivateKeyAlgorithmName());
      assertEquals(privateKey.getPrivateKeyAlgorithmName(), "RSA");

      assertEquals(privateKey.toPrivateKey().getAlgorithm(), "RSA");

      assertNull(r.readPrivateKey());
    }
  }



  /**
   * Tests the behavior with a file that contains a single elliptic curve
   * private key.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidECPrivateKey()
         throws Exception
  {
    // Generate a key store with an elliptic curve key.
    final File keyStoreFile = createTempFile();
    assertTrue(keyStoreFile.delete());

    final String keyStorePath = keyStoreFile.getAbsolutePath();
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", keyStorePath,
         "--keystore-password", "password",
         "--alias", "cert",
         "--subject-dn", "CN=Test Cert",
         "--key-algorithm", "EC",
         "--key-size-bits", "256",
         "--signature-algorithm", "SHA256withECDSA");


    // Export the private key to a PEM file.
    final File pemFile = createTempFile();
    assertTrue(pemFile.delete());

    final String pemFilePath = pemFile.getAbsolutePath();
    manageCertificates(
         "export-private-key",
         "--keystore", keyStorePath,
         "--keystore-password", "password",
         "--alias", "cert",
         "--output-format", "PEM",
         "--output-file", pemFilePath);


    // Read the contents of the private key file and verify that it uses the
    // generic "-----BEGIN PRIVATE KEY-----" header and the
    // "-----END PRIVATE KEY-----" footer.
    final List<String> fileLines = StaticUtils.readFileLines(pemFile);
    assertTrue(fileLines.contains("-----BEGIN PRIVATE KEY-----"));
    assertTrue(fileLines.contains("-----END PRIVATE KEY-----"));


    // Make sure that we can read the private key from the file.
    try (PKCS8PEMFileReader r = new PKCS8PEMFileReader(pemFilePath))
    {
      final PKCS8PrivateKey privateKey = r.readPrivateKey();
      assertNotNull(privateKey);

      assertNotNull(privateKey.getPrivateKeyAlgorithmName());
      assertEquals(privateKey.getPrivateKeyAlgorithmName(), "EC");

      assertEquals(privateKey.toPrivateKey().getAlgorithm(), "EC");

      assertNull(r.readPrivateKey());
    }
  }



  /**
   * Tests the behavior when trying to read a private key from an empty file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyFile()
         throws Exception
  {
    final File emptyFile = createTempFile();
    try (PKCS8PEMFileReader r = new PKCS8PEMFileReader(emptyFile))
    {
      assertNull(r.readPrivateKey());
    }
  }



  /**
   * Tests the behavior when trying to read a private key from a file that
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
    try (PKCS8PEMFileReader r = new PKCS8PEMFileReader(f))
    {
      assertNull(r.readPrivateKey());
    }
  }



  /**
   * Test the behavior when trying to read from a file that contains multiple
   * valid private keys.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFileWithMultiplePrivateKeys()
         throws Exception
  {
    // Generate a key store with multiple certificates.
    final File keyStoreFile = createTempFile();
    assertTrue(keyStoreFile.delete());

    final String keyStorePath = keyStoreFile.getAbsolutePath();
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", keyStorePath,
         "--keystore-password", "password",
         "--alias", "cert1",
         "--subject-dn", "CN=Test Cert 1");
    manageCertificates(
         "generate-self-signed-certificate",
         "--keystore", keyStorePath,
         "--keystore-password", "password",
         "--alias", "cert2",
         "--subject-dn", "CN=Test Cert 2");


    // Export the private keys to separate PEM files.
    final File cert1PEMFile = createTempFile();
    assertTrue(cert1PEMFile.delete());

    final String cert1PEMFilePath = cert1PEMFile.getAbsolutePath();
    manageCertificates(
         "export-private-key",
         "--keystore", keyStorePath,
         "--keystore-password", "password",
         "--alias", "cert1",
         "--output-format", "PEM",
         "--output-file", cert1PEMFilePath);

    final File cert2PEMFile = createTempFile();
    assertTrue(cert2PEMFile.delete());

    final String cert2PEMFilePath = cert2PEMFile.getAbsolutePath();
    manageCertificates(
         "export-private-key",
         "--keystore", keyStorePath,
         "--keystore-password", "password",
         "--alias", "cert2",
         "--output-format", "PEM",
         "--output-file", cert2PEMFilePath);


    // Create a single file with both private keys.
    final File combinedKeysPEMFile = createTempFile();
    try (PrintWriter w = new PrintWriter(combinedKeysPEMFile))
    {
      for (final String line : StaticUtils.readFileLines(cert1PEMFile))
      {
        w.println(line);
      }

      for (final String line : StaticUtils.readFileLines(cert2PEMFile))
      {
        w.println(line);
      }
    }


    // Verify that we can read both private keys from the PEM file.
    try (PKCS8PEMFileReader r = new PKCS8PEMFileReader(combinedKeysPEMFile))
    {
      assertNotNull(r.readPrivateKey());
      assertNotNull(r.readPrivateKey());
      assertNull(r.readPrivateKey());
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


    // Export the private key to a PEM file.
    final File pemFile = createTempFile();
    assertTrue(pemFile.delete());

    final String pemFilePath = pemFile.getAbsolutePath();
    manageCertificates(
         "export-private-key",
         "--keystore", keyStorePath,
         "--keystore-password", "password",
         "--alias", "cert",
         "--output-format", "PEM",
         "--output-file", pemFilePath);


    // Read the contents of the private key file and verify that it uses the
    // generic "-----BEGIN PRIVATE KEY-----" header and the
    // "-----END PRIVATE KEY-----" footer.
    final List<String> fileLines = StaticUtils.readFileLines(pemFile);
    assertTrue(fileLines.contains("-----BEGIN PRIVATE KEY-----"));
    assertTrue(fileLines.contains("-----END PRIVATE KEY-----"));


    // Make sure that we can read the private key from the file.
    try (PKCS8PEMFileReader r = new PKCS8PEMFileReader(pemFilePath))
    {
      final PKCS8PrivateKey privateKey = r.readPrivateKey();
      assertNotNull(privateKey);
    }


    // Test with a PEM file that is missing the begin header.
    final File pemFileWithoutBeginHeader = createTempFile();
    try (PrintWriter w = new PrintWriter(pemFileWithoutBeginHeader))
    {
      for (final String line : fileLines)
      {
        if (! line.equals("-----BEGIN PRIVATE KEY-----"))
        {
          w.println(line);
        }
      }
    }

    try (PKCS8PEMFileReader r =
              new PKCS8PEMFileReader(pemFileWithoutBeginHeader))
    {
      try
      {
        r.readPrivateKey();
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
      w.println("-----BEGIN PRIVATE KEY-----");
      for (final String line : fileLines)
      {
        w.println(line);
      }
    }

    try (PKCS8PEMFileReader r =
              new PKCS8PEMFileReader(pemFileWithDuplicateBeginHeader))
    {
      try
      {
        r.readPrivateKey();
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
        if (! line.equals("-----END PRIVATE KEY-----"))
        {
          w.println(line);
        }
      }
    }

    try (PKCS8PEMFileReader r =
              new PKCS8PEMFileReader(pemFileWithoutEndFooter))
    {
      try
      {
        r.readPrivateKey();
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
      w.println("-----END PRIVATE KEY-----");
    }

    try (PKCS8PEMFileReader r =
              new PKCS8PEMFileReader(pemFileWithDuplicateEndFooter))
    {
      assertNotNull(r.readPrivateKey());

      try
      {
        r.readPrivateKey();
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
         "-----BEGIN PRIVATE KEY-----",
         "-----END PRIVATE KEY-----");

    try (PKCS8PEMFileReader r =
              new PKCS8PEMFileReader(pemFileWithoutBase64Data))
    {
      try
      {
        r.readPrivateKey();
        fail("Expected an exception because of no base64 data.");
      }
      catch (final CertException e)
      {
        // This was expected.
      }
    }
  }



  /**
   * Tests the behavior when trying to read a private key from a file without
   * valid base64-encoded data.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFileWithInvalidBase64()
         throws Exception
  {
    final File f = createTempFile(
         "-----BEGIN PRIVATE KEY-----",
         "This is not valid base64-encoded data.",
         "-----END PRIVATE KEY-----");
    try (PKCS8PEMFileReader r = new PKCS8PEMFileReader(f))
    {
      try
      {
        r.readPrivateKey();
        fail("Expected an exception because of invalid base64 data.");
      }
      catch (final CertException e)
      {
        // This was expected.
      }
    }
  }



  /**
   * Tests the behavior when trying to read a private key from a file in which
   * the base64-encoded data cannot be parsed as a valid PKCS #8 private key.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFileWithInvalidPrivateKey()
         throws Exception
  {
    final File f = createTempFile(
         "-----BEGIN PRIVATE KEY-----",
         Base64.encode("This is not a valid PKCS #8 private key."),
         "-----END PRIVATE KEY-----");
    try (PKCS8PEMFileReader r = new PKCS8PEMFileReader(f))
    {
      try
      {
        r.readPrivateKey();
        fail("Expected an exception because of invalid private key data.");
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
