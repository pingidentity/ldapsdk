/*
 * Copyright 2021-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021-2023 Ping Identity Corporation
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
 * Copyright (C) 2021-2023 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ssl.cert.ManageCertificates;



/**
 * This class provides a set of test cases for the
 * {@code CertificateDataReplaceCertificateKeyStoreContent} class.
 */
public final class CertificateDataReplaceCertificateKeyStoreContentTestCase
       extends LDAPSDKTestCase
{
  /**
   * A pre-allocated null file.
   */
  private static final File NULL_FILE = null;



  /**
   * Tests the behavior for a key store content object with only the required
   * fields set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalFieldsSet()
         throws Exception
  {
    final byte[] testCert1Bytes = StaticUtils.getBytes("test-cert-1");
    final List<byte[]> testCertChainData =
         Collections.singletonList(testCert1Bytes);
    CertificateDataReplaceCertificateKeyStoreContent c =
         new CertificateDataReplaceCertificateKeyStoreContent(
              testCertChainData, null);

    c = CertificateDataReplaceCertificateKeyStoreContent.decodeInternal(
         c.encode());
    assertNotNull(c);

    assertNotNull(c.getCertificateChainData());
    assertEquals(c.getCertificateChainData().size(), 1);
    assertEquals(c.getCertificateChainData().get(0), testCert1Bytes);

    assertNull(c.getPrivateKeyData());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior for a key store content object with values set for all
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllFieldsSet()
         throws Exception
  {
    final byte[] testCert1Bytes = StaticUtils.getBytes("test-cert-1");
    final byte[] testCert2Bytes = StaticUtils.getBytes("test-cert-2");
    final byte[] testCert3Bytes = StaticUtils.getBytes("test-cert-3");
    final List<byte[]> testCertChainData =
         Arrays.asList(testCert1Bytes, testCert2Bytes, testCert3Bytes);

    final byte[] testPrivateKeyData = StaticUtils.getBytes("test-private-key");
    CertificateDataReplaceCertificateKeyStoreContent c =
         new CertificateDataReplaceCertificateKeyStoreContent(
              testCertChainData, testPrivateKeyData);

    c = CertificateDataReplaceCertificateKeyStoreContent.decodeInternal(
         c.encode());
    assertNotNull(c);

    assertNotNull(c.getCertificateChainData());
    assertEquals(c.getCertificateChainData().size(), 3);
    assertEquals(c.getCertificateChainData().get(0), testCert1Bytes);
    assertEquals(c.getCertificateChainData().get(1), testCert2Bytes);
    assertEquals(c.getCertificateChainData().get(2), testCert3Bytes);

    assertNotNull(c.getPrivateKeyData());
    assertEquals(c.getPrivateKeyData(), testPrivateKeyData);

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when attempting to decode an ASN.1 element that is not a
   * valid sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeElementNotSequence()
         throws Exception
  {
    try
    {
      CertificateDataReplaceCertificateKeyStoreContent.decodeInternal(
           new ASN1OctetString(
                CertificateDataReplaceCertificateKeyStoreContent.
                     TYPE_KEY_STORE_CONTENT,
                "not-a-valid-asn1-sequence"));
      fail("Expected an exception when trying to decode an encoded element " +
           "whose value is not a valid sequence.");
    }
    catch (final LDAPException e)
    {
      // This was expected.
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior when trying to create certificate data from files
   * that contain the PEM representations of certificates and private keys.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateFromPEMFiles()
         throws Exception
  {
    // Generate a self-signed Ca certificate.
    final String keyStorePath = getTestFilePath();
    final String caCertPath = getTestFilePath();
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "generate-self-signed-certificate",
              "--keystore", keyStorePath,
              "--keystore-password", "password",
              "--alias", "ca-cert",
              "--subject-dn", "CN=Example CA,O=Example Corp,C=US",
              "--days-valid", "7300",
              "--output-file", caCertPath,
              "--output-format", "PEM"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));


    // Generate a certificate signing request for a server certificate.
    out.reset();
    final String serverCertRequestPath = getTestFilePath();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "generate-certificate-signing-request",
              "--keystore", keyStorePath,
              "--keystore-password", "password",
              "--alias", "server-cert",
              "--subject-dn", "CN=ds.example.com,O=Example Corp,C=US",
              "--output-file", serverCertRequestPath,
              "--output-format", "PEM"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));


    // Sign the certificate signing request.
    out.reset();
    final String serverCertPath = getTestFilePath();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "sign-certificate-signing-request",
              "--keystore", keyStorePath,
              "--keystore-password", "password",
              "--signing-certificate-alias", "ca-cert",
              "--request-input-file", serverCertRequestPath,
              "--certificate-output-file", serverCertPath,
              "--output-format", "PEM",
              "--days-valid", "365",
              "--include-requested-extensions",
              "--no-prompt"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));


    // Import the signed certificate chain into the key store.
    out.reset();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "import-certificate",
              "--keystore", keyStorePath,
              "--keystore-password", "password",
              "--alias", "server-cert",
              "--certificate-file", serverCertPath,
              "--certificate-file", caCertPath,
              "--no-prompt"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));


    // Export the private key for the server certificate.
    out.reset();
    final String serverKeyPath = getTestFilePath();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "export-private-key",
              "--keystore", keyStorePath,
              "--keystore-password", "password",
              "--alias", "server-cert",
              "--output-file", serverKeyPath,
              "--output-format", "PEM"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));


    // Export the private key for the server certificate in encrypted form.
    out.reset();
    final String encryptedServerKeyPath = getTestFilePath();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "export-private-key",
              "--keystore", keyStorePath,
              "--keystore-password", "password",
              "--alias", "server-cert",
              "--output-file", encryptedServerKeyPath,
              "--output-format", "PEM",
              "--encryption-password", "encryption-password"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));


    // Make sure that we can create a certificate data object with the PEM
    // certificate chain and private key.
    CertificateDataReplaceCertificateKeyStoreContent c =
         new CertificateDataReplaceCertificateKeyStoreContent(
              Arrays.asList(
                   new File(serverCertPath),
                   new File(caCertPath)),
              new File(serverKeyPath));

    c = CertificateDataReplaceCertificateKeyStoreContent.decodeInternal(
         c.encode());
    assertNotNull(c);

    assertNotNull(c.getCertificateChainData());
    assertEquals(c.getCertificateChainData().size(), 2);

    assertNotNull(c.getPrivateKeyData());


    // Make sure that we can create a certificate data object with the PEM
    // certificate chain and encrypted private key.
    c =
         new CertificateDataReplaceCertificateKeyStoreContent(
              Arrays.asList(
                   new File(serverCertPath),
                   new File(caCertPath)),
              new File(serverKeyPath),
              "encryption-password".toCharArray());

    c = CertificateDataReplaceCertificateKeyStoreContent.decodeInternal(
         c.encode());
    assertNotNull(c);

    assertNotNull(c.getCertificateChainData());
    assertEquals(c.getCertificateChainData().size(), 2);

    assertNotNull(c.getPrivateKeyData());


    // Make sure that we can also create a certificate data object with the PEM
    // certificate chain without the private key.
    c = new CertificateDataReplaceCertificateKeyStoreContent(
              Arrays.asList(
                   new File(serverCertPath),
                   new File(caCertPath)),
              NULL_FILE);

    c = CertificateDataReplaceCertificateKeyStoreContent.decodeInternal(
         c.encode());
    assertNotNull(c);

    assertNotNull(c.getCertificateChainData());
    assertEquals(c.getCertificateChainData().size(), 2);

    assertNull(c.getPrivateKeyData());


    // Also cover the readCertificateChain method that takes an array of files.
    assertEquals(
         CertificateDataReplaceCertificateKeyStoreContent.readCertificateChain(
              new File(serverCertPath),
              new File(caCertPath)).size(),
         2);


    // Concatenate the files together into a single file and verify that
    // the readCertificateChain method will still get both certificates.
    final String serverCertPEM =
         StaticUtils.readFileAsString(serverCertPath, true);
    final String caCertPEM =
         StaticUtils.readFileAsString(caCertPath, true);
    final File combinedCertFile = createTempFile(
         serverCertPEM, caCertPEM);
    assertEquals(
         CertificateDataReplaceCertificateKeyStoreContent.readCertificateChain(
              combinedCertFile).size(),
         2);
  }



  /**
   * Tests the behavior when trying to create certificate data from files
   * that contain the DER representations of certificates and private keys.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateFromDERFiles()
         throws Exception
  {
    // Generate a self-signed Ca certificate.
    final String keyStorePath = getTestFilePath();
    final String caCertPath = getTestFilePath();
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "generate-self-signed-certificate",
              "--keystore", keyStorePath,
              "--keystore-password", "password",
              "--alias", "ca-cert",
              "--subject-dn", "CN=Example CA,O=Example Corp,C=US",
              "--days-valid", "7300",
              "--output-file", caCertPath,
              "--output-format", "DER"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));


    // Generate a certificate signing request for a server certificate.
    out.reset();
    final String serverCertRequestPath = getTestFilePath();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "generate-certificate-signing-request",
              "--keystore", keyStorePath,
              "--keystore-password", "password",
              "--alias", "server-cert",
              "--subject-dn", "CN=ds.example.com,O=Example Corp,C=US",
              "--output-file", serverCertRequestPath,
              "--output-format", "DER"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));


    // Sign the certificate signing request.
    out.reset();
    final String serverCertPath = getTestFilePath();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "sign-certificate-signing-request",
              "--keystore", keyStorePath,
              "--keystore-password", "password",
              "--signing-certificate-alias", "ca-cert",
              "--request-input-file", serverCertRequestPath,
              "--certificate-output-file", serverCertPath,
              "--output-format", "DER",
              "--days-valid", "365",
              "--include-requested-extensions",
              "--no-prompt"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));


    // Import the signed certificate chain into the key store.
    out.reset();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "import-certificate",
              "--keystore", keyStorePath,
              "--keystore-password", "password",
              "--alias", "server-cert",
              "--certificate-file", serverCertPath,
              "--certificate-file", caCertPath,
              "--no-prompt"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));


    // Export the private key for the server certificate.
    out.reset();
    final String serverKeyPath = getTestFilePath();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "export-private-key",
              "--keystore", keyStorePath,
              "--keystore-password", "password",
              "--alias", "server-cert",
              "--output-file", serverKeyPath,
              "--output-format", "DER"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));


    // Make sure that we can create a certificate data object with the DER
    // certificate chain and private key.
    CertificateDataReplaceCertificateKeyStoreContent c =
         new CertificateDataReplaceCertificateKeyStoreContent(
              Arrays.asList(
                   new File(serverCertPath),
                   new File(caCertPath)),
              new File(serverKeyPath));

    c = CertificateDataReplaceCertificateKeyStoreContent.decodeInternal(
         c.encode());
    assertNotNull(c);

    assertNotNull(c.getCertificateChainData());
    assertEquals(c.getCertificateChainData().size(), 2);

    assertNotNull(c.getPrivateKeyData());


    // Make sure that we can create a certificate data object with the DER
    // certificate chain without the private key.
    c = new CertificateDataReplaceCertificateKeyStoreContent(
              Arrays.asList(
                   new File(serverCertPath),
                   new File(caCertPath)),
              NULL_FILE);

    c = CertificateDataReplaceCertificateKeyStoreContent.decodeInternal(
         c.encode());
    assertNotNull(c);

    assertNotNull(c.getCertificateChainData());
    assertEquals(c.getCertificateChainData().size(), 2);

    assertNull(c.getPrivateKeyData());


    // Also cover the readCertificateChain method that takes an array of files.
    assertEquals(
         CertificateDataReplaceCertificateKeyStoreContent.readCertificateChain(
              new File(serverCertPath),
              new File(caCertPath)).size(),
         2);


    // Concatenate the files together into a single file and verify that
    // the readCertificateChain method will still get both certificates.
    final byte[] serverCertDER = StaticUtils.readFileBytes(serverCertPath);
    final byte[] caCertDER = StaticUtils.readFileBytes(caCertPath);

    final File combinedCertFile = createTempFile();
    assertTrue(combinedCertFile.delete());
    try (FileOutputStream outputStream = new FileOutputStream(combinedCertFile))
    {
      outputStream.write(serverCertDER);
      outputStream.write(caCertDER);
    }

    assertEquals(
         CertificateDataReplaceCertificateKeyStoreContent.readCertificateChain(
              combinedCertFile).size(),
         2);
  }



  /**
   * Tests the behavior of the {@code readCertificateChain} method when provided
   * with a file that does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadCertificateChainFromNonexistentFile()
         throws Exception
  {
    try
    {
      final File f = createTempFile();
      assertTrue(f.delete());

      CertificateDataReplaceCertificateKeyStoreContent.readCertificateChain(f);
      fail("Expected an exception when trying to read a chain from a " +
           "nonexistent file");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior of the {@code readCertificateChain} method when provided
   * with an empty file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadCertificateChainFromEmptyFile()
         throws Exception
  {
    try
    {
      final File f = createTempFile();

      CertificateDataReplaceCertificateKeyStoreContent.readCertificateChain(f);
      fail("Expected an exception when trying to read a chain from an empty " +
           "file");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior of the {@code readCertificateChain} method when provided
   * with a file that contains a malformed DER-encoded certificate.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadCertificateChainFromMalformedDERFile()
         throws Exception
  {
    try
    {
      final File f = createTempFile();
      assertTrue(f.delete());
      try (FileOutputStream outputStream = new FileOutputStream(f))
      {
        // Write just the DER sequence header without any other data.
        outputStream.write(0x30);
      }

      CertificateDataReplaceCertificateKeyStoreContent.readCertificateChain(f);
      fail("Expected an exception when trying to read a chain from a " +
           "malformed DER file");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior of the {@code readCertificateChain} method when provided
   * with a file that contains a malformed PEM-encoded certificate.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadCertificateChainFromMalformedPEMFile()
         throws Exception
  {
    try
    {
      final File f = createTempFile(
           "-----BEGIN MALFORMED CERTIFICATE-----");

      CertificateDataReplaceCertificateKeyStoreContent.readCertificateChain(f);
      fail("Expected an exception when trying to read a chain from a " +
           "malformed PEM file");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior of the {@code readPrivateKey} method when provided with
   * a file that does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadPrivateKeyFromNonexistentFile()
         throws Exception
  {
    try
    {
      final File f = createTempFile();
      assertTrue(f.delete());

      CertificateDataReplaceCertificateKeyStoreContent.readPrivateKey(f);
      fail("Expected an exception when trying to read a key from a " +
           "nonexistent file");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior of the {@code readPrivateKey} method when provided with
   * an empty file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadPrivateKeyFromEmptyFile()
         throws Exception
  {
    try
    {
      final File f = createTempFile();

      CertificateDataReplaceCertificateKeyStoreContent.readPrivateKey(f);
      fail("Expected an exception when trying to read a key from an empty " +
           "file");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior of the {@code readPrivateKey} method when provided with
   * a file that contains a malformed DER-encoded key.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadPrivateKeyFromMalformedDERFile()
         throws Exception
  {
    try
    {
      final File f = createTempFile();
      assertTrue(f.delete());
      try (FileOutputStream outputStream = new FileOutputStream(f))
      {
        // Write just the DER sequence header without any other data.
        outputStream.write(0x30);
      }

      CertificateDataReplaceCertificateKeyStoreContent.readPrivateKey(f);
      fail("Expected an exception when trying to read a key from a " +
           "malformed DER file");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior of the {@code readPrivateKey} method when provided with
   * a file that contains a malformed PEM-encoded certificate.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadPrivateKeyFromMalformedPEMFile()
         throws Exception
  {
    try
    {
      final File f = createTempFile(
           "-----BEGIN MALFORMED KEY-----");

      CertificateDataReplaceCertificateKeyStoreContent.readPrivateKey(f);
      fail("Expected an exception when trying to read a key from a " +
           "malformed PEM file");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior of the {@code readPrivateKey} method when provided with
   * a file that contains multiple DER-encoded private keys.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadPrivateKeyFromFileWithMultipleDERKeys()
         throws Exception
  {
    // Generate a pair of self-signed certificates and export their private keys
    // to DER files.
    final String keyStorePath = getTestFilePath();
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "generate-self-signed-certificate",
              "--keystore", keyStorePath,
              "--keystore-password", "password",
              "--alias", "cert-1",
              "--subject-dn", "CN=Cert 1,O=Example Corp,C=US"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertEquals(
         ManageCertificates.main(null, out, out,
              "generate-self-signed-certificate",
              "--keystore", keyStorePath,
              "--keystore-password", "password",
              "--alias", "cert-2",
              "--subject-dn", "CN=Cert 2,O=Example Corp,C=US"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    final String privateKey1Path = getTestFilePath();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "export-private-key",
              "--keystore", keyStorePath,
              "--keystore-password", "password",
              "--alias", "cert-1",
              "--output-file", privateKey1Path,
              "--output-format", "DER"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    final String privateKey2Path = getTestFilePath();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "export-private-key",
              "--keystore", keyStorePath,
              "--keystore-password", "password",
              "--alias", "cert-2",
              "--output-file", privateKey2Path,
              "--output-format", "DER"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));


    // Concatenate the private key files.
    final byte[] privateKey1Bytes = StaticUtils.readFileBytes(privateKey1Path);
    final byte[] privateKey2Bytes = StaticUtils.readFileBytes(privateKey2Path);

    final File combinedKeysFile = createTempFile();
    assertTrue(combinedKeysFile.delete());
    try (FileOutputStream outputStream = new FileOutputStream(combinedKeysFile))
    {
      outputStream.write(privateKey1Bytes);
      outputStream.write(privateKey2Bytes);
    }


    // Verify that we get an exception when trying to read a private key from
    // the combined file.
    try
    {
      CertificateDataReplaceCertificateKeyStoreContent.readPrivateKey(
           combinedKeysFile);
      fail("Expected an exception when trying to read a DER-encoded private " +
           "key from a file with multiple keys");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior of the {@code readPrivateKey} method when provided with
   * a file that contains multiple PEM-encoded private keys.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadPrivateKeyFromFileWithMultiplePEMKeys()
         throws Exception
  {
    // Generate a pair of self-signed certificates and export their private keys
    // to PEM files.
    final String keyStorePath = getTestFilePath();
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "generate-self-signed-certificate",
              "--keystore", keyStorePath,
              "--keystore-password", "password",
              "--alias", "cert-1",
              "--subject-dn", "CN=Cert 1,O=Example Corp,C=US"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertEquals(
         ManageCertificates.main(null, out, out,
              "generate-self-signed-certificate",
              "--keystore", keyStorePath,
              "--keystore-password", "password",
              "--alias", "cert-2",
              "--subject-dn", "CN=Cert 2,O=Example Corp,C=US"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    final String privateKey1Path = getTestFilePath();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "export-private-key",
              "--keystore", keyStorePath,
              "--keystore-password", "password",
              "--alias", "cert-1",
              "--output-file", privateKey1Path,
              "--output-format", "PEM"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    final String privateKey2Path = getTestFilePath();
    assertEquals(
         ManageCertificates.main(null, out, out,
              "export-private-key",
              "--keystore", keyStorePath,
              "--keystore-password", "password",
              "--alias", "cert-2",
              "--output-file", privateKey2Path,
              "--output-format", "PEM"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));


    // Concatenate the private key files.
    final String privateKey1PEM =
         StaticUtils.readFileAsString(privateKey1Path, true);
    final String privateKey2PEM =
         StaticUtils.readFileAsString(privateKey2Path, true);

    final File combinedKeysFile =
         createTempFile(privateKey1PEM, privateKey2PEM);


    // Verify that we get an exception when trying to read a private key from
    // the combined file.
    try
    {
      CertificateDataReplaceCertificateKeyStoreContent.readPrivateKey(
           combinedKeysFile);
      fail("Expected an exception when trying to read a PEM-encoded private " +
           "key from a file with multiple keys");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }
  }



  /**
   * Retrieves a path that can be used for a test file.  The file will not
   * exist.
   *
   * @return  A path that can be used for a test file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static String getTestFilePath()
          throws Exception
  {
    final File f = createTempFile();
    assertTrue(f.delete());
    return f.getAbsolutePath();
  }
}
