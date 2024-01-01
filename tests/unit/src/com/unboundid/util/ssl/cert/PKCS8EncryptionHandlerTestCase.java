/*
 * Copyright 2022-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2024 Ping Identity Corporation
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
 * Copyright (C) 2022-2024 Ping Identity Corporation
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



import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1ObjectIdentifier;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NullOutputStream;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the PKCS #8 encryption handler
 * class.
 */
public final class PKCS8EncryptionHandlerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests to ensure that it's possible to encrypt and decrypt PKCS #8 private
   * keys with a variety of settings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncryptAndDecryptPrivateKey()
         throws Exception
  {
    // Create a self-signed certificate and get its private key.
    final File keyStoreFile = createTempFile();
    assertTrue(keyStoreFile.delete());

    final InputStream in = new ByteArrayInputStream(StaticUtils.NO_BYTES);
    final OutputStream out = NullOutputStream.getInstance();
    assertEquals(
         ManageCertificates.main(in, out, out,
              "generate-self-signed-certificate",
              "--keystore", keyStoreFile.getAbsolutePath(),
              "--keystore-password", "password",
              "--keystore-type", "JKS",
              "--alias", "server-cert",
              "--subject-dn", "CN=ds.example.com,O=Example Corp,C=US"),
         ResultCode.SUCCESS);

    final byte[] privateKeyBytes = getPrivateKeyBytes(keyStoreFile);
    final PKCS8PrivateKey privateKey = new PKCS8PrivateKey(privateKeyBytes);


    // Get a PEM representation of the certificate.
    final File certificatePEMFile = createTempFile();
    assertTrue(certificatePEMFile.delete());
    assertEquals(
         ManageCertificates.main(in, out, out,
              "export-certificate",
              "--keystore", keyStoreFile.getAbsolutePath(),
              "--keystore-password", "password",
              "--alias", "server-cert",
              "--output-file", certificatePEMFile.getAbsolutePath(),
              "--output-format", "PEM"),
         ResultCode.SUCCESS);


    // Test encryption and decryption with all of the supported PRF and cipher
    // algorithms.
    for (final PKCS5AlgorithmIdentifier prfAlgorithm :
         PKCS5AlgorithmIdentifier.getPseudorandomFunctions())
    {
      for (final PKCS5AlgorithmIdentifier cipherAlgorithm :
           PKCS5AlgorithmIdentifier.getCipherTransformations())
      {
        for (final int iterationCount : new int[] { 2048, 4096 })
        {
          for (final int saltLengthBytes : new int[] { 8, 16 })
          {
            // Encrypt and decrypt the private key.
            final PKCS8EncryptionProperties encryptionProperties =
                 new PKCS8EncryptionProperties();
            encryptionProperties.setKeyFactoryPRFAlgorithm(prfAlgorithm);
            encryptionProperties.setKeyFactoryIterationCount(iterationCount);
            encryptionProperties.setKeyFactorySaltLengthBytes(saltLengthBytes);
            encryptionProperties.setCipherTransformationAlgorithm(
                 cipherAlgorithm);

            final char[] encryptionPassword =
                 StaticUtils.randomAlphanumericString(12, true).toCharArray();

            final byte[] encryptedKeyBytes =
                 PKCS8EncryptionHandler.encryptPrivateKey(privateKey,
                      encryptionPassword, encryptionProperties);
            assertNotNull(encryptedKeyBytes);
            assertFalse(Arrays.equals(encryptedKeyBytes, privateKeyBytes));

            final PKCS8PrivateKey decryptedPrivateKey =
                 PKCS8EncryptionHandler.decryptPrivateKey(
                      encryptedKeyBytes, encryptionPassword);
            assertNotNull(decryptedPrivateKey);
            assertEquals(decryptedPrivateKey.getPKCS8PrivateKeyBytes(),
                 privateKeyBytes);


            // Test writing the encrypted private key to PEM.
            final File encryptedPEMArrayFile = createTempFile();
            assertTrue(encryptedPEMArrayFile.delete());
            try (PrintWriter w = new PrintWriter(encryptedPEMArrayFile))
            {
              for (final String pemLine :
                   privateKey.toEncryptedPEM(encryptionPassword,
                        encryptionProperties))
              {
                w.println(pemLine);
              }
            }

            final File encryptedPEMStringFile = createTempFile();
            assertTrue(encryptedPEMStringFile.delete());
            try (PrintWriter w = new PrintWriter(encryptedPEMStringFile))
            {
              w.println(privateKey.toEncryptedPEMString(encryptionPassword,
                   encryptionProperties));
            }


            // Test reading the encrypted PEM files back.
            for (final File f :
                 new File[] { encryptedPEMArrayFile, encryptedPEMStringFile })
            {
              try (PKCS8PEMFileReader r = new PKCS8PEMFileReader(f))
              {
                final PKCS8PrivateKey keyFromPEM =
                     r.readPrivateKey(encryptionPassword);
                assertNotNull(keyFromPEM);

                assertEquals(keyFromPEM.getPKCS8PrivateKeyBytes(),
                     privateKeyBytes);
              }
            }


            // Test importing the certificate and private key into a new key
            // store.
            final File newKeyStoreFile = createTempFile();
            assertTrue(newKeyStoreFile.delete());

            assertEquals(
                 ManageCertificates.main(in, out, out,
                      "import-certificate",
                      "--keystore", newKeyStoreFile.getAbsolutePath(),
                      "--keystore-password", "password",
                      "--alias", "server-cert",
                      "--certificate-file",
                           certificatePEMFile.getAbsolutePath(),
                      "--private-key-file",
                           encryptedPEMStringFile.getAbsolutePath(),
                      "--encryption-password", new String(encryptionPassword),
                      "--no-prompt"),
                 ResultCode.SUCCESS);

            assertEquals(getPrivateKeyBytes(newKeyStoreFile), privateKeyBytes);
          }
        }
      }
    }
  }



  /**
   * Retrieves the bytes that comprise the private key stored in the server-cert
   * alias of the specifierd JKS key store.
   *
   * @param  keyStoreFile  The key store file.
   *
   * @return  The bytes that comprise the private key.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static byte[] getPrivateKeyBytes(final File keyStoreFile)
          throws Exception
  {
    final KeyStore keyStore = KeyStore.getInstance("JKS");
    try (FileInputStream inputStream = new FileInputStream(keyStoreFile))
    {
      keyStore.load(inputStream, "password".toCharArray());
    }

    return  keyStore.getKey("server-cert",
         "password".toCharArray()).getEncoded();
  }



  /**
   * Tests the behavior when trying to decrypt a private key when the provided
   * byte array cannot be parsed as an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecryptPrivateKeyNotSequence()
         throws Exception
  {
    try
    {
      PKCS8EncryptionHandler.decryptPrivateKey(
           StaticUtils.getBytes("this is not a valid sequence"),
           "password".toCharArray());
      fail("Expected an exception when trying to decrypt a key that isn't a " +
           "valid sequence.");
    }
    catch (final CertException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to decrypt a private key when the provided
   * byte array represents a sequence that doesn't contain exactly two elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecryptPrivateKeySequenceNotTwoElements()
         throws Exception
  {
    try
    {
      PKCS8EncryptionHandler.decryptPrivateKey(
           new ASN1Sequence(new ASN1OctetString("foo")).encode(),
           "password".toCharArray());
      fail("Expected an exception when trying to decrypt a key sequence that " +
           "doesn't contain exactly two elements.");
    }
    catch (final CertException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to decrypt a private key when the provided
   * byte array represents a sequence in which the first element isn't a
   * sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecryptPrivateKeySequenceFirstElementNotSequence()
         throws Exception
  {
    try
    {
      PKCS8EncryptionHandler.decryptPrivateKey(
           new ASN1Sequence(
                new ASN1OctetString("not a sequence"),
                new ASN1OctetString("does not matter")).encode(),
           "password".toCharArray());
      fail("Expected an exception when trying to decrypt a key sequence in " +
           "which the first element is not a sequence.");
    }
    catch (final CertException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to decrypt a private key when the provided
   * byte array represents a sequence in which the first element is a sequence
   * that doesn't have exactly two elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecryptPrivateKeySequenceFirstSequenceNotTwoElements()
         throws Exception
  {
    try
    {
      PKCS8EncryptionHandler.decryptPrivateKey(
           new ASN1Sequence(
                new ASN1Sequence(
                     new ASN1OctetString("foo")),
                new ASN1OctetString("does not matter")).encode(),
           "password".toCharArray());
      fail("Expected an exception when trying to decrypt a key sequence in " +
           "which the first element is a sequence that doesn't contain two " +
           "elements.");
    }
    catch (final CertException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to decrypt a private key when the provided
   * byte array represents a sequence in which the first element is a sequence
   * in which the first element isn't a valid OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecryptPrivateKeySequenceFirstSequenceElementNotOID()
         throws Exception
  {
    try
    {
      PKCS8EncryptionHandler.decryptPrivateKey(
           new ASN1Sequence(
                new ASN1Sequence(
                     new ASN1OctetString(""),
                     new ASN1OctetString("bar")),
                new ASN1OctetString("does not matter")).encode(),
           "password".toCharArray());
      fail("Expected an exception when trying to decrypt a key sequence in " +
           "which the first element is a sequence in which the first element " +
           "is not an OID.");
    }
    catch (final CertException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to decrypt a private key when the provided
   * byte array represents a sequence in which the first element is a sequence
   * in which the first element isn't the OID for the PBES2 encryption scheme.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecryptPrivateKeyNotUsingPBES2()
         throws Exception
  {
    try
    {
      PKCS8EncryptionHandler.decryptPrivateKey(
           new ASN1Sequence(
                new ASN1Sequence(
                     new ASN1ObjectIdentifier("1.2.3.4"),
                     new ASN1OctetString("bar")),
                new ASN1OctetString("does not matter")).encode(),
           "password".toCharArray());
      fail("Expected an exception when trying to decrypt a key sequence in " +
           "which the encryption scheme OID isn't the OID for PBES2.");
    }
    catch (final CertException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to decrypt a private key when the provided
   * byte array represents a sequence in which the PBES2 parameters element
   * isn't a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecryptPrivateKeyPBES2ParamsNotSequence()
         throws Exception
  {
    try
    {
      PKCS8EncryptionHandler.decryptPrivateKey(
           new ASN1Sequence(
                new ASN1Sequence(
                     new ASN1ObjectIdentifier(
                          PKCS5AlgorithmIdentifier.PBES2.getOID()),
                     new ASN1OctetString("not a sequence")),
                new ASN1OctetString("does not matter")).encode(),
           "password".toCharArray());
      fail("Expected an exception when trying to decrypt a key sequence in " +
           "which the PBES2 parameters element isn't a sequence.");
    }
    catch (final CertException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to decrypt a private key when the provided
   * byte array represents a sequence in which the PBES2 parameters element
   * is a sequence that doesn't contain two elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecryptPrivateKeyPBES2ParamsNotTwoElementSequence()
         throws Exception
  {
    try
    {
      PKCS8EncryptionHandler.decryptPrivateKey(
           new ASN1Sequence(
                new ASN1Sequence(
                     new ASN1ObjectIdentifier(
                          PKCS5AlgorithmIdentifier.PBES2.getOID()),
                     new ASN1Sequence(
                          new ASN1OctetString("foo"))),
                new ASN1OctetString("does not matter")).encode(),
           "password".toCharArray());
      fail("Expected an exception when trying to decrypt a key sequence in " +
           "which the PBES2 parameters sequence doesn't contain two elements.");
    }
    catch (final CertException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to decrypt a private key when the provided
   * byte array represents a sequence in which the KDF element can't be
   * properly decoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecryptPrivateKeyMalformedKDFElement()
         throws Exception
  {
    try
    {
      PKCS8EncryptionHandler.decryptPrivateKey(
           new ASN1Sequence(
                new ASN1Sequence(
                     new ASN1ObjectIdentifier(
                          PKCS5AlgorithmIdentifier.PBES2.getOID()),
                     new ASN1Sequence(
                          new ASN1OctetString(""),
                          new ASN1OctetString(""))),
                new ASN1OctetString("does not matter")).encode(),
           "password".toCharArray());
      fail("Expected an exception when trying to decrypt a key sequence in " +
           "which the KDF element is malformed.");
    }
    catch (final CertException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to decrypt a private key when the provided
   * byte array represents a sequence in which the KDF element indicates an
   * algorithm other than PBKDF2.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecryptPrivateKeyKDFNotPBKDF2()
         throws Exception
  {
    try
    {
      PKCS8EncryptionHandler.decryptPrivateKey(
           new ASN1Sequence(
                new ASN1Sequence(
                     new ASN1ObjectIdentifier(
                          PKCS5AlgorithmIdentifier.PBES2.getOID()),
                     new ASN1Sequence(
                          new ASN1Sequence(
                               new ASN1ObjectIdentifier("1.2.3.4"),
                               new ASN1Sequence()),
                          new ASN1Sequence())),
                new ASN1OctetString("does not matter")).encode(),
           "password".toCharArray());
      fail("Expected an exception when trying to decrypt a key sequence in " +
           "which the KDF is not PBKDF2.");
    }
    catch (final CertException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to decrypt a private key when the provided
   * byte array represents a sequence in which the PRF element is unrecognized.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecryptPrivateKeyUnrecognizedPRF()
         throws Exception
  {
    try
    {
      PKCS8EncryptionHandler.decryptPrivateKey(
           new ASN1Sequence(
                new ASN1Sequence(
                     new ASN1ObjectIdentifier(
                          PKCS5AlgorithmIdentifier.PBES2.getOID()),
                     new ASN1Sequence(
                          new ASN1Sequence(
                               new ASN1ObjectIdentifier(
                                    PKCS5AlgorithmIdentifier.PBKDF2.getOID()),
                               new ASN1Sequence(
                                    new ASN1OctetString(""),
                                    new ASN1Integer(2048),
                                    new ASN1Sequence(
                                         new ASN1ObjectIdentifier("1.2.3.4"),
                                         new ASN1OctetString()))),
                          new ASN1Sequence())),
                new ASN1OctetString("does not matter")).encode(),
           "password".toCharArray());
      fail("Expected an exception when trying to decrypt a key sequence in " +
           "which the PRF is unrecognized.");
    }
    catch (final CertException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to decrypt a private key when the provided
   * byte array represents a sequence in which the PRF element is recognized
   * but not a PRF.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecryptPrivateKeyPRFNotPRF()
         throws Exception
  {
    try
    {
      PKCS8EncryptionHandler.decryptPrivateKey(
           new ASN1Sequence(
                new ASN1Sequence(
                     new ASN1ObjectIdentifier(
                          PKCS5AlgorithmIdentifier.PBES2.getOID()),
                     new ASN1Sequence(
                          new ASN1Sequence(
                               new ASN1ObjectIdentifier(
                                    PKCS5AlgorithmIdentifier.PBKDF2.getOID()),
                               new ASN1Sequence(
                                    new ASN1OctetString(""),
                                    new ASN1Integer(2048),
                                    new ASN1Sequence(
                                         new ASN1ObjectIdentifier(
                                              PKCS5AlgorithmIdentifier.
                                                   AES_128_CBC_PAD.getOID()),
                                         new ASN1OctetString()))),
                          new ASN1Sequence())),
                new ASN1OctetString("does not matter")).encode(),
           "password".toCharArray());
      fail("Expected an exception when trying to decrypt a key sequence in " +
           "which the PRF is recognized but doesn't identify a PRF.");
    }
    catch (final CertException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to decrypt a private key when the provided
   * byte array represents a sequence in which the cipher transformation element
   * is malformed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecryptPrivateKeyMalformedCipherTransformation()
         throws Exception
  {
    try
    {
      PKCS8EncryptionHandler.decryptPrivateKey(
           new ASN1Sequence(
                new ASN1Sequence(
                     new ASN1ObjectIdentifier(
                          PKCS5AlgorithmIdentifier.PBES2.getOID()),
                     new ASN1Sequence(
                          new ASN1Sequence(
                               new ASN1ObjectIdentifier(
                                    PKCS5AlgorithmIdentifier.PBKDF2.getOID()),
                               new ASN1Sequence(
                                    new ASN1OctetString(""),
                                    new ASN1Integer(2048),
                                    new ASN1Sequence(
                                         new ASN1ObjectIdentifier(
                                              PKCS5AlgorithmIdentifier.
                                                   HMAC_SHA_256.getOID()),
                                         new ASN1OctetString()))),
                          new ASN1OctetString("foo"))),
                new ASN1OctetString("does not matter")).encode(),
           "password".toCharArray());
      fail("Expected an exception when trying to decrypt a key sequence in " +
           "which the cipher transformation element is malformed.");
    }
    catch (final CertException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to decrypt a private key when the provided
   * byte array represents a sequence in which the cipher transformation OID
   * is unrecognized.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecryptPrivateKeyUnrecognizedCipherTransformationOID()
         throws Exception
  {
    try
    {
      PKCS8EncryptionHandler.decryptPrivateKey(
           new ASN1Sequence(
                new ASN1Sequence(
                     new ASN1ObjectIdentifier(
                          PKCS5AlgorithmIdentifier.PBES2.getOID()),
                     new ASN1Sequence(
                          new ASN1Sequence(
                               new ASN1ObjectIdentifier(
                                    PKCS5AlgorithmIdentifier.PBKDF2.getOID()),
                               new ASN1Sequence(
                                    new ASN1OctetString(""),
                                    new ASN1Integer(2048),
                                    new ASN1Sequence(
                                         new ASN1ObjectIdentifier(
                                              PKCS5AlgorithmIdentifier.
                                                   HMAC_SHA_256.getOID()),
                                         new ASN1OctetString()))),
                          new ASN1Sequence(
                               new ASN1ObjectIdentifier("1.2.3.4"),
                               new ASN1OctetString()))),
                new ASN1OctetString("does not matter")).encode(),
           "password".toCharArray());
      fail("Expected an exception when trying to decrypt a key sequence in " +
           "which the cipher transformation OID is unrecognized.");
    }
    catch (final CertException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to decrypt a private key when the provided
   * byte array represents a sequence in which the cipher transformation OID
   * is recognized but not a cipher transformation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecryptPrivateKeyUnrecognizedCipherTransformationOIDNotCT()
         throws Exception
  {
    try
    {
      PKCS8EncryptionHandler.decryptPrivateKey(
           new ASN1Sequence(
                new ASN1Sequence(
                     new ASN1ObjectIdentifier(
                          PKCS5AlgorithmIdentifier.PBES2.getOID()),
                     new ASN1Sequence(
                          new ASN1Sequence(
                               new ASN1ObjectIdentifier(
                                    PKCS5AlgorithmIdentifier.PBKDF2.getOID()),
                               new ASN1Sequence(
                                    new ASN1OctetString(""),
                                    new ASN1Integer(2048),
                                    new ASN1Integer(128),
                                    new ASN1Sequence(
                                         new ASN1ObjectIdentifier(
                                              PKCS5AlgorithmIdentifier.
                                                   HMAC_SHA_256.getOID()),
                                         new ASN1OctetString()))),
                          new ASN1Sequence(
                               new ASN1ObjectIdentifier(
                                    PKCS5AlgorithmIdentifier.HMAC_SHA_1.
                                         getOID()),
                               new ASN1OctetString()))),
                new ASN1OctetString("does not matter")).encode(),
           "password".toCharArray());
      fail("Expected an exception when trying to decrypt a key sequence in " +
           "which the cipher transformation OID doesn't reference a cipher " +
           "transformation.");
    }
    catch (final CertException e)
    {
      // This was expected.
    }
  }
}
