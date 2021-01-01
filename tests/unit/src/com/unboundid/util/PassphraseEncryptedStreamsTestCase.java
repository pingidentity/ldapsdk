/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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
package com.unboundid.util;



import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test cases for the
 * {@link PassphraseEncryptedOutputStream},
 * {@link PassphraseEncryptedInputStream}, and
 * {@link PassphraseEncryptedStreamHeader} classes.
 */
public final class PassphraseEncryptedStreamsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when writing an encrypted stream that has the header
   * written to the beginning of it.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithHeaderWrittenToStream()
         throws Exception
  {
    // Define the data to be encrypted.
    final List<String> linesToEncrypt = Arrays.asList(
         "This is some data that will be encrypted.",
         "So is this.",
         "And this.");


    // Get the path to a file to which encrypted data will be written.
    final File encryptedFile = createTempFile();
    assertTrue(encryptedFile.delete());


    // Write the data to an encrypted file.
    try (FileOutputStream fileOutputStream =
              new FileOutputStream(encryptedFile);
         PassphraseEncryptedOutputStream passphraseEncryptedOutputStream =
              new PassphraseEncryptedOutputStream("passphrase",
                   fileOutputStream);
         PrintStream printStream =
              new PrintStream(passphraseEncryptedOutputStream))
    {
      assertNotNull(passphraseEncryptedOutputStream.getEncryptionHeader());

      for (final String line : linesToEncrypt)
      {
        printStream.println(line);
      }
    }


    // Read the data back from the encrypted file.
    final ArrayList<String> decryptedLines = new ArrayList<>(10);
    try (FileInputStream fileInputStream =
              new FileInputStream(encryptedFile);
         PassphraseEncryptedInputStream passphraseEncryptedInputStream =
              new PassphraseEncryptedInputStream("passphrase",
                   fileInputStream);
         InputStreamReader inputStreamReader =
              new InputStreamReader(passphraseEncryptedInputStream);
         BufferedReader bufferedReader = new BufferedReader(inputStreamReader))
    {
      assertNotNull(passphraseEncryptedInputStream.getEncryptionHeader());

      while (true)
      {
        final String line = bufferedReader.readLine();
        if (line == null)
        {
          break;
        }

        decryptedLines.add(line);
      }
    }


    // Make sure that the decrypted data matches the data we originally wrote.
    assertEquals(decryptedLines, linesToEncrypt);
  }



  /**
   * Tests the behavior when writing an encrypted stream that does not have the
   * header written to the beginning of it.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithHeaderNotWrittenToStream()
         throws Exception
  {
    // Define the data to be encrypted.
    final List<String> linesToEncrypt = Arrays.asList(
         "This is some data that will be encrypted.",
         "So is this.",
         "And this.");


    // Get the path to a file to which encrypted data will be written.
    final File encryptedFile = createTempFile();
    assertTrue(encryptedFile.delete());


    // Write the data to an encrypted file, and make sure to capture the header.
    final PassphraseEncryptedStreamHeader encryptionHeader;
    try (FileOutputStream fileOutputStream =
              new FileOutputStream(encryptedFile);
         PassphraseEncryptedOutputStream passphraseEncryptedOutputStream =
              new PassphraseEncryptedOutputStream("passphrase",
                   fileOutputStream, "key-identifier", false, false);
         PrintStream printStream =
              new PrintStream(passphraseEncryptedOutputStream))
    {
      encryptionHeader = passphraseEncryptedOutputStream.getEncryptionHeader();
      assertNotNull(encryptionHeader);

      for (final String line : linesToEncrypt)
      {
        printStream.println(line);
      }
    }


    // Read the data back from the encrypted file.
    final ArrayList<String> decryptedLines = new ArrayList<>(10);
    try (FileInputStream fileInputStream =
              new FileInputStream(encryptedFile);
         PassphraseEncryptedInputStream passphraseEncryptedInputStream =
              new PassphraseEncryptedInputStream(fileInputStream,
                   encryptionHeader);
         InputStreamReader inputStreamReader =
              new InputStreamReader(passphraseEncryptedInputStream);
         BufferedReader bufferedReader = new BufferedReader(inputStreamReader))
    {
      assertNotNull(passphraseEncryptedInputStream.getEncryptionHeader());

      while (true)
      {
        final String line = bufferedReader.readLine();
        if (line == null)
        {
          break;
        }

        decryptedLines.add(line);
      }
    }


    // Make sure that the decrypted data matches the data we originally wrote.
    assertEquals(decryptedLines, linesToEncrypt);
  }



  /**
   * Tests the behavior when trying to use strong encryption.  This method
   * should succeed even if strong encryption is not available; it will merely
   * revert to the baseline encryption strength.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithAttemptedStrongEncryption()
         throws Exception
  {
    // Define the data to be encrypted.
    final List<String> linesToEncrypt = Arrays.asList(
         "This is some data that will be encrypted.",
         "So is this.",
         "And this.");


    // Get the path to a file to which encrypted data will be written.
    final File encryptedFile = createTempFile();
    assertTrue(encryptedFile.delete());


    // Write the data to an encrypted file, and make sure to capture the header.
    // If this is the first attempt to use strong encryption, then it will make
    // the determination and cache the result.  If there has been more than one
    // attempt, then it should use the cached value.
    try (FileOutputStream fileOutputStream =
              new FileOutputStream(encryptedFile);
         PassphraseEncryptedOutputStream passphraseEncryptedOutputStream =
              new PassphraseEncryptedOutputStream("passphrase",
                   fileOutputStream, "key-identifier", true, 4_096, true);
         PrintStream printStream =
              new PrintStream(passphraseEncryptedOutputStream))
    {
      assertNotNull(passphraseEncryptedOutputStream.getEncryptionHeader());
      assertEquals(
           passphraseEncryptedOutputStream.getEncryptionHeader().
                getKeyFactoryIterationCount(),
           4_096);

      for (final String line : linesToEncrypt)
      {
        printStream.println(line);
      }
    }


    // Try to use strong encryption again.  This should always use the cached
    // result.
    try (FileOutputStream fileOutputStream =
              new FileOutputStream(encryptedFile);
         PassphraseEncryptedOutputStream passphraseEncryptedOutputStream =
              new PassphraseEncryptedOutputStream("passphrase",
                   fileOutputStream, "key-identifier", true, 4_096, true);
         PrintStream printStream =
              new PrintStream(passphraseEncryptedOutputStream))
    {
      assertNotNull(passphraseEncryptedOutputStream.getEncryptionHeader());
      assertEquals(
           passphraseEncryptedOutputStream.getEncryptionHeader().
                getKeyFactoryIterationCount(),
           4_096);

      for (final String line : linesToEncrypt)
      {
        printStream.println(line);
      }
    }


    // Read the data back from the encrypted file.
    final ArrayList<String> decryptedLines = new ArrayList<>(10);
    try (FileInputStream fileInputStream =
              new FileInputStream(encryptedFile);
         PassphraseEncryptedInputStream passphraseEncryptedInputStream =
              new PassphraseEncryptedInputStream("passphrase", fileInputStream);
         InputStreamReader inputStreamReader =
              new InputStreamReader(passphraseEncryptedInputStream);
         BufferedReader bufferedReader = new BufferedReader(inputStreamReader))
    {
      assertNotNull(passphraseEncryptedInputStream.getEncryptionHeader());

      while (true)
      {
        final String line = bufferedReader.readLine();
        if (line == null)
        {
          break;
        }

        decryptedLines.add(line);
      }
    }


    // Make sure that the decrypted data matches the data we originally wrote.
    assertEquals(decryptedLines, linesToEncrypt);
  }



  /**
   * Tests the behavior when writing trying to decode a passphrase-encrypted
   * stream header when no passphrase was provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeWithoutPassphrase()
         throws Exception
  {
    // Define the data to be encrypted.
    final List<String> linesToEncrypt = Arrays.asList(
         "This is some data that will be encrypted.",
         "So is this.",
         "And this.");


    // Get the path to a file to which encrypted data will be written.
    final File encryptedFile = createTempFile();
    assertTrue(encryptedFile.delete());


    // Write the data to an encrypted file.
    try (FileOutputStream fileOutputStream =
              new FileOutputStream(encryptedFile);
         PassphraseEncryptedOutputStream passphraseEncryptedOutputStream =
              new PassphraseEncryptedOutputStream("passphrase",
                   fileOutputStream);
         PrintStream printStream =
              new PrintStream(passphraseEncryptedOutputStream))
    {
      assertNotNull(passphraseEncryptedOutputStream.getEncryptionHeader());

      for (final String line : linesToEncrypt)
      {
        printStream.println(line);
      }
    }


    // Try to read back the encrypted data, but don't provide a passphrase.
    PassphraseEncryptedStreamHeader encryptionHeader;
    try (FileInputStream fileInputStream =
              new FileInputStream(encryptedFile))
    {
      encryptionHeader =
           PassphraseEncryptedStreamHeader.readFrom(fileInputStream, null);
      assertNotNull(encryptionHeader);
      assertFalse(encryptionHeader.isSecretKeyAvailable());
      assertNotNull(encryptionHeader.toString());

      // This should fail because the header was created without a passphrase.
      try
      {
        encryptionHeader.createCipher(Cipher.ENCRYPT_MODE);
      }
      catch (final InvalidKeyException e)
      {
        // This was expected.
      }
    }


    // Make sure that we can decode the header with the correct passphrase and
    // that it now works properly.
    encryptionHeader = PassphraseEncryptedStreamHeader.decode(
         encryptionHeader.getEncodedHeader(), "passphrase".toCharArray());
    assertNotNull(encryptionHeader);
    assertTrue(encryptionHeader.isSecretKeyAvailable());
    assertNotNull(encryptionHeader.toString());

    encryptionHeader.createCipher(Cipher.ENCRYPT_MODE);
  }



  /**
   * Tests the behavior when writing an encrypted stream using one passphrase,
   * and then using a different passphrase when trying to decrypt the stream.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { InvalidKeyException.class })
  public void testWithDifferentPassphrases()
         throws Exception
  {
    // Define the data to be encrypted.
    final List<String> linesToEncrypt = Arrays.asList(
         "This is some data that will be encrypted.",
         "So is this.",
         "And this.");


    // Get the path to a file to which encrypted data will be written.
    final File encryptedFile = createTempFile();
    assertTrue(encryptedFile.delete());


    // Write the data to an encrypted file.
    try (FileOutputStream fileOutputStream =
              new FileOutputStream(encryptedFile);
         PassphraseEncryptedOutputStream passphraseEncryptedOutputStream =
              new PassphraseEncryptedOutputStream("passphrase",
                   fileOutputStream);
         PrintStream printStream =
              new PrintStream(passphraseEncryptedOutputStream))
    {
      assertNotNull(passphraseEncryptedOutputStream.getEncryptionHeader());

      for (final String line : linesToEncrypt)
      {
        printStream.println(line);
      }
    }


    // Try to read back the encrypted data, but provide the wrong passphrase.
    try (FileInputStream fileInputStream =
              new FileInputStream(encryptedFile);
         PassphraseEncryptedInputStream passphraseEncryptedInputStream =
              new PassphraseEncryptedInputStream("wrong-passphrase",
                   fileInputStream))
    {
      passphraseEncryptedInputStream.getEncryptionHeader();
      fail("Expected an exception when providing the wrong passphrase when " +
           "creating a PassphraseEncryptedInputStream");
    }
  }



  /**
   * Tests the behavior when using all of the methods that can be used to write
   * and read data with the passphrase-encrypted streams.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMoreOutputStreamAndInputStreamMethods()
         throws Exception
  {
    // Create a buffer that will hold the clear-text data that will be
    // encrypted.
    final ByteStringBuffer dataToEncrypt = new ByteStringBuffer();


    // Get the path to a file to which encrypted data will be written.
    final File encryptedFile = createTempFile();
    assertTrue(encryptedFile.delete());


    // Create an output stream and write data to it.
    try (FileOutputStream fileOutputStream =
              new FileOutputStream(encryptedFile);
         PassphraseEncryptedOutputStream passphraseEncryptedOutputStream =
              new PassphraseEncryptedOutputStream("passphrase",
                   fileOutputStream))
    {
      final byte singleByte = 0x00;
      passphraseEncryptedOutputStream.write(singleByte);
      dataToEncrypt.append(singleByte);

      final byte[] completeByteArray =
           { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };
      passphraseEncryptedOutputStream.write(completeByteArray);
      dataToEncrypt.append(completeByteArray);

      final byte[] partialByteArray =
           { 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };
      passphraseEncryptedOutputStream.write(partialByteArray, 3, 4);
      dataToEncrypt.append(partialByteArray, 3, 4);

      passphraseEncryptedOutputStream.flush();
    }


    // Read the data back into a new buffer.
    final ByteStringBuffer decryptedData = new ByteStringBuffer();
    try (FileInputStream fileInputStream =
              new FileInputStream(encryptedFile);
         BufferedInputStream bufferedInputStream =
              new BufferedInputStream(fileInputStream);
         PassphraseEncryptedInputStream passphraseEncryptedInputStream =
              new PassphraseEncryptedInputStream("passphrase",
              bufferedInputStream))
    {
      // Just get coverage for some input stream methods.
      assertTrue(passphraseEncryptedInputStream.available() >= 0);
      passphraseEncryptedInputStream.skip(0L);
      passphraseEncryptedInputStream.markSupported();
      passphraseEncryptedInputStream.mark(1);

      try
      {
        passphraseEncryptedInputStream.reset();
      }
      catch (final Exception e)
      {
        // Ignore it, since we don't really care about whether we can do this
        // or not.
      }

      // Read a single byte.
      final int singleByte = passphraseEncryptedInputStream.read();
      assertEquals(singleByte, 0x00);
      decryptedData.append((byte) singleByte);

      // Read into a complete array.
      final byte[] buffer = new byte[4];
      int bytesRead = passphraseEncryptedInputStream.read(buffer);
      assertTrue(bytesRead > 0);
      decryptedData.append(buffer, 0, bytesRead);

      // Repeatedly read into a portion of the array until the rest of the data
      // is consumed.
      while (true)
      {
        bytesRead = passphraseEncryptedInputStream.read(buffer, 1, 2);
        if (bytesRead < 0)
        {
          break;
        }

        decryptedData.append(buffer, 1, bytesRead);
      }
    }


    // Make sure that the decrypted data we read back is the same as the
    // clear-text data we originally wrote.
    assertEquals(decryptedData.toByteArray(), dataToEncrypt.toByteArray());
  }



  /**
   * Tests the behavior of a number of methods in the
   * {@link PassphraseEncryptedStreamHeader} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStreamHeader()
         throws Exception
  {
    try (ByteArrayOutputStream byteArrayOutputStream =
              new ByteArrayOutputStream();
         PassphraseEncryptedOutputStream passphraseEncryptedOutputStream =
              new PassphraseEncryptedOutputStream("passphrase",
                   byteArrayOutputStream, "the-key-identifier", false, false))
    {
      PassphraseEncryptedStreamHeader header =
           passphraseEncryptedOutputStream.getEncryptionHeader();
      assertNotNull(header);

      final byte[] encodedHeader = header.getEncodedHeader();
      assertNotNull(encodedHeader);

      header = PassphraseEncryptedStreamHeader.decode(encodedHeader,
           "passphrase".toCharArray());
      assertNotNull(header);

      assertNotNull(header.getKeyFactoryAlgorithm());
      assertEquals(header.getKeyFactoryAlgorithm(), "PBKDF2WithHmacSHA1");

      assertEquals(header.getKeyFactoryIterationCount(), 16_384);

      assertNotNull(header.getKeyFactorySalt());
      assertEquals(header.getKeyFactorySalt().length, 16);

      assertEquals(header.getKeyFactoryKeyLengthBits(), 128);

      assertNotNull(header.getCipherTransformation());
      assertEquals(header.getCipherTransformation(), "AES/CBC/PKCS5Padding");

      assertNotNull(header.getCipherInitializationVector());
      assertEquals(header.getCipherInitializationVector().length, 16);

      assertNotNull(header.getKeyIdentifier());
      assertEquals(header.getKeyIdentifier(), "the-key-identifier");

      assertNotNull(header.getMACAlgorithm());
      assertEquals(header.getMACAlgorithm(), "HmacSHA256");

      assertNotNull(header.getEncodedHeader());
      assertEquals(header.getEncodedHeader(), encodedHeader);

      assertTrue(header.isSecretKeyAvailable());

      assertNotNull(header.toString());
    }
  }



  /**
   * Tests the behavior when trying to read a header from an empty stream.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { LDAPException.class })
  public void testReadHeaderFromEmptyStream()
         throws Exception
  {
    PassphraseEncryptedStreamHeader.readFrom(
         new ByteArrayInputStream(StaticUtils.NO_BYTES),
         "passphrase".toCharArray());
  }



  /**
   * Tests the behavior when trying to read a header with a bad magic.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { LDAPException.class })
  public void testReadHeaderWithBadMagic()
         throws Exception
  {
    final ByteArrayInputStream byteArrayInputStream =
         new ByteArrayInputStream("BadMagic".getBytes("UTF-8"));
    PassphraseEncryptedStreamHeader.readFrom(byteArrayInputStream,
         "passphrase".toCharArray());
  }



  /**
   * Tests the behavior when trying to read a header with no data after the
   * magic.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { LDAPException.class })
  public void testReadNoDataAfterMagic()
         throws Exception
  {
    final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(
         PassphraseEncryptedStreamHeader.MAGIC_BYTES);
    PassphraseEncryptedStreamHeader.readFrom(byteArrayInputStream,
         "passphrase".toCharArray());
  }



  /**
   * Tests the behavior when trying to read a header with bad data after the
   * magic.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { LDAPException.class })
  public void testReadBadDataAfterMagic()
         throws Exception
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append(PassphraseEncryptedStreamHeader.MAGIC_BYTES);
    buffer.append("bad");

    final ByteArrayInputStream byteArrayInputStream =
         new ByteArrayInputStream(buffer.toByteArray());
    PassphraseEncryptedStreamHeader.readFrom(byteArrayInputStream,
         "passphrase".toCharArray());
  }



  /**
   * Tests the behavior when trying to read a header with an invalid encoding
   * version.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { LDAPException.class })
  public void testReadBadEncodingVersion()
         throws Exception
  {
    final ASN1Sequence headerSequence = new ASN1Sequence(
         new ASN1Integer(PassphraseEncryptedStreamHeader.TYPE_ENCODING_VERSION,
              PassphraseEncryptedStreamHeader.ENCODING_VERSION_1 + 1),
         new ASN1OctetString(
              PassphraseEncryptedStreamHeader.TYPE_KEY_FACTORY_ALGORITHM,
              "PBKDF2WithHmacSHA1"),
         new ASN1Integer(
              PassphraseEncryptedStreamHeader.TYPE_KEY_FACTORY_ITERATION_COUNT,
              16_384),
         new ASN1OctetString(
              PassphraseEncryptedStreamHeader.TYPE_KEY_FACTORY_SALT,
              new byte[16]),
         new ASN1Integer(
              PassphraseEncryptedStreamHeader.TYPE_KEY_FACTORY_KEY_LENGTH_BITS,
              128),
         new ASN1OctetString(
              PassphraseEncryptedStreamHeader.TYPE_CIPHER_TRANSFORMATION,
              "AES/CBC/PKCS5Padding"),
         new ASN1OctetString(
              PassphraseEncryptedStreamHeader.TYPE_CIPHER_INITIALIZATION_VECTOR,
              new byte[16]),
         new ASN1OctetString(
              PassphraseEncryptedStreamHeader.TYPE_KEY_IDENTIFIER,
              "key-identifier"),
         new ASN1OctetString(
              PassphraseEncryptedStreamHeader.TYPE_MAC_ALGORITHM,
              "HmacSHA256"),
         new ASN1OctetString(
              PassphraseEncryptedStreamHeader.TYPE_MAC_ALGORITHM,
              StaticUtils.getBytes("bad-mac")));

    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append(PassphraseEncryptedStreamHeader.MAGIC_BYTES);
    buffer.append(headerSequence.encode());

    final ByteArrayInputStream byteArrayInputStream =
         new ByteArrayInputStream(buffer.toByteArray());
    PassphraseEncryptedStreamHeader.readFrom(byteArrayInputStream,
         "passphrase".toCharArray());
  }



  /**
   * Tests the behavior when trying to read a header with an element with an
   * unexpected BER type at the end of the sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { LDAPException.class })
  public void testReadBadBERTypeInHeaderSequence()
         throws Exception
  {
    final ASN1Sequence headerSequence = new ASN1Sequence(
         new ASN1Integer(PassphraseEncryptedStreamHeader.TYPE_ENCODING_VERSION,
              PassphraseEncryptedStreamHeader.ENCODING_VERSION_1),
         new ASN1OctetString(
              PassphraseEncryptedStreamHeader.TYPE_KEY_FACTORY_ALGORITHM,
              "PBKDF2WithHmacSHA1"),
         new ASN1Integer(
              PassphraseEncryptedStreamHeader.TYPE_KEY_FACTORY_ITERATION_COUNT,
              16_384),
         new ASN1OctetString(
              PassphraseEncryptedStreamHeader.TYPE_KEY_FACTORY_SALT,
              new byte[16]),
         new ASN1Integer(
              PassphraseEncryptedStreamHeader.TYPE_KEY_FACTORY_KEY_LENGTH_BITS,
              128),
         new ASN1OctetString(
              PassphraseEncryptedStreamHeader.TYPE_CIPHER_TRANSFORMATION,
              "AES/CBC/PKCS5Padding"),
         new ASN1OctetString(
              PassphraseEncryptedStreamHeader.TYPE_CIPHER_INITIALIZATION_VECTOR,
              new byte[16]),
         new ASN1OctetString((byte) 0x00,
              "unrecognized-element-type"));

    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append(PassphraseEncryptedStreamHeader.MAGIC_BYTES);
    buffer.append(headerSequence.encode());

    final ByteArrayInputStream byteArrayInputStream =
         new ByteArrayInputStream(buffer.toByteArray());
    PassphraseEncryptedStreamHeader.readFrom(byteArrayInputStream,
         "passphrase".toCharArray());
  }



  /**
   * Tests the behavior when trying to read a header with too few elements in
   * the header sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { LDAPException.class })
  public void testReadHeaderSequenceTooShort()
         throws Exception
  {
    final ASN1Sequence headerSequence = new ASN1Sequence(
         new ASN1Integer(PassphraseEncryptedStreamHeader.TYPE_ENCODING_VERSION,
              PassphraseEncryptedStreamHeader.ENCODING_VERSION_1),
         new ASN1OctetString(
              PassphraseEncryptedStreamHeader.TYPE_KEY_FACTORY_ALGORITHM,
              "PBKDF2WithHmacSHA1"));

    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append(PassphraseEncryptedStreamHeader.MAGIC_BYTES);
    buffer.append(headerSequence.encode());

    final ByteArrayInputStream byteArrayInputStream =
         new ByteArrayInputStream(buffer.toByteArray());
    PassphraseEncryptedStreamHeader.readFrom(byteArrayInputStream,
         "passphrase".toCharArray());
  }



  /**
   * Tests the behavior when trying to decode a header from a byte array that is
   * too short to be a valid header.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { LDAPException.class })
  public void testDecodeArrayTooShort()
         throws Exception
  {
    PassphraseEncryptedStreamHeader.decode(StaticUtils.NO_BYTES,
         "passphrase".toCharArray());
  }



  /**
   * Tests the behavior when trying to decode a header from a byte array with a
   * bad magic.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { LDAPException.class })
  public void testDecodeArrayWithBadMagic()
         throws Exception
  {
    PassphraseEncryptedStreamHeader.decode(new byte[50],
         "passphrase".toCharArray());
  }



  /**
   * Tests the behavior when trying to decode a header from a byte array with
   * bad data after the magic.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { LDAPException.class })
  public void testDecodeArrayWithBadDataAfterMagic()
         throws Exception
  {
    final byte[] headerBytes = new byte[50];
    System.arraycopy(PassphraseEncryptedStreamHeader.MAGIC_BYTES, 0,
         headerBytes, 0, PassphraseEncryptedStreamHeader.MAGIC_BYTES.length);
    PassphraseEncryptedStreamHeader.decode(headerBytes,
         "passphrase".toCharArray());
  }



  /**
   * Tests the behavior when explicitly using 128-bit AES encryption.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplicit128BitAES()
         throws Exception
  {
    // Define the data to be encrypted.
    final List<String> linesToEncrypt = Arrays.asList(
         "This is some data that will be encrypted.",
         "So is this.",
         "And this.");


    // Get the path to a file to which encrypted data will be written.
    final File encryptedFile = createTempFile();
    assertTrue(encryptedFile.delete());


    // Create the properties that will be used for the encryption.
    final PassphraseEncryptedOutputStreamProperties properties =
         new PassphraseEncryptedOutputStreamProperties(
              PassphraseEncryptionCipherType.AES_128);
    properties.setKeyIdentifier("key-id");


    // Write the data to an encrypted file.
    try (FileOutputStream fileOutputStream =
              new FileOutputStream(encryptedFile);
         PassphraseEncryptedOutputStream passphraseEncryptedOutputStream =
              new PassphraseEncryptedOutputStream("passphrase",
                   fileOutputStream, properties);
         PrintStream printStream =
              new PrintStream(passphraseEncryptedOutputStream))
    {
      assertNotNull(passphraseEncryptedOutputStream.getEncryptionHeader());

      for (final String line : linesToEncrypt)
      {
        printStream.println(line);
      }
    }


    // Read the data back from the encrypted file.
    final ArrayList<String> decryptedLines = new ArrayList<>(10);
    try (FileInputStream fileInputStream =
              new FileInputStream(encryptedFile);
         PassphraseEncryptedInputStream passphraseEncryptedInputStream =
              new PassphraseEncryptedInputStream("passphrase",
                   fileInputStream);
         InputStreamReader inputStreamReader =
              new InputStreamReader(passphraseEncryptedInputStream);
         BufferedReader bufferedReader = new BufferedReader(inputStreamReader))
    {
      assertNotNull(passphraseEncryptedInputStream.getEncryptionHeader());

      while (true)
      {
        final String line = bufferedReader.readLine();
        if (line == null)
        {
          break;
        }

        decryptedLines.add(line);
      }
    }


    // Make sure that the decrypted data matches the data we originally wrote.
    assertEquals(decryptedLines, linesToEncrypt);


    // Read the encryption header to ensure that it's using all of the expected
    // properties.
    final PassphraseEncryptedStreamHeader header;
    try (FileInputStream inputStream = new FileInputStream(encryptedFile))
    {
      header = PassphraseEncryptedStreamHeader.readFrom(inputStream, null);
    }

    assertNotNull(header);

    assertNotNull(header.getKeyFactoryAlgorithm());
    assertEquals(header.getKeyFactoryAlgorithm(),
         PassphraseEncryptionCipherType.AES_128.getKeyFactoryAlgorithm());

    assertNotNull(header.getKeyFactoryIterationCount());
    assertEquals(header.getKeyFactoryIterationCount(),
         PassphraseEncryptionCipherType.AES_128.getKeyFactoryIterationCount());

    assertNotNull(header.getKeyFactorySalt());
    assertEquals(header.getKeyFactorySalt().length,
         PassphraseEncryptionCipherType.AES_128.getKeyFactorySaltLengthBytes());

    assertNotNull(header.getKeyFactoryKeyLengthBits());
    assertEquals(header.getKeyFactoryKeyLengthBits(),
         PassphraseEncryptionCipherType.AES_128.getKeyLengthBits());

    assertNotNull(header.getCipherTransformation());
    assertEquals(header.getCipherTransformation(),
         PassphraseEncryptionCipherType.AES_128.getCipherTransformation());

    assertNotNull(header.getCipherInitializationVector());
    assertEquals(header.getCipherInitializationVector().length,
         PassphraseEncryptionCipherType.AES_128.
              getInitializationVectorLengthBytes());

    assertNotNull(header.getKeyIdentifier());
    assertEquals(header.getKeyIdentifier(), "key-id");
  }



  /**
   * Tests the behavior when explicitly using 256-bit AES encryption.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplicit256BitAES()
         throws Exception
  {
    // Define the data to be encrypted.
    final List<String> linesToEncrypt = Arrays.asList(
         "This is some data that will be encrypted.",
         "So is this.",
         "And this.");


    // Get the path to a file to which encrypted data will be written.
    final File encryptedFile = createTempFile();
    assertTrue(encryptedFile.delete());


    // Create the properties that will be used for the encryption.
    final PassphraseEncryptedOutputStreamProperties properties =
         new PassphraseEncryptedOutputStreamProperties(
              PassphraseEncryptionCipherType.AES_256);
    properties.setKeyIdentifier("different-key-id");


    // Figure out whether the JVM supports 256-bit AES.  If not, then expect
    // the encryption attempt to fail.
    final PassphraseEncryptionCipherType strongCipherType =
         PassphraseEncryptionCipherType.getStrongestAvailableCipherType();


    // Try to write the data to an encrypted file.  This should fail if the JVM
    // doesn't support 256-bit AES.  It should not fail if the JVM does support
    // 256-bit AES.
    try (FileOutputStream fileOutputStream =
              new FileOutputStream(encryptedFile);
         PassphraseEncryptedOutputStream passphraseEncryptedOutputStream =
              new PassphraseEncryptedOutputStream("passphrase",
                   fileOutputStream, properties);
         PrintStream printStream =
              new PrintStream(passphraseEncryptedOutputStream))
    {
      assertNotNull(passphraseEncryptedOutputStream.getEncryptionHeader());

      for (final String line : linesToEncrypt)
      {
        printStream.println(line);
      }

      assertEquals(strongCipherType, PassphraseEncryptionCipherType.AES_256);
    }
    catch (final Exception e)
    {
      // Make sure that we expected this.  If so, then there's no need to test
      // any more.
      assertEquals(strongCipherType, PassphraseEncryptionCipherType.AES_128);
      return;
    }


    // Read the data back from the encrypted file.
    final ArrayList<String> decryptedLines = new ArrayList<>(10);
    try (FileInputStream fileInputStream =
              new FileInputStream(encryptedFile);
         PassphraseEncryptedInputStream passphraseEncryptedInputStream =
              new PassphraseEncryptedInputStream("passphrase",
                   fileInputStream);
         InputStreamReader inputStreamReader =
              new InputStreamReader(passphraseEncryptedInputStream);
         BufferedReader bufferedReader = new BufferedReader(inputStreamReader))
    {
      assertNotNull(passphraseEncryptedInputStream.getEncryptionHeader());

      while (true)
      {
        final String line = bufferedReader.readLine();
        if (line == null)
        {
          break;
        }

        decryptedLines.add(line);
      }
    }


    // Make sure that the decrypted data matches the data we originally wrote.
    assertEquals(decryptedLines, linesToEncrypt);


    // Read the encryption header to ensure that it's using all of the expected
    // properties.
    final PassphraseEncryptedStreamHeader header;
    try (FileInputStream inputStream = new FileInputStream(encryptedFile))
    {
      header = PassphraseEncryptedStreamHeader.readFrom(inputStream, null);
    }

    assertNotNull(header);

    assertNotNull(header.getKeyFactoryAlgorithm());
    assertEquals(header.getKeyFactoryAlgorithm(),
         PassphraseEncryptionCipherType.AES_256.getKeyFactoryAlgorithm());

    assertNotNull(header.getKeyFactoryIterationCount());
    assertEquals(header.getKeyFactoryIterationCount(),
         PassphraseEncryptionCipherType.AES_256.getKeyFactoryIterationCount());

    assertNotNull(header.getKeyFactorySalt());
    assertEquals(header.getKeyFactorySalt().length,
         PassphraseEncryptionCipherType.AES_256.getKeyFactorySaltLengthBytes());

    assertNotNull(header.getKeyFactoryKeyLengthBits());
    assertEquals(header.getKeyFactoryKeyLengthBits(),
         PassphraseEncryptionCipherType.AES_256.getKeyLengthBits());

    assertNotNull(header.getCipherTransformation());
    assertEquals(header.getCipherTransformation(),
         PassphraseEncryptionCipherType.AES_256.getCipherTransformation());

    assertNotNull(header.getCipherInitializationVector());
    assertEquals(header.getCipherInitializationVector().length,
         PassphraseEncryptionCipherType.AES_256.
              getInitializationVectorLengthBytes());

    assertNotNull(header.getKeyIdentifier());
    assertEquals(header.getKeyIdentifier(), "different-key-id");
  }
}
