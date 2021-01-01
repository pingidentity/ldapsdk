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



import java.security.GeneralSecurityException;
import java.text.ParseException;
import java.util.Random;
import javax.crypto.BadPaddingException;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.StaticUtils;

import static com.unboundid.ldap.sdk.unboundidds.AES256EncodedPassword.*;



/**
 * This class provides test coverage for the LDAP SDK's support for
 * AES256-encoded passwords in the Ping Identity Directory Server.
 */
public final class AES256EncodedPasswordTestCase
       extends LDAPSDKTestCase
{
  // A non-null secret key.
  private AES256EncodedPasswordSecretKey nonNullSecretKey = null;

  // A null secret key.
  private final AES256EncodedPasswordSecretKey nullSecretKey = null;



  /**
   * Generates a secret key to use for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    nonNullSecretKey = AES256EncodedPasswordSecretKey.generate(
         "1234567890abcdef", "encryption-settings-definition-passphrase");
  }



  /**
   * Provides basic coverage to ensure that it is possible to encode, decode,
   * and decrypt AES256 passwords.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncodeDecodeAndDecrypt()
         throws Exception
  {
    final AES256EncodedPassword encodedPassword = AES256EncodedPassword.encode(
         "1234567890abcdef", "encryption-settings-definition-passphrase",
         "clear-text-password");
    assertNotNull(encodedPassword);

    assertEquals(encodedPassword.getEncodingVersion(), 0);

    assertEquals(encodedPassword.getPaddingBytes(), 13);

    assertNotNull(encodedPassword.getKeyFactorySalt());
    assertEquals(encodedPassword.getKeyFactorySalt().length, 16);

    assertNotNull(encodedPassword.getInitializationVector());
    assertEquals(encodedPassword.getInitializationVector().length, 16);

    assertNotNull(encodedPassword.getEncryptionSettingsDefinitionIDBytes());
    assertEquals(encodedPassword.getEncryptionSettingsDefinitionIDBytes(),
         StaticUtils.byteArray(0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef));

    assertNotNull(encodedPassword.getEncryptionSettingsDefinitionIDString());
    assertEquals(encodedPassword.getEncryptionSettingsDefinitionIDString(),
         "1234567890ABCDEF");

    assertNotNull(encodedPassword.getStringRepresentation(true));
    assertFalse(encodedPassword.getStringRepresentation(true).isEmpty());
    assertTrue(encodedPassword.getStringRepresentation(true).startsWith(
         "{AES256}"));

    assertNotNull(encodedPassword.getStringRepresentation(false));
    assertFalse(encodedPassword.getStringRepresentation(false).isEmpty());
    assertFalse(encodedPassword.getStringRepresentation(false).startsWith(
         "{AES256}"));

    assertNotNull(encodedPassword.toString());
    assertFalse(encodedPassword.toString().isEmpty());


    // Verify that we can decode the password from its byte array representation
    // and that we can decrypt it to get the original clear-text password.
    final AES256EncodedPassword decodedFromBytes =
         AES256EncodedPassword.decode(
              encodedPassword.getEncodedRepresentation());
    assertNotNull(decodedFromBytes);

    assertEquals(decodedFromBytes.getEncodingVersion(), 0);

    assertEquals(decodedFromBytes.getPaddingBytes(), 13);

    assertNotNull(decodedFromBytes.getKeyFactorySalt());
    assertEquals(decodedFromBytes.getKeyFactorySalt(),
         encodedPassword.getKeyFactorySalt());

    assertNotNull(decodedFromBytes.getInitializationVector());
    assertEquals(decodedFromBytes.getInitializationVector(),
         encodedPassword.getInitializationVector());

    assertNotNull(decodedFromBytes.getEncryptionSettingsDefinitionIDBytes());
    assertEquals(decodedFromBytes.getEncryptionSettingsDefinitionIDBytes(),
         StaticUtils.byteArray(0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef));

    assertNotNull(decodedFromBytes.getEncryptionSettingsDefinitionIDString());
    assertEquals(decodedFromBytes.getEncryptionSettingsDefinitionIDString(),
         "1234567890ABCDEF");

    assertNotNull(decodedFromBytes.getStringRepresentation(true));
    assertEquals(decodedFromBytes.getStringRepresentation(true),
         encodedPassword.getStringRepresentation(true));

    assertNotNull(decodedFromBytes.getStringRepresentation(false));
    assertEquals(decodedFromBytes.getStringRepresentation(false),
         encodedPassword.getStringRepresentation(false));

    assertNotNull(decodedFromBytes.toString());
    assertEquals(decodedFromBytes.toString(), encodedPassword.toString());

    final byte[] decryptedFromBytes = decodedFromBytes.decrypt(
         "encryption-settings-definition-passphrase");
    assertNotNull(decryptedFromBytes);
    assertEquals(decryptedFromBytes,
         StaticUtils.getBytes("clear-text-password"));


    // Verify that we can decode the password from its string representation
    // (when the scheme is included) and that we can decrypt it to get the
    // original clear-text password.
    final AES256EncodedPassword decodedFromStringWithScheme =
         AES256EncodedPassword.decode(
              encodedPassword.getStringRepresentation(true));
    assertNotNull(decodedFromStringWithScheme);

    assertEquals(decodedFromStringWithScheme.getEncodingVersion(), 0);

    assertEquals(decodedFromStringWithScheme.getPaddingBytes(), 13);

    assertNotNull(decodedFromStringWithScheme.getKeyFactorySalt());
    assertEquals(decodedFromStringWithScheme.getKeyFactorySalt(),
         encodedPassword.getKeyFactorySalt());

    assertNotNull(decodedFromStringWithScheme.getInitializationVector());
    assertEquals(decodedFromStringWithScheme.getInitializationVector(),
         encodedPassword.getInitializationVector());

    assertNotNull(
         decodedFromStringWithScheme.getEncryptionSettingsDefinitionIDBytes());
    assertEquals(
         decodedFromStringWithScheme.getEncryptionSettingsDefinitionIDBytes(),
         StaticUtils.byteArray(0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef));

    assertNotNull(
         decodedFromStringWithScheme.getEncryptionSettingsDefinitionIDString());
    assertEquals(
         decodedFromStringWithScheme.getEncryptionSettingsDefinitionIDString(),
         "1234567890ABCDEF");

    assertNotNull(decodedFromStringWithScheme.getStringRepresentation(true));
    assertEquals(decodedFromStringWithScheme.getStringRepresentation(true),
         encodedPassword.getStringRepresentation(true));

    assertNotNull(decodedFromStringWithScheme.getStringRepresentation(false));
    assertEquals(decodedFromStringWithScheme.getStringRepresentation(false),
         encodedPassword.getStringRepresentation(false));

    assertNotNull(decodedFromStringWithScheme.toString());
    assertEquals(decodedFromStringWithScheme.toString(),
         encodedPassword.toString());

    final byte[] decryptedFromStringWithScheme =
         decodedFromStringWithScheme.decrypt(
              "encryption-settings-definition-passphrase");
    assertNotNull(decryptedFromStringWithScheme);
    assertEquals(decryptedFromStringWithScheme,
         StaticUtils.getBytes("clear-text-password"));


    // Verify that we can decode the password from its string representation
    // (when the scheme is not included) and that we can decrypt it to get the
    // original clear-text password.
    final AES256EncodedPassword decodedFromStringWithoutScheme =
         AES256EncodedPassword.decode(
              encodedPassword.getStringRepresentation(false));
    assertNotNull(decodedFromStringWithoutScheme);

    assertEquals(decodedFromStringWithoutScheme.getEncodingVersion(), 0);

    assertEquals(decodedFromStringWithoutScheme.getPaddingBytes(), 13);

    assertNotNull(decodedFromStringWithoutScheme.getKeyFactorySalt());
    assertEquals(decodedFromStringWithoutScheme.getKeyFactorySalt(),
         encodedPassword.getKeyFactorySalt());

    assertNotNull(decodedFromStringWithoutScheme.getInitializationVector());
    assertEquals(decodedFromStringWithoutScheme.getInitializationVector(),
         encodedPassword.getInitializationVector());

    assertNotNull(decodedFromStringWithoutScheme.
         getEncryptionSettingsDefinitionIDBytes());
    assertEquals(
         decodedFromStringWithoutScheme.
              getEncryptionSettingsDefinitionIDBytes(),
         StaticUtils.byteArray(0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef));

    assertNotNull(decodedFromStringWithoutScheme.
         getEncryptionSettingsDefinitionIDString());
    assertEquals(
         decodedFromStringWithoutScheme.
              getEncryptionSettingsDefinitionIDString(),
         "1234567890ABCDEF");

    assertNotNull(decodedFromStringWithoutScheme.getStringRepresentation(true));
    assertEquals(decodedFromStringWithoutScheme.getStringRepresentation(true),
         encodedPassword.getStringRepresentation(true));

    assertNotNull(
         decodedFromStringWithoutScheme.getStringRepresentation(false));
    assertEquals(decodedFromStringWithoutScheme.getStringRepresentation(false),
         encodedPassword.getStringRepresentation(false));

    assertNotNull(decodedFromStringWithoutScheme.toString());
    assertEquals(decodedFromStringWithoutScheme.toString(),
         encodedPassword.toString());

    final byte[] decryptedFromStringWithoutScheme =
         decodedFromStringWithoutScheme.decrypt(
              "encryption-settings-definition-passphrase");
    assertNotNull(decryptedFromStringWithoutScheme);
    assertEquals(decryptedFromStringWithoutScheme,
         StaticUtils.getBytes("clear-text-password"));
  }



  /**
   * Verifies the ability to encode, decode, and encrypt AES256 passwords with
   * a range of clear-text password sizes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRangeOfPasswordSizes()
         throws Exception
  {
    final Random random = new Random();

    final byte[] initializationVector = new byte[16];
    random.nextBytes(initializationVector);

    for (int i=1; i <= 513; i++)
    {
      final byte[] passwordBytes = new byte[i];
      random.nextBytes(passwordBytes);

      final AES256EncodedPassword encodedPassword =
           AES256EncodedPassword.encode(nonNullSecretKey, initializationVector,
                passwordBytes);
      assertNotNull(encodedPassword);

      assertEquals(encodedPassword.getEncodingVersion(), 0);

      if ((i % 16) == 0)
      {
        assertEquals(encodedPassword.getPaddingBytes(), 0);
      }
      else
      {
        assertEquals(encodedPassword.getPaddingBytes(), 16 - (i % 16));
      }

      assertNotNull(encodedPassword.getKeyFactorySalt());
      assertEquals(encodedPassword.getKeyFactorySalt(),
           nonNullSecretKey.getKeyFactorySalt());

      assertNotNull(encodedPassword.getInitializationVector());
      assertEquals(encodedPassword.getInitializationVector(),
           initializationVector);

      assertNotNull(encodedPassword.getEncryptionSettingsDefinitionIDBytes());
      assertEquals(encodedPassword.getEncryptionSettingsDefinitionIDBytes(),
           StaticUtils.byteArray(0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd,
                0xef));

      assertNotNull(encodedPassword.getEncryptionSettingsDefinitionIDString());
      assertEquals(encodedPassword.getEncryptionSettingsDefinitionIDString(),
           "1234567890ABCDEF");

      assertNotNull(encodedPassword.getStringRepresentation(true));
      assertFalse(encodedPassword.getStringRepresentation(true).isEmpty());
      assertTrue(encodedPassword.getStringRepresentation(true).startsWith(
           "{AES256}"));

      assertNotNull(encodedPassword.getStringRepresentation(false));
      assertFalse(encodedPassword.getStringRepresentation(false).isEmpty());
      assertFalse(encodedPassword.getStringRepresentation(false).startsWith(
           "{AES256}"));

      assertNotNull(encodedPassword.toString());
      assertFalse(encodedPassword.toString().isEmpty());


      final AES256EncodedPassword decodedPassword =
           AES256EncodedPassword.decode(
                encodedPassword.getEncodedRepresentation());
      assertNotNull(decodedPassword);

      final byte[] decryptedPassword =
           decodedPassword.decrypt(nonNullSecretKey);
      assertNotNull(decryptedPassword);
      assertEquals(decryptedPassword, passwordBytes);
    }
  }



  /**
   * Tests the behavior when trying to decrypt a password with the wrong
   * encryption settings definition passphrase.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { GeneralSecurityException.class })
  public void testDecryptWithWrongPassphrase()
         throws Exception
  {
    final AES256EncodedPassword encodedPassword = AES256EncodedPassword.encode(
         nonNullSecretKey, new byte[16],
         StaticUtils.getBytes("clear-text-password"));

    encodedPassword.decrypt("wrong-clear-text-password");
  }



  /**
   * Tests the behavior when trying to encode a password with a {@code null}
   * secret key.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEncodeNullSecretKey()
         throws Exception
  {
    AES256EncodedPassword.encode(nullSecretKey, new byte[16], new byte[1]);
  }



  /**
   * Tests the behavior when trying to encode a password with a {@code null}
   * initialization vector.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEncodeNullInitializationVector()
         throws Exception
  {
    AES256EncodedPassword.encode(nonNullSecretKey, null, new byte[1]);
  }



  /**
   * Tests the behavior when trying to encode a password with an empty
   * initialization vector.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEncodeEmptyInitializationVector()
         throws Exception
  {
    AES256EncodedPassword.encode(nonNullSecretKey, StaticUtils.NO_BYTES,
         new byte[1]);
  }



  /**
   * Tests the behavior when trying to encode a password with a {@code null}
   * clear-text password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEncodeNullClearTextPassword()
         throws Exception
  {
    AES256EncodedPassword.encode(nonNullSecretKey, new byte[16], null);
  }



  /**
   * Tests the behavior when trying to encode a password with an empty
   * clear-text password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEncodeEmptyClearTextPassword()
         throws Exception
  {
    AES256EncodedPassword.encode(nonNullSecretKey, new byte[16],
         StaticUtils.NO_BYTES);
  }



  /**
   * Tests the behavior when trying to decode a password from a string
   * representation that is not base64-encoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testDecodeNonBase64EncodedString()
         throws Exception
  {
    AES256EncodedPassword.decode("this is not a valid base64-encoded string");
  }



  /**
   * Tests the behavior when trying to decode a password from a byte array that
   * is too short for any encoded password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testDecodeByteArrayTooShort()
         throws Exception
  {
    AES256EncodedPassword.decode(StaticUtils.byteArray(0x00, 0x01, 0x02));
  }



  /**
   * Tests the behavior when trying to decode a password from a byte array in
   * which the encoding version is nonzero.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testDecodeNonzeroEncodingVersion()
         throws Exception
  {
    final AES256EncodedPassword encodedPassword = AES256EncodedPassword.encode(
         nonNullSecretKey, new byte[16],
         StaticUtils.getBytes("clear-text-password"));
    assertNotNull(encodedPassword);

    final byte[] encodedPasswordBytes =
         encodedPassword.getEncodedRepresentation();
    encodedPasswordBytes[0] |= 0x10;

    AES256EncodedPassword.decode(encodedPasswordBytes);
  }



  /**
   * Tests the behavior when trying to decode a password from a byte array that
   * is too short based on the encryption settings definition ID length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testDecodeTooShortForEncryptionSettingsDefinitionID()
         throws Exception
  {
    final AES256EncodedPassword encodedPassword = AES256EncodedPassword.encode(
         nonNullSecretKey, new byte[16],
         StaticUtils.getBytes("clear-text-password"));
    assertNotNull(encodedPassword);

    final byte[] encodedPasswordBytes =
         encodedPassword.getEncodedRepresentation();
    final byte[] truncatedEncodedPasswordBytes = new byte[40];
    System.arraycopy(encodedPasswordBytes, 0, truncatedEncodedPasswordBytes, 0,
         40);

    AES256EncodedPassword.decode(truncatedEncodedPasswordBytes);
  }



  /**
   * Tests the behavior when trying to decrypt a password when an expected
   * padding byte is nonzero.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { BadPaddingException.class })
  public void testDecryptPaddingByteNonZero()
         throws Exception
  {
    final AES256EncodedPassword encodedPassword = AES256EncodedPassword.encode(
         nonNullSecretKey, new byte[16],
         StaticUtils.getBytes("clear-text-password"));
    assertNotNull(encodedPassword);

    assertFalse(encodedPassword.getPaddingBytes() == 15);

    final byte[] encodedPasswordBytes =
         encodedPassword.getEncodedRepresentation();
    final byte[] encodedPasswordBytesWithBadPadding =
         new byte[encodedPasswordBytes.length];
    System.arraycopy(encodedPasswordBytes, 0,
         encodedPasswordBytesWithBadPadding, 0, encodedPasswordBytes.length);
    encodedPasswordBytesWithBadPadding[0] = 0x0F;

    final AES256EncodedPassword decodedPassword =
         AES256EncodedPassword.decode(encodedPasswordBytesWithBadPadding);
    decodedPassword.decrypt(nonNullSecretKey);
  }
}
