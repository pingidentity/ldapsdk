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



import java.util.Random;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.Base64;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.StaticUtils;



/**
 * This class provides test coverage for the LDAP SDK's support for generating
 * secret keys for use with AES256-encoded passwords in the Ping Identity
 * Directory Server.
 */
public final class AES256EncodedPasswordSecretKeyTestCase
       extends LDAPSDKTestCase
{
  /**
   * Verify that it is possible to generate a secret key from string
   * representations of the encryption settings definition ID and passphrase.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateFromStrings()
         throws Exception
  {
    final AES256EncodedPasswordSecretKey secretKey =
         AES256EncodedPasswordSecretKey.generate(
              "1234567890abcdef", "esd-passphrase");
    assertNotNull(secretKey);

    assertNotNull(secretKey.getEncryptionSettingsDefinitionID());
    assertEquals(secretKey.getEncryptionSettingsDefinitionID(),
         StaticUtils.byteArray(0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef));

    assertNotNull(secretKey.getKeyFactorySalt());
    assertEquals(secretKey.getKeyFactorySalt().length, 16);

    assertNotNull(secretKey.getSecretKey());

    assertNotNull(secretKey.toString());

    secretKey.destroy();
  }



  /**
   * Verifies that it is possible to generate a secret key from a byte array
   * representation of the encryption settings definition ID, a character array
   * representation of the encryption settings definition passphrase, and a
   * provided salt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateWithSalt()
         throws Exception
  {
    final Random random = new Random();

    final byte[] salt = new byte[16];
    random.nextBytes(salt);

    final byte[] encryptionSettingsDefinitionID = new byte[32];
    random.nextBytes(encryptionSettingsDefinitionID);

    final byte[] encryptionSettingsPassphraseData = new byte[20];
    random.nextBytes(encryptionSettingsPassphraseData);
    final char[] encryptionSettingsDefinitionPassphrase =
         Base64.encode(encryptionSettingsPassphraseData).toCharArray();

    final AES256EncodedPasswordSecretKey secretKey =
         AES256EncodedPasswordSecretKey.generate(encryptionSettingsDefinitionID,
              encryptionSettingsDefinitionPassphrase, salt);
    assertNotNull(secretKey);

    assertNotNull(secretKey.getEncryptionSettingsDefinitionID());
    assertEquals(secretKey.getEncryptionSettingsDefinitionID(),
         encryptionSettingsDefinitionID);

    assertNotNull(secretKey.getKeyFactorySalt());
    assertEquals(secretKey.getKeyFactorySalt(), salt);

    assertNotNull(secretKey.getSecretKey());

    assertNotNull(secretKey.toString());

    secretKey.destroy();
  }



  /**
   * Tests the behavior when trying to generate a secret key with a {@code null}
   * encryption settings definition ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNullEncryptionSettingsDefinitionID()
         throws Exception
  {
    final Random random = new Random();

    final byte[] salt = new byte[16];
    random.nextBytes(salt);

    final byte[] encryptionSettingsPassphraseData = new byte[20];
    random.nextBytes(encryptionSettingsPassphraseData);
    final char[] encryptionSettingsDefinitionPassphrase =
         Base64.encode(encryptionSettingsPassphraseData).toCharArray();

    AES256EncodedPasswordSecretKey.generate(null,
         encryptionSettingsDefinitionPassphrase, salt);
  }



  /**
   * Tests the behavior when trying to generate a secret key with an empty
   * encryption settings definition ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEmptyEncryptionSettingsDefinitionID()
         throws Exception
  {
    final Random random = new Random();

    final byte[] salt = new byte[16];
    random.nextBytes(salt);

    final byte[] encryptionSettingsPassphraseData = new byte[20];
    random.nextBytes(encryptionSettingsPassphraseData);
    final char[] encryptionSettingsDefinitionPassphrase =
         Base64.encode(encryptionSettingsPassphraseData).toCharArray();

    AES256EncodedPasswordSecretKey.generate(StaticUtils.NO_BYTES,
         encryptionSettingsDefinitionPassphrase, salt);
  }



  /**
   * Tests the behavior when trying to generate a secret key with an empty
   * encryption settings definition ID that is longer than 255 bytes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEncryptionSettingsDefinitionIDTooLong()
         throws Exception
  {
    final Random random = new Random();

    final byte[] salt = new byte[16];
    random.nextBytes(salt);

    final byte[] encryptionSettingsPassphraseData = new byte[20];
    random.nextBytes(encryptionSettingsPassphraseData);
    final char[] encryptionSettingsDefinitionPassphrase =
         Base64.encode(encryptionSettingsPassphraseData).toCharArray();

    AES256EncodedPasswordSecretKey.generate(new byte[256],
         encryptionSettingsDefinitionPassphrase, salt);
  }



  /**
   * Tests the behavior when trying to generate a secret key with a {@code null}
   * encryption settings definition passphrase.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNullEncryptionSettingsDefinitionPassphrase()
         throws Exception
  {
    final Random random = new Random();

    final byte[] salt = new byte[16];
    random.nextBytes(salt);

    final byte[] encryptionSettingsDefinitionID = new byte[32];
    random.nextBytes(encryptionSettingsDefinitionID);

    AES256EncodedPasswordSecretKey.generate(encryptionSettingsDefinitionID,
         null, salt);
  }



  /**
   * Tests the behavior when trying to generate a secret key with an empty
   * encryption settings definition passphrase.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEmptyEncryptionSettingsDefinitionPassphrase()
         throws Exception
  {
    final Random random = new Random();

    final byte[] salt = new byte[16];
    random.nextBytes(salt);

    final byte[] encryptionSettingsDefinitionID = new byte[32];
    random.nextBytes(encryptionSettingsDefinitionID);

    AES256EncodedPasswordSecretKey.generate(encryptionSettingsDefinitionID,
         StaticUtils.NO_CHARS, salt);
  }



  /**
   * Tests the behavior when trying to generate a secret key with a {@code null}
   * salt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNullSalt()
         throws Exception
  {
    final Random random = new Random();

    final byte[] encryptionSettingsDefinitionID = new byte[32];
    random.nextBytes(encryptionSettingsDefinitionID);

    final byte[] encryptionSettingsPassphraseData = new byte[20];
    random.nextBytes(encryptionSettingsPassphraseData);
    final char[] encryptionSettingsDefinitionPassphrase =
         Base64.encode(encryptionSettingsPassphraseData).toCharArray();

    AES256EncodedPasswordSecretKey.generate(encryptionSettingsDefinitionID,
         encryptionSettingsDefinitionPassphrase, null);
  }



  /**
   * Tests the behavior when trying to generate a secret key with an empty salt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEmptySalt()
         throws Exception
  {
    final Random random = new Random();

    final byte[] encryptionSettingsDefinitionID = new byte[32];
    random.nextBytes(encryptionSettingsDefinitionID);

    final byte[] encryptionSettingsPassphraseData = new byte[20];
    random.nextBytes(encryptionSettingsPassphraseData);
    final char[] encryptionSettingsDefinitionPassphrase =
         Base64.encode(encryptionSettingsPassphraseData).toCharArray();

    AES256EncodedPasswordSecretKey.generate(encryptionSettingsDefinitionID,
         encryptionSettingsDefinitionPassphrase, StaticUtils.NO_BYTES);
  }



  /**
   * Tests the behavior when trying to use a secret key after it has been
   * destroyed.
   *
   *
   * Tests the behavior when trying to generate a secret key with an empty salt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testUseAfterDestroy()
         throws Exception
  {
    final AES256EncodedPasswordSecretKey secretKey =
         AES256EncodedPasswordSecretKey.generate(
              "1234567890abcdef", "esd-passphrase");
    assertNotNull(secretKey);

    assertNotNull(secretKey.getEncryptionSettingsDefinitionID());
    assertEquals(secretKey.getEncryptionSettingsDefinitionID(),
         StaticUtils.byteArray(0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef));

    assertNotNull(secretKey.getKeyFactorySalt());
    assertEquals(secretKey.getKeyFactorySalt().length, 16);

    assertNotNull(secretKey.getSecretKey());

    assertNotNull(secretKey.toString());

    secretKey.destroy();

    secretKey.getSecretKey();
  }
}
