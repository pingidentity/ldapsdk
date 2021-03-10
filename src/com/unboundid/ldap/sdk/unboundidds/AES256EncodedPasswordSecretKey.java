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



import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Destroyable;

import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.AES256EncodedPassword.*;



/**
 * This class provides a data structure that may be used to hold a reusable
 * secret key for use in conjunction with {@link AES256EncodedPassword}
 * objects.  Reusing a secret key avoids the (potentially significant) cost of
 * generating it for each encryption and decryption operation.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@NotMutable
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AES256EncodedPasswordSecretKey
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5993762526459847323L;



  // A references to the secret key that was generated.
  @NotNull private final AtomicReference<SecretKey> secretKeyRef;

  // The bytes that comprise the raw encryption settings definition ID whose
  // passphrase was used to generate the secret key.
  @NotNull private final byte[] encryptionSettingsDefinitionID;

  // The salt used in the course of generating the secret key.
  @NotNull private final byte[] keyFactorySalt;



  /**
   * Creates a new ASE256 secret key object from the provided information.
   *
   * @param  encryptionSettingsDefinitionID
   *              The bytes that comprise the raw encryption settings definition
   *              ID whose passphrase was used to generate the secret key.  It
   *              must not be {@code null} or empty, and its length must be less
   *              than or equal to 255 bytes.
   * @param  keyFactorySalt
   *              The salt used to generate the encryption key from the
   *              encryption settings definition passphrase.  It must not be
   *              {@code null} and it must have a length of exactly 16 bytes.
   * @param  secretKey
   *              The secret key that was generated from the salt and the
   *              encryption settings definition passphrase.
   */
  private AES256EncodedPasswordSecretKey(
              @NotNull final byte[] encryptionSettingsDefinitionID,
              @NotNull final byte[] keyFactorySalt,
              @NotNull final SecretKey secretKey)
  {
    this.encryptionSettingsDefinitionID = encryptionSettingsDefinitionID;
    this.keyFactorySalt = keyFactorySalt;

    secretKeyRef = new AtomicReference<>(secretKey);
  }



  /**
   * Generates an AES256 secret key from the provided information.
   *
   * @param  encryptionSettingsDefinitionID
   *              A string with the hexadecimal representation of the
   *              encryption settings definition whose passphrase was used to
   *              generate the encoded password.  It must not be
   *              {@code null} or empty, and it must represent a valid
   *              hexadecimal string whose length is an even number less than
   *              or equal to 510 bytes.
   * @param  encryptionSettingsDefinitionPassphrase
   *              The passphrase associated with the specified encryption
   *              settings definition.  It must not be {@code null} or empty.
   *
   * @return  The AES256 secret key that was generated.
   *
   * @throws  GeneralSecurityException  If a problem occurs while trying to
   *                                    generate the secret key.
   *
   * @throws  ParseException  If the provided encryption settings ID cannot be
   *                          parsed as a hexadecimal string.
   */
  @NotNull()
  public static AES256EncodedPasswordSecretKey generate(
              @NotNull final String encryptionSettingsDefinitionID,
              @NotNull final String encryptionSettingsDefinitionPassphrase)
         throws GeneralSecurityException, ParseException
  {
    final char[] passphraseChars =
         encryptionSettingsDefinitionPassphrase.toCharArray();
    try
    {
      return generate(
           StaticUtils.fromHex(encryptionSettingsDefinitionID),
           passphraseChars);
    }
    finally
    {
      Arrays.fill(passphraseChars, '\u0000');
    }
  }



  /**
   * Generates an AES256 secret key from the provided information.
   *
   * @param  encryptionSettingsDefinitionID
   *              The bytes that comprise the raw encryption settings definition
   *              ID whose passphrase was used to generate the encoded password.
   *              It must not be {@code null} or empty, and its length must be
   *              less than or equal to 255 bytes.
   * @param  encryptionSettingsDefinitionPassphrase
   *              The passphrase associated with the specified encryption
   *              settings definition.  It must not be {@code null} or empty.
   *
   * @return  The AES256 secret key that was generated.
   *
   * @throws  GeneralSecurityException  If a problem occurs while trying to
   *                                    generate the secret key.
   */
  @NotNull()
  public static AES256EncodedPasswordSecretKey generate(
              @NotNull final byte[] encryptionSettingsDefinitionID,
              @NotNull final char[] encryptionSettingsDefinitionPassphrase)
         throws GeneralSecurityException
  {
    final SecureRandom random = CryptoHelper.getSecureRandom();
    final byte[] keyFactorySalt =
         new byte[ENCODING_VERSION_0_KEY_FACTORY_SALT_LENGTH_BYTES];
    random.nextBytes(keyFactorySalt);

    return generate(encryptionSettingsDefinitionID,
         encryptionSettingsDefinitionPassphrase, keyFactorySalt);
  }



  /**
   * Generates an AES256 secret key from the provided information.
   *
   * @param  encryptionSettingsDefinitionID
   *              The bytes that comprise the raw encryption settings definition
   *              ID whose passphrase was used to generate the encoded password.
   *              It must not be {@code null} or empty, and its length must be
   *              less than or equal to 255 bytes.
   * @param  encryptionSettingsDefinitionPassphrase
   *              The passphrase associated with the specified encryption
   *              settings definition.  It must not be {@code null} or empty.
   * @param  keyFactorySalt
   *              The salt used to generate the encryption key from the
   *              encryption settings definition passphrase.  It must not be
   *              {@code null} and it must have a length of exactly 16 bytes.
   *
   * @return  The AES256 secret key that was generated.
   *
   * @throws  GeneralSecurityException  If a problem occurs while trying to
   *                                    generate the secret key.
   */
  @NotNull()
  public static AES256EncodedPasswordSecretKey generate(
              @NotNull final byte[] encryptionSettingsDefinitionID,
              @NotNull final char[] encryptionSettingsDefinitionPassphrase,
              @NotNull final byte[] keyFactorySalt)
         throws GeneralSecurityException
  {
    Validator.ensureNotNullOrEmpty(encryptionSettingsDefinitionID,
         "AES256EncodedPasswordSecretKey.encryptionSettingsDefinitionID must " +
              "not be null or empty.");
    Validator.ensureTrue((encryptionSettingsDefinitionID.length <= 255),
         "AES256EncodedPasswordSecretKey.encryptionSettingsDefinitionID must " +
              "have a length that is between 1 and 255 bytes, inclusive.");

    Validator.ensureNotNullOrEmpty(encryptionSettingsDefinitionPassphrase,
         "AES256EncodedPasswordSecretKey." +
              "encryptionSettingsDefinitionPassphrase must not be null or " +
              "empty.");
    Validator.ensureNotNull(keyFactorySalt,
         "AES256EncodedPasswordSecretKey.keyFactorySalt must not be null.");
    Validator.ensureTrue((keyFactorySalt.length == 16),
         "AES256EncodedPasswordSecretKey.keyFactorySalt must have a length " +
              "of exactly 16 bytes.");

    final PBEKeySpec pbeKeySpec = new PBEKeySpec(
         encryptionSettingsDefinitionPassphrase, keyFactorySalt,
         ENCODING_VERSION_0_KEY_FACTORY_ITERATION_COUNT,
         ENCODING_VERSION_0_GENERATED_KEY_LENGTH_BITS);

    final SecretKeyFactory secretKeyFactory = CryptoHelper.getSecretKeyFactory(
         ENCODING_VERSION_0_KEY_FACTORY_ALGORITHM);

    final SecretKey secretKey = new SecretKeySpec(
         secretKeyFactory.generateSecret(pbeKeySpec).getEncoded(),
         ENCODING_VERSION_0_CIPHER_ALGORITHM);

    return new AES256EncodedPasswordSecretKey(encryptionSettingsDefinitionID,
         keyFactorySalt, secretKey);
  }



  /**
   * Retrieves the bytes that comprise the raw identifier for the encryption
   * settings definition whose passphrase was used to generate the secret key.
   *
   * @return  A bytes that comprise the raw identifier for the encryption
   *          settings definition whose passphrase was used to generate the
   *          secret key.
   */
  @NotNull()
  public byte[] getEncryptionSettingsDefinitionID()
  {
    return encryptionSettingsDefinitionID;
  }



  /**
   * Retrieves the salt used to generate the secret key from the encryption
   * settings definition passphrase.
   *
   * @return  The salt used to generate the secret key from the encryption
   *          settings definition passphrase.
   */
  @NotNull()
  public byte[] getKeyFactorySalt()
  {
    return keyFactorySalt;
  }



  /**
   * Retrieves the secret key that was generated.  This method must not be
   * called after the {@link #destroy} method has been called.
   *
   * @return  The secret key that was generated.
   */
  @NotNull()
  public SecretKey getSecretKey()
  {
    final SecretKey secretKey = secretKeyRef.get();
    if (secretKey == null)
    {
      Validator.violation("An AES256EncodedPasswordSecretKey instance must " +
           "not be used after it has been destroyed.");
    }

    return secretKey;
  }



  /**
   * Destroys this secret key.  The key must not be used after it has been
   * destroyed.
   */
  public void destroy()
  {
    final SecretKey secretKey = secretKeyRef.getAndSet(null);
    if ((secretKey != null) && (secretKey instanceof Destroyable))
    {
      try
      {
        final Destroyable destroyableSecretKey = (Destroyable) secretKey;
        destroyableSecretKey.destroy();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }
  }



  /**
   * Retrieves a string representation of this AES256 encoded password secret
   * key.
   *
   * @return  A string representation of this AES256 encoded password secret
   *          key.
   */
  @NotNull()
  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this AES256 encoded password secret key
   * to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("AES256EncodedPasswordSecretKey(" +
         "encryptionSettingsDefinitionIDHex='");
    StaticUtils.toHex(encryptionSettingsDefinitionID, buffer);
    buffer.append("', keyFactorySaltBytesHex='");
    StaticUtils.toHex(keyFactorySalt, buffer);
    buffer.append("')");
  }
}
