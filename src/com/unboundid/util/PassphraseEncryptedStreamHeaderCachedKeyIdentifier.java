/*
 * Copyright 2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2023 Ping Identity Corporation
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
 * Copyright (C) 2023 Ping Identity Corporation
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



import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;



/**
 * This class represents a data structure that may be used to identify a cached
 * secret key held in the {@link PassphraseEncryptedStreamHeaderSecretKeyCache}.
 */
final class PassphraseEncryptedStreamHeaderCachedKeyIdentifier
      implements Serializable
{
  /**
   * The digest algorithm to use to compute salted passphrase digests.
   */
  @NotNull private static final String DIGEST_ALGORITHM = "SHA-256";



  /**
   * A set of thread-local {@code ByteStringBuffer} instances for use in
   * creating salted passphrases.
   */
  @NotNull private static final ThreadLocal<ByteStringBuffer> BUFFERS =
       new ThreadLocal<>();



  /**
   * A set of thread-local {@code MessageDigest} instances for use in computing
   * salted passphrase digests.
   */
  @NotNull private static final ThreadLocal<MessageDigest> DIGESTS =
       new ThreadLocal<>();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 103858128692088432L;



  // The salt used to generate the secret key.
  @NotNull private final byte[] keyFactorySalt;

  // A salted digest for the passphrase used to generate the secret key.
  @NotNull private final byte[] saltedPaspshraseDigest;

  // The hash code for this key identifier.
  private final int hashCode;

  // The key factory iteration count used to generate the secret key.
  private final int keyFactoryIterationCount;

  // The length of the secret key, in bits.
  private final int keyFactoryKeyLengthBits;

  // The name of the key factory algorithm used to generate the secret key.
  @NotNull private final String keyFactoryAlgorithm;



  /**
   * Creates a new passphrase-encrypted stream header cached key identifier with
   * the provided information.
   *
   * @param  keyFactoryAlgorithm       The name of the key factory algorithm
   *                                   used to generate the cached key.  It
   *                                   must not be {@code null}.
   * @param  keyFactorySalt            The key factory salt used to generate the
   *                                   cached key.  It must not be {@code null}
   *                                   or empty.
   * @param  keyFactoryIterationCount  The key factory iteration count used to
   *                                   generate the cached key.
   * @param  keyFactoryKeyLengthBits   The length of the secret key, in bits.
   * @param  passphrase                The passphrase used to generate the
   *                                   secret key.  It must not be {@code null}
   *                                   or empty.
   *
   * @throws  GeneralSecurityException  If a problem occurs while creating the
   *                                    key identifier.
   */
  PassphraseEncryptedStreamHeaderCachedKeyIdentifier(
       @NotNull final String keyFactoryAlgorithm,
       @NotNull final byte[] keyFactorySalt,
       final int keyFactoryIterationCount,
       final int keyFactoryKeyLengthBits,
       @NotNull final char[] passphrase)
       throws GeneralSecurityException
  {
    this.keyFactoryAlgorithm = keyFactoryAlgorithm;
    this.keyFactorySalt = keyFactorySalt;
    this.keyFactoryIterationCount = keyFactoryIterationCount;
    this.keyFactoryKeyLengthBits = keyFactoryKeyLengthBits;

    saltedPaspshraseDigest =
         computeSaltedPassphraseDigest(passphrase, keyFactorySalt);
    hashCode = Arrays.hashCode(keyFactorySalt);
  }



  /**
   * Creates a new passphrase-encrypted stream header cached key identifier with
   * the provided information.
   *
   * @param  encryptionHeader  The encryption header to use to construct the key
   *                           identifier.
   * @param  passphrase        The passphrase used to generate the secret key.
   *                           It must not be {@code null} or empty.
   *
   * @throws  GeneralSecurityException  If a problem occurs while creating the
   *                                    key identifier.
   */
  PassphraseEncryptedStreamHeaderCachedKeyIdentifier(
       @NotNull final PassphraseEncryptedStreamHeader encryptionHeader,
       @NotNull final char[] passphrase)
       throws GeneralSecurityException
  {
    this(encryptionHeader.getKeyFactoryAlgorithm(),
         encryptionHeader.getKeyFactorySalt(),
         encryptionHeader.getKeyFactoryIterationCount(),
         encryptionHeader.getKeyFactoryKeyLengthBits(),
         passphrase);
  }



  /**
   * Computes a digest from the provided passphrase and salt.
   *
   * @param  passphrase  The passphrase for which to compute the digest.  It
   *                     must not be {@code null} or empty.
   * @param  salt        The salt to use when computing the digest.  It must not
   *                     be {@code null} or empty.
   *
   * @return  The computed digest.
   *
   * @throws  GeneralSecurityException  If a problem occurs while trying to
   *                                    compute the salted passphrase digest.
   */
  @NotNull()
  private static byte[] computeSaltedPassphraseDigest(
               @NotNull final char[] passphrase,
               @NotNull final byte[] salt)
         throws GeneralSecurityException
  {
    ByteStringBuffer buffer = BUFFERS.get();
    if (buffer == null)
    {
      buffer = new ByteStringBuffer();
      BUFFERS.set(buffer);
    }

    try
    {
      buffer.append(passphrase);
      buffer.append(salt);

      MessageDigest digest = DIGESTS.get();
      if (digest == null)
      {
        digest = CryptoHelper.getMessageDigest(DIGEST_ALGORITHM);
        DIGESTS.set(digest);
      }

      digest.update(buffer.getBackingArray(), 0, buffer.length());
      return digest.digest();
    }
    finally
    {
      buffer.clear(true);
    }
  }



  /**
   * Retrieves the hash code for this key identifier.
   *
   * @return  The hash code for this key identifier.
   */
  @Override()
  public int hashCode()
  {
    return hashCode;
  }



  /**
   * Indicates whether the provided object is equal to this cached key
   * identifier.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is considered equal to this
   *          cached key identifier, or {@code false} if not.
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (! (o instanceof PassphraseEncryptedStreamHeaderCachedKeyIdentifier))
    {
      return false;
    }

    final PassphraseEncryptedStreamHeaderCachedKeyIdentifier i =
         (PassphraseEncryptedStreamHeaderCachedKeyIdentifier) o;
    return Arrays.equals(saltedPaspshraseDigest, i.saltedPaspshraseDigest) &&
         Arrays.equals(keyFactorySalt, i.keyFactorySalt) &&
         (keyFactoryIterationCount == i.keyFactoryIterationCount) &&
         (keyFactoryKeyLengthBits == i.keyFactoryKeyLengthBits) &&
         keyFactoryAlgorithm.equals(i.keyFactoryAlgorithm);
  }
}
