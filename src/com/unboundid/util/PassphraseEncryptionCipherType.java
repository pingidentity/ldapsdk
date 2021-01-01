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
package com.unboundid.util;



import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Cipher;



/**
 * This enum defines sets of settings that may be used when encrypting data with
 * a {@link PassphraseEncryptedOutputStream}.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum PassphraseEncryptionCipherType
{
  /**
   * Cipher settings that use a 128-bit AES cipher.
   */
  AES_128("AES/CBC/PKCS5Padding", 128, "PBKDF2WithHmacSHA1", 16_384, 16, 16,
       "HmacSHA256"),



  /**
   * Cipher settings that use a 256-bit AES cipher.
   */
  AES_256("AES/CBC/PKCS5Padding", 256, "PBKDF2WithHmacSHA512", 131_072, 16, 16,
       "HmacSHA512");



  /**
   * A reference to the strongest defined cipher type value that is supported by
   * the underlying JVM.  Its value will be {@code null} until the first attempt
   * is made to determine it.  The cached value will be used for subsequent
   * attempts to retrieve the value.
   */
  @NotNull private static final AtomicReference<PassphraseEncryptionCipherType>
       STRONGEST_AVAILABLE_CIPHER_TYPE = new AtomicReference<>();



  // The length (in bytes) to use for the initialization vector when creating
  // the cipher.
  private final int initializationVectorLengthBytes;

  // The iteration count that will be used when generating the encryption key
  // from the passphrase.
  private final int keyFactoryIterationCount;

  // The length (in bytes) to use for the salt when generating the encryption
  // key from the passphrase.
  private final int keyFactorySaltLengthBytes;

  // The length (in bits) for the encryption key to generate from the
  // passphrase.
  private final int keyLengthBits;

  // The cipher transformation that will be used for the encryption.
  @NotNull private final String cipherTransformation;

  // The name of the algorithm that will be used to generate the encryption key
  // from the passphrase.
  @NotNull private final String keyFactoryAlgorithm;

  // The name of the algorithm that will be used to generate a MAC of the
  // encryption header contents.
  @NotNull private final String macAlgorithm;



  /**
   * Creates a new passphrase encryption cipher type value with the provided
   * information.
   *
   * @param  cipherTransformation
   *              The cipher transformation that will be used for the
   *              encryption.
   * @param  keyLengthBits
   *              The length (in bits) for the encryption key to generate.
   * @param  keyFactoryAlgorithm
   *              The name of the algorithm that will be used to generate the
   *              encryption key from the passphrase.
   * @param  keyFactoryIterationCount
   *              The iteration count that will be used when generating the
   *              encryption key from the passphrase.
   * @param  keyFactorySaltLengthBytes
   *              The length (in bytes) to use for the salt when generating the
   *              encryption key from the passphrase.
   * @param  initializationVectorLengthBytes
   *              The length (in bytes) to use for the initialization vector
   *              when creating the cipher.
   * @param  macAlgorithm
   *              The name of the algorithm that will be used to generate a MAC
   *              of the encryption header contents.
   */
  PassphraseEncryptionCipherType(@NotNull final String cipherTransformation,
                                 final int keyLengthBits,
                                 @NotNull final String keyFactoryAlgorithm,
                                 final int keyFactoryIterationCount,
                                 final int keyFactorySaltLengthBytes,
                                 final int initializationVectorLengthBytes,
                                 @NotNull final String macAlgorithm)
  {
    this.cipherTransformation = cipherTransformation;
    this.keyLengthBits = keyLengthBits;
    this.keyFactoryAlgorithm = keyFactoryAlgorithm;
    this.keyFactoryIterationCount = keyFactoryIterationCount;
    this.keyFactorySaltLengthBytes = keyFactorySaltLengthBytes;
    this.initializationVectorLengthBytes = initializationVectorLengthBytes;
    this.macAlgorithm = macAlgorithm;
  }



  /**
   * Retrieves the cipher transformation that will be used for the encryption.
   *
   * @return  The cipher transformation that will be used for the encryption.
   */
  @NotNull()
  public String getCipherTransformation()
  {
    return cipherTransformation;
  }



  /**
   * Retrieves the length (in bits) for the encryption key to generate.
   *
   * @return  The length (in bits) for the encryption key to generate.
   */
  public int getKeyLengthBits()
  {
    return keyLengthBits;
  }



  /**
   * Retrieves the name of the algorithm that will be used to generate the
   * encryption key from the passphrase.
   *
   * @return  The name of the algorithm that will be used to generate the
   *          encryption key from the passphrase.
   */
  @NotNull()
  public String getKeyFactoryAlgorithm()
  {
    return keyFactoryAlgorithm;
  }



  /**
   * Retrieves the iteration count that will be used when generating the
   * encryption key from the passphrase.
   *
   * @return  The iteration count that will be used when generating the
   *          encryption key from the passphrase.
   */
  public int getKeyFactoryIterationCount()
  {
    return keyFactoryIterationCount;
  }



  /**
   * Retrieves the length (in bytes) to use for the salt when generating the
   * encryption key from the passphrase.
   *
   * @return  The length (in bytes) to use for the salt when generating the
   *          encryption key from the passphrase.
   */
  public int getKeyFactorySaltLengthBytes()
  {
    return keyFactorySaltLengthBytes;
  }



  /**
   * Retrieves the length (in bytes) to use for the initialization vector when
   * generating the cipher.
   *
   * @return  The length (in bytes) to use for the initialization vector when
   *          generating the cipher.
   */
  public int getInitializationVectorLengthBytes()
  {
    return initializationVectorLengthBytes;
  }



  /**
   * Retrieves the name of the algorithm that will be used to generate a MAC of
   * the encryption header contents.
   *
   * @return  The name of the algorithm that will be used to generate a MAC of
   *          the encryption header contents.
   */
  @NotNull()
  public String getMacAlgorithm()
  {
    return macAlgorithm;
  }



  /**
   * Retrieves the cipher type value for the provided name.
   *
   * @param  name  The name of the cipher type value to retrieve.
   *
   * @return  The cipher type object for the given name, or {@code null} if the
   *          provided name does not map to any cipher type value.
   */
  @Nullable()
  public static PassphraseEncryptionCipherType forName(
              @NotNull final String name)
  {
    final String transformedName =
         StaticUtils.toUpperCase(name).replace('-', '_');
    for (final PassphraseEncryptionCipherType value : values())
    {
      if (value.name().equals(transformedName))
      {
        return value;
      }
    }

    return null;
  }



  /**
   * Retrieves the cipher type value that corresponds to the strongest supported
   * level of protection that is available in the underlying JVM.
   *
   * @return  The cipher type value that corresponds to the strongest supported
   *          level of protection in the underlying JVM.
   */
  @NotNull()
  public static PassphraseEncryptionCipherType getStrongestAvailableCipherType()
  {
    PassphraseEncryptionCipherType cipherType =
         STRONGEST_AVAILABLE_CIPHER_TYPE.get();
    if (cipherType == null)
    {
      cipherType = PassphraseEncryptionCipherType.AES_128;

      try
      {
        final PassphraseEncryptionCipherType ct =
             PassphraseEncryptionCipherType.AES_256;
        final PassphraseEncryptedStreamHeader header =
             new PassphraseEncryptedStreamHeader(
                  "dummy-passphrase".toCharArray(), ct.getKeyFactoryAlgorithm(),
                  ct.getKeyFactoryIterationCount(),
                  new byte[ct.getKeyFactorySaltLengthBytes()],
                  ct.getKeyLengthBits(), ct.getCipherTransformation(),
                  new byte[ct.getInitializationVectorLengthBytes()],
                  null, ct.getMacAlgorithm());
        header.createCipher(Cipher.ENCRYPT_MODE);
        cipherType = ct;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }

      if (! STRONGEST_AVAILABLE_CIPHER_TYPE.compareAndSet(null, cipherType))
      {
        cipherType = STRONGEST_AVAILABLE_CIPHER_TYPE.get();
      }
    }

    return cipherType;
  }



  /**
   * Retrieves a string representation of this cipher type value.
   *
   * @return  A string representation of this cipher type value.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this cipher type value to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("PassphraseEncryptedCipherType(cipherTransformation='");
    buffer.append(cipherTransformation);
    buffer.append("', keyLengthBits=");
    buffer.append(keyLengthBits);
    buffer.append(", keyFactoryAlgorithm='");
    buffer.append(keyFactoryAlgorithm);
    buffer.append("', keyFactoryIterationCount=");
    buffer.append(keyFactoryIterationCount);
    buffer.append(", keyFactorySaltLengthBytes=");
    buffer.append(keyFactorySaltLengthBytes);
    buffer.append(", initializationVectorLengthBytes=");
    buffer.append(initializationVectorLengthBytes);
    buffer.append(", macAlgorithm='");
    buffer.append(macAlgorithm);
    buffer.append("')");
  }
}
