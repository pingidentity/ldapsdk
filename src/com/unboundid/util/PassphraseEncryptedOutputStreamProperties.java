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



import java.io.Serializable;



/**
 * This class provides a set of properties that will be used when creating a
 * {@link PassphraseEncryptedOutputStream}.  The default settings that will be
 * used for properties that are not required in the constructor are:
 * <UL>
 *   <LI>
 *     The header will be written to the beginning of the output stream.
 *   </LI>
 *   <LI>
 *     The cipher type's key factory iteration count will be used.
 *   </LI>
 *   <LI>
 *     No key identifier will be included in the encryption header.
 *   </LI>
 * </UL>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class PassphraseEncryptedOutputStreamProperties
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2778471308512283705L;



  // Indicates whether to write the encryption header to the beginning of the
  // output stream.
  private boolean writeHeaderToStream;

  // The iteration count that will be used when generating the encryption key
  // from the passphrase.
  private int keyFactoryIterationCount;

  // The cipher type value that will be used to obtain settings when encrypting
  // data.
  @NotNull private final PassphraseEncryptionCipherType cipherType;

  // An optional identifier that may be used to associate the encryption details
  // with information in another system.
  @Nullable private String keyIdentifier;



  /**
   * Creates a new {@code PassphraseEncryptedOutputStreamProperties} instance
   * with the provided cipher type value.
   *
   * @param  cipherType  The cipher type value that will be used to obtain
   *                     settings when encrypting data.
   */
  public PassphraseEncryptedOutputStreamProperties(
       @NotNull final PassphraseEncryptionCipherType cipherType)
  {
    this.cipherType = cipherType;

    writeHeaderToStream = true;
    keyFactoryIterationCount = cipherType.getKeyFactoryIterationCount();
    keyIdentifier = null;
  }



  /**
   * Retrieves the cipher type value that will be used to obtain settings when
   * encrypting data.
   *
   * @return  The cipher type value that will be used to obtain settings when
   *          encrypting data.
   */
  @NotNull()
  public PassphraseEncryptionCipherType getCipherType()
  {
    return cipherType;
  }



  /**
   * Indicates whether the {@link PassphraseEncryptedOutputStream} should write
   * the generated {@link PassphraseEncryptedStreamHeader} to the wrapped output
   * stream before starting the encrypted data so that a
   * {@link PassphraseEncryptedInputStream} can read it to obtain the necessary
   * information for decrypting the data.
   *
   * @return  {@code true} if the {@code PassphraseEncryptedOutputStream} should
   *          write a {@code PassphraseEncryptedStreamHeader} to the wrapped
   *          output stream before any encrypted data, or {@code false} if not.
   */
  public boolean writeHeaderToStream()
  {
    return writeHeaderToStream;
  }



  /**
   * Specifies whether the {@link PassphraseEncryptedOutputStream} should write
   * the generated {@link PassphraseEncryptedStreamHeader} to the wrapped output
   * stream before starting the encrypted data so that a
   * {@link PassphraseEncryptedInputStream} can read it to obtain the necessary
   * information for decrypting the data.  If this is {@code false}, then the
   * necessary metadata should be stored elsewhere so that it can be used to
   * decrypt the data.
   *
   * @param  writeHeaderToStream  Indicates whether the
   *                              {@code PassphraseEncryptedOutputStream} should
   *                              write the generated
   *                              {@code PassphraseEncryptedStreamHeader} to the
   *                              wrapped output stream before starting the
   *                              encrypted data.
   */
  public void setWriteHeaderToStream(final boolean writeHeaderToStream)
  {
    this.writeHeaderToStream = writeHeaderToStream;
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
   * Specifies the iteration count that will be used when generating the
   * encryption key from the passphrase.
   *
   * @param  keyFactoryIterationCount  The iteration count that will be used
   *                                   when generating the encryption key from
   *                                   the passphrase.  If this is {@code null},
   *                                   then the cipher type's key factory
   *                                   iteration count will be used.
   */
  public void setKeyFactoryIterationCount(
                   @Nullable final Integer keyFactoryIterationCount)
  {
    if (keyFactoryIterationCount == null)
    {
      this.keyFactoryIterationCount = cipherType.getKeyFactoryIterationCount();
    }
    else
    {
      this.keyFactoryIterationCount = keyFactoryIterationCount;
    }
  }



  /**
   * Retrieves a key identifier that may be used to associate the encryption
   * details with information in another system.  This is primarily intended for
   * use in conjunction with the UnboundID/Ping Identity server products, but it
   * may be useful in other systems as well.
   *
   * @return  A key identifier that may be used to associate the encryption
   *          details with information in another system, or {@code null} if no
   *          key identifier should be used.
   */
  @Nullable()
  public String getKeyIdentifier()
  {
    return keyIdentifier;
  }



  /**
   * Specifies a key identifier that may be used to associate the encryption
   * details with information in another system.  This is primarily intended for
   * use in conjunction with the UnboundID/Ping Identity server products, but it
   * may be useful in other systems as well.
   *
   * @param  keyIdentifier  A key identifier that may be used to associate the
   *                        encryption details with information in another
   *                        system.  It may be {@code null} if no key identifier
   *                        should be used.
   */
  public void setKeyIdentifier(@Nullable final String keyIdentifier)
  {
    this.keyIdentifier = keyIdentifier;
  }



  /**
   * Retrieves a string representation of these properties.
   *
   * @return  A string representation of these properties.
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
   * Appends a string representation of these properties to the provided buffer.
   *
   * @param  buffer  The buffer to which the properties should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("PassphraseEncryptedOutputStreamProperties(cipherType=");
    cipherType.toString(buffer);
    buffer.append(", writeHeaderToStream=");
    buffer.append(writeHeaderToStream);

    if (keyFactoryIterationCount != cipherType.getKeyFactoryIterationCount())
    {
      buffer.append(", keyFactoryIterationCount=");
      buffer.append(keyFactoryIterationCount);
    }

    if (keyIdentifier != null)
    {
      buffer.append(", keyIdentifier='");
      buffer.append(keyIdentifier);
      buffer.append('\'');
    }


    buffer.append(')');
  }
}
