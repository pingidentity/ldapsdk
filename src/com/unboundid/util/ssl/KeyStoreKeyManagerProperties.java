/*
 * Copyright 2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024 Ping Identity Corporation
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
 * Copyright (C) 2024 Ping Identity Corporation
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
package com.unboundid.util.ssl;



import java.io.File;
import java.io.Serializable;
import java.security.Provider;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a data structure with information about properties to
 * use when accessing the {@link KeyStoreKeyManager}.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class KeyStoreKeyManagerProperties
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -115811521330361189L;



  // Indicates whether to allow accessing a non-FIPS-compliant key store when
  // running in FIPS-compliant mode.
  private boolean allowNonFIPSInFIPSMode;

  // Indicates whether to validate that the provided store is acceptable and can
  // actually be used obtain a valid certificate.
  private boolean validateKeyStore;

  // The PIN needed to access the contents of the key store.
  @Nullable private char[] keyStorePIN;

  // The security provider to use to access the key store.
  @Nullable private Provider provider;

  // The alias for the target certificate in the key store.
  @Nullable private String certificateAlias;

  // The path to the key store file.
  @NotNull private String keyStorePath;

  // The format to use for the key store file.
  @Nullable private String keyStoreFormat;



  /**
   * Creates a new set of key manage provider properties for the specified key
   * store file.
   *
   * @param  keyStoreFile  The target key store file.  It must not be
   *                       {@code null}.
   */
  public KeyStoreKeyManagerProperties(@NotNull final File keyStoreFile)
  {
    this(keyStoreFile.getAbsolutePath());
  }



  /**
   * Creates a new set of key manage provider properties for the specified key
   * store file.
   *
   * @param  keyStorePath  The path to the target key store file.  It must not
   *                       be {@code null}.
   */
  public KeyStoreKeyManagerProperties(@NotNull final String keyStorePath)
  {
    Validator.ensureNotNull(keyStorePath);

    this.keyStorePath = keyStorePath;

    keyStorePIN = null;
    keyStoreFormat = null;
    certificateAlias = null;
    provider = null;
    validateKeyStore = false;
    allowNonFIPSInFIPSMode = false;
  }



  /**
   * Retrieves the path to the target key store file.
   *
   * @return  The path to the target key store file.
   */
  @NotNull()
  public String getKeyStorePath()
  {
    return keyStorePath;
  }



  /**
   * Specifies the target key store file.
   *
   * @param  keyStoreFile  The target key store file.  It must not be
   *                       {@code null}.
   */
  public void setKeyStoreFile(@NotNull final File keyStoreFile)
  {
    Validator.ensureNotNull(keyStoreFile);
    keyStorePath = keyStoreFile.getAbsolutePath();
  }



  /**
   * Specifies the path to the target key store file.
   *
   * @param  keyStorePath  The path to the target key store file.  It must not
   *                       be {@code null}.
   */
  public void setKeyStorePath(@NotNull final String keyStorePath)
  {
    Validator.ensureNotNull(keyStorePath);
    this.keyStorePath = keyStorePath;
  }



  /**
   * Retrieves the PIN needed to access the contents of the key store, if
   * specified.
   *
   * @return  The PIN needed to access the contents of the key store, or
   *          {@code null} if none has been specified.
   */
  @Nullable()
  public char[] getKeyStorePIN()
  {
    return keyStorePIN;
  }



  /**
   * Specifies the PIN needed to access the contents of the key store.
   *
   * @param  keyStorePIN  The PIN needed to access the contents of the key
   *                      store.  It may be {@code null} if no PIN is needed.
   */
  public void setKeyStorePIN(@Nullable final char[] keyStorePIN)
  {
    this.keyStorePIN = keyStorePIN;
  }



  /**
   * Specifies the PIN needed to access the contents of the key store.
   *
   * @param  keyStorePIN  The PIN needed to access the contents of the key
   *                      store.  It may be {@code null} if no PIN is needed.
   */
  public void setKeyStorePIN(@Nullable final String keyStorePIN)
  {
    if (keyStorePIN == null)
    {
      this.keyStorePIN = null;
    }
    else
    {
      this.keyStorePIN = keyStorePIN.toCharArray();
    }

  }



  /**
   * Retrieves the format for the target key store, if specified.
   *
   * @return  The format for the target key store, or {@code null} if a default
   *          format should be used.
   */
  @Nullable()
  public String getKeyStoreFormat()
  {
    return keyStoreFormat;
  }



  /**
   * Specifies the format for the target key store.
   *
   * @param  keyStoreFormat  The format for the target key store.  It may be
   *                         {@code null} if a default format should be used.
   */
  public void setKeyStoreFormat(@Nullable final String keyStoreFormat)
  {
    this.keyStoreFormat = keyStoreFormat;
  }



  /**
   * Retrieves the alias (nickname) of the certificate chain to use in the
   * target key store, if specified.
   *
   * @return  The alias of the certificate chain to use in the target key store,
   *          or {@code null} if any acceptable certificate found in the key
   *          store may be used.
   */
  @Nullable()
  public String getCertificateAlias()
  {
    return certificateAlias;
  }



  /**
   * Specifies the alias (nickname) of the certificate chain ot use in the
   * target key store.
   *
   * @param  certificateAlias  The alias of the certificate chain to use in the
   *                           target key store.  It may be {@code null} if any
   *                           acceptable certificate found in the key store may
   *                           be used.
   */
  public void setCertificateAlias(@Nullable final String certificateAlias)
  {
    this.certificateAlias = certificateAlias;
  }



  /**
   * Indicates whether to validate that the provided key store is acceptable and
   * can actually be used to obtain a valid certificate chain.
   *
   * @return  {@code true} if the key store should be validated before
   *          attempting to use it, or {@code false} if not.
   */
  public boolean validateKeyStore()
  {
    return validateKeyStore;
  }



  /**
   * Specifies whether to validate that the provided key store is acceptable and
   * can actually be used to obtain a valid certificate chain.
   *
   * @param  validateKeyStore  Indicates whether to validate that the provided
   *                           key store is acceptable and can actually be used
   *                           to obtain a valid certificate chain.  If a
   *                           certificate alias was specified, then this will
   *                           ensure that the key store contains a valid
   *                           private key entry with that alias.  If no
   *                           certificate alias was specified, then this will
   *                           ensure that the key store contains at least one
   *                           valid private key entry.
   */
  public void setValidateKeyStore(final boolean validateKeyStore)
  {
    this.validateKeyStore = validateKeyStore;
  }



  /**
   * Retrieves the security provider to use to access the key store, if a
   * non-default provider should be used.
   *
   * @return  The security provider to use to access the key store, or
   *          {@code null} if a default provider should be used.
   */
  @Nullable()
  public Provider getProvider()
  {
    return provider;
  }



  /**
   * Specifies the security provider to use to access the key store.
   *
   * @param  provider  The security provider to use to access the key store.  It
   *                   may be {@code null} if a default provider should be used.
   */
  public void setProvider(@Nullable final Provider provider)
  {
    this.provider = provider;
  }



  /**
   * Indicates whether to allow access to a non-FIPS-compliant key store even
   * when operating in FIPS-compliant mode.
   *
   * @return  {@code true} if access to a non-FIPS-compliant key store should be
   *          allowed even when operating in FIPS-compliant mode, or
   *          {@code false} if not.
   */
  public boolean allowNonFIPSInFIPSMode()
  {
    return allowNonFIPSInFIPSMode;
  }



  /**
   * Specifies whether to allow access to a non-FIPS-compliant key store even
   * when operating in FIPS-compliant mode.
   *
   * @param  allowNonFIPSInFIPSMode  Indicates whether to allow access to a
   *                                 non-FIPS-compliant key store even when
   *                                 operating in FIPS-compliant mode.
   */
  public void setAllowNonFIPSInFIPSMode(final boolean allowNonFIPSInFIPSMode)
  {
    this.allowNonFIPSInFIPSMode = allowNonFIPSInFIPSMode;
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
   * @param  buffer  The buffer to which the information should be appended.
   *                 It must not be {@code null}.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("KeyStoreKeyManagerProperties(keyStorePath='");
    buffer.append(keyStorePath);
    buffer.append('\'');
    buffer.append(", keyStorePINProvided=");
    buffer.append(keyStorePIN != null);

    if (keyStoreFormat != null)
    {
      buffer.append(", keyStoreFormat='");
      buffer.append(keyStoreFormat);
      buffer.append('\'');
    }

    if (certificateAlias != null)
    {
      buffer.append(", certificateAlias='");
      buffer.append(certificateAlias);
      buffer.append('\'');
    }

    buffer.append(", validateKeyStore=");
    buffer.append(validateKeyStore);

    if (provider != null)
    {
      buffer.append(", providerClass='");
      buffer.append(provider.getClass().getName());
      buffer.append('\'');
    }

    buffer.append(", allowNonFIPSInFIPSMode=");
    buffer.append(allowNonFIPSInFIPSMode);
    buffer.append(')');
  }
}
