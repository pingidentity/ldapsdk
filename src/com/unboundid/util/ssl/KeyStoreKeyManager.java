/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
import java.io.FileInputStream;
import java.io.Serializable;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.security.auth.x500.X500Principal;

import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.util.ssl.SSLMessages.*;



/**
 * This class provides an SSL key manager that may be used to retrieve
 * certificates from a key store file.  By default it will use the default key
 * store format for the JVM (e.g., "JKS" for Sun-provided Java implementations),
 * but alternate formats like PKCS12 may be used.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class KeyStoreKeyManager
       extends WrapperKeyManager
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5202641256733094253L;



  // The path to the key store file.
  @NotNull private final String keyStoreFile;

  // The format to use for the key store file.
  @NotNull private final String keyStoreFormat;



  /**
   * Creates a new instance of this key store key manager that provides the
   * ability to retrieve certificates from the specified key store file.  It
   * will use the default key store format.
   *
   * @param  keyStoreFile  The path to the key store file to use.  It must not
   *                       be {@code null}.
   * @param  keyStorePIN   The PIN to use to access the contents of the key
   *                       store.  It may be {@code null} if no PIN is required.
   *
   * @throws  KeyStoreException  If a problem occurs while initializing this key
   *                             manager.
   */
  public KeyStoreKeyManager(@NotNull final File keyStoreFile,
                            @Nullable final char[] keyStorePIN)
         throws KeyStoreException
  {
    this(keyStoreFile.getAbsolutePath(), keyStorePIN, null, null);
  }



  /**
   * Creates a new instance of this key store key manager that provides the
   * ability to retrieve certificates from the specified key store file.  It
   * will use the default key store format.
   *
   * @param  keyStoreFile  The path to the key store file to use.  It must not
   *                       be {@code null}.
   * @param  keyStorePIN   The PIN to use to access the contents of the key
   *                       store.  It may be {@code null} if no PIN is required.
   *
   * @throws  KeyStoreException  If a problem occurs while initializing this key
   *                             manager.
   */
  public KeyStoreKeyManager(@NotNull final String keyStoreFile,
                            @Nullable final char[] keyStorePIN)
         throws KeyStoreException
  {
    this(keyStoreFile, keyStorePIN, null, null);
  }



  /**
   * Creates a new instance of this key store key manager that provides the
   * ability to retrieve certificates from the specified key store file.
   *
   * @param  keyStoreFile      The path to the key store file to use.  It must
   *                           not be {@code null}.
   * @param  keyStorePIN       The PIN to use to access the contents of the key
   *                           store.  It may be {@code null} if no PIN is
   *                           required.
   * @param  keyStoreFormat    The format to use for the key store.  It may be
   *                           {@code null} if the default format should be
   *                           used.
   * @param  certificateAlias  The nickname of the certificate that should be
   *                           selected.  It may be {@code null} if any
   *                           acceptable certificate found in the keystore may
   *                           be used.
   *
   * @throws  KeyStoreException  If a problem occurs while initializing this key
   *                             manager.
   */
  public KeyStoreKeyManager(@NotNull final File keyStoreFile,
                            @Nullable final char[] keyStorePIN,
                            @Nullable final String keyStoreFormat,
                            @Nullable final String certificateAlias)
         throws KeyStoreException
  {
    this(keyStoreFile.getAbsolutePath(), keyStorePIN, keyStoreFormat,
         certificateAlias);
  }



  /**
   * Creates a new instance of this key store key manager that provides the
   * ability to retrieve certificates from the specified key store file.
   *
   * @param  keyStoreFile      The path to the key store file to use.  It must
   *                           not be {@code null}.
   * @param  keyStorePIN       The PIN to use to access the contents of the key
   *                           store.  It may be {@code null} if no PIN is
   *                           required.
   * @param  keyStoreFormat    The format to use for the key store.  It may be
   *                           {@code null} if the default format should be
   *                           used.
   * @param  certificateAlias  The nickname of the certificate that should be
   *                           selected.  It may be {@code null} if any
   *                           acceptable certificate found in the keystore may
   *                           be used.
   *
   * @throws  KeyStoreException  If a problem occurs while initializing this key
   *                             manager.
   */
  public KeyStoreKeyManager(@NotNull final String keyStoreFile,
                            @Nullable final char[] keyStorePIN,
                            @Nullable final String keyStoreFormat,
                            @Nullable final String certificateAlias)
         throws KeyStoreException
  {
    this(keyStoreFile, keyStorePIN, keyStoreFormat, certificateAlias, false);
  }



  /**
   * Creates a new instance of this key store key manager that provides the
   * ability to retrieve certificates from the specified key store file.
   *
   * @param  keyStoreFile      The path to the key store file to use.  It must
   *                           not be {@code null}.
   * @param  keyStorePIN       The PIN to use to access the contents of the key
   *                           store.  It may be {@code null} if no PIN is
   *                           required.
   * @param  keyStoreFormat    The format to use for the key store.  It may be
   *                           {@code null} if the default format should be
   *                           used.
   * @param  certificateAlias  The nickname of the certificate that should be
   *                           selected.  It may be {@code null} if any
   *                           acceptable certificate found in the keystore may
   *                           be used.
   * @param  validateKeyStore  Indicates whether to validate that the provided
   *                           key store is acceptable and can actually be used
   *                           to obtain a valid certificate.  If a certificate
   *                           alias was specified, then this will ensure that
   *                           the key store contains a valid private key entry
   *                           with that alias.  If no certificate alias was
   *                           specified, then this will ensure that the key
   *                           store contains at least one valid private key
   *                           entry.
   *
   * @throws  KeyStoreException  If a problem occurs while initializing this key
   *                             manager, or if validation fails.
   */
  public KeyStoreKeyManager(@NotNull final File keyStoreFile,
                            @Nullable final char[] keyStorePIN,
                            @Nullable final String keyStoreFormat,
                            @Nullable final String certificateAlias,
                            final boolean validateKeyStore)
         throws KeyStoreException
  {
    this(keyStoreFile.getAbsolutePath(), keyStorePIN, keyStoreFormat,
         certificateAlias, validateKeyStore);
  }



  /**
   * Creates a new instance of this key store key manager that provides the
   * ability to retrieve certificates from the specified key store file.
   *
   * @param  keyStoreFile      The path to the key store file to use.  It must
   *                           not be {@code null}.
   * @param  keyStorePIN       The PIN to use to access the contents of the key
   *                           store.  It may be {@code null} if no PIN is
   *                           required.
   * @param  keyStoreFormat    The format to use for the key store.  It may be
   *                           {@code null} if the default format should be
   *                           used.
   * @param  certificateAlias  The nickname of the certificate that should be
   *                           selected.  It may be {@code null} if any
   *                           acceptable certificate found in the keystore may
   *                           be used.
   * @param  validateKeyStore  Indicates whether to validate that the provided
   *                           key store is acceptable and can actually be used
   *                           to obtain a valid certificate.  If a certificate
   *                           alias was specified, then this will ensure that
   *                           the key store contains a valid private key entry
   *                           with that alias.  If no certificate alias was
   *                           specified, then this will ensure that the key
   *                           store contains at least one valid private key
   *                           entry.
   *
   * @throws  KeyStoreException  If a problem occurs while initializing this key
   *                             manager, or if validation fails.
   */
  public KeyStoreKeyManager(@NotNull final String keyStoreFile,
                            @Nullable final char[] keyStorePIN,
                            @Nullable final String keyStoreFormat,
                            @Nullable final String certificateAlias,
                            final boolean validateKeyStore)
         throws KeyStoreException
  {
    super(
         getKeyManagers(keyStoreFile, keyStorePIN, keyStoreFormat,
              certificateAlias, validateKeyStore),
          certificateAlias);

    this.keyStoreFile     = keyStoreFile;

    if (keyStoreFormat == null)
    {
      this.keyStoreFormat = CryptoHelper.getDefaultKeyStoreType();
    }
    else
    {
      this.keyStoreFormat = keyStoreFormat;
    }
  }



  /**
   * Retrieves the set of key managers that will be wrapped by this key manager.
   *
   * @param  keyStoreFile      The path to the key store file to use.  It must
   *                           not be {@code null}.
   * @param  keyStorePIN       The PIN to use to access the contents of the key
   *                           store.  It may be {@code null} if no PIN is
   *                           required.
   * @param  keyStoreFormat    The format to use for the key store.  It may be
   *                           {@code null} if the default format should be
   *                           used.
   * @param  certificateAlias  The nickname of the certificate that should be
   *                           selected.  It may be {@code null} if any
   *                           acceptable certificate found in the keystore may
   *                           be used.
   * @param  validateKeyStore  Indicates whether to validate that the provided
   *                           key store is acceptable and can actually be used
   *                           to obtain a valid certificate.  If a certificate
   *                           alias was specified, then this will ensure that
   *                           the key store contains a valid private key entry
   *                           with that alias.  If no certificate alias was
   *                           specified, then this will ensure that the key
   *                           store contains at least one valid private key
   *                           entry.
   *
   * @return  The set of key managers that will be wrapped by this key manager.
   *
   * @throws  KeyStoreException  If a problem occurs while initializing this key
   *                             manager, or if validation fails.
   */
  @NotNull()
  private static KeyManager[] getKeyManagers(
                                   @NotNull final String keyStoreFile,
                                   @Nullable final char[] keyStorePIN,
                                   @Nullable final String keyStoreFormat,
                                   @Nullable final String certificateAlias,
                                   final boolean validateKeyStore)
          throws KeyStoreException
  {
    Validator.ensureNotNull(keyStoreFile);

    String type = keyStoreFormat;
    if (type == null)
    {
      type = CryptoHelper.getDefaultKeyStoreType();
    }

    final File f = new File(keyStoreFile);
    if (! f.exists())
    {
      throw new KeyStoreException(ERR_KEYSTORE_NO_SUCH_FILE.get(keyStoreFile));
    }

    final KeyStore ks = CryptoHelper.getKeyStore(type);
    FileInputStream inputStream = null;
    try
    {
      inputStream = new FileInputStream(f);
      ks.load(inputStream, keyStorePIN);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new KeyStoreException(
           ERR_KEYSTORE_CANNOT_LOAD.get(keyStoreFile, type, String.valueOf(e)),
           e);
    }
    finally
    {
      if (inputStream != null)
      {
        try
        {
          inputStream.close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }

    if (validateKeyStore)
    {
      validateKeyStore(ks, f, keyStorePIN, certificateAlias);
    }

    try
    {
      final KeyManagerFactory factory = CryptoHelper.getKeyManagerFactory();
      factory.init(ks, keyStorePIN);
      return factory.getKeyManagers();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new KeyStoreException(
           ERR_KEYSTORE_CANNOT_GET_KEY_MANAGERS.get(keyStoreFile,
                keyStoreFormat, StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Validates that the provided key store has an appropriate private key entry
   * in which all certificates in the chain are currently within the validity
   * window.
   *
   * @param  keyStore          The key store to examine.  It must not be
   *                           {@code null}.
   * @param  keyStoreFile      The file that backs the key store.  It must not
   *                           be {@code null}.
   * @param  keyStorePIN       The PIN to use to access the contents of the key
   *                           store.  It may be {@code null} if no PIN is
   *                           required.
   * @param  certificateAlias  The nickname of the certificate that should be
   *                           selected.  It may be {@code null} if any
   *                           acceptable certificate found in the keystore may
   *                           be used.
   *
   * @throws  KeyStoreException  If a validation error was encountered.
   */
  private static void validateKeyStore(@NotNull final KeyStore keyStore,
                                       @NotNull final File keyStoreFile,
                                       @Nullable final char[] keyStorePIN,
                                       @Nullable final String certificateAlias)
          throws KeyStoreException
  {
    final KeyStore.ProtectionParameter protectionParameter;
    if (keyStorePIN == null)
    {
      protectionParameter = null;
    }
    else
    {
      protectionParameter = new KeyStore.PasswordProtection(keyStorePIN);
    }

    try
    {
      if (certificateAlias == null)
      {
        final StringBuilder invalidMessages = new StringBuilder();
        final Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements())
        {
          final String alias = aliases.nextElement();
          if (! keyStore.isKeyEntry(alias))
          {
            continue;
          }

          try
          {
            final KeyStore.PrivateKeyEntry entry =
                 (KeyStore.PrivateKeyEntry)
                 keyStore.getEntry(alias, protectionParameter);
            ensureAllCertificatesInChainAreValid(alias, entry);

            // We found a private key entry in which all certificates in the
            // chain are within their validity window, so we'll assume that
            // it's acceptable.
            return;
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            if (invalidMessages.length() > 0)
            {
              invalidMessages.append("  ");
            }
            invalidMessages.append(e.getMessage());
          }
        }

        if ( invalidMessages.length() > 0)
        {
          // The key store has at least one private key entry, but none of
          // them are currently valid.
          throw new KeyStoreException(
               ERR_KEYSTORE_NO_VALID_PRIVATE_KEY_ENTRIES.get(
                    keyStoreFile.getAbsolutePath(),
                    invalidMessages.toString()));
        }
        else
        {
          // The key store doesn't have any private key entries.
          throw new KeyStoreException(ERR_KEYSTORE_NO_PRIVATE_KEY_ENTRIES.get(
               keyStoreFile.getAbsolutePath()));
        }
      }
      else
      {
        if (! keyStore.containsAlias(certificateAlias))
        {
          throw new KeyStoreException(ERR_KEYSTORE_NO_ENTRY_WITH_ALIAS.get(
               keyStoreFile.getAbsolutePath(), certificateAlias));
        }

        if (! keyStore.isKeyEntry(certificateAlias))
        {
          throw new KeyStoreException(ERR_KEYSTORE_ENTRY_NOT_PRIVATE_KEY.get(
               certificateAlias, keyStoreFile.getAbsolutePath()));
        }

        final KeyStore.PrivateKeyEntry entry =
             (KeyStore.PrivateKeyEntry)
             keyStore.getEntry(certificateAlias, protectionParameter);
        ensureAllCertificatesInChainAreValid(certificateAlias, entry);
      }
    }
    catch (final KeyStoreException e)
    {
      Debug.debugException(e);
      throw e;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new KeyStoreException(
           ERR_KEYSTORE_CANNOT_VALIDATE.get(keyStoreFile.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Ensures that all certificates in the provided private key entry's chain are
   * currently within their validity window.
   *
   * @param  alias  The alias from which the entry was read.  It must not be
   *                {@code null}.
   * @param  entry  The private key entry to examine.  It must not be
   *                {@code null}.
   *
   * @throws  KeyStoreException  If any certificate in the chain is expired or
   *                             not yet valid.
   */
  private static void ensureAllCertificatesInChainAreValid(
                           @NotNull final String alias,
                           @NotNull final KeyStore.PrivateKeyEntry entry)
          throws KeyStoreException
  {
    final Date currentTime = new Date();
    for (final Certificate cert : entry.getCertificateChain())
    {
      if (cert instanceof X509Certificate)
      {
        final X509Certificate c = (X509Certificate) cert;
        if (currentTime.before(c.getNotBefore()))
        {
          throw new KeyStoreException(
               ERR_KEYSTORE_CERT_NOT_YET_VALID.get(alias,
                    c.getSubjectX500Principal().getName(
                         X500Principal.RFC2253),
                    String.valueOf(c.getNotBefore())));
        }
        else if (currentTime.after(c.getNotAfter()))
        {
          throw new KeyStoreException(
               ERR_KEYSTORE_CERT_EXPIRED.get(alias,
                    c.getSubjectX500Principal().getName(
                         X500Principal.RFC2253),
                    String.valueOf(c.getNotAfter())));
        }
      }
    }
  }



  /**
   * Retrieves the path to the key store file to use.
   *
   * @return  The path to the key store file to use.
   */
  @NotNull()
  public String getKeyStoreFile()
  {
    return keyStoreFile;
  }



  /**
   * Retrieves the name of the key store file format.
   *
   * @return  The name of the key store file format.
   */
  @NotNull()
  public String getKeyStoreFormat()
  {
    return keyStoreFormat;
  }
}
