/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;

import com.unboundid.util.NotMutable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Debug.*;
import static com.unboundid.util.Validator.*;
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
  private final String keyStoreFile;

  // The format to use for the key store file.
  private final String keyStoreFormat;



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
  public KeyStoreKeyManager(final File keyStoreFile, final char[] keyStorePIN)
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
  public KeyStoreKeyManager(final String keyStoreFile, final char[] keyStorePIN)
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
  public KeyStoreKeyManager(final File keyStoreFile, final char[] keyStorePIN,
                            final String keyStoreFormat,
                            final String certificateAlias)
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
  public KeyStoreKeyManager(final String keyStoreFile, final char[] keyStorePIN,
                            final String keyStoreFormat,
                            final String certificateAlias)
         throws KeyStoreException
  {
    super(getKeyManagers(keyStoreFile, keyStorePIN, keyStoreFormat),
          certificateAlias);

    this.keyStoreFile     = keyStoreFile;

    if (keyStoreFormat == null)
    {
      this.keyStoreFormat = KeyStore.getDefaultType();
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
   *
   * @return  The set of key managers that will be wrapped by this key manager.
   *
   * @throws  KeyStoreException  If a problem occurs while initializing this key
   *                             manager.
   */
  private static KeyManager[] getKeyManagers(final String keyStoreFile,
                                             final char[] keyStorePIN,
                                             final String keyStoreFormat)
          throws KeyStoreException
  {
    ensureNotNull(keyStoreFile);

    String type = keyStoreFormat;
    if (type == null)
    {
      type = KeyStore.getDefaultType();
    }

    final File f = new File(keyStoreFile);
    if (! f.exists())
    {
      throw new KeyStoreException(ERR_KEYSTORE_NO_SUCH_FILE.get(keyStoreFile));
    }

    final KeyStore ks = KeyStore.getInstance(type);
    FileInputStream inputStream = null;
    try
    {
      inputStream = new FileInputStream(f);
      ks.load(inputStream, keyStorePIN);
    }
    catch (final Exception e)
    {
      debugException(e);

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
          debugException(e);
        }
      }
    }

    try
    {
      final KeyManagerFactory factory = KeyManagerFactory.getInstance(
           KeyManagerFactory.getDefaultAlgorithm());
      factory.init(ks, keyStorePIN);
      return factory.getKeyManagers();
    }
    catch (final Exception e)
    {
      debugException(e);

      throw new KeyStoreException(
           ERR_KEYSTORE_CANNOT_GET_KEY_MANAGERS.get(keyStoreFile,
                keyStoreFormat, StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the path to the key store file to use.
   *
   * @return  The path to the key store file to use.
   */
  public String getKeyStoreFile()
  {
    return keyStoreFile;
  }



  /**
   * Retrieves the name of the key store file format.
   *
   * @return  The name of the key store file format.
   */
  public String getKeyStoreFormat()
  {
    return keyStoreFormat;
  }
}
