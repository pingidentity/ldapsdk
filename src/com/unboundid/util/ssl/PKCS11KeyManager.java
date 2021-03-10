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



import java.security.KeyStoreException;
import java.security.KeyStore;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;

import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.SSLMessages.*;



/**
 * This class provides an SSL key manager that may be used to retrieve
 * certificates from a PKCS#11 token.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PKCS11KeyManager
       extends WrapperKeyManager
{
  /**
   * The key store type to use to access PKCS#11 tokens.
   */
  @NotNull private static final String PKCS11_KEY_STORE_TYPE = "PKCS11";



  /**
   * Creates a new instance of this PKCS11 key manager that provides the ability
   * to retrieve certificates from a PKCS#11 token.
   *
   * @param  keyStorePIN       The PIN to use to access the contents of the
   *                           PKCS#11 token.  It may be {@code null} if no PIN
   *                           is required.
   * @param  certificateAlias  The nickname of the certificate that should be
   *                           selected.  It may be {@code null} if any
   *                           acceptable certificate found may be used.
   *
   * @throws  KeyStoreException  If a problem occurs while initializing this key
   *                             manager.
   */
  public PKCS11KeyManager(@Nullable final char[] keyStorePIN,
                          @Nullable final String certificateAlias)
         throws KeyStoreException
  {
    super(getKeyManagers(keyStorePIN), certificateAlias);
  }



  /**
   * Retrieves the set of key managers that will be wrapped by this key manager.
   *
   * @param  keyStorePIN  The PIN to use to access the contents of the PKCS#11
   *                      token.  It may be {@code null} if no PIN is required.
   *
   * @return  The set of key managers that will be wrapped by this key manager.
   *
   * @throws  KeyStoreException  If a problem occurs while initializing this key
   *                             manager.
   */
  @NotNull()
  private static KeyManager[] getKeyManagers(@Nullable final char[] keyStorePIN)
          throws KeyStoreException
  {
    final KeyStore ks = CryptoHelper.getKeyStore(PKCS11_KEY_STORE_TYPE);
    try
    {
      ks.load(null, keyStorePIN);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new KeyStoreException(
           ERR_PKCS11_CANNOT_ACCESS.get(StaticUtils.getExceptionMessage(e)), e);
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
           ERR_PKCS11_CANNOT_GET_KEY_MANAGERS.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }
}
