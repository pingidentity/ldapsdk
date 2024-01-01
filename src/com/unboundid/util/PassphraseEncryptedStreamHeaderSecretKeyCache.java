/*
 * Copyright 2023-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2023-2024 Ping Identity Corporation
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
 * Copyright (C) 2023-2024 Ping Identity Corporation
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



import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.SecretKey;



/**
 * This class provides a mechanism for caching secret keys that are associated
 * with passphrase-encrypted stream headers.
 */
final class PassphraseEncryptedStreamHeaderSecretKeyCache
{
  /**
   * The maximum number of passphrase-encrypted stream headers and their
   * associated keys that may be held in the cache.
   */
  private static final int MAX_CACHE_COUNT = 10_000;



  /**
   * The map that acts as the key cache.
   */
  // The map that acts as the key cache.
  @NotNull private static final
       Map<PassphraseEncryptedStreamHeaderCachedKeyIdentifier,SecretKey>
            KEY_MAP = new ConcurrentHashMap<>();



  /**
   * Prevents this utility class from being instantiated.
   */
  private PassphraseEncryptedStreamHeaderSecretKeyCache()
  {
    // No implementation is required.
  }



  /**
   * Retrieves the secret key for the provided identifier, if it is contained in
   * the cache.
   *
   * @param  id  The identifier for the secret key to retrieve.  It must not be
   *             {@code null}.
   *
   * @return  The cached secret key for the specified identifier, or
   *          {@code null} if there is no cached key with the specified
   *          identifier.
   */
  @Nullable()
  static SecretKey get(
       @NotNull final PassphraseEncryptedStreamHeaderCachedKeyIdentifier id)
  {
    return KEY_MAP.get(id);
  }



  /**
   * Stores the provided secret key in the cache.  If the cache is full, then it
   * will be cleared before storing the new key.
   *
   * @param  id         The identifier for the secret key to store in the
   *                    cache.  It must not be {@code null}.
   * @param  secretKey  The secret key to be cached.  It must not be
   *                    {@code null}.
   */
  static void put(
       @NotNull final PassphraseEncryptedStreamHeaderCachedKeyIdentifier id,
       @NotNull final SecretKey secretKey)
  {
    KEY_MAP.put(id, secretKey);

    if (KEY_MAP.size() > MAX_CACHE_COUNT)
    {
      KEY_MAP.clear();
      KEY_MAP.put(id, secretKey);
    }
  }



  /**
   * Removes the key with the specified ID from the cache.
   *
   * @param  id  The identifier for the secret key to remove from the cache.
   *
   * @return  The secret key that was associated with the specified ID, or
   *          {@code null} if no key was cached with the given ID.
   */
  @Nullable()
  static SecretKey remove(
       @NotNull final PassphraseEncryptedStreamHeaderCachedKeyIdentifier id)
  {
    return KEY_MAP.remove(id);
  }



  /**
   * Clears the cache.
   */
  static void clear()
  {
    KEY_MAP.clear();
  }



  /**
   * Retrieves the number of keys currently held in the cache.
   *
   * @return  The number of keys currently held in the cache.
   */
  static int size()
  {
    return KEY_MAP.size();
  }
}
