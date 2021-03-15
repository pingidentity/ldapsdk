/*
 * Copyright 2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021 Ping Identity Corporation
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
 * Copyright (C) 2021 Ping Identity Corporation
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



import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.concurrent.atomic.AtomicReference;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a helper to ensure that the Bouncy Castle FIPS provider
 * is properly loaded into the JVM so that the provider can be used for
 * cryptographic processing.  The appropriate jar file (typically
 * "bc-fips-{version}.jar") must be available in the JVM classpath.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class BouncyCastleFIPSHelper
{
  /**
   * A reference to the Bouncy Castle FIPS provider, if one is available.
   */
  @NotNull private static final AtomicReference<Provider>
       BOUNCY_CASTLE_FIPS_PROVIDER = new AtomicReference<>();



  /**
   * A reference to the Bouncy Castle JSSE provider, if one is available.
   */
  @NotNull private static final AtomicReference<Provider>
       BOUNCY_CASTLE_JSSE_PROVIDER = new AtomicReference<>();



  /**
   * The fully qualified name of the Java class that should be used as the
   * Bouncy Castle FIPS provider.
   */
  @NotNull private static final String BOUNCY_CASTLE_FIPS_PROVIDER_CLASS_NAME =
       "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider";



  /**
   * The fully qualified name of the Java class that should be used as the
   * Bouncy Castle JSSE provider.
   */
  @NotNull private static final String BOUNCY_CASTLE_JSSE_PROVIDER_CLASS_NAME =
       "org.bouncycastle.jsse.provider.BouncyCastleJsseProvider";



  /**
   * The name that may be used to reference the Bouncy Castle FIPS provider.
   */
  @NotNull public static final String FIPS_PROVIDER_NAME = "BCFIPS";



  /**
   * The name that may be used to reference the Bouncy Castle JSSE provider.
   */
  @NotNull public static final String JSSE_PROVIDER_NAME = "BCJSSE";



  /**
   * The key store type name that should be used to reference the Bouncy Castle
   * FIPS key store.
   */
  @NotNull public static final String FIPS_KEY_STORE_TYPE = "BCFKS";



  /**
   * The name of the default key manager factory algorithm that should be used
   * with the Bouncy Castle JSSE provider.
   */
  @NotNull public static final String DEFAULT_KEY_MANAGER_FACTORY_ALGORITHM =
       "X.509";



  /**
   * The name of the SSLContext protocol that should be used when requesting
   * the default context from the Bouncy Castle JSSE provider.
   */
  @NotNull public static final String DEFAULT_SSL_CONTEXT_PROTOCOL = "DEFAULT";



  /**
   * The name of the default key manager factory algorithm that should be used
   * with the Bouncy Castle JSSE provider.
   */
  @NotNull public static final String DEFAULT_TRUST_MANAGER_FACTORY_ALGORITHM =
       "PKIX";



  /**
   * Prevents this utility class from being instantiated.
   */
  private BouncyCastleFIPSHelper()
  {
    // No implementation required.
  }



  /**
   * Retrieves a reference to the the Bouncy Castle FIPS provider.
   *
   * @return   The Bouncy Castle FIPS provider instance.  It will not be
   *           {@code null}.
   *
   * @throws  NoSuchProviderException  If the Bouncy Castle FIPS provider is
   *                                   not available in the JVM.
   */
  @NotNull()
  public static Provider getBouncyCastleFIPSProvider()
         throws NoSuchProviderException
  {
    final Provider provider = BOUNCY_CASTLE_FIPS_PROVIDER.get();
    if (provider == null)
    {
      return loadBouncyCastleFIPSProvider(false);
    }
    else
    {
      return provider;
    }
  }



  /**
   * Loads the Bouncy Castle FIPS provider into the JVM, if it has not already
   * been loaded.
   *
   * @param  makeDefault  Indicates whether to make the Bouncy Castle FIPS
   *                      provider the default provider in the JVM.
   *
   * @return  The provider that was loaded.  It will not be {@code null}.
   *
   * @throws  NoSuchProviderException  If the Bouncy Castle FIPS provider is
   *                                   not available in the JVM.
   */
  @NotNull()
  static synchronized Provider loadBouncyCastleFIPSProvider(
                                    final boolean makeDefault)
          throws NoSuchProviderException
  {
    // If the provider class has already been loaded through some means, then
    // just return it.
    try
    {
      final Provider existingProvider =
           Security.getProvider(FIPS_PROVIDER_NAME);
      if (existingProvider != null)
      {
        BOUNCY_CASTLE_FIPS_PROVIDER.compareAndSet(null, existingProvider);
        return existingProvider;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }


    // Load the provider class.  If this fails, then the Bouncy Castle FIPS
    // provider is not in the classpath.
    final Class<?> providerClass;
    try
    {
      providerClass = Class.forName(BOUNCY_CASTLE_FIPS_PROVIDER_CLASS_NAME);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new NoSuchProviderException(
           ERR_BC_FIPS_HELPER_CANNOT_LOAD_FIPS_PROVIDER_CLASS.get(
                BOUNCY_CASTLE_FIPS_PROVIDER_CLASS_NAME,
                StaticUtils.getExceptionMessage(e)));
    }


    // Instantiate the provider class.
    final Provider provider;
    try
    {
      provider = (Provider) providerClass.newInstance();

      if (makeDefault)
      {
        Security.insertProviderAt(provider, 1);
      }
      else
      {
        Security.addProvider(provider);
      }

      BOUNCY_CASTLE_FIPS_PROVIDER.set(provider);
      return provider;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new NoSuchProviderException(
           ERR_BC_FIPS_PROVIDER_CANNOT_INSTANTIATE_FIPS_PROVIDER.get(
                BOUNCY_CASTLE_FIPS_PROVIDER_CLASS_NAME,
                StaticUtils.getExceptionMessage(e)));
    }
  }



  /**
   * Retrieves a reference to the the Bouncy Castle JSSE provider.
   *
   * @return   The Bouncy Castle JSSE provider instance.  It will not be
   *           {@code null}.
   *
   * @throws  NoSuchProviderException  If the Bouncy Castle JSSE provider is
   *                                   not available in the JVM.
   */
  @NotNull()
  public static Provider getBouncyCastleJSSEProvider()
         throws NoSuchProviderException
  {
    final Provider provider = BOUNCY_CASTLE_JSSE_PROVIDER.get();
    if (provider == null)
    {
      return loadBouncyCastleJSSEProvider(false);
    }
    else
    {
      return provider;
    }
  }



  /**
   * Loads the Bouncy Castle JSSE provider into the JVM, if it has not already
   * been loaded.
   *
   * @param  makeSecond  Indicates whether to make the Bouncy Castle JSSE
   *                     provider second in the JVM's search order (presumably
   *                     after the Bouncy Castle FIPS provider as the first
   *                     provider, in which case the Bouncy Castle FIPS provider
   *                     must have already been loaded and made first).
   *
   * @return  The provider that was loaded.  It will not be {@code null}.
   *
   * @throws  NoSuchProviderException  If the Bouncy Castle JSSE provider is
   *                                   not available in the JVM.
   */
  @NotNull()
  static synchronized Provider loadBouncyCastleJSSEProvider(
                                    final boolean makeSecond)
          throws NoSuchProviderException
  {
    // If the provider class has already been loaded through some means, then
    // just return it.
    try
    {
      final Provider existingProvider =
           Security.getProvider(JSSE_PROVIDER_NAME);
      if (existingProvider != null)
      {
        BOUNCY_CASTLE_JSSE_PROVIDER.compareAndSet(null, existingProvider);
        return existingProvider;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }


    // Load the provider class.  If this fails, then the Bouncy Castle JSSE
    // provider is not in the classpath.
    final Class<?> providerClass;
    try
    {
      providerClass = Class.forName(BOUNCY_CASTLE_JSSE_PROVIDER_CLASS_NAME);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new NoSuchProviderException(
           ERR_BC_FIPS_HELPER_CANNOT_LOAD_JSSE_PROVIDER_CLASS.get(
                BOUNCY_CASTLE_JSSE_PROVIDER_CLASS_NAME,
                StaticUtils.getExceptionMessage(e)));
    }


    // Instantiate the provider class.
    final Provider provider;
    try
    {
      provider = (Provider) providerClass.newInstance();

      if (makeSecond)
      {
        Security.insertProviderAt(provider, 2);
      }
      else
      {
        Security.addProvider(provider);
      }

      BOUNCY_CASTLE_JSSE_PROVIDER.set(provider);
      return provider;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new NoSuchProviderException(
           ERR_BC_FIPS_PROVIDER_CANNOT_INSTANTIATE_JSSE_PROVIDER.get(
                BOUNCY_CASTLE_JSSE_PROVIDER_CLASS_NAME,
                StaticUtils.getExceptionMessage(e)));
    }
  }
}
