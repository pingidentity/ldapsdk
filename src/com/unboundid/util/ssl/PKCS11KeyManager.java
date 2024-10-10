/*
 * Copyright 2008-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2024 Ping Identity Corporation
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
 * Copyright (C) 2008-2024 Ping Identity Corporation
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
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.KeyStoreException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
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
 * This class provides an SSL key manager that may be used to interact with
 * PKCS #11 tokens.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PKCS11KeyManager
       extends WrapperKeyManager
{
  /**
   * The default key store type to use when accessing PKCS #11 tokens.
   */
  @NotNull public static final String DEFAULT_KEY_STORE_TYPE = "PKCS11";



  /**
   * The fully-qualified name of the default provider class
   * ({@code sun.security.pkcs11.SunPKCS11}) to use when accessing PKCS #11
   * tokens.
   */
  @NotNull public static final String DEFAULT_PROVIDER_CLASS =
       "sun.security.pkcs11.SunPKCS11";



  /**
   * The provider service type that will be used for key store implementations.
   */
  @NotNull private static final String SERVICE_TYPE_KEY_STORE = "KeyStore";



  /**
   * The name used for the SunJSSE provider.
   */
  @NotNull private static final String SUN_JSSE_PROVIDER_NAME = "SunJSSE";



  /**
   * The JSSE provider that should be used when interacting with PKCS #11
   * tokens.  This may be {@code null} if we can't automatically determine an
   * appropriate provider.
   */
  @Nullable private static final Provider PKCS11_JSSE_PROVIDER;
  static
  {
    // NOTE:  Even when we're operating in FIPS-compliant mode, we will likely
    // want to use the SunJSSE provider in conjunction with PKCS #11 tokens
    // because the Bouncy Castle FIPS-compliant BCJSSE provider does not work
    // well in conjunction with PKCS #11 tokens.
    final Provider sunJSSEProvider =
         Security.getProvider(SUN_JSSE_PROVIDER_NAME);
    if (sunJSSEProvider != null)
    {
      PKCS11_JSSE_PROVIDER = sunJSSEProvider;
    }
    else
    {
      // Select the first provider that offers support for TLSv1.3.  If we
      // can't find one, then select the first provider that offer support for
      // TLSv1.2.
      Provider tls13Provider = null;
      Provider tls12Provider = null;
      for (final Provider provider : Security.getProviders())
      {
        if (provider.getService(SSLUtil.PROVIDER_SERVICE_TYPE_SSL_CONTEXT,
             SSLUtil.SSL_PROTOCOL_TLS_1_3) != null)
        {
          tls13Provider = provider;
          break;
        }
        else if (provider.getService(SSLUtil.PROVIDER_SERVICE_TYPE_SSL_CONTEXT,
             SSLUtil.SSL_PROTOCOL_TLS_1_2) != null)
        {
          tls12Provider = provider;
        }
      }

      if (tls13Provider != null)
      {
        PKCS11_JSSE_PROVIDER = tls13Provider;
      }
      else
      {
        PKCS11_JSSE_PROVIDER = tls12Provider;
      }
    }
  }



  /**
   * Creates a new instance of this PKCS #11 key manager with the provided
   * information.
   *
   * @param  keyStorePIN        The user PIN to use to access the PKCS #11
   *                            token.  This may be {@code null} if no PIN is
   *                            required.
   * @param  certificateAlias   The nickname for the key entry to use in the
   *                            PKCS #11 token.  It may be {@code null} if any
   *                            acceptable entry may be used.
   *
   * @throws  KeyStoreException  If a problem occurs while initializing this key
   *                             manager.
   */
  public PKCS11KeyManager(@Nullable final char[] keyStorePIN,
                          @Nullable final String certificateAlias)
         throws KeyStoreException
  {
    this(getProvider(null, null, null, false), null, keyStorePIN,
         certificateAlias);
  }



  /**
   * Creates a new instance of this PKCS11 key manager with the provided
   * information.
   *
   * @param  providerClassName   The fully-qualified name of the Java class that
   *                             implements the provider to use to interact with
   *                             the PKCS #11 module.  If this is {@code null},
   *                             then the key manager will attempt to
   *                             automatically identify the appropriate
   *                             provider.
   * @param  providerConfigFile  A file that contains the configuration to use
   *                             for the provider.  This may be {@code null} if
   *                             no provider configuration is needed, or if the
   *                             provider is already properly instantiated.
   * @param  keyStoreType        The name of the key store type to use when
   *                             interacting with the PKCS #11 token.  If this
   *                             is {@code null}, then a default key store type
   *                             of {@code PKCS11} will be used.
   * @param  keyStorePIN         The user PIN to use to access the PKCS #11
   *                             token.  This may be {@code null} if no PIN is
   *                             required.
   * @param  certificateAlias    The nickname for the key entry to use in the
   *                             PKCS #11 token.  It may be {@code null} if any
   *                             acceptable entry may be used.
   *
   * @throws  KeyStoreException  If a problem occurs while initializing this
   *                             key manager.
   */
  public PKCS11KeyManager(@Nullable final String providerClassName,
                          @Nullable final File providerConfigFile,
                          @Nullable final String keyStoreType,
                          @Nullable final char[] keyStorePIN,
                          @Nullable final String certificateAlias)
         throws KeyStoreException
  {
    this(getProvider(providerClassName, providerConfigFile, keyStoreType,
              false),
         keyStoreType, keyStorePIN, certificateAlias);
  }



  /**
   * Creates a new instance of this PKCS11 key manager with the provided
   * information.
   *
   * @param  provider            The Java security provider to use to access the
   *                             PKCS #11 token.  It must not be {@code null}.
   * @param  keyStoreType        The name of the key store type to use when
   *                             interacting with the PKCS #11 token.  If this
   *                             is {@code null}, then a default key store type
   *                             of {@code PKCS11} will be used.
   * @param  keyStorePIN         The user PIN to use to access the PKCS #11
   *                             token.  This may be {@code null} if no PIN is
   *                             required.
   * @param  certificateAlias    The nickname for the key entry to use in the
   *                             PKCS #11 token.  It may be {@code null} if any
   *                             acceptable entry may be used.
   *
   * @throws  KeyStoreException  If a problem occurs while initializing this
   *                             key manager.
   */
  public PKCS11KeyManager(@NotNull final Provider provider,
                          @Nullable final String keyStoreType,
                          @Nullable final char[] keyStorePIN,
                          @Nullable final String certificateAlias)
         throws KeyStoreException
  {
    super(getKeyManagers(provider, keyStoreType, keyStorePIN),
         certificateAlias);
  }



  /**
   * Retrieves an instance of a Java security provider that may be used to
   * interact with a PKCS #11 token.  If a suitable new provider instance is
   * created, then it will be added to the JVM's configured list of providers.
   *
   * @param  providerClassName        The fully-qualified name of the Java class
   *                                  to use for the provider.  If this is
   *                                  {@code null}, then an attempt will be made
   *                                  to automatically identify the appropriate
   *                                  provider class.
   * @param  providerConfigFile       A file that contains the configuration to
   *                                  use for the provider.  This may be
   *                                  {@code null} if no provider configuration
   *                                  is needed, or if the provider is already
   *                                  properly instantiated.
   * @param  keyStoreType             The name of the key store type to use when
   *                                  interacting with the PKCS #11 token.  If
   *                                  this is {@code null}, then a default key
   *                                  store type of {@code PKCS11} will be used.
   * @param  alwaysCreateNewInstance  Indicates whether to always create a new
   *                                  instance of the provider, even
   *
   * @return  The provider instance that should be used to interact with a
   *          PKCS #11 token.
   *
   * @throws  KeyStoreException  If a problem occurs while retrieving the
   */
  @NotNull()
  public static Provider getProvider(@Nullable final String providerClassName,
                                     @Nullable final File providerConfigFile,
                                     @Nullable final String keyStoreType,
                                     final boolean alwaysCreateNewInstance)
         throws KeyStoreException
  {
    final String ksType;
    if (keyStoreType == null)
    {
      ksType = DEFAULT_KEY_STORE_TYPE;
    }
    else
    {
      ksType = keyStoreType;
    }


    // If no provider class was specified, then try to automatically determine
    // the provider class to use.  Otherwise, try to load the provider class.
    final Class<?> providerClass;
    final Provider[] providers = Security.getProviders();
    if (providerClassName == null)
    {
      providerClass = inferProviderClass(providers, ksType);
    }
    else
    {
      try
      {
        providerClass = Class.forName(providerClassName);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new KeyStoreException(
             ERR_PCKS11_NO_SUCH_PROVIDER_CLASS.get(providerClassName,
                  StaticUtils.getExceptionMessage(e)), e);
      }
    }


    // See if any of the already defined providers has the identified class.  If
    // there is already a provider of that type loaded, and if it advertises
    // support for the desired key store type, and if we either don't have a
    // configuration file or don't need to always create a new instance, then
    // just use the existing provider.
    //
    // don't need to always
    // create a new instance, then just use the existing provider.
    Provider provider = null;
    for (final Provider p : providers)
    {
      if (p.getClass().getName().equals(providerClass.getName()))
      {
        provider = p;
        if ((p.getService(SERVICE_TYPE_KEY_STORE, ksType) != null) &&
             ((providerConfigFile == null) || (! alwaysCreateNewInstance)))
        {
          return p;
        }
        break;
      }
    }


    // At this point, we know that we're going to need to create a new instance
    // of the provider.  Get the default constructor for the provider class, if
    // there is one.
    Constructor<?> defaultConstructor = null;
    try
    {
      defaultConstructor = providerClass.getConstructor();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }


    // If we don't have a configuration file, then there must be a default
    // constructor.  Invoke it to create the provider, and make sure that it
    // advertises support for the target key store type.
    if (providerConfigFile == null)
    {
      if (defaultConstructor == null)
      {
        throw new KeyStoreException(
             ERR_PKCS11_NO_DEFAULT_CONSTRUCTOR_NO_CONFIG.get(
                  providerClass.getName(), ksType));
      }

      try
      {
        provider = (Provider) defaultConstructor.newInstance();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new KeyStoreException(
             ERR_PKCS11_CANNOT_INVOKE_DEFAULT_CONSTRUCTOR.get(
                  providerClass.getName(), ksType,
                  StaticUtils.getExceptionMessage(e)),
             e);
      }

      if (provider.getService(SERVICE_TYPE_KEY_STORE, ksType) == null)
      {
        throw new KeyStoreException(
             ERR_PKCS11_DEFAULT_CONSTRUCTOR_NO_KS_TYPE.get(
                  providerClass.getName(), ksType));
      }
      else
      {
        Security.addProvider(provider);
        return provider;
      }
    }


    // We know that we need to configure the provider.  If the provider offers
    // a public configure(String) method, then use it to accomplish that.
    if (defaultConstructor != null)
    {
      Method configureMethod = null;
      try
      {
        configureMethod = providerClass.getMethod("configure", String.class);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }

      if (configureMethod != null)
      {
        if (provider == null)
        {
          try
          {
            provider = (Provider) defaultConstructor.newInstance();
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new KeyStoreException(
                 ERR_PKCS11_CANNOT_INVOKE_DEFAULT_CONSTRUCTOR.get(
                      providerClass.getName(), ksType,
                      StaticUtils.getExceptionMessage(e)),
                 e);
          }
        }

        final Provider configuredProvider;
        try
        {
          configuredProvider = (Provider) configureMethod.invoke(provider,
               providerConfigFile.getAbsolutePath());
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new KeyStoreException(
               ERR_PKCS11_CANNOT_CONFIGURE_PROVIDER.get(
                    providerClass.getName(),
                    providerConfigFile.getAbsolutePath(),
                    StaticUtils.getExceptionMessage(e)),
               e);
        }

        if (configuredProvider.getService(SERVICE_TYPE_KEY_STORE, ksType) ==
             null)
        {
          throw new KeyStoreException(
               ERR_PKCS11_CONFIGURED_PROVIDER_NO_KS_TYPE.get(
                    providerClass.getName(), ksType,
                    providerConfigFile.getAbsolutePath()));
        }
        else
        {
          Security.addProvider(configuredProvider);
          return configuredProvider;
        }
      }
    }


    // If we've gotten here, then our last hope is that there's a public
    // constructor that takes a single String argument.  If there is, then
    // invoke it with the path to the configuration file to create the provider.
    final Constructor<?> stringConstructor;
    try
    {
      stringConstructor = providerClass.getConstructor(String.class);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new KeyStoreException(
           ERR_PKCS11_NO_STRING_CONSTRUCTOR.get(providerClass.getName(),
                providerConfigFile.getAbsolutePath(), ksType),
           e);
    }

    final Provider configuredProvider;
    try
    {
      configuredProvider = (Provider) stringConstructor.newInstance(
           providerConfigFile.getAbsolutePath());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new KeyStoreException(
           ERR_PKCS11_CANNOT_INVOKE_STRING_CONSTRUCTOR.get(
                providerClass.getName(), providerConfigFile.getAbsolutePath(),
                ksType, StaticUtils.getExceptionMessage(e)),
           e);
    }


    // Make sure that the configured provider advertises support for the
    // key store type.
    if (configuredProvider.getService(SERVICE_TYPE_KEY_STORE, ksType) == null)
    {
      throw new KeyStoreException(
           ERR_PKCS11_CONFIGURED_PROVIDER_NO_KS_TYPE.get(
                providerClass.getName(), ksType,
                providerConfigFile.getAbsolutePath()));
    }
    else
    {
      Security.addProvider(configuredProvider);
      return configuredProvider;
    }
  }



  /**
   * Attempts to infer the class for the PKCS #11 provider to use.
   *
   * @param  providers     The set of providers that have already been loaded in
   *                       the JVM.  This must not be {@code null}.
   * @param  keyStoreType  The name of the key store type to use when
   *                       interacting with the PKCS #11 token.  This must not
   *                       be {@code null}.
   *
   * @return  The class to use for the PKCS #11 provider.
   *
   * @throws  KeyStoreException  If no suitable class can be identified.
   */
  @NotNull()
  private static Class<?> inferProviderClass(
               @NotNull final Provider[] providers,
               @NotNull final String keyStoreType)
          throws KeyStoreException
  {
    // First, see if there is already a provider defined in the JVM that already
    // advertises support for the specified key store type.
    for (final Provider p : providers)
    {
      if (p.getService(SERVICE_TYPE_KEY_STORE, keyStoreType) != null)
      {
        return p.getClass();
      }
    }


    // See if there is already a provider defined in the JVM whose provider or
    // class name contains the string "PKCS11".
    for (final Provider p : providers)
    {
      final Class<?> providerClass = p.getClass();
      if (StaticUtils.toUpperCase(p.getName()).contains("PKCS11") ||
           StaticUtils.toUpperCase(providerClass.getName()).contains("PKCS11"))
      {
        return providerClass;
      }
    }


    // We couldn't find an existing provider that looks like it might support
    // PKCS #11, so try to use the default provider class.
    try
    {
      return Class.forName(DEFAULT_PROVIDER_CLASS);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new KeyStoreException(
           ERR_PKCS11_CANNOT_INFER_PROVIDER_CLASS.get(
                DEFAULT_PROVIDER_CLASS),
           e);
    }
  }



  /**
   * Retrieves the set of key managers that will be wrapped by this key manager.
   *
   * @param  provider      The Java security provider to use to access the PKCS
   *                       #11 token.  It must not be {@code null}.
   * @param  keyStoreType  The name of the key store type to use when
   *                       interacting with the PKCS #11 token.  If this is
   *                       {@code null}, then a default key store type of
   *                       {@code PKCS11} will be used.
   * @param  keyStorePIN   The user PIN to use to access the PKCS #11 token.
   *                       This may be {@code null} if no PIN is required.
   *
   * @return  The set of key managers that will be wrapped by this key manager.
   *
   * @throws  KeyStoreException  If a problem occurs while initializing this key
   *                             manager.
   */
  @NotNull()
  private static KeyManager[] getKeyManagers(
               @NotNull final Provider provider,
               @Nullable final String keyStoreType,
               @Nullable final char[] keyStorePIN)
          throws KeyStoreException
  {
    final String ksType;
    if (keyStoreType == null)
    {
      ksType = DEFAULT_KEY_STORE_TYPE;
    }
    else
    {
      ksType = keyStoreType;
    }

    final KeyStore ks = CryptoHelper.getKeyStore(ksType, provider);
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



  /**
   * Retrieves an instance of a Java security provider that should be used when
   * performing JSSE-related operations in conjunction with PKCS #11 tokens.
   * The JVM's preferred JSSE provider may not be the best choice when using a
   * PKCS #11 token (including when operating in FIPS-compliant mode).
   *
   * @return  An instance of a Java security provider that should be used when
   *          performing JSSE-related operations in conjunction with PKCS #11
   *          tokens.  It may be {@code null} if the best provider cannot be
   *          determined.
   */
  @Nullable()
  public static Provider getPKCS11JSSESProvider()
  {
    return PKCS11_JSSE_PROVIDER;
  }
}
