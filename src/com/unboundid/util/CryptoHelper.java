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



import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPRuntimeException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.ssl.TLSCipherSuiteSelector;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a set of utility methods for performing cryptographic
 * processing.  The LDAP SDK should only use methods in this class to perform
 * cryptographic processing, and should not use the corresponding Java
 * cryptographic methods directly.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CryptoHelper
{
  /**
   * The name of the Java property (com.unboundid.crypto.FIPS_MODE) that will be
   * used to indicate that the LDAP SDK should operate in FIPS 140-2-compliant
   * mode.  If this property is defined, then it must have a value of either
   * "true" or "false".  If the {@link #PROPERTY_FIPS_PROVIDER} property is also
   * defined, then the specified provider will be used; otherwise, the Bouncy
   * Castle "BCFIPS" provider will be assumed.
   */
  @NotNull public static final String PROPERTY_FIPS_MODE =
       "com.unboundid.crypto.FIPS_MODE";



  /**
   * The name of the Java property (com.unboundid.crypto.FIPS_PROVIDER) that
   * will be used to specify the name of the security provider to use when
   * operating in FIPS 140-2-compliant mode.  At present, only the Bouncy Castle
   * "BCFIPS" provider is supported.
   */
  @NotNull public static final String PROPERTY_FIPS_PROVIDER =
       "com.unboundid.crypto.FIPS_PROVIDER";



  /**
   * The name of the Java property
   * (com.unboundid.crypto.REMOVE_NON_ESSENTIAL_PROVIDERS) that will be used to
   * indicate that the LDAP SDK should update the JVM to remove providers that
   * are not believed to be necessary in FIPS 104-2-compliant mode.  This
   * property will only have any effect if the {@link #PROPERTY_FIPS_MODE}
   * property is set to true.  Also note that this property assumes the use of
   * an Oracle or OpenJDK-based JVM, and may not work as expected in JVMs from
   * other vendors that may have different essential providers.  If this
   * property is defined, then it must have a value of either "true" or "false".
   */
  @NotNull public static final String PROPERTY_REMOVE_NON_NECESSARY_PROVIDERS =
       "com.unboundid.crypto.REMOVE_NON_ESSENTIAL_PROVIDERS";



  /**
   * The set of essential providers that will be preserved when pruning
   * non-essential providers.  Note that this assumes the use of an Oracle or
   * OpenJDK-based JVM.  JVMs from other vendors may use different provider
   * classes.
   */
  @NotNull private static final Set<String> ESSENTIAL_PROVIDERS_TO_PRESERVE =
       StaticUtils.setOf(
            BouncyCastleFIPSHelper.BOUNCY_CASTLE_FIPS_PROVIDER_CLASS_NAME,
            BouncyCastleFIPSHelper.BOUNCY_CASTLE_JSSE_PROVIDER_CLASS_NAME,

            "com.sun.net.ssl.internal.ssl.Provider",
            "sun.security.provider.Sun",
            "sun.security.jgss.SunProvider",
            "com.sun.security.sasl.Provider",
            "sun.security.provider.certpath.ldap.JdkLDAP",
            "com.sun.security.sasl.gsskerb.JdkSASL",
            "sun.security.pkcs11.SunPKCS11",

            "com.ibm.security.jgss.IBMJGSSProvider",
            "com.ibm.security.sasl.IBMSASL");



  /**
   * Indicates whether the LDAP SDK should operate in FIPS 140-2-compliant mode.
   */
  @NotNull private static final AtomicBoolean FIPS_MODE;
  @NotNull private static final AtomicReference<Provider> FIPS_PROVIDER =
       new AtomicReference<>();
  @NotNull private static final AtomicReference<Provider>
       FIPS_JSSE_PROVIDER = new AtomicReference<>();
  @NotNull private static final AtomicReference<String>
       FIPS_DEFAULT_KEY_MANAGER_FACTORY_ALGORITHM = new AtomicReference<>();
  @NotNull private static final AtomicReference<String>
       FIPS_DEFAULT_KEY_STORE_TYPE = new AtomicReference<>();
  @NotNull private static final AtomicReference<String>
       FIPS_DEFAULT_SSL_CONTEXT_PROTOCOL = new AtomicReference<>();
  @NotNull private static final AtomicReference<String>
       FIPS_DEFAULT_TRUST_MANAGER_FACTORY_ALGORITHM = new AtomicReference<>();
  static
  {
    final String fipsModePropertyValue =
         StaticUtils.getSystemProperty(PROPERTY_FIPS_MODE);
    if (fipsModePropertyValue == null)
    {
      FIPS_MODE = new AtomicBoolean(false);
    }
    else if (fipsModePropertyValue.equalsIgnoreCase("true"))
    {
      final String fipsProviderPropertyValue =
           StaticUtils.getSystemProperty(PROPERTY_FIPS_PROVIDER);
      if ((fipsProviderPropertyValue != null) &&
           (! fipsProviderPropertyValue.equalsIgnoreCase(
                BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME)))
      {
        Validator.violation(
             ERR_CRYPTO_HELPER_UNSUPPORTED_FIPS_PROVIDER.get(
                  fipsProviderPropertyValue,
                  BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME));
      }

      FIPS_MODE = new AtomicBoolean(true);
      try
      {
        FIPS_PROVIDER.set(
             BouncyCastleFIPSHelper.loadBouncyCastleFIPSProvider(true));
        FIPS_JSSE_PROVIDER.set(
             BouncyCastleFIPSHelper.loadBouncyCastleJSSEProvider(true));
        FIPS_DEFAULT_KEY_MANAGER_FACTORY_ALGORITHM.set(
             BouncyCastleFIPSHelper.DEFAULT_KEY_MANAGER_FACTORY_ALGORITHM);
        FIPS_DEFAULT_KEY_STORE_TYPE.set(
             BouncyCastleFIPSHelper.FIPS_KEY_STORE_TYPE);
        FIPS_DEFAULT_SSL_CONTEXT_PROTOCOL.set(
             BouncyCastleFIPSHelper.DEFAULT_SSL_CONTEXT_PROTOCOL);
        FIPS_DEFAULT_TRUST_MANAGER_FACTORY_ALGORITHM.set(
             BouncyCastleFIPSHelper.DEFAULT_TRUST_MANAGER_FACTORY_ALGORITHM);

        final String prunePropertyValue = StaticUtils.getSystemProperty(
             PROPERTY_REMOVE_NON_NECESSARY_PROVIDERS);
        if (prunePropertyValue != null)
        {
          if (prunePropertyValue.equalsIgnoreCase("true"))
          {
            removeNonEssentialSecurityProviders();
          }
          else if (! prunePropertyValue.equalsIgnoreCase("false"))
          {
            Validator.violation(
                 ERR_CRYPTO_HELPER_INVALID_FIPS_MODE_PROPERTY_VALUE.get(
                      PROPERTY_REMOVE_NON_NECESSARY_PROVIDERS,
                      prunePropertyValue));
          }
        }

        TLSCipherSuiteSelector.recompute();
      }
      catch (final Exception e)
      {
        Validator.violation(
             ERR_CRYPTO_HELPER_INSTANTIATION_ERROR_FROM_FIPS_MODE_PROPERTY.get(
                  PROPERTY_FIPS_MODE, StaticUtils.getExceptionMessage(e)),
             e);
        FIPS_MODE.set(false);
      }
    }
    else if (fipsModePropertyValue.equalsIgnoreCase("false"))
    {
      FIPS_MODE = new AtomicBoolean(false);
    }
    else
    {
      FIPS_MODE = new AtomicBoolean(false);
      Validator.violation(
           ERR_CRYPTO_HELPER_INVALID_FIPS_MODE_PROPERTY_VALUE.get(
                PROPERTY_FIPS_MODE, fipsModePropertyValue));
    }
  }



  /**
   * The key store type value that should be used for BCFKS (Bouncy Castle
   * FIPS 140-2-compliant) key stores.
   */
  @NotNull public static final String KEY_STORE_TYPE_BCFKS =
       BouncyCastleFIPSHelper.FIPS_KEY_STORE_TYPE;



  /**
   * The key store type value that should be used for JKS key stores.
   */
  @NotNull public static final String KEY_STORE_TYPE_JKS = "JKS";



  /**
   * The key store type value that should be used for PKCS #11 key stores.
   */
  @NotNull public static final String KEY_STORE_TYPE_PKCS_11 = "PKCS11";



  /**
   * The key store type value that should be used for PKCS #12 key stores.
   */
  @NotNull public static final String KEY_STORE_TYPE_PKCS_12 = "PKCS12";



  /**
   * The name of the Java system property that can be used to override the
   * default key store type that will be used by the LDAP SDK.  If this is not
   * specified, then the default key store type will be BCFKS in FIPS-compliant
   * mode, or the JVM's default key store type in non-FIPS mode.
   */
  @NotNull public static final String PROPERTY_DEFAULT_KEY_STORE_TYPE =
       "com.unboundid.crypto.DEFAULT_KEY_STORE_TYPE";



  /**
   * The default key store type that should be used.
   */
  @NotNull private static final AtomicReference<String> DEFAULT_KEY_STORE_TYPE;
  static
  {
    final String defaultKeyStoreType;
    final String propertyValue =
         StaticUtils.getSystemProperty(PROPERTY_DEFAULT_KEY_STORE_TYPE);
    if (propertyValue == null)
    {
      if (FIPS_MODE.get())
      {
        defaultKeyStoreType = KEY_STORE_TYPE_BCFKS;
      }
      else
      {
        defaultKeyStoreType = KeyStore.getDefaultType();
      }
    }
    else
    {
      defaultKeyStoreType = propertyValue;
    }

    DEFAULT_KEY_STORE_TYPE = new AtomicReference<>(defaultKeyStoreType);
  }



  /**
   * The name of the provider service type for secure random number generator
   * algorithms.
   */
  @NotNull private static final String SECURE_RANDOM_SERVICE_TYPE =
       "SecureRandom";



  /**
   * A null Provider instance.
   */
  @Nullable private static final Provider NULL_PROVIDER = null;



  /**
   * Prevents this utility class from being instantiated.
   */
  private CryptoHelper()
  {
    // No implementation required.
  }



  /**
   * Indicates whether the LDAP SDK should operate in a strict
   * FIPS 140-2-compliant mode.
   *
   * @return  {@code true} if the LDAP SDK should operate in a strict
   *          FIPS 140-2-compliant mode, or {@code false} if not.
   */
  public static boolean usingFIPSMode()
  {
    return FIPS_MODE.get();
  }



  /**
   * Specifies whether the LDAP SDK should operate in a strict FIPS
   * 140-2-compliant mode.  If the LDAP SDK should operate in FIPS mode, then
   * the Bouncy Castle FIPS provider will be used by default.
   *
   * @param  useFIPSMode  Indicates whether the LDAP SDK should operate in a
   *                      strict FIPS 140-2-compliant mode.
   *
   * @throws  NoSuchProviderException  If FIPS mode should be enabled but the
   *                                   Bouncy Castle FIPS libraries are not
   *                                   available.
   */
  public static void setUseFIPSMode(final boolean useFIPSMode)
         throws NoSuchProviderException
  {
    if (useFIPSMode)
    {
      setUseFIPSMode(BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME);
    }
    else
    {
      FIPS_MODE.set(false);
    }
  }



  /**
   * Specifies that the LDAP SDK should operate in a strict FIPS 140-2-compliant
   * mode using the specified provider.
   *
   * @param  providerName  The name of the security provider to use to provide
   *                       the FIPS 140-2-compliant functionality.  At present,
   *                       only the Bouncy Castle "BCFIPS" provider is
   *                       supported.
   *
   * @throws  NoSuchProviderException  If the specified provider is not
   *                                   supported or available.
   */
  public static void setUseFIPSMode(@NotNull final String providerName)
         throws NoSuchProviderException
  {
    final Provider fipsProvider;
    final Provider jsseProvider;

    if (providerName.equalsIgnoreCase(
         BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME))
    {
      fipsProvider = BouncyCastleFIPSHelper.loadBouncyCastleFIPSProvider(true);
      jsseProvider = BouncyCastleFIPSHelper.loadBouncyCastleJSSEProvider(true);
    }
    else
    {
      throw new NoSuchProviderException(
           ERR_CRYPTO_HELPER_UNSUPPORTED_FIPS_PROVIDER.get(providerName,
                BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME));
    }

    FIPS_PROVIDER.set(fipsProvider);
    FIPS_JSSE_PROVIDER.set(jsseProvider);
    FIPS_DEFAULT_KEY_MANAGER_FACTORY_ALGORITHM.set(
         BouncyCastleFIPSHelper.DEFAULT_KEY_MANAGER_FACTORY_ALGORITHM);
    FIPS_DEFAULT_KEY_STORE_TYPE.set(
         BouncyCastleFIPSHelper.FIPS_KEY_STORE_TYPE);
    FIPS_DEFAULT_SSL_CONTEXT_PROTOCOL.set(
         BouncyCastleFIPSHelper.DEFAULT_SSL_CONTEXT_PROTOCOL);
    FIPS_DEFAULT_TRUST_MANAGER_FACTORY_ALGORITHM.set(
         BouncyCastleFIPSHelper.DEFAULT_TRUST_MANAGER_FACTORY_ALGORITHM);
    FIPS_MODE.set(true);

    TLSCipherSuiteSelector.recompute();
  }



  /**
   * Attempts to remove any security providers that are not believed to be
   * needed when operating in FIPS 140-2-compliant mode.  Note that this method
   * assumes the use of an Oracle or OpenJDK-based JVM and may not work as
   * expected in JVMs from other vendors that may have a different set of
   * essential providers.
   */
  public static void removeNonEssentialSecurityProviders()
  {
    for (final Provider provider : Security.getProviders())
    {
      if (! ESSENTIAL_PROVIDERS_TO_PRESERVE.contains(
           provider.getClass().getName()))
      {
        Security.removeProvider(provider.getName());
      }
    }
  }



  /**
   * Retrieves a certificate factory instance using the specified certificate
   * type.
   *
   * @param  type  The name of the type of certificate to create.  It must not
   *               be {@code null}.
   *
   * @return  A certificate factory instance using the specified type.  It will
   *          not be {@code null}.
   *
   * @throws  CertificateException  If the specified certificate type is not
   *                                available.
   */
  @NotNull()
  public static CertificateFactory getCertificateFactory(
              @NotNull final String type)
         throws CertificateException
  {
    return getCertificateFactory(type, NULL_PROVIDER);
  }



  /**
   * Retrieves a certificate factory instance using the specified certificate
   * type and provider.
   *
   * @param  type          The name of the type of certificate to create.  It
   *                       must not be {@code null}.
   * @param  providerName  The name of the provider to use.  It may be
   *                       {@code null} if a default provider should be used.
   *
   * @return  A certificate factory instance using the specified type and
   *          provider.  It will not be {@code null}.
   *
   * @throws  CertificateException  If the specified certificate type is not
   *                                available.
   *
   * @throws  NoSuchProviderException  If the specified provider is not
   *                                   available.
   */
  @NotNull()
  public static CertificateFactory getCertificateFactory(
              @NotNull final String type,
              @Nullable final String providerName)
         throws CertificateException, NoSuchProviderException
  {
    return getCertificateFactory(type,  getProvider(providerName, true));
  }



  /**
   * Retrieves a certificate factory instance using the specified certificate
   * type and provider.
   *
   * @param  type      The name of the type of certificate to create.  It must
   *                   not be {@code null}.
   * @param  provider  The provider to use.  It may be {@code null} if a default
   *                  provider should be used.
   *
   * @return  A certificate factory instance using the specified type and
   *          provider.  It will not be {@code null}.
   *
   * @throws  CertificateException  If the specified certificate type is not
   *                                available.
   */
  @NotNull()
  public static CertificateFactory getCertificateFactory(
              @NotNull final String type,
              @Nullable final Provider provider)
         throws CertificateException
  {
    if (provider == null)
    {
      if (usingFIPSMode())
      {
        return CertificateFactory.getInstance(type, FIPS_PROVIDER.get());
      }
      else
      {
        return CertificateFactory.getInstance(type);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(FIPS_PROVIDER.get().getName()))
      {
        throw new CertificateException(
             ERR_CRYPTO_HELPER_GET_CERT_FACTORY_WRONG_PROVIDER_FOR_FIPS_MODE.
                  get(type, providerName,
                       FIPS_PROVIDER.get().getName()));
      }
    }

    return CertificateFactory.getInstance(type, provider);
  }



  /**
   * Retrieves a cipher instance using the specified transformation.
   *
   * @param  cipherTransformation  The cipher transformation to use for the
   *                               cipher instance to create.  It must not be
   *                               {@code null}.
   *
   * @return  A cipher instance using the specified cipher transformation.  It
   *          will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the cipher transformation uses an
   *                                    algorithm that is not available.
   *
   * @throws  NoSuchPaddingException  If the cipher transformation uses a
   *                                  padding scheme that is not available.
   */
  @NotNull()
  public static Cipher getCipher(@NotNull final String cipherTransformation)
         throws NoSuchAlgorithmException, NoSuchPaddingException
  {
    return getCipher(cipherTransformation, NULL_PROVIDER);
  }



  /**
   * Retrieves a cipher instance using the specified transformation and
   * provider.
   *
   * @param  cipherTransformation  The cipher transformation to use for the
   *                               cipher instance to create.  It must not be
   *                               {@code null}.
   * @param  providerName          The name of the provider to use.  It may be
   *                               {@code null} if a default provider should be
   *                               used.
   *
   * @return  A cipher instance using the specified cipher transformation and
   *          provider.  It will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the cipher transformation uses an
   *                                    algorithm that is not available.
   *
   * @throws  NoSuchPaddingException  If the cipher transformation uses a
   *                                  padding scheme that is not available.
   *
   * @throws  NoSuchProviderException  If the specified provider is not
   *                                   available.
   */
  @NotNull()
  public static Cipher getCipher(@NotNull final String cipherTransformation,
                                 @Nullable final String providerName)
         throws NoSuchAlgorithmException, NoSuchPaddingException,
                NoSuchProviderException
  {
    return getCipher(cipherTransformation, getProvider(providerName, true));
  }



  /**
   * Retrieves a cipher instance using the specified transformation and
   * provider.
   *
   * @param  cipherTransformation  The cipher transformation to use for the
   *                               cipher instance to create.  It must not be
   *                               {@code null}.
   * @param  provider              The provider to use.  It may be {@code null}
   *                               if a default provider should be used.
   *
   * @return  A cipher instance using the specified cipher transformation and
   *          provider.  It will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the cipher transformation uses an
   *                                    algorithm that is not available.
   *
   * @throws  NoSuchPaddingException  If the cipher transformation uses a
   *                                  padding scheme that is not available.
   */
  @NotNull()
  public static Cipher getCipher(@NotNull final String cipherTransformation,
                                 @Nullable final Provider provider)
         throws NoSuchAlgorithmException, NoSuchPaddingException
  {
    if (provider == null)
    {
      if (usingFIPSMode())
      {
        return Cipher.getInstance(cipherTransformation, FIPS_PROVIDER.get());
      }
      else
      {
        return Cipher.getInstance(cipherTransformation);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(FIPS_PROVIDER.get().getName()))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_CIPHER_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                  cipherTransformation, providerName,
                  FIPS_PROVIDER.get().getName()));
      }
    }

    return Cipher.getInstance(cipherTransformation, provider);
  }



  /**
   * Retrieves a key factory instance using the specified algorithm.
   *
   * @param  algorithmName  The name of the key factory instance to retrieve.
   *                        It must not be {@code null}.
   *
   * @return  A key factory instance using the specified algorithm.  It will not
   *          be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified key factory algorithm
   *                                    is not available.
   */
  @NotNull()
  public static KeyFactory getKeyFactory(@NotNull final String algorithmName)
         throws NoSuchAlgorithmException
  {
    return getKeyFactory(algorithmName, NULL_PROVIDER);
  }



  /**
   * Retrieves a key factory instance using the specified algorithm and
   * provider.
   *
   * @param  algorithmName  The name of the key factory instance to retrieve.
   *                        It must not be {@code null}.
   * @param  providerName   The name of the provider to use.  It may be
   *                        {@code null} if a default provider should be used.
   *
   * @return  A key factory instance using the specified algorithm and provider.
   *          It will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified key factory algorithm
   *                                    is not available.
   *
   * @throws  NoSuchProviderException  If the specified provider is not
   *                                   available.
   */
  @NotNull()
  public static KeyFactory getKeyFactory(@NotNull final String algorithmName,
                                         @Nullable final String providerName)
         throws NoSuchAlgorithmException, NoSuchProviderException
  {
    return getKeyFactory(algorithmName, getProvider(providerName, true));
  }



  /**
   * Retrieves a key factory instance using the specified algorithm and
   * provider.
   *
   * @param  algorithmName  The name of the key factory instance to retrieve.
   *                        It must not be {@code null}.
   * @param  provider       The name provider to use.  It may be {@code null} if
   *                        a default provider should be used.
   *
   * @return  A key factory instance using the specified algorithm and provider.
   *          It will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified key factory algorithm
   *                                    is not available.
   */
  @NotNull()
  public static KeyFactory getKeyFactory(@NotNull final String algorithmName,
                                         @Nullable final Provider provider)
         throws NoSuchAlgorithmException
  {
    if (provider == null)
    {
      if (usingFIPSMode())
      {
        return KeyFactory.getInstance(algorithmName, FIPS_PROVIDER.get());
      }
      else
      {
        return KeyFactory.getInstance(algorithmName);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(FIPS_PROVIDER.get().getName()))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_KEY_FACTORY_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                  algorithmName, providerName, FIPS_PROVIDER.get().getName()));
      }
    }

    return KeyFactory.getInstance(algorithmName, provider);
  }



  /**
   * Retrieves a key manager factory instance using a default algorithm.
   *
   * @return  A key manager factory instance using a default algorithm.  It will
   *          not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the key manager factory instance
   *                                    cannot be created because the default
   *                                    algorithm is not available.
   */
  @NotNull()
  public static KeyManagerFactory getKeyManagerFactory()
         throws NoSuchAlgorithmException
  {
    if (usingFIPSMode())
    {
      return KeyManagerFactory.getInstance(
           FIPS_DEFAULT_KEY_MANAGER_FACTORY_ALGORITHM.get(),
           FIPS_JSSE_PROVIDER.get());
    }
    else
    {
      return getKeyManagerFactory(KeyManagerFactory.getDefaultAlgorithm());
    }
  }



  /**
   * Retrieves a key manager factory instance using the specified algorithm.
   *
   * @param  algorithmName  The name of the key manager factory instance to
   *                        retrieve.  It must not be {@code null}.
   *
   * @return  A key manager factory instance using the specified algorithm.  It
   *          will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified key manager factory
   *                                    algorithm is not available.
   */
  @NotNull()
  public static KeyManagerFactory getKeyManagerFactory(
              @NotNull final String algorithmName)
         throws NoSuchAlgorithmException
  {
    return getKeyManagerFactory(algorithmName, NULL_PROVIDER);
  }



  /**
   * Retrieves a key manager factory instance using the specified algorithm and
   * provider.
   *
   * @param  algorithmName  The name of the key manager factory instance to
   *                        retrieve.  It must not be {@code null}.
   * @param  providerName   The name of the provider to use.  It may be
   *                        {@code null} if a default provider should be used.
   *
   * @return  A key manager factory instance using the specified algorithm and
   *          provider.  It will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified key manager factory
   *                                    algorithm is not available.
   *
   * @throws  NoSuchProviderException  If the specified provider is not
   *                                   available.
   */
  @NotNull()
  public static KeyManagerFactory getKeyManagerFactory(
              @NotNull final String algorithmName,
              @Nullable final String providerName)
         throws NoSuchAlgorithmException, NoSuchProviderException
  {
    return getKeyManagerFactory(algorithmName, getProvider(providerName, true));
  }



  /**
   * Retrieves a key manager factory instance using the specified algorithm and
   * provider.
   *
   * @param  algorithmName  The name of the key manager factory instance to
   *                        retrieve.  It must not be {@code null}.
   * @param  provider       The name provider to use.  It may be {@code null} if
   *                        a default provider should be used.
   *
   * @return  A key manager factory instance using the specified algorithm and
   *          provider.  It will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified key manager factory
   *                                    algorithm is not available.
   */
  @NotNull()
  public static KeyManagerFactory getKeyManagerFactory(
              @NotNull final String algorithmName,
              @Nullable final Provider provider)
         throws NoSuchAlgorithmException
  {
    if (provider == null)
    {
      if (usingFIPSMode())
      {
        return KeyManagerFactory.getInstance(algorithmName,
             FIPS_PROVIDER.get());
      }
      else
      {
        return KeyManagerFactory.getInstance(algorithmName);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(FIPS_PROVIDER.get().getName()))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_KM_FACTORY_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                  algorithmName, providerName, FIPS_PROVIDER.get().getName()));
      }
    }

    return KeyManagerFactory.getInstance(algorithmName, provider);
  }



  /**
   * Retrieves a key pair generator instance using the specified algorithm.
   *
   * @param  algorithmName  The name of the key pair generator instance to
   *                        retrieve.  It must not be {@code null}.
   *
   * @return  A key pair generator instance using the specified algorithm.  It
   *          will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified key pair generator
   *                                    algorithm is not available.
   */
  @NotNull()
  public static KeyPairGenerator getKeyPairGenerator(
              @NotNull final String algorithmName)
         throws NoSuchAlgorithmException
  {
    return getKeyPairGenerator(algorithmName, NULL_PROVIDER);
  }



  /**
   * Retrieves a key pair generator instance using the specified algorithm and
   * provider.
   *
   * @param  algorithmName  The name of the key pair generator instance to
   *                        retrieve.  It must not be {@code null}.
   * @param  providerName   The name of the provider to use.  It may be
   *                        {@code null} if a default provider should be used.
   *
   * @return  A key pair generator instance using the specified algorithm and
   *          provider.  It will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified key pair generator
   *                                    algorithm is not available.
   *
   * @throws  NoSuchProviderException  If the specified provider is not
   *                                   available.
   */
  @NotNull()
  public static KeyPairGenerator getKeyPairGenerator(
              @NotNull final String algorithmName,
              @Nullable final String providerName)
         throws NoSuchAlgorithmException, NoSuchProviderException
  {
    return getKeyPairGenerator(algorithmName, getProvider(providerName, true));
  }



  /**
   * Retrieves a key pair generator instance using the specified algorithm and
   * provider.
   *
   * @param  algorithmName  The name of the key pair generator instance to
   *                        retrieve.  It must not be {@code null}.
   * @param  provider       The name provider to use.  It may be {@code null} if
   *                        a default provider should be used.
   *
   * @return  A key pair generator instance using the specified algorithm and
   *          provider.  It will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified key pair generator
   *                                    algorithm is not available.
   */
  @NotNull()
  public static KeyPairGenerator getKeyPairGenerator(
              @NotNull final String algorithmName,
              @Nullable final Provider provider)
         throws NoSuchAlgorithmException
  {
    if (provider == null)
    {
      if (usingFIPSMode())
      {
        return KeyPairGenerator.getInstance(algorithmName, FIPS_PROVIDER.get());
      }
      else
      {
        return KeyPairGenerator.getInstance(algorithmName);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(FIPS_PROVIDER.get().getName()))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_KP_GEN_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                  algorithmName, providerName, FIPS_PROVIDER.get().getName()));
      }
    }

    return KeyPairGenerator.getInstance(algorithmName, provider);
  }



  /**
   * Retrieves the default type of key store that should be used.
   *
   * @return  The default type of key store that should be used.
   */
  @NotNull()
  public static String getDefaultKeyStoreType()
  {
    return DEFAULT_KEY_STORE_TYPE.get();
  }



  /**
   * Specifies the default type of key store that should be used.
   *
   * @param  defaultKeyStoreType  The default type of key store that should be
   *                              used.  It must not be {@code null}.
   */
  public static void setDefaultKeyStoreType(
              @NotNull final String defaultKeyStoreType)
  {
    DEFAULT_KEY_STORE_TYPE.set(defaultKeyStoreType);
  }



  /**
   * Retrieves a key store instance using the specified key store type.
   *
   * @param  keyStoreType  The name of the key store type to use.  It must not
   *                       be {@code null}.
   *
   * @return  A key store instance using the specified key store type.  It will
   *          not be {@code null}.
   *
   * @throws  KeyStoreException  If the specified key store type is not
   *                             available.
   */
  @NotNull()
  public static KeyStore getKeyStore(@NotNull final String keyStoreType)
         throws KeyStoreException
  {
    return getKeyStore(keyStoreType, NULL_PROVIDER);
  }



  /**
   * Retrieves a key store instance using the specified key store type and
   * provider.
   *
   * @param  keyStoreType  The name of the key store type to use.  It must not
   *                       be {@code null}.
   * @param  providerName  The name of the provider to use.  It may be
   *                       {@code null} if a default provider should be used.
   *
   * @return  A key store instance using the specified key store type and
   *          provider.  It will not be {@code null}.
   *
   * @throws  KeyStoreException  If the specified key store type is not
   *                             available.
   *
   * @throws  NoSuchProviderException  If the specified provider is not
   *                                   available.
   */
  @NotNull()
  public static KeyStore getKeyStore(@NotNull final String keyStoreType,
                                     @Nullable final String providerName)
         throws KeyStoreException, NoSuchProviderException
  {
    return getKeyStore(keyStoreType, getProvider(providerName, false));
  }



  /**
   * Retrieves a key store instance using the specified key store type and
   * provider.
   *
   * @param  keyStoreType  The name of the key store type to use.  It must not
   *                       be {@code null}.
   * @param  provider      The provider to use.  It may be {@code null} if a
   *                       default provider should be used.
   *
   * @return  A key store instance using the specified key store type and
   *          provider.  It will not be {@code null}.
   *
   * @throws  KeyStoreException  If the specified key store type is not
   *                             available.
   */
  @NotNull()
  public static KeyStore getKeyStore(@NotNull final String keyStoreType,
                                     @Nullable final Provider provider)
         throws KeyStoreException
  {
    return getKeyStore(keyStoreType, provider, false);
  }



  /**
   * Retrieves a key store instance using the specified key store type and
   * provider.
   *
   * @param  keyStoreType            The name of the key store type to use.  It
   *                                 must not be {@code null}.
   * @param  provider                The provider to use.  It may be
   *                                 {@code null} if a default provider should
   *                                 be used.
   * @param  allowNonFIPSInFIPSMode  Indicates whether to allow attempts to use
   *                                 a non-FIPS-compliant key store even when
   *                                 operating in FIPS mode.  This should
   *                                 generally only be {@code true} when the
   *                                 key store will be used for certain types of
   *                                 trust stores (e.g., for the JVM-default
   *                                 trust store).
   *
   * @return  A key store instance using the specified key store type and
   *          provider.  It will not be {@code null}.
   *
   * @throws  KeyStoreException  If the specified key store type is not
   *                             available.
   */
  @NotNull()
  public static KeyStore getKeyStore(@NotNull final String keyStoreType,
                                     @Nullable final Provider provider,
                                     final boolean allowNonFIPSInFIPSMode)
         throws KeyStoreException
  {
    // If the LDAP SDK is operating in FIPS mode, then we will only allow the
    // BCFKS and PKCS #11 key store types.
    if (usingFIPSMode() && (! allowNonFIPSInFIPSMode))
    {
      if (! (keyStoreType.equals(KEY_STORE_TYPE_BCFKS) ||
             keyStoreType.equals(KEY_STORE_TYPE_PKCS_11)))
      {
        throw new KeyStoreException(
             ERR_CRYPTO_HELPER_GET_KEY_STORE_WRONG_STORE_TYPE_FOR_FIPS_MODE.get(
                  keyStoreType, KEY_STORE_TYPE_BCFKS, KEY_STORE_TYPE_PKCS_11));
      }
    }

    if (provider == null)
    {
      if (usingFIPSMode() &&
           keyStoreType.equals(FIPS_DEFAULT_KEY_STORE_TYPE.get()))
      {
        return KeyStore.getInstance(keyStoreType, FIPS_PROVIDER.get());
      }
      else
      {
        return KeyStore.getInstance(keyStoreType);
      }
    }

    if (keyStoreType.equals(
             BouncyCastleFIPSHelper.FIPS_KEY_STORE_TYPE) &&
        (! provider.getName().equals(
             BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME)))
    {
      throw new KeyStoreException(
           ERR_CRYPTO_HELPER_GET_KEY_STORE_WRONG_PROVIDER_FOR_STORE_TYPE.get(
                keyStoreType, provider.getName(),
                BouncyCastleFIPSHelper.FIPS_KEY_STORE_TYPE, keyStoreType));
    }

    return KeyStore.getInstance(keyStoreType, provider);
  }



  /**
   * Retrieves a MAC instance using the specified algorithm.
   *
   * @param  algorithmName  The name of the MAC algorithm to use.  It must not
   *                        be {@code null}.
   *
   * @return  A MAC instance using the specified algorithm.  It will not be
   *          {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified MAC algorithm is not
   *                                    available.
   */
  @NotNull()
  public static Mac getMAC(@NotNull final String algorithmName)
         throws NoSuchAlgorithmException
  {
    return getMAC(algorithmName, NULL_PROVIDER);
  }



  /**
   * Retrieves a MAC instance using the specified algorithm and provider.
   *
   * @param  algorithmName  The name of the MAC algorithm to use.  It must not
   *                        be {@code null}.
   * @param  providerName   The name of the provider to use.  It may be
   *                        {@code null} if a default provider should be used.
   *
   * @return  A MAC instance using the specified algorithm and provider.  It
   *          will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified MAC algorithm is not
   *                                    available.
   *
   * @throws  NoSuchProviderException  If the specified provider is not
   *                                   available.
   */
  @NotNull()
  public static Mac getMAC(@NotNull final String algorithmName,
                           @Nullable final String providerName)
         throws NoSuchAlgorithmException, NoSuchProviderException
  {
    return getMAC(algorithmName, getProvider(providerName, true));
  }



  /**
   * Retrieves a MAC instance using the specified algorithm and provider.
   *
   * @param  algorithmName  The name of the MAC algorithm to use.  It must not
   *                        be {@code null}.
   * @param  provider       The provider to use.  It may be {@code null} if a
   *                        default provider should be used.
   *
   * @return  A MAC instance using the specified algorithm and provider.  It
   *          will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified MAC algorithm is not
   *                                    available.
   */
  @NotNull()
  public static Mac getMAC(@NotNull final String algorithmName,
                           @Nullable final Provider provider)
         throws NoSuchAlgorithmException
  {
    if (provider == null)
    {
      if (usingFIPSMode())
      {
        return Mac.getInstance(algorithmName, FIPS_PROVIDER.get());
      }
      else
      {
        return Mac.getInstance(algorithmName);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(FIPS_PROVIDER.get().getName()))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_MAC_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                  algorithmName, providerName, FIPS_PROVIDER.get().getName()));
      }
    }

    return Mac.getInstance(algorithmName, provider);
  }



  /**
   * Retrieves a message digest instance using the specified algorithm.
   *
   * @param  algorithmName  The name of the digest algorithm to use.  It must
   *                        not be {@code null}.
   *
   * @return  A message digest instance using the specified algorithm.  It will
   *          not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified digest algorithm is not
   *                                    available.
   */
  @NotNull()
  public static MessageDigest getMessageDigest(
              @NotNull final String algorithmName)
         throws NoSuchAlgorithmException
  {
    return getMessageDigest(algorithmName, NULL_PROVIDER);
  }



  /**
   * Retrieves a message digest instance using the specified algorithm and
   * provider.
   *
   * @param  algorithmName  The name of the digest algorithm to use.  It must
   *                        not be {@code null}.
   * @param  providerName   The name of the provider to use.  It may be
   *                        {@code null} if a default provider should be used.
   *
   * @return  A message digest instance using the specified algorithm and
   *          provider.  It will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified digest algorithm is not
   *                                    available.
   *
   * @throws  NoSuchProviderException  If the specified provider is not
   *                                   available.
   */
  @NotNull()
  public static MessageDigest getMessageDigest(
              @NotNull final String algorithmName,
              @Nullable final String providerName)
         throws NoSuchAlgorithmException, NoSuchProviderException
  {
    return getMessageDigest(algorithmName, getProvider(providerName, true));
  }



  /**
   * Retrieves a message digest instance using the specified algorithm and
   * provider.
   *
   * @param  algorithmName  The name of the digest algorithm to use.  It must
   *                        not be {@code null}.
   * @param  provider       The provider to use.  It may be {@code null} if a
   *                        default provider should be used.
   *
   * @return  A message digest instance using the specified algorithm and
   *          provider.  It will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified digest algorithm is not
   *                                    available.
   */
  @NotNull()
  public static MessageDigest getMessageDigest(
              @NotNull final String algorithmName,
              @Nullable final Provider provider)
         throws NoSuchAlgorithmException
  {
    if (provider == null)
    {
      if (usingFIPSMode())
      {
        return MessageDigest.getInstance(algorithmName, FIPS_PROVIDER.get());
      }
      else
      {
        return MessageDigest.getInstance(algorithmName);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(FIPS_PROVIDER.get().getName()))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_DIGEST_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                  algorithmName, providerName, FIPS_PROVIDER.get().getName()));
      }
    }

    return MessageDigest.getInstance(algorithmName, provider);
  }



  /**
   * Retrieves a secret key factory instance using the specified algorithm.
   *
   * @param  algorithmName  The name of the algorithm to use.  It must not be
   *                        {@code null}.
   *
   * @return  A secret key factory instance using the specified algorithm.  It
   *          will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified algorithm is not
   *                                    available.
   */
  @NotNull()
  public static SecretKeyFactory getSecretKeyFactory(
              @NotNull final String algorithmName)
         throws NoSuchAlgorithmException
  {
    return getSecretKeyFactory(algorithmName, NULL_PROVIDER);
  }



  /**
   * Retrieves a secret key factory instance using the specified algorithm and
   * provider.
   *
   * @param  algorithmName  The name of the algorithm to use.  It must not be
   *                        {@code null}.
   * @param  providerName   The name of the provider to use.  It may be
   *                        {@code null} if a default provider should be used.
   *
   * @return  A secret key factory instance using the specified algorithm and
   *          provider.  It will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified algorithm is not
   *                                    available.
   *
   * @throws  NoSuchProviderException  If the specified provider is not
   *                                   available.
   */
  @NotNull()
  public static SecretKeyFactory getSecretKeyFactory(
              @NotNull final String algorithmName,
              @Nullable final String providerName)
         throws NoSuchAlgorithmException, NoSuchProviderException
  {
    return getSecretKeyFactory(algorithmName, getProvider(providerName, true));
  }



  /**
   * Retrieves a secret key factory instance using the specified algorithm and
   * provider.
   *
   * @param  algorithmName  The name of the algorithm to use.  It must not be
   *                        {@code null}.
   * @param  provider       The provider to use.  It may be {@code null} if a
   *                        default provider should be used.
   *
   * @return  A secret key factory instance using the specified algorithm and
   *          provider.  It will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified algorithm is not
   *                                    available.
   */
  @NotNull()
  public static SecretKeyFactory getSecretKeyFactory(
              @NotNull final String algorithmName,
              @Nullable final Provider provider)
         throws NoSuchAlgorithmException
  {
    if (provider == null)
    {
      if (usingFIPSMode())
      {
        return SecretKeyFactory.getInstance(algorithmName, FIPS_PROVIDER.get());
      }
      else
      {
        return SecretKeyFactory.getInstance(algorithmName);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(FIPS_PROVIDER.get().getName()))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_SK_FACTORY_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                  algorithmName, providerName, FIPS_PROVIDER.get().getName()));
      }
    }

    return SecretKeyFactory.getInstance(algorithmName, provider);
  }



  /**
   * Retrieves a secure random instance using the default algorithm and
   * provider.
   *
   * @return  A secure random instance using the default algorithm and provider.
   *          It will not be {@code null}.
   */
  @NotNull()
  public static SecureRandom getSecureRandom()
  {
    try
    {
      return getSecureRandom(null, NULL_PROVIDER);
    }
    catch (final NoSuchAlgorithmException e)
    {
      // This should never happen.
      Debug.debugException(e);
      throw new LDAPRuntimeException(new LDAPException(ResultCode.LOCAL_ERROR,
           e.getMessage(), e));
    }
  }



  /**
   * Retrieves a secure random instance using the specified algorithm.
   *
   * @param  algorithmName  The name of the algorithm to use.  It may be
   *                        {@code null} if a default algorithm should be used.
   *
   * @return  A secure random instance using the specified algorithm.  It will
   *          not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified algorithm is not
   *                                    available.
   */
  @NotNull()
  public static SecureRandom getSecureRandom(
              @Nullable final String algorithmName)
         throws NoSuchAlgorithmException
  {
    return getSecureRandom(algorithmName, NULL_PROVIDER);
  }



  /**
   * Retrieves a secure random instance using the specified algorithm and
   * provider.
   *
   * @param  algorithmName  The name of the algorithm to use.  It may be
   *                        {@code null} if a default algorithm should be used.
   * @param  providerName   The name of the provider to use.  It may be
   *                        {@code null} if a default provider should be used.
   *
   * @return  A secure random instance using the specified algorithm and
   *          provider.  It will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified algorithm is not
   *                                    available.
   *
   * @throws  NoSuchProviderException  If the specified provider is not
   *                                   available.
   */
  @NotNull()
  public static SecureRandom getSecureRandom(
              @Nullable final String algorithmName,
              @Nullable final String providerName)
         throws NoSuchAlgorithmException, NoSuchProviderException
  {
    return getSecureRandom(algorithmName, getProvider(providerName, true));
  }



  /**
   * Retrieves a secure random instance using the specified algorithm and
   * provider.
   *
   * @param  algorithmName  The name of the algorithm to use.  It may be
   *                        {@code null} if a default algorithm should be used.
   * @param  provider       The provider to use.  It may be {@code null} if a
   *                        default provider should be used.
   *
   * @return  A secure random instance using the specified algorithm and
   *          provider.  It will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified algorithm is not
   *                                    available.
   */
  @NotNull()
  public static SecureRandom getSecureRandom(
              @Nullable final String algorithmName,
              @Nullable final Provider provider)
         throws NoSuchAlgorithmException
  {
    if (algorithmName == null)
    {
      if (provider == null)
      {
        if (usingFIPSMode())
        {
          return getSecureRandom(FIPS_PROVIDER.get());
        }
        else
        {
          return new SecureRandom();
        }
      }
      else
      {
        return getSecureRandom(provider);
      }
    }
    else if (provider == null)
    {
      if (usingFIPSMode())
      {
        return getSecureRandom(algorithmName, FIPS_PROVIDER.get());
      }
      else
      {
        return SecureRandom.getInstance(algorithmName);
      }
    }
    else
    {
      if (usingFIPSMode())
      {
        final String providerName = provider.getName();
        if (! providerName.equals(FIPS_PROVIDER.get().getName()))
        {
          throw new NoSuchAlgorithmException(
               ERR_CRYPTO_HELPER_GET_SEC_RAND_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                    algorithmName, providerName,
                    FIPS_PROVIDER.get().getName()));
        }
      }

      return SecureRandom.getInstance(algorithmName, provider);
    }
  }



  /**
   * Retrieves a secure random instance using the first available algorithm for
   * the specified provider.
   *
   * @param  provider  The provider to use.  It must not be {@code null}.
   *
   * @return  A secure random instance using the specified provider.  It will
   *          not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified provider does not
   *                                    support any secure random algorithms.
   */
  @NotNull()
  private static SecureRandom getSecureRandom(@NotNull final Provider provider)
          throws NoSuchAlgorithmException
  {
    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(FIPS_PROVIDER.get().getName()))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_SEC_RAND_WRONG_PROVIDER_FOR_FIPS_MODE_NO_ALG.
                  get(providerName, FIPS_PROVIDER.get().getName()));
      }
    }

    for (final Provider.Service service : provider.getServices())
    {
      if (service.getType().equals(SECURE_RANDOM_SERVICE_TYPE))
      {
        return SecureRandom.getInstance(service.getAlgorithm(), provider);
      }
    }

    throw new NoSuchAlgorithmException(
         ERR_CRYPTO_HELPER_GET_SEC_RAND_NO_ALG_FOR_PROVIDER.get(
              provider.getName()));
  }



  /**
   * Retrieves a signature instance using the specified algorithm.
   *
   * @param  algorithmName  The name of the algorithm to use.  It must not be
   *                        {@code null}.
   *
   * @return  A signature instance using the specified algorithm.  It will noe
   *          be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified algorithm is not
   *                                    available.
   */
  @NotNull()
  public static Signature getSignature(@NotNull final String algorithmName)
         throws NoSuchAlgorithmException
  {
    return getSignature(algorithmName, NULL_PROVIDER);
  }



  /**
   * Retrieves a signature instance using the specified algorithm and provider.
   *
   * @param  algorithmName  The name of the algorithm to use.  It must not be
   *                        {@code null}.
   * @param  providerName   The name of the provider to use.  It may be
   *                        {@code null} if a default provider should be used.
   *
   * @return  A signature instance using the specified algorithm and provider.
   *          It will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified algorithm is not
   *                                    available.
   *
   * @throws  NoSuchProviderException  If the specified provider is not
   *                                   available.
   */
  @NotNull()
  public static Signature getSignature(
              @NotNull final String algorithmName,
              @Nullable final String providerName)
         throws NoSuchAlgorithmException, NoSuchProviderException
  {
    return getSignature(algorithmName, getProvider(providerName, true));
  }



  /**
   * Retrieves a signature instance using the specified algorithm and provider.
   *
   * @param  algorithmName  The name of the algorithm to use.  It must not be
   *                        {@code null}.
   * @param  provider       The provider to use.  It may be {@code null} if a
   *                        default provider should be used.
   *
   * @return  A signature instance using the specified algorithm and provider.
   *          It will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified algorithm is not
   *                                    available.
   */
  @NotNull()
  public static Signature getSignature(
              @NotNull final String algorithmName,
              @Nullable final Provider provider)
         throws NoSuchAlgorithmException
  {
    if (provider == null)
    {
      if (usingFIPSMode())
      {
        return Signature.getInstance(algorithmName, FIPS_PROVIDER.get());
      }
      else
      {
        return Signature.getInstance(algorithmName);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(FIPS_PROVIDER.get().getName()))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_SIGNATURE_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                  algorithmName, providerName, FIPS_PROVIDER.get().getName()));
      }
    }

    return Signature.getInstance(algorithmName, provider);
  }



  /**
   * Retrieves an SSL context instance using the default settings.
   *
   * @return  An SSL context instance using the default settings.
   *
   * @throws  NoSuchAlgorithmException  If the default SSL context cannot be
   *                                    obtained.
   */
  @NotNull()
  public static SSLContext getDefaultSSLContext()
         throws NoSuchAlgorithmException
  {
    if (usingFIPSMode())
    {
      return SSLContext.getInstance(FIPS_DEFAULT_SSL_CONTEXT_PROTOCOL.get(),
           FIPS_JSSE_PROVIDER.get());
    }
    else
    {
      return SSLContext.getDefault();
    }
  }



  /**
   * Retrieves an SSL context instance using the specified protocol.
   *
   * @param  protocol  The name of the TLS protocol to use.  It must not be
   *                   {@code null}.
   *
   * @return  An SSL context instance using the specified protocol.  It will not
   *          be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified TLS protocol is not
   *                                    available.
   */
  @NotNull()
  public static SSLContext getSSLContext(@NotNull final String protocol)
         throws NoSuchAlgorithmException
  {
    return getSSLContext(protocol, NULL_PROVIDER);
  }



  /**
   * Retrieves an SSL context instance using the specified protocol and
   * provider.
   *
   * @param  protocol      The name of the TLS protocol to use.  It must not be
   *                       {@code null}.
   * @param  providerName  The name of the provider to use.  It may be
   *                       {@code null} if a default provider should be used.
   *
   * @return  An SSL context instance using the specified protocol and provider.
   *          It will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified TLS protocol is not
   *                                    available.
   *
   * @throws  NoSuchProviderException  If the specified provider is not
   *                                   available.
   */
  @NotNull()
  public static SSLContext getSSLContext(@NotNull final String protocol,
                                         @Nullable final String  providerName)
         throws NoSuchAlgorithmException, NoSuchProviderException
  {
    return getSSLContext(protocol, getProvider(providerName, true));
  }



  /**
   * Retrieves an SSL context instance using the specified protocol and
   * provider.
   *
   * @param  protocol  The name of the TLS protocol to use.  It must not be
   *                   {@code null}.
   * @param  provider  The provider to use.  It may be {@code null} if a default
   *                   provider should be used.
   *
   * @return  An SSL context instance using the specified protocol and provider.
   *          It will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified TLS protocol is not
   *                                    available.
   */
  @NotNull()
  public static SSLContext getSSLContext(@NotNull final String protocol,
                                         @Nullable final Provider provider)
         throws NoSuchAlgorithmException
  {
    if (provider == null)
    {
      if (usingFIPSMode())
      {
        return SSLContext.getInstance(protocol, FIPS_JSSE_PROVIDER.get());
      }
      else
      {
        return SSLContext.getInstance(protocol);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(FIPS_JSSE_PROVIDER.get().getName()))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_SSL_CONTEXT_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                  protocol, providerName, FIPS_JSSE_PROVIDER.get().getName()));
      }
    }

    return SSLContext.getInstance(protocol, provider);
  }



  /**
   * Retrieves a trust manager factory instance using a default algorithm.
   *
   * @return  A trust manager factory instance using a default algorithm.  It
   *          will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the trust manager factory instance
   *                                    cannot be created because the default
   *                                    algorithm is not available.
   */
  @NotNull()
  public static TrustManagerFactory getTrustManagerFactory()
         throws NoSuchAlgorithmException
  {
    if (usingFIPSMode())
    {
      return TrustManagerFactory.getInstance(
           FIPS_DEFAULT_TRUST_MANAGER_FACTORY_ALGORITHM.get(),
           FIPS_JSSE_PROVIDER.get());
    }
    else
    {
      return getTrustManagerFactory(TrustManagerFactory.getDefaultAlgorithm());
    }
  }



  /**
   * Retrieves a trust manager factory instance using the specified algorithm.
   *
   * @param  algorithmName  The name of the trust manager factory instance to
   *                        retrieve.  It must not be {@code null}.
   *
   * @return  A trust manager factory instance using the specified algorithm.
   *          It will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified trust manager factory
   *                                    algorithm is not available.
   */
  @NotNull()
  public static TrustManagerFactory getTrustManagerFactory(
              @NotNull final String algorithmName)
         throws NoSuchAlgorithmException
  {
    return getTrustManagerFactory(algorithmName, NULL_PROVIDER);
  }



  /**
   * Retrieves a trust manager factory instance using the specified algorithm
   * and provider.
   *
   * @param  algorithmName  The name of the trust manager factory instance to
   *                        retrieve.  It must not be {@code null}.
   * @param  providerName   The name of the provider to use.  It may be
   *                        {@code null} if a default provider should be used.
   *
   * @return  A trust manager factory instance using the specified algorithm and
   *          provider.  It will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified trust manager factory
   *                                    algorithm is not available.
   *
   * @throws  NoSuchProviderException  If the specified provider is not
   *                                   available.
   */
  @NotNull()
  public static TrustManagerFactory getTrustManagerFactory(
              @NotNull final String algorithmName,
              @Nullable final String providerName)
         throws NoSuchAlgorithmException, NoSuchProviderException
  {
    return getTrustManagerFactory(algorithmName,
         getProvider(providerName, true));
  }



  /**
   * Retrieves a trust manager factory instance using the specified algorithm
   * and provider.
   *
   * @param  algorithmName  The name of the trust manager factory instance to
   *                        retrieve.  It must not be {@code null}.
   * @param  provider       The name provider to use.  It may be {@code null} if
   *                        a default provider should be used.
   *
   * @return  A trust manager factory instance using the specified algorithm and
   *          provider.  It will not be {@code null}.
   *
   * @throws  NoSuchAlgorithmException  If the specified trust manager factory
   *                                    algorithm is not available.
   */
  @NotNull()
  public static TrustManagerFactory getTrustManagerFactory(
              @NotNull final String algorithmName,
              @Nullable final Provider provider)
         throws NoSuchAlgorithmException
  {
    if (provider == null)
    {
      if (usingFIPSMode())
      {
        return TrustManagerFactory.getInstance(algorithmName,
             FIPS_PROVIDER.get());
      }
      else
      {
        return TrustManagerFactory.getInstance(algorithmName);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(FIPS_PROVIDER.get().getName()))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_TM_FACTORY_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                  algorithmName, providerName, FIPS_PROVIDER.get().getName()));
      }
    }

    return TrustManagerFactory.getInstance(algorithmName, provider);
  }



  /**
   * Retrieves the provider instance with the specified name.
   *
   * @param  providerName                   The name of the provider to
   *                                        retrieve.  It may be {@code null} if
   *                                        a default provider should be used.
   * @param  requireFIPSProviderInFIPSMode  Indicates whether to only allow the
   *                                        FIPS provider when the LDAP SDK is
   *                                        operating in FIPS 140-2-compliant
   *                                        mode.
   *
   * @return  The provider with the specified name, or {@code null} if the
   *          given provider name was {@code null}.
   *
   * @throws  NoSuchProviderException  If the specified provider is not
   *                                   available.
   */
  @Nullable()
  private static Provider getProvider(@Nullable final String providerName,
               final boolean requireFIPSProviderInFIPSMode)
          throws NoSuchProviderException
  {
    if (providerName == null)
    {
      return null;
    }

    if (providerName.equals(BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME))
    {
      return BouncyCastleFIPSHelper.getBouncyCastleFIPSProvider();
    }
    else if (providerName.equals(BouncyCastleFIPSHelper.JSSE_PROVIDER_NAME))
    {
      return BouncyCastleFIPSHelper.getBouncyCastleJSSEProvider();
    }
    else
    {
      if (usingFIPSMode())
      {
        if (providerName.equals(FIPS_PROVIDER.get().getName()))
        {
          return FIPS_PROVIDER.get();
        }
        else if (providerName.equals(FIPS_JSSE_PROVIDER.get().getName()))
        {
          return FIPS_JSSE_PROVIDER.get();
        }
        else if (requireFIPSProviderInFIPSMode)
        {
          throw new NoSuchProviderException(
               ERR_CRYPTO_HELPER_PROVIDER_NOT_AVAILABLE_IN_FIPS_MODE.get(
                    providerName, FIPS_PROVIDER.get().getName()));
        }
      }

      final Provider provider = Security.getProvider(providerName);
      if (provider == null)
      {
        throw new NoSuchProviderException(
             ERR_CRYPTO_HELPER_NO_SUCH_PROVIDER.get(providerName));
      }

      return provider;
    }
  }
}
