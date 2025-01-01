/*
 * Copyright 2021-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021-2025 Ping Identity Corporation
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
 * Copyright (C) 2021-2025 Ping Identity Corporation
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



import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import com.unboundid.asn1.ASN1Constants;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPRuntimeException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.ssl.JVMDefaultTrustManager;
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
   * used to indicate that the LDAP SDK should operate in FIPS-compliant mode.
   * If this property is defined, then it must have a value of either "true" or
   * "false".  If the {@link #PROPERTY_FIPS_PROVIDER} property is also defined,
   * then the specified provider will be used; otherwise, the Bouncy Castle
   * "BCFIPS" provider will be assumed.
   */
  @NotNull public static final String PROPERTY_FIPS_MODE =
       "com.unboundid.crypto.FIPS_MODE";



  /**
   * The name of the Java property (com.unboundid.crypto.FIPS_PROVIDER) that
   * will be used to specify the name of the security provider to use when
   * operating in FIPS-compliant mode.  At present, only the Bouncy Castle
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
  @NotNull public static final String
       PROPERTY_REMOVE_NON_NECESSARY_PROVIDERS =
            "com.unboundid.crypto.REMOVE_NON_ESSENTIAL_PROVIDERS";



  /**
   * The name of the Java property
   * (com.unboundid.crypto.ALLOWED_FIPS_MODE_PROVIDER) whose value may be a
   * comma-delimited list of the fully qualified names of the Java provider
   * classes that will be allowed when the LDAP SDK is running in FIPS-compliant
   * mode.  If defined, these classes will not be removed from the JVM when
   * pruning non-essential providers (whether via the
   * {@link #PROPERTY_REMOVE_NON_NECESSARY_PROVIDERS} property or the
   * {@link #removeNonEssentialSecurityProviders()} method), and calls to
   * methods in this class will allow uses of these providers when running in
   * FIPS-compliant mode.
   */
  @NotNull public static final String PROPERTY_ALLOWED_FIPS_MODE_PROVIDER =
       "com.unboundid.crypto.ALLOWED_FIPS_MODE_PROVIDER";



  /**
   * A set containing the fully qualified names of the Java classes for
   * providers that will be allowed in FIPS-compliant mode.  By default, this
   * will include a set of providers from Oracle, OpenJDK-based, and IBM JVMs.
   * This default set of providers may be augmented using the
   * {@link #PROPERTY_ALLOWED_FIPS_MODE_PROVIDER} property or the
   * {@link #addAllowedFIPSModeProvider} method.
   */
  @NotNull private static final Set<String> ALLOWED_FIPS_MODE_PROVIDERS =
       new CopyOnWriteArraySet<>();



  /**
   * Indicates whether the LDAP SDK should operate in FIPS-compliant mode.
   */
  @NotNull private static final AtomicBoolean FIPS_MODE;



  /**
   * A reference to the provider that offers the main FIPS-compliant
   * functionality, if enabled.
   */
  @NotNull private static final AtomicReference<Provider> FIPS_PROVIDER =
       new AtomicReference<>();



  /**
   * A reference to the provider that offers the JSSE provider for
   * FIPS-compliant functionality.
   */
  @NotNull private static final AtomicReference<Provider>
       FIPS_JSSE_PROVIDER = new AtomicReference<>();



  /**
   * A reference to the default key manager factory algorithm that will be used
   * in FIPS-compliant mode.
   */
  @NotNull private static final AtomicReference<String>
       FIPS_DEFAULT_KEY_MANAGER_FACTORY_ALGORITHM =
            new AtomicReference<>();



  /**
   * A reference to the default key store type that will be used in
   * FIPS-compliant mode, if appropriate.
   */
  @NotNull private static final AtomicReference<String>
       FIPS_DEFAULT_KEY_STORE_TYPE = new AtomicReference<>();



  /**
   * A reference to the default SSL context protocol that will be used in
   * FIPS-compliant mode, if appropriate.
   */
  @NotNull private static final AtomicReference<String>
       FIPS_DEFAULT_SSL_CONTEXT_PROTOCOL = new AtomicReference<>();



  /**
   * A reference to the default SSL context protocol that will be used in
   * FIPS-compliant mode, if appropriate.
   */
  @NotNull private static final AtomicReference<String[]>
       FIPS_ALTERNATIVE_DEFAULT_SSL_CONTEXT_PROTOCOLS = new AtomicReference<>();



  /**
   * A reference to the default trust manager factory algorithm that will be
   * used in FIPS-compliant mode.
   */
  @NotNull private static final AtomicReference<String>
       FIPS_DEFAULT_TRUST_MANAGER_FACTORY_ALGORITHM =
            new AtomicReference<>();



  /**
   * A reference to the name of the provider used to provide FIPS compliance,
   * if applicable.
   */
  @NotNull private static final AtomicReference<String> FIPS_PROVIDER_NAME =
       new AtomicReference<>();
  static
  {
    ALLOWED_FIPS_MODE_PROVIDERS.addAll(StaticUtils.setOf(
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
         "com.ibm.security.sasl.IBMSASL"));

    final String preserveProviderPropertyValue =
         PropertyManager.get(PROPERTY_ALLOWED_FIPS_MODE_PROVIDER);
    if (preserveProviderPropertyValue != null)
    {
      final StringTokenizer tokenizer = new StringTokenizer(
           preserveProviderPropertyValue, ",");
      while (tokenizer.hasMoreTokens())
      {
        final String className = tokenizer.nextToken().trim();
        if (! className.isEmpty())
        {
          ALLOWED_FIPS_MODE_PROVIDERS.add(className);
        }
      }
    }


    final String fipsModePropertyValue =
         PropertyManager.get(PROPERTY_FIPS_MODE);
    if ((fipsModePropertyValue == null) ||
         fipsModePropertyValue.equalsIgnoreCase("false"))
    {
      FIPS_MODE = new AtomicBoolean(false);
      FIPS_PROVIDER_NAME.set(null);
    }
    else if (fipsModePropertyValue.equalsIgnoreCase("true"))
    {
      final String fipsProviderVersionString;
      final String fipsProviderPropertyValue =
           PropertyManager.get(PROPERTY_FIPS_PROVIDER);
      if ((fipsProviderPropertyValue == null) ||
           fipsProviderPropertyValue.equalsIgnoreCase(
                BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME))
      {
        fipsProviderVersionString = null;
        FIPS_PROVIDER_NAME.set(BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME);
      }
      else if (fipsProviderPropertyValue.equalsIgnoreCase(
                BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME +
                     BouncyCastleFIPSHelper.FIPS_PROVIDER_VERSION_1))
      {
        fipsProviderVersionString =
             BouncyCastleFIPSHelper.FIPS_PROVIDER_VERSION_1;
        FIPS_PROVIDER_NAME.set(BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME +
             BouncyCastleFIPSHelper.FIPS_PROVIDER_VERSION_1);
      }
      else if (fipsProviderPropertyValue.equalsIgnoreCase(
                BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME +
                     BouncyCastleFIPSHelper.FIPS_PROVIDER_VERSION_2))
      {
        fipsProviderVersionString =
             BouncyCastleFIPSHelper.FIPS_PROVIDER_VERSION_2;
        FIPS_PROVIDER_NAME.set(BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME +
             BouncyCastleFIPSHelper.FIPS_PROVIDER_VERSION_2);
      }
      else
      {
        fipsProviderVersionString = null;
        FIPS_PROVIDER_NAME.set(null);
        Validator.violation(
             ERR_CRYPTO_HELPER_UNSUPPORTED_FIPS_PROVIDER.get(
                  fipsProviderPropertyValue,
                  BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME));
      }

      FIPS_MODE = new AtomicBoolean(true);
      try
      {
        BouncyCastleFIPSHelper.setPropertiesForPingIdentityServer();
        FIPS_PROVIDER.set(
             BouncyCastleFIPSHelper.loadBouncyCastleFIPSProvider(true,
                  fipsProviderVersionString));
        FIPS_JSSE_PROVIDER.set(
             BouncyCastleFIPSHelper.loadBouncyCastleJSSEProvider(true,
                  fipsProviderVersionString));
        FIPS_DEFAULT_KEY_MANAGER_FACTORY_ALGORITHM.set(
             BouncyCastleFIPSHelper.DEFAULT_KEY_MANAGER_FACTORY_ALGORITHM);
        FIPS_DEFAULT_KEY_STORE_TYPE.set(
             BouncyCastleFIPSHelper.FIPS_KEY_STORE_TYPE);
        FIPS_DEFAULT_SSL_CONTEXT_PROTOCOL.set(
             BouncyCastleFIPSHelper.DEFAULT_SSL_CONTEXT_PROTOCOL);
        FIPS_ALTERNATIVE_DEFAULT_SSL_CONTEXT_PROTOCOLS.set(
             BouncyCastleFIPSHelper.ALTERNATIVE_DEFAULT_SSL_CONTEXT_PROTOCOLS);
        FIPS_DEFAULT_TRUST_MANAGER_FACTORY_ALGORITHM.set(
             BouncyCastleFIPSHelper.DEFAULT_TRUST_MANAGER_FACTORY_ALGORITHM);

        final String prunePropertyValue = PropertyManager.get(
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
        ERR_CRYPTO_HELPER_INSTANTIATION_ERROR_FROM_FIPS_MODE_PROPERTY.
             get(PROPERTY_FIPS_MODE, StaticUtils.getExceptionMessage(e)),
        e);
        FIPS_MODE.set(false);
        FIPS_PROVIDER_NAME.set(null);
      }
    }
    else
    {
      FIPS_MODE = new AtomicBoolean(false);
        FIPS_PROVIDER_NAME.set(null);
      Validator.violation(
           ERR_CRYPTO_HELPER_INVALID_FIPS_MODE_PROPERTY_VALUE.get(
                PROPERTY_FIPS_MODE, fipsModePropertyValue));
    }
  }



  /**
   * The default provider that should be used for JSSE operations, regardless of
   * whether the LDAP SDK is operating in FIPS-compliant mode.
   */
  @NotNull private static final AtomicReference<Provider>
       DEFAULT_JSSE_PROVIDER = new AtomicReference<>();



  /**
   * The key store type value that should be used for BCFKS (Bouncy Castle
   * FIPS-compliant) key stores.
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
  @NotNull private static final AtomicReference<String>
       DEFAULT_KEY_STORE_TYPE;
  static
  {
    final String defaultKeyStoreType;
    final String propertyValue =
         PropertyManager.get(PROPERTY_DEFAULT_KEY_STORE_TYPE);
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
   * Indicates whether the LDAP SDK should operate in a strict FIPS-compliant
   * mode.
   *
   * @return  {@code true} if the LDAP SDK should operate in a strict
   *          FIPS-compliant mode, or {@code false} if not.
   */
  public static boolean usingFIPSMode()
  {
    return FIPS_MODE.get();
  }



  /**
   * Retrieves the name of the security provider used to provide FIPS
   * compliance, if applicable.
   *
   * @return  The name of the security provider used to provide FIPS compliance,
   *          or {@code null} if the LDAP SDK is not operating in FIPS-compliant
   *          mode.
   */
  @Nullable()
  public static String getFIPSModeProviderName()
  {
    return FIPS_PROVIDER_NAME.get();
  }



  /**
   * Specifies whether the LDAP SDK should operate in a strict FIPS-compliant
   * mode.  If the LDAP SDK should operate in FIPS mode, then the Bouncy Castle
   * FIPS provider will be used by default.
   *
   * @param  useFIPSMode  Indicates whether the LDAP SDK should operate in a
   *                      strict FIPS-compliant mode.
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
      FIPS_PROVIDER_NAME.set(null);
    }
  }



  /**
   * Specifies that the LDAP SDK should operate in a strict FIPS-compliant mode
   * using the specified provider.
   *
   * @param  providerName  The name of the security provider to use to provide
   *                       the FIPS-compliant functionality.  At present, only
   *                       the Bouncy Castle "BCFIPS" provider is supported.
   *                       However, you may optionally append a version string
   *                       to indicate which version of the provider to use,
   *                       with a provider name of "BCFIPS1" indicating that
   *                       version 1.x of the BCFIPS provider (which supports
   *                       FIPS 140-2 compliance) should be used, and
   *                       "BCFIPS2" indicates that version 2.x of the BCFIPS
   *                       provider (which supports FIPS 140-3 compliance)
   *                       should be used.
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
      FIPS_PROVIDER_NAME.set(BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME);
    }
    else if (providerName.equalsIgnoreCase(
         BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME +
              BouncyCastleFIPSHelper.FIPS_PROVIDER_VERSION_1))
    {
      fipsProvider = BouncyCastleFIPSHelper.loadBouncyCastleFIPSProvider(true,
                BouncyCastleFIPSHelper.FIPS_PROVIDER_VERSION_1);
      jsseProvider = BouncyCastleFIPSHelper.loadBouncyCastleJSSEProvider(true,
           BouncyCastleFIPSHelper.FIPS_PROVIDER_VERSION_1);
      FIPS_PROVIDER_NAME.set(BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME +
           BouncyCastleFIPSHelper.FIPS_PROVIDER_VERSION_1);
    }
    else if (providerName.equalsIgnoreCase(
         BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME +
              BouncyCastleFIPSHelper.FIPS_PROVIDER_VERSION_2))
    {
      fipsProvider = BouncyCastleFIPSHelper.loadBouncyCastleFIPSProvider(true,
                BouncyCastleFIPSHelper.FIPS_PROVIDER_VERSION_2);
      jsseProvider = BouncyCastleFIPSHelper.loadBouncyCastleJSSEProvider(true,
           BouncyCastleFIPSHelper.FIPS_PROVIDER_VERSION_2);
      FIPS_PROVIDER_NAME.set(BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME +
           BouncyCastleFIPSHelper.FIPS_PROVIDER_VERSION_2);
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
    FIPS_ALTERNATIVE_DEFAULT_SSL_CONTEXT_PROTOCOLS.set(
         BouncyCastleFIPSHelper.ALTERNATIVE_DEFAULT_SSL_CONTEXT_PROTOCOLS);
    FIPS_DEFAULT_TRUST_MANAGER_FACTORY_ALGORITHM.set(
         BouncyCastleFIPSHelper.DEFAULT_TRUST_MANAGER_FACTORY_ALGORITHM);
    FIPS_MODE.set(true);

    TLSCipherSuiteSelector.recompute();
  }



  /**
   * Retrieves an unmodifiable set containing the fully qualified names of the
   * Java provider classes that will be allowed when the LDAP SDK is operating
   * in FIPS-compliant mode.  This also represents the set of providers
   * that will be preserved when calling the
   * {@link #removeNonEssentialSecurityProviders()} method.
   *
   * @return  An unmodifiable set containing the fully qualified names of the
   *          Java provider classes that will be allowed when the LDAP SDK is
   *          operating in FIPS-compliant mode.
   */
  @NotNull()
  public static Set<String> getAllowedFIPSModeProviders()
  {
    return Collections.unmodifiableSet(ALLOWED_FIPS_MODE_PROVIDERS);
  }



  /**
   * Adds the specified class to the set of allowed Java provider classes that
   * will be allowed when the LDAP SDK is operating in FIPS-complaint mode.
   *
   * @param  providerClass  The fully qualified name of a Java class that
   *                        references a provider that will be allowed when the
   *                        LDAP SDK is operating in FIPS-compliant mode.
   */
  public static void addAllowedFIPSModeProvider(
              @NotNull final String providerClass)
  {
    ALLOWED_FIPS_MODE_PROVIDERS.add(providerClass);
  }



  /**
   * Attempts to remove any security providers that are not believed to be
   * needed when operating in FIPS-compliant mode.  Note that this method
   * assumes the use of an Oracle or OpenJDK-based JVM and may not work as
   * expected in JVMs from other vendors that may have a different set of
   * essential providers.
   */
  public static void removeNonEssentialSecurityProviders()
  {
    for (final Provider provider : Security.getProviders())
    {
      if (! ALLOWED_FIPS_MODE_PROVIDERS.contains(
           provider.getClass().getName()))
      {
        Security.removeProvider(provider.getName());
      }
    }
  }



  /**
   * Specifies the default provider that should be used for JSSE operations,
   * regardless of whether the LDAP SDK is operating in FIPS-compliant mode.
   *
   * @param  defaultJSSEProvider  The default provider that should be used for
   *                              JSSE operations, regardless of whether the
   *                              LDAP SDK is operating in FIPS-compliant mode.
   */
  public static void setDefaultJSSEProvider(
              @NotNull final Provider defaultJSSEProvider)
  {
    Validator.ensureNotNull(defaultJSSEProvider);
    DEFAULT_JSSE_PROVIDER.set(defaultJSSEProvider);

    // If the LDAP SDK is running in FIPS-compliant mode, then give the new
    // provider the second-highest priority.  Otherwise, give it the highest
    // priority.
    if (usingFIPSMode())
    {
      Security.insertProviderAt(defaultJSSEProvider, 2);
    }
    else
    {
      Security.insertProviderAt(defaultJSSEProvider, 1);
    }

    TLSCipherSuiteSelector.recompute();
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
    return getCertificateFactory(type,  getProvider(providerName));
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
      final String providerClass = provider.getClass().getName();
      if (! ALLOWED_FIPS_MODE_PROVIDERS.contains(providerClass))
      {
        throw new CertificateException(
        ERR_CRYPTO_HELPER_GET_CERT_FACTORY_WRONG_PROVIDER_FOR_FIPS_MODE.
             get(type, providerClass,
                  StaticUtils.concatenateStrings(new ArrayList<>(
                       ALLOWED_FIPS_MODE_PROVIDERS))));
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
    return getCipher(cipherTransformation, getProvider(providerName));
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
    // NOTE:  While the standard Java JCA allows "AES/GCM/PKCS5Padding" and
    // treats it as equivalent to "AES/GCM/NoPadding", some other providers
    // (including the Bouncy Castle FIPS provider) do not accept the former.
    // Although the LDAP SDK does not directly use the "AES/GCM/PKCS5Padding",
    // there are known cases in which something using the LDAP SDK has used that
    // cipher transformation.  For best compatibility, automatically convert
    // "AES/GCM/PKCS5Padding" into "AES/GCM/NoPadding".
    final String transformation;
    if (cipherTransformation.equalsIgnoreCase("AES/GCM/PKCS5Padding"))
    {
      transformation = "AES/GCM/NoPadding";
    }
    else
    {
      transformation = cipherTransformation;
    }

    if (provider == null)
    {
      if (usingFIPSMode())
      {
        return Cipher.getInstance(transformation, FIPS_PROVIDER.get());
      }
      else
      {
        return Cipher.getInstance(transformation);
      }
    }

    if (usingFIPSMode())
    {
      final String providerClass = provider.getClass().getName();
      if (! ALLOWED_FIPS_MODE_PROVIDERS.contains(providerClass))
      {
        throw new NoSuchAlgorithmException(
        ERR_CRYPTO_HELPER_GET_CIPHER_WRONG_PROVIDER_FOR_FIPS_MODE.get(
             transformation, providerClass,
             StaticUtils.concatenateStrings(new ArrayList<>(
                  ALLOWED_FIPS_MODE_PROVIDERS))));
      }
    }

    return Cipher.getInstance(transformation, provider);
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
    return getKeyFactory(algorithmName, getProvider(providerName));
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
      final String providerClass = provider.getClass().getName();
      if (! ALLOWED_FIPS_MODE_PROVIDERS.contains(providerClass))
      {
        throw new NoSuchAlgorithmException(
        ERR_CRYPTO_HELPER_GET_KEY_FACTORY_WRONG_PROVIDER_FOR_FIPS_MODE.
             get(algorithmName, providerClass,
                  StaticUtils.concatenateStrings(new ArrayList<>(
                       ALLOWED_FIPS_MODE_PROVIDERS))));
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
    final Provider defaultJSSEProvider = DEFAULT_JSSE_PROVIDER.get();
    if (defaultJSSEProvider != null)
    {
      // See if the provider supports the default key manager factory algorithm.
      NoSuchAlgorithmException noSuchAlgorithmException = null;
      final String defaultAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
      try
      {
        return KeyManagerFactory.getInstance(defaultAlgorithm,
             defaultJSSEProvider);
      }
      catch (final NoSuchAlgorithmException e)
      {
        Debug.debugException(e);
        noSuchAlgorithmException = e;
      }


      // If we have a FIPS-default key manager factory algorithm, then try that.
      final String fipsDefaultAlgorithm =
           FIPS_DEFAULT_KEY_MANAGER_FACTORY_ALGORITHM.get();
      if (fipsDefaultAlgorithm != null)
      {
        try
        {
          return KeyManagerFactory.getInstance(fipsDefaultAlgorithm,
               defaultJSSEProvider);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }

      for (final Provider.Service service : defaultJSSEProvider.getServices())
      {
        if (service.getType().equalsIgnoreCase("KeyManagerFactory"))
        {
          return KeyManagerFactory.getInstance(service.getAlgorithm(),
               defaultJSSEProvider);
        }
      }

      throw noSuchAlgorithmException;
    }

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
    return getKeyManagerFactory(algorithmName, getProvider(providerName));
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
      final Provider defaultJSSEProvider = DEFAULT_JSSE_PROVIDER.get();
      if (defaultJSSEProvider != null)
      {
        return KeyManagerFactory.getInstance(algorithmName,
             defaultJSSEProvider);
      }

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
      final String providerClass = provider.getClass().getName();
      if (! ALLOWED_FIPS_MODE_PROVIDERS.contains(providerClass))
      {
        throw new NoSuchAlgorithmException(
        ERR_CRYPTO_HELPER_GET_KM_FACTORY_WRONG_PROVIDER_FOR_FIPS_MODE.
             get(algorithmName, providerClass,
                  StaticUtils.concatenateStrings(new ArrayList<>(
                       ALLOWED_FIPS_MODE_PROVIDERS))));
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
    return getKeyPairGenerator(algorithmName, getProvider(providerName));
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
        return KeyPairGenerator.getInstance(algorithmName,
             FIPS_PROVIDER.get());
      }
      else
      {
        return KeyPairGenerator.getInstance(algorithmName);
      }
    }

    if (usingFIPSMode())
    {
      final String providerClass = provider.getClass().getName();
      if (! ALLOWED_FIPS_MODE_PROVIDERS.contains(providerClass))
      {
        throw new NoSuchAlgorithmException(
        ERR_CRYPTO_HELPER_GET_KP_GEN_WRONG_PROVIDER_FOR_FIPS_MODE.get(
             algorithmName, providerClass,
             StaticUtils.concatenateStrings(new ArrayList<>(
                  ALLOWED_FIPS_MODE_PROVIDERS))));
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
   * Attempts to automatically determine the type of key store that the
   * specified file represents.  This method supports JKS, PKCS #12, and BCFKS
   * key store types.
   *
   * @param  keyStoreFile  The key store file to examine.  It must not be
   *                       {@code null}, and the file must exist.
   *
   * @return  The inferred key store type for the specified key store.
   *
   * @throws  KeyStoreException  If the key store type cannot be inferred.
   */
  @NotNull()
  public static String inferKeyStoreType(@NotNull final File keyStoreFile)
         throws KeyStoreException
  {
    if (! keyStoreFile.exists())
    {
      throw new KeyStoreException(
           ERR_CRYPTO_HELPER_INFER_KS_TYPE_NO_SUCH_FILE.get(
                keyStoreFile.getAbsolutePath()));
    }

    try (FileInputStream fis = new FileInputStream(keyStoreFile);
         BufferedInputStream bis = new BufferedInputStream(fis))
    {
      // Read the first byte from the file.  Set a mark so that we can back up
      // and re-read it if we need to make a more complete determination.
      bis.mark(1);
      final int firstByte = bis.read();
      bis.reset();


      // If the file is empty, then that's an error.
      if (firstByte < 0)
      {
        throw new KeyStoreException(
             ERR_CRYPTO_HELPER_INFER_KS_TYPE_EMPTY_FILE.get(
                  keyStoreFile.getAbsolutePath()));
      }


      // If the first byte is 0xFE, then assume a key store type of JKS, since
      // JKS key stores should start with 0xFEEDFEED.
      if (firstByte == 0xFE)
      {
        return KEY_STORE_TYPE_JKS;
      }


      // If the first byte is 0x30, then that suggests it may be either a
      // PKCS #12 key store or a BCFKS key store, both of which are DER-encoded.
      // Try to read the contents of the file as an ASN.1 element.  If it's a
      // PKCS #12 key store, then the first element of the sequence should be
      // an integer with a value of 3.  If it's a BCFKS key store, then the
      // first element of the sequence will be another sequence.
      if (firstByte == 0x30)
      {
        try (ASN1StreamReader asn1StreamReader = new ASN1StreamReader(bis))
        {
          final ASN1StreamReaderSequence sequenceHeader =
               asn1StreamReader.beginSequence();
          if (sequenceHeader.hasMoreElements())
          {
            final int firstSequenceElementType = asn1StreamReader.peek();
            if (firstSequenceElementType ==
                 ASN1Constants.UNIVERSAL_INTEGER_TYPE)
            {
              final int intValue = asn1StreamReader.readInteger();
              if (intValue == 3)
              {
                return KEY_STORE_TYPE_PKCS_12;
              }
            }
            else if (firstSequenceElementType ==
                 ASN1Constants.UNIVERSAL_SEQUENCE_TYPE)
            {
              return KEY_STORE_TYPE_BCFKS;
            }
          }
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }


      // If we've gotten here, then we can't infer the key store type.
      throw new KeyStoreException(
           ERR_CRYPTO_HELPER_INFER_KS_TYPE_UNRECOGNIZED.get(
                keyStoreFile.getAbsolutePath()));
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
           ERR_CRYPTO_HELPER_INFER_KS_TYPE_READ_ERROR.get(
                keyStoreFile.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
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
    return getKeyStore(keyStoreType, getProvider(providerName));
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
        ERR_CRYPTO_HELPER_GET_KEY_STORE_WRONG_STORE_TYPE_FOR_FIPS_MODE.
             get(keyStoreType, KEY_STORE_TYPE_BCFKS,
                  KEY_STORE_TYPE_PKCS_11));
      }

      if (provider != null)
      {
        final String providerClass = provider.getClass().getName();
        if (! ALLOWED_FIPS_MODE_PROVIDERS.contains(providerClass))
        {
          throw new KeyStoreException(
          ERR_CRYPTO_HELPER_GET_KEY_STORE_WRONG_PROVIDER_FOR_FIPS_MODE.
               get(keyStoreType, providerClass,
                    StaticUtils.concatenateStrings(new ArrayList<>(
                         ALLOWED_FIPS_MODE_PROVIDERS))));
        }
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
    return getMAC(algorithmName, getProvider(providerName));
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
      final String providerClass = provider.getClass().getName();
      if (! ALLOWED_FIPS_MODE_PROVIDERS.contains(providerClass))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_MAC_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                  algorithmName, providerClass,
                  StaticUtils.concatenateStrings(new ArrayList<>(
                       ALLOWED_FIPS_MODE_PROVIDERS))));
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
    return getMessageDigest(algorithmName, getProvider(providerName));
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
      final String providerClass = provider.getClass().getName();
      if (! ALLOWED_FIPS_MODE_PROVIDERS.contains(providerClass))
      {
        throw new NoSuchAlgorithmException(
        ERR_CRYPTO_HELPER_GET_DIGEST_WRONG_PROVIDER_FOR_FIPS_MODE.get(
             algorithmName, providerClass,
             StaticUtils.concatenateStrings(new ArrayList<>(
                  ALLOWED_FIPS_MODE_PROVIDERS))));
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
    return getSecretKeyFactory(algorithmName, getProvider(providerName));
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
        return SecretKeyFactory.getInstance(algorithmName,
             FIPS_PROVIDER.get());
      }
      else
      {
        return SecretKeyFactory.getInstance(algorithmName);
      }
    }

    if (usingFIPSMode())
    {
      final String providerClass = provider.getClass().getName();
      if (! ALLOWED_FIPS_MODE_PROVIDERS.contains(providerClass))
      {
        throw new NoSuchAlgorithmException(
        ERR_CRYPTO_HELPER_GET_SK_FACTORY_WRONG_PROVIDER_FOR_FIPS_MODE.
             get(algorithmName, providerClass,
                  StaticUtils.concatenateStrings(new ArrayList<>(
                       ALLOWED_FIPS_MODE_PROVIDERS))));
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
    return getSecureRandom(algorithmName, getProvider(providerName));
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
        final String providerClass = provider.getClass().getName();
        if (! ALLOWED_FIPS_MODE_PROVIDERS.contains(providerClass))
        {
          throw new NoSuchAlgorithmException(
          ERR_CRYPTO_HELPER_GET_SEC_RAND_WRONG_PROVIDER_FOR_FIPS_MODE.
               get(algorithmName, providerClass,
                    StaticUtils.concatenateStrings(new ArrayList<>(
                         ALLOWED_FIPS_MODE_PROVIDERS))));
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
ERR_CRYPTO_HELPER_GET_SEC_RAND_WRONG_PROVIDER_FOR_FIPS_MODE_NO_ALG.get(
     providerName, FIPS_PROVIDER.get().getName()));
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
    return getSignature(algorithmName, getProvider(providerName));
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
      final String providerClass = provider.getClass().getName();
      if (! ALLOWED_FIPS_MODE_PROVIDERS.contains(providerClass))
      {
        throw new NoSuchAlgorithmException(
        ERR_CRYPTO_HELPER_GET_SIGNATURE_WRONG_PROVIDER_FOR_FIPS_MODE.
             get(algorithmName, providerClass,
                  StaticUtils.concatenateStrings(new ArrayList<>(
                       ALLOWED_FIPS_MODE_PROVIDERS))));
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
    final Provider defaultJSSEProvider = DEFAULT_JSSE_PROVIDER.get();
    if (defaultJSSEProvider != null)
    {
      final SSLContext defaultContext = SSLContext.getDefault();
      if (defaultContext.getProvider().equals(defaultJSSEProvider))
      {
        return defaultContext;
      }

      for (final Provider.Service service : defaultJSSEProvider.getServices())
      {
        if (service.getType().equalsIgnoreCase("SSLContext") &&
             service.getAlgorithm().equalsIgnoreCase("default"))
        {
          return SSLContext.getInstance(service.getAlgorithm(),
               defaultJSSEProvider);
        }
      }
    }

    if (usingFIPSMode())
    {
      try
      {
        return SSLContext.getInstance(FIPS_DEFAULT_SSL_CONTEXT_PROTOCOL.get(),
             FIPS_JSSE_PROVIDER.get());
      }
      catch (final NoSuchAlgorithmException e)
      {
        Debug.debugException(e);

        // NOTE:  It sees like in later versions of Java (like Java 17), the
        // above call to SSLContext.getInstance will fail with an instance name
        // of DEFAULT.  As a fallback, try using some common, secure TLS
        // protocols with a JVM-default trust manager.
        for (final String protocol :
             FIPS_ALTERNATIVE_DEFAULT_SSL_CONTEXT_PROTOCOLS.get())
        {
          try
          {
            final SSLContext context = SSLContext.getInstance(protocol,
                 FIPS_JSSE_PROVIDER.get());
            final TrustManager[] defaultTrustManagers =
            {
              JVMDefaultTrustManager.getInstance()
            };
            context.init(null, defaultTrustManagers, getSecureRandom());
            return context;
          }
          catch (final Exception e2)
          {
            Debug.debugException(e2);
          }
        }

        throw e;
      }
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
    return getSSLContext(protocol, getProvider(providerName));
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
      final Provider defaultJSSEProvider = DEFAULT_JSSE_PROVIDER.get();
      if (defaultJSSEProvider != null)
      {
        return SSLContext.getInstance(protocol, defaultJSSEProvider);
      }

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
      final String providerClass = provider.getClass().getName();
      if (! ALLOWED_FIPS_MODE_PROVIDERS.contains(providerClass))
      {
        throw new NoSuchAlgorithmException(
        ERR_CRYPTO_HELPER_GET_SSL_CONTEXT_WRONG_PROVIDER_FOR_FIPS_MODE.
             get(protocol, providerClass,
                  StaticUtils.concatenateStrings(new ArrayList<>(
                       ALLOWED_FIPS_MODE_PROVIDERS))));
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
    final Provider defaultJSSEProvider = DEFAULT_JSSE_PROVIDER.get();
    if (defaultJSSEProvider != null)
    {
      // See if the provider supports the default trust manager factory
      // algorithm.
      NoSuchAlgorithmException noSuchAlgorithmException = null;
      final String defaultAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
      try
      {
        return TrustManagerFactory.getInstance(defaultAlgorithm,
             defaultJSSEProvider);
      }
      catch (final NoSuchAlgorithmException e)
      {
        Debug.debugException(e);
        noSuchAlgorithmException = e;
      }


      // If we have a FIPS-default trust manager factory algorithm, then try
      // that.
      final String fipsDefaultAlgorithm =
           FIPS_DEFAULT_TRUST_MANAGER_FACTORY_ALGORITHM.get();
      if (fipsDefaultAlgorithm != null)
      {
        try
        {
          return TrustManagerFactory.getInstance(fipsDefaultAlgorithm,
               defaultJSSEProvider);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }

      for (final Provider.Service service : defaultJSSEProvider.getServices())
      {
        if (service.getType().equalsIgnoreCase("TrustManagerFactory"))
        {
          return TrustManagerFactory.getInstance(service.getAlgorithm(),
               defaultJSSEProvider);
        }
      }

      throw noSuchAlgorithmException;
    }


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
    return getTrustManagerFactory(algorithmName, getProvider(providerName));
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
      final Provider defaultJSSEProvider = DEFAULT_JSSE_PROVIDER.get();
      if (defaultJSSEProvider != null)
      {
        return TrustManagerFactory.getInstance(algorithmName,
             defaultJSSEProvider);
      }

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
      final String providerClass = provider.getClass().getName();
      if (! ALLOWED_FIPS_MODE_PROVIDERS.contains(providerClass))
      {
        throw new NoSuchAlgorithmException(
        ERR_CRYPTO_HELPER_GET_TM_FACTORY_WRONG_PROVIDER_FOR_FIPS_MODE.
             get(algorithmName, providerClass,
                  StaticUtils.concatenateStrings(new ArrayList<>(
                       ALLOWED_FIPS_MODE_PROVIDERS))));
      }
    }

    return TrustManagerFactory.getInstance(algorithmName, provider);
  }



  /**
   * Retrieves a randomly generated UUID.
   *
   * @return  A randomly generated UUID.
   */
  @NotNull()
  public static UUID getRandomUUID()
  {
    if (usingFIPSMode())
    {
      // Generate 128 bits of random data, and then transform it to conform to
      // the UUID specification in RFC 4122.  This includes:
      // * The four most significant bits of the seventh byte specify the
      //   version.  Random UUIDs should have variant bits of 0b0100.
      // * The two most significant bits of the ninth byte specify the variant.
      //   RFC 4122 indicates that the variant bits should be 0b10.
      final byte[] uuidBytes = new byte[16];
      ThreadLocalSecureRandom.get().nextBytes(uuidBytes);
      uuidBytes[6] = (byte) ((uuidBytes[6] & 0x0F) | 0x40);
      uuidBytes[8] = (byte) ((uuidBytes[8] & 0x3F) | 0x80);

      return uuidFromBytes(uuidBytes);
    }
    else
    {
      return UUID.randomUUID();
    }
  }



  /**
   * Retrieves a name-based UUID generated from the provided set of bytes.
   *
   * @param  name  The bytes that comprise the name to use to generate the UUID.
   *               It must not be {@code null}.
   *
   * @return  A randomly generated UUID.
   */
  @NotNull()
  public static UUID getNameUUIDFromBytes(@NotNull final byte[] name)
  {
    if (usingFIPSMode())
    {
      try
      {
        // Compute a SHA-256 digest of the provided name.
        final MessageDigest sha256 = getMessageDigest("SHA-256");
        final byte[] digestBytes = sha256.digest(name);

        // The first 16 bytes of the digest will be the UUID.  Transform it to
        // conform to the UUID specification in RFC 4122.  This includes:
        // * The four most significant bits of the seventh byte specify the
        //   version.  Name-based UUIDs should have variant bits of 0b0011.
        // * The two most significant bits of the ninth byte specify the
        //   variant.  RFC 4122 indicates that the variant bits should be 0b10.
        digestBytes[6] = (byte) ((digestBytes[6] & 0x0F) | 0x30);
        digestBytes[8] = (byte) ((digestBytes[8] & 0x3F) | 0x80);

        return uuidFromBytes(digestBytes);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new RuntimeException(e);
      }
    }
    else
    {
      return UUID.nameUUIDFromBytes(name);
    }
  }



  /**
   * Creates a UUID from the provided set of bytes.
   *
   * @param  uuidBytes  The bytes that comprise the UUID to create.  It must not
   *                    be {@code null} and must be at least 16 bytes long with
   *                    the first 16 bytes containing the data to use to create
   *                    the UUID.
   *
   * @return  The UUID created from the provided bytes.
   */
  @NotNull()
  private static UUID uuidFromBytes(@NotNull final byte[] uuidBytes)
  {
    final long mostSignificantBits =
         ((uuidBytes[0] & 0xFFL) << 56) |
         ((uuidBytes[1] & 0xFFL) << 48) |
         ((uuidBytes[2] & 0xFFL) << 40) |
         ((uuidBytes[3] & 0xFFL) << 32) |
         ((uuidBytes[4] & 0xFFL) << 24) |
         ((uuidBytes[5] & 0xFFL) << 16) |
         ((uuidBytes[6] & 0xFFL) << 8) |
         (uuidBytes[7] & 0xFFL);
    final long leastSignificantBits =
         ((uuidBytes[8] & 0xFFL) << 56) |
         ((uuidBytes[9] & 0xFFL) << 48) |
         ((uuidBytes[10] & 0xFFL) << 40) |
         ((uuidBytes[11] & 0xFFL) << 32) |
         ((uuidBytes[12] & 0xFFL) << 24) |
         ((uuidBytes[13] & 0xFFL) << 16) |
         ((uuidBytes[14] & 0xFFL) << 8) |
         (uuidBytes[15] & 0xFFL);
    return new UUID(mostSignificantBits, leastSignificantBits);
  }



  /**
   * Retrieves the provider instance with the specified name.
   *
   * @param  providerName  The name of the provider to retrieve.  It may be
   *                       {@code null} if a default provider should be used.
   *
   * @return  The provider with the specified name, or {@code null} if the
   *          given provider name was {@code null}.
   *
   * @throws  NoSuchProviderException  If the specified provider is not
   *                                   available.
   */
  @Nullable()
  private static Provider getProvider(@Nullable final String providerName)
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
      final Provider provider = Security.getProvider(providerName);
      if (provider == null)
      {
        throw new NoSuchProviderException(
             ERR_CRYPTO_HELPER_NO_SUCH_PROVIDER.get(providerName));
      }

      if (usingFIPSMode())
      {
        final String providerClass = provider.getClass().getName();
        if (! ALLOWED_FIPS_MODE_PROVIDERS.contains(providerClass))
        {
          throw new NoSuchProviderException(
               ERR_CRYPTO_HELPER_PROVIDER_NOT_AVAILABLE_IN_FIPS_MODE.get(
                    providerClass,
                    StaticUtils.concatenateStrings(new ArrayList<>(
                         ALLOWED_FIPS_MODE_PROVIDERS))));
        }
      }

      return provider;
    }
  }



  /**
   * Generates a digest of the provided bytes using the specified algorithm.
   *
   * @param  digestAlgorithm  The name of the algorithm to use to generate the
   *                          digest.  It must not be {@code null}.
   * @param  dataToDigest     The bytes for which to generate the digest.  It
   *                          must not be {@code null} but may be empty.
   *
   * @return  The bytes that comprise the digest of the provided bytes.
   *
   * @throws  NoSuchAlgorithmException  If the JVM does not support the
   *                                    requested digest algorithm.
   */
  @NotNull()
  public static byte[] digest(@NotNull final String digestAlgorithm,
                              @NotNull final byte[] dataToDigest)
         throws NoSuchAlgorithmException
  {
    final MessageDigest digest = getMessageDigest(digestAlgorithm);
    return digest.digest(dataToDigest);
  }



  /**
   * Generates a digest of the UTF-8 representation of the provided string
   * using the specified algorithm.
   *
   * @param  digestAlgorithm  The name of the algorithm to use to generate the
   *                          digest.  It must not be {@code null}.
   * @param  dataToDigest     The string for which to generate the digest.  It
   *                          must not be {@code null} but may be empty.
   *
   * @return  The bytes that comprise the digest of the provided string.
   *
   * @throws  NoSuchAlgorithmException  If the JVM does not support the
   *                                    requested digest algorithm.
   */
  @NotNull()
  public static byte[] digest(@NotNull final String digestAlgorithm,
                              @NotNull final String dataToDigest)
         throws NoSuchAlgorithmException
  {
    final MessageDigest digest = getMessageDigest(digestAlgorithm);
    return digest.digest(StaticUtils.getBytes(dataToDigest));
  }



  /**
   * Generates a digest of the contents of the provided file using the specified
   * algorithm.
   *
   * @param  digestAlgorithm  The name of the algorithm to use to generate the
   *                          digest.  It must not be {@code null}.
   * @param  fileToDigest     The file for which to generate the digest.  It
   *                          must not be {@code null}, and the file must exist.
   *
   * @return  The bytes that comprise the digest of the provided file.
   *
   * @throws  NoSuchAlgorithmException  If the JVM does not support the
   *                                    requested digest algorithm.
   *
   * @throws  java.io.IOException  If a problem occurs while trying to read from
   *                               the file.
   */
  @NotNull()
  public static byte[] digest(@NotNull final String digestAlgorithm,
                              @NotNull final File fileToDigest)
         throws NoSuchAlgorithmException, java.io.IOException
  {
    try (FileInputStream inputStream = new FileInputStream(fileToDigest))
    {
      final MessageDigest digest = getMessageDigest(digestAlgorithm);
      final byte[] buffer = new byte[1048576];
      while (true)
      {
        final int bytesRead = inputStream.read(buffer);
        if (bytesRead < 0)
        {
          return digest.digest();
        }
        else
        {
          digest.update(buffer, 0, bytesRead);
        }
      }
    }
  }



  /**
   * Generates a SHA-256 digest of the provided bytes.
   *
   * @param  dataToDigest  The bytes for which to generate the digest.  It must
   *                       not be {@code null} but may be empty.
   *
   * @return  The bytes that comprise the SHA-256 digest of the provided bytes.
   *
   * @throws  NoSuchAlgorithmException  If the JVM does not support the SHA-256
   *                                    digest algorithm.
   */
  @NotNull()
  public static byte[] sha256(@NotNull final byte[] dataToDigest)
         throws NoSuchAlgorithmException
  {
    return CryptoHelper.digest("SHA-256", dataToDigest);
  }



  /**
   * Generates a SHA-256 digest of the UTF-8 representation of the provided
   * string.
   *
   * @param  dataToDigest  The string for which to generate the digest.  It must
   *                       not be {@code null} but may be empty.
   *
   * @return  The bytes that comprise the SHA-256 digest of the provided string.
   *
   * @throws  NoSuchAlgorithmException  If the JVM does not support the SHA-256
   *                                    digest algorithm.
   */
  @NotNull()
  public static byte[] sha256(@NotNull final String dataToDigest)
         throws NoSuchAlgorithmException
  {
    return CryptoHelper.digest("SHA-256", dataToDigest);
  }



  /**
   * Generates a SHA-256 digest of the contents of the provided file.
   *
   * @param  fileToDigest  The file for which to generate the digest.  It must
   *                       not be {@code null}, and the file must exist.
   *
   * @return  The bytes that comprise the SHA-256 digest of the provided file.
   *
   * @throws  NoSuchAlgorithmException  If the JVM does not support the SHA-256
   *                                    digest algorithm.
   *
   * @throws  java.io.IOException  If a problem occurs while trying to read from
   *                               the file.
   */
  @NotNull()
  public static byte[] sha256(@NotNull final File fileToDigest)
         throws NoSuchAlgorithmException, java.io.IOException
  {
    return CryptoHelper.digest("SHA-256", fileToDigest);
  }



  /**
   * Generates a SHA-384 digest of the provided bytes.
   *
   * @param  dataToDigest  The bytes for which to generate the digest.  It must
   *                       not be {@code null} but may be empty.
   *
   * @return  The bytes that comprise the SHA-384 digest of the provided bytes.
   *
   * @throws  NoSuchAlgorithmException  If the JVM does not support the SHA-384
   *                                    digest algorithm.
   */
  @NotNull()
  public static byte[] sha384(@NotNull final byte[] dataToDigest)
         throws NoSuchAlgorithmException
  {
    return CryptoHelper.digest("SHA-384", dataToDigest);
  }



  /**
   * Generates a SHA-384 digest of the UTF-8 representation of the provided
   * string.
   *
   * @param  dataToDigest  The string for which to generate the digest.  It must
   *                       not be {@code null} but may be empty.
   *
   * @return  The bytes that comprise the SHA-384 digest of the provided string.
   *
   * @throws  NoSuchAlgorithmException  If the JVM does not support the SHA-384
   *                                    digest algorithm.
   */
  @NotNull()
  public static byte[] sha384(@NotNull final String dataToDigest)
         throws NoSuchAlgorithmException
  {
    return CryptoHelper.digest("SHA-384", dataToDigest);
  }



  /**
   * Generates a SHA-384 digest of the contents of the provided file.
   *
   * @param  fileToDigest  The file for which to generate the digest.  It must
   *                       not be {@code null}, and the file must exist.
   *
   * @return  The bytes that comprise the SHA-384 digest of the provided file.
   *
   * @throws  NoSuchAlgorithmException  If the JVM does not support the SHA-384
   *                                    digest algorithm.
   *
   * @throws  java.io.IOException  If a problem occurs while trying to read from
   *                               the file.
   */
  @NotNull()
  public static byte[] sha384(@NotNull final File fileToDigest)
         throws NoSuchAlgorithmException, java.io.IOException
  {
    return CryptoHelper.digest("SHA-384", fileToDigest);
  }



  /**
   * Generates a SHA-512 digest of the provided bytes.
   *
   * @param  dataToDigest  The bytes for which to generate the digest.  It must
   *                       not be {@code null} but may be empty.
   *
   * @return  The bytes that comprise the SHA-512 digest of the provided bytes.
   *
   * @throws  NoSuchAlgorithmException  If the JVM does not support the SHA-512
   *                                    digest algorithm.
   */
  @NotNull()
  public static byte[] sha512(@NotNull final byte[] dataToDigest)
         throws NoSuchAlgorithmException
  {
    return CryptoHelper.digest("SHA-512", dataToDigest);
  }



  /**
   * Generates a SHA-512 digest of the UTF-8 representation of the provided
   * string.
   *
   * @param  dataToDigest  The string for which to generate the digest.  It must
   *                       not be {@code null} but may be empty.
   *
   * @return  The bytes that comprise the SHA-512 digest of the provided string.
   *
   * @throws  NoSuchAlgorithmException  If the JVM does not support the SHA-512
   *                                    digest algorithm.
   */
  @NotNull()
  public static byte[] sha512(@NotNull final String dataToDigest)
         throws NoSuchAlgorithmException
  {
    return CryptoHelper.digest("SHA-512", dataToDigest);
  }



  /**
   * Generates a SHA-512 digest of the contents of the provided file.
   *
   * @param  fileToDigest  The file for which to generate the digest.  It must
   *                       not be {@code null}, and the file must exist.
   *
   * @return  The bytes that comprise the SHA-512 digest of the provided file.
   *
   * @throws  NoSuchAlgorithmException  If the JVM does not support the SHA-512
   *                                    digest algorithm.
   *
   * @throws  java.io.IOException  If a problem occurs while trying to read from
   *                               the file.
   */
  @NotNull()
  public static byte[] sha512(@NotNull final File fileToDigest)
         throws NoSuchAlgorithmException, java.io.IOException
  {
    return CryptoHelper.digest("SHA-512", fileToDigest);
  }
}
