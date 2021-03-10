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
   * The name of the Java system property that will be used to indicate that the
   * LDAP SDK should operate in FIPS 140-2-compliant mode.  If this property is
   * defined, then it must have a value of either "true" or "false".
   */
  @NotNull public static final String PROPERTY_NAME_FIPS_MODE =
       "com.unboundid.crypto.FIPS_MODE";



  /**
   * Indicates whether the LDAP SDK should operate in FIPS 140-2-compliant mode.
   */
  private static final boolean FIPS_MODE;
  static
  {
    final String propertyValue =
         StaticUtils.getSystemProperty(PROPERTY_NAME_FIPS_MODE);
    if (propertyValue == null)
    {
      FIPS_MODE = false;
    }
    else if (propertyValue.equalsIgnoreCase("true"))
    {
      FIPS_MODE = true;
      try
      {
        BouncyCastleFIPSHelper.loadBouncyCastleFIPSProvider(true);
        BouncyCastleFIPSHelper.loadBouncyCastleJSSEProvider(true);
      }
      catch (final Exception e)
      {
        Validator.violation(
             ERR_CRYPTO_HELPER_INSTANTIATION_ERROR_FROM_FIPS_MODE_PROPERTY.get(
                  PROPERTY_NAME_FIPS_MODE, StaticUtils.getExceptionMessage(e)),
             e);
      }
    }
    else if (propertyValue.equalsIgnoreCase("false"))
    {
      FIPS_MODE = false;
    }
    else
    {
      FIPS_MODE = false;
      Validator.violation(
           ERR_CRYPTO_HELPER_INVALID_FIPS_MODE_PROPERTY_VALUE.get(
                PROPERTY_NAME_FIPS_MODE, propertyValue));
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
   * The SSL protocol version string that can be used to request TLS version 1.
   */
  @NotNull public static final String TLS_VERSION_1;



  /**
   * The SSL protocol version string that can be used to request TLS version
   * 1.1.
   */
  @NotNull public static final String TLS_VERSION_1_1;



  /**
   * The SSL protocol version string that can be used to request TLS version
   * 1.2.
   */
  @NotNull public static final String TLS_VERSION_1_2;



  /**
   * The SSL protocol version string that can be used to request TLS version
   * 1.3.
   */
  @NotNull public static final String TLS_VERSION_1_3;

  static
  {
    if (FIPS_MODE)
    {
      TLS_VERSION_1 = BouncyCastleFIPSHelper.TLS_VERSION_1;
      TLS_VERSION_1_1 = BouncyCastleFIPSHelper.TLS_VERSION_1_1;
      TLS_VERSION_1_2 = BouncyCastleFIPSHelper.TLS_VERSION_1_2;
      TLS_VERSION_1_3 = BouncyCastleFIPSHelper.TLS_VERSION_1_3;
    }
    else
    {
      TLS_VERSION_1 = "TLSv1";
      TLS_VERSION_1_1 = "TLSv1.1";
      TLS_VERSION_1_2 = "TLSv1.2";
      TLS_VERSION_1_3 = "TLSv1.3";
    }
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
    return FIPS_MODE;
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
        try
        {
          return CertificateFactory.getInstance(type,
               BouncyCastleFIPSHelper.getBouncyCastleFIPSProvider());
        }
        catch (final NoSuchProviderException e)
        {
          Debug.debugException(e);
          throw new CertificateException(e.getMessage(), e);
        }
      }
      else
      {
        return CertificateFactory.getInstance(type);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME))
      {
        throw new CertificateException(
             ERR_CRYPTO_HELPER_GET_CERT_FACTORY_WRONG_PROVIDER_FOR_FIPS_MODE.
                  get(type, providerName,
                       BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME));
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
        try
        {
          return Cipher.getInstance(cipherTransformation,
               BouncyCastleFIPSHelper.getBouncyCastleFIPSProvider());
        }
        catch (final NoSuchProviderException e)
        {
          Debug.debugException(e);
          throw new NoSuchAlgorithmException(e.getMessage(), e);
        }
      }
      else
      {
        return Cipher.getInstance(cipherTransformation);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_CIPHER_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                  cipherTransformation, providerName,
                  BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME));
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
        try
        {
          return KeyFactory.getInstance(algorithmName,
               BouncyCastleFIPSHelper.getBouncyCastleFIPSProvider());
        }
        catch (final NoSuchProviderException e)
        {
          Debug.debugException(e);
          throw new NoSuchAlgorithmException(e.getMessage(), e);
        }
      }
      else
      {
        return KeyFactory.getInstance(algorithmName);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_KEY_FACTORY_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                  algorithmName, providerName,
                  BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME));
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
      try
      {
        return KeyManagerFactory.getInstance(
             BouncyCastleFIPSHelper.DEFAULT_KEY_MANAGER_FACTORY_ALGORITHM,
             BouncyCastleFIPSHelper.getBouncyCastleJSSEProvider());
      }
      catch (final NoSuchProviderException e)
      {
        Debug.debugException(e);
        throw new NoSuchAlgorithmException(e.getMessage(), e);
      }
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
        try
        {
          return KeyManagerFactory.getInstance(algorithmName,
               BouncyCastleFIPSHelper.getBouncyCastleFIPSProvider());
        }
        catch (final NoSuchProviderException e)
        {
          Debug.debugException(e);
          throw new NoSuchAlgorithmException(e.getMessage(), e);
        }
      }
      else
      {
        return KeyManagerFactory.getInstance(algorithmName);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_KM_FACTORY_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                  algorithmName, providerName,
                  BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME));
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
        try
        {
          return KeyPairGenerator.getInstance(algorithmName,
               BouncyCastleFIPSHelper.getBouncyCastleFIPSProvider());
        }
        catch (final NoSuchProviderException e)
        {
          Debug.debugException(e);
          throw new NoSuchAlgorithmException(e.getMessage(), e);
        }
      }
      else
      {
        return KeyPairGenerator.getInstance(algorithmName);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_KP_GEN_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                  algorithmName, providerName,
                  BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME));
      }
    }

    return KeyPairGenerator.getInstance(algorithmName, provider);
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
      if (keyStoreType.equals(BouncyCastleFIPSHelper.FIPS_KEY_STORE_TYPE))
      {
        try
        {
          return KeyStore.getInstance(keyStoreType,
               BouncyCastleFIPSHelper.getBouncyCastleFIPSProvider());
        }
        catch (final NoSuchProviderException e)
        {
          throw new KeyStoreException(e.getMessage(), e);
        }
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
        try
        {
          return Mac.getInstance(algorithmName,
               BouncyCastleFIPSHelper.getBouncyCastleFIPSProvider());
        }
        catch (final NoSuchProviderException e)
        {
          Debug.debugException(e);
          throw new NoSuchAlgorithmException(e.getMessage(), e);
        }
      }
      else
      {
        return Mac.getInstance(algorithmName);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_MAC_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                  algorithmName, providerName,
                  BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME));
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
        try
        {
          return MessageDigest.getInstance(algorithmName,
               BouncyCastleFIPSHelper.getBouncyCastleFIPSProvider());
        }
        catch (final NoSuchProviderException e)
        {
          Debug.debugException(e);
          throw new NoSuchAlgorithmException(e.getMessage(), e);
        }
      }
      else
      {
        return MessageDigest.getInstance(algorithmName);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_DIGEST_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                  algorithmName, providerName,
                  BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME));
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
        try
        {
          return SecretKeyFactory.getInstance(algorithmName,
               BouncyCastleFIPSHelper.getBouncyCastleFIPSProvider());
        }
        catch (final NoSuchProviderException e)
        {
          Debug.debugException(e);
          throw new NoSuchAlgorithmException(e.getMessage(), e);
        }
      }
      else
      {
        return SecretKeyFactory.getInstance(algorithmName);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_SK_FACTORY_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                  algorithmName, providerName,
                  BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME));
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
          try
          {
            return getSecureRandom(
                 BouncyCastleFIPSHelper.getBouncyCastleFIPSProvider());
          }
          catch (final NoSuchProviderException e)
          {
            Debug.debugException(e);
            throw new NoSuchAlgorithmException(e.getMessage(), e);
          }
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
        try
        {
          return getSecureRandom(algorithmName,
               BouncyCastleFIPSHelper.getBouncyCastleFIPSProvider());
        }
        catch (final NoSuchProviderException e)
        {
          Debug.debugException(e);
          throw new NoSuchAlgorithmException(e.getMessage(), e);
        }
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
        if (! providerName.equals(BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME))
        {
          throw new NoSuchAlgorithmException(
               ERR_CRYPTO_HELPER_GET_SEC_RAND_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                    algorithmName, providerName,
                    BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME));
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
      if (! providerName.equals(
           BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_SEC_RAND_WRONG_PROVIDER_FOR_FIPS_MODE_NO_ALG.
                  get(providerName, BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME));
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
        try
        {
          return Signature.getInstance(algorithmName,
               BouncyCastleFIPSHelper.getBouncyCastleFIPSProvider());
        }
        catch (final NoSuchProviderException e)
        {
          Debug.debugException(e);
          throw new NoSuchAlgorithmException(e.getMessage(), e);
        }
      }
      else
      {
        return Signature.getInstance(algorithmName);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_SIGNATURE_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                  algorithmName, providerName,
                  BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME));
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
      try
      {
        return SSLContext.getInstance(
             BouncyCastleFIPSHelper.DEFAULT_SSL_CONTEXT_PROTOCOL,
             BouncyCastleFIPSHelper.getBouncyCastleJSSEProvider());
      }
      catch (final NoSuchProviderException e)
      {
        Debug.debugException(e);
        throw new NoSuchAlgorithmException(e.getMessage(), e);
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
        try
        {
          return SSLContext.getInstance(protocol,
               BouncyCastleFIPSHelper.getBouncyCastleJSSEProvider());
        }
        catch (final NoSuchProviderException e)
        {
          Debug.debugException(e);
          throw new NoSuchAlgorithmException(e.getMessage(), e);
        }
      }
      else
      {
        return SSLContext.getInstance(protocol);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_SSL_CONTEXT_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                  protocol, providerName,
                  BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME));
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
      try
      {
        return TrustManagerFactory.getInstance(
             BouncyCastleFIPSHelper.DEFAULT_TRUST_MANAGER_FACTORY_ALGORITHM,
             BouncyCastleFIPSHelper.getBouncyCastleJSSEProvider());
      }
      catch (final NoSuchProviderException e)
      {
        Debug.debugException(e);
        throw new NoSuchAlgorithmException(e.getMessage(), e);
      }
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
        try
        {
          return TrustManagerFactory.getInstance(algorithmName,
               BouncyCastleFIPSHelper.getBouncyCastleFIPSProvider());
        }
        catch (final NoSuchProviderException e)
        {
          Debug.debugException(e);
          throw new NoSuchAlgorithmException(e.getMessage(), e);
        }
      }
      else
      {
        return TrustManagerFactory.getInstance(algorithmName);
      }
    }

    if (usingFIPSMode())
    {
      final String providerName = provider.getName();
      if (! providerName.equals(BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME))
      {
        throw new NoSuchAlgorithmException(
             ERR_CRYPTO_HELPER_GET_TM_FACTORY_WRONG_PROVIDER_FOR_FIPS_MODE.get(
                  algorithmName, providerName,
                  BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME));
      }
    }

    return TrustManagerFactory.getInstance(algorithmName, provider);
  }



  /**
   * Retrieves the provider instance with the specified name.
   *
   * @param  providerName         The name of the provider to retrieve.  It may
   *                              be {@code null} if a default provider should
   *                              be used.
   * @param  requireBCInFIPSMode  Indicates whether to only allow the BCFIPS
   *                              provider when the LDAP SDK is operating in
   *                              FIPS 140-2-compliant mode.
   *
   * @return  The provider with the specified name, or {@code null} if the
   *          given provider name was {@code null}.
   *
   * @throws  NoSuchProviderException  If the specified provider is not
   *                                   available.
   */
  @Nullable()
  private static Provider getProvider(@Nullable final String providerName,
                                      final boolean requireBCInFIPSMode)
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
    else
    {
      if (requireBCInFIPSMode && usingFIPSMode())
      {
        throw new NoSuchProviderException(
             ERR_CRYPTO_HELPER_PROVIDER_NOT_AVAILABLE_IN_FIPS_MODE.get(
                  providerName,
                  BouncyCastleFIPSHelper.FIPS_PROVIDER_NAME));
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
