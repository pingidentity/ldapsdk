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



import java.io.File;
import java.lang.reflect.Constructor;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.unboundid.ldap.sdk.InternalSDKHelper;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a helper to ensure that the Bouncy Castle FIPS provider
 * is properly loaded into the JVM so that the provider can be used for
 * cryptographic processing.  The appropriate jar files (typically at least
 * "bc-fips-{version}.jar" and "bctls-fips-{version}.jar", as well as
 * "bcutil-fips-{version}.jar" in 2.x versions) must be available in the JVM
 * classpath.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class BouncyCastleFIPSHelper
{
  /**
   * A reference to the Bouncy Castle FIPS provider, if one is available.
   */
  @NotNull private static final AtomicReference<Provider>
       BOUNCY_CASTLE_FIPS_PROVIDER_REF = new AtomicReference<>();



  /**
   * A reference to the Bouncy Castle JSSE provider, if one is available.
   */
  @NotNull private static final AtomicReference<Provider>
       BOUNCY_CASTLE_JSSE_PROVIDER_REF = new AtomicReference<>();



  /**
   * A reference to the class that implements the Bouncy Castle FIPS provider,
   * if available.
   */
  @NotNull private static final AtomicReference<Class<?>>
       BOUNCY_CASTLE_FIPS_PROVIDER_CLASS_REF = new AtomicReference<>();



  /**
   * A reference to the class that implements the Bouncy Castle JSSE provider,
   * if one is available.
   */
  @NotNull private static final AtomicReference<Class<?>>
       BOUNCY_CASTLE_JSSE_PROVIDER_CLASS_REF = new AtomicReference<>();



  /**
   * The fully qualified name of the Java class that should be used as the
   * Bouncy Castle FIPS provider.
   */
  @NotNull public static final String
       BOUNCY_CASTLE_FIPS_PROVIDER_CLASS_NAME =
            "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider";



  /**
   * The fully qualified name of the Java class that should be used as the
   * Bouncy Castle JSSE provider.
   */
  @NotNull public static final String
       BOUNCY_CASTLE_JSSE_PROVIDER_CLASS_NAME =
            "org.bouncycastle.jsse.provider.BouncyCastleJsseProvider";



  /**
   * The name that may be used to reference the Bouncy Castle FIPS provider.
   */
  @NotNull public static final String FIPS_PROVIDER_NAME = "BCFIPS";



  /**
   * A string that can be used to represent version 1 of the Bouncy Castle FIPS
   * provider, which offers support for FIPS 140-2 compliance.
   */
  @NotNull public static final String FIPS_PROVIDER_VERSION_1 = "1";



  /**
   * A string that can be used to represent version 2 of the Bouncy Castle FIPS
   * provider, which offers support for FIPS 140-3 compliance.
   */
  @NotNull public static final String FIPS_PROVIDER_VERSION_2 = "2";



  /**
   * A string that can be used to represent the default version of the
   * Bouncy Castle FIPS provider.  At present, version 1 is the default,
   * although it may be the case that version 2 (or a later version) could
   * become the default in the future.
   */
  @NotNull public static final String FIPS_PROVIDER_VERSION_DEFAULT =
       FIPS_PROVIDER_VERSION_1;



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
  @NotNull public static final String
       DEFAULT_KEY_MANAGER_FACTORY_ALGORITHM = "X.509";



  /**
   * The name of the SSLContext protocol that should be used when requesting
   * the default context from the Bouncy Castle JSSE provider.
   */
  @NotNull public static final String DEFAULT_SSL_CONTEXT_PROTOCOL =
       "DEFAULT";



  /**
   * The names of alternative SSLContext protocols that should be used when
   * requesting the default context from the Bouncy Castle JSSE provider when
   * the preferred default protocol is not available.
   */
  @NotNull public static final String[]
       ALTERNATIVE_DEFAULT_SSL_CONTEXT_PROTOCOLS = { "TLSv1.3", "TLSv1.2" };



  /**
   * The name of the default key manager factory algorithm that should be used
   * with the Bouncy Castle JSSE provider.
   */
  @NotNull public static final String
       DEFAULT_TRUST_MANAGER_FACTORY_ALGORITHM = "PKIX";



  /**
   * The name of a Java property (org.bouncycastle.rsa.allow_multi_use) that the
   * Bouncy Castle FIPS provider uses to determine whether to allow the same RSA
   * key to be used for multiple purposes (for example, both for
   * signing/verifying and encrypting/decrypting or use in TLS negotiation).
   */
  @NotNull public static final String PROPERTY_ALLOW_RSA_MULTI_USE =
       "org.bouncycastle.rsa.allow_multi_use";



  /**
   * The name of a Java property (org.bouncycastle.fips.approved_only) that the
   * Bouncy Castle FIPS provider uses to determine whether to start in approved
   * mode, in which non-approved functionality will be disabled.
   */
  @NotNull public static final String PROPERTY_APPROVED_ONLY =
       "org.bouncycastle.fips.approved_only";



  /**
   * The name of a Java property (org.bouncycastle.jca.enable_jks) that the
   * Bouncy Castle FIPS provider uses to determine whether to allow the use of
   * JKS key stores to access certificates.
   */
  @NotNull public static final String PROPERTY_ENABLE_JKS =
       "org.bouncycastle.jca.enable_jks";



  /**
   * The name of a Java property (org.bouncycastle.jsse.enable_md5) that the
   * Bouncy Castle FIPS provider uses to determine whether to allow the use of
   * the MD5 digest algorithm.
   */
  @NotNull public static final String PROPERTY_ENABLE_MD5 =
       "org.bouncycastle.jsse.enable_md5";



  /**
   * The name of a Java property
   * (com.unboundid.util.BouncyCastleFIPSHelper.ENABLE_LOGGING) that indicates
   * whether to enable or disable the Bouncy Castle JSSE provider's logging.
   */
  @NotNull public static final String PROPERTY_ENABLE_LOGGING =
       BouncyCastleFIPSHelper.class.getName() + ".ENABLE_LOGGING";



  /**
   * The name of a Java property
   * (com.unboundid.util.BouncyCastleFIPSHelper.LOG_LEVEL) that can be used to
   * set the default log level for the Bouncy Castle JSSE provider's logging.
   * This will only be used if the {@link #PROPERTY_ENABLE_LOGGING} property is
   * set to {@code true}, and the value must match the name of one of of the
   * {@code java.util.logging.Level} constants ({@code SEVERE},
   * {@code WARNING}, {@code INFO}, {@code CONFIG}, {@code  FINE},
   * {@code FINER}, {@code FINEST}, {@code ALL}, or {@code OFF}).
   */
  @NotNull public static final String PROPERTY_LOG_LEVEL =
       BouncyCastleFIPSHelper.class.getName() + ".LOG_LEVEL";



  /**
   * The name of the logger used for Bouncy Castle functionality.
   */
  @NotNull private static final String LOGGER_NAME = "org.bouncycastle";



  /**
   * The logger for the Bouncy Castle JSSE provider's logging.
   */
  @NotNull private static final Logger LOGGER = Logger.getLogger(LOGGER_NAME);
  static
  {
    LOGGER.setUseParentHandlers(false);

    if (PropertyManager.getBoolean(PROPERTY_ENABLE_LOGGING, false))
    {
      Level level = Level.INFO;
      final String levelPropertyValue = PropertyManager.get(PROPERTY_LOG_LEVEL);
      if (levelPropertyValue != null)
      {
        switch (StaticUtils.toUpperCase(levelPropertyValue))
        {
          case "SEVERE":
            level = Level.SEVERE;
            break;
          case "WARNING":
            level = Level.WARNING;
            break;
          case "INFO":
            level = Level.INFO;
            break;
          case "CONFIG":
            level = Level.CONFIG;
            break;
          case "FINE":
            level = Level.FINE;
            break;
          case "FINER":
            level = Level.FINER;
            break;
          case "FINEST":
            level = Level.FINEST;
            break;
          case "ALL":
            level = Level.ALL;
            break;
          case "OFF":
            level = Level.OFF;
            break;
          default:
            Validator.violation("Unsupported " + PROPERTY_LOG_LEVEL +
                 " property value '" + levelPropertyValue + "'.");
            break;
        }
      }

      StaticUtils.setLoggerLevel(LOGGER, level);
    }
    else
    {
      StaticUtils.setLoggerLevel(LOGGER, Level.OFF);
    }
  }



  /**
   * Prevents this utility class from being instantiated.
   */
  private BouncyCastleFIPSHelper()
  {
    // No implementation required.
  }



  /**
   * Retrieves a reference to the Bouncy Castle FIPS provider.
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
    return getBouncyCastleFIPSProvider(null);
  }



  /**
   * Retrieves a reference to the Bouncy Castle FIPS provider.
   *
   * @param  versionString  A string that indicates which version of the
   *                        provider should be used.  It may be {@code null} if
   *                        the default version should be used.
   *
   * @return   The Bouncy Castle FIPS provider instance.  It will not be
   *           {@code null}.
   *
   * @throws  NoSuchProviderException  If the Bouncy Castle FIPS provider is
   *                                   not available in the JVM.
   */
  @NotNull()
  public static Provider getBouncyCastleFIPSProvider(
              @Nullable final String versionString)
         throws NoSuchProviderException
  {
    final Provider cachedProvider = BOUNCY_CASTLE_FIPS_PROVIDER_REF.get();
    if (cachedProvider != null)
    {
      return cachedProvider;
    }

    return loadBouncyCastleFIPSProvider(false, versionString);
  }



  /**
   * Ensures that an appropriate set of system properties are in place if the
   * LDAP SDK is being used as part of a Ping Identity server product.
   */
  static void setPropertiesForPingIdentityServer()
  {
    if (InternalSDKHelper.getPingIdentityServerRoot() == null)
    {
      return;
    }

    StaticUtils.setSystemPropertyIfNotAlreadyDefined(PROPERTY_APPROVED_ONLY,
         "true");
    StaticUtils.setSystemPropertyIfNotAlreadyDefined(
         PROPERTY_ALLOW_RSA_MULTI_USE, "true");
    StaticUtils.setSystemPropertyIfNotAlreadyDefined(PROPERTY_ENABLE_MD5,
         "true");
  }



  /**
   * Loads the Bouncy Castle FIPS provider into the JVM, if it has not already
   * been loaded.  The default version of the provider will be used.
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
    return loadBouncyCastleFIPSProvider(makeDefault, null);
  }



  /**
   * Loads the Bouncy Castle FIPS provider into the JVM, if it has not already
   * been loaded.
   *
   * @param  makeDefault    Indicates whether to make the Bouncy Castle FIPS
   *                        provider the default provider in the JVM.
   * @param  versionString  A string that indicates which version of the
   *                        provider should be used.  It may be {@code null} if
   *                        the default version should be used.
   *
   * @return  The provider that was loaded.  It will not be {@code null}.
   *
   * @throws  NoSuchProviderException  If the Bouncy Castle FIPS provider is
   *                                   not available in the JVM.
   */
  @NotNull()
  static synchronized Provider loadBouncyCastleFIPSProvider(
                                    final boolean makeDefault,
                                    @Nullable final String versionString)
          throws NoSuchProviderException
  {
    // Validate and parse the provider version string.
    final int versionNumber =
         parseVersionString(FIPS_PROVIDER_NAME, versionString);


    // If the provider class has already been loaded through some means, then
    // just return it.
    try
    {
      final Provider existingProvider =
           Security.getProvider(FIPS_PROVIDER_NAME);
      if (existingProvider != null)
      {
        BOUNCY_CASTLE_FIPS_PROVIDER_REF.compareAndSet(null, existingProvider);
        return existingProvider;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }


    // Load the provider class.  If this fails, then the Bouncy Castle FIPS
    // provider is not in the classpath.
    Class<?> fipsProviderClass = BOUNCY_CASTLE_FIPS_PROVIDER_CLASS_REF.get();
    if (fipsProviderClass == null)
    {
      try
      {
        fipsProviderClass =
             Class.forName(BOUNCY_CASTLE_FIPS_PROVIDER_CLASS_NAME);
        BOUNCY_CASTLE_FIPS_PROVIDER_CLASS_REF.set(fipsProviderClass);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        // Before giving up, check to see if the LDAP SDK is part of a Ping
        // Identity Directory Server installation, and if so, whether we can
        // find the library as part of that installation.
        boolean shouldThrow = true;
        try
        {
          final File instanceRoot =
               InternalSDKHelper.getPingIdentityServerRoot();
          if (instanceRoot != null)
          {
            File fipsProviderJarFile = null;
            File fipsJSSEProviderJarFile = null;
            final List<File> additionalFIPSProviderJarFiles = new ArrayList<>();
            final File resourceDir = new File(instanceRoot, "resource");
            final File bcDir = new File(resourceDir, "bc");

            final File fipsDir;
            if (versionNumber == 2)
            {
              fipsDir = new File(bcDir, "fips2");
            }
            else
            {
              fipsDir = new File(bcDir, "fips");
            }

            if (fipsDir.exists())
            {
              for (final File f : fipsDir.listFiles())
              {
                final String name = f.getName();
                if (name.startsWith("bc-fips-") && name.endsWith(".jar"))
                {
                  fipsProviderJarFile = f;
                }
                else if (name.startsWith("bctls-fips-") &&
                     name.endsWith(".jar"))
                {
                  fipsJSSEProviderJarFile = f;
                }
                else if (name.endsWith(".jar"))
                {
                  additionalFIPSProviderJarFiles.add(f);
                }
              }
            }

            if ((fipsProviderJarFile != null) &&
                 (fipsJSSEProviderJarFile != null))
            {
              final List<File> fipsJarFiles = new ArrayList<>();
              fipsJarFiles.add(fipsProviderJarFile);
              fipsJarFiles.add(fipsJSSEProviderJarFile);
              fipsJarFiles.addAll(additionalFIPSProviderJarFiles);

              final URL[] fileURLs = new URL[fipsJarFiles.size()];
              for (int  i=0; i < fileURLs.length; i++)
              {
                fileURLs[i] = fipsJarFiles.get(i).toURI().toURL();
              }

              final URLClassLoader classLoader = new URLClassLoader(fileURLs,
                   BouncyCastleFIPSHelper.class.getClassLoader());
              fipsProviderClass = classLoader.loadClass(
                   BOUNCY_CASTLE_FIPS_PROVIDER_CLASS_NAME);
              BOUNCY_CASTLE_FIPS_PROVIDER_CLASS_REF.set(fipsProviderClass);

              final Class<?> jsseProviderClass = classLoader.loadClass(
                   BOUNCY_CASTLE_JSSE_PROVIDER_CLASS_NAME);
              BOUNCY_CASTLE_JSSE_PROVIDER_CLASS_REF.set(jsseProviderClass);

              shouldThrow = false;
            }
          }
        }
        catch (final Exception e2)
        {
          Debug.debugException(e2);
        }

        if (shouldThrow)
        {
          throw new NoSuchProviderException(
               ERR_BC_FIPS_HELPER_CANNOT_LOAD_FIPS_PROVIDER_CLASS.get(
                    BOUNCY_CASTLE_FIPS_PROVIDER_CLASS_NAME,
                    StaticUtils.getExceptionMessage(e)));
        }
      }
    }


    // Instantiate the provider class.
    final Provider provider;
    try
    {
      final Constructor<?> constructor =
           fipsProviderClass.getConstructor(String.class);
      provider = (Provider) constructor.newInstance("C:HYBRID;ENABLE{All};");

      if (makeDefault)
      {
        Security.insertProviderAt(provider, 1);
      }
      else
      {
        Security.addProvider(provider);
      }

      BOUNCY_CASTLE_FIPS_PROVIDER_REF.set(provider);

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
   * Parses the provided version string to determine which version of the
   * Bouncy Castle FIPS provider has been requested.
   *
   * @param  providerName   The name of the associated provider, which should
   *                        be either "BCFIPS" or "BCJSSE".
   * @param  versionString  The version string for which to make the
   *                        determination.  It may be {@code null} if the
   *                        default version should be used.
   *
   * @return  The version of the library that should be used.  At present, it
   *          will be either {@code 1} or {@code 2}, but additional values may
   *          be used in future releases.
   *
   * @throws  NoSuchProviderException  If the provided version string is not
   *                                   recognized as an allowed value.
   */
  private static int parseVersionString(
               @NotNull final String providerName,
               @Nullable final String versionString)
          throws NoSuchProviderException
  {
    if ((versionString == null) ||
         versionString.equalsIgnoreCase(FIPS_PROVIDER_NAME) ||
         versionString.equalsIgnoreCase(providerName))
    {
      // We should use the default version, which is currently v1.
      return 1;
    }

    if (versionString.equalsIgnoreCase(FIPS_PROVIDER_VERSION_1) ||
         versionString.equalsIgnoreCase(FIPS_PROVIDER_NAME +
              FIPS_PROVIDER_VERSION_1) ||
         versionString.equalsIgnoreCase(providerName + FIPS_PROVIDER_VERSION_1))
    {
      // The caller explicitly requested v1.
      return 1;
    }

    if (versionString.equalsIgnoreCase(FIPS_PROVIDER_VERSION_2) ||
         versionString.equalsIgnoreCase(FIPS_PROVIDER_NAME +
              FIPS_PROVIDER_VERSION_2) ||
         versionString.equalsIgnoreCase(providerName + FIPS_PROVIDER_VERSION_2))
    {
      // The caller explicitly requested v2.
      return 2;
    }


    // If we've gotten here, then we don't recognize the version string.
    throw new NoSuchProviderException(
         ERR_BC_FIPS_HELPER_UNSUPPORTED_VERSION.get(versionString,
              providerName, FIPS_PROVIDER_VERSION_1,
              FIPS_PROVIDER_VERSION_2));
  }



  /**
   * Retrieves a reference to the Bouncy Castle JSSE provider.
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
    return getBouncyCastleJSSEProvider(null);
  }



  /**
   * Retrieves a reference to the Bouncy Castle JSSE provider.
   *
   * @param  versionString        A string that indicates which version of the
   *                              provider should be used.  It may be
   *                              {@code null} if the default version should be
   *                              used.
   * @return   The Bouncy Castle JSSE provider instance.  It will not be
   *           {@code null}.
   *
   * @throws  NoSuchProviderException  If the Bouncy Castle JSSE provider is
   *                                   not available in the JVM.
   */
  @NotNull()
  public static Provider getBouncyCastleJSSEProvider(
              @Nullable final String versionString)
         throws NoSuchProviderException
  {
    final Provider cachedProvider = BOUNCY_CASTLE_JSSE_PROVIDER_REF.get();
    if (cachedProvider != null)
    {
      return cachedProvider;
    }

    return loadBouncyCastleJSSEProvider(false, versionString);
  }



  /**
   * Loads the Bouncy Castle JSSE provider into the JVM, if it has not already
   * been loaded.  The default version of the provider will be used.
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
    return loadBouncyCastleJSSEProvider(makeSecond, null);
  }



  /**
   * Loads the Bouncy Castle JSSE provider into the JVM, if it has not already
   * been loaded.
   *
   * @param  makeSecond     Indicates whether to make the Bouncy Castle JSSE
   *                        provider second in the JVM's search order
   *                        (presumably after the Bouncy Castle FIPS provider as
   *                        the first provider, in which case the Bouncy Castle
   *                        FIPS provider must have already been loaded and made
   *                        first).
   * @param  versionString  A string that indicates which version of the
   *                        provider should be used.  It may be {@code null} if
   *                        the default version should be used.
   *
   * @return  The provider that was loaded.  It will not be {@code null}.
   *
   * @throws  NoSuchProviderException  If the Bouncy Castle JSSE provider is
   *                                   not available in the JVM.
   */
  @NotNull()
  static synchronized Provider loadBouncyCastleJSSEProvider(
                                    final boolean makeSecond,
                                    @Nullable final String versionString)
          throws NoSuchProviderException
  {
    // Validate and parse the provided version string.  At present, we shouldn't
    // need to do anything different when using version 2 of the JSSE provider
    // than when using version 1, but we will still check the version string to
    // make sure it's valid, in case something different is needed in the
    // future.
    parseVersionString(JSSE_PROVIDER_NAME, versionString);


    // If the provider class has already been loaded through some means, then
    // just return it.
    try
    {
      final Provider existingProvider =
           Security.getProvider(JSSE_PROVIDER_NAME);
      if (existingProvider != null)
      {
        BOUNCY_CASTLE_JSSE_PROVIDER_REF.compareAndSet(null, existingProvider);
        return existingProvider;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }


    // Load the provider class.  If this fails, then the Bouncy Castle JSSE
    // provider is not in the classpath.
    Class<?> jsseProviderClass = BOUNCY_CASTLE_JSSE_PROVIDER_CLASS_REF.get();
    if (jsseProviderClass == null)
    {
      try
      {
        jsseProviderClass =
             Class.forName(BOUNCY_CASTLE_JSSE_PROVIDER_CLASS_NAME);
        BOUNCY_CASTLE_JSSE_PROVIDER_CLASS_REF.set(jsseProviderClass);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new NoSuchProviderException(
             ERR_BC_FIPS_HELPER_CANNOT_LOAD_JSSE_PROVIDER_CLASS.get(
                  BOUNCY_CASTLE_JSSE_PROVIDER_CLASS_NAME,
                  StaticUtils.getExceptionMessage(e)));
      }
    }


    // Instantiate the provider class.
    final Provider provider;
    try
    {
      final Constructor<?> constructor =
           jsseProviderClass.getConstructor(String.class);
      provider = (Provider) constructor.newInstance("fips:BCFIPS");

      if (makeSecond)
      {
        Security.insertProviderAt(provider, 2);
      }
      else
      {
        Security.addProvider(provider);
      }

      BOUNCY_CASTLE_JSSE_PROVIDER_REF.set(provider);
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



  /**
   * Disables logging for Bouncy Castle functionality.
   */
  public static void disableLogging()
  {
    StaticUtils.setLoggerLevel(LOGGER, Level.OFF);
    LOGGER.setUseParentHandlers(false);
  }



  /**
   * Enables logging for Bouncy Castle functionality.
   *
   * @param  level  The logging level to use.  If it is {@code null}, then a
   *                default level of {@code INFO} will be used.
   *
   * @return  The logger used for Bouncy Castle functionality.
   */
  @NotNull()
  public static Logger enableLogging(@Nullable final Level level)
  {
    StaticUtils.setLoggerLevel(LOGGER,
         (level == null) ? Level.INFO : level);
    return LOGGER;
  }
}
