/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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



import java.io.OutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPRuntimeException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;

import static com.unboundid.util.ssl.SSLMessages.*;



/**
 * This class provides a utility for selecting the cipher suites that should be
 * supported for TLS communication.  The logic used to select the recommended
 * TLS cipher suites is as follows:
 * <UL>
 *   <LI>
 *     Only cipher suites that use the TLS protocol will be recommended.  Legacy
 *     SSL suites will not be recommended, nor will any suites that use an
 *     unrecognized protocol.
 *   </LI>
 *
 *   <LI>
 *     Any cipher suite that uses a NULL key exchange, authentication, bulk
 *     encryption, or digest algorithm will not be recommended.
 *   </LI>
 *
 *   <LI>
 *     Any cipher suite that uses anonymous authentication will not be
 *     recommended.
 *   </LI>
 *
 *   <LI>
 *     Any cipher suite that uses weakened export-grade encryption will not be
 *     recommended.
 *   </LI>
 *
 *   <LI>
 *     By default, only cipher suites that use the ECDHE or DHE key exchange
 *     algorithms will be recommended, as they allow for forward secrecy.
 *     Suites that use RSA key exchange algorithms (which don't support forward
 *     secrecy) will only be recommended if the JVM doesn't support either
 *     TLSv1.3 or TLSv1.2, or if overridden programmatically or by system
 *     property.  Other key agreement algorithms (like ECDH, DH, and KRB5) will
 *     not be recommended.  Similarly, cipher suites that use a pre-shared key
 *     or password will not be recommended.
 *   </LI>
 *
 *   <LI>
 *     Only cipher suites that use AES or ChaCha20 bulk encryption ciphers will
 *     be recommended.  Other bulk cipher algorithms (like RC4, DES, 3DES, IDEA,
 *     Camellia, and ARIA) will not be recommended.
 *   </LI>
 *
 *   <LI>
 *     By default, only cipher suites that use SHA-2 digests will be
 *     recommended.  SHA-1 suites will only be recommended if the JVM doesn't
 *     support either TLSv1.3 or TLSv1.2, or if overridden programmatically or
 *     by system property.  All other digest algorithms (like MD5) will not be
 *     recommended.
 *   </LI>
 * </UL>
 * <BR><BR>
 * Also note that this class can be used as a command-line tool for debugging
 * purposes.
 */
@NotMutable()
@ThreadSafety(level= ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TLSCipherSuiteSelector
       extends CommandLineTool
{
  /**
   * The singleton instance of this TLS cipher suite selector.
   */
  @NotNull private static final AtomicReference<TLSCipherSuiteSelector>
       INSTANCE = new AtomicReference<>(new TLSCipherSuiteSelector(true));



  /**
   * The name of a system property
   * (com.unboundid.util.ssl.TLSCipherSuiteSelector.allowRSAKeyExchange) that
   * can be used to indicate whether to recommend cipher suites that use the RSA
   * key exchange algorithm.  RSA key exchange does not support forward secrecy,
   * so it will not be recommended by default unless the JVM doesn't support
   * either TLSv1.3 or TLSv1.2.  This can be overridden via the
   * {@link #setAllowRSAKeyExchange(boolean)} method.
   */
  @NotNull public static final String PROPERTY_ALLOW_RSA_KEY_EXCHANGE =
       TLSCipherSuiteSelector.class.getName() + ".allowRSAKeyExchange";



  /**
   * The name of a system property
   * (com.unboundid.util.ssl.TLSCipherSuiteSelector.allowSHA1) that can be used
   * to indicate whether to recommend cipher suites that use the SHA-1 digest
   * algorithm.  The SHA-1 digest is now considered weak, so it will not be
   * recommended by default unless the JVM doesn't support either TLSv1.3 or
   * TLSv1.2.  This can be overridden via the {@link #setAllowSHA1(boolean)}
   * method.
   */
  @NotNull public static final String PROPERTY_ALLOW_SHA_1 =
       TLSCipherSuiteSelector.class.getName() + ".allowSHA1";



  /**
   * A flag that indicates whether to allow the RSA key exchange algorithm.
   */
  @NotNull private static final AtomicBoolean ALLOW_RSA_KEY_EXCHANGE =
       new AtomicBoolean(false);



  /**
   * A flag that indicates whether to allow cipher suites that use the SHA-1
   * digest algorithm.
   */
  @NotNull private static final AtomicBoolean ALLOW_SHA_1 =
       new AtomicBoolean(false);



  static
  {
    boolean jvmSupportsTLSv13OrTLSv12 = false;
    try
    {
      final SSLContext sslContext = SSLContext.getDefault();
      for (final String supportedProtocol :
           sslContext.getSupportedSSLParameters().getProtocols())
      {
        if (supportedProtocol.equalsIgnoreCase(SSLUtil.SSL_PROTOCOL_TLS_1_3) ||
             supportedProtocol.equalsIgnoreCase(SSLUtil.SSL_PROTOCOL_TLS_1_2))
        {
          jvmSupportsTLSv13OrTLSv12 = true;
          break;
        }
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }


    final boolean allowRSA;
    final String allowRSAPropertyValue =
         StaticUtils.getSystemProperty(PROPERTY_ALLOW_RSA_KEY_EXCHANGE);
    if (allowRSAPropertyValue != null)
    {
      allowRSA = allowRSAPropertyValue.equalsIgnoreCase("true");
    }
    else
    {
      allowRSA = (! jvmSupportsTLSv13OrTLSv12);
    }

    final boolean allowSHA1;
    final String allowSHA1PropertyValue =
         StaticUtils.getSystemProperty(PROPERTY_ALLOW_SHA_1);
    if (allowSHA1PropertyValue != null)
    {
      allowSHA1 = allowSHA1PropertyValue.equalsIgnoreCase("true");
    }
    else
    {
      allowSHA1 = (! jvmSupportsTLSv13OrTLSv12);
    }

    ALLOW_RSA_KEY_EXCHANGE.set(allowRSA);
    ALLOW_SHA_1.set(allowSHA1);
    INSTANCE.set(new TLSCipherSuiteSelector(false));
  }



  // Retrieves a map of the supported cipher suites that are not recommended
  // for use, mapped to a list of the reasons that the cipher suites are not
  // recommended.
  @NotNull private final SortedMap<String,List<String>>
       nonRecommendedCipherSuites;

  // The set of TLS cipher suites enabled in the JVM by default, sorted in
  // order of most preferred to least preferred.
  @NotNull private final SortedSet<String> defaultCipherSuites;

  // The recommended set of TLS cipher suites selected by this class, sorted in
  // order of most preferred to least preferred.
  @NotNull private final SortedSet<String> recommendedCipherSuites;

  // The full set of TLS cipher suites supported in the JVM, sorted in order of
  // most preferred to least preferred.
  @NotNull private final SortedSet<String> supportedCipherSuites;

  // The recommended set of TLS cipher suites as an array rather than a set.
  @NotNull private final String[] recommendedCipherSuiteArray;



  /**
   * Invokes this command-line program with the provided set of arguments.
   *
   * @param  args  The command-line arguments provided to this program.
   */
  public static void main(@NotNull final String... args)
  {
    final ResultCode resultCode = main(System.out, System.err, args);
    if (resultCode != ResultCode.SUCCESS)
    {
      System.exit(resultCode.intValue());
    }
  }



  /**
   * Invokes this command-line program with the provided set of arguments.
   *
   * @param  out   The output stream to use for standard output.  It may be
   *               {@code null} if standard output should be suppressed.
   * @param  err   The output stream to use for standard error.  It may be
   *               {@code null} if standard error should be suppressed.
   * @param  args  The command-line arguments provided to this program.
   *
   * @return  A result code that indicates whether the processing was
   *          successful.
   */
  @NotNull()
  public static ResultCode main(@Nullable final OutputStream out,
                                @Nullable final OutputStream err,
                                @NotNull final String... args)
  {
    final TLSCipherSuiteSelector tool = new TLSCipherSuiteSelector(out, err);
    return tool.runTool(args);
  }



  /**
   * Creates a new instance of this TLS cipher suite selector that will suppress
   * all output.
   *
   * @param  useJVMDefaults  Indicates whether to use the JVM-default settings.
   *                         This should only be {@code true} for the initial
   *                         instance created before the static initializer has
   *                         run.
   */
  private TLSCipherSuiteSelector(final boolean useJVMDefaults)
  {
    this(null, null, useJVMDefaults);
  }




  /**
   * Creates a new instance of this TLS cipher suite selector that will use the
   * provided output streams.  Note that this constructor should only be used
   * when invoking it as a command-line tool.
   *
   * @param  out  The output stream to use for standard output.  It may be
   *              {@code null} if standard output should be suppressed.
   * @param  err  The output stream to use for standard error.  It may be
   *              {@code null} if standard error should be suppressed.
   */
  public TLSCipherSuiteSelector(@Nullable final OutputStream out,
                                @Nullable final OutputStream err)
  {
    this(out, err, false);
  }




  /**
   * Creates a new instance of this TLS cipher suite selector that will use the
   * provided output streams.  Note that this constructor should only be used
   * when invoking it as a command-line tool.
   *
   * @param  out             The output stream to use for standard output.  It
   *                         may be {@code null} if standard output should be
   *                         suppressed.
   * @param  err             The output stream to use for standard error.  It
   *                         may be {@code null} if standard error should be
   *                         suppressed.
   * @param  useJVMDefaults  Indicates whether to use the JVM-default settings.
   *                         This should only be {@code true} for the initial
   *                         instance created before the static initializer has
   *                         run.
   */
  public TLSCipherSuiteSelector(@Nullable final OutputStream out,
                                @Nullable final OutputStream err,
                                final boolean useJVMDefaults)
  {
    super(out, err);

    try
    {
      final SSLContext sslContext;
      if (useJVMDefaults)
      {
        sslContext = SSLContext.getDefault();
      }
      else
      {
        sslContext = CryptoHelper.getDefaultSSLContext();
      }

      final SSLParameters supportedParameters =
           sslContext.getSupportedSSLParameters();
      final TreeSet<String> supportedSet =
           new TreeSet<>(TLSCipherSuiteComparator.getInstance());
      supportedSet.addAll(Arrays.asList(supportedParameters.getCipherSuites()));
      supportedCipherSuites = Collections.unmodifiableSortedSet(supportedSet);

      final SSLParameters defaultParameters =
           sslContext.getDefaultSSLParameters();
      final TreeSet<String> defaultSet =
           new TreeSet<>(TLSCipherSuiteComparator.getInstance());
      defaultSet.addAll(Arrays.asList(defaultParameters.getCipherSuites()));
      defaultCipherSuites = Collections.unmodifiableSortedSet(defaultSet);

      if (useJVMDefaults)
      {
        recommendedCipherSuites = defaultCipherSuites;
        nonRecommendedCipherSuites = Collections.unmodifiableSortedMap(
             new TreeMap<String,List<String>>());
      }
      else
      {
        final ObjectPair<SortedSet<String>,SortedMap<String,List<String>>>
             selectedPair = selectCipherSuites(
             supportedParameters.getCipherSuites());
        if (selectedPair.getFirst().isEmpty())
        {
          // We couldn't identify any recommended suites.  Just fall back on the
          // JVM-default suites.
          recommendedCipherSuites = defaultCipherSuites;
          nonRecommendedCipherSuites = Collections.unmodifiableSortedMap(
               new TreeMap<String,List<String>>());
        }
        else
        {
          recommendedCipherSuites =
               Collections.unmodifiableSortedSet(selectedPair.getFirst());
          nonRecommendedCipherSuites =
               Collections.unmodifiableSortedMap(selectedPair.getSecond());
        }
      }

      recommendedCipherSuiteArray =
           recommendedCipherSuites.toArray(StaticUtils.NO_STRINGS);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      // This should never happen.
      throw new LDAPRuntimeException(new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_TLS_CIPHER_SUITE_SELECTOR_INIT_ERROR.get(
                StaticUtils.getExceptionMessage(e)),
           e));
    }


    // If the JVM's TLS debugging support is enabled, then invoke the tool
    // and send its output to standard error.
    final String debugProperty =
         StaticUtils.getSystemProperty("javax.net.debug");
    if ((debugProperty != null) && debugProperty.equals("all"))
    {
      System.err.println();
      System.err.println(getClass().getName() + " Results:");
      generateOutput(System.err);
      System.err.println();
    }
  }



  /**
   * Retrieves the set of all TLS cipher suites supported by the JVM.  The set
   * will be sorted in order of most preferred to least preferred, as determined
   * by the {@link TLSCipherSuiteComparator}.
   *
   * @return  The set of all TLS cipher suites supported by the JVM.
   */
  @NotNull()
  public static SortedSet<String> getSupportedCipherSuites()
  {
    return INSTANCE.get().supportedCipherSuites;
  }



  /**
   * Retrieves the set of TLS cipher suites enabled by default in the JVM.  The
   * set will be sorted in order of most preferred to least preferred, as
   * determined by the {@link TLSCipherSuiteComparator}.
   *
   * @return  The set of TLS cipher suites enabled by default in the JVM.
   */
  @NotNull()
  public static SortedSet<String> getDefaultCipherSuites()
  {
    return INSTANCE.get().defaultCipherSuites;
  }



  /**
   * Retrieves the recommended set of TLS cipher suites as selected by this
   * class.  The set will be sorted in order of most preferred to least
   * preferred, as determined by the {@link TLSCipherSuiteComparator}.
   *
   * @return  The recommended set of TLS cipher suites as selected by this
   *          class.
   */
  @NotNull()
  public static SortedSet<String> getRecommendedCipherSuites()
  {
    return INSTANCE.get().recommendedCipherSuites;
  }



  /**
   * Retrieves an array containing the recommended set of TLS cipher suites as
   * selected by this class.  The array will be sorted in order of most
   * preferred to least preferred, as determined by the
   * {@link TLSCipherSuiteComparator}.
   *
   * @return  An array containing the recommended set of TLS cipher suites as
   *          selected by this class.
   */
  @NotNull()
  public static String[] getRecommendedCipherSuiteArray()
  {
    return INSTANCE.get().recommendedCipherSuiteArray.clone();
  }



  /**
   * Retrieves a map containing the TLS cipher suites that are supported by the
   * JVM but are not recommended for use.  The keys of the map will be the names
   * of the non-recommended cipher suites, sorted in order of most preferred to
   * least preferred, as determined by the {@link TLSCipherSuiteComparator}.
   * Each TLS cipher suite name will be mapped to a list of the reasons it is
   * not recommended for use.
   *
   * @return  A map containing the TLS cipher suites that are supported by the
   *          JVM but are not recommended for use
   */
  @NotNull()
  public static SortedMap<String,List<String>> getNonRecommendedCipherSuites()
  {
    return INSTANCE.get().nonRecommendedCipherSuites;
  }



  /**
   * Organizes the provided set of cipher suites into recommended and
   * non-recommended sets.
   *
   * @param  cipherSuiteArray  An array of the cipher suites to be organized.
   *
   * @return  An object pair in which the first element is the sorted set of
   *          recommended cipher suites, and the second element is the sorted
   *          map of non-recommended cipher suites and the reasons they are not
   *          recommended for use.
   */
  @NotNull()
  static ObjectPair<SortedSet<String>,SortedMap<String,List<String>>>
       selectCipherSuites(@NotNull final String[] cipherSuiteArray)
  {
    return selectCipherSuites(cipherSuiteArray, false);
  }



  /**
   * Organizes the provided set of cipher suites into recommended and
   * non-recommended sets.
   *
   * @param  cipherSuiteArray  An array of the cipher suites to be organized.
   * @param  includeSSLSuites  Indicates whether to allow suites that start
   *                           with "SSL_".  If this is {@code false} (which
   *                           should be the case for all calls to this method
   *                           that don't come directly from this method), then
   *                           only suites that start with "TLS_" will be
   *                           included.  If this is {@code true}, then suites
   *                           that start with "SSL_" may be included.  This is
   *                           necessary because some JVMs (for example, the IBM
   *                           JVM) only report suites that start with "SSL_"
   *                           and none with "TLS_".  In that case, we'll rely
   *                           only on other logic to determine which suites to
   *                           recommend and which to exclude.
   *
   * @return  An object pair in which the first element is the sorted set of
   *          recommended cipher suites, and the second element is the sorted
   *          map of non-recommended cipher suites and the reasons they are not
   *          recommended for use.
   */
  @NotNull()
  private static ObjectPair<SortedSet<String>,SortedMap<String,List<String>>>
               selectCipherSuites(@NotNull final String[] cipherSuiteArray,
                                 final boolean includeSSLSuites)
  {
    final SortedSet<String> recommendedSet =
         new TreeSet<>(TLSCipherSuiteComparator.getInstance());
    final SortedMap<String,List<String>> nonRecommendedMap =
         new TreeMap<>(TLSCipherSuiteComparator.getInstance());

    boolean anyTLSSuitesFound = false;
    for (final String cipherSuiteName : cipherSuiteArray)
    {
      String name =
           StaticUtils.toUpperCase(cipherSuiteName).replace('-', '_');

      // Signalling cipher suite values (which indicate capabilities of the
      // implementation and aren't really cipher suites on their own) will
      // always be accepted.
      if (name.endsWith("_SCSV"))
      {
        recommendedSet.add(cipherSuiteName);
        continue;
      }


      // Only cipher suites using the TLS protocol will be accepted.
      final List<String> nonRecommendedReasons = new ArrayList<>(5);
      if (name.startsWith("SSL_") && (! includeSSLSuites))
      {
        nonRecommendedReasons.add(
             ERR_TLS_CIPHER_SUITE_SELECTOR_LEGACY_SSL_PROTOCOL.get());
      }
      else if (name.startsWith("TLS_") || name.startsWith("SSL_"))
      {
        if (name.startsWith("TLS_"))
        {
          anyTLSSuitesFound = true;
        }
        else
        {
          name = "TLS_" + name.substring(4);
        }

        // Only TLS cipher suites using a recommended key exchange algorithm
        // will be accepted.
        if (name.startsWith("TLS_AES_") ||
             name.startsWith("TLS_CHACHA20_") ||
             name.startsWith("TLS_ECDHE_") ||
             name.startsWith("TLS_DHE_"))
        {
          // These are recommended key exchange algorithms.
        }
        else if (name.startsWith("TLS_RSA_"))
        {
          if (ALLOW_RSA_KEY_EXCHANGE.get())
          {
            // This will be considered a recommended key exchange algorithm.
          }
          else
          {
            nonRecommendedReasons.add(
                 ERR_TLS_CIPHER_SUITE_SELECTOR_NON_RECOMMENDED_KNOWN_KE_ALG.get(
                      "RSA"));
          }
        }
        else if (name.startsWith("TLS_ECDH_"))
        {
          nonRecommendedReasons.add(
               ERR_TLS_CIPHER_SUITE_SELECTOR_NON_RECOMMENDED_KNOWN_KE_ALG.get(
                    "ECDH"));
        }
        else if (name.startsWith("TLS_DH_"))
        {
          nonRecommendedReasons.add(
               ERR_TLS_CIPHER_SUITE_SELECTOR_NON_RECOMMENDED_KNOWN_KE_ALG.get(
                    "DH"));
        }
        else if (name.startsWith("TLS_KRB5_"))
        {
          nonRecommendedReasons.add(
               ERR_TLS_CIPHER_SUITE_SELECTOR_NON_RECOMMENDED_KNOWN_KE_ALG.get(
                    "KRB5"));
        }
        else
        {
          nonRecommendedReasons.add(
               ERR_TLS_CIPHER_SUITE_SELECTOR_NON_RECOMMENDED_UNKNOWN_KE_ALG.
                    get());
        }
      }
      else
      {
        nonRecommendedReasons.add(
             ERR_TLS_CIPHER_SUITE_SELECTOR_UNRECOGNIZED_PROTOCOL.get());
      }


      // Cipher suites that rely on pre-shared keys will not be accepted.
      if (name.contains("_PSK"))
      {
        nonRecommendedReasons.add(ERR_TLS_CIPHER_SUITE_SELECTOR_PSK.get());
      }


      // Cipher suites that use a null component will not be accepted.
      if (name.contains("_NULL"))
      {
        nonRecommendedReasons.add(
             ERR_TLS_CIPHER_SUITE_SELECTOR_NULL_COMPONENT.get());
      }


      // Cipher suites that use anonymous authentication will not be accepted.
      if (name.contains("_ANON"))
      {
        nonRecommendedReasons.add(
             ERR_TLS_CIPHER_SUITE_SELECTOR_ANON_AUTH.get());
      }


      // Cipher suites that use export-grade encryption will not be accepted.
      if (name.contains("_EXPORT"))
      {
        nonRecommendedReasons.add(
             ERR_TLS_CIPHER_SUITE_SELECTOR_EXPORT_ENCRYPTION.get());
      }


      // Only cipher suites that use AES or ChaCha20 will be accepted.
      if (name.contains("_AES") || name.contains("_CHACHA20"))
      {
        // These are recommended bulk cipher algorithms.
      }
      else if (name.contains("_RC4"))
      {
        nonRecommendedReasons.add(
             ERR_TLS_CIPHER_SUITE_SELECTOR_NON_RECOMMENDED_KNOWN_BE_ALG.get(
                  "RC4"));
      }
      else if (name.contains("_3DES"))
      {
        nonRecommendedReasons.add(
             ERR_TLS_CIPHER_SUITE_SELECTOR_NON_RECOMMENDED_KNOWN_BE_ALG.get(
                  "3DES"));
      }
      else if (name.contains("_DES"))
      {
        nonRecommendedReasons.add(
             ERR_TLS_CIPHER_SUITE_SELECTOR_NON_RECOMMENDED_KNOWN_BE_ALG.get(
                  "DES"));
      }
      else if (name.contains("_IDEA"))
      {
        nonRecommendedReasons.add(
             ERR_TLS_CIPHER_SUITE_SELECTOR_NON_RECOMMENDED_KNOWN_BE_ALG.get(
                  "IDEA"));
      }
      else if (name.contains("_CAMELLIA"))
      {
        nonRecommendedReasons.add(
             ERR_TLS_CIPHER_SUITE_SELECTOR_NON_RECOMMENDED_KNOWN_BE_ALG.get(
                  "Camellia"));
      }
      else if (name.contains("_ARIA"))
      {
        nonRecommendedReasons.add(
             ERR_TLS_CIPHER_SUITE_SELECTOR_NON_RECOMMENDED_KNOWN_BE_ALG.get(
                  "ARIA"));
      }
      else
      {
        nonRecommendedReasons.add(
             ERR_TLS_CIPHER_SUITE_SELECTOR_NON_RECOMMENDED_UNKNOWN_BE_ALG.
                  get());
      }


      // Only cipher suites that use a SHA-1 or SHA-2 digest algorithm will be
      // accepted.
      if (name.endsWith("_SHA512") ||
           name.endsWith("_SHA384") ||
           name.endsWith("_SHA256"))
      {
        // These are recommended digest algorithms.
      }
      else if (name.endsWith("_SHA"))
      {
        if (ALLOW_SHA_1.get())
        {
          // This will be considered a recommended digest algorithm.
        }
        else
        {
          nonRecommendedReasons.add(
               ERR_TLS_CIPHER_SUITE_SELECTOR_NON_RECOMMENDED_KNOWN_DIGEST_ALG.
                    get("SHA-1"));
        }
      }
      else if (name.endsWith("_MD5"))
      {
        nonRecommendedReasons.add(
             ERR_TLS_CIPHER_SUITE_SELECTOR_NON_RECOMMENDED_KNOWN_DIGEST_ALG.get(
                  "MD5"));
      }
      else
      {
        nonRecommendedReasons.add(
             ERR_TLS_CIPHER_SUITE_SELECTOR_NON_RECOMMENDED_UNKNOWN_DIGEST_ALG.
                  get());
      }


      // Determine whether to recommend the cipher suite based on whether there
      // are any non-recommended reasons.
      if (nonRecommendedReasons.isEmpty())
      {
        recommendedSet.add(cipherSuiteName);
      }
      else
      {
        nonRecommendedMap.put(cipherSuiteName,
             Collections.unmodifiableList(nonRecommendedReasons));
      }
    }

    if (recommendedSet.isEmpty() && (! anyTLSSuitesFound) &&
         (! includeSSLSuites))
    {
      // We didn't find any suite names starting with "TLS_".  Assume that the
      // JVM only reports suites that start with "SSL_" and try again, allowing
      // those suites.
      return selectCipherSuites(cipherSuiteArray, true);
    }

    return new ObjectPair<>(recommendedSet, nonRecommendedMap);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "tls-cipher-suite-selector";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_TLS_CIPHER_SUITE_SELECTOR_TOOL_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolVersion()
  {
    return Version.NUMERIC_VERSION_STRING;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void addToolArguments(@NotNull final ArgumentParser parser)
       throws ArgumentException
  {
    // This tool does not require any arguments.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    generateOutput(getOut());
    return ResultCode.SUCCESS;
  }



  /**
   * Writes the output to the provided print stream.
   *
   * @param  s  The print stream to which the output should be written.
   */
  private void generateOutput(@NotNull final PrintStream s)
  {
    try
    {
      final SSLContext sslContext = CryptoHelper.getDefaultSSLContext();
      s.println("Supported TLS Protocols:");
      for (final String protocol :
           sslContext.getSupportedSSLParameters().getProtocols())
      {
        s.println("* " + protocol);
      }
      s.println();

      s.println("Enabled TLS Protocols:");
      for (final String protocol : SSLUtil.getEnabledSSLProtocols())
      {
        s.println("* " + protocol);
      }
      s.println();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    s.println("Supported TLS Cipher Suites:");
    for (final String cipherSuite : supportedCipherSuites)
    {
      s.println("* " + cipherSuite);
    }

    s.println();
    s.println("JVM-Default TLS Cipher Suites:");
    for (final String cipherSuite : defaultCipherSuites)
    {
      s.println("* " + cipherSuite);
    }

    s.println();
    s.println("Non-Recommended TLS Cipher Suites:");
    for (final Map.Entry<String,List<String>> e :
         nonRecommendedCipherSuites.entrySet())
    {
      s.println("* " + e.getKey());
      for (final String reason : e.getValue())
      {
        s.println("  - " + reason);
      }
    }

    s.println();
    s.println("Recommended TLS Cipher Suites:");
    for (final String cipherSuite : recommendedCipherSuites)
    {
      s.println("* " + cipherSuite);
    }
  }



  /**
   * Filters the provided collection of potential cipher suite names to retrieve
   * a set of the suites that are supported by the JVM.
   *
   * @param  potentialSuiteNames  The collection of cipher suite names to be
   *                              filtered.
   *
   * @return  The set of provided cipher suites that are supported by the JVM,
   *          or an empty set if none of the potential provided suite names are
   *          supported by the JVM.
   */
  @NotNull()
  public static Set<String> selectSupportedCipherSuites(
                     @Nullable final Collection<String> potentialSuiteNames)
  {
    if (potentialSuiteNames == null)
    {
      return Collections.emptySet();
    }

    final int capacity = StaticUtils.computeMapCapacity(
         INSTANCE.get().supportedCipherSuites.size());
    final Map<String,String> supportedMap = new HashMap<>(capacity);
    for (final String supportedSuite : INSTANCE.get().supportedCipherSuites)
    {
      supportedMap.put(
           StaticUtils.toUpperCase(supportedSuite).replace('-', '_'),
           supportedSuite);
    }

    final Set<String> selectedSet = new LinkedHashSet<>(capacity);
    for (final String potentialSuite : potentialSuiteNames)
    {
      final String supportedName = supportedMap.get(
           StaticUtils.toUpperCase(potentialSuite).replace('-', '_'));
      if (supportedName != null)
      {
        selectedSet.add(supportedName);
      }
    }

    return Collections.unmodifiableSet(selectedSet);
  }



  /**
   * Indicates whether cipher suites that use the RSA key exchange algorithm
   * should be recommended by default.
   *
   * @return  {@code true} if cipher suites that use the RSA key exchange
   *          algorithm should be recommended by default, or {@code false} if
   *          not.
   */
  public static boolean allowRSAKeyExchange()
  {
    return ALLOW_RSA_KEY_EXCHANGE.get();
  }



  /**
   * Specifies whether cipher suites that use the RSA key exchange algorithm
   * should be recommended by default.
   *
   * @param  allowRSAKeyExchange  Indicates whether cipher suites that use the
   *                              RSA key exchange algorithm should be
   *                              recommended by default.
   */
  public static void setAllowRSAKeyExchange(final boolean allowRSAKeyExchange)
  {
    ALLOW_RSA_KEY_EXCHANGE.set(allowRSAKeyExchange);
    recompute();
  }



  /**
   * Indicates whether cipher suites that use the SHA-1 digest algorithm should
   * be recommended by default.
   *
   * @return  {@code true} if cipher suites that use the SHA-1 digest algorithm
   *          should be recommended by default, or {@code false} if not.
   */
  public static boolean allowSHA1()
  {
    return ALLOW_SHA_1.get();
  }



  /**
   * Specifies whether cipher suites that use the SHA-1 digest algorithm should
   * be recommended by default.
   *
   * @param  allowSHA1  Indicates whether cipher suites that use the SHA-1
   *                    digest algorithm should be recommended by default.
   */
  public static void setAllowSHA1(final boolean allowSHA1)
  {
    ALLOW_SHA_1.set(allowSHA1);
    recompute();
  }



  /**
   * Re-computes the default instance of this cipher suite selector.  This may
   * be necessary after certain actions that alter the supported set of TLS
   * cipher suites (for example, installing or removing cryptographic
   * providers).
   */
  public static void recompute()
  {
    INSTANCE.set(new TLSCipherSuiteSelector(false));
  }
}
