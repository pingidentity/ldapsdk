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



import java.io.Serializable;
import java.util.Comparator;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a comparator that may be used to order TLS cipher suites
 * from most-preferred to least-preferred.  Note that its behavior is undefined
 * for strings that are not valid TLS cipher suite names.
 * <BR><BR>
 * This comparator uses the following logic:
 * <UL>
 *   <LI>
 *     Cipher suite names that end with "_SCSV" will be ordered after those that
 *     do not.  These are signalling cipher suite values that indicate special
 *     capabilities and aren't really cipher suites.
 *   </LI>
 *
 *   <LI>
 *     Cipher suite names that contain "_NULL" will be ordered after those that
 *     do not.
 *   </LI>
 *
 *   <LI>
 *     Cipher suite names that contain "_ANON" will be ordered after those that
 *     do not.
 *   </LI>
 *
 *   <LI>
 *     Cipher suite names that contain "_EXPORT" will be ordered after those
 *     that do not.
 *   </LI>
 *
 *   <LI>
 *     Cipher suites will be ordered according to their prefix, as follows:
 *     <UL>
 *       <LI>
 *         Suite names starting with TLS_AES_ will come first, as they are
 *         TLSv1.3 (or later) suites that use AES for bulk encryption.
 *       </LI>
 *       <LI>
 *         Suite names starting with TLS_CHACHA20_ will come next, as they are
 *         TLSv1.3 (or later) suites that use the ChaCha20 stream cipher, which
 *         is less widely supported than AES.
 *       </LI>
 *       <LI>
 *         Suite names starting with TLS_ECDHE_ will come next, as they use
 *         elliptic curve Diffie-Hellman key exchange with ephemeral keys,
 *         providing support for forward secrecy.
 *       </LI>
 *       <LI>
 *         Suite names starting with TLS_DHE_ will come next, as they use
 *         Diffie-Hellman key exchange with ephemeral keys, also providing
 *         support for forward secrecy, but less efficient than the elliptic
 *         curve variant.
 *       </LI>
 *       <LI>
 *         Suite names starting with TLS_RSA_ will come next, as they use RSA
 *         key exchange, which does not support forward secrecy, but is still
 *         considered secure.
 *       </LI>
 *       <LI>
 *         Suite names starting with TLS_ but that do not match any of the
 *         above values will come next, as they are less desirable than any of
 *         the more specific TLS-based suites.
 *       </LI>
 *       <LI>
 *         Suite names starting with SSL_ will come next, as they are legacy
 *         SSL-based protocols that should be considered weaker than TLS-based
 *         protocol.s
 *       </LI>
 *       <LI>
 *         Suite names that do not start with TLS_ or SSL_ will come last.  No
 *         such suites are expected.
 *       </LI>
 *     </UL>
 *   </LI>
 *
 *   <LI>
 *     Cipher suite names that contain _AES will be ordered before those that
 *     contain _CHACHA20, as AES is a more widely supported bulk cipher than
 *     ChaCha20.  Suite names that do not contain either _AES or _CHACHA20 will
 *     be ordered after those that contain _CHACHA20, as they likely use a bulk
 *     cipher that is weaker or not as widely supported.
 *   </LI>
 *
 *   <LI>
 *     Cipher suites that use AES with a GCM mode will be ordered before those
 *     that use AES with a non-GCM mode.  GCM (Galois/Counter Mode) uses
 *     authenticated encryption, which provides better security guarantees than
 *     non-authenticated encryption.
 *   </LI>
 *
 *   <LI>
 *     Cipher suites that use AES with a 256-bit key will be ordered before
 *     those that use AES with a 128-bit key.
 *   </LI>
 *
 *   <LI>
 *     Cipher suites will be ordered according to their digest algorithm, as
 *     follows:
 *     <UL>
 *       <LI>
 *         Suites that use a 512-bit SHA-2 digest will come first.  At present,
 *         no such suites are defined, but they may be added in the future.
 *       </LI>
 *       <LI>
 *         Suites that use a 384-bit SHA-2 digest will come next.
 *       </LI>
 *       <LI>
 *         Suites that use a 256-bit SHA-2 digest will come next.
 *       </LI>
 *       <LI>
 *         Suites that use a SHA-1 digest will come next.
 *       </LI>
 *       <LI>
 *         Suites that use any other digest algorithm will come last, as they
 *         likely use an algorithm that is weaker or not as widely supported.
 *       </LI>
 *     </UL>
 *   </LI>
 *
 *   <LI>
 *     If none of the above criteria can be used to differentiate the cipher
 *     suites, then it will fall back to simple lexicographic ordering.
 *   </LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TLSCipherSuiteComparator
       implements Comparator<String>, Serializable
{
  /**
   * The singleton instance of this comparator.
   */
  @NotNull private static final TLSCipherSuiteComparator INSTANCE =
       new TLSCipherSuiteComparator();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7719643162516590858L;



  /**
   * Creates a new instance of this comparator.
   */
  private TLSCipherSuiteComparator()
  {
    // No implementation is required.
  }



  /**
   * Retrieves the singleton instance of this TLS cipher suite comparator.
   *
   * @return  The singleton instance of this TLS cipher suite comparator.
   */
  @NotNull()
  public static TLSCipherSuiteComparator getInstance()
  {
    return INSTANCE;
  }



  /**
   * Compares the provided strings to determine the logical order of the TLS
   * cipher suites that they represent.
   *
   * @param  s1  The first string to compare.  It must not be {@code null}, and
   *             it should represent a valid cipher suite name.
   * @param  s2  The second string to compare.  It must not be {@code null}, and
   *             it should represent a valid cipher suite name.
   *
   * @return  A negative integer value if the first cipher suite name should be
   *          ordered before the second, a positive integer value if the first
   *          cipher suite name should be ordered after the second, or zero if
   *          the names are considered logically equivalent.
   */
  @Override()
  public int compare(@NotNull final String s1, @NotNull final String s2)
  {
    final String cipherSuiteName1 =
         StaticUtils.toUpperCase(s1).replace('-', '_');
    final String cipherSuiteName2 =
         StaticUtils.toUpperCase(s2).replace('-', '_');

    final int scsvOrder = getSCSVOrder(cipherSuiteName1, cipherSuiteName2);
    if (scsvOrder != 0)
    {
      return scsvOrder;
    }

    final int explicitlyWeakOrder =
         getExplicitlyWeakOrder(cipherSuiteName1, cipherSuiteName2);
    if (explicitlyWeakOrder != 0)
    {
      return explicitlyWeakOrder;
    }

    final int prefixOrder = getPrefixOrder(cipherSuiteName1, cipherSuiteName2);
    if (prefixOrder != 0)
    {
      return prefixOrder;
    }

    final int blockCipherOrder =
         getBlockCipherOrder(cipherSuiteName1, cipherSuiteName2);
    if (blockCipherOrder != 0)
    {
      return blockCipherOrder;
    }

    final int digestOrder = getDigestOrder(cipherSuiteName1, cipherSuiteName2);
    if (digestOrder != 0)
    {
      return digestOrder;
    }

    return s1.compareTo(s2);
  }



  /**
   * Attempts to order the provided cipher suite names using signalling cipher
   * suite values.
   *
   * @param  cipherSuiteName1  The first cipher suite name to compare.  It must
   *                           not be {@code null}, and it should represent a
   *                           valid cipher suite name.
   * @param  cipherSuiteName2  The second cipher suite name to compare.  It must
   *                           not be {@code null}, and it should represent a
   *                           valid cipher suite name.
   *
   * @return  A negative integer value if the first cipher suite name should be
   *          ordered before the second, a positive integer value if the first
   *          cipher suite should be ordered after the second, or zero if they
   *          are considered logically equivalent for the purposes of this
   *          method.
   */
  private static int getSCSVOrder(@NotNull final String cipherSuiteName1,
                                  @NotNull final String cipherSuiteName2)
  {
    if (cipherSuiteName1.endsWith("_SCSV"))
    {
      if (cipherSuiteName2.endsWith("_SCSV"))
      {
        return 0;
      }
      else
      {
        return 1;
      }
    }
    else if (cipherSuiteName2.endsWith("_SCSV"))
    {
      return -1;
    }
    else
    {
      return 0;
    }
  }



  /**
   * Attempts to order the provided cipher suite names by whether the use a
   * null component. anonymous authentication, or export-grade encryption.
   *
   * @param  cipherSuiteName1  The first cipher suite name to compare.  It must
   *                           not be {@code null}, and it should represent a
   *                           valid cipher suite name.
   * @param  cipherSuiteName2  The second cipher suite name to compare.  It must
   *                           not be {@code null}, and it should represent a
   *                           valid cipher suite name.
   *
   * @return  A negative integer value if the first cipher suite name should be
   *          ordered before the second, a positive integer value if the first
   *          cipher suite should be ordered after the second, or zero if they
   *          are considered logically equivalent for the purposes of this
   *          method.
   */
  private static int getExplicitlyWeakOrder(
               @NotNull final String cipherSuiteName1,
               @NotNull final String cipherSuiteName2)
  {
    if (cipherSuiteName1.contains("_NULL"))
    {
      if (! cipherSuiteName2.contains("_NULL"))
      {
        return 1;
      }
    }
    else if (cipherSuiteName2.contains("_NULL"))
    {
      return -1;
    }

    if (cipherSuiteName1.contains("_ANON"))
    {
      if (! cipherSuiteName2.contains("_ANON"))
      {
        return 1;
      }
    }
    else if (cipherSuiteName2.contains("_ANON"))
    {
      return -1;
    }

    if (cipherSuiteName1.contains("_EXPORT"))
    {
      if (! cipherSuiteName2.contains("_EXPORT"))
      {
        return 1;
      }
    }
    else if (cipherSuiteName2.contains("_EXPORT"))
    {
      return -1;
    }

    return 0;
  }



  /**
   * Attempts to order the provided cipher suite names using the protocol and
   * key agreement algorithm.
   *
   * @param  cipherSuiteName1  The first cipher suite name to compare.  It must
   *                           not be {@code null}, and it should represent a
   *                           valid cipher suite name.
   * @param  cipherSuiteName2  The second cipher suite name to compare.  It must
   *                           not be {@code null}, and it should represent a
   *                           valid cipher suite name.
   *
   * @return  A negative integer value if the first cipher suite name should be
   *          ordered before the second, a positive integer value if the first
   *          cipher suite should be ordered after the second, or zero if they
   *          are considered logically equivalent for the purposes of this
   *          method.
   */
  private static int getPrefixOrder(@NotNull final String cipherSuiteName1,
                                    @NotNull final String cipherSuiteName2)
  {
    final int prefixValue1 = getPrefixValue(cipherSuiteName1);
    final int prefixValue2 = getPrefixValue(cipherSuiteName2);
    return prefixValue1 - prefixValue2;
  }



  /**
   * Retrieves an integer value for the provided cipher suite name based on the
   * protocol and key agreement algorithm.  Lower values are preferred over
   * higher values.
   *
   * @param  cipherSuiteName  The cipher suite name for which to obtain the
   *                          prefix value.  It must not be {@code null}, and it
   *                          should represent a valid cipher suite name.
   *
   * @return  An integer value for the provided cipher suite name based on the
   *          protocol and key agreement algorithm.
   */
  private static int getPrefixValue(@NotNull final String cipherSuiteName)
  {
    if (cipherSuiteName.startsWith("TLS_AES_"))
    {
      return 1;
    }
    else if (cipherSuiteName.startsWith("TLS_CHACHA20_"))
    {
      return 2;
    }
    else if (cipherSuiteName.startsWith("TLS_ECDHE_"))
    {
      return 3;
    }
    else if (cipherSuiteName.startsWith("TLS_DHE_"))
    {
      return 4;
    }
    else if (cipherSuiteName.startsWith("TLS_RSA_"))
    {
      return 5;
    }
    else if (cipherSuiteName.startsWith("TLS_ECDH_"))
    {
      return 6;
    }
    else if (cipherSuiteName.startsWith("TLS_DH_"))
    {
      return 7;
    }
    else if (cipherSuiteName.startsWith("TLS_"))
    {
      return 8;
    }
    if (cipherSuiteName.startsWith("SSL_AES_"))
    {
      return 9;
    }
    else if (cipherSuiteName.startsWith("SSL_CHACHA20_"))
    {
      return 10;
    }
    else if (cipherSuiteName.startsWith("SSL_ECDHE_"))
    {
      return 11;
    }
    else if (cipherSuiteName.startsWith("SSL_DHE_"))
    {
      return 12;
    }
    else if (cipherSuiteName.startsWith("SSL_RSA_"))
    {
      return 13;
    }
    else if (cipherSuiteName.startsWith("SSL_ECDH_"))
    {
      return 14;
    }
    else if (cipherSuiteName.startsWith("SSL_DH_"))
    {
      return 15;
    }
    else if (cipherSuiteName.startsWith("SSL_"))
    {
      return 16;
    }
    else
    {
      return 17;
    }
  }



  /**
   * Attempts to order the provided cipher suite names using the block cipher
   * settings.
   *
   * @param  cipherSuiteName1  The first cipher suite name to compare.  It must
   *                           not be {@code null}, and it should represent a
   *                           valid cipher suite name.
   * @param  cipherSuiteName2  The second cipher suite name to compare.  It must
   *                           not be {@code null}, and it should represent a
   *                           valid cipher suite name.
   *
   * @return  A negative integer value if the first cipher suite name should be
   *          ordered before the second, a positive integer value if the first
   *          cipher suite should be ordered after the second, or zero if they
   *          are considered logically equivalent for the purposes of this
   *          method.
   */
  private static int getBlockCipherOrder(@NotNull final String cipherSuiteName1,
                                         @NotNull final String cipherSuiteName2)
  {
    final int blockCipherValue1 = getBlockCipherValue(cipherSuiteName1);
    final int blockCipherValue2 = getBlockCipherValue(cipherSuiteName2);
    return blockCipherValue1 - blockCipherValue2;
  }



  /**
   * Retrieves an integer value for the provided cipher suite name based on the
   * block cipher settings.  Lower values are preferred over higher values.
   *
   * @param  cipherSuiteName  The cipher suite name for which to obtain the
   *                          prefix value.  It must not be {@code null}, and it
   *                          should represent a valid cipher suite name.
   *
   * @return  An integer value for the provided cipher suite name based on the
   *          block cipher settings.
   */
  private static int getBlockCipherValue(@NotNull final String cipherSuiteName)
  {
    if (cipherSuiteName.contains("_AES_256_GCM"))
    {
      return 1;
    }
    else if (cipherSuiteName.contains("_AES_128_GCM"))
    {
      return 2;
    }
    else if (cipherSuiteName.contains("_AES") &&
         cipherSuiteName.contains("_GCM"))
    {
      return 3;
    }
    else if (cipherSuiteName.contains("_AES_256"))
    {
      return 4;
    }
    else if (cipherSuiteName.contains("_AES_128"))
    {
      return 5;
    }
    else if (cipherSuiteName.contains("_AES"))
    {
      return 6;
    }
    else if (cipherSuiteName.contains("_CHACHA20"))
    {
      return 7;
    }
    else if (cipherSuiteName.contains("_GCM"))
    {
      return 8;
    }
    else
    {
      return 9;
    }
  }



  /**
   * Attempts to order the provided cipher suite names using the block cipher
   * settings.
   *
   * @param  cipherSuiteName1  The first cipher suite name to compare.  It must
   *                           not be {@code null}, and it should represent a
   *                           valid cipher suite name.
   * @param  cipherSuiteName2  The second cipher suite name to compare.  It must
   *                           not be {@code null}, and it should represent a
   *                           valid cipher suite name.
   *
   * @return  A negative integer value if the first cipher suite name should be
   *          ordered before the second, a positive integer value if the first
   *          cipher suite should be ordered after the second, or zero if they
   *          are considered logically equivalent for the purposes of this
   *          method.
   */
  private static int getDigestOrder(@NotNull final String cipherSuiteName1,
                                    @NotNull final String cipherSuiteName2)
  {
    final int digestValue1 = getDigestValue(cipherSuiteName1);
    final int digestValue2 = getDigestValue(cipherSuiteName2);
    return digestValue1 - digestValue2;
  }



  /**
   * Retrieves an integer value for the provided cipher suite name based on the
   * block cipher settings.  Lower values are preferred over higher values.
   *
   * @param  cipherSuiteName  The cipher suite name for which to obtain the
   *                          prefix value.  It must not be {@code null}, and it
   *                          should represent a valid cipher suite name.
   *
   * @return  An integer value for the provided cipher suite name based on the
   *          block cipher settings.
   */
  private static int getDigestValue(@NotNull final String cipherSuiteName)
  {
    if (cipherSuiteName.endsWith("_SHA512"))
    {
      return 1;
    }
    else if (cipherSuiteName.endsWith("_SHA384"))
    {
      return 2;
    }
    else if (cipherSuiteName.endsWith("_SHA256"))
    {
      return 3;
    }
    else if (cipherSuiteName.endsWith("_SHA"))
    {
      return 4;
    }
    else
    {
      return 5;
    }
  }



  /**
   * Indicates whether the provided object is logically equivalent to this TLS
   * cipher suite comparator.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is logically equivalent to
   *          this TLS cipher suite comparator.
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    return ((o != null) && (o instanceof TLSCipherSuiteComparator));
  }



  /**
   * Retrieves the hash code for this TLS cipher suite comparator.
   *
   * @return  The hash code for this TLS cipher suite comparator.
   */
  @Override()
  public int hashCode()
  {
    return 0;
  }
}
