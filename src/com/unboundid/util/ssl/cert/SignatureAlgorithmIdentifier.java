/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.util.ssl.cert;



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.OID;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines a set of algorithm names and OIDs.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum SignatureAlgorithmIdentifier
{
  /**
   * The algorithm identifier for the MD2 message digest with RSA encryption.
   * This identifier is defined in RFC 3279 section 2.2.1.
   */
  MD2_WITH_RSA("1.2.840.113549.1.1.2", "MD2withRSA", "MD2 with RSA"),



  /**
   * The algorithm identifier for the MD5 message digest with RSA encryption.
   * This identifier is defined in RFC 3279 section 2.2.1.
   */
  MD5_WITH_RSA("1.2.840.113549.1.1.4", "MD5withRSA", "MD5 with RSA"),



  /**
   * The algorithm identifier for the SHA-1 message digest with RSA encryption.
   * This identifier is defined in RFC 3279 section 2.2.1.
   */
  SHA_1_WITH_RSA("1.2.840.113549.1.1.5", "SHA1withRSA", "SHA-1 with RSA"),



  /**
   * The algorithm identifier for the 224-bit SHA-2 message digest with RSA
   * encryption.  This identifier is defined in RFC 4055 section 5.
   */
  SHA_224_WITH_RSA("1.2.840.113549.1.1.14", "SHA224withRSA",
       "SHA-224 with RSA"),



  /**
   * The algorithm identifier for the 256-bit SHA-2 message digest with RSA
   * encryption.  This identifier is defined in RFC 4055 section 5.
   */
  SHA_256_WITH_RSA("1.2.840.113549.1.1.11", "SHA256withRSA",
       "SHA-256 with RSA"),



  /**
   * The algorithm identifier for the 384-bit SHA-2 message digest with RSA
   * encryption.  This identifier is defined in RFC 4055 section 5.
   */
  SHA_384_WITH_RSA("1.2.840.113549.1.1.12", "SHA384withRSA",
       "SHA-384 with RSA"),



  /**
   * The algorithm identifier for the 512-bit SHA-2 message digest with RSA
   * encryption.  This identifier is defined in RFC 4055 section 5.
   */
  SHA_512_WITH_RSA("1.2.840.113549.1.1.13", "SHA512withRSA",
       "SHA-512 with RSA"),



  /**
   * The algorithm identifier for the SHA-1 message digest with the DSA
   * signature algorithm.  This identifier is defined in RFC 3279 section 2.2.2.
   */
  SHA_1_WITH_DSA("1.2.840.10040.4.3", "SHA1withDSA", "SHA-1 with DSA"),



  /**
   * The algorithm identifier for the 224-bit SHA-2 message digest with the DSA
   * signature algorithm.  This identifier is defined in RFC 5758 section 3.1.
   */
  SHA_224_WITH_DSA("2.16.840.1.101.3.4.3.1", "SHA224withDSA",
       "SHA-224 with DSA"),



  /**
   * The algorithm identifier for the 256-bit SHA-2 message digest with the DSA
   * signature algorithm.  This identifier is defined in RFC 5758 section 3.1.
   */
  SHA_256_WITH_DSA("2.16.840.1.101.3.4.3.2", "SHA256withDSA",
       "SHA-256 with DSA"),



  /**
   * The algorithm identifier for the SHA-1 message digest with the ECDSA
   * signature algorithm.  This identifier is defined in RFC 3279 section 2.2.3.
   */
  SHA_1_WITH_ECDSA("1.2.840.10045.4.1", "SHA1withECDSA", "SHA-1 with ECDSA"),



  /**
   * The algorithm identifier for the 224-bit SHA-2 message digest with the
   * ECDSA signature algorithm.  This identifier is defined in RFC 5758 section
   * 3.2.
   */
  SHA_224_WITH_ECDSA("1.2.840.10045.4.3.1", "SHA224withECDSA",
       "SHA-224 with ECDSA"),



  /**
   * The algorithm identifier for the 256-bit SHA-2 message digest with the
   * ECDSA signature algorithm.  This identifier is defined in RFC 5758 section
   * 3.2.
   */
  SHA_256_WITH_ECDSA("1.2.840.10045.4.3.2", "SHA256withECDSA",
       "SHA-256 with ECDSA"),



  /**
   * The algorithm identifier for the 384-bit SHA-2 message digest with the
   * ECDSA signature algorithm.  This identifier is defined in RFC 5758 section
   * 3.2.
   */
  SHA_384_WITH_ECDSA("1.2.840.10045.4.3.3", "SHA384withECDSA",
       "SHA-384 with ECDSA"),



  /**
   * The algorithm identifier for the 512-bit SHA-2 message digest with the
   * ECDSA signature algorithm.  This identifier is defined in RFC 5758 section
   * 3.2.
   */
  SHA_512_WITH_ECDSA("1.2.840.10045.4.3.4", "SHA512withECDSA",
       "SHA-512 with ECDSA");



  // The OID for this signature algorithm.
  @NotNull private final OID oid;

  // The name for this signature algorithm as it would be used internally by
  // Java.
  @NotNull private final String javaName;

  // The user-friendly name for this signature algorithm.
  @NotNull private final String userFriendlyName;



  /**
   * Creates a new signature algorithm with the provided information.
   *
   * @param  oidString         The string representation of the OID for this
   *                           signature algorithm.
   * @param  javaName          The name for this signature algorithm as it would
   *                           be used internally by Java.
   * @param  userFriendlyName  The user-friendly name for this signature
   *                           algorithm.
   */
  SignatureAlgorithmIdentifier(@NotNull final String oidString,
                               @NotNull final String javaName,
                               @NotNull final String userFriendlyName)
  {
    this.javaName = javaName;
    this.userFriendlyName = userFriendlyName;

    oid = new OID(oidString);
  }



  /**
   * Retrieves the OID for this signature algorithm.
   *
   * @return  The OID for this signature algorithm.
   */
  @NotNull()
  public OID getOID()
  {
    return oid;
  }



  /**
   * Retrieves the name for this signature algorithm as it would be used
   * internally by Java.
   *
   * @return  The name for this signature algorithm as it would be used
   *          internally by Java.
   */
  @NotNull()
  public String getJavaName()
  {
    return javaName;
  }



  /**
   * Retrieves the user-friendly name for this signature algorithm.
   *
   * @return  The user-friendly name for this signature algorithm.
   */
  @NotNull()
  public String getUserFriendlyName()
  {
    return userFriendlyName;
  }



  /**
   * Retrieves the signature algorithm identifier instance with the specified
   * OID.
   *
   * @param  oid  The OID for the signature algorithm identifier instance to
   *              retrieve.
   *
   * @return  The appropriate signature algorithm identifier instance, or
   *          {@code null} if the provided OID does not reference a known
   *          signature algorithm identifier.
   */
  @Nullable()
  public static SignatureAlgorithmIdentifier forOID(@NotNull final OID oid)
  {
    for (final SignatureAlgorithmIdentifier v : values())
    {
      if (v.oid.equals(oid))
      {
        return v;
      }
    }

    return null;
  }



  /**
   * Retrieves the signature algorithm identifier instance with the specified
   * name.
   *
   * @param  name  The name of the signature algorithm identifier instance to
   *               retrieve.
   *
   * @return  The appropriate signature algorithm identifier instance, or
   *          {@code null} if the provided name does not reference a known
   *          signature algorithm identifier.
   */
  @Nullable()
  public static SignatureAlgorithmIdentifier forName(@NotNull final String name)
  {
    final String preparedName = prepareName(name);
    for (final SignatureAlgorithmIdentifier v : values())
    {
      if (v.javaName.equalsIgnoreCase(preparedName))
      {
        return v;
      }
    }

    return null;
  }



  /**
   * Prepares the provided name to be used by the {@link #forName(String)}
   * method.  All spaces, dashes, and underscores will be removed.
   *
   * @param  name  The name to be compared.
   *
   * @return  The prepared version of the provided name.
   */
  @NotNull()
  private static String prepareName(@NotNull final String name)
  {
    final StringBuilder buffer = new StringBuilder(name.length());

    for (final char c : name.toCharArray())
    {
      switch (c)
      {
        case ' ':
        case '-':
        case '_':
          // This character will be omitted.
          break;
        default:
          // This character will be used.
          buffer.append(c);
      }
    }

    return buffer.toString();
  }



  /**
   * Retrieves the user-friendly name for the signature algorithm identifier
   * value with the provided OID, or a string representation of the OID if there
   * is no value with that OID.
   *
   * @param  oid  The OID for the signature algorithm identifier to retrieve.
   *
   * @return  The user-friendly name for the signature algorithm identifier
   *          value with the provided OID, or a string representation of the OID
   *          if there is no value with that OID.
   */
  @NotNull()
  public static String getNameOrOID(@NotNull final OID oid)
  {
    final SignatureAlgorithmIdentifier id = forOID(oid);
    if (id == null)
    {
      return oid.toString();
    }
    else
    {
      return id.userFriendlyName;
    }
  }



  /**
   * Retrieves a string representation of this signature algorithm identifier.
   *
   * @return  A string representation of this signature algorithm identifier.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return userFriendlyName;
  }
}
