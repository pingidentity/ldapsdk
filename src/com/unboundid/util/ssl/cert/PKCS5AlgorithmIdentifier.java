/*
 * Copyright 2022-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2023 Ping Identity Corporation
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
 * Copyright (C) 2022-2023 Ping Identity Corporation
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



import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.OID;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.cert.CertMessages.*;



/**
 * This enum defines a set of OIDs and algorithm names for password-based
 * cryptography as described in the PKCS #5 specification defined in RFC 8018.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum PKCS5AlgorithmIdentifier
{
  /**
   * The algorithm identifier for the PBES2 encryption scheme.  This scheme is
   * defined in RFC 8018 section 6.2, and the identifier is defined in appendix
   * A.4 of that specification.
   */
  PBES2("1.2.840.113549.1.5.13", "PBES2", Collections.<String>emptySet(),
       INFO_PKCS5_ALG_ID_DESC_PBES2.get()),



  /**
   * The algorithm identifier for the PBKDF2 key derivation function, which is
   * intended to be used by the PBES2 encryption scheme.  This identifier is
   * described in RFC 8018 appendix A.2.
   */
  PBKDF2("1.2.840.113549.1.5.12", "PBKDF2", Collections.<String>emptySet(),
       INFO_PKCS5_ALG_ID_DESC_PBKDF2.get()),



  /**
   * The algorithm identifier for the HMAC-SHA-1 pseudorandom function, which
   * may be used in conjunction with the PBKDF2 key derivation function.  This
   * identifier is described in RFC 8018 appendix B.1.1.
   */
  HMAC_SHA_1("1.2.840.113549.2.7", "HMAC-SHA-1",
       StaticUtils.setOf("HMAC-SHA", "HmacSHA"),
       INFO_PKCS5_ALG_ID_DESC_HMAC_SHA_1.get()),



  /**
   * The algorithm identifier for the HMAC-SHA-224 pseudorandom function, which
   * may be used in conjunction with the PBKDF2 key derivation function.  This
   * identifier is described in RFC 8018 appendix B.1.2.
   */
  HMAC_SHA_224("1.2.840.113549.2.8", "HMAC-SHA-224",
       StaticUtils.setOf("HmacSHA224"),
       INFO_PKCS5_ALG_ID_DESC_HMAC_SHA_224.get()),



  /**
   * The algorithm identifier for the HMAC-SHA-256 pseudorandom function, which
   * may be used in conjunction with the PBKDF2 key derivation function.  This
   * identifier is described in RFC 8018 appendix B.1.2.
   */
  HMAC_SHA_256("1.2.840.113549.2.9", "HMAC-SHA-256",
       StaticUtils.setOf("HmacSHA256"),
       INFO_PKCS5_ALG_ID_DESC_HMAC_SHA_256.get()),



  /**
   * The algorithm identifier for the HMAC-SHA-384 pseudorandom function, which
   * may be used in conjunction with the PBKDF2 key derivation function.  This
   * identifier is described in RFC 8018 appendix B.1.2.
   */
  HMAC_SHA_384("1.2.840.113549.2.10", "HMAC-SHA-384",
       StaticUtils.setOf("HmacSHA384"),
       INFO_PKCS5_ALG_ID_DESC_HMAC_SHA_384.get()),



  /**
   * The algorithm identifier for the HMAC-SHA-512 pseudorandom function, which
   * may be used in conjunction with the PBKDF2 key derivation function.  This
   * identifier is described in RFC 8018 appendix B.1.2.
   */
  HMAC_SHA_512("1.2.840.113549.2.11", "HMAC-SHA-512",
       StaticUtils.setOf("HmacSHA512"),
       INFO_PKCS5_ALG_ID_DESC_HMAC_SHA_512.get()),



  /**
   * The algorithm identifier for the DESede/CBC/PKCS5Padding cipher
   * transformation.  This identifier is described in RFC 8018 appendix B.2.2.
   */
  DES_EDE3_CBC_PAD("1.2.840.113549.3.7", "DES-EDE3-CBC-PAD",
       StaticUtils.setOf("DES-EDE-CBC-PAD", "DES-EDE3-CBC", "DES-EDE-CBC",
            "DES-EDE3", "DESEDE3", "DES-EDE", "DESEDE",
            "3DES-CBC-PAD", "3DES-CBC", "3DES"),
       INFO_PKCS5_ALG_ID_DESC_DES_EDE_CBC_PAD.get()),



  /**
   * The algorithm identifier for the 128-bit AES/CBC/PKCS5Padding cipher
   * transformation.  This identifier is described in RFC 8018 appendix B.2.2.
   */
  AES_128_CBC_PAD("2.16.840.1.101.3.4.1.2", "AES-128-CBC-PAD",
       StaticUtils.setOf("AES128-CBC", "AES128", "AES",
            "AES/CBC/PKCS5Padding", "AES128/CBC/PKCS5Padding"),
       INFO_PKCS5_ALG_ID_DESC_AES_128_CBC_PAD.get()),



  /**
   * The algorithm identifier for the 192-bit AES/CBC/PKCS5Padding cipher
   * transformation.  This identifier is described in RFC 8018 appendix C.
   */
  AES_192_CBC_PAD("2.16.840.1.101.3.4.1.22", "AES-192-CBC-PAD",
       StaticUtils.setOf("AES192-CBC", "AES192",  "AES192/CBC/PKCS5Padding"),
       INFO_PKCS5_ALG_ID_DESC_AES_192_CBC_PAD.get()),



  /**
   * The algorithm identifier for the 256-bit AES/CBC/PKCS5Padding cipher
   * transformation.  This identifier is described in RFC 8018 appendix C.
   */
  AES_256_CBC_PAD("2.16.840.1.101.3.4.1.42", "AES-256-CBC-PAD",
       StaticUtils.setOf("AES256-CBC", "AES256",  "AES256/CBC/PKCS5Padding"),
       INFO_PKCS5_ALG_ID_DESC_AES_256_CBC_PAD.get());



  /**
   * Retrieve a map of pseudorandom functions defined in this set of PKCS #5
   * algorithm identifiers.  The value for each item in the map will be the
   * name of the secret key factory algorithm that corresponds to the PBKDF2
   * variant that uses the specified function.
   */
  @NotNull private static final Map<PKCS5AlgorithmIdentifier,String>
       PSEUDORANDOM_FUNCTIONS = StaticUtils.mapOf(
            HMAC_SHA_1, "PBKDF2WithHmacSHA1",
            HMAC_SHA_224, "PBKDF2WithHmacSHA224",
            HMAC_SHA_256, "PBKDF2WithHmacSHA256",
            HMAC_SHA_384, "PBKDF2WithHmacSHA384",
            HMAC_SHA_512, "PBKDF2WithHmacSHA512");



  /**
   * A map of information about cipher transformations defined in this set of
   * PKCS #5 algorithm identifiers.  The value for each item in the map is an
   * object pair in which the first element is the name of the cipher
   * transformation and the second element is the expected key size, in bits.
   */
  @NotNull()
  private static final Map<PKCS5AlgorithmIdentifier,ObjectPair<String,Integer>>
       CIPHER_TRANSFORMATIONS = StaticUtils.mapOf(
            DES_EDE3_CBC_PAD, new ObjectPair<>("DESede/CBC/PKCS5Padding", 192),
            AES_128_CBC_PAD, new ObjectPair<>("AES/CBC/PKCS5Padding", 128),
            AES_192_CBC_PAD, new ObjectPair<>("AES/CBC/PKCS5Padding", 192),
            AES_256_CBC_PAD, new ObjectPair<>("AES/CBC/PKCS5Padding", 256));



  // The OID for this identifier.
  @NotNull private final OID oid;

  // A set of prepared names that may be used to reference this algorithm
  // identifier.
  @NotNull private final Set<String> preparedNames;

  // A human-readable description for the associated algorithm.
  @NotNull private final String description;

  // The primary name for the associated algorithm.
  @NotNull private final String primaryName;



  /**
   * Creates a new PKCS #5 algorithm identifier with the provided information.
   *
   * @param  oidString         The string representation of the OID for this
   *                           algorithm identifier.  It must not be
   *                           {@code null} and must represent a valid OID.
   * @param  primaryName       The primary name for this algorithm identifier.
   *                           It must not be {@code null}.
   * @param  alternativeNames  A set of alternative names for this algorithm
   *                           identifier.  It must not be {@code null}, but may
   *                           be empty.
   * @param  description       A human-readable description for the associated
   *                           algorithm.
   */
  PKCS5AlgorithmIdentifier(@NotNull final String oidString,
                           @NotNull final String primaryName,
                           @NotNull final Set<String> alternativeNames,
                           @NotNull final String description)
  {
    this.primaryName = primaryName;
    this.description = description;

    final Set<String> preparedNameSet = new HashSet<>();
    preparedNameSet.add(prepareName(primaryName));
    for (final String alternativeName : alternativeNames)
    {
      preparedNameSet.add(prepareName(alternativeName));
    }

    preparedNames = Collections.unmodifiableSet(preparedNameSet);

    oid = new OID(oidString);
  }



  /**
   * Retrieves the OID for this PKCS #5 algorithm identifier.
   *
   * @return  The OID for this PKCS #5 algorithm identifier.
   */
  @NotNull()
  public OID getOID()
  {
    return oid;
  }



  /**
   * Retrieves the name for the algorithm.
   *
   * @return  The name for the algorithm.
   */
  @NotNull()
  public String getName()
  {
    return primaryName;
  }



  /**
   * Retrieves a human-readable description for the algorithm.
   *
   * @return  A human-readable description for the algorithm.
   */
  @NotNull()
  public String getDescription()
  {
    return description;
  }



  /**
   * Retrieves the PKCS #5 algorithm identifier with the specified OID.
   *
   * @param  oid  The OID for the PKCS #5 algorithm identifier instance to
   *              retrieve.  It must not be {@code null}.
   *
   * @return  The appropriate PKCS #5 algorithm identifier instance, or
   *          {@code null} if the provided OID does not reference a known PKCS
   *          #5 algorithm identifier.
   */
  @Nullable()
  public static PKCS5AlgorithmIdentifier forOID(@NotNull final OID oid)
  {
    for (final PKCS5AlgorithmIdentifier v : values())
    {
      if (v.oid.equals(oid))
      {
        return v;
      }
    }

    return null;
  }



  /**
   * Retrieves the PKCS #5 algorithm identifier with the specified name.
   *
   * @param  name  The name for the PKCS #5 algorithm identifier to retrieve.
   *               It must not be {@code null}.
   *
   * @return  The appropriate PKCS #5 algorithm identifier instance, or
   *          {@code null} if the provided name does not reference a known PKCS
   *          #5 algorithm identifier.
   */
  @Nullable()
  public static PKCS5AlgorithmIdentifier forName(@NotNull final String name)
  {
    final String preparedName = prepareName(name);
    for (final PKCS5AlgorithmIdentifier v : values())
    {
      if (v.preparedNames.contains(preparedName))
      {
        return v;
      }
    }

    return null;
  }



  /**
   * Prepares the provided name to be used by the {@link #forName(String)}
   * method.  All spaces, dashes, underscores, and forward slashes will be
   * removed.
   *
   * @param  name  The name to be compared.
   *
   * @return  The prepared version of the provided name.
   */
  @NotNull()
  private static String prepareName(@NotNull final String name)
  {
    final StringBuilder buffer = new StringBuilder(name.length());

    for (final char c : name.toLowerCase().toCharArray())
    {
      switch (c)
      {
        case ' ':
        case '-':
        case '_':
        case '/':
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
   * Retrieves the human-readable name for the PKCS #5 algorithm identifier
   * value with the provided OID, or a string representation of the OID if there
   * is no value with that OID.
   *
   * @param  oid  The OID for the PKCS #5 algorithm identifier to retrieve.
   *
   * @return  The human-readable name for the PKCS #5 algorithm identifier value
   *          with the provided OID, or a string representation of the OID if
   *          there is no value with that OID.
   */
  @NotNull()
  public static String getNameOrOID(@NotNull final OID oid)
  {
    final PKCS5AlgorithmIdentifier id = forOID(oid);
    if (id == null)
    {
      return oid.toString();
    }
    else
    {
      return id.primaryName;
    }
  }



  /**
   * Retrieves the set of PKCS #5 algorithm identifiers that represent
   * pseudorandom functions.
   *
   * @return  The set of PKCS #5 algorithm identifiers that represent
   *          pseudorandom functions.
   */
  @NotNull()
  public static Set<PKCS5AlgorithmIdentifier> getPseudorandomFunctions()
  {
    return PSEUDORANDOM_FUNCTIONS.keySet();
  }



  /**
   * Retrieves the name of the secret key factory algorithm that should be used
   * to create a PBKDF2 key factory that uses the specified pseudorandom
   * function.
   *
   * @param  identifier  The PKCS #5 algorithm identifier that represents the
   *                     pseudorandom function for which to obtain the name of
   *                     the corresponding PBKDF2 secret key factory algorithm.
   *                     It must not be {@code null}.
   *
   * @return  The name of the PBKDF2 key factory algorithm that uses the
   *          specified pseudorandom function, or {@code null} if the provided
   *          identifier does not represent a known pseudorandom function.
   */
  @Nullable()
  public static String
              getPBKDF2SecretKeyFactoryAlgorithmForPseudorandomFunction(
                   @NotNull final PKCS5AlgorithmIdentifier identifier)
  {
    return PSEUDORANDOM_FUNCTIONS.get(identifier);
  }



  /**
   * Retrieves the set of PKCS #5 algorithm identifiers that represent cipher
   * transformations.
   *
   * @return  The set of PKCS #5 algorithm identifiers that represent cipher
   *          transformations.
   */
  @NotNull()
  public static Set<PKCS5AlgorithmIdentifier> getCipherTransformations()
  {
    return CIPHER_TRANSFORMATIONS.keySet();
  }



  /**
   * Retrieves the name of the cipher algorithm that should be used when
   * creating a secret key for the specified cipher transformation.
   *
   * @param  identifier  The PKCS #5 algorithm identifier that represents the
   *                     cipher transformation for which to obtain the name of
   *                     the corresponding cipher algorithm.  It must not be
   *                     {@code null}.
   *
   * @return  The name of the cipher algorithm that should be used when creating
   *          a secret key for the specified cipher transformation, or
   *          {@code null} if the provided identifier does not represent a known
   *          cipher transformation.
   */
  @Nullable()
  public static String getCipherAlgorithmName(
              @NotNull final PKCS5AlgorithmIdentifier identifier)
  {
    final ObjectPair<String,Integer> cipherTransformationPair =
         CIPHER_TRANSFORMATIONS.get(identifier);
    if (cipherTransformationPair == null)
    {
      return null;
    }

    final String cipherTransformationName = cipherTransformationPair.getFirst();
    final int slashPos = cipherTransformationName.indexOf('/');
    return cipherTransformationName.substring(0, slashPos);
  }



  /**
   * Retrieves the name of the cipher transformation that should be used when
   * creating a cipher instance for the specified cipher transformation.
   *
   * @param  identifier  The PKCS #5 algorithm identifier that represents the
   *                     cipher transformation for which to obtain the name.  It
   *                     must not be {@code null}.
   *
   * @return  The name of the cipher transformation that should be used when
   *          creating a cipher instance for the specified cipher
   *          transformation, or {@code null} if the provided identifier does
   *          not represent a known cipher transformation.
   */
  @Nullable()
  public static String getCipherTransformationName(
              @NotNull final PKCS5AlgorithmIdentifier identifier)
  {
    final ObjectPair<String,Integer> cipherTransformationPair =
         CIPHER_TRANSFORMATIONS.get(identifier);
    if (cipherTransformationPair == null)
    {
      return null;
    }

    return cipherTransformationPair.getFirst();
  }



  /**
   * Retrieves the key size, in bits, that should be used when creating a
   * secret key for the specified cipher transformation.
   *
   * @param  identifier  The PKCS #5 algorithm identifier that represents the
   *                     cipher transformation for which to obtain the key size.
   *                     It must not be {@code null}.
   *
   * @return  The key size, in bits, that should be used when creating a secret
   *          key for the specified cipher transformation, or {@code null} if
   *          the provided identifier does not represent a known cipher
   *          transformation.
   */
  @Nullable()
  public static Integer getCipherKeySizeBits(
              @NotNull final PKCS5AlgorithmIdentifier identifier)
  {
    final ObjectPair<String,Integer> cipherTransformationPair =
         CIPHER_TRANSFORMATIONS.get(identifier);
    if (cipherTransformationPair == null)
    {
      return null;
    }

    return cipherTransformationPair.getSecond();
  }



  /**
   * Retrieves a string representation of this PKCS #5 algorithm identifier.
   *
   * @return  A string representation of this PKCS #5 algorithm identifier.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return primaryName;
  }
}
