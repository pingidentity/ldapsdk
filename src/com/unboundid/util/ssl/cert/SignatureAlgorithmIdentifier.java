/*
 * Copyright 2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017 Ping Identity Corporation
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
  MD2_WITH_RSA("1.2.840.113549.1.1.2", "MD2withRSA"),



  /**
   * The algorithm identifier for the MD5 message digest with RSA encryption.
   * This identifier is defined in RFC 3279 section 2.2.1.
   */
  MD5_WITH_RSA("1.2.840.113549.1.1.4", "MD5withRSA"),



  /**
   * The algorithm identifier for the SHA-1 message digest with RSA encryption.
   * This identifier is defined in RFC 3279 section 2.2.1.
   */
  SHA_1_WITH_RSA("1.2.840.113549.1.1.5", "SHA1withRSA"),



  /**
   * The algorithm identifier for the 224-bit SHA-2 message digest with RSA
   * encryption.  This identifier is defined in RFC 4055 section 5.
   */
  SHA_224_WITH_RSA("1.2.840.113549.1.1.14", "SHA224withRSA"),



  /**
   * The algorithm identifier for the 256-bit SHA-2 message digest with RSA
   * encryption.  This identifier is defined in RFC 4055 section 5.
   */
  SHA_256_WITH_RSA("1.2.840.113549.1.1.11", "SHA256withRSA"),



  /**
   * The algorithm identifier for the 384-bit SHA-2 message digest with RSA
   * encryption.  This identifier is defined in RFC 4055 section 5.
   */
  SHA_384_WITH_RSA("1.2.840.113549.1.1.12", "SHA384withRSA"),



  /**
   * The algorithm identifier for the 512-bit SHA-2 message digest with RSA
   * encryption.  This identifier is defined in RFC 4055 section 5.
   */
  SHA_512WITH_RSA("1.2.840.113549.1.1.13", "SHA512withRSA"),



  /**
   * The algorithm identifier for the SHA-1 message digest with the DSA
   * signature algorithm.  This identifier is defined in RFC 3279 section 2.2.2.
   */
  SHA_1_WITH_DSA("1.2.840.10040.4.3", "SHA1withDSA"),



  /**
   * The algorithm identifier for the 224-bit SHA-2 message digest with the DSA
   * signature algorithm.  This identifier is defined in RFC 5758 section 3.1.
   */
  SHA_224_WITH_DSA("2.16.840.1.101.3.4.3.1", "SHA224withDSA"),



  /**
   * The algorithm identifier for the 256-bit SHA-2 message digest with the DSA
   * signature algorithm.  This identifier is defined in RFC 5758 section 3.1.
   */
  SHA_256_WITH_DSA("2.16.840.1.101.3.4.3.2", "SHA256withDSA"),



  /**
   * The algorithm identifier for the SHA-1 message digest with the ECDSA
   * signature algorithm.  This identifier is defined in RFC 3279 section 2.2.3.
   */
  SHA_1_WITH_ECDSA("1.2.840.10045.4.1", "SHA1withECDSA"),



  /**
   * The algorithm identifier for the 224-bit SHA-2 message digest with the
   * ECDSA signature algorithm.  This identifier is defined in RFC 5758 section
   * 3.2.
   */
  SHA_224_WITH_ECDSA("1.2.840.10045.4.3.1", "SHA224withECDSA"),



  /**
   * The algorithm identifier for the 256-bit SHA-2 message digest with the
   * ECDSA signature algorithm.  This identifier is defined in RFC 5758 section
   * 3.2.
   */
  SHA_256_WITH_ECDSA("1.2.840.10045.4.3.2", "SHA256withECDSA"),



  /**
   * The algorithm identifier for the 384-bit SHA-2 message digest with the
   * ECDSA signature algorithm.  This identifier is defined in RFC 5758 section
   * 3.2.
   */
  SHA_384_WITH_ECDSA("1.2.840.10045.4.3.3", "SHA384withECDSA"),



  /**
   * The algorithm identifier for the 512-bit SHA-2 message digest with the
   * ECDSA signature algorithm.  This identifier is defined in RFC 5758 section
   * 3.2.
   */
  SHA_512_WITH_ECDSA("1.2.840.10045.4.3.4", "SHA512withECDSA");



  // The OID for this signature algorithm.
  private final OID oid;

  // The name for this signature algorithm.
  private final String name;



  /**
   * Creates a new signature algorithm with the provided information.
   *
   * @param  oidString  The string representation of the OID for this signature
   *                    algorithm.
   * @param  name       The name for this signature algorithm.
   */
  SignatureAlgorithmIdentifier(final String oidString, final String name)
  {
    this.name = name;

    oid = new OID(oidString);
  }



  /**
   * Retrieves the OID for this signature algorithm.
   *
   * @return  The OID for this signature algorithm.
   */
  public OID getOID()
  {
    return oid;
  }



  /**
   * Retrieves the name for this signature algorithm.
   *
   * @return  The name for this signature algorithm.
   */
  public String getName()
  {
    return name;
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
  public static SignatureAlgorithmIdentifier forOID(final OID oid)
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
   * Retrieves the human-readable name for the signature algorithm identifier
   * value with the provided OID, or a string representation of the OID if there
   * is no value with that OID.
   *
   * @param  oid  The OID for the signature algorithm identifier to retrieve.
   *
   * @return  The human-readable name for the signature algorithm identifier
   *          value with the provided OID, or a string representation of the OID
   *          if there is no value with that OID.
   */
  public static String getNameOrOID(final OID oid)
  {
    final SignatureAlgorithmIdentifier id = forOID(oid);
    if (id == null)
    {
      return oid.toString();
    }
    else
    {
      return id.name;
    }
  }
}
