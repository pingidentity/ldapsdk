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
 * This enum defines a set of public key algorithm names and OIDs.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum PublicKeyAlgorithmIdentifier
{
  /**
   * The algorithm identifier for the RSA public key algorithm.  This identifier
   * is defined in RFC 3279 section 2.3.1.
   */
  RSA("1.2.840.113549.1.1.1", "RSA"),



  /**
   * The algorithm identifier for the DSA public key algorithm.  This identifier
   * is defined in RFC 3279 section 2.3.2.
   */
  DSA("1.2.840.10040.4.1", "DSA"),



  /**
   * The algorithm identifier for the Diffie-Hellman public key algorithm.  This
   * identifier is defined in RFC 3279 section 2.3.3.
   */
  DIFFIE_HELLMAN("1.2.840.10046.2.1", "DiffieHellman"),



  /**
   * The algorithm identifier for the elliptic curve public key algorithm.  This
   * identifier is defined in RFC 3279 section 2.3.5.
   */
  EC("1.2.840.10045.2.1", "EC");



  // The OID for this public key algorithm.
  private final OID oid;

  // The name for this public key algorithm.
  private final String name;



  /**
   * Creates a new public key algorithm identifier with the provided
   * information.
   *
   * @param  oidString  The string representation of the OID for this public key
   *                    algorithm.
   * @param  name       The name for this public key algorithm.
   */
  PublicKeyAlgorithmIdentifier(final String oidString, final String name)
  {
    this.name = name;

    oid = new OID(oidString);
  }



  /**
   * Retrieves the OID for this public key algorithm.
   *
   * @return  The OID for this public key algorithm.
   */
  public OID getOID()
  {
    return oid;
  }



  /**
   * Retrieves the name for this public key algorithm.
   *
   * @return  The name for this public key algorithm.
   */
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the public key algorithm identifier instance with the specified
   * OID.
   *
   * @param  oid  The OID for the public key algorithm identifier instance to
   *              retrieve.
   *
   * @return  The appropriate public key algorithm identifier instance, or
   *          {@code null} if the provided OID does not reference a known
   *          public key algorithm identifier.
   */
  public static PublicKeyAlgorithmIdentifier forOID(final OID oid)
  {
    for (final PublicKeyAlgorithmIdentifier v : values())
    {
      if (v.oid.equals(oid))
      {
        return v;
      }
    }

    return null;
  }



  /**
   * Retrieves the human-readable name for the public key algorithm identifier
   * value with the provided OID, or a string representation of the OID if there
   * is no value with that OID.
   *
   * @param  oid  The OID for the public key algorithm identifier to retrieve.
   *
   * @return  The human-readable name for the public key algorithm identifier
   *          value with the provided OID, or a string representation of the OID
   *          if there is no value with that OID.
   */
  public static String getNameOrOID(final OID oid)
  {
    final PublicKeyAlgorithmIdentifier id = forOID(oid);
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
