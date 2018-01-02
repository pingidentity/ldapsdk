/*
 * Copyright 2017-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017-2018 Ping Identity Corporation
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



import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines a set of supported PKCS #8 private key versions.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum PKCS8PrivateKeyVersion
{
  /**
   * The PKCS #8 v1 private key version.
   */
  V1(0, "v1"),



  /**
   * The PKCS #8 v2 private key version.
   */
  V2(1, "v2");



  // The integer value for this private key version, as used in the encoded
  // PKCS #8 private key.
  private final int intValue;

  // The name for this PKCS #8 private key version.
  private final String name;



  /**
   * Creates a new PKCS #8 private key version with the provided information.
   *
   * @param  intValue  The integer value for the private key version.  Note that
   *                   this is the integer value that is used in the encoded
   *                   private key, and not the logical version number that the
   *                   encoded value represents (for example, the "v1" private
   *                   key version has an integer value of 0 rather than 1).
   * @param  name      The name for this private key version.  It must not be
   *                   {@code null}.
   */
  PKCS8PrivateKeyVersion(final int intValue, final String name)
  {
    this.intValue = intValue;
    this.name = name;
  }



  /**
   * Retrieves the integer value for this private key version.  Note that this
   * is the integer value that is used in the encoded private key, and not the
   * logical version number that the encoded value represents (for example, the
   * "v1" private key version has an integer value of 0 rather than 1).
   *
   * @return  The integer value for this private key version.
   */
  int getIntValue()
  {
    return intValue;
  }



  /**
   * Retrieves the name for this private key version.
   *
   * @return  The name for this private key version.
   */
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the private key version for the provided integer value.
   *
   * @param  intValue  The integer value for the private key version to
   *                   retrieve.  Note that this is the integer value that is
   *                   used in the encoded private key, and not the logical
   *                   version number that the encoded value represents (for
   *                   example, the "v1" private key version has an integer
   *                   value of 0 rather than 1).
   *
   * @return  The private key version for the provided integer value, or
   *          {@code null} if the provided version does not correspond to any
   *          known private key version value.
   */
  static PKCS8PrivateKeyVersion valueOf(final int intValue)
  {
    for (final PKCS8PrivateKeyVersion v : values())
    {
      if (v.intValue == intValue)
      {
        return v;
      }
    }

    return null;
  }
}
