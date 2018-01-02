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
 * This enum defines a set of supported RSA private key versions.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum RSAPrivateKeyVersion
{
  /**
   * The two-prime RSA private key version.
   */
  TWO_PRIME(0, "two-prime"),



  /**
   * The multi RSA private key version.
   */
  MULTI(1, "multi");



  // The integer value for this RSA private key version.
  private final int intValue;

  // The name for this RSA private key version.
  private final String name;



  /**
   * Creates a new RSA private key version with the provided information.
   *
   * @param  intValue  The integer value for the private key version.
   * @param  name      The name for this private key version.  It must not be
   *                   {@code null}.
   */
  RSAPrivateKeyVersion(final int intValue, final String name)
  {
    this.intValue = intValue;
    this.name = name;
  }



  /**
   * Retrieves the integer value for this private key version.
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
   *                   retrieve.
   *
   * @return  The private key version for the provided integer value, or
   *          {@code null} if the provided version does not correspond to any
   *          known private key version value.
   */
  static RSAPrivateKeyVersion valueOf(final int intValue)
  {
    for (final RSAPrivateKeyVersion v : values())
    {
      if (v.intValue == intValue)
      {
        return v;
      }
    }

    return null;
  }
}
