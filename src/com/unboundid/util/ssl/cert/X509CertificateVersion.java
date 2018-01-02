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
 * This enum defines a set of supported X.509 certificate versions.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum X509CertificateVersion
{
  /**
   * The X.509 v1 certificate version.
   */
  V1(0, "v1"),



  /**
   * The X.509 v2 certificate version.
   */
  V2(1, "v2"),



  /**
   * The X.509 v3 certificate version.
   */
  V3(2, "v3");



  // The integer value for this certificate version, as used in the encoded
  // X.509 certificate.
  private final int intValue;

  // The name for this X.509 certificate version.
  private final String name;



  /**
   * Creates a new X.509 certificate version with the provided information.
   *
   * @param  intValue  The integer value for the certificate version.  Note that
   *                   this is the integer value that is used in the encoded
   *                   certificate, and not the logical version number that the
   *                   encoded value represents (for example, the "v1"
   *                   certificate version has an integer value of 0 rather than
   *                   1).
   * @param  name      The name for this certificate version.  It must not be
   *                   {@code null}.
   */
  X509CertificateVersion(final int intValue, final String name)
  {
    this.intValue = intValue;
    this.name = name;
  }



  /**
   * Retrieves the integer value for this certificate version.  Note that this
   * is the integer value that is used in the encoded certificate, and not the
   * logical version number that the encoded value represents (for example, the
   * "v1" certificate version has an integer value of 0 rather than 1).
   *
   * @return  The integer value for this certificate version.
   */
  int getIntValue()
  {
    return intValue;
  }



  /**
   * Retrieves the name for this certificate version.
   *
   * @return  The name for this certificate version.
   */
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the certificate version for the provided integer value.
   *
   * @param  intValue  The integer value for the certificate version to
   *                   retrieve.  Note that this is the integer value that is
   *                   used in the encoded certificate, and not the logical
   *                   version number that the encoded value represents (for
   *                   example, the "v1" certificate version has an integer
   *                   value of 0 rather than 1).
   *
   * @return  The certificate version for the provided integer value, or
   *          {@code null} if the provided version does not correspond to any
   *          known certificate value.
   */
  static X509CertificateVersion valueOf(final int intValue)
  {
    for (final X509CertificateVersion v : values())
    {
      if (v.intValue == intValue)
      {
        return v;
      }
    }

    return null;
  }
}
