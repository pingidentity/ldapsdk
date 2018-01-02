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
 * This enum defines a set of supported PKCS #10 certificate signing request
 * versions.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum PKCS10CertificateSigningRequestVersion
{
  /**
   * The PKCS #10 v1 certificate signing request version.
   */
  V1(0, "v1");



  // The integer value for this certificate signing request version, as used in
  // the encoded PKCS #10 request.
  private final int intValue;

  // The name for this PKCS #10 certificate signing request version.
  private final String name;



  /**
   * Creates a new PKCS #10 certificate signing request version with the
   * provided information.
   *
   * @param  intValue  The integer value for the certificate signing request
   *                   version.  Note that this is the integer value that is
   *                   used in the encoded request, and not the logical version
   *                   number that the encoded value represents (for example,
   *                   the "v1" certificate signing request version has an
   *                   integer value of 0 rather than 1).
   * @param  name      The name for this certificate signing request version.
   *                   It must not be {@code null}.
   */
  PKCS10CertificateSigningRequestVersion(final int intValue, final String name)
  {
    this.intValue = intValue;
    this.name = name;
  }



  /**
   * Retrieves the integer value for this certificate signing request version.
   * Note that this is the integer value that is used in the encoded request,
   * and not the logical version number that the encoded value represents (for
   * example, the "v1" certificate signing request version has an integer value
   * of 0 rather than 1).
   *
   * @return  The integer value for this certificate signing request version.
   */
  int getIntValue()
  {
    return intValue;
  }



  /**
   * Retrieves the name for this certificate signing request version.
   *
   * @return  The name for this certificate signing request version.
   */
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the certificate signing request version for the provided integer
   * value.
   *
   * @param  intValue  The integer value for the certificate signing request
   *                   version to retrieve.  Note that this is the integer value
   *                   that is used in the encoded request, and not the logical
   *                   version number that the encoded value represents (for
   *                   example, the "v1" certificate signing request version has
   *                   an integer value of 0 rather than 1).
   *
   * @return  The certificate signing request version for the provided integer
   *          value, or {@code null} if the provided version does not correspond
   *          to any known certificate signing request version value.
   */
  static PKCS10CertificateSigningRequestVersion valueOf(final int intValue)
  {
    for (final PKCS10CertificateSigningRequestVersion v : values())
    {
      if (v.intValue == intValue)
      {
        return v;
      }
    }

    return null;
  }
}
