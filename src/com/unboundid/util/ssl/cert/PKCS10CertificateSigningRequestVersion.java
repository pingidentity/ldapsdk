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
import com.unboundid.util.StaticUtils;
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
  @NotNull private final String name;



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
  PKCS10CertificateSigningRequestVersion(final int intValue,
                                         @NotNull final String name)
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
  @NotNull()
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
  @Nullable()
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



  /**
   * Retrieves the CSR version with the specified name.
   *
   * @param  name  The name of the CSR version to retrieve.  It must not be
   *               {@code null}.
   *
   * @return  The requested CSR version, or {@code null} if no such version is
   *          defined.
   */
  @Nullable()
  public static PKCS10CertificateSigningRequestVersion forName(
                     @NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "1":
      case "v1":
        return V1;
      default:
        return null;
    }
  }
}
