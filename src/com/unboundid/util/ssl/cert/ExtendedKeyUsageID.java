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
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.cert.CertMessages.*;



/**
 * This enum defines a set of OIDs that are known to be used in the
 * {@link ExtendedKeyUsageExtension}.  Note that extended key usage extensions
 * may include OIDs that are not included in this enum, and any code that makes
 * use of the extension should be prepared to handle other key usage IDs.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum ExtendedKeyUsageID
{
  /**
   * The extended key usage ID that indicates that the associated certificate
   * may be used for TLS server authentication.
   */
  TLS_SERVER_AUTHENTICATION("1.3.6.1.5.5.7.3.1",
       INFO_EXTENDED_KEY_USAGE_ID_TLS_SERVER_AUTHENTICATION.get()),



  /**
   * The extended key usage ID that indicates that the associated certificate
   * may be used for TLS client authentication.
   */
  TLS_CLIENT_AUTHENTICATION("1.3.6.1.5.5.7.3.2",
       INFO_EXTENDED_KEY_USAGE_ID_TLS_CLIENT_AUTHENTICATION.get()),



  /**
   * The extended key usage ID that indicates that the associated certificate
   * may be used for code signing.
   */
  CODE_SIGNING("1.3.6.1.5.5.7.3.3",
       INFO_EXTENDED_KEY_USAGE_ID_CODE_SIGNING.get()),



  /**
   * The extended key usage ID that indicates that the associated certificate
   * may be used for email protection.
   */
  EMAIL_PROTECTION("1.3.6.1.5.5.7.3.4",
       INFO_EXTENDED_KEY_USAGE_ID_EMAIL_PROTECTION.get()),



  /**
   * The extended key usage ID that indicates that the associated certificate
   * may be used for time stamping.
   */
  TIME_STAMPING("1.3.6.1.5.5.7.3.8",
       INFO_EXTENDED_KEY_USAGE_ID_TIME_STAMPING.get()),



  /**
   * The extended key usage ID that indicates that the associated certificate
   * may be used for signing OCSP responses.
   */
  OCSP_SIGNING("1.3.6.1.5.5.7.3.9",
       INFO_EXTENDED_KEY_USAGE_ID_OCSP_SIGNING.get());



  // The OID for this extended key usage ID value.
  @NotNull private final OID oid;

  // The human-readable name for this extended key usage ID value.
  @NotNull private final String name;



  /**
   * Creates a new extended key usage ID value with the provided information.
   *
   * @param  oidString  The string representation of the OID for this extended
   *                    key usage ID value.
   * @param  name       The human-readable name for this extended key usage ID
   *                    value.
   */
  ExtendedKeyUsageID(@NotNull final String oidString,
                     @NotNull final String name)
  {
    this.name = name;

    oid = new OID(oidString);
  }



  /**
   * Retrieves the OID for this extended key usage ID value.
   *
   * @return  The OID for this extended key usage ID value.
   */
  @NotNull()
  public OID getOID()
  {
    return oid;
  }



  /**
   * Retrieves the human-readable name for this extended key usage ID value.
   *
   * @return  The human-readable name for this extended key usage ID value.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the extended key usage ID value with the specified OID.
   *
   * @param  oid  The OID of the extended key usage ID value to retrieve.  It
   *              must not be {@code null}.
   *
   * @return  The extended key usage ID value with the specified OID, or
   *          {@code null} if there is no value with the specified OID.
   */
  @Nullable()
  public static ExtendedKeyUsageID forOID(@NotNull final OID oid)
  {
    for (final ExtendedKeyUsageID id : values())
    {
      if (id.oid.equals(oid))
      {
        return id;
      }
    }

    return null;
  }



  /**
   * Retrieves the human-readable name for the extended key usage ID value with
   * the provided OID, or a string representation of the OID if there is no
   * value with that OID.
   *
   * @param  oid  The OID for the extended key usage ID to retrieve.
   *
   * @return  The human-readable name for the extended key usage ID value with
   *            the provided OID, or a string representation of the OID if there
   *            is no value with that OID.
   */
  @NotNull()
  public static String getNameOrOID(@NotNull final OID oid)
  {
    final ExtendedKeyUsageID id = forOID(oid);
    if (id == null)
    {
      return oid.toString();
    }
    else
    {
      return id.name;
    }
  }



  /**
   * Retrieves the extended key usage ID with the specified name.
   *
   * @param  name  The name of the extended key usage ID to retrieve.  It must
   *               not be {@code null}.
   *
   * @return  The requested extended key usage ID, or {@code null} if no such ID
   *          is defined.
   */
  @Nullable()
  public static ExtendedKeyUsageID forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "tlsserverauthentication":
      case "tls-server-authentication":
      case "tls_server_authentication":
      case "tls server authentication":
      case "serverauth":
      case "server-auth":
      case "server_auth":
      case "server auth":
        return TLS_SERVER_AUTHENTICATION;
      case "tlsclientauthentication":
      case "tls-client-authentication":
      case "tls_client_authentication":
      case "tls client authentication":
      case "clientauth":
      case "client-auth":
      case "client_auth":
      case "client auth":
        return TLS_CLIENT_AUTHENTICATION;
      case "codesigning":
      case "code-signing":
      case "code_signing":
      case "code signing":
        return CODE_SIGNING;
      case "emailprotection":
      case "email-protection":
      case "email_protection":
      case "email protection":
        return EMAIL_PROTECTION;
      case "timestamping":
      case "time-stamping":
      case "time_stamping":
      case "time stamping":
        return TIME_STAMPING;
      case "ocspsigning":
      case "ocsp-signing":
      case "ocsp_signing":
      case "ocsp signing":
        return OCSP_SIGNING;
      default:
        return null;
    }
  }
}
