/*
 * Copyright 2021-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021-2022 Ping Identity Corporation
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
 * Copyright (C) 2021-2022 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class defines an extended request that may be used to request that a
 * Ping Identity Directory Server instance (or related Ping Identity server
 * product) purge information about any retired listener certificates from its
 * topology registry.  This extended request has an OID of
 * 1.3.6.1.4.1.30221.2.6.70 and no value.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 *
 * @see  PurgeRetiredListenerCertificatesExtendedResult
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PurgeRetiredListenerCertificatesExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.70) for the purge retired listener
   * certificates extended request.
   */
  @NotNull public static final String PURGE_RETIRED_LISTENER_CERTS_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.70";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 3182708156067344907L;



  /**
   * Creates a new purge retired listener certificates extended request with the
   * provided information.
   *
   * @param  requestControls  The set of controls to include in the extended
   *                          request.  It may be {@code null} or empty if no
   *                          request controls should be included.
   */
  public PurgeRetiredListenerCertificatesExtendedRequest(
              @Nullable final Control... requestControls)
  {
    super(PURGE_RETIRED_LISTENER_CERTS_REQUEST_OID, null, requestControls);
  }



  /**
   * Creates a new purge retired listener certificates extended request that is
   * decoded from the provided generic extended request.
   *
   * @param  request  The generic extended request to be decoded as a purge
   *                  retired listener certificates extended request.  It must
   *                  not be {@code null}.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided extended request as a purge retired
   *                         listener certificates request.
   */
  public PurgeRetiredListenerCertificatesExtendedRequest(
              @NotNull final ExtendedRequest request)
         throws LDAPException
  {
    super(request);

    final ASN1OctetString value = request.getValue();
    if (value != null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PURGE_RETIRED_LISTENER_CERTS_REQ_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public PurgeRetiredListenerCertificatesExtendedResult process(
              @NotNull final LDAPConnection connection, final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new PurgeRetiredListenerCertificatesExtendedResult(extendedResponse);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedRequestName()
  {
    return INFO_PURGE_RETIRED_LISTENER_CERTS_REQUEST_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("PurgeRetiredListenerCertificatesExtendedRequest(oid='");
    buffer.append(getOID());
    buffer.append('\'');

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append(", controls={");
      for (int i=0; i < controls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(controls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
