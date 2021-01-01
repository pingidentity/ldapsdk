/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a response control that may be used to provide the server
 * ID of the Directory Server instance that processed the associated request.
 * For search operations, each entry and reference returned will include the
 * server ID of the server that provided that entry or reference.  For all other
 * types of operations, it will be in the {@code LDAPResult} (or appropriate
 * subclass) returned for that operation.
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
 * <BR>
 * This control has an OID of 1.3.6.1.4.1.30221.2.5.15 and a criticality of
 * false.  This control must have a value, which will simply be the string
 * representation of the server ID of the associated server.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetServerIDResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.15) for the get server ID response control.
   */
  @NotNull public static final String GET_SERVER_ID_RESPONSE_OID =
       "1.3.6.1.4.1.30221.2.5.15";


  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5271084342514677677L;



  // The server ID of the server that processed the associated request.
  @NotNull private final String serverID;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  GetServerIDResponseControl()
  {
    serverID = null;
  }



  /**
   * Creates a new get server ID response control with the provided server ID.
   *
   * @param  serverID  The server ID of the server that processed the associated
   *                   request.  It must not be {@code null}.
   */
  public GetServerIDResponseControl(@NotNull final String serverID)
  {
    super(GET_SERVER_ID_RESPONSE_OID, false, new ASN1OctetString(serverID));

    Validator.ensureNotNull(serverID);

    this.serverID = serverID;
  }



  /**
   * Creates a new get server ID response control decoded from the given generic
   * control contents.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   * @param  value       The value for the control.  It may be {@code null} if
   *                     the control to decode does not have a value.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         generic control as a get server ID response
   *                         control.
   */
  public GetServerIDResponseControl(@NotNull final String oid,
                                    final boolean isCritical,
                                    @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_SERVER_ID_RESPONSE_MISSING_VALUE.get());
    }

    serverID = value.stringValue();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GetServerIDResponseControl decodeControl(@NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new GetServerIDResponseControl(oid, isCritical, value);
  }



  /**
   * Extracts a get server ID response control from the provided result.
   *
   * @param  result  The result from which to retrieve the get server ID
   *                 response control.
   *
   * @return  The get server ID response control contained in the provided
   *          result, or {@code null} if the result did not contain a get server
   *          ID response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the get server ID response control contained
   *                         in the provided result.
   */
  @Nullable()
  public static GetServerIDResponseControl get(@NotNull final LDAPResult result)
         throws LDAPException
  {
    final Control c = result.getResponseControl(GET_SERVER_ID_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof GetServerIDResponseControl)
    {
      return (GetServerIDResponseControl) c;
    }
    else
    {
      return new GetServerIDResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * Extracts a get server ID response control from the provided search result
   * entry.
   *
   * @param  entry  The search result entry from which to retrieve the get
   *                server ID response control.
   *
   * @return  The get server ID response control contained in the provided
   *          search result entry, or {@code null} if the entry did not contain
   *          a get server ID response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the get server ID response control contained
   *                         in the provided entry.
   */
  @Nullable()
  public static GetServerIDResponseControl get(
                     @NotNull final SearchResultEntry entry)
         throws LDAPException
  {
    final Control c = entry.getControl(GET_SERVER_ID_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof GetServerIDResponseControl)
    {
      return (GetServerIDResponseControl) c;
    }
    else
    {
      return new GetServerIDResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * Extracts a get server ID response control from the provided search result
   * reference.
   *
   * @param  ref  The search result reference from which to retrieve the get
   *              server ID response control.
   *
   * @return  The get server ID response control contained in the provided
   *          search result reference, or {@code null} if the reference did not
   *          contain a get server ID response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the get server ID response control contained
   *                         in the provided reference.
   */
  @Nullable()
  public static GetServerIDResponseControl get(
                     @NotNull final SearchResultReference ref)
         throws LDAPException
  {
    final Control c = ref.getControl(GET_SERVER_ID_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof GetServerIDResponseControl)
    {
      return (GetServerIDResponseControl) c;
    }
    else
    {
      return new GetServerIDResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * Retrieves the server ID of the server that actually processed the
   * associated request.
   *
   * @return  The server ID of the server that actually processed the associated
   *          request.
   */
  @NotNull()
  public String getServerID()
  {
    return serverID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_GET_SERVER_ID_RESPONSE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GetServerIDResponseControl(serverID='");
    buffer.append(serverID);
    buffer.append("')");
  }
}
