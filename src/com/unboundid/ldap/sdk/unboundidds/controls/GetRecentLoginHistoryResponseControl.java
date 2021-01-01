/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONException;
import com.unboundid.util.json.JSONObject;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides an implementation of a response control that can be
 * included in the response to a successful bind operation to provide
 * information about recent successful and failed authentication attempts.
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
 * This control has an OID of 1.3.6.1.4.1.30221.2.5.62, a criticality of
 * {@code false}, and a value that is a JSON object with two top-level fields:
 * successful-attempts and failed-attempts.  The value for each of these fields
 * will be an array of JSON objects with the following fields:
 * <UL>
 *   <LI>timestamp -- The timestamp of the login attempt in the ISO 8601 format
 *       described in RFC 3339.</LI>
 *   <LI>client-ip-address -- A string representation of the IP address of the
 *       client that tried to authenticate.</LI>
 *   <LI>authentication-method -- The name of the method that the client used
 *       when trying to authenticate.</LI>
 *   <LI>failure-reason -- A string providing a general reason that the
 *       authentication attempt failed (only used for failed attempts).</LI>
 *   <LI>additional-attempt-count -- An integer value that indicates how many
 *       other attempts were made on the same date with the same settings for
 *       all fields except the timestamp.</LI>
 * </UL>
 *
 * @see  GetRecentLoginHistoryRequestControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetRecentLoginHistoryResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.62) for the get password policy state issues
   * response control.
   */
  @NotNull public static final String GET_RECENT_LOGIN_HISTORY_RESPONSE_OID =
       "1.3.6.1.4.1.30221.2.5.62";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4604204310334007290L;



  // The recent login history contained in the response control.
  @NotNull private final RecentLoginHistory recentLoginHistory;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  GetRecentLoginHistoryResponseControl()
  {
    recentLoginHistory = null;
  }



  /**
   * Creates a new instance of this control with the provided information.
   *
   * @param  recentLoginHistory  The recent login history to include in the
   *                             response control.  It must not be {@code null}.
   */
  public GetRecentLoginHistoryResponseControl(
              @NotNull final RecentLoginHistory recentLoginHistory)
  {
    super(GET_RECENT_LOGIN_HISTORY_RESPONSE_OID, false,
         new ASN1OctetString(recentLoginHistory.asJSONObject().toString()));

    this.recentLoginHistory = recentLoginHistory;
  }



  /**
   * Creates a new instance of this control that is decoded from the provided
   * generic control.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.
   *
   * @throws LDAPException  If a problem is encountered while attempting to
   *                         decode the provided control as a get recent login
   *                         history response control.
   */
  public GetRecentLoginHistoryResponseControl(@NotNull final String oid,
              final boolean isCritical, @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_RECENT_LOGIN_HISTORY_RESPONSE_NO_VALUE.get());
    }

    final JSONObject jsonObject;
    try
    {
      jsonObject = new JSONObject(value.stringValue());
    }
    catch (final JSONException e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_RECENT_LOGIN_HISTORY_RESPONSE_VALUE_NOT_JSON.get(
                e.getMessage()),
           e);
    }

    try
    {
      recentLoginHistory = new RecentLoginHistory(jsonObject);
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_RECENT_LOGIN_HISTORY_RESPONSE_CANNOT_PARSE_VALUE.get(
                e.getMessage()),
           e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GetRecentLoginHistoryResponseControl decodeControl(
              @NotNull final String oid, final boolean isCritical,
              @Nullable final ASN1OctetString value)
          throws LDAPException
  {
    return new GetRecentLoginHistoryResponseControl(oid, isCritical, value);
  }



  /**
   * Retrieves the recent login history contained in this response control.
   *
   * @return  The recent login history contained in this response control.
   */
  @NotNull()
  public RecentLoginHistory getRecentLoginHistory()
  {
    return recentLoginHistory;
  }



  /**
   * Extracts a get recent login history response control from the provided bind
   * result.
   *
   * @param  bindResult  The bind result from which to retrieve the get recent
   *                     login history response control.
   *
   * @return  The get recent login history response control contained in the
   *          provided bind result, or {@code null} if the bind result did not
   *          contain a get recent login history response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the get recent login history response
   *                         control contained in the provided bind result.
   */
  @Nullable()
  public static GetRecentLoginHistoryResponseControl get(
                     @NotNull final BindResult bindResult)
         throws LDAPException
  {
    final Control c =
         bindResult.getResponseControl(GET_RECENT_LOGIN_HISTORY_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof GetRecentLoginHistoryResponseControl)
    {
      return (GetRecentLoginHistoryResponseControl) c;
    }
    else
    {
      return new GetRecentLoginHistoryResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_GET_RECENT_LOGIN_HISTORY_RESPONSE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GetRecentLoginHistoryResponseControl(recentLoginHistory=");
    buffer.append(recentLoginHistory.toString());
    buffer.append(')');
  }
}
