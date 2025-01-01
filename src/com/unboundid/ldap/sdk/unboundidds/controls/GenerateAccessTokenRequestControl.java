/*
 * Copyright 2023-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2023-2025 Ping Identity Corporation
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
 * Copyright (C) 2023-2025 Ping Identity Corporation
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



import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a request control that can be included in a bind request
 * to indicate that if the bind succeeds, the server should generate an access
 * token that can be used in the
 * {@link com.unboundid.ldap.sdk.OAUTHBEARERBindRequest} to authenticate as the
 * user for subsequent authentication attempts.  This can be useful for cases in
 * which the initial authentication attempt is made with credentials that cannot
 * be replayed, like a those involving a one-time password (e.g.,
 * {@link com.unboundid.ldap.sdk.unboundidds.UnboundIDTOTPBindRequest},
 * {@link com.unboundid.ldap.sdk.unboundidds.UnboundIDDeliveredOTPBindRequest},
 * or
 * {@link com.unboundid.ldap.sdk.unboundidds.UnboundIDYubiKeyOTPBindRequest}).
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
 * The OID for this control is 1.3.6.1.4.1.30221.2.5.67, the criticality may be
 * either {@code true} or {@code false}, and it does not have a value.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process of requesting an access token
 * when performing one bind, and then using that access token to authenticate
 * with subsequent bind operations:
 * <PRE>
 *   // Authenticate with the UNBOUNDID-TOTP SASL mechanism, which uses a
 *   // time-based one-time password.  Since it's a one-time password, it
 *   // can't be reused.  If we want to re-authenticate as the same user,
 *   // we can request that the server return an access token that we can
 *   // use instead.
 *   GenerateAccessTokenRequestControl requestControl =
 *        new GenerateAccessTokenRequestControl();
 *   SingleUseTOTPBindRequest totpBindRequest =
 *        new SingleUseTOTPBindRequest(authenticationID, authorizationID,
 *             totpPassword, staticPassword, requestControl);
 *
 *   BindResult totpBindResult = connection.bind(totpBindRequest);
 *
 *   // Get the access token from the bind result.
 *   String accessToken = null;
 *   GenerateAccessTokenResponseControl responseControl =
 *        GenerateAccessTokenResponseControl.get(totpBindResult);
 *   if (responseControl != null)
 *   {
 *     accessToken = responseControl.getAccessToken();
 *   }
 *
 *   // The next time you need to authenticate, you can use the access
 *   // token with an OAUTHBEARER SASL mechanism using the access token.
 *   if (accessToken != null)
 *   {
 *     OAUTHBEARERBindRequest tokenBindRequest =
 *          new OAUTHBEARERBindRequest(accessToken);
 *     BindResult tokenBindResult = connection.bind(tokenBindRequest);
 *   }
 * </PRE>
 *
 * @see  GenerateAccessTokenResponseControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GenerateAccessTokenRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.67) for the generate access token request
   * control.
   */
  @NotNull public static final  String GENERATE_ACCESS_TOKEN_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.67";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7583146521476190879L;



  /**
   * Creates a new generate access token request control.  It will be marked
   * critical.
   */
  public GenerateAccessTokenRequestControl()
  {
    this(true);
  }



  /**
   * Creates a new generate access token request control with the specified
   * criticality.
   *
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   */
  public GenerateAccessTokenRequestControl(final boolean isCritical)
  {
    super(GENERATE_ACCESS_TOKEN_REQUEST_OID, isCritical,  null);
  }



  /**
   * Creates a new generate access token request control which is decoded from
   * the provided generic control.
   *
   * @param  control  The generic control to be decoded as a generate access
   *                  token request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         generate access token request control.
   */
  public GenerateAccessTokenRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GENERATE_ACCESS_TOKEN_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_GENERATE_ACCESS_TOKEN_REQUEST.get();
  }



  /**
   * Retrieves a representation of this generate access token request control as
   * a JSON object.  The JSON object uses the following fields (note that since
   * this control does not have a value, neither the {@code value-base64} nor
   * {@code value-json} fields may be present):
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the generate access token request
   *     control, the OID is "1.3.6.1.4.1.30221.2.5.67".
   *   </LI>
   *   <LI>
   *     {@code control-name} -- An optional string field whose value is a
   *     human-readable name for this control.  This field is only intended for
   *     descriptive purposes, and when decoding a control, the {@code oid}
   *     field should be used to identify the type of control.
   *   </LI>
   *   <LI>
   *     {@code criticality} -- A mandatory Boolean field used to indicate
   *     whether this control is considered critical.
   *   </LI>
   * </UL>
   *
   * @return  A JSON object that contains a representation of this control.
   */
  @Override()
  @NotNull()
  public JSONObject toJSONControl()
  {
    return new JSONObject(
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_OID,
              GENERATE_ACCESS_TOKEN_REQUEST_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_GENERATE_ACCESS_TOKEN_REQUEST.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a
   * generate access token request control.
   *
   * @param  controlObject  The JSON object to be decoded.  It must not be
   *                        {@code null}.
   * @param  strict         Indicates whether to use strict mode when decoding
   *                        the provided JSON object.  If this is {@code true},
   *                        then this method will throw an exception if the
   *                        provided JSON object contains any unrecognized
   *                        fields.  If this is {@code false}, then unrecognized
   *                        fields will be ignored.
   *
   * @return  The generate access token request control that was decoded from
   *          the provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid generate access token request control.
   */
  @NotNull()
  public static GenerateAccessTokenRequestControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, false, false);

    return new GenerateAccessTokenRequestControl(jsonControl.getCriticality());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GenerateAccessTokenRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
