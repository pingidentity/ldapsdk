/*
 * Copyright 2007-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2025 Ping Identity Corporation
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
 * Copyright (C) 2007-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.controls;



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

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides an implementation of the authorization identity bind
 * request control as described in
 * <A HREF="http://www.ietf.org/rfc/rfc3829.txt">RFC 3829</A>.  It may be
 * included in a bind request to request that the server include the
 * authorization identity associated with the client connection in the bind
 * response message, in the form of an
 * {@link AuthorizationIdentityResponseControl}.
 * <BR><BR>
 * The authorization identity request control is similar to the "Who Am I?"
 * extended request as implemented in the
 * {@link com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest} class.  The
 * primary difference between them is that the "Who Am I?" extended request can
 * be used at any time but requires a separate operation, while the
 * authorization identity request control can be included only with a bind
 * request but does not require a separate operation.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the authorization identity
 * request and response controls.  It authenticates to the directory server and
 * attempts to retrieve the authorization identity from the response:
 * <PRE>
 * String authzID = null;
 * BindRequest bindRequest =
 *      new SimpleBindRequest("uid=test.user,ou=People,dc=example,dc=com",
 *           "password", new AuthorizationIdentityRequestControl());
 *
 * BindResult bindResult = connection.bind(bindRequest);
 * AuthorizationIdentityResponseControl authzIdentityResponse =
 *      AuthorizationIdentityResponseControl.get(bindResult);
 * if (authzIdentityResponse != null)
 * {
 *   authzID = authzIdentityResponse.getAuthorizationID();
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AuthorizationIdentityRequestControl
       extends Control
{
  /**
   * The OID (2.16.840.1.113730.3.4.16) for the authorization identity request
   * control.
   */
  @NotNull public static final String AUTHORIZATION_IDENTITY_REQUEST_OID =
       "2.16.840.1.113730.3.4.16";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4059607155175828138L;



  /**
   * Creates a new authorization identity request control.  The control will not
   * be marked critical.
   */
  public AuthorizationIdentityRequestControl()
  {
    super(AUTHORIZATION_IDENTITY_REQUEST_OID, false, null);
  }



  /**
   * Creates a new authorization identity request control.
   *
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   */
  public AuthorizationIdentityRequestControl(final boolean isCritical)
  {
    super(AUTHORIZATION_IDENTITY_REQUEST_OID, isCritical, null);
  }



  /**
   * Creates a new authorization identity request control which is decoded from
   * the provided generic control.
   *
   * @param  control  The generic control to be decoded as an authorization
   *                  identity request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         authorization identity request control.
   */
  public AuthorizationIdentityRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_AUTHZID_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_AUTHZID_REQUEST.get();
  }



  /**
   * Retrieves a representation of this authorization identity request control
   * as a JSON object.  The JSON object uses the following fields (note that
   * since this control does not have a value, neither the {@code value-base64}
   * nor {@code value-json} fields may be present):
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the authorization identity request
   *     control, the OID is "2.16.840.1.113730.3.4.16".
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
              AUTHORIZATION_IDENTITY_REQUEST_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_AUTHZID_REQUEST.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of an
   * authorization identity request control.
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
   * @return  The authorization identity request control that was decoded from
   *          the provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid authorization identity request control.
   */
  @NotNull()
  public static AuthorizationIdentityRequestControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, false, false);

    return new AuthorizationIdentityRequestControl(
         jsonControl.getCriticality());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("AuthorizationIdentityRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
