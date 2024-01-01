/*
 * Copyright 2007-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2024 Ping Identity Corporation
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
 * Copyright (C) 2007-2024 Ping Identity Corporation
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



import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides an implementation of the proxied authorization V2
 * request control, as defined in
 * <A HREF="http://www.ietf.org/rfc/rfc4370.txt">RFC 4370</A>.  It may be used
 * to request that the associated operation be performed as if it has been
 * requested by some other user.
 * <BR><BR>
 * The target authorization identity for this control is specified as an
 * "authzId" value as described in section 5.2.1.8 of
 * <A HREF="http://www.ietf.org/rfc/rfc4513.txt">RFC 4513</A>.  That is, it
 * should be either "dn:" followed by the distinguished name of the target user,
 * or "u:" followed by the username.  If the "u:" form is used, then the
 * mechanism used to resolve the provided username to an entry may vary from
 * server to server.
 * <BR><BR>
 * This control may be used in conjunction with add, delete, compare, delete,
 * extended, modify, modify DN, and search requests.  In that case, the
 * associated operation will be processed under the authority of the specified
 * authorization identity rather than the identity associated with the client
 * connection (i.e., the user as whom that connection is bound).  Note that
 * because of the inherent security risks associated with the use of the proxied
 * authorization control, most directory servers which support its use enforce
 * strict restrictions on the users that are allowed to request this control.
 * If a user attempts to use the proxied authorization V2 request control and
 * does not have sufficient permission to do so, then the server will return a
 * failure response with the {@link ResultCode#AUTHORIZATION_DENIED} result
 * code.
 * <BR><BR>
 * There is no corresponding response control for this request control.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the proxied authorization V2
 * control to delete an entry under the authority of the user with username
 * "alternate.user":
 * <PRE>
 * // Create a delete request to delete an entry.  Include the proxied
 * // authorization v2 request control in the delete request so that the
 * // delete will be processed as the user with username "alternate.user"
 * // instead of the user that's actually authenticated on the connection.
 * DeleteRequest deleteRequest =
 *      new DeleteRequest("uid=test.user,ou=People,dc=example,dc=com");
 * deleteRequest.addControl(new ProxiedAuthorizationV2RequestControl(
 *      "u:alternate.user"));
 *
 * LDAPResult deleteResult;
 * try
 * {
 *   deleteResult = connection.delete(deleteRequest);
 *   // If we got here, then the delete was successful.
 * }
 * catch (LDAPException le)
 * {
 *   // The delete failed for some reason.  In addition to all of the normal
 *   // reasons a delete could fail (e.g., the entry doesn't exist, or has one
 *   // or more subordinates), proxied-authorization specific failures may
 *   // include that the authenticated user doesn't have permission to use the
 *   // proxied authorization control to impersonate the alternate user, that
 *   // the alternate user doesn't exist, or that the alternate user doesn't
 *   // have permission to perform the requested operation.
 *   deleteResult = le.toLDAPResult();
 *   ResultCode resultCode = le.getResultCode();
 *   String errorMessageFromServer = le.getDiagnosticMessage();
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ProxiedAuthorizationV2RequestControl
       extends Control
{
  /**
   * The OID (2.16.840.1.113730.3.4.18) for the proxied authorization v2 request
   * control.
   */
  @NotNull public static final String PROXIED_AUTHORIZATION_V2_REQUEST_OID =
       "2.16.840.1.113730.3.4.18";



  /**
   * The name of the field used to hold the authorization ID in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_AUTHORIZATION_ID =
       "authorization-id";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1054244283964851067L;



  // The authorization ID string that may be used to identify the user under
  // whose authorization the associated operation should be performed.
  @NotNull private final String authorizationID;



  /**
   * Creates a new proxied authorization V2 request control that will proxy as
   * the specified user.
   *
   * @param  authorizationID  The authorization ID string that will be used to
   *                          identify the user under whose authorization the
   *                          associated operation should be performed.  It may
   *                          take one of three forms:  it can be an empty
   *                          string (to indicate that the operation should use
   *                          anonymous authorization), a string that begins
   *                          with "dn:" and is followed by the DN of the target
   *                          user, or a string that begins with "u:" and is
   *                          followed by the username for the target user
   *                          (where the process of mapping the provided
   *                          username to the corresponding entry will depend on
   *                          the server configuration).  It must not be
   *                          {@code null}.
   */
  public ProxiedAuthorizationV2RequestControl(
              @NotNull final String authorizationID)
  {
    super(PROXIED_AUTHORIZATION_V2_REQUEST_OID, true,
          new ASN1OctetString(authorizationID));

    Validator.ensureNotNull(authorizationID);

    this.authorizationID = authorizationID;
  }



  /**
   * Creates a new proxied authorization v2 request control which is decoded
   * from the provided generic control.
   *
   * @param  control  The generic control to be decoded as a proxied
   *                  authorization v2 request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         proxied authorization v2 request control.
   */
  public ProxiedAuthorizationV2RequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PROXY_V2_NO_VALUE.get());
    }

    authorizationID = value.stringValue();
  }



  /**
   * Retrieves the authorization ID string that will be used to identify the
   * user under whose authorization the associated operation should be
   * performed.
   *
   * @return  The authorization ID string that will be used to identify the user
   *          under whose authorization the associated operation should be
   *          performed.
   */
  @NotNull()
  public String getAuthorizationID()
  {
    return authorizationID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PROXIED_AUTHZ_V2_REQUEST.get();
  }



  /**
   * Retrieves a representation of this proxied authorization v2 request control
   * as a JSON object.  The JSON object uses the following fields:
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the proxied authorization v2 request
   *     control, the OID is "2.16.840.1.113730.3.4.18".
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
   *   <LI>
   *     {@code value-base64} -- An optional string field whose value is a
   *     base64-encoded representation of the raw value for this proxied
   *     authorization v2 request control.  Exactly one of the
   *     {@code value-base64} and {@code value-json} fields must be present.
   *   </LI>
   *   <LI>
   *     {@code value-json} -- An optional JSON object field whose value is a
   *     user-friendly representation of the value for this proxied
   *     authorization v2 request control.  Exactly one of the
   *     {@code value-base64} and {@code value-json} fields must be present, and
   *     if the {@code value-json} field is used, then it will use the following
   *     fields:
   *     <UL>
   *       <LI>
   *         {@code authorization-id} -- A mandatory string field whose value is
   *         an authorization ID that identifies the user as whom the request
   *         should be authorized.
   *       </LI>
   *     </UL>
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
              PROXIED_AUTHORIZATION_V2_REQUEST_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_PROXIED_AUTHZ_V2_REQUEST.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              new JSONObject(
                   new JSONField(JSON_FIELD_AUTHORIZATION_ID,
                        authorizationID))));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a
   * proxied authorization v2 request control.
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
   * @return  The proxied authorization v2 request control that was decoded from
   *          the provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid proxied authorization v2 request control.
   */
  @NotNull()
  public static ProxiedAuthorizationV2RequestControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new ProxiedAuthorizationV2RequestControl(new Control(
           jsonControl.getOID(), jsonControl.getCriticality(), rawValue));
    }


    final JSONObject valueObject = jsonControl.getValueObject();

    final String authorizationID =
         valueObject.getFieldAsString(JSON_FIELD_AUTHORIZATION_ID);
    if (authorizationID == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PROXYV2_JSON_MISSING_AUTHZ_ID.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_AUTHORIZATION_ID));
    }


    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_AUTHORIZATION_ID);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PROXYV2_JSON_UNRECOGNIZED_FIELD.get(
                  controlObject.toSingleLineString(),
                  unrecognizedFields.get(0)));
      }
    }


    return new ProxiedAuthorizationV2RequestControl(authorizationID);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ProxiedAuthorizationV2RequestControl(authorizationID='");
    buffer.append(authorizationID);
    buffer.append("')");
  }
}
