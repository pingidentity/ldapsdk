/*
 * Copyright 2007-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2022 Ping Identity Corporation
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
 * Copyright (C) 2007-2022 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides an implementation of the authorization identity bind
 * response control as defined in
 * <A HREF="http://www.ietf.org/rfc/rfc3829.txt">RFC 3829</A>.  It may be used
 * to provide the primary authorization identity associated with the client
 * connection after processing of the associated bind operation has completed.
 * <BR><BR>
 * The authorization identity value returned may be empty if the resulting
 * authorization identity is that of the anonymous user.  Otherwise, it should
 * be an "authzId" value as described in section 5.2.1.8 of
 * <A HREF="http://www.ietf.org/rfc/rfc4513.txt">RFC 4513</A>.  That is, it
 * should be either "dn:" followed by the distinguished name of the target user,
 * or "u:" followed by the username.
 * <BR><BR>
 * Note that the authorization identity response control should only be included
 * in a bind response message if the corresponding request included the
 * {@link AuthorizationIdentityRequestControl}, and only if the bind was
 * successful.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AuthorizationIdentityResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (2.16.840.1.113730.3.4.15) for the authorization identity response
   * control.
   */
  @NotNull public static final String AUTHORIZATION_IDENTITY_RESPONSE_OID =
       "2.16.840.1.113730.3.4.15";



  /**
   * The name of the field used to represent the authorization ID in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_AUTHORIZATION_ID =
       "authorization-id";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6315724175438820336L;



  // The authorization ID string returned by the server.
  @NotNull private final String authorizationID;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  AuthorizationIdentityResponseControl()
  {
    authorizationID = null;
  }



  /**
   * Creates a new authorization identity response control with the provided
   * authorization ID.
   *
   * @param  authorizationID  The authorization identity associated with the
   *                          client connection.  It must not be {@code null},
   *                          although it may be a zero-length string to
   *                          indicate that the authorization identity is the
   *                          anonymous user.
   */
  public AuthorizationIdentityResponseControl(
              @NotNull final String authorizationID)
  {
    super(AUTHORIZATION_IDENTITY_RESPONSE_OID, false,
          new ASN1OctetString(authorizationID));

    Validator.ensureNotNull(authorizationID);

    this.authorizationID = authorizationID;
  }



  /**
   * Creates a new authorization identity response control with the provided
   * information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         authorization identity response control.
   */
  public AuthorizationIdentityResponseControl(@NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_AUTHZID_RESPONSE_NO_VALUE.get());
    }
    else
    {
      authorizationID = value.stringValue();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public AuthorizationIdentityResponseControl
              decodeControl(@NotNull final String oid, final boolean isCritical,
                            @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new AuthorizationIdentityResponseControl(oid, isCritical, value);
  }



  /**
   * Extracts an authorization identity response control from the provided
   * result.
   *
   * @param  result  The result from which to retrieve the authorization
   *                 identity response control.
   *
   * @return  The authorization identity response control contained in the
   *          provided result, or {@code null} if the result did not contain an
   *          authorization identity response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the authorization identity response control
   *                         contained in the provided result.
   */
  @Nullable()
  public static AuthorizationIdentityResponseControl get(
                     @NotNull final BindResult result)
         throws LDAPException
  {
    final Control c =
         result.getResponseControl(AUTHORIZATION_IDENTITY_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof AuthorizationIdentityResponseControl)
    {
      return (AuthorizationIdentityResponseControl) c;
    }
    else
    {
      return new AuthorizationIdentityResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
  }



  /**
   * Retrieves the authorization ID string for this authorization identity
   * response control.  It may be a zero-length string if the associated
   * authorization identity is that of the anonymous user.
   *
   * @return  The authorization ID string for this authorization identity
   *          response control.
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
    return INFO_CONTROL_NAME_AUTHZID_RESPONSE.get();
  }



  /**
   * Retrieves a representation of this authorization identity response control
   * as a JSON object.  The JSON object uses the following fields:
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the authorization identity response
   *     control, the OID is "2.16.840.1.113730.3.4.15".
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
   *     base64-encoded representation of the raw value for this authorization
   *     identity response control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present.
   *   </LI>
   *   <LI>
   *     {@code value-json} -- An optional JSON object field whose value is a
   *     user-friendly representation of the value for this authorization
   *     identity response control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present, and if the
   *     {@code value-json} field is used, then it will use the following
   *     fields:
   *     <UL>
   *       <LI>
   *         {@code authorization-id} -- A string field whose value is the
   *         authorization identity assigned during the bind operation.
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
              AUTHORIZATION_IDENTITY_RESPONSE_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_AUTHZID_RESPONSE.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              new JSONObject(
                   new JSONField(JSON_FIELD_AUTHORIZATION_ID,
                        authorizationID))));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of an
   * authorization identity response control.
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
   * @return  The authorization identity response control that was decoded from
   *          the provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid authorization identity response control.
   */
  @NotNull()
  public static AuthorizationIdentityResponseControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new AuthorizationIdentityResponseControl(jsonControl.getOID(),
           jsonControl.getCriticality(), rawValue);
    }


    final JSONObject valueObject = jsonControl.getValueObject();

    final String authzID =
         valueObject.getFieldAsString(JSON_FIELD_AUTHORIZATION_ID);
    if (authzID == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_AUTHZID_RESPONSE_JSON_MISSING_AUTHZ_ID.get(
                valueObject.toSingleLineString(),
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
             ERR_AUTHZID_RESPONSE_JSON_CONTROL_UNRECOGNIZED_FIELD.get(
                  controlObject.toSingleLineString(),
                  unrecognizedFields.get(0)));
      }
    }


    return new AuthorizationIdentityResponseControl(authzID);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("AuthorizationIdentityResponseControl(authorizationID='");
    buffer.append(authorizationID);
    buffer.append("', isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
