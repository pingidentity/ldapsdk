/*
 * Copyright 2007-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2023 Ping Identity Corporation
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
 * Copyright (C) 2007-2023 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides an implementation of the proxied authorization V1
 * request control, which may be used to request that the associated operation
 * be performed as if it had been requested by some other user.  It is based on
 * the specification provided in early versions of the
 * draft-weltman-ldapv3-proxy Internet Draft (this implementation is based on
 * the "-04" revision).  Later versions of the draft, and subsequently
 * <A HREF="http://www.ietf.org/rfc/rfc4370.txt">RFC 4370</A>, define a second
 * version of the proxied authorization control with a different OID and
 * different value format.  This control is supported primarily for legacy
 * purposes, and it is recommended that new applications use the
 * {@link ProxiedAuthorizationV2RequestControl} instead if this version.
 * <BR><BR>
 * The value of this control includes the DN of the user as whom the operation
 * should be performed.  Note that it should be a distinguished name, and not an
 * authzId value as is used in the proxied authorization V2 control.
 * <BR><BR>
 * This control may be used in conjunction with add, delete, compare, delete,
 * extended, modify, modify DN, and search requests.  In that case, the
 * associated operation will be processed under the authority of the specified
 * authorization identity rather than the identity associated with the client
 * connection (i.e., the user as whom that connection is bound).  Note that
 * because of the inherent security risks associated with the use of the proxied
 * authorization control, most directory servers which support its use enforce
 * strict restrictions on the users that are allowed to request this control.
 * Note that while the directory server should return a
 * {@link ResultCode#AUTHORIZATION_DENIED} result for a proxied authorization V2
 * control if the requester does not have the appropriate permission to use that
 * control, this result will not necessarily be used for the same condition with
 * the proxied authorization V1 control because this result code was not defined
 * until the release of the proxied authorization V2 specification.
 * code.
 * <BR><BR>
 * There is no corresponding response control for this request control.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the proxied authorization V1
 * control to delete an entry under the authority of the user with DN
 * "uid=alternate.user,ou=People,dc=example,dc=com":
 * <PRE>
 * // Create a delete request to delete an entry.  Include the proxied
 * // authorization v1 request control in the delete request so that the
 * // delete will be processed as user
 * // "uid=alternate.user,ou=People,dc=example,dc=com" instead of the user
 * // that's actually authenticated on the connection.
 * DeleteRequest deleteRequest =
 *      new DeleteRequest("uid=test.user,ou=People,dc=example,dc=com");
 * deleteRequest.addControl(new ProxiedAuthorizationV1RequestControl(
 *      "uid=alternate.user,ou=People,dc=example,dc=com"));
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
public final class ProxiedAuthorizationV1RequestControl
       extends Control
{
  /**
   * The OID (2.16.840.1.113730.3.4.12) for the proxied authorization v1 request
   * control.
   */
  @NotNull public static final String PROXIED_AUTHORIZATION_V1_REQUEST_OID =
       "2.16.840.1.113730.3.4.12";



  /**
   * The name of the field used to hold the authorization DN in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_AUTHORIZATION_DN =
       "authorization-dn";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7312632337431962774L;



  // The DN of the target user under whose authorization the associated
  // operation should be performed.
  @NotNull private final String proxyDN;



  /**
   * Creates a new proxied authorization V1 request control that will proxy as
   * the specified user.
   *
   * @param  proxyDN  The DN of the target user under whose authorization the
   *                  associated request should be performed.  It must not be
   *                  {@code null}, although it may be an empty string to
   *                  request an anonymous authorization.
   */
  public ProxiedAuthorizationV1RequestControl(@NotNull final String proxyDN)
  {
    super(PROXIED_AUTHORIZATION_V1_REQUEST_OID, true, encodeValue(proxyDN));

    Validator.ensureNotNull(proxyDN);

    this.proxyDN = proxyDN;
  }



  /**
   * Creates a new proxied authorization V1 request control that will proxy as
   * the specified user.
   *
   * @param  proxyDN  The DN of the target user under whose authorization the
   *                  associated request should be performed.  It must not be
   *                  {@code null}.
   */
  public ProxiedAuthorizationV1RequestControl(@NotNull final DN proxyDN)
  {
    super(PROXIED_AUTHORIZATION_V1_REQUEST_OID, true,
          encodeValue(proxyDN.toString()));

    this.proxyDN = proxyDN.toString();
  }



  /**
   * Creates a new proxied authorization v1 request control which is decoded
   * from the provided generic control.
   *
   * @param  control  The generic control to be decoded as a proxied
   *                  authorization v1 request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         proxied authorization v1 request control.
   */
  public ProxiedAuthorizationV1RequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PROXY_V1_NO_VALUE.get());
    }

    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(valueElement).elements();
      proxyDN = ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PROXYV1_DECODE_ERROR.get(e), e);
    }
  }



  /**
   * Encodes the provided information into an octet string that can be used as
   * the value for this control.
   *
   * @param  proxyDN  The DN of the target user under whose authorization the
   *                  associated request should be performed.  It must not be
   *                  {@code null}, although it may be an empty string to
   *                  request an anonymous authorization.
   *
   * @return  An ASN.1 octet string that can be used as the value for this
   *          control.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(@NotNull final String proxyDN)
  {
    final ASN1Element[] valueElements =
    {
      new ASN1OctetString(proxyDN)
    };

    return new ASN1OctetString(new ASN1Sequence(valueElements).encode());
  }



  /**
   * Retrieves the DN of the target user under whose authorization the
   * associated request should be performed.
   *
   * @return  The DN of the target user under whose authorization the associated
   *          request should be performed.
   */
  @NotNull()
  public String getProxyDN()
  {
    return proxyDN;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PROXIED_AUTHZ_V1_REQUEST.get();
  }



  /**
   * Retrieves a representation of this proxied authorization v1 request control
   * as a JSON object.  The JSON object uses the following fields:
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the proxied authorization v1 request
   *     control, the OID is "2.16.840.1.113730.3.4.12".
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
   *     authorization v1 request control.  Exactly one of the
   *     {@code value-base64} and {@code value-json} fields must be present.
   *   </LI>
   *   <LI>
   *     {@code value-json} -- An optional JSON object field whose value is a
   *     user-friendly representation of the value for this proxied
   *     authorization v1 request control.  Exactly one of the
   *     {@code value-base64} and {@code value-json} fields must be present, and
   *     if the {@code value-json} field is used, then it will use the following
   *     fields:
   *     <UL>
   *       <LI>
   *         {@code authorization-dn} -- A mandatory string field whose value is
   *         the DN of the user as whom the request should be authorized.
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
              PROXIED_AUTHORIZATION_V1_REQUEST_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_PROXIED_AUTHZ_V1_REQUEST.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              new JSONObject(
                   new JSONField(JSON_FIELD_AUTHORIZATION_DN, proxyDN))));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a
   * proxied authorization v1 request control.
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
   * @return  The proxied authorization v1 request control that was decoded from
   *          the provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid proxied authorization v1 request control.
   */
  @NotNull()
  public static ProxiedAuthorizationV1RequestControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new ProxiedAuthorizationV1RequestControl(new Control(
           jsonControl.getOID(), jsonControl.getCriticality(), rawValue));
    }


    final JSONObject valueObject = jsonControl.getValueObject();

    final String authorizationDN =
         valueObject.getFieldAsString(JSON_FIELD_AUTHORIZATION_DN);
    if (authorizationDN == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PROXYV1_JSON_MISSING_AUTHZ_DN.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_AUTHORIZATION_DN));
    }


    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_AUTHORIZATION_DN);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PROXYV1_JSON_UNRECOGNIZED_FIELD.get(
                  controlObject.toSingleLineString(),
                  unrecognizedFields.get(0)));
      }
    }


    return new ProxiedAuthorizationV1RequestControl(authorizationDN);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ProxiedAuthorizationV1RequestControl(proxyDN='");
    buffer.append(proxyDN);
    buffer.append("')");
  }
}
