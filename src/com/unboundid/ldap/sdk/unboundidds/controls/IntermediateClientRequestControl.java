/*
 * Copyright 2008-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2025 Ping Identity Corporation
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
 * Copyright (C) 2008-2025 Ping Identity Corporation
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



import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class defines an intermediate client request control, which can be used
 * to provide a server with information about the client and any downstream
 * clients that it may have.  It can be used to help trace operations from the
 * client to the directory server, potentially through any intermediate hops
 * (like proxy servers) that may also support the intermediate client controls.
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
 * This control is not based on any public standard.  It was originally
 * developed for use with the Ping Identity, UnboundID, and Nokia/Alcatel-Lucent
 * 8661 Directory Server.  The value of this control uses the following
 * encoding:
 * <BR><BR>
 * <PRE>
 * IntermediateClientRequest ::= SEQUENCE {
 *      downstreamRequest        [0] IntermediateClientRequest OPTIONAL,
 *      downstreamClientAddress  [1] OCTET STRING OPTIONAL,
 *      downstreamClientSecure   [2] BOOLEAN DEFAULT FALSE,
 *      clientIdentity           [3] authzId OPTIONAL,
 *      clientName               [4] OCTET STRING OPTIONAL,
 *      clientSessionID          [5] OCTET STRING OPTIONAL,
 *      clientRequestID          [6] OCTET STRING OPTIONAL,
 *      ... }
 * </PRE>
 * <H2>Example</H2>
 * The following example demonstrates the use of the intermediate client
 * controls to perform a search operation in the directory server.  The request
 * will be from an application named "my client" with a session ID of
 * "session123" and a request ID of "request456":
 * <PRE>
 * SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
 *      SearchScope.SUB, Filter.createEqualityFilter("uid", "john.doe"));
 * searchRequest.addControl(new IntermediateClientRequestControl(null, null,
 *      null, null, "my client", "session123", "request456"));
 * SearchResult searchResult = connection.search(searchRequest);
 *
 * IntermediateClientResponseControl c =
 *      IntermediateClientResponseControl.get(searchResult);
 * if (c != null)
 * {
 *   // There was an intermediate client response control.
 *   IntermediateClientResponseValue responseValue = c.getResponseValue();
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class IntermediateClientRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.2) for the intermediate client request
   * control.
   */
  @NotNull public static final String INTERMEDIATE_CLIENT_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.2";



  /**
   * The name of the field used to hold the client identity in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_CLIENT_IDENTITY =
       "client-identity";



  /**
   * The name of the field used to hold the client name in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_CLIENT_NAME = "client-name";



  /**
   * The name of the field used to hold the client request ID in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_CLIENT_REQUEST_ID =
       "client-request-id";



  /**
   * The name of the field used to hold the client session ID in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_CLIENT_SESSION_ID =
       "client-session-id";



  /**
   * The name of the field used to hold the downstream client address in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_DOWNSTREAM_CLIENT_ADDRESS =
       "downstream-client-address";



  /**
   * The name of the field used to hold the downstream client secure flag in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_DOWNSTREAM_CLIENT_SECURE =
       "downstream-client-secure";



  /**
   * The name of the field used to hold the downstream request in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_DOWNSTREAM_REQUEST =
       "downstream-request";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4883725840393001578L;



  // The value for this intermediate client request control.
  @NotNull private final IntermediateClientRequestValue value;



  /**
   * Creates a new intermediate client request control with the provided
   * information.  It will be marked critical.
   *
   * @param  downstreamRequest        A wrapped intermediate client request from
   *                                  a downstream client.  It may be
   *                                  {@code null} if there is no downstream
   *                                  request.
   * @param  downstreamClientAddress  The IP address or resolvable name of the
   *                                  downstream client system.  It may be
   *                                  {@code null} if there is no downstream
   *                                  client or its address is not available.
   * @param  downstreamClientSecure   Indicates whether communication with the
   *                                  downstream client is secure.  It may be
   *                                  {@code null} if there is no downstream
   *                                  client or it is not known whether the
   *                                  communication is secure.
   * @param  clientIdentity           The requested client authorization
   *                                  identity.  It may be {@code null} if there
   *                                  is no requested authorization identity.
   * @param  clientName               An identifier string that summarizes the
   *                                  client application that created this
   *                                  intermediate client request.  It may be
   *                                  {@code null} if that information is not
   *                                  available.
   * @param  clientSessionID          A string that may be used to identify the
   *                                  session in the client application.  It may
   *                                  be {@code null} if there is no available
   *                                  session identifier.
   * @param  clientRequestID          A string that may be used to identify the
   *                                  request in the client application.  It may
   *                                  be {@code null} if there is no available
   *                                  request identifier.
   */
  public IntermediateClientRequestControl(
              @Nullable final IntermediateClientRequestValue downstreamRequest,
              @Nullable final String downstreamClientAddress,
              @Nullable final Boolean downstreamClientSecure,
              @Nullable final String clientIdentity,
              @Nullable final String clientName,
              @Nullable final String clientSessionID,
              @Nullable final String clientRequestID)
  {
    this(true,
         new IntermediateClientRequestValue(downstreamRequest,
                  downstreamClientAddress, downstreamClientSecure,
                  clientIdentity, clientName, clientSessionID,
                  clientRequestID));
  }



  /**
   * Creates a new intermediate client request control with the provided value.
   * It will be marked critical.
   *
   * @param  value  The value to use for this intermediate client request
   *                control.  It must not be {@code null}.
   */
  public IntermediateClientRequestControl(
              @NotNull final IntermediateClientRequestValue value)
  {
    this(true, value);
  }



  /**
   * Creates a new intermediate client request control with the provided value.
   *
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The value to use for this intermediate client request
   *                     control.  It must not be {@code null}.
   */
  public IntermediateClientRequestControl(final boolean isCritical,
              @NotNull final IntermediateClientRequestValue value)
  {
    super(INTERMEDIATE_CLIENT_REQUEST_OID, isCritical,
          new ASN1OctetString(value.encode().encode()));

    this.value = value;
  }



  /**
   * Creates a new intermediate client request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as an intermediate
   *                  client request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         intermediate client request control.
   */
  public IntermediateClientRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString controlValue = control.getValue();
    if (controlValue == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ICREQ_CONTROL_NO_VALUE.get());
    }

    final ASN1Sequence valueSequence;
    try
    {
      final ASN1Element valueElement =
           ASN1Element.decode(controlValue.getValue());
      valueSequence = ASN1Sequence.decodeAsSequence(valueElement);
    }
    catch (final Exception e)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ICREQ_CONTROL_VALUE_NOT_SEQUENCE.get(e), e);
    }

    value = IntermediateClientRequestValue.decode(valueSequence);
  }



  /**
   * Retrieves the value for this intermediate client request.
   *
   * @return  The value for this intermediate client request.
   */
  @NotNull()
  public IntermediateClientRequestValue getRequestValue()
  {
    return value;
  }



  /**
   * Retrieves the wrapped request from a downstream client, if available.
   *
   * @return  The wrapped request from a downstream client, or {@code null} if
   *          there is none.
   */
  @Nullable()
  public IntermediateClientRequestValue getDownstreamRequest()
  {
    return value.getDownstreamRequest();
  }



  /**
   * Retrieves the requested client authorization identity, if available.
   *
   * @return  The requested client authorization identity, or {@code null} if
   *          there is none.
   */
  @Nullable()
  public String getClientIdentity()
  {
    return value.getClientIdentity();
  }



  /**
   * Retrieves the IP address or resolvable name of the downstream client
   * system, if available.
   *
   * @return  The IP address or resolvable name of the downstream client system,
   *          or {@code null} if there is no downstream client or its address is
   *          not available.
   */
  @Nullable()
  public String getDownstreamClientAddress()
  {
    return value.getDownstreamClientAddress();
  }



  /**
   * Indicates whether the communication with the communication with the
   * downstream client is secure (i.e., whether communication between the
   * client application and the downstream client is safe from interpretation or
   * undetectable alteration by a third party observer or interceptor).
   *
   *
   * @return  {@code Boolean.TRUE} if communication with the downstream client
   *          is secure, {@code Boolean.FALSE} if it is not secure, or
   *          {@code null} if there is no downstream client or it is not known
   *          whether the communication is secure.
   */
  @Nullable()
  public Boolean downstreamClientSecure()
  {
    return value.downstreamClientSecure();
  }



  /**
   * Retrieves a string that identifies the client application that created this
   * intermediate client request value.
   *
   * @return  A string that may be used to identify the client application that
   *          created this intermediate client request value.
   */
  @Nullable()
  public String getClientName()
  {
    return value.getClientName();
  }



  /**
   * Retrieves a string that may be used to identify the session in the client
   * application.
   *
   * @return  A string that may be used to identify the session in the client
   *          application, or {@code null} if there is none.
   */
  @Nullable()
  public String getClientSessionID()
  {
    return value.getClientSessionID();
  }



  /**
   * Retrieves a string that may be used to identify the request in the client
   * application.
   *
   * @return  A string that may be used to identify the request in the client
   *          application, or {@code null} if there is none.
   */
  @Nullable()
  public String getClientRequestID()
  {
    return value.getClientRequestID();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_INTERMEDIATE_CLIENT_REQUEST.get();
  }



  /**
   * Retrieves a representation of this intermediate client request control as a
   * JSON object.  The JSON object uses the following fields:
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the intermediate client request
   *     control, the OID is "1.3.6.1.4.1.30221.2.5.2".
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
   *     base64-encoded representation of the raw value for this intermediate
   *     client request control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present.
   *   </LI>
   *   <LI>
   *     {@code value-json} -- An optional JSON object field whose value is a
   *     user-friendly representation of the value for this intermediate client
   *     request control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present, and if the
   *     {@code value-json} field is used, then it will use the following
   *     fields:
   *     <UL>
   *       <LI>
   *         {@code downstream-request} -- An optional JSON object field whose
   *         content represents a downstream request value.  If present, the
   *         fields of this object are the same as the fields that may be
   *         included in the top-level {@code value-json} object (optionally
   *         including a nested {@code downstream-request} field, if
   *         appropriate).
   *       </LI>
   *       <LI>
   *         {@code downstream-client-address} -- An optional string field whose
   *         value is the address of the immediate client from which the request
   *         was received.
   *       </LI>
   *       <LI>
   *         {@code downstream-client-secure} -- An optional Boolean field that
   *         indicates whether communication with the immediate client is using
   *         a secure channel.
   *       </LI>
   *       <LI>
   *         {@code client-identity} -- An optional string field whose value is
   *         the authorization identity of a user as whom the operation should
   *         be authorized.
   *       </LI>
   *       <LI>
   *         {@code client-name} -- An optional string field whose value is the
   *         name of the client application that generated this control.
   *       </LI>
   *       <LI>
   *         {@code client-session-id} -- An optional string field whose value
   *         is an identifier that the client is using to reference the current
   *         communication session with a downstream client.
   *       </LI>
   *       <LI>
   *         {@code client-request-id} -- An optional string field whose value
   *         is an identifier that the client is using to reference this request
   *         from a downstream client.
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
              INTERMEDIATE_CLIENT_REQUEST_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_INTERMEDIATE_CLIENT_REQUEST.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              encodeRequestValueJSON(value)));
  }



  /**
   * Encodes the provided intermediate client request value to a JSON object.
   *
   * @param  value  The intermediate client request value to be encoded.  It
   *                must not be {@code null}.
   *
   * @return  The JSON object containing the encoded intermediate client
   *          request value.
   */
  @NotNull()
  private static JSONObject encodeRequestValueJSON(
               @NotNull final IntermediateClientRequestValue value)
  {
    final Map<String,JSONValue> fields = new LinkedHashMap<>();

    final IntermediateClientRequestValue downstreamRequest =
         value.getDownstreamRequest();
    if (downstreamRequest != null)
    {
      fields.put(JSON_FIELD_DOWNSTREAM_REQUEST,
           encodeRequestValueJSON(downstreamRequest));
    }

    final String downstreamClientAddress = value.getDownstreamClientAddress();
    if (downstreamClientAddress != null)
    {
      fields.put(JSON_FIELD_DOWNSTREAM_CLIENT_ADDRESS,
           new JSONString(downstreamClientAddress));
    }

    final Boolean downstreamClientSecure = value.downstreamClientSecure();
    if (downstreamClientSecure != null)
    {
      fields.put(JSON_FIELD_DOWNSTREAM_CLIENT_SECURE,
           new JSONBoolean(downstreamClientSecure));
    }

    final String clientIdentity = value.getClientIdentity();
    if (clientIdentity != null)
    {
      fields.put(JSON_FIELD_CLIENT_IDENTITY, new JSONString(clientIdentity));
    }

    final String clientName = value.getClientName();
    if (clientName != null)
    {
      fields.put(JSON_FIELD_CLIENT_NAME, new JSONString(clientName));
    }

    final String clientSessionID = value.getClientSessionID();
    if (clientSessionID != null)
    {
      fields.put(JSON_FIELD_CLIENT_SESSION_ID, new JSONString(clientSessionID));
    }

    final String clientRequestID = value.getClientRequestID();
    if (clientRequestID != null)
    {
      fields.put(JSON_FIELD_CLIENT_REQUEST_ID, new JSONString(clientRequestID));
    }

    return new JSONObject(fields);
  }



  /**
   * Attempts to decode the provided object as a JSON representation of an
   * intermediate client request control.
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
   * @return  The intermediate client request control that was decoded from
   *          the provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid intermediate client request control.
   */
  @NotNull()
  public static IntermediateClientRequestControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new IntermediateClientRequestControl(new Control(
           jsonControl.getOID(), jsonControl.getCriticality(), rawValue));
    }


    final IntermediateClientRequestValue value =
         decodeIntermediateClientRequestValueJSON(controlObject,
              jsonControl.getValueObject(), false, strict);
    return new IntermediateClientRequestControl(jsonControl.getCriticality(),
         value);
  }



  /**
   * Decodes the provided JSON Object as an intermediate client request value.
   *
   * @param  controlObject        The JSON object that represents the entire
   *                              intermediate client request control.  It must
   *                              not be {@code null}.
   * @param  valueObject          The intermediate client request value to
   *                              decode.  It must not be {@code null}.
   * @param  isDownstreamRequest  Indicates whether the provided JSON object
   *                              represents a downstream request.
   * @param  strict               Indicates whether to use strict mode when
   *                              decoding the provided JSON object.  If this is
   *                              {@code true}, then this method will throw an
   *                              exception if the provided JSON object contains
   *                              any unrecognized fields.  If this is
   *                              {@code false}, then unrecognized fields will
   *                              be ignored.
   *
   * @return  The intermediate client request value that was decoded.
   *
   * @throws  LDAPException  If the provided JSON object cannot be decoded as an
   *                         intermediate client request value.
   */
  @NotNull()
  private static IntermediateClientRequestValue
               decodeIntermediateClientRequestValueJSON(
                    @NotNull final JSONObject controlObject,
                    @NotNull final JSONObject valueObject,
                    final boolean isDownstreamRequest,
                    final boolean strict)
          throws LDAPException
  {
    final IntermediateClientRequestValue downstreamRequest;
    final JSONObject downstreamRequestObject =
         valueObject.getFieldAsObject(JSON_FIELD_DOWNSTREAM_REQUEST);
    if (downstreamRequestObject == null)
    {
      downstreamRequest = null;
    }
    else
    {
      downstreamRequest = decodeIntermediateClientRequestValueJSON(
           controlObject, downstreamRequestObject, true, strict);
    }

    final String downstreamClientAddress =
         valueObject.getFieldAsString(JSON_FIELD_DOWNSTREAM_CLIENT_ADDRESS);
    final Boolean downstreamClientSecure =
         valueObject.getFieldAsBoolean(JSON_FIELD_DOWNSTREAM_CLIENT_SECURE);
    final String clientIdentity =
         valueObject.getFieldAsString(JSON_FIELD_CLIENT_IDENTITY);
    final String clientName =
         valueObject.getFieldAsString(JSON_FIELD_CLIENT_NAME);
    final String clientSessionID =
         valueObject.getFieldAsString(JSON_FIELD_CLIENT_SESSION_ID);
    final String clientRequestID =
         valueObject.getFieldAsString(JSON_FIELD_CLIENT_REQUEST_ID);



    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_DOWNSTREAM_REQUEST,
                JSON_FIELD_DOWNSTREAM_CLIENT_ADDRESS,
                JSON_FIELD_DOWNSTREAM_CLIENT_SECURE,
                JSON_FIELD_CLIENT_IDENTITY,
                JSON_FIELD_CLIENT_NAME,
                JSON_FIELD_CLIENT_SESSION_ID,
                JSON_FIELD_CLIENT_REQUEST_ID);
      if (! unrecognizedFields.isEmpty())
      {
        if (isDownstreamRequest)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_INTERMEDIATE_CLIENT_REQUEST_JSON_DS_VALUE_UNRECOGNIZED_FIELD.
                    get(controlObject.toSingleLineString(),
                         unrecognizedFields.get(0)));
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_INTERMEDIATE_CLIENT_REQUEST_JSON_VALUE_UNRECOGNIZED_FIELD.
                    get(controlObject.toSingleLineString(),
                         unrecognizedFields.get(0)));
        }
      }
    }


    return new IntermediateClientRequestValue(downstreamRequest,
         downstreamClientAddress, downstreamClientSecure, clientIdentity,
         clientName, clientSessionID, clientRequestID);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("IntermediateClientRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(", value=");
    value.toString(buffer);
    buffer.append(')');
  }
}
