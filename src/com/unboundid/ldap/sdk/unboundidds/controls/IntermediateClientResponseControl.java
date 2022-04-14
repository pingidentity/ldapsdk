/*
 * Copyright 2008-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2022 Ping Identity Corporation
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
 * Copyright (C) 2008-2022 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class defines an intermediate client response control, which can be used
 * to provide a server with information about the client and any downstream
 * clients that it may have.
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
 * IntermediateClientResponse ::= SEQUENCE {
 *      upstreamResponse       [0] IntermediateClientResponse OPTIONAL,
 *      upstreamServerAddress  [1] OCTET STRING OPTIONAL,
 *      upstreamServerSecure   [2] BOOLEAN DEFAULT FALSE,
 *      serverName             [3] OCTET STRING OPTIONAL,
 *      serverSessionID        [4] OCTET STRING OPTIONAL,
 *      serverResponseID       [5] OCTET STRING OPTIONAL,
 *      ... }
 * </PRE>
 * See the documentation in the {@link IntermediateClientRequestControl} class
 * for an example of using the intermediate client request and response
 * controls.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class IntermediateClientResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.2) for the intermediate client response
   * control.
   */
  @NotNull public static final String INTERMEDIATE_CLIENT_RESPONSE_OID =
       "1.3.6.1.4.1.30221.2.5.2";



  /**
   * The name of the field used to hold the server name in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_SERVER_NAME = "server-name";



  /**
   * The name of the field used to hold the server request ID in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_SERVER_RESPONSE_ID =
       "server-response-id";



  /**
   * The name of the field used to hold the server session ID in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_SERVER_SESSION_ID =
       "server-session-id";



  /**
   * The name of the field used to hold the upstream response in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_UPSTREAM_RESPONSE =
       "upstream-response";



  /**
   * The name of the field used to hold the upstream server address in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_UPSTREAM_SERVER_ADDRESS =
       "upstream-server-address";



  /**
   * The name of the field used to hold the upstream server secure flag in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_UPSTREAM_SERVER_SECURE =
       "upstream-server-secure";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7476073413872875835L;



  // The value for this intermediate client response control.
  @NotNull private final IntermediateClientResponseValue value;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  IntermediateClientResponseControl()
  {
    value = null;
  }



  /**
   * Creates a new intermediate client response control with the provided
   * information.  It will not be marked critical.
   *
   * @param  upstreamResponse       A wrapped intermediate client response from
   *                                an upstream server.  It may be {@code null}
   *                                if there is no wrapped upstream response.
   * @param  upstreamServerAddress  The IP address or resolvable name of the
   *                                upstream server system.  It may be
   *                                {@code null} if there is no upstream server
   *                                or its address is not available.
   * @param  upstreamServerSecure   Indicates whether communication with the
   *                                upstream server is secure.  It may be
   *                                {@code null} if there is no upstream server
   *                                or it is not known whether the communication
   *                                is secure.
   * @param  serverName             An identifier string that summarizes the
   *                                server application that created this
   *                                intermediate client response.  It may be
   *                                {@code null} if that information is not
   *                                available.
   * @param  serverSessionID        A string that may be used to identify the
   *                                session in the server application.  It may
   *                                be {@code null} if there is no available
   *                                session identifier.
   * @param  serverResponseID       A string that may be used to identify the
   *                                response in the server application.  It may
   *                                be {@code null} if there is no available
   *                                response identifier.
   */
  public IntermediateClientResponseControl(
              @Nullable final IntermediateClientResponseValue upstreamResponse,
              @Nullable final String upstreamServerAddress,
              @Nullable final Boolean upstreamServerSecure,
              @Nullable final String serverName,
              @Nullable final String serverSessionID,
              @Nullable final String serverResponseID)
  {
    this(false,
         new IntermediateClientResponseValue(upstreamResponse,
                  upstreamServerAddress, upstreamServerSecure, serverName,
                  serverSessionID, serverResponseID));
  }



  /**
   * Creates a new intermediate client response control with the provided
   * information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         intermediate client response control.
   */
  public IntermediateClientResponseControl(@NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ICRESP_CONTROL_NO_VALUE.get());
    }

    final ASN1Sequence valueSequence;
    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      valueSequence = ASN1Sequence.decodeAsSequence(valueElement);
    }
    catch (final Exception e)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ICRESP_CONTROL_VALUE_NOT_SEQUENCE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    this.value = IntermediateClientResponseValue.decode(valueSequence);
  }



  /**
   * Creates a new intermediate client response control with the provided value.
   * It will be marked critical.
   *
   * @param  value  The value to use for this intermediate client response
   *                control.  It must not be {@code null}.
   */
  public IntermediateClientResponseControl(
              @NotNull final IntermediateClientResponseValue value)
  {
    this(false, value);
  }



  /**
   * Creates a new intermediate client response control with the provided value.
   *
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.  Response controls should generally not be
   *                     critical.
   * @param  value       The value to use for this intermediate client response
   *                     control.  It must not be {@code null}.
   */
  public IntermediateClientResponseControl(final boolean isCritical,
              @NotNull final IntermediateClientResponseValue value)
  {
    super(INTERMEDIATE_CLIENT_RESPONSE_OID, isCritical,
          new ASN1OctetString(value.encode().encode()));

    this.value = value;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public IntermediateClientResponseControl decodeControl(
              @NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
          throws LDAPException
  {
    return new IntermediateClientResponseControl(oid, isCritical, value);
  }



  /**
   * Extracts an intermediate client response control from the provided result.
   *
   * @param  result  The result from which to retrieve the intermediate client
   *                 response control.
   *
   * @return  The intermediate client response control contained in the provided
   *          result, or {@code null} if the result did not contain an
   *          intermediate client response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the intermediate client response control
   *                         contained in the provided result.
   */
  @Nullable()
  public static IntermediateClientResponseControl get(
                     @NotNull final LDAPResult result)
         throws LDAPException
  {
    final Control c =
         result.getResponseControl(INTERMEDIATE_CLIENT_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof IntermediateClientResponseControl)
    {
      return (IntermediateClientResponseControl) c;
    }
    else
    {
      return new IntermediateClientResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * Retrieves the value for this intermediate client response.
   *
   * @return  The value for this intermediate client response.
   */
  @NotNull()
  public IntermediateClientResponseValue getResponseValue()
  {
    return value;
  }



  /**
   * Retrieves the wrapped response from an upstream server, if available.
   *
   * @return  The wrapped response from an upstream server, or {@code null} if
   *          there is none.
   */
  @Nullable()
  public IntermediateClientResponseValue getUpstreamResponse()
  {
    return value.getUpstreamResponse();
  }



  /**
   * Retrieves the IP address or resolvable name of the upstream server system,
   * if available.
   *
   * @return  The IP address or resolvable name of the upstream server system,
   *          {@code null} if there is no upstream server or its address is not
   *          available.
   */
  @Nullable()
  public String getUpstreamServerAddress()
  {
    return value.getUpstreamServerAddress();
  }



  /**
   * Indicates whether the communication with the communication with the
   * upstream server is secure (i.e., whether communication between the
   * server application and the upstream server is safe from interpretation or
   * undetectable alteration by a third party observer or interceptor).
   *
   *
   * @return  {@code Boolean.TRUE} if communication with the upstream server is
   *          secure, {@code Boolean.FALSE} if it is not secure, or
   *          {@code null} if there is no upstream server or it is not known
   *          whether the communication is secure.
   */
  @Nullable()
  public Boolean upstreamServerSecure()
  {
    return value.upstreamServerSecure();
  }



  /**
   * Retrieves a string that identifies the server application that created this
   * intermediate client response value.
   *
   * @return  A string that may be used to identify the server application that
   *          created this intermediate client response value.
   */
  @Nullable()
  public String getServerName()
  {
    return value.getServerName();
  }



  /**
   * Retrieves a string that may be used to identify the session in the server
   * application.
   *
   * @return  A string that may be used to identify the session in the server
   *          application, or {@code null} if there is none.
   */
  @Nullable()
  public String getServerSessionID()
  {
    return value.getServerSessionID();
  }



  /**
   * Retrieves a string that may be used to identify the response in the server
   * application.
   *
   * @return  A string that may be used to identify the response in the server
   *          application, or {@code null} if there is none.
   */
  @Nullable()
  public String getServerResponseID()
  {
    return value.getServerResponseID();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_INTERMEDIATE_CLIENT_RESPONSE.get();
  }



  /**
   * Retrieves a representation of this intermediate client response control as
   * a JSON object.  The JSON object uses the following fields:
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the intermediate client response
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
   *     client response control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present.
   *   </LI>
   *   <LI>
   *     {@code value-json} -- An optional JSON object field whose value is a
   *     user-friendly representation of the value for this intermediate client
   *     response control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present, and if the
   *     {@code value-json} field is used, then it will use the following
   *     fields:
   *     <UL>
   *       <LI>
   *         {@code upstream-response} -- An optional JSON object field whose
   *         content represents an upstream response value.  If present, the
   *         fields of this object are the same as the fields that may be
   *         included in the top-level {@code value-json} object (optionally
   *         including a nested {@code upstream-response} field, if
   *         appropriate).
   *       </LI>
   *       <LI>
   *         {@code upstream-server-address} -- An optional string field whose
   *         value is the address of an upstream server to which the requested
   *         operation was forwarded.
   *       </LI>
   *       <LI>
   *         {@code upstream-server-secure} -- An optional Boolean field that
   *         indicates whether communication with an upstream server occurred
   *         over a secure channel.
   *       </LI>
   *       <LI>
   *         {@code server-name} -- An optional string field whose value is the
   *         name of the application used to process the request.
   *       </LI>
   *       <LI>
   *         {@code server-session-id} -- An optional string field whose value
   *         is an identifier that the server is using to reference the current
   *         communication session with the client.
   *       </LI>
   *       <LI>
   *         {@code server-response-id} -- An optional string field whose value
   *         is an identifier that the server is using to reference the current
   *         operation being processed.
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
              INTERMEDIATE_CLIENT_RESPONSE_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_INTERMEDIATE_CLIENT_RESPONSE.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              encodeResponseValueJSON(value)));
  }



  /**
   * Encodes the provided intermediate client response value to a JSON object.
   *
   * @param  value  The intermediate client response value to be encoded.  It
   *                must not be {@code null}.
   *
   * @return  The JSON object containing the encoded intermediate client
   *          response value.
   */
  @NotNull()
  private static JSONObject encodeResponseValueJSON(
               @NotNull final IntermediateClientResponseValue value)
  {
    final Map<String,JSONValue> fields = new LinkedHashMap<>();

    final IntermediateClientResponseValue upstreamResponse =
         value.getUpstreamResponse();
    if (upstreamResponse != null)
    {
      fields.put(JSON_FIELD_UPSTREAM_RESPONSE,
           encodeResponseValueJSON(upstreamResponse));
    }

    final String upstreamServerAddress = value.getUpstreamServerAddress();
    if (upstreamServerAddress != null)
    {
      fields.put(JSON_FIELD_UPSTREAM_SERVER_ADDRESS,
           new JSONString(upstreamServerAddress));
    }

    final Boolean upstreamServerSecure = value.upstreamServerSecure();
    if (upstreamServerSecure != null)
    {
      fields.put(JSON_FIELD_UPSTREAM_SERVER_SECURE,
           new JSONBoolean(upstreamServerSecure));
    }
    final String serverName = value.getServerName();
    if (serverName != null)
    {
      fields.put(JSON_FIELD_SERVER_NAME, new JSONString(serverName));
    }

    final String serverSessionID = value.getServerSessionID();
    if (serverSessionID != null)
    {
      fields.put(JSON_FIELD_SERVER_SESSION_ID, new JSONString(serverSessionID));
    }

    final String serverResponseID = value.getServerResponseID();
    if (serverResponseID != null)
    {
      fields.put(JSON_FIELD_SERVER_RESPONSE_ID,
           new JSONString(serverResponseID));
    }

    return new JSONObject(fields);
  }



  /**
   * Attempts to decode the provided object as a JSON representation of an
   * intermediate client response control.
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
   * @return  The intermediate client response control that was decoded from
   *          the provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid intermediate client response control.
   */
  @NotNull()
  public static IntermediateClientResponseControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new IntermediateClientResponseControl(jsonControl.getOID(),
           jsonControl.getCriticality(), rawValue);
    }


    final IntermediateClientResponseValue value =
         decodeIntermediateClientResponseValueJSON(controlObject,
              jsonControl.getValueObject(), false, strict);
    return new IntermediateClientResponseControl(jsonControl.getCriticality(),
         value);
  }



  /**
   * Decodes the provided JSON Object as an intermediate client response value.
   *
   * @param  controlObject       The JSON object that represents the entire
   *                             intermediate client response control.  It must
   *                             not be {@code null}.
   * @param  valueObject         The intermediate client response value to
   *                             decode.  It must not be {@code null}.
   * @param  isUpstreamResponse  Indicates whether the provided JSON object
   *                             represents an upstream response.
   * @param  strict              Indicates whether to use strict mode when
   *                             decoding the provided JSON object.  If this is
   *                             {@code true}, then this method will throw an
   *                             exception if the provided JSON object contains
   *                             any unrecognized fields.  If this is
   *                             {@code false}, then unrecognized fields will
   *                             be ignored.
   *
   * @return  The intermediate client response value that was decoded.
   *
   * @throws  LDAPException  If the provided JSON object cannot be decoded as an
   *                         intermediate client response value.
   */
  @NotNull()
  private static IntermediateClientResponseValue
               decodeIntermediateClientResponseValueJSON(
                    @NotNull final JSONObject controlObject,
                    @NotNull final JSONObject valueObject,
                    final boolean isUpstreamResponse,
                    final boolean strict)
          throws LDAPException
  {
    final IntermediateClientResponseValue upstreamResponse;
    final JSONObject upstreamResponseObject =
         valueObject.getFieldAsObject(JSON_FIELD_UPSTREAM_RESPONSE);
    if (upstreamResponseObject == null)
    {
      upstreamResponse = null;
    }
    else
    {
      upstreamResponse = decodeIntermediateClientResponseValueJSON(
           controlObject, upstreamResponseObject, true, strict);
    }

    final String upstreamServerAddress =
         valueObject.getFieldAsString(JSON_FIELD_UPSTREAM_SERVER_ADDRESS);
    final Boolean upstreamServerSecure =
         valueObject.getFieldAsBoolean(JSON_FIELD_UPSTREAM_SERVER_SECURE);
    final String serverName =
         valueObject.getFieldAsString(JSON_FIELD_SERVER_NAME);
    final String serverSessionID =
         valueObject.getFieldAsString(JSON_FIELD_SERVER_SESSION_ID);
    final String serverResponseID =
         valueObject.getFieldAsString(JSON_FIELD_SERVER_RESPONSE_ID);



    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_UPSTREAM_RESPONSE,
                JSON_FIELD_UPSTREAM_SERVER_ADDRESS,
                JSON_FIELD_UPSTREAM_SERVER_SECURE,
                JSON_FIELD_SERVER_NAME,
                JSON_FIELD_SERVER_SESSION_ID,
                JSON_FIELD_SERVER_RESPONSE_ID);
      if (! unrecognizedFields.isEmpty())
      {
        if (isUpstreamResponse)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_INTERMEDIATE_CLIENT_RESPONSE_JSON_US_VALUE_UNRECOGNIZED_FIELD
                    .get(controlObject.toSingleLineString(),
                         unrecognizedFields.get(0)));
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_INTERMEDIATE_CLIENT_RESPONSE_JSON_VALUE_UNRECOGNIZED_FIELD.
                    get(controlObject.toSingleLineString(),
                         unrecognizedFields.get(0)));
        }
      }
    }


    return new IntermediateClientResponseValue(upstreamResponse,
         upstreamServerAddress, upstreamServerSecure, serverName,
         serverSessionID, serverResponseID);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("IntermediateClientResponseControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(", value=");
    value.toString(buffer);
    buffer.append(')');
  }
}
