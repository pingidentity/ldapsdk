/*
 * Copyright 2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2025 Ping Identity Corporation
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
 * Copyright (C) 2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.forgerockds.controls;



import java.util.ArrayList;
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
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.forgerockds.controls.ControlMessages.*;



/**
 * This class provides support for an implementation of a request control that
 * may be used to convey a
 * <a href="https://www.w3.org/TR/trace-context/">W3C trace context</a> to the
 * Directory Server in support of distributed tracing.
 * <BR>
 * This control is based on an implementation originally created for use in the
 * ForgeRock OpenDJ Directory Server, now known as PingDS.  It may be included
 * in any kind of request.  It has an OID of 1.3.6.1.4.1.36733.2.1.5.7, and it
 * must have a value with the following encoding:
 * <PRE>
 *   W3CTraceContextRequestValue ::= SEQUENCE {
 *        traceParent     OCTET STRING,
 *        traceState      OCTET STRING OPTIONAL
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class W3CTraceContextRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.36733.2.1.5.7) for the W3C trace context request
   * control.
   */
  @NotNull public static final String W3C_TRACE_CONTEXT_REQUEST_OID =
       "1.3.6.1.4.1.36733.2.1.5.7";



  /**
   * The name of the field used to hold the "traceparent" header value in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_TRACE_PARENT = "trace-parent";



  /**
   * The name of the field used to hold the "tracestate" header value in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_TRACE_STATE = "trace-state";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4086202983109938297L;



  // The value of the "traceparent" header for this control.
  @NotNull private final String traceParent;

  // The value of the "tracestate" header for this control.
  @Nullable private final String traceState;



  /**
   * Creates a new instance of this W3C trace context request control with the
   * provided information.  It will not be considered critical.
   *
   * @param  traceParent  The value of the "traceparent" header, as defined in
   *                      the W3C specification.  It must not be {@code null}
   *                      or empty.
   * @param  traceState   The value of the "tracestate" header.  It may be
   *                      {@code null} if no additional vendor-specific state
   *                      information is needed.
   */
  public W3CTraceContextRequestControl(@NotNull final String traceParent,
                                       @Nullable final String traceState)
  {
    this(traceParent, traceState, false);
  }



  /**
   * Creates a new instance of this W3C trace context request control with the
   * provided information.  It will not be considered critical.
   *
   * @param  traceParent  The value of the "traceparent" header, as defined in
   *                      the W3C specification.  It must not be {@code null}
   *                      or empty.
   * @param  traceState   The value of the "tracestate" header.  It may be
   *                      {@code null} if no additional vendor-specific state
   *                      information is needed.
   * @param  isCritical   Indicates whether this control should be considered
   *                      critical.
   */
  public W3CTraceContextRequestControl(@NotNull final String traceParent,
                                       @Nullable final String traceState,
                                       final boolean isCritical)
  {
    super(W3C_TRACE_CONTEXT_REQUEST_OID, isCritical,
         encodeValue(traceParent, traceState));

    this.traceParent = traceParent;
    this.traceState = traceState;
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of a W3C trace context request control.
   *
   * @param  traceParent  The value of the "traceparent" header, as defined in
   *                      the W3C specification.  It must not be {@code null}
   *                      or empty.
   * @param  traceState   The value of the "tracestate" header.  It may be
   *                      {@code null} if no additional vendor-specific state
   *                      information is needed.
   *
   * @return  The encoded value for the request control.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(@NotNull final String traceParent,
                                             @Nullable final String traceState)
  {
    Validator.ensureNotNullWithMessage(traceParent,
         "W3CTraceContextRequestControl.traceParent must not be null");

    final List<ASN1Element> valueElements = new ArrayList<>(2);
    valueElements.add(new ASN1OctetString(traceParent));

    if (traceState != null)
    {
      valueElements.add(new ASN1OctetString(traceState));
    }

    final ASN1Sequence valueSequence = new ASN1Sequence(valueElements);
    return new ASN1OctetString(valueSequence.encode());
  }



  /**
   * Creates a new W3C trace context request control that has been decoded from
   * the provided generic control.
   *
   * @param  control  The generic control to decode as a W3C trace context
   *                  request control.  It must not be {@code null}.
   *
   * @throws  LDAPException  If the provided generic control cannot be decoded
   *                         as a valid W3C trace context request control.
   */
  public W3CTraceContextRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);


    // Ensure that the control has a value.
    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_WC3_TRACE_CONTEXT_REQUST_NO_VALUE.get());
    }


    // Parse the control value.
    try
    {
      final ASN1Sequence valueSequence =
           ASN1Sequence.decodeAsSequence(value.getValue());
      final ASN1Element[] valueElements = valueSequence.elements();
      traceParent = valueElements[0].decodeAsOctetString().stringValue();

      if (valueElements.length > 1)
      {
        traceState = valueElements[1].decodeAsOctetString().stringValue();
      }
      else
      {
        traceState = null;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_WC3_TRACE_CONTEXT_REQUST_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the value of the "traceparent" header for this control.
   *
   * @return  The value of the "traceparent" header for this control.
   */
  @NotNull()
  public String getTraceParent()
  {
    return traceParent;
  }



  /**
   * Retrieves the value of the "tracestate" header for this control, if
   * provided.
   *
   * @return  The value of the "tracestate" header for this control, or
   *          {@code null} if no such value was provided.
   */
  @NotNull()
  public String getTraceState()
  {
    return traceState;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_WC3_TRACE_CONTEXT_REQUEST.get();
  }



  /**
   * Retrieves a representation of this W3C trace context request control as a
   * JSON object.  The JSON object uses the following fields:
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the W3C trace context request
   *     control, the OID is "1.3.6.1.4.1.36733.2.1.5.7".
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
   *     base64-encoded representation of the raw value for this W3C trace
   *     context request control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present.
   *   </LI>
   *   <LI>
   *     {@code value-json} -- An optional JSON object field whose value is a
   *     user-friendly representation of the value for this uniqueness request
   *     control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present, and if the
   *     {@code value-json} field is used, then it will use the following
   *     fields:
   *     <UL>
   *       <LI>
   *         {@code trace-parent} -- A mandatory string field that holds the
   *         value of the "traceparent" header for this control.
   *       </LI>
   *       <LI>
   *         {@code trace-state} -- An optional string field that holds the
   *         value of the "tracestate" header for this control.
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
    final Map<String,JSONValue> valueFields = new LinkedHashMap<>();
    valueFields.put(JSON_FIELD_TRACE_PARENT, new JSONString(traceParent));

    if (traceState != null)
    {
      valueFields.put(JSON_FIELD_TRACE_STATE, new JSONString(traceState));
    }


    return new JSONObject(
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_OID,
              W3C_TRACE_CONTEXT_REQUEST_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_WC3_TRACE_CONTEXT_REQUEST.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              new JSONObject(valueFields)));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a W3C
   * trace context request control.
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
   * @return  The W3C trace cotnext request control that was decoded from the
   *          provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid W3C trace context request control.
   */
  @NotNull()
  public static W3CTraceContextRequestControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new W3CTraceContextRequestControl(new Control(jsonControl.getOID(),
           jsonControl.getCriticality(), rawValue));
    }


    final JSONObject valueObject = jsonControl.getValueObject();

    final String traceParent =
         valueObject.getFieldAsString(JSON_FIELD_TRACE_PARENT);
    if (traceParent == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_WC3_TRACE_CONTEXT_REQUEST_MISSING_JSON_TRACE_PARENT.get(
                JSON_FIELD_TRACE_PARENT));
    }

    final String traceState =
         valueObject.getFieldAsString(JSON_FIELD_TRACE_STATE);


    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_TRACE_PARENT, JSON_FIELD_TRACE_STATE);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_WC3_TRACE_CONTEXT_REQUEST_UNRECOGNIZED_JSON_FIELD.get(
                  controlObject.toSingleLineString(),
                  unrecognizedFields.get(0)));
      }
    }

    return new W3CTraceContextRequestControl(traceParent, traceState,
         jsonControl.getCriticality());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("W3CTraceContextRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(", traceParent='");
    buffer.append(traceParent);
    buffer.append('\'');

    if (traceState != null)
    {
      buffer.append(", traceState='");
      buffer.append(traceState);
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
