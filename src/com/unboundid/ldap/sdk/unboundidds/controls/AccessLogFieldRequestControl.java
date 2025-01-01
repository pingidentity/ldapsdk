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



import java.util.Collection;
import java.util.Map;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a request control that can be included in any type of
 * request to indicate that the server should include one or more fields,
 * specified as name-value pairs, that should appear in the Ping Identity
 * Directory Server's access log message for the operation.
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
 * The OID for this control is 1.3.6.1.4.1.30221.2.5.66, the criticality may be
 * either {@code true} or {@code false}.  Its value should be the string
 * representation of a JSON object whose fields will represent the fields to
 * include in the access log message for the operation.  The JSON object may
 * only include Boolean, number, and string fields; array, null, and object
 * fields will not be permitted.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AccessLogFieldRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.66) for the generate access token request
   * control.
   */
  @NotNull public static final  String ACCESS_LOG_FIELD_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.66";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6329096464063641398L;



  // The JSON object that contains the fields to include in the access log
  // message.
  @NotNull private final JSONObject fieldsObject;



  /**
   * Creates a new access log field request control with the provided fields.
   * It will not be marked critical.
   *
   * @param  fields  The set of fields to include in the access log message.  It
   *                 must not be {@code null} or empty, and the values may only
   *                 have Boolean, number, or string types.  Array, null, and
   *                 object fields will not be allowed.
   *
   * @throws  LDAPException  If the provided set of fields is not acceptable.
   */
  public AccessLogFieldRequestControl(@NotNull final JSONField... fields)
         throws LDAPException
  {
    this(false, fields);
  }



  /**
   * Creates a new access log field request control with the provided fields.
   * It will not be marked critical.
   *
   * @param  fields  The set of fields to include in the access log message.  It
   *                 must not be {@code null} or empty, and the values may only
   *                 have Boolean, number, or string types.  Array, null, and
   *                 object fields will not be allowed.
   *
   * @throws  LDAPException  If the provided set of fields is not acceptable.
   */
  public AccessLogFieldRequestControl(
              @NotNull final Collection<JSONField> fields)
         throws LDAPException
  {
    this(false, fields);
  }



  /**
   * Creates a new access log field request control with the specified
   * criticality.
   *
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   * @param  fields      The set of fields to include in the access log message.
   *                     It must not be {@code null} or empty, and the values
   *                     may only have Boolean, number, or string types.  Array,
   *                     null, and object fields will not be allowed.
   *
   * @throws  LDAPException  If the provided set of fields is not acceptable.
   */
  public AccessLogFieldRequestControl(final boolean isCritical,
                                      @NotNull final JSONField... fields)
         throws LDAPException
  {
    this(isCritical, new JSONObject(fields));
  }



  /**
   * Creates a new access log field request control with the specified
   * criticality.
   *
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   * @param  fields      The set of fields to include in the access log message.
   *                     It must not be {@code null} or empty, and the values
   *                     may only have Boolean, number, or string types.  Array,
   *                     null, and object fields will not be allowed.
   *
   * @throws  LDAPException  If the provided set of fields is not acceptable.
   */
  public AccessLogFieldRequestControl(final boolean isCritical,
              @NotNull final Collection<JSONField> fields)
         throws LDAPException
  {
    this(isCritical,
         new JSONObject(StaticUtils.toArray(fields, JSONField.class)));
  }



  /**
   * Creates a new access log field request control with the specified
   * criticality.
   *
   * @param  isCritical    Indicates whether this control should be marked
   *                       critical.
   * @param  fieldsObject  A JSON object containing the set of fields to include
   *                       in the access log message.  It must not be
   *                       {@code null}, it must have at least one field, and it
   *                       may only have Boolean, number, or string fields.
   *                       Array, null, and object fields will not be allowed.
   *
   * @throws  LDAPException  If the provided object has an unacceptable set of
   *                         fields.
   */
  public AccessLogFieldRequestControl(final boolean isCritical,
                                      @NotNull final JSONObject fieldsObject)
         throws LDAPException
  {
    super(ACCESS_LOG_FIELD_REQUEST_OID, isCritical,
         new ASN1OctetString(fieldsObject.toString()));

    this.fieldsObject = fieldsObject;

    validateFields(fieldsObject);
  }



  /**
   * Ensures that the provided JSON object has an acceptable set of fields.
   *
   * @param  o  The JSON object to validate.  It must not be {@code null}.
   *
   * @throws  LDAPException  If the provided object has an unacceptable set of
   *                         fields.
   */
  private static void validateFields(@NotNull final JSONObject o)
          throws LDAPException
  {
    final Map<String,JSONValue> fields = o.getFields();
    if (fields.isEmpty())
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_ACCESS_LOG_FIELD_REQUEST_NO_FIELDS.get());
    }

    for (final Map.Entry<String,JSONValue> e : fields.entrySet())
    {
      final String fieldName = e.getKey();
      if (fieldName.isEmpty())
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_ACCESS_LOG_FIELD_REQUEST_EMPTY_FIELD_NAME.get());
      }

      for (final char c : fieldName.toCharArray())
      {
        if (! (((c >= 'a') && (c <= 'z')) ||
             ((c >= 'A') && (c <= 'Z')) ||
             ((c >= '0') && (c <= '9')) ||
             (c == '-') ||
             (c == '_')))
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_ACCESS_LOG_FIELD_REQUEST_INVALID_FIELD_NAME.get(fieldName));
        }
      }

      final JSONValue fieldValue = e.getValue();
      if (! ((fieldValue instanceof JSONBoolean) ||
           (fieldValue instanceof JSONNumber) ||
           (fieldValue instanceof JSONString)))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_ACCESS_LOG_FIELD_REQUEST_INVALID_FIELD_TYPE.get(fieldName));
      }
    }
  }



  /**
   * Creates a new access log field  request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as an access log field
   *                  request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         access log field request control.
   */
  public AccessLogFieldRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (! control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ACCESS_LOG_FIELD_REQUEST_DECODE_NO_VALUE.get());
    }

    try
    {
      fieldsObject = new JSONObject(control.getValue().stringValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ACCESS_LOG_FIELD_REQUEST_DECODE_VALUE_NOT_JSON.get());
    }

    try
    {
      validateFields(fieldsObject);
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ACCESS_LOG_FIELD_REQUEST_DECODE_VALUE_UNACCEPTABLE_FIELDS.get(
                e.getMessage()),
           e);
    }
  }



  /**
   * Retrieves a JSON object containing the set of fields to include in the
   * access log message.
   *
   * @return  A JSON object containing the set of fields to include in the
   *          access log message.
   */
  @NotNull()
  public JSONObject getFieldsObject()
  {
    return fieldsObject;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_ACCESS_LOG_FIELD_REQUEST.get();
  }



  /**
   * Retrieves a representation of this generate access token request control as
   * a JSON object.  The JSON object uses the following fields:
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the access log field request control,
   *     the OID is "1.3.6.1.4.1.30221.2.5.66".
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
   *     base64-encoded representation of the raw value for this access log
   *     field request control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present.
   *   </LI>
   *   <LI>
   *     {@code value-json} -- An optional JSON object field in which the object
   *     contains the set of fields to include in the access log message.
   *     Exactly one of the {@code value-base64} and {@code value-json} fields
   *     must be present, and if the {@code value-json} field is used, then the
   *     object must not be empty and it must contain only Boolean, number, and
   *     string fields.
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
              ACCESS_LOG_FIELD_REQUEST_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_ACCESS_LOG_FIELD_REQUEST.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              fieldsObject));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of an
   * access log field request control.
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
   * @return  The access log field request control that was decoded from the
   *          provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid access log field request control.
   */
  @NotNull()
  public static AccessLogFieldRequestControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new AccessLogFieldRequestControl(new Control(jsonControl.getOID(),
           jsonControl.getCriticality(), rawValue));
    }


    return new AccessLogFieldRequestControl(jsonControl.getCriticality(),
         jsonControl.getValueObject());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("AccessLogFieldRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(", fields=");
    buffer.append(fieldsObject.toSingleLineString());
    buffer.append(')');
  }
}
