/*
 * Copyright 2022-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2024 Ping Identity Corporation
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
 * Copyright (C) 2022-2024 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.Base64;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONObject;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides a helper class for use in parsing a JSON object as an
 * LDAP control.  It is a data structure that encapsulates the OID, criticality,
 * and unparsed value for the control.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JSONControlDecodeHelper
       implements Serializable
{
  /**
   * The name of the field used to hold a user-friendly name in the JSON object
   * representation of a control.
   */
  @NotNull public static final String JSON_FIELD_CONTROL_NAME = "control-name";



  /**
   * The name of the field used to hold the criticality in the JSON object
   * representation of a control.
   */
  @NotNull public static final String JSON_FIELD_CRITICALITY = "criticality";



  /**
   * The name of the field used to hold the object identifier in the JSON object
   * representation of a control.
   */
  @NotNull public static final String JSON_FIELD_OID = "oid";



  /**
   * The name of the field used to hold a base64-encoded representation of the
   * value in the JSON object representation of a control.
   */
  @NotNull public static final String JSON_FIELD_VALUE_BASE64 = "value-base64";



  /**
   * The name of the field used to hold a JSON-formatted representation of the
   * value in the JSON object representation of a control.
   */
  @NotNull public static final String JSON_FIELD_VALUE_JSON = "value-json";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5752098418939503096L;



  // The raw value for this control.
  @Nullable private final ASN1OctetString rawValue;

  // The criticality for the control.
  private final boolean criticality;

   // The JSON object that contains an encoded representation of this control.
  @NotNull private final JSONObject controlObject;

  // The JSON object that represents the value for this control.
  @Nullable private final JSONObject valueObject;

  // The OID for the control.
  @NotNull private final String oid;



  /**
   * Creates a new JSON control decode helper instance that is decoded from the
   * provided JSON object.
   *
   * @param  controlObject             The JSON object that represents an
   *                                   encoded representation of this control.
   *                                   It must not be {@code null}.
   * @param  throwOnUnrecognizedField  Indicates whether to throw an exception
   *                                   if the provided JSON object contains a
   *                                   field that is not expected to be
   *                                   present in the generic JSON
   *                                   representation of a control.
   * @param  allowValue                Indicates whether the control is allowed
   *                                   to have a value.
   * @param  requireValue              Indicates whether the control is required
   *                                   to have a value.
   *
   * @throws  LDAPException  If the provided JSON object does not represent a
   *                         valid control.
   */
  public JSONControlDecodeHelper(@NotNull final JSONObject controlObject,
                                 final boolean throwOnUnrecognizedField,
                                 final boolean allowValue,
                                 final boolean requireValue)
         throws LDAPException
  {
    this.controlObject = controlObject;


    oid = controlObject.getFieldAsString(JSON_FIELD_OID);
    if (oid == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_JSON_CONTROL_MISSING_OID.get(
                controlObject.toSingleLineString(), JSON_FIELD_OID));
    }

    final Boolean criticalityObject =
         controlObject.getFieldAsBoolean(JSON_FIELD_CRITICALITY);
    if (criticalityObject == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_JSON_CONTROL_MISSING_CRITICALITY.get(
                controlObject.toSingleLineString(), JSON_FIELD_OID));
    }

    criticality = criticalityObject;


    ASN1OctetString valueOctetString = null;
    valueObject = controlObject.getFieldAsObject(JSON_FIELD_VALUE_JSON);
    final String valueBase64 =
         controlObject.getFieldAsString(JSON_FIELD_VALUE_BASE64);
    if (valueBase64 == null)
    {
      if (valueObject == null)
      {
        if (allowValue && requireValue)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_JSON_CONTROL_MISSING_VALUE.get(
                    controlObject.toSingleLineString(),
                    JSON_FIELD_VALUE_BASE64, JSON_FIELD_VALUE_JSON));

        }
      }
      else if (! allowValue)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_JSON_CONTROL_DISALLOWED_VALUE.get(
                  controlObject.toSingleLineString()));
      }
    }
    else if (! allowValue)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_JSON_CONTROL_DISALLOWED_VALUE.get(
                controlObject.toSingleLineString()));
    }
    else if (valueObject != null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_JSON_CONTROL_VALUE_CONFLICT.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_VALUE_BASE64, JSON_FIELD_VALUE_JSON));
    }
    else
    {
      try
      {
        valueOctetString = new ASN1OctetString(Base64.decode(valueBase64));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_JSON_CONTROL_VALUE_NOT_VALID_BASE64.get(
                  controlObject.toSingleLineString(),
                  JSON_FIELD_VALUE_BASE64),
             e);
      }
    }

    rawValue = valueOctetString;

    if (throwOnUnrecognizedField)
    {
      final List<String> unexpectedFields = getControlObjectUnexpectedFields(
           controlObject, JSON_FIELD_OID, JSON_FIELD_CONTROL_NAME,
           JSON_FIELD_CRITICALITY, JSON_FIELD_VALUE_BASE64,
           JSON_FIELD_VALUE_JSON);
      if (! unexpectedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_JSON_CONTROL_UNEXPECTED_FIELD.get(
                  controlObject.toSingleLineString(), unexpectedFields.get(0)));
      }
    }
  }



  /**
   * Retrieves a list with the names of any unexpected fields in the provided
   * JSON object.
   *
   * @param  object         The JSON object to examine.  It must not be
   *                        {@code null}.
   * @param  allowedFields  The names of the fields that are allowed to be
   *                        present in the JSON object.  It must not be
   *                        {@code null}.
   *
   * @return  A list with the names of any unexpected fields in the provided
   *          JSON object, or an empty list if no unexpected fields were found.
   */
  @NotNull()
  public static List<String> getControlObjectUnexpectedFields(
                 @NotNull final JSONObject object,
                 @NotNull final String... allowedFields)
  {
    final Set<String> allowedFieldSet = new LinkedHashSet<>(
         Arrays.asList(allowedFields));
    final List<String> disallowedFields = new ArrayList<>();
    for (final String fieldName : object.getFields().keySet())
    {
      if (! allowedFieldSet.contains(fieldName))
      {
        disallowedFields.add(fieldName);
      }
    }

    return Collections.unmodifiableList(disallowedFields);
  }



  /**
   * Retrieves the JSON object used to create this control.
   *
   * @return  The JSON object used to create this control.
   */
  @NotNull()
  public JSONObject getControlObject()
  {
    return controlObject;
  }



  /**
   * Retrieves the OID for this control.
   *
   * @return  The OID for this control.
   */
  @NotNull()
  public String getOID()
  {
    return oid;
  }



  /**
   * Retrieves the criticality for this control.
   *
   * @return  {@code true} if the control is considered critical, or
   *          {@code false} if not.
   */
  public boolean getCriticality()
  {
    return criticality;
  }



  /**
   * Retrieves an ASN.1 octet string that represents the raw value for this
   * control, if available.
   *
   * @return  An ASN.1 octet string that represents the raw value for this
   *          control, or {@code null} if no raw value is available.
   */
  @Nullable()
  public ASN1OctetString getRawValue()
  {
    return rawValue;
  }



  /**
   * Retrieves the
   *
   * Retrieves an ASN.1 octet string that represents the raw value for this
   * control, if available.
   *
   * @return  An ASN.1 octet string that represents the raw value for this
   *          control, or {@code null} if no raw value is available.
   */
  @Nullable()
  public JSONObject getValueObject()
  {
    return valueObject;
  }



  /**
   * Retrieves a string representation of the JSON control.
   *
   * @return  A string representation of the JSON control.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return controlObject.toSingleLineString();
  }
}
