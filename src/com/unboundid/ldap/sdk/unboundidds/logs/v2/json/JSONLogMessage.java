/*
 * Copyright 2022-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2023 Ping Identity Corporation
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
 * Copyright (C) 2022-2023 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.json;



import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.unboundid.ldap.sdk.unboundidds.logs.LogException;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.LogField;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.LogMessage;
import com.unboundid.util.Debug;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.logs.v2.json.JSONLogMessages.*;



/**
 * This class provides a data structure that holds information about a
 * JSON-formatted log message.
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
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class JSONLogMessage
       implements LogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 997950529069507711L;



  // The JSON object that contains an encoded representation of this log
  // message.
  @NotNull private final JSONObject jsonObject;

  // The timestamp value for this log message.
  private final long timestampValue;

  // A map of the fields in this log message.
  @NotNull private final Map<String,List<String>> logFields;

  // A string representation of this log message.
  @NotNull private final String logMessageString;

  // The log type for this log message.
  @Nullable private final String logType;



  /**
   * Creates a new JSON log message from the provided JSON object.
   *
   * @param  jsonObject  The JSON object that contains an encoded representation
   *                     of this log message.  It must not be {@code null}.
   *
   * @throws  LogException  If the provided JSON object cannot be parsed as a
   *                        valid log message.
   */
  protected JSONLogMessage(@NotNull final JSONObject jsonObject)
            throws LogException
  {
    this.jsonObject = jsonObject;
    logMessageString = jsonObject.toSingleLineString();

    final JSONValue timestampJSONValue = jsonObject.getField(
         JSONFormattedAccessLogFields.TIMESTAMP.getFieldName());
    if (timestampJSONValue == null)
    {
      throw new LogException(logMessageString,
           ERR_JSON_LOG_MESSAGE_MISSING_TIMESTAMP.get(logMessageString,
                JSONFormattedAccessLogFields.TIMESTAMP.getFieldName()));
    }

    if (! (timestampJSONValue instanceof JSONString))
    {
      throw new LogException(logMessageString,
           ERR_JSON_LOG_MESSAGE_TIMESTAMP_NOT_STRING.get(logMessageString,
           JSONFormattedAccessLogFields.TIMESTAMP.getFieldName()));
    }

    try
    {
      timestampValue = StaticUtils.decodeRFC3339Time(
           ((JSONString) timestampJSONValue).stringValue()).getTime();
    }
    catch (final ParseException e)
    {
      Debug.debugException(e);
      throw new LogException(logMessageString,
           ERR_JSON_LOG_MESSAGE_MALFORMED_TIMESTAMP.get(logMessageString,
                JSONFormattedAccessLogFields.TIMESTAMP.getFieldName()),
           e);
    }


    final Map<String,List<String>> fieldMap = new LinkedHashMap<>();
    for (final Map.Entry<String,JSONValue> e :
         jsonObject.getFields().entrySet())
    {
      fieldMap.put(e.getKey(), valueToStrings(e.getValue()));
    }

    logFields = Collections.unmodifiableMap(fieldMap);

    logType = getString(JSONFormattedAccessLogFields.LOG_TYPE);
  }



  /**
   * Retrieves a list of the string representations of the values represented by
   * the provided JSON value.
   *
   * @param  value  The JSON value for which to obtain the string
   *                representations.  It must not be {@code null}.
   *
   * @return  A list of the string representations of the values represented by
   *          the provided JSON value.
   */
  @NotNull()
  static List<String> valueToStrings(@NotNull final JSONValue value)
  {
    if (value instanceof JSONArray)
    {
      final JSONArray a = (JSONArray) value;
      final List<JSONValue> valueList = a.getValues();
      final List<String> valueStrings = new ArrayList<>(valueList.size());
      for (final JSONValue v : valueList)
      {
        if (v instanceof JSONString)
        {
          valueStrings.add(((JSONString) v).stringValue());
        }
        else
        {
          valueStrings.add(v.toSingleLineString());
        }
      }

      return Collections.unmodifiableList(valueStrings);
    }
    else if (value instanceof JSONString)
    {
      return Collections.singletonList(((JSONString) value).stringValue());
    }
    else
    {
      return Collections.singletonList(value.toSingleLineString());
    }
  }



  /**
   * Retrieves the JSON object that contains an encoded representation of this
   * log message.
   *
   * @return  The JSON object that contains an encoded representation of this
   *          log message.
   */
  @NotNull()
  public final JSONObject getJSONObject()
  {
    return jsonObject;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public final Date getTimestamp()
  {
    return new Date(timestampValue);
  }



  /**
   * Retrieves the type of logger with which this message is associated.
   *
   * @return  The type of logger with which this message is associated, or
   *          {@code null} if it is not included in the log message.
   */
  @Nullable()
  public final String getLogType()
  {
    return logType;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public final Map<String,List<String>> getFields()
  {
    return logFields;
  }


  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Boolean getBoolean(@NotNull final LogField logField)
         throws LogException
  {
    final JSONValue fieldValue = getFirstValue(logField);
    if (fieldValue == null)
    {
      return null;
    }

    if (fieldValue instanceof JSONBoolean)
    {
      return ((JSONBoolean) fieldValue).booleanValue();
    }
    else if (fieldValue instanceof JSONString)
    {
      final String stringValue = ((JSONString) fieldValue).stringValue();
      if (stringValue.equalsIgnoreCase("true"))
      {
        return Boolean.TRUE;
      }
      else if (stringValue.equalsIgnoreCase("false"))
      {
        return Boolean.FALSE;
      }
      else
      {
        throw new LogException(logMessageString,
             ERR_JSON_LOG_MESSAGE_VALUE_NOT_BOOLEAN.get(logField.getFieldName(),
                  logMessageString));
      }
    }
    else
    {
      throw new LogException(logMessageString,
           ERR_JSON_LOG_MESSAGE_VALUE_NOT_BOOLEAN.get(logField.getFieldName(),
                logMessageString));
    }
  }



  /**
   * Retrieves the Boolean value of the specified field.
   *
   * @param  logField  The field for which to retrieve the Boolean value.
   *
   * @return  The Boolean value of the specified field, or {@code null} if the
   *          field does not exist in the log message or cannot be parsed as a
   *          Boolean.
   */
  @Nullable()
  final Boolean getBooleanNoThrow(@NotNull final LogField logField)
  {
    try
    {
      return getBoolean(logField);
    }
    catch (final LogException e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Date getGeneralizedTime(@NotNull final LogField logField)
         throws LogException
  {
    final JSONValue fieldValue = getFirstValue(logField);
    if (fieldValue == null)
    {
      return null;
    }

    if (fieldValue instanceof JSONString)
    {
      final String stringValue = ((JSONString) fieldValue).stringValue();
      try
      {
        return StaticUtils.decodeGeneralizedTime(stringValue);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LogException(logMessageString,
             ERR_JSON_LOG_MESSAGE_VALUE_NOT_GENERALIZED_TIME.get(
                  logField.getFieldName(), logMessageString),
             e);
      }
    }
    else
    {
      throw new LogException(logMessageString,
           ERR_JSON_LOG_MESSAGE_VALUE_NOT_GENERALIZED_TIME.get(
                logField.getFieldName(), logMessageString));
    }
  }



  /**
   * Retrieves the generalized time value of the specified field.
   *
   * @param  logField  The field for which to retrieve the generalized time
   *                   value.
   *
   * @return  The generalized time value of the specified field, or {@code null}
   *          if the field does not exist in the log message or cannot be parsed
   *          as a timestamp in the generalized time format.
   */
  @Nullable()
  final Date getGeneralizedTimeNoThrow(@NotNull final LogField logField)
  {
    try
    {
      return getGeneralizedTime(logField);
    }
    catch (final LogException e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Double getDouble(@NotNull final LogField logField)
         throws LogException
  {
    final JSONValue fieldValue = getFirstValue(logField);
    if (fieldValue == null)
    {
      return null;
    }

    if (fieldValue instanceof JSONNumber)
    {
      return ((JSONNumber) fieldValue).getValue().doubleValue();
    }
    else if (fieldValue instanceof JSONString)
    {
      final String stringValue = ((JSONString) fieldValue).stringValue();
      try
      {
        return Double.valueOf(stringValue);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LogException(logMessageString,
             ERR_JSON_LOG_MESSAGE_VALUE_NOT_FLOATING_POINT.get(
                  logField.getFieldName(), logMessageString),
             e);
      }
    }
    else
    {
      throw new LogException(logMessageString,
           ERR_JSON_LOG_MESSAGE_VALUE_NOT_FLOATING_POINT.get(
                logField.getFieldName(), logMessageString));
    }
  }



  /**
   * Retrieves the floating-point value of the specified field.
   *
   * @param  logField  The field for which to retrieve the floating-point value.
   *
   * @return  The floating-point value of the specified field, or {@code null}
   *          if the field does not exist in the log message or cannot be parsed
   *          as a Double.
   */
  @Nullable()
  final Double getDoubleNoThrow(@NotNull final LogField logField)
  {
    try
    {
      return getDouble(logField);
    }
    catch (final LogException e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Integer getInteger(@NotNull final LogField logField)
         throws LogException
  {
    final JSONValue fieldValue = getFirstValue(logField);
    if (fieldValue == null)
    {
      return null;
    }

    if (fieldValue instanceof JSONNumber)
    {
      try
      {
        return ((JSONNumber) fieldValue).getValue().intValueExact();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LogException(logMessageString,
             ERR_JSON_LOG_MESSAGE_VALUE_NOT_INTEGER.get(
                  logField.getFieldName(), logMessageString),
             e);
      }
    }
    else if (fieldValue instanceof JSONString)
    {
      final String stringValue = ((JSONString) fieldValue).stringValue();
      try
      {
        return Integer.parseInt(stringValue);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LogException(logMessageString,
             ERR_JSON_LOG_MESSAGE_VALUE_NOT_INTEGER.get(
                  logField.getFieldName(), logMessageString),
             e);
      }
    }
    else
    {
      throw new LogException(logMessageString,
           ERR_JSON_LOG_MESSAGE_VALUE_NOT_INTEGER.get(
                logField.getFieldName(), logMessageString));
    }
  }



  /**
   * Retrieves the integer value of the specified field.
   *
   * @param  logField  The field for which to retrieve the integer value.
   *
   * @return  The integer value of the specified field, or {@code null} if the
   *          field does not exist in the log message or cannot be parsed as an
   *          {@code Integer}.
   */
  @Nullable()
  final Integer getIntegerNoThrow(@NotNull final LogField logField)
  {
    try
    {
      return getInteger(logField);
    }
    catch (final LogException e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Long getLong(@NotNull final LogField logField)
         throws LogException
  {
    final JSONValue fieldValue = getFirstValue(logField);
    if (fieldValue == null)
    {
      return null;
    }

    if (fieldValue instanceof JSONNumber)
    {
      try
      {
        return ((JSONNumber) fieldValue).getValue().longValueExact();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LogException(logMessageString,
             ERR_JSON_LOG_MESSAGE_VALUE_NOT_INTEGER.get(
                  logField.getFieldName(), logMessageString),
             e);
      }
    }
    else if (fieldValue instanceof JSONString)
    {
      final String stringValue = ((JSONString) fieldValue).stringValue();
      try
      {
        return Long.parseLong(stringValue);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LogException(logMessageString,
             ERR_JSON_LOG_MESSAGE_VALUE_NOT_INTEGER.get(
                  logField.getFieldName(), logMessageString),
             e);
      }
    }
    else
    {
      throw new LogException(logMessageString,
           ERR_JSON_LOG_MESSAGE_VALUE_NOT_INTEGER.get(
                logField.getFieldName(), logMessageString));
    }
  }



  /**
   * Retrieves the integer value of the specified field.
   *
   * @param  logField  The field for which to retrieve the integer value.
   *
   * @return  The integer value of the specified field, or {@code null} if the
   *          field does not exist in the log message or cannot be parsed as a
   *          {@code Long}.
   */
  @Nullable()
  final Long getLongNoThrow(@NotNull final LogField logField)
  {
    try
    {
      return getLong(logField);
    }
    catch (final LogException e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Date getRFC3339Timestamp(@NotNull final LogField logField)
         throws LogException
  {
    final JSONValue fieldValue = getFirstValue(logField);
    if (fieldValue == null)
    {
      return null;
    }

    if (fieldValue instanceof JSONString)
    {
      final String stringValue = ((JSONString) fieldValue).stringValue();
      try
      {
        return StaticUtils.decodeRFC3339Time(stringValue);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LogException(logMessageString,
             ERR_JSON_LOG_MESSAGE_VALUE_NOT_RFC_3339_TIME.get(
                  logField.getFieldName(), logMessageString),
             e);
      }
    }
    else
    {
      throw new LogException(logMessageString,
           ERR_JSON_LOG_MESSAGE_VALUE_NOT_RFC_3339_TIME.get(
                logField.getFieldName(), logMessageString));
    }
  }



  /**
   * Retrieves the RFC 3339 timestamp value of the specified field.
   *
   * @param  logField  The field for which to retrieve the RFC 3339 timestamp
   *                   value.
   *
   * @return  The RFC 3339 timestamp value of the specified field, or
   *          {@code null} if the field does not exist in the log message or
   *          cannot be parsed as a timestamp in the RFC 3339 format.
   */
  @Nullable()
  final Date getRFC3339TimestampNoThrow(@NotNull final LogField logField)
  {
    try
    {
      return getRFC3339Timestamp(logField);
    }
    catch (final LogException e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getString(@NotNull final LogField logField)
  {
    final JSONValue fieldValue = getFirstValue(logField);
    if (fieldValue == null)
    {
      return null;
    }

    if (fieldValue instanceof JSONString)
    {
      return ((JSONString) fieldValue).stringValue();
    }
    else
    {
      return fieldValue.toSingleLineString();
    }
  }



  /**
   * Retrieves the list of values for the specified field as a list of strings.
   * The values are expected to be in a JSON array whose values are all strings.
   *
   * @param  logField  The field for which to retrieve the list of values.
   *
   * @return  The list of values for the specified field as a list of strings,
   *          or an empty list if the field is not present in the JSON object or
   *          if it is not an array of strings.
   */
  @NotNull()
  final List<String> getStringList(@NotNull final LogField logField)
  {
    final JSONValue fieldValue = jsonObject.getField(logField.getFieldName());
    if (fieldValue == null)
    {
      return Collections.emptyList();
    }

    if (fieldValue instanceof JSONString)
    {
      return Collections.singletonList(((JSONString) fieldValue).stringValue());
    }
    else if (fieldValue instanceof JSONArray)
    {
      final List<JSONValue> values = ((JSONArray) fieldValue).getValues();
      final List<String> stringValues = new ArrayList<>(values.size());
      for (final JSONValue v : values)
      {
        if (v instanceof JSONString)
        {
          stringValues.add(((JSONString) v).stringValue());
        }
      }

      return Collections.unmodifiableList(stringValues);
    }

    return Collections.emptyList();
  }



  /**
   * Retrieves the set of values for the specified field as a set of strings.
   * The values are expected to be in a JSON array whose values are all strings.
   *
   * @param  logField  The field for which to retrieve the set of values.
   *
   * @return  The set of values for the specified field as a set of strings, or
   *          an empty set if the field is not present in the JSON object or if
   *          it is not an array of strings.
   */
  @NotNull()
  final Set<String> getStringSet(@NotNull final LogField logField)
  {
    return Collections.unmodifiableSet(
         new LinkedHashSet<>(getStringList(logField)));
  }



  /**
   * Retrieves the first value of the specified field from the log message
   * object.
   *
   * @param  logField  The field for which to retrieve the first value.
   *
   * @return  The first value of the specified field, or {@code null} if the
   *          field is not present in the log message object, or if its value is
   *          an empty array.
   */
  @Nullable()
  JSONValue getFirstValue(@NotNull final LogField logField)
  {
    final JSONValue value = jsonObject.getField(logField.getFieldName());
    if (value == null)
    {
      return null;
    }

    if (value instanceof JSONArray)
    {
      final List<JSONValue> arrayValues = ((JSONArray) value).getValues();
      if (arrayValues.isEmpty())
      {
        return null;
      }
      else
      {
        return arrayValues.get(0);
      }
    }
    else
    {
      return value;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public final String toString()
  {
    return logMessageString;
  }
}
