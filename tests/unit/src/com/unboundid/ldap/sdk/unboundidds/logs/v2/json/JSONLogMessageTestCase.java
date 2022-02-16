/*
 * Copyright 2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022 Ping Identity Corporation
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
 * Copyright (C) 2022 Ping Identity Corporation
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



import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.unboundidds.logs.LogException;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.LogField;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax.
            GeneralizedTimeLogFieldSyntax;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax.IntegerLogFieldSyntax;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax.
            RFC3339TimestampLogFieldSyntax;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax.StringLogFieldSyntax;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNull;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.logs.AccessLogMessageType.*;
import static com.unboundid.ldap.sdk.unboundidds.logs.v2.json.
                   JSONFormattedAccessLogFields.*;



/**
 * This class provides a set of test cases for JSON log messages.
 */
public final class JSONLogMessageTestCase
       extends JSONLogsTestCase
{
  /**
   * Provides basic coverage for JSON log messages.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicMethods()
         throws Exception
  {
    final JSONObject messageObject = createPopulatedMessageObject(CONNECT, null,
         createField(CONNECT_FROM_ADDRESS, "2.3.4.5"),
         createField(CONNECT_FROM_PORT, 1234),
         createField(CONNECT_TO_ADDRESS, "2.3.4.6"),
         createField(CONNECT_TO_PORT, 4567),
         createField(PROTOCOL, "LDAP"),
         createField(CLIENT_CONNECTION_POLICY, "Default"));

    final JSONConnectAccessLogMessage logMessage =
         new JSONConnectAccessLogMessage(messageObject);

    assertNotNull(logMessage.getJSONObject());
    assertEquals(logMessage.getJSONObject(), messageObject);

    assertNotNull(logMessage.getTimestamp());
    assertEquals(logMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);

    assertNotNull(logMessage.getLogType());
    assertEquals(logMessage.getLogType(), ACCESS_LOG_TYPE);

    assertNotNull(logMessage.getFields());
    assertFalse(logMessage.getFields().isEmpty());

    assertNotNull(logMessage.toString());
  }



  /**
   * Tests to ensure that it's not possible to create a log message without a
   * timestamp.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLogMessageWithoutTimestamp()
         throws Exception
  {
    // Create a valid minimal message object and make sure we can create a log
    // message from it.
    final JSONObject validMessageObject =
         createMinimalMessageObject(CONNECT, null);
    new JSONConnectAccessLogMessage(validMessageObject);


    // Create a JSON object with all of the fields from the valid object except
    // the timestamp and verify that we can't create a log message from it.
    final Map<String,JSONValue> fieldsWithoutTimestamp =
         new LinkedHashMap<>(validMessageObject.getFields());
    assertNotNull(fieldsWithoutTimestamp.remove(TIMESTAMP.getFieldName()));
    final JSONObject messageObjectWithoutTimestamp =
         new JSONObject(fieldsWithoutTimestamp);

    try
    {
      new JSONConnectAccessLogMessage(messageObjectWithoutTimestamp);
      fail("Expected an exception when trying to create a log message " +
           "without a timestamp.");
    }
    catch (final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests to ensure that it's not possible to create a log message with a
   * timestamp field whose value is not a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLogMessageWithTimestampNotString()
         throws Exception
  {
    // Create a valid minimal message object and make sure we can create a log
    // message from it.
    final JSONObject validMessageObject =
         createMinimalMessageObject(CONNECT, null);
    new JSONConnectAccessLogMessage(validMessageObject);


    // Create a JSON object with all of the fields from the valid object except
    // this time use a malformed timestamp.
    final Map<String,JSONValue> fieldsWithNonStringTimestamp =
         new LinkedHashMap<>(validMessageObject.getFields());
    assertNotNull(fieldsWithNonStringTimestamp.put(TIMESTAMP.getFieldName(),
         JSONBoolean.TRUE));
    final JSONObject messageObjectWithNonStringTimestamp =
         new JSONObject(fieldsWithNonStringTimestamp);

    try
    {
      new JSONConnectAccessLogMessage(messageObjectWithNonStringTimestamp);
      fail("Expected an exception when trying to create a log message " +
           "with a non-string timestamp.");
    }
    catch (final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests to ensure that it's not possible to create a log message with a
   * malformed timestamp.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLogMessageWithMalformedTimestamp()
         throws Exception
  {
    // Create a valid minimal message object and make sure we can create a log
    // message from it.
    final JSONObject validMessageObject =
         createMinimalMessageObject(CONNECT, null);
    new JSONConnectAccessLogMessage(validMessageObject);


    // Create a JSON object with all of the fields from the valid object except
    // this time use a malformed timestamp.
    final Map<String,JSONValue> fieldsWithMalformedTimestamp =
         new LinkedHashMap<>(validMessageObject.getFields());
    assertNotNull(fieldsWithMalformedTimestamp.put(TIMESTAMP.getFieldName(),
         new JSONString("malformed")));
    final JSONObject messageObjectWithMalformedTimestamp =
         new JSONObject(fieldsWithMalformedTimestamp);

    try
    {
      new JSONConnectAccessLogMessage(messageObjectWithMalformedTimestamp);
      fail("Expected an exception when trying to create a log message " +
           "with a malformed timestamp.");
    }
    catch (final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior for the {@code valueToStrings} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValueToStrings()
         throws Exception
  {
    // Simple values.
    assertEquals(JSONLogMessage.valueToStrings(JSONBoolean.TRUE),
         Collections.singletonList("true"));
    assertEquals(JSONLogMessage.valueToStrings(JSONBoolean.FALSE),
         Collections.singletonList("false"));
    assertEquals(JSONLogMessage.valueToStrings(JSONNull.NULL),
         Collections.singletonList("null"));
    assertEquals(JSONLogMessage.valueToStrings(new JSONNumber(1234L)),
         Collections.singletonList("1234"));
    assertEquals(JSONLogMessage.valueToStrings(new JSONNumber(1.5d)),
         Collections.singletonList("1.5"));
    assertEquals(JSONLogMessage.valueToStrings(new JSONString("foo")),
         Collections.singletonList("foo"));

    // A JSON object value.
    final JSONObject o = new JSONObject(
         new JSONField("foo", "a"),
         new JSONField("bar", "b"));
    assertEquals(JSONLogMessage.valueToStrings(o),
         Collections.singletonList(o.toSingleLineString()));

    // An array of strings.
    final JSONArray stringArray = new JSONArray(
         new JSONString("one"),
         new JSONString("two"),
         new JSONString("three"));
    assertEquals(JSONLogMessage.valueToStrings(stringArray),
         Arrays.asList("one", "two", "three"));

    // An array that mixes values of different types.
    final JSONArray mixedTypeArray = new JSONArray(
         JSONBoolean.TRUE,
         new JSONNumber(0L),
         new JSONString("foo"),
         JSONArray.EMPTY_ARRAY,
         JSONObject.EMPTY_OBJECT);
    assertEquals(JSONLogMessage.valueToStrings(mixedTypeArray),
         Arrays.asList(
              "true",
              "0",
              "foo",
              JSONArray.EMPTY_ARRAY.toSingleLineString(),
              JSONObject.EMPTY_OBJECT.toSingleLineString()));
  }



  /**
   * Tests the methods for getting a Boolean value from a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetBoolean()
         throws Exception
  {
    // Test with a field whose value is a Boolean true.
    JSONObject o = createMinimalMessageObject(CONNECT, null,
         createField(UNCACHED_DATA_ACCESSED, true));
    JSONAccessLogMessage m = new JSONConnectAccessLogMessage(o);

    assertTrue(m.getBoolean(UNCACHED_DATA_ACCESSED));
    assertTrue(m.getBooleanNoThrow(UNCACHED_DATA_ACCESSED));


    // Test with a field whose value is a Boolean false.
    o = createMinimalMessageObject(CONNECT, null,
         createField(UNCACHED_DATA_ACCESSED, false));
    m = new JSONConnectAccessLogMessage(o);

    assertFalse(m.getBoolean(UNCACHED_DATA_ACCESSED));
    assertFalse(m.getBooleanNoThrow(UNCACHED_DATA_ACCESSED));


    // Test with a field whose value is a string true.
    o = createMinimalMessageObject(CONNECT, null,
         createField(UNCACHED_DATA_ACCESSED, "true"));
    m = new JSONConnectAccessLogMessage(o);

    assertTrue(m.getBoolean(UNCACHED_DATA_ACCESSED));
    assertTrue(m.getBooleanNoThrow(UNCACHED_DATA_ACCESSED));


    // Test with a field whose value is a string false.
    o = createMinimalMessageObject(CONNECT, null,
         createField(UNCACHED_DATA_ACCESSED, "false"));
    m = new JSONConnectAccessLogMessage(o);

    assertFalse(m.getBoolean(UNCACHED_DATA_ACCESSED));
    assertFalse(m.getBooleanNoThrow(UNCACHED_DATA_ACCESSED));


    // Test with a field that is missing.
    o = createMinimalMessageObject(CONNECT, null);
    m = new JSONConnectAccessLogMessage(o);

    assertNull(m.getBoolean(UNCACHED_DATA_ACCESSED));
    assertNull(m.getBooleanNoThrow(UNCACHED_DATA_ACCESSED));


    // Test with a field that has an invalid string value.
    o = createMinimalMessageObject(CONNECT, null,
         createField(UNCACHED_DATA_ACCESSED, "invalid"));
    m = new JSONConnectAccessLogMessage(o);

    try
    {
      m.getBoolean(UNCACHED_DATA_ACCESSED);
      fail("Expected an exception for an invalid string value.");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(m.getBooleanNoThrow(UNCACHED_DATA_ACCESSED));


    // Test with a field that has a non-Boolean/non-string value.
    o = createMinimalMessageObject(CONNECT, null,
         createField(UNCACHED_DATA_ACCESSED, 1234L));
    m = new JSONConnectAccessLogMessage(o);

    try
    {
      m.getBoolean(UNCACHED_DATA_ACCESSED);
      fail("Expected an exception for an invalid value type.");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(m.getBooleanNoThrow(UNCACHED_DATA_ACCESSED));
  }



  /**
   * Tests the methods for getting a generalized time value from a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetGeneralizedTime()
         throws Exception
  {
    // Test with a field whose value is a valid generalized time string.
    final LogField testField = new LogField("test-gt",
         GeneralizedTimeLogFieldSyntax.getInstance());
    JSONObject o = createMinimalMessageObject(CONNECT, null,
         createField(testField,
              StaticUtils.encodeGeneralizedTime(DEFAULT_TIMESTAMP_DATE)));
    JSONAccessLogMessage m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getGeneralizedTime(testField), DEFAULT_TIMESTAMP_DATE);
    assertEquals(m.getGeneralizedTimeNoThrow(testField),
         DEFAULT_TIMESTAMP_DATE);


    // Test with a field that is missing.
    o = createMinimalMessageObject(CONNECT, null);
    m = new JSONConnectAccessLogMessage(o);

    assertNull(m.getGeneralizedTime(testField));
    assertNull(m.getGeneralizedTimeNoThrow(testField));


    // Test with a field that has an invalid string value.
    o = createMinimalMessageObject(CONNECT, null,
         createField(testField, "invalid"));
    m = new JSONConnectAccessLogMessage(o);

    try
    {
      m.getGeneralizedTime(testField);
      fail("Expected an exception for an invalid string value.");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(m.getGeneralizedTimeNoThrow(testField));


    // Test with a field that has a non-string value.
    o = createMinimalMessageObject(CONNECT, null,
         createField(testField, 1234L));
    m = new JSONConnectAccessLogMessage(o);

    try
    {
      m.getGeneralizedTime(testField);
      fail("Expected an exception for an invalid value type.");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(m.getGeneralizedTimeNoThrow(UNCACHED_DATA_ACCESSED));
  }



  /**
   * Tests the methods for getting a Double value from a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetDouble()
         throws Exception
  {
    // Test with a field whose value is a floating-point number
    JSONObject o = createMinimalMessageObject(CONNECT, null,
         createField(PROCESSING_TIME_MILLIS, 1.5d));
    JSONAccessLogMessage m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getDouble(PROCESSING_TIME_MILLIS).doubleValue(), 1.5d);
    assertEquals(m.getDoubleNoThrow(PROCESSING_TIME_MILLIS).doubleValue(),
         1.5d);


    // Test with a field whose value is an integer.
    o = createMinimalMessageObject(CONNECT, null,
         createField(PROCESSING_TIME_MILLIS, 1L));
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getDouble(PROCESSING_TIME_MILLIS).doubleValue(), 1.0d);
    assertEquals(m.getDoubleNoThrow(PROCESSING_TIME_MILLIS).doubleValue(),
         1.0d);


    // Test with a field whose value is a string representation of a
    // floating-point number.
    o = createMinimalMessageObject(CONNECT, null,
         createField(PROCESSING_TIME_MILLIS, "1.5"));
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getDouble(PROCESSING_TIME_MILLIS).doubleValue(), 1.5d);
    assertEquals(m.getDoubleNoThrow(PROCESSING_TIME_MILLIS).doubleValue(),
         1.5d);


    // Test with a field whose value is a string representation of an integer.
    o = createMinimalMessageObject(CONNECT, null,
         createField(PROCESSING_TIME_MILLIS, "1"));
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getDouble(PROCESSING_TIME_MILLIS).doubleValue(), 1.0d);
    assertEquals(m.getDoubleNoThrow(PROCESSING_TIME_MILLIS).doubleValue(),
         1.0d);


    // Test with a field that is missing.
    o = createMinimalMessageObject(CONNECT, null);
    m = new JSONConnectAccessLogMessage(o);

    assertNull(m.getDouble(PROCESSING_TIME_MILLIS));
    assertNull(m.getDoubleNoThrow(PROCESSING_TIME_MILLIS));


    // Test with a field that has an invalid string value.
    o = createMinimalMessageObject(CONNECT, null,
         createField(PROCESSING_TIME_MILLIS, "invalid"));
    m = new JSONConnectAccessLogMessage(o);

    try
    {
      m.getDouble(PROCESSING_TIME_MILLIS);
      fail("Expected an exception for an invalid string value.");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(m.getDoubleNoThrow(PROCESSING_TIME_MILLIS));


    // Test with a field that has a non-numeric/non-string value.
    o = createMinimalMessageObject(CONNECT, null,
         createField(PROCESSING_TIME_MILLIS, true));
    m = new JSONConnectAccessLogMessage(o);

    try
    {
      m.getDouble(PROCESSING_TIME_MILLIS);
      fail("Expected an exception for an invalid value type.");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(m.getDoubleNoThrow(PROCESSING_TIME_MILLIS));
  }



  /**
   * Tests the methods for getting an Integer value from a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetInteger()
         throws Exception
  {
    // Test with a field whose value is a valid positive integer.
    JSONObject o = createMinimalMessageObject(CONNECT, null,
         createField(OPERATION_ID, 1234L));
    JSONAccessLogMessage m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getInteger(OPERATION_ID).intValue(), 1234);
    assertEquals(m.getIntegerNoThrow(OPERATION_ID).intValue(), 1234);


    // Test with a field whose value is a valid negative integer.
    o = createMinimalMessageObject(CONNECT, null,
         createField(OPERATION_ID, -5678L));
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getInteger(OPERATION_ID).intValue(), -5678);
    assertEquals(m.getIntegerNoThrow(OPERATION_ID).intValue(), -5678);


    // Test with a field whose value is a string representation of an
    // integer.
    o = createMinimalMessageObject(CONNECT, null,
         createField(OPERATION_ID, "4321"));
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getInteger(OPERATION_ID).intValue(), 4321);
    assertEquals(m.getIntegerNoThrow(OPERATION_ID).intValue(), 4321);


    // Test with a field that is missing.
    o = createMinimalMessageObject(CONNECT, null);
    m = new JSONConnectAccessLogMessage(o);

    assertNull(m.getInteger(OPERATION_ID));
    assertNull(m.getIntegerNoThrow(OPERATION_ID));


    // Test with a field that has an invalid string value.
    o = createMinimalMessageObject(CONNECT, null,
         createField(OPERATION_ID, "invalid"));
    m = new JSONConnectAccessLogMessage(o);

    try
    {
      m.getInteger(OPERATION_ID);
      fail("Expected an exception for an invalid string value.");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(m.getIntegerNoThrow(OPERATION_ID));


    // Test with a field that has a non-numeric/non-string value.
    o = createMinimalMessageObject(CONNECT, null,
         createField(OPERATION_ID, true));
    m = new JSONConnectAccessLogMessage(o);

    try
    {
      m.getInteger(OPERATION_ID);
      fail("Expected an exception for an invalid value type.");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(m.getIntegerNoThrow(OPERATION_ID));


    // Test with a field that has a numeric value that is out of the valid int
    // range.
    o = createMinimalMessageObject(CONNECT, null,
         createField(OPERATION_ID, Long.MAX_VALUE));
    m = new JSONConnectAccessLogMessage(o);

    try
    {
      m.getInteger(OPERATION_ID);
      fail("Expected an exception for a value that is out of range.");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(m.getIntegerNoThrow(OPERATION_ID));


    // Test with a field that has a string value that is out of the valid int
    // range.
    o = createMinimalMessageObject(CONNECT, null,
         createField(OPERATION_ID, String.valueOf(Long.MIN_VALUE)));
    m = new JSONConnectAccessLogMessage(o);

    try
    {
      m.getInteger(OPERATION_ID);
      fail("Expected an exception for a value that is out of range.");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(m.getIntegerNoThrow(OPERATION_ID));
  }



  /**
   * Tests the methods for getting a Long value from a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetLong()
         throws Exception
  {
    // Test with a field whose value is a valid positive integer.
    JSONObject o = createMinimalMessageObject(CONNECT, null,
         createField(OPERATION_ID, 1234L));
    JSONAccessLogMessage m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getLong(OPERATION_ID).longValue(), 1234);
    assertEquals(m.getLongNoThrow(OPERATION_ID).longValue(), 1234);


    // Test with a field whose value is a valid negative integer.
    o = createMinimalMessageObject(CONNECT, null,
         createField(OPERATION_ID, -5678L));
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getLong(OPERATION_ID).longValue(), -5678);
    assertEquals(m.getLongNoThrow(OPERATION_ID).longValue(), -5678);


    // Test with a field whose value is a string representation of an
    // integer.
    o = createMinimalMessageObject(CONNECT, null,
         createField(OPERATION_ID, "4321"));
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getLong(OPERATION_ID).longValue(), 4321);
    assertEquals(m.getLongNoThrow(OPERATION_ID).longValue(), 4321);


    // Test with a field that is missing.
    o = createMinimalMessageObject(CONNECT, null);
    m = new JSONConnectAccessLogMessage(o);

    assertNull(m.getLong(OPERATION_ID));
    assertNull(m.getLongNoThrow(OPERATION_ID));


    // Test with a field that has an invalid string value.
    o = createMinimalMessageObject(CONNECT, null,
         createField(OPERATION_ID, "invalid"));
    m = new JSONConnectAccessLogMessage(o);

    try
    {
      m.getLong(OPERATION_ID);
      fail("Expected an exception for an invalid string value.");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(m.getLongNoThrow(OPERATION_ID));


    // Test with a field that has a non-numeric/non-string value.
    o = createMinimalMessageObject(CONNECT, null,
         createField(OPERATION_ID, true));
    m = new JSONConnectAccessLogMessage(o);

    try
    {
      m.getLong(OPERATION_ID);
      fail("Expected an exception for an invalid value type.");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(m.getLongNoThrow(OPERATION_ID));


    // Test with a field that has a numeric value that is out of the valid int
    // range but is in the valid long range.
    o = createMinimalMessageObject(CONNECT, null,
         createField(OPERATION_ID, Long.MAX_VALUE));
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getLong(OPERATION_ID).longValue(), Long.MAX_VALUE);
    assertEquals(m.getLongNoThrow(OPERATION_ID).longValue(), Long.MAX_VALUE);


    // Test with a field that has a string value that is out of the valid int
    // range but is in the valid long range.
    o = createMinimalMessageObject(CONNECT, null,
         createField(OPERATION_ID, String.valueOf(Long.MIN_VALUE)));
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getLong(OPERATION_ID).longValue(), Long.MIN_VALUE);
    assertEquals(m.getLongNoThrow(OPERATION_ID).longValue(), Long.MIN_VALUE);


    // Test with a field that has floating-point numeric value.
    o = createMinimalMessageObject(CONNECT, null,
         createField(OPERATION_ID, 1.5d));
    m = new JSONConnectAccessLogMessage(o);


    try
    {
      m.getLong(OPERATION_ID);
      fail("Expected an exception for a floating-point numeric value.");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(m.getLongNoThrow(OPERATION_ID));


    // Test with a field that has floating-point string value.
    o = createMinimalMessageObject(CONNECT, null,
         createField(OPERATION_ID, "1.5"));
    m = new JSONConnectAccessLogMessage(o);


    try
    {
      m.getLong(OPERATION_ID);
      fail("Expected an exception for a floating-point numeric value.");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(m.getLongNoThrow(OPERATION_ID));
  }



  /**
   * Tests the methods for getting an RFC 3339 timestamp value from a JSON
   * object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetRFC3339Timestamp()
         throws Exception
  {
    // Test with a field whose value is a valid generalized time string.
    final LogField testField = new LogField("test-gt",
         RFC3339TimestampLogFieldSyntax.getInstance());
    JSONObject o = createMinimalMessageObject(CONNECT, null,
         createField(testField,
              StaticUtils.encodeRFC3339Time(DEFAULT_TIMESTAMP_DATE)));
    JSONAccessLogMessage m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getRFC3339Timestamp(testField), DEFAULT_TIMESTAMP_DATE);
    assertEquals(m.getRFC3339TimestampNoThrow(testField),
         DEFAULT_TIMESTAMP_DATE);


    // Test with a field that is missing.
    o = createMinimalMessageObject(CONNECT, null);
    m = new JSONConnectAccessLogMessage(o);

    assertNull(m.getRFC3339Timestamp(testField));
    assertNull(m.getRFC3339TimestampNoThrow(testField));


    // Test with a field that has an invalid string value.
    o = createMinimalMessageObject(CONNECT, null,
         createField(testField, "invalid"));
    m = new JSONConnectAccessLogMessage(o);

    try
    {
      m.getRFC3339Timestamp(testField);
      fail("Expected an exception for an invalid string value.");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(m.getRFC3339TimestampNoThrow(testField));


    // Test with a field that has a non-string value.
    o = createMinimalMessageObject(CONNECT, null,
         createField(testField, 1234L));
    m = new JSONConnectAccessLogMessage(o);

    try
    {
      m.getRFC3339Timestamp(testField);
      fail("Expected an exception for an invalid value type.");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(m.getRFC3339TimestampNoThrow(UNCACHED_DATA_ACCESSED));
  }



  /**
   * Tests the methods for getting a string value from a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetString()
         throws Exception
  {
    // Test with a field whose value is a valid string.
    JSONObject o = createMinimalMessageObject(CONNECT, null,
         createField(CONNECT_FROM_ADDRESS, "1.2.3.4"));
    JSONAccessLogMessage m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getString(CONNECT_FROM_ADDRESS), "1.2.3.4");


    // Test with a field whose value is a Boolean.
    o = createMinimalMessageObject(CONNECT, null,
         createField(UNCACHED_DATA_ACCESSED, true));
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getString(UNCACHED_DATA_ACCESSED), "true");


    // Test with a field whose value is a number.
    o = createMinimalMessageObject(CONNECT, null,
         createField(OPERATION_ID, 1L));
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getString(OPERATION_ID), "1");


    // Test with a missing field.
    o = createMinimalMessageObject(CONNECT, null);
    m = new JSONConnectAccessLogMessage(o);

    assertNull(m.getString(CONNECT_FROM_ADDRESS));
  }



  /**
   * Tests the methods for getting a string list from a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetStringList()
         throws Exception
  {
    // Test with a field whose value is an array of strings.
    JSONObject o = createMinimalMessageObject(CONNECT, null,
         createField(REQUEST_CONTROL_OIDS, "1.2.3.4", "5.6.7.8"));
    JSONAccessLogMessage m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getStringList(REQUEST_CONTROL_OIDS),
         Arrays.asList("1.2.3.4", "5.6.7.8"));


    // Test with a field whose value is a single string.
    o = createMinimalMessageObject(CONNECT, null,
         createField(REQUEST_CONTROL_OIDS, "1.2.3.4"));
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getStringList(REQUEST_CONTROL_OIDS),
         Collections.singletonList("1.2.3.4"));


    // Test with a field whose value is a single number.
    o = createMinimalMessageObject(CONNECT, null,
         createField(OPERATION_ID, 1L));
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getStringList(OPERATION_ID),
         Collections.emptyList());


    // Test with a field whose value is an array of non-strings.
    final LogField testField = new LogField("testField",
         new StringLogFieldSyntax(100));
    o = createMinimalMessageObject(CONNECT, null,
         new JSONField(testField.getFieldName(), new JSONArray(
              JSONBoolean.TRUE,
              new JSONNumber("1234"))));
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getStringList(testField),
         Collections.emptyList());


    // Test with a nonexistent field.
    o = createMinimalMessageObject(CONNECT, null);
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getStringList(REQUEST_CONTROL_OIDS),
         Collections.emptyList());
  }



  /**
   * Tests the methods for getting a string list from a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetStringSet()
         throws Exception
  {
    // Test with a field whose value is an array of strings.
    JSONObject o = createMinimalMessageObject(CONNECT, null,
         createField(REQUEST_CONTROL_OIDS, "1.2.3.4", "5.6.7.8"));
    JSONAccessLogMessage m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getStringSet(REQUEST_CONTROL_OIDS),
         StaticUtils.setOf("1.2.3.4", "5.6.7.8"));


    // Test with a field whose value is a single string.
    o = createMinimalMessageObject(CONNECT, null,
         createField(REQUEST_CONTROL_OIDS, "1.2.3.4"));
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getStringSet(REQUEST_CONTROL_OIDS),
         Collections.singleton("1.2.3.4"));


    // Test with a field whose value is a single number.
    o = createMinimalMessageObject(CONNECT, null,
         createField(OPERATION_ID, 1L));
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getStringSet(OPERATION_ID),
         Collections.emptySet());


    // Test with a field whose value is an array of non-strings.
    final LogField testField = new LogField("testField",
         new StringLogFieldSyntax(100));
    o = createMinimalMessageObject(CONNECT, null,
         new JSONField(testField.getFieldName(), new JSONArray(
              JSONBoolean.TRUE,
              new JSONNumber("1234"))));
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getStringSet(testField),
         Collections.emptySet());


    // Test with a nonexistent field.
    o = createMinimalMessageObject(CONNECT, null);
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getStringSet(REQUEST_CONTROL_OIDS),
         Collections.emptySet());
  }



  /**
   * Tests the methods for retrieving the first value for a given field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetFirstValue()
         throws Exception
  {
    // Test with a field whose value is a single string.
    JSONObject o = createMinimalMessageObject(CONNECT, null,
         createField(CONNECT_FROM_ADDRESS, "1.2.3.4"));
    JSONAccessLogMessage m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getFirstValue(CONNECT_FROM_ADDRESS),
         new JSONString("1.2.3.4"));


    // Test with a field whose value is a single Boolean.
    o = createMinimalMessageObject(CONNECT, null,
         createField(UNCACHED_DATA_ACCESSED, true));
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getFirstValue(UNCACHED_DATA_ACCESSED),
         JSONBoolean.TRUE);


    // Test with a field whose value is a non-empty array of strings.
    o = createMinimalMessageObject(CONNECT, null,
         createField(REQUEST_CONTROL_OIDS, "1.2.3.4", "5.6.7.8"));
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getFirstValue(REQUEST_CONTROL_OIDS),
         new JSONString("1.2.3.4"));


    // Test with a field whose value is a non-empty array of non-strings.
    final LogField testField =
         new LogField("testField", IntegerLogFieldSyntax.getInstance());
    o = createMinimalMessageObject(CONNECT, null,
         new JSONField("testField", new JSONArray(
              new JSONNumber(1L),
              new JSONNumber(2L),
              new JSONNumber(3L),
              new JSONNumber(4L))));
    m = new JSONConnectAccessLogMessage(o);

    assertEquals(m.getFirstValue(testField),
         new JSONNumber(1L));


    // Test with a field whose value is an empty array.
    o = createMinimalMessageObject(CONNECT, null,
         createField(REQUEST_CONTROL_OIDS));
    m = new JSONConnectAccessLogMessage(o);

    assertNull(m.getFirstValue(REQUEST_CONTROL_OIDS));
  }
}
