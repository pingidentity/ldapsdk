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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.text;



import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.unboundidds.logs.LogException;
import com.unboundid.util.StaticUtils;

import static com.unboundid.ldap.sdk.unboundidds.logs.AccessLogMessageType.*;
import static com.unboundid.ldap.sdk.unboundidds.logs.v2.text.
                   TextFormattedAccessLogFields.*;



/**
 * This class provides a set of test cases for text-formatted log messages.
 */
public final class TextFormattedLogMessageTestCase
       extends TextFormattedLogsTestCase
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
    final StringBuilder buffer = createLogMessage(true, CONNECT, null, true);

    final TextFormattedConnectAccessLogMessage logMessage =
         new TextFormattedConnectAccessLogMessage(buffer.toString());

    assertNotNull(logMessage.getTimestamp());
    assertEquals(logMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);

    assertNotNull(logMessage.getFields());
    assertFalse(logMessage.getFields().isEmpty());

    assertNotNull(logMessage.toString());
  }



  /**
   * Tests the behavior with a timestamp with seconds precision rather than
   * milliseconds.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTimestampSecondPrecision()
         throws Exception
  {
    final StringBuilder buffer = createLogMessage(false, CONNECT, null, true);

    final TextFormattedConnectAccessLogMessage logMessage =
         new TextFormattedConnectAccessLogMessage(buffer.toString());

    assertNotNull(logMessage.getTimestamp());

    final long decodedTime = logMessage.getTimestamp().getTime();
    final long expectedTime = DEFAULT_TIMESTAMP_DATE.getTime();
    final long differenceMillis = Math.abs(expectedTime - decodedTime);
    assertTrue(differenceMillis < 1_000L);
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
    final String messageString = "CONNECT conn=" + DEFAULT_CONNECTION_ID;

    try
    {
      new TextFormattedLogMessage(messageString);
      fail("Expected an exception when trying to create a log message " +
           "without a timestamp");
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
    final String messageString =
         "[malformed] CONNECT conn=" + DEFAULT_CONNECTION_ID;

    try
    {
      new TextFormattedLogMessage(messageString);
      fail("Expected an exception when trying to create a log message with a " +
           "malformed timestamp");
    }
    catch (final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the methods for getting a Boolean value from a log field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetBoolean()
         throws Exception
  {
    // Create a message with a range of fields.
    final StringBuilder buffer = createLogMessage(true, CONNECT, null, false);
    appendField(buffer, CONNECTION_ID, DEFAULT_CONNECTION_ID);
    appendField(buffer, LOCAL_ASSURANCE_SATISFIED, true);
    appendField(buffer, REMOTE_ASSURANCE_SATISFIED, false);
    appendField(buffer, DIAGNOSTIC_MESSAGE, "true");
    appendField(buffer, ADDITIONAL_INFO, "false");

    final TextFormattedLogMessage logMessage =
         new TextFormattedLogMessage(buffer.toString());


    // Test with fields whose values are Booleans.
    assertTrue(logMessage.getBoolean(LOCAL_ASSURANCE_SATISFIED));
    assertFalse(logMessage.getBoolean(REMOTE_ASSURANCE_SATISFIED));

    assertTrue(logMessage.getBooleanNoThrow(LOCAL_ASSURANCE_SATISFIED));
    assertFalse(logMessage.getBooleanNoThrow(REMOTE_ASSURANCE_SATISFIED));


    // Test with fields whose values are strings that can be parsed as Booleans.
    assertTrue(logMessage.getBoolean(DIAGNOSTIC_MESSAGE));
    assertFalse(logMessage.getBooleanNoThrow(ADDITIONAL_INFO));

    assertTrue(logMessage.getBoolean(DIAGNOSTIC_MESSAGE));
    assertFalse(logMessage.getBooleanNoThrow(ADDITIONAL_INFO));


    // Test with a field that cannot be parsed as a Boolean.
    try
    {
      logMessage.getBoolean(CONNECTION_ID);
      fail("Expected an exception when trying to get a Boolean value for a " +
           "non-Boolean field.");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(logMessage.getBooleanNoThrow(CONNECTION_ID));


    // Test with a field that does not exist.
    assertNull(logMessage.getBoolean(UNCACHED_DATA_ACCESSED));
    assertNull(logMessage.getBooleanNoThrow(UNCACHED_DATA_ACCESSED));
  }



  /**
   * Tests the methods for getting a generalized time value from a log field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetGeneralizedTime()
         throws Exception
  {
    // Create a message with a range of fields.
    final StringBuilder buffer = createLogMessage(true, CONNECT, null, false);
    appendField(buffer, CONNECTION_ID, DEFAULT_CONNECTION_ID);
    appendField(buffer, DIAGNOSTIC_MESSAGE,
         StaticUtils.encodeGeneralizedTime(DEFAULT_TIMESTAMP_DATE));
    appendField(buffer, ADDITIONAL_INFO, "malformed");

    final TextFormattedLogMessage logMessage =
         new TextFormattedLogMessage(buffer.toString());


    // Test with a field containing a valid generalized time value.
    assertEquals(logMessage.getGeneralizedTime(DIAGNOSTIC_MESSAGE),
         DEFAULT_TIMESTAMP_DATE);

    assertEquals(logMessage.getGeneralizedTimeNoThrow(DIAGNOSTIC_MESSAGE),
         DEFAULT_TIMESTAMP_DATE);


    // Test with a field containing a malformed generalized time.
    try
    {
      logMessage.getGeneralizedTime(ADDITIONAL_INFO);
      fail("Expected an exception when trying to parse a malformed " +
           "generalized time value");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(logMessage.getGeneralizedTimeNoThrow(ADDITIONAL_INFO));


    // Test with a missing field.
    assertNull(logMessage.getGeneralizedTime(ADMINISTRATIVE_OPERATION));
    assertNull(logMessage.getGeneralizedTimeNoThrow(ADMINISTRATIVE_OPERATION));
  }



  /**
   * Tests the methods for getting floating-point values from a log field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetDouble()
         throws Exception
  {
    // Create a message with a range of fields.
    final StringBuilder buffer = createLogMessage(true, CONNECT, null, false);
    appendField(buffer, CONNECTION_ID, 1L);
    appendField(buffer, PROCESSING_TIME_MILLIS, 2.5d);
    appendField(buffer, DIAGNOSTIC_MESSAGE, "3.5");
    appendField(buffer, ADDITIONAL_INFO, "malformed");

    final TextFormattedLogMessage logMessage =
         new TextFormattedLogMessage(buffer.toString());


    // Test with a field containing a valid floating-point value provided as a
    // double.
    assertEquals(logMessage.getDouble(PROCESSING_TIME_MILLIS).doubleValue(),
         2.5d);

    assertEquals(
         logMessage.getDoubleNoThrow(PROCESSING_TIME_MILLIS).doubleValue(),
         2.5d);


    // Test with a field containing a valid floating-point value provided as a
    // string.
    assertEquals(logMessage.getDouble(DIAGNOSTIC_MESSAGE).doubleValue(),
         3.5d);

    assertEquals(
         logMessage.getDoubleNoThrow(DIAGNOSTIC_MESSAGE).doubleValue(),
         3.5d);


    // Test with a field containing an integer value.
    assertEquals(logMessage.getDouble(CONNECTION_ID).doubleValue(),
         1.0d);

    assertEquals(
         logMessage.getDoubleNoThrow(CONNECTION_ID).doubleValue(),
         1.0d);


    // Test with a field containing a malformed value.
    try
    {
      logMessage.getDouble(ADDITIONAL_INFO);
      fail("Expected an exception when trying to parse a malformed " +
           "floating-point value");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(logMessage.getDoubleNoThrow(ADDITIONAL_INFO));


    // Test with a missing field.
    assertNull(logMessage.getDouble(ADMINISTRATIVE_OPERATION));
    assertNull(logMessage.getDoubleNoThrow(ADMINISTRATIVE_OPERATION));
  }



  /**
   * Tests the methods for getting integer values from a log field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetIntegerAndLong()
         throws Exception
  {
    // Create a message with a range of fields.
    final StringBuilder buffer = createLogMessage(true, CONNECT, null, false);
    appendField(buffer, CONNECTION_ID, 1L);
    appendField(buffer, DIAGNOSTIC_MESSAGE, "2");
    appendField(buffer, ADDITIONAL_INFO, "malformed");

    final TextFormattedLogMessage logMessage =
         new TextFormattedLogMessage(buffer.toString());


    // Tests with a field containing a valid integer provided as a long.
    assertEquals(logMessage.getInteger(CONNECTION_ID).intValue(), 1);
    assertEquals(logMessage.getIntegerNoThrow(CONNECTION_ID).intValue(), 1);

    assertEquals(logMessage.getLong(CONNECTION_ID).longValue(), 1L);
    assertEquals(logMessage.getLongNoThrow(CONNECTION_ID).longValue(), 1L);


    // Tests with a field containing a valid integer provided as a string.
    assertEquals(logMessage.getInteger(DIAGNOSTIC_MESSAGE).intValue(), 2);
    assertEquals(logMessage.getIntegerNoThrow(DIAGNOSTIC_MESSAGE).intValue(),
         2);

    assertEquals(logMessage.getLong(DIAGNOSTIC_MESSAGE).longValue(), 2L);
    assertEquals(logMessage.getLongNoThrow(DIAGNOSTIC_MESSAGE).longValue(), 2L);


    // Test with a field containing a malformed value.
    try
    {
      logMessage.getInteger(ADDITIONAL_INFO);
      fail("Expected an exception when trying to parse a malformed integer " +
           "value");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(logMessage.getIntegerNoThrow(ADDITIONAL_INFO));

    try
    {
      logMessage.getLong(ADDITIONAL_INFO);
      fail("Expected an exception when trying to parse a malformed integer " +
           "value");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(logMessage.getLongNoThrow(ADDITIONAL_INFO));


    // Test with a missing field.
    assertNull(logMessage.getInteger(ADMINISTRATIVE_OPERATION));
    assertNull(logMessage.getIntegerNoThrow(ADMINISTRATIVE_OPERATION));

    assertNull(logMessage.getLong(ADMINISTRATIVE_OPERATION));
    assertNull(logMessage.getLongNoThrow(ADMINISTRATIVE_OPERATION));
  }



  /**
   * Tests the methods for getting an RFC 3339 timestamp value from a log field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetRFC3339Timestamp()
         throws Exception
  {
    // Create a message with a range of fields.
    final StringBuilder buffer = createLogMessage(true, CONNECT, null, false);
    appendField(buffer, CONNECTION_ID, DEFAULT_CONNECTION_ID);
    appendField(buffer, DIAGNOSTIC_MESSAGE,
         StaticUtils.encodeRFC3339Time(DEFAULT_TIMESTAMP_DATE));
    appendField(buffer, ADDITIONAL_INFO, "malformed");

    final TextFormattedLogMessage logMessage =
         new TextFormattedLogMessage(buffer.toString());


    // Test with a field containing a valid RFC 3339 timestamp value.
    assertEquals(logMessage.getRFC3339Timestamp(DIAGNOSTIC_MESSAGE),
         DEFAULT_TIMESTAMP_DATE);

    assertEquals(logMessage.getRFC3339TimestampNoThrow(DIAGNOSTIC_MESSAGE),
         DEFAULT_TIMESTAMP_DATE);


    // Test with a field containing a malformed RFC 3339 timestamp value.
    try
    {
      logMessage.getRFC3339Timestamp(ADDITIONAL_INFO);
      fail("Expected an exception when trying to parse a malformed " +
           "generalized time value");
    }
    catch (final LogException e)
    {
      // This was expected.
    }

    assertNull(logMessage.getRFC3339TimestampNoThrow(ADDITIONAL_INFO));


    // Test with a missing field.
    assertNull(logMessage.getRFC3339Timestamp(ADMINISTRATIVE_OPERATION));
    assertNull(logMessage.getRFC3339TimestampNoThrow(ADMINISTRATIVE_OPERATION));
  }



  /**
   * Tests the methods for getting a comma-delimited string list from a field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetCommaDelimitedStringList()
         throws Exception
  {
    // Create a message with a range of fields.
    final StringBuilder buffer = createLogMessage(true, CONNECT, null, false);
    appendField(buffer, CONNECTION_ID, DEFAULT_CONNECTION_ID);
    appendField(buffer, DIAGNOSTIC_MESSAGE, "a,b,c");
    appendField(buffer, ADDITIONAL_INFO, "d");
    appendField(buffer, OPERATION_PURPOSE, "");

    final TextFormattedLogMessage logMessage =
         new TextFormattedLogMessage(buffer.toString());


    // Test with a field containing multiple values.
    assertEquals(logMessage.getCommaDelimitedStringList(DIAGNOSTIC_MESSAGE),
         Arrays.asList("a", "b", "c"));

    // Test with a field containing a single value.
    assertEquals(logMessage.getCommaDelimitedStringList(ADDITIONAL_INFO),
         Collections.singletonList("d"));

    // Test with a field containing an empty string value..
    assertEquals(logMessage.getCommaDelimitedStringList(OPERATION_PURPOSE),
         Collections.emptyList());

    // Test with a missing field.
    assertEquals(
         logMessage.getCommaDelimitedStringList(ADMINISTRATIVE_OPERATION),
         Collections.emptyList());
  }



  /**
   * Tests the methods for getting a comma-delimited string set from a field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetCommaDelimitedStringSet()
         throws Exception
  {
    // Create a message with a range of fields.
    final StringBuilder buffer = createLogMessage(true, CONNECT, null, false);
    appendField(buffer, CONNECTION_ID, DEFAULT_CONNECTION_ID);
    appendField(buffer, DIAGNOSTIC_MESSAGE, "a,b,c");
    appendField(buffer, ADDITIONAL_INFO, "d");
    appendField(buffer, OPERATION_PURPOSE, "");

    final TextFormattedLogMessage logMessage =
         new TextFormattedLogMessage(buffer.toString());


    // Test with a field containing multiple values.
    assertEquals(logMessage.getCommaDelimitedStringSet(DIAGNOSTIC_MESSAGE),
         StaticUtils.setOf("a", "b", "c"));

    // Test with a field containing a single value.
    assertEquals(logMessage.getCommaDelimitedStringSet(ADDITIONAL_INFO),
         Collections.singleton("d"));

    // Test with a field containing an empty string value..
    assertEquals(logMessage.getCommaDelimitedStringSet(OPERATION_PURPOSE),
         Collections.emptySet());

    // Test with a missing field.
    assertEquals(
         logMessage.getCommaDelimitedStringSet(ADMINISTRATIVE_OPERATION),
         Collections.emptySet());
  }



  /**
   * Tests the behavior for a log message that contains multiple occurrences of
   * the same field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleOccurrences()
         throws Exception
  {
    // Create a message with a range of fields.
    final StringBuilder buffer = createLogMessage(true, CONNECT, null, false);
    appendField(buffer, CONNECTION_ID, DEFAULT_CONNECTION_ID);
    appendField(buffer, DIAGNOSTIC_MESSAGE, "first");
    appendField(buffer, DIAGNOSTIC_MESSAGE, "second");
    appendField(buffer, DIAGNOSTIC_MESSAGE, "third");

    final TextFormattedLogMessage logMessage =
         new TextFormattedLogMessage(buffer.toString());

    final List<String> valueList = logMessage.getFields().get(
         DIAGNOSTIC_MESSAGE.getFieldName());
    assertNotNull(valueList);
    assertEquals(valueList, Arrays.asList("first", "second", "third"));
  }



  /**
   * Tests the behavior for a log field with valid hex-encoded characters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidHexEncodedCharacters()
         throws Exception
  {
    // Create a message with a range of fields.
    final StringBuilder buffer = createLogMessage(true, CONNECT, null, false);
    appendField(buffer, CONNECTION_ID, DEFAULT_CONNECTION_ID);
    appendField(buffer, DIAGNOSTIC_MESSAGE,
         "#40#41#42#43#44#45#46#47#48#49#4A#4B#4C#4D#4E#4F");
    appendField(buffer, ADDITIONAL_INFO,
         "x#40#41#42#43#44#45#46#47#48#49#4a#4b#4c#4d#4e#4fy");

    final TextFormattedLogMessage logMessage =
         new TextFormattedLogMessage(buffer.toString());

    assertNotNull(logMessage.getString(DIAGNOSTIC_MESSAGE));
    assertEquals(logMessage.getString(DIAGNOSTIC_MESSAGE),
         "@ABCDEFGHIJKLMNO");

    assertNotNull(logMessage.getString(ADDITIONAL_INFO));
    assertEquals(logMessage.getString(ADDITIONAL_INFO),
         "x@ABCDEFGHIJKLMNOy");
  }



  /**
   * Tests the behavior for a log field with a value that ends with an
   * octothorpe.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedHexEncodedCharactersEndsWithOctothorpe()
         throws Exception
  {
    // Create a message with a range of fields.
    final StringBuilder buffer = createLogMessage(true, CONNECT, null, false);
    appendField(buffer, CONNECTION_ID, DEFAULT_CONNECTION_ID);
    appendField(buffer, DIAGNOSTIC_MESSAGE, "a#");

    try
    {
      new TextFormattedLogMessage(buffer.toString());
      fail("Expected an exception for a hex character with an octothorpe not " +
           "followed by any other characters.");
    }
    catch (final LogException e)
    {
      // This was expected
    }
  }



  /**
   * Tests the behavior for a log field with a value that ends with an
   * octothorpe and only a single digit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedHexEncodedCharactersEndsWithOctothorpeAndOneDigit()
         throws Exception
  {
    // Create a message with a range of fields.
    final StringBuilder buffer = createLogMessage(true, CONNECT, null, false);
    appendField(buffer, CONNECTION_ID, DEFAULT_CONNECTION_ID);
    appendField(buffer, DIAGNOSTIC_MESSAGE, "a#1");

    try
    {
      new TextFormattedLogMessage(buffer.toString());
      fail("Expected an exception for a hex character with an octothorpe not " +
           "followed by only one other character.");
    }
    catch (final LogException e)
    {
      // This was expected
    }
  }



  /**
   * Tests the behavior for a log field with malformed hex-encoded characters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedHexEncodedCharactersDigitOutOfRange()
         throws Exception
  {
    // Create a message with a range of fields.
    final StringBuilder buffer = createLogMessage(true, CONNECT, null, false);
    appendField(buffer, CONNECTION_ID, DEFAULT_CONNECTION_ID);
    appendField(buffer, DIAGNOSTIC_MESSAGE, "a#1xb");

    try
    {
      new TextFormattedLogMessage(buffer.toString());
      fail("Expected an exception for a hex character with an out-of-range " +
           "digit");
    }
    catch (final LogException e)
    {
      // This was expected
    }
  }
}
