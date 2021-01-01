/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.util.json;



import java.io.ByteArrayOutputStream;
import java.math.BigDecimal;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.StaticUtils;



/**
 * This class provides test coverage for the {@code JSONBuffer} test.
 */
public final class JSONBufferTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when constructing an empty JSON object with single-line
   * formatting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyObjectSingleLine()
         throws Exception
  {
    final JSONBuffer buffer = new JSONBuffer();

    buffer.beginObject();
    buffer.endObject();

    assertEquals(buffer.length(), 3);

    assertNotNull(buffer.getBuffer());

    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    buffer.writeTo(outputStream);
    assertEquals(outputStream.toByteArray(),
         "{ }".getBytes("UTF-8"));

    assertEquals(buffer.toString(), "{ }");
    assertEquals(buffer.toJSONObject(), JSONObject.EMPTY_OBJECT);

    buffer.clear();
    assertEquals(buffer.length(), 0);

    assertEquals(buffer.toString(), "");
  }



  /**
   * Tests the behavior when constructing an empty JSON object with multi-line
   * formatting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyObjectMultiLine()
         throws Exception
  {
    final ByteStringBuffer bsb = new ByteStringBuffer();
    final JSONBuffer buffer = new JSONBuffer(bsb, 12345678, true);

    buffer.beginObject();
    buffer.endObject();

    assertEquals(buffer.length(), 3);

    assertNotNull(buffer.getBuffer());
    assertSame(buffer.getBuffer(), bsb);
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    buffer.writeTo(outputStream);
    assertEquals(outputStream.toByteArray(),
         "{ }".getBytes("UTF-8"));

    assertEquals(buffer.toString(), "{ }");
    assertEquals(buffer.toJSONObject(), JSONObject.EMPTY_OBJECT);

    buffer.clear();
    assertEquals(buffer.length(), 0);

    assertEquals(buffer.toString(), "");
  }



  /**
   * Tests the behavior when constructing a simple JSON object with single-line
   * formatting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimpleObjectSingleLine()
         throws Exception
  {
    final JSONBuffer buffer = new JSONBuffer();

    buffer.beginObject();

    buffer.appendBoolean("trueValue", true);
    buffer.appendBoolean("falseValue", false);
    buffer.appendValue("jsonBooleanValue", new JSONBoolean(true));

    buffer.appendNull("nullValue");
    buffer.appendValue("jsonNullValue", JSONNull.NULL);

    buffer.appendNumber("intValue", 123);
    buffer.appendNumber("longValue", 456L);
    buffer.appendNumber("stringNumberValue", "123.456");
    buffer.appendNumber("bigDecimalNumberValue", new BigDecimal("456.789"));
    buffer.appendValue("jsonNumberValue", new JSONNumber(9876));

    buffer.appendString("stringValue", "abcdefg");
    buffer.appendValue("jsonStringValue", new JSONString("gfedcba"));

    buffer.endObject();

    final String expected = "{ \"trueValue\":true, \"falseValue\":false, " +
         "\"jsonBooleanValue\":true, \"nullValue\":null, " +
         "\"jsonNullValue\":null, \"intValue\":123, \"longValue\":456, " +
         "\"stringNumberValue\":123.456, \"bigDecimalNumberValue\":456.789, " +
         "\"jsonNumberValue\":9876, \"stringValue\":\"abcdefg\", " +
         "\"jsonStringValue\":\"gfedcba\" }";
    assertEquals(buffer.toString(), expected);

    assertEquals(buffer.length(), expected.length());

    assertNotNull(buffer.getBuffer());

    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    buffer.writeTo(outputStream);
    assertEquals(outputStream.toByteArray(),
         expected.getBytes("UTF-8"));

    assertEquals(buffer.toJSONObject(),
         new JSONObject(
              new JSONField("trueValue", true),
              new JSONField("falseValue", false),
              new JSONField("jsonBooleanValue", true),
              new JSONField("nullValue", JSONNull.NULL),
              new JSONField("jsonNullValue", JSONNull.NULL),
              new JSONField("intValue", 123),
              new JSONField("longValue", 456L),
              new JSONField("stringNumberValue", new JSONNumber("123.456")),
              new JSONField("bigDecimalNumberValue", new JSONNumber("456.789")),
              new JSONField("jsonNumberValue", new JSONNumber(9876)),
              new JSONField("stringValue", "abcdefg"),
              new JSONField("jsonStringValue", "gfedcba")));

    buffer.clear();
    assertEquals(buffer.length(), 0);

    assertEquals(buffer.toString(), "");
  }



  /**
   * Tests the behavior when constructing a simple JSON object with multi-line
   * formatting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimpleObjectMultiLine()
         throws Exception
  {
    final ByteStringBuffer bsb = new ByteStringBuffer();
    final JSONBuffer buffer = new JSONBuffer(bsb, 12345678, true);

    buffer.beginObject();

    buffer.appendBoolean("trueValue", true);
    buffer.appendBoolean("falseValue", false);
    buffer.appendValue("jsonBooleanValue", new JSONBoolean(true));

    buffer.appendNull("nullValue");
    buffer.appendValue("jsonNullValue", JSONNull.NULL);

    buffer.appendNumber("intValue", 123);
    buffer.appendNumber("longValue", 456L);
    buffer.appendNumber("stringNumberValue", "123.456");
    buffer.appendNumber("bigDecimalNumberValue", new BigDecimal("456.789"));
    buffer.appendValue("jsonNumberValue", new JSONNumber(9876));

    buffer.appendString("stringValue", "abcdefg");
    buffer.appendValue("jsonStringValue", new JSONString("gfedcba"));

    buffer.endObject();

    final String expected =
         "{ \"trueValue\":true," + StaticUtils.EOL +
         "  \"falseValue\":false," + StaticUtils.EOL +
         "  \"jsonBooleanValue\":true," + StaticUtils.EOL +
         "  \"nullValue\":null," + StaticUtils.EOL +
         "  \"jsonNullValue\":null," + StaticUtils.EOL +
         "  \"intValue\":123," + StaticUtils.EOL +
         "  \"longValue\":456," + StaticUtils.EOL +
         "  \"stringNumberValue\":123.456," + StaticUtils.EOL +
         "  \"bigDecimalNumberValue\":456.789," + StaticUtils.EOL +
         "  \"jsonNumberValue\":9876," + StaticUtils.EOL +
         "  \"stringValue\":\"abcdefg\"," + StaticUtils.EOL +
         "  \"jsonStringValue\":\"gfedcba\" }";
    assertEquals(buffer.toString(), expected);

    assertEquals(buffer.length(), expected.length());

    assertNotNull(buffer.getBuffer());
    assertSame(buffer.getBuffer(), bsb);

    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    buffer.writeTo(outputStream);
    assertEquals(outputStream.toByteArray(),
         expected.getBytes("UTF-8"));

    assertEquals(buffer.toJSONObject(),
         new JSONObject(
              new JSONField("trueValue", true),
              new JSONField("falseValue", false),
              new JSONField("jsonBooleanValue", true),
              new JSONField("nullValue", JSONNull.NULL),
              new JSONField("jsonNullValue", JSONNull.NULL),
              new JSONField("intValue", 123),
              new JSONField("longValue", 456L),
              new JSONField("stringNumberValue", new JSONNumber("123.456")),
              new JSONField("bigDecimalNumberValue", new JSONNumber("456.789")),
              new JSONField("jsonNumberValue", new JSONNumber(9876)),
              new JSONField("stringValue", "abcdefg"),
              new JSONField("jsonStringValue", "gfedcba")));

    buffer.clear();
    assertEquals(buffer.length(), 0);

    assertEquals(buffer.toString(), "");
  }



  /**
   * Tests the behavior when constructing a simple JSON object with single-line
   * formatting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultiLevelObjectSingleLine()
         throws Exception
  {
    final JSONBuffer buffer = new JSONBuffer();

    buffer.setBuffer(null);

    final ByteStringBuffer bsb = new ByteStringBuffer();
    buffer.setBuffer(bsb);

    buffer.beginObject();

    buffer.appendBoolean("trueValue", true);
    buffer.appendBoolean("falseValue", false);

    buffer.appendNull("nullValue");

    buffer.appendNumber("intValue", 123);
    buffer.appendNumber("longValue", 456L);
    buffer.appendNumber("stringNumberValue", "123.456");

    buffer.appendString("stringValue", "abcdefg");

    buffer.beginArray("arrayValue");

    buffer.appendBoolean(true);
    buffer.appendBoolean(false);

    buffer.appendNull();

    buffer.appendNumber(-987);
    buffer.appendNumber(-654L);
    buffer.appendNumber("-987.654");
    buffer.appendNumber(new BigDecimal("-654.321"));
    buffer.appendValue(new JSONNumber("-321"));

    buffer.appendString("hijklmnop");

    buffer.beginObject();
    buffer.appendString("foo", "bar");

    buffer.beginArray("nestedArray");
    buffer.appendString("abc");
    buffer.appendString("def");
    buffer.beginArray();
    buffer.appendString("ghi");
    buffer.appendString("jkl");
    buffer.endArray();
    buffer.endArray();

    buffer.endObject();

    buffer.endArray();

    buffer.beginObject("testObject");
    buffer.appendString("ghi", "jkl");
    buffer.endObject();

    buffer.endObject();

    final String expected = "{ \"trueValue\":true, \"falseValue\":false, " +
         "\"nullValue\":null, \"intValue\":123, \"longValue\":456, " +
         "\"stringNumberValue\":123.456, \"stringValue\":\"abcdefg\", " +
         "\"arrayValue\":[ true, false, null, -987, -654, -987.654, " +
         "-654.321, -321, \"hijklmnop\", { \"foo\":\"bar\", " +
         "\"nestedArray\":[ \"abc\", \"def\", [ \"ghi\", \"jkl\" ] ] } ], " +
         "\"testObject\":{ \"ghi\":\"jkl\" } }";
    assertEquals(buffer.toString(), expected);

    assertEquals(buffer.length(), expected.length());

    assertNotNull(buffer.getBuffer());
    assertSame(buffer.getBuffer(), bsb);

    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    buffer.writeTo(outputStream);
    assertEquals(outputStream.toByteArray(),
         expected.getBytes("UTF-8"));

    assertEquals(buffer.toJSONObject(),
         new JSONObject(
              new JSONField("trueValue", true),
              new JSONField("falseValue", false),
              new JSONField("nullValue", JSONNull.NULL),
              new JSONField("intValue", 123),
              new JSONField("longValue", 456L),
              new JSONField("stringNumberValue", new JSONNumber("123.456")),
              new JSONField("stringValue", "abcdefg"),
              new JSONField("arrayValue", new JSONArray(
                   JSONBoolean.TRUE,
                   JSONBoolean.FALSE,
                   JSONNull.NULL,
                   new JSONNumber(-987),
                   new JSONNumber(-654L),
                   new JSONNumber("-987.654"),
                   new JSONNumber("-654.321"),
                   new JSONNumber("-321"),
                   new JSONString("hijklmnop"),
                   new JSONObject(
                        new JSONField("foo", "bar"),
                        new JSONField("nestedArray", new JSONArray(
                             new JSONString("abc"),
                             new JSONString("def"),
                             new JSONArray(
                                  new JSONString("ghi"),
                                  new JSONString("jkl"))))))),
              new JSONField("testObject", new JSONObject(
                   new JSONField("ghi", "jkl")))));

    buffer.clear();
    assertEquals(buffer.length(), 0);

    assertEquals(buffer.toString(), "");
  }



  /**
   * Tests the behavior when constructing a simple JSON object with multi-line
   * formatting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultiLevelObjectMultiLine()
         throws Exception
  {
    final ByteStringBuffer bsb = new ByteStringBuffer();
    final JSONBuffer buffer = new JSONBuffer(bsb, 10, true);

    buffer.beginObject();

    buffer.appendBoolean("trueValue", true);
    buffer.appendBoolean("falseValue", false);

    buffer.appendNull("nullValue");

    buffer.appendNumber("intValue", 123);
    buffer.appendNumber("longValue", 456L);
    buffer.appendNumber("stringNumberValue", "123.456");

    buffer.appendString("stringValue", "abcdefg");

    buffer.beginArray("arrayValue");

    buffer.appendBoolean(true);
    buffer.appendBoolean(false);

    buffer.appendNull();

    buffer.appendNumber(-987);
    buffer.appendNumber(-654L);
    buffer.appendNumber("-987.654");

    buffer.appendString("hijklmnop");

    buffer.beginObject();
    buffer.appendString("foo", "bar");

    buffer.beginArray("nestedArray");
    buffer.appendString("abc");
    buffer.appendString("def");
    buffer.beginArray();
    buffer.appendString("ghi");
    buffer.appendString("jkl");
    buffer.endArray();
    buffer.endArray();

    buffer.endObject();

    buffer.endArray();

    buffer.beginObject("testObject");
    buffer.appendString("ghi", "jkl");
    buffer.endObject();

    buffer.endObject();

    final String expected =
         "{ \"trueValue\":true," + StaticUtils.EOL +
         "  \"falseValue\":false," + StaticUtils.EOL +
         "  \"nullValue\":null," + StaticUtils.EOL +
         "  \"intValue\":123," + StaticUtils.EOL +
         "  \"longValue\":456," + StaticUtils.EOL +
         "  \"stringNumberValue\":123.456," + StaticUtils.EOL +
         "  \"stringValue\":\"abcdefg\"," + StaticUtils.EOL +
         "  \"arrayValue\":[ true," + StaticUtils.EOL +
         "                 false," + StaticUtils.EOL +
         "                 null," + StaticUtils.EOL +
         "                 -987," + StaticUtils.EOL +
         "                 -654," + StaticUtils.EOL +
         "                 -987.654," + StaticUtils.EOL +
         "                 \"hijklmnop\"," + StaticUtils.EOL +
         "                 { \"foo\":\"bar\"," + StaticUtils.EOL +
         "                   \"nestedArray\":[ \"abc\"," + StaticUtils.EOL +
         "                                   \"def\"," + StaticUtils.EOL +
         "                                   [ \"ghi\"," + StaticUtils.EOL +
         "                                     \"jkl\" ] ] } ]," +
              StaticUtils.EOL +
         "  \"testObject\":{ \"ghi\":\"jkl\" } }";
    assertEquals(buffer.toString(), expected);

    assertEquals(buffer.length(), expected.length());

    assertNotNull(buffer.getBuffer());
    assertSame(buffer.getBuffer(), bsb);

    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    buffer.writeTo(outputStream);
    assertEquals(outputStream.toByteArray(),
         expected.getBytes("UTF-8"));

    assertEquals(buffer.toJSONObject(),
         new JSONObject(
              new JSONField("trueValue", true),
              new JSONField("falseValue", false),
              new JSONField("nullValue", JSONNull.NULL),
              new JSONField("intValue", 123),
              new JSONField("longValue", 456L),
              new JSONField("stringNumberValue", new JSONNumber("123.456")),
              new JSONField("stringValue", "abcdefg"),
              new JSONField("arrayValue", new JSONArray(
                   JSONBoolean.TRUE,
                   JSONBoolean.FALSE,
                   JSONNull.NULL,
                   new JSONNumber(-987),
                   new JSONNumber(-654L),
                   new JSONNumber("-987.654"),
                   new JSONString("hijklmnop"),
                   new JSONObject(
                        new JSONField("foo", "bar"),
                        new JSONField("nestedArray", new JSONArray(
                             new JSONString("abc"),
                             new JSONString("def"),
                             new JSONArray(
                                  new JSONString("ghi"),
                                  new JSONString("jkl"))))))),
              new JSONField("testObject", new JSONObject(
                   new JSONField("ghi", "jkl")))));

    buffer.clear();
    assertEquals(buffer.length(), 0);

    assertEquals(buffer.toString(), "");
  }
}
