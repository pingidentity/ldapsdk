/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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



import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code JSONObject} class.
 */
public final class JSONObjectTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for JSON object methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicObject()
         throws Exception
  {
    final LinkedHashMap<String,JSONValue> fields =
         new LinkedHashMap<String,JSONValue>(20);
    fields.put("nullField", JSONNull.NULL);
    fields.put("trueField", JSONBoolean.TRUE);
    fields.put("falseField", JSONBoolean.FALSE);
    fields.put("numberField", new JSONNumber(1234));
    fields.put("stringField", new JSONString("This is a string"));
    fields.put("emptyArrayField", new JSONArray());
    fields.put("oneElementArrayField", new JSONArray(new JSONString("foo")));
    fields.put("multiElementArrayField",
         new JSONArray(new JSONString("foo"), new JSONString("bar")));
    fields.put("emptyObjectField",
         new JSONObject(Collections.<String,JSONValue>emptyMap()));

    final LinkedHashMap<String,JSONValue> seFields =
         new LinkedHashMap<String,JSONValue>(1);
    seFields.put("foo", new JSONString("bar"));
    fields.put("oneElementObjectField", new JSONObject(seFields));

    final LinkedHashMap<String,JSONValue> meFields =
         new LinkedHashMap<String,JSONValue>(2);
    meFields.put("a", new JSONNumber(-5678));
    meFields.put("b", new JSONNumber("9.876e3"));
    fields.put("multiElementObjectField", new JSONObject(meFields));

    JSONObject o = new JSONObject(fields);
    o = new JSONObject(o.toString());

    assertNotNull(o.getFields());
    assertEquals(o.getFields(), fields);

    assertNotNull(o.getField("nullField"));
    assertEquals(o.getField("nullField"), new JSONNull());

    assertNull(o.getField("nonexistent"));

    assertNotNull(o.toString());

    assertNotNull(o.toSingleLineString());

    assertNotNull(o.toMultiLineString());

    final StringBuilder toStringBuffer = new StringBuilder();
    o.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), o.toString());

    final StringBuilder toSingleLineStringBuffer = new StringBuilder();
    o.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(), o.toString());

    assertNotNull(o.toNormalizedString());

    final StringBuilder toNormalizedStringBuffer = new StringBuilder();
    o.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(), o.toNormalizedString());

    assertNotNull(o.toNormalizedString(true, true, true));

    assertNotNull(o.toNormalizedString(false, false, false));

    toNormalizedStringBuffer.setLength(0);
    o.toNormalizedString(toNormalizedStringBuffer, true, true, true);
    assertEquals(toNormalizedStringBuffer.toString(),
         o.toNormalizedString(true, true, true));

    toNormalizedStringBuffer.setLength(0);
    o.toNormalizedString(toNormalizedStringBuffer, false, false, false);
    assertEquals(toNormalizedStringBuffer.toString(),
         o.toNormalizedString(false, false, false));

    toNormalizedStringBuffer.setLength(0);
    o.toNormalizedString(toNormalizedStringBuffer, false, true, false);
    assertEquals(toNormalizedStringBuffer.toString(),
         o.toNormalizedString());
  }



  /**
   * Tests the behavior for a JSON object without any fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyObject()
         throws Exception
  {
    final LinkedHashMap<String,JSONValue> nullMap = null;
    final JSONObject o1 = new JSONObject(nullMap);

    assertNotNull(o1.getFields());
    assertTrue(o1.getFields().isEmpty());

    assertNull(o1.getField("nonexistent"));

    assertNotNull(o1.toString());
    assertEquals(o1.toString(), "{ }");

    assertNotNull(o1.toSingleLineString());
    assertEquals(o1.toSingleLineString(), "{ }");

    assertNotNull(o1.toMultiLineString());
    assertEquals(o1.toMultiLineString(), "{ }");

    final StringBuilder toStringBuffer = new StringBuilder();
    o1.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), "{ }");

    final StringBuilder toSingleLineStringBuffer = new StringBuilder();
    o1.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(), "{ }");

    assertNotNull(o1.toNormalizedString());
    assertEquals(o1.toNormalizedString(), "{}");

    final StringBuilder toNormalizedStringBuffer = new StringBuilder();
    o1.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(), "{}");

    assertNotNull(o1.toNormalizedString(true, true, true));

    assertNotNull(o1.toNormalizedString(false, false, false));

    toNormalizedStringBuffer.setLength(0);
    o1.toNormalizedString(toNormalizedStringBuffer, true, true, true);
    assertEquals(toNormalizedStringBuffer.toString(),
         o1.toNormalizedString(true, true, true));

    toNormalizedStringBuffer.setLength(0);
    o1.toNormalizedString(toNormalizedStringBuffer, false, false, false);
    assertEquals(toNormalizedStringBuffer.toString(),
         o1.toNormalizedString(false, false, false));

    toNormalizedStringBuffer.setLength(0);
    o1.toNormalizedString(toNormalizedStringBuffer, false, true, false);
    assertEquals(toNormalizedStringBuffer.toString(),
         o1.toNormalizedString());

    final JSONObject o2 = new JSONObject(o1.toString());
    assertTrue(o1.equals(o2));
    assertEquals(o1.hashCode(), o2.hashCode());
    assertEquals(o1.toNormalizedString(), o2.toNormalizedString());

    final JSONObject o3 = new JSONObject(o1.toNormalizedString());
    assertTrue(o1.equals(o3));
    assertEquals(o1.hashCode(), o3.hashCode());
    assertEquals(o1.toNormalizedString(), o3.toNormalizedString());
  }



  /**
   * Tests the ability to decode a valid string as a JSON object.
   *
   * @param  s  The string to be decoded.
   * @param  o  A JSON object that is equal to the one expected to be decoded.
   * @param  n  The expected normalized string representation of the object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="validObjectStrings")
  public void testDecodeValidStrings(final String s, final JSONObject o,
                                     final String n)
         throws Exception
  {
    final JSONObject decoded = new JSONObject(s);

    assertTrue(decoded.equals(o));
    assertTrue(o.equals(decoded));

    assertEquals(decoded.hashCode(), o.hashCode());

    assertNotNull(o.toNormalizedString());
    assertEquals(o.toNormalizedString(), n);

    assertNotNull(o.toSingleLineString());
    assertNotNull(o.toMultiLineString());

    assertTrue(decoded.equals(o, false, false, false));
    assertTrue(decoded.equals(o, true, false, false));
    assertTrue(decoded.equals(o, false, true, false));
    assertTrue(decoded.equals(o, false, false, true));
    assertTrue(decoded.equals(o, true, true, false));
    assertTrue(decoded.equals(o, true, false, true));
    assertTrue(decoded.equals(o, false, true, true));
    assertTrue(decoded.equals(o, true, true, true));

    assertTrue(o.equals(decoded, false, false, false));
    assertTrue(o.equals(decoded, true, false, false));
    assertTrue(o.equals(decoded, false, true, false));
    assertTrue(o.equals(decoded, false, false, true));
    assertTrue(o.equals(decoded, true, true, false));
    assertTrue(o.equals(decoded, true, false, true));
    assertTrue(o.equals(decoded, false, true, true));
    assertTrue(o.equals(decoded, true, true, true));
  }



  /**
   * Tests the ability to decode an invalid string as a JSON object.
   *
   * @param  s  The string to be decoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="invalidObjectStrings",
        expectedExceptions = { JSONException.class })
  public void testDecodeInvalidStrings(final String s)
         throws Exception
  {
    new JSONObject(s);
  }



  /**
   * Tests the behavior of the {@code equals} method when matched against the
   * same object.
   *
   * @param  s  The string to be decoded.
   * @param  o  A JSON object that is equal to the one expected to be decoded.
   * @param  n  The expected normalized string representation of the object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="validObjectStrings")
  public void testEqualsIdentity(final String s, final JSONObject o,
                                 final String n)
         throws Exception
  {
    assertTrue(o.equals(o));
  }



  /**
   * Tests the behavior of the {@code equals} method when matched against the
   * same object.
   *
   * @param  s  The string to be decoded.
   * @param  o  A JSON object that is equal to the one expected to be decoded.
   * @param  n  The expected normalized string representation of the object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="validObjectStrings")
  public void testEqualsNull(final String s, final JSONObject o,
                             final String n)
         throws Exception
  {
    assertFalse(o.equals(null));

    final JSONObject o2 = null;
    assertFalse(o.equals(o2));
  }



  /**
   * Tests the behavior of the {@code equals} method for an argument that is
   * not a JSON object.
   *
   * @param  s  The string to be decoded.
   * @param  o  A JSON object that is equal to the one expected to be decoded.
   * @param  n  The expected normalized string representation of the object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="validObjectStrings")
  public void testEqualsNotObject(final String s, final JSONObject o,
                                  final String n)
         throws Exception
  {
    assertFalse(o.equals("not a JSON object"));
  }



  /**
   * Tests the behavior of the {@code equals} method with non-equivalent JSON
   * objects.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNonEquivalentObject()
         throws Exception
  {
    final LinkedHashMap<String,JSONValue> m1 =
         new LinkedHashMap<String,JSONValue>(1);
    m1.put("fieldName", JSONBoolean.TRUE);
    final JSONObject o1 = new JSONObject(m1);

    final LinkedHashMap<String,JSONValue> m2 =
         new LinkedHashMap<String,JSONValue>(1);
    m2.put("fieldName", JSONBoolean.FALSE);
    final JSONObject o2 = new JSONObject(m2);

    assertFalse(o1.equals(o2));
    assertFalse(o2.equals(o1));

    assertFalse(o1.equals(o2, false, false, false));
    assertFalse(o2.equals(o1, false, false, false));

    assertFalse(o1.equals(o2, false, true, false));
    assertFalse(o2.equals(o1, false, true, false));

    assertFalse(o1.equals(o2, true, true, true));
    assertFalse(o2.equals(o1, true, true, true));

    final LinkedHashMap<String,JSONValue> m3 =
         new LinkedHashMap<String,JSONValue>(1);
    m3.put("fieldname", JSONBoolean.TRUE);
    final JSONObject o3 = new JSONObject(m3);

    assertFalse(o1.equals(o3));
    assertFalse(o3.equals(o1));

    assertFalse(o1.equals(o3, false, false, false));
    assertFalse(o3.equals(o1, false, false, false));

    assertFalse(o1.equals(o3, false, true, false));
    assertFalse(o3.equals(o1, false, true, false));

    assertTrue(o1.equals(o3, true, true, true));
    assertTrue(o3.equals(o1, true, true, true));
  }



  /**
   * Tests the behavior of the enhanced {@code equals} method when field name
   * case is to be ignored.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIgnoreFieldNameCase()
         throws Exception
  {
    final LinkedHashMap<String,JSONValue> m1 =
         new LinkedHashMap<String,JSONValue>(1);
    m1.put("fieldName", JSONBoolean.TRUE);
    final JSONObject o1 = new JSONObject(m1);

    final LinkedHashMap<String,JSONValue> m2 =
         new LinkedHashMap<String,JSONValue>(1);
    m2.put("fieldname", JSONBoolean.TRUE);
    final JSONObject o2 = new JSONObject(m2);

    assertFalse(o1.equals(o2));
    assertFalse(o2.equals(o1));

    assertFalse(o1.equals(o2, false, false, false));
    assertTrue(o1.equals(o2, true, false, false));
    assertTrue(o1.equals(o2, true, true, true));

    assertFalse(o2.equals(o1, false, false, false));
    assertTrue(o2.equals(o1, true, false, false));
    assertTrue(o2.equals(o1, true, true, true));
  }



  /**
   * Tests the behavior of the enhanced {@code equals} method for the case in
   * which an object has multiple equivalent fields if case is ignored.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsMultipleEquivalentFieldsIgnoringCase()
         throws Exception
  {
    final LinkedHashMap<String,JSONValue> m1 =
         new LinkedHashMap<String,JSONValue>(3);
    m1.put("booleanField", JSONBoolean.TRUE);
    m1.put("BooleanField", JSONBoolean.TRUE);
    m1.put("nullField", JSONNull.NULL);
    final JSONObject o1 = new JSONObject(m1);

    final LinkedHashMap<String,JSONValue> m2 =
         new LinkedHashMap<String,JSONValue>(3);
    m2.put("booleanField", JSONBoolean.TRUE);
    m2.put("nullField", JSONNull.NULL);
    m2.put("NullField", JSONNull.NULL);
    final JSONObject o2 = new JSONObject(m2);

    assertFalse(o1.equals(o2));
    assertFalse(o2.equals(o1));

    assertFalse(o1.equals(o2, false, false, false));
    assertFalse(o1.equals(o2, true, false, false));
    assertFalse(o1.equals(o2, true, true, true));

    assertFalse(o2.equals(o1, false, false, false));
    assertFalse(o2.equals(o1, true, false, false));
    assertFalse(o2.equals(o1, true, true, true));
  }



  /**
   * Tests the behavior of the enhanced {@code equals} method when field value
   * case is to be ignored.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIgnoreStringValueCase()
         throws Exception
  {
    final LinkedHashMap<String,JSONValue> m1 =
         new LinkedHashMap<String,JSONValue>(1);
    m1.put("fieldName", new JSONString("This Is A Value"));
    final JSONObject o1 = new JSONObject(m1);

    final LinkedHashMap<String,JSONValue> m2 =
         new LinkedHashMap<String,JSONValue>(1);
    m2.put("fieldName", new JSONString("this is a value"));
    final JSONObject o2 = new JSONObject(m2);

    assertFalse(o1.equals(o2));
    assertFalse(o2.equals(o1));

    assertFalse(o1.equals(o2, false, false, false));
    assertTrue(o1.equals(o2, false, true, false));
    assertTrue(o1.equals(o2, true, true, true));

    assertFalse(o2.equals(o1, false, false, false));
    assertTrue(o2.equals(o1, false, true, false));
    assertTrue(o2.equals(o1, true, true, true));
  }



  /**
   * Tests the behavior of the enhanced {@code equals} method when field value
   * case is to be ignored and the string is in an array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIgnoreStringInArrayCase()
         throws Exception
  {
    final LinkedHashMap<String,JSONValue> m1 =
         new LinkedHashMap<String,JSONValue>(1);
    m1.put("fieldName", new JSONArray(new JSONString("This Is A Value")));
    final JSONObject o1 = new JSONObject(m1);

    final LinkedHashMap<String,JSONValue> m2 =
         new LinkedHashMap<String,JSONValue>(1);
    m2.put("fieldName", new JSONArray(new JSONString("this is a value")));
    final JSONObject o2 = new JSONObject(m2);

    assertFalse(o1.equals(o2));
    assertFalse(o2.equals(o1));

    assertFalse(o1.equals(o2, false, false, false));
    assertTrue(o1.equals(o2, false, true, false));
    assertTrue(o1.equals(o2, true, true, true));

    assertFalse(o2.equals(o1, false, false, false));
    assertTrue(o2.equals(o1, false, true, false));
    assertTrue(o2.equals(o1, true, true, true));
  }



  /**
   * Tests the behavior of the enhanced {@code equals} method when the order
   * of elements in an array should be ignored.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIgnoreArrayOrder()
         throws Exception
  {
    final LinkedHashMap<String,JSONValue> m1 =
         new LinkedHashMap<String,JSONValue>(1);
    m1.put("fieldName",
         new JSONArray(new JSONString("first"), new JSONString("second")));
    final JSONObject o1 = new JSONObject(m1);

    final LinkedHashMap<String,JSONValue> m2 =
         new LinkedHashMap<String,JSONValue>(1);
    m2.put("fieldName",
         new JSONArray(new JSONString("second"), new JSONString("first")));
    final JSONObject o2 = new JSONObject(m2);

    assertFalse(o1.equals(o2));
    assertFalse(o2.equals(o1));

    assertFalse(o1.equals(o2, false, false, false));
    assertTrue(o1.equals(o2, false, false, true));
    assertTrue(o1.equals(o2, true, true, true));

    assertFalse(o2.equals(o1, false, false, false));
    assertTrue(o2.equals(o1, false, false, true));
    assertTrue(o2.equals(o1, true, true, true));
  }



  /**
   * Tests the behavior of the various {@code equals} methods for objects that
   * have different numbers of elements.
   *
   * @throws  Exception  If an unexpected problem occurs
   */
  @Test()
  public void testEqualsDifferentObjectSizes()
         throws Exception
  {
    final LinkedHashMap<String,JSONValue> m1 =
         new LinkedHashMap<String,JSONValue>(1);
    m1.put("first", JSONBoolean.TRUE);
    final JSONObject o1 = new JSONObject(m1);

    final LinkedHashMap<String,JSONValue> m2 =
         new LinkedHashMap<String,JSONValue>(2);
    m2.put("first", JSONBoolean.TRUE);
    m2.put("second", JSONBoolean.FALSE);
    final JSONObject o2 = new JSONObject(m2);

    assertFalse(o1.equals(o2));
    assertFalse(o2.equals(o1));

    assertFalse(o1.equals(o2, false, false, false));
    assertFalse(o2.equals(o1, false, false, false));

    assertFalse(o1.equals(o2, true, true, true));
    assertFalse(o2.equals(o1, true, true, true));
  }



  /**
   * Tests the behavior of the {@code getFieldAsString} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetFieldAsString()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("stringField", "foo"),
         new JSONField("trueField", true),
         new JSONField("falseField", false),
         new JSONField("intField", 1234),
         new JSONField("longField", Long.MAX_VALUE),
         new JSONField("bigDecimalField", new JSONNumber(new BigDecimal(1.5d))),
         new JSONField("nullField", JSONNull.NULL),
         new JSONField("objectField", JSONObject.EMPTY_OBJECT),
         new JSONField("arrayField", JSONArray.EMPTY_ARRAY));

    assertNotNull(o.getFieldAsString("stringField"));
    assertEquals(o.getFieldAsString("stringField"), "foo");

    assertNull(o.getFieldAsString("missingField"));
    assertNull(o.getFieldAsString("trueField"));
    assertNull(o.getFieldAsString("falseField"));
    assertNull(o.getFieldAsString("intField"));
    assertNull(o.getFieldAsString("longField"));
    assertNull(o.getFieldAsString("bigDecimalField"));
    assertNull(o.getFieldAsString("nullField"));
    assertNull(o.getFieldAsString("objectField"));
    assertNull(o.getFieldAsString("arrayField"));
  }



  /**
   * Tests the behavior of the {@code getFieldAsBoolean} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetFieldAsBoolean()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("stringField", "foo"),
         new JSONField("trueField", true),
         new JSONField("falseField", false),
         new JSONField("intField", 1234),
         new JSONField("longField", Long.MAX_VALUE),
         new JSONField("bigDecimalField", new JSONNumber(new BigDecimal(1.5d))),
         new JSONField("nullField", JSONNull.NULL),
         new JSONField("objectField", JSONObject.EMPTY_OBJECT),
         new JSONField("arrayField", JSONArray.EMPTY_ARRAY));

    assertNotNull(o.getFieldAsBoolean("trueField"));
    assertEquals(o.getFieldAsBoolean("trueField"), Boolean.TRUE);

    assertNotNull(o.getFieldAsBoolean("falseField"));
    assertEquals(o.getFieldAsBoolean("falseField"), Boolean.FALSE);

    assertNull(o.getFieldAsBoolean("missingField"));
    assertNull(o.getFieldAsBoolean("stringField"));
    assertNull(o.getFieldAsBoolean("intField"));
    assertNull(o.getFieldAsBoolean("longField"));
    assertNull(o.getFieldAsBoolean("bigDecimalField"));
    assertNull(o.getFieldAsBoolean("nullField"));
    assertNull(o.getFieldAsBoolean("objectField"));
    assertNull(o.getFieldAsBoolean("arrayField"));
  }



  /**
   * Tests the behavior of the {@code getFieldAsInteger} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetFieldAsInteger()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("stringField", "foo"),
         new JSONField("trueField", true),
         new JSONField("falseField", false),
         new JSONField("intField", 1234),
         new JSONField("longField", Long.MAX_VALUE),
         new JSONField("bigDecimalField", new JSONNumber(new BigDecimal(1.5d))),
         new JSONField("nullField", JSONNull.NULL),
         new JSONField("objectField", JSONObject.EMPTY_OBJECT),
         new JSONField("arrayField", JSONArray.EMPTY_ARRAY));

    assertNotNull(o.getFieldAsInteger("intField"));
    assertEquals(o.getFieldAsInteger("intField"), Integer.valueOf(1234));

    assertNull(o.getFieldAsInteger("missingField"));
    assertNull(o.getFieldAsInteger("stringField"));
    assertNull(o.getFieldAsInteger("trueField"));
    assertNull(o.getFieldAsInteger("falseField"));
    assertNull(o.getFieldAsInteger("longField"));
    assertNull(o.getFieldAsInteger("bigDecimalField"));
    assertNull(o.getFieldAsInteger("nullField"));
    assertNull(o.getFieldAsInteger("objectField"));
    assertNull(o.getFieldAsInteger("arrayField"));
  }



  /**
   * Tests the behavior of the {@code getFieldAsLong} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetFieldAsLong()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("stringField", "foo"),
         new JSONField("trueField", true),
         new JSONField("falseField", false),
         new JSONField("intField", 1234),
         new JSONField("longField", Long.MAX_VALUE),
         new JSONField("bigDecimalField", new JSONNumber(new BigDecimal(1.5d))),
         new JSONField("nullField", JSONNull.NULL),
         new JSONField("objectField", JSONObject.EMPTY_OBJECT),
         new JSONField("arrayField", JSONArray.EMPTY_ARRAY));

    assertNotNull(o.getFieldAsLong("intField"));
    assertEquals(o.getFieldAsLong("intField"), Long.valueOf(1234));

    assertNotNull(o.getFieldAsLong("longField"));
    assertEquals(o.getFieldAsLong("longField"), Long.valueOf(Long.MAX_VALUE));

    assertNull(o.getFieldAsLong("missingField"));
    assertNull(o.getFieldAsLong("stringField"));
    assertNull(o.getFieldAsLong("trueField"));
    assertNull(o.getFieldAsLong("falseField"));
    assertNull(o.getFieldAsLong("bigDecimalField"));
    assertNull(o.getFieldAsLong("nullField"));
    assertNull(o.getFieldAsLong("objectField"));
    assertNull(o.getFieldAsLong("arrayField"));
  }



  /**
   * Tests the behavior of the {@code getFieldAsBigDecimal} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetFieldAsBigDecimal()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("stringField", "foo"),
         new JSONField("trueField", true),
         new JSONField("falseField", false),
         new JSONField("intField", 1234),
         new JSONField("longField", Long.MAX_VALUE),
         new JSONField("bigDecimalField", new JSONNumber(new BigDecimal(1.5d))),
         new JSONField("nullField", JSONNull.NULL),
         new JSONField("objectField", JSONObject.EMPTY_OBJECT),
         new JSONField("arrayField", JSONArray.EMPTY_ARRAY));

    assertNotNull(o.getFieldAsBigDecimal("intField"));
    assertEquals(o.getFieldAsBigDecimal("intField"), new BigDecimal(1234));

    assertNotNull(o.getFieldAsBigDecimal("longField"));
    assertEquals(o.getFieldAsBigDecimal("longField"),
         new BigDecimal(Long.MAX_VALUE));

    assertNotNull(o.getFieldAsBigDecimal("bigDecimalField"));
    assertEquals(o.getFieldAsBigDecimal("bigDecimalField"),
         new BigDecimal(1.5d));

    assertNull(o.getFieldAsBigDecimal("missingField"));
    assertNull(o.getFieldAsBigDecimal("stringField"));
    assertNull(o.getFieldAsBigDecimal("trueField"));
    assertNull(o.getFieldAsBigDecimal("falseField"));
    assertNull(o.getFieldAsBigDecimal("nullField"));
    assertNull(o.getFieldAsBigDecimal("objectField"));
    assertNull(o.getFieldAsBigDecimal("arrayField"));
  }



  /**
   * Tests the behavior of the {@code getFieldAsObject} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetFieldAsObject()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("stringField", "foo"),
         new JSONField("trueField", true),
         new JSONField("falseField", false),
         new JSONField("intField", 1234),
         new JSONField("longField", Long.MAX_VALUE),
         new JSONField("bigDecimalField", new JSONNumber(new BigDecimal(1.5d))),
         new JSONField("nullField", JSONNull.NULL),
         new JSONField("objectField", JSONObject.EMPTY_OBJECT),
         new JSONField("arrayField", JSONArray.EMPTY_ARRAY));

    assertNotNull(o.getFieldAsObject("objectField"));
    assertEquals(o.getFieldAsObject("objectField"), JSONObject.EMPTY_OBJECT);

    assertNull(o.getFieldAsObject("missingField"));
    assertNull(o.getFieldAsObject("stringField"));
    assertNull(o.getFieldAsObject("trueField"));
    assertNull(o.getFieldAsObject("falseField"));
    assertNull(o.getFieldAsObject("intField"));
    assertNull(o.getFieldAsObject("longField"));
    assertNull(o.getFieldAsObject("bigDecimalField"));
    assertNull(o.getFieldAsObject("nullField"));
    assertNull(o.getFieldAsObject("arrayField"));
  }



  /**
   * Tests the behavior of the {@code getFieldAsArray} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetFieldAsArray()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("stringField", "foo"),
         new JSONField("trueField", true),
         new JSONField("falseField", false),
         new JSONField("intField", 1234),
         new JSONField("longField", Long.MAX_VALUE),
         new JSONField("bigDecimalField", new JSONNumber(new BigDecimal(1.5d))),
         new JSONField("nullField", JSONNull.NULL),
         new JSONField("objectField", JSONObject.EMPTY_OBJECT),
         new JSONField("arrayField", JSONArray.EMPTY_ARRAY));

    assertNotNull(o.getFieldAsArray("arrayField"));
    assertEquals(o.getFieldAsArray("arrayField"), Collections.emptyList());

    assertNull(o.getFieldAsArray("missingField"));
    assertNull(o.getFieldAsArray("stringField"));
    assertNull(o.getFieldAsArray("trueField"));
    assertNull(o.getFieldAsArray("falseField"));
    assertNull(o.getFieldAsArray("intField"));
    assertNull(o.getFieldAsArray("longField"));
    assertNull(o.getFieldAsArray("bigDecimalField"));
    assertNull(o.getFieldAsArray("nullField"));
    assertNull(o.getFieldAsArray("objectField"));
  }



  /**
   * Tests the behavior of the {@code hasNullField} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHasNullField()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("stringField", "foo"),
         new JSONField("trueField", true),
         new JSONField("falseField", false),
         new JSONField("intField", 1234),
         new JSONField("longField", Long.MAX_VALUE),
         new JSONField("bigDecimalField", new JSONNumber(new BigDecimal(1.5d))),
         new JSONField("nullField", JSONNull.NULL),
         new JSONField("objectField", JSONObject.EMPTY_OBJECT),
         new JSONField("arrayField", JSONArray.EMPTY_ARRAY));

    assertTrue(o.hasNullField("nullField"));

    assertFalse(o.hasNullField("missingField"));
    assertFalse(o.hasNullField("stringField"));
    assertFalse(o.hasNullField("trueField"));
    assertFalse(o.hasNullField("falseField"));
    assertFalse(o.hasNullField("intField"));
    assertFalse(o.hasNullField("longField"));
    assertFalse(o.hasNullField("bigDecimalField"));
    assertFalse(o.hasNullField("objectField"));
    assertFalse(o.hasNullField("arrayField"));
  }



  /**
   * Retrieves a set of test data that can be used to test the ability to decode
   * valid JSON strings to their corresponding objects.
   *
   * @return  A set of test data that can be used to test the ability to decode
   *          valid JSON strings to their corresponding objects.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="validObjectStrings")
  public Iterator<Object[]> getValidObjectStrings()
         throws Exception
  {
    final ArrayList<Object[]> argList = new ArrayList<Object[]>(50);


    // Test empty objects.
    argList.add(new Object[]
    {
      "{}",
      JSONObject.EMPTY_OBJECT,
      "{}"
    });

    argList.add(new Object[]
    {
      " {} ",
      JSONObject.EMPTY_OBJECT,
      "{}"
    });

    argList.add(new Object[]
    {
      "     {}     ",
      JSONObject.EMPTY_OBJECT,
      "{}"
    });

    argList.add(new Object[]
    {
      "{ }",
      JSONObject.EMPTY_OBJECT,
      "{}"
    });

    argList.add(new Object[]
    {
      "{      }",
      JSONObject.EMPTY_OBJECT,
      "{}"
    });

    argList.add(new Object[]
    {
      "{\n}",
      JSONObject.EMPTY_OBJECT,
      "{}"
    });

    argList.add(new Object[]
    {
      "{\r\n}",
      JSONObject.EMPTY_OBJECT,
      "{}"
    });

    argList.add(new Object[]
    {
      "{ \t \t \n }",
      JSONObject.EMPTY_OBJECT,
      "{}"
    });


    // Test nulls.
    final LinkedHashMap<String,JSONValue> m1 =
         new LinkedHashMap<String,JSONValue>(1);
    m1.put("fieldName", JSONNull.NULL);
    final JSONObject nullObject = new JSONObject(m1);

    argList.add(new Object[]
    {
      "{\"fieldName\":null}",
      nullObject,
      "{\"fieldName\":null}"
    });

    argList.add(new Object[]
    {
      "{ \"fieldName\":null }",
      nullObject,
      "{\"fieldName\":null}"
    });

    argList.add(new Object[]
    {
      "{ \"fieldName\" : null }",
      nullObject,
      "{\"fieldName\":null}"
    });

    argList.add(new Object[]
    {
      "{\n  \"fieldName\" : null\n}",
      nullObject,
      "{\"fieldName\":null}"
    });


    // Test booleans.
    final LinkedHashMap<String,JSONValue> m2 =
         new LinkedHashMap<String,JSONValue>(2);
    m2.put("trueField", JSONBoolean.TRUE);
    m2.put("falseField", JSONBoolean.FALSE);
    final JSONObject booleanObject = new JSONObject(m2);

    argList.add(new Object[]
    {
      "{\"trueField\":true,\"falseField\":false}",
      booleanObject,
      "{\"falseField\":false,\"trueField\":true}"
    });

    argList.add(new Object[]
    {
      "{ \"trueField\" : true , \"falseField\" : false }",
      booleanObject,
      "{\"falseField\":false,\"trueField\":true}"
    });

    argList.add(new Object[]
    {
      "{\n  \"trueField\" : true,\n  \"falseField\" : false\n}",
      booleanObject,
      "{\"falseField\":false,\"trueField\":true}"
    });


    // Test strings.
    final LinkedHashMap<String,JSONValue> m3 =
         new LinkedHashMap<String,JSONValue>(3);
    m3.put("emptyField", new JSONString(""));
    m3.put("fooField", new JSONString("Foo"));
    m3.put("escapedField",
         new JSONString(
              "a\"B\\c/d\bE\ff\ng\rH\ti\u0000j\u00E1k\u0201l\u1E01m\uFF41n"));
    final JSONObject stringObject = new JSONObject(m3);

    argList.add(new Object[]
    {
      "{\"emptyField\":\"\",\"fooField\":\"Foo\",\"escapedField\":" +
           "\"a\\\"B\\\\c\\/d\\bE\\ff\\ng\\rH\\ti\\u0000j\u00E1k\u0201l" +
           "\u1E01m\uFF41n\"}",
      stringObject,
      "{\"emptyField\":\"\",\"escapedField\":\"a\\u0022b\\u005Cc/d\\u0008e" +
           "\\u000Cf\\u000Ag\\u000Dh\\u0009i\\u0000j\\u00E1k\\u0201l" +
           "\\u1E01m\\uFF41n\",\"fooField\":\"foo\"}"
    });

    argList.add(new Object[]
    {
      "{ \"emptyField\" : \"\" , \"fooField\" : \"Foo\" , \"escapedField\" : " +
           "\"a\\\"B\\\\c\\/d\\bE\\ff\\ng\\rH\\ti\\u0000j\u00E1k\u0201l" +
           "\u1E01m\uFF41n\" }",
      stringObject,
      "{\"emptyField\":\"\",\"escapedField\":\"a\\u0022b\\u005Cc/d\\u0008e" +
           "\\u000Cf\\u000Ag\\u000Dh\\u0009i\\u0000j\\u00E1k\\u0201l" +
           "\\u1E01m\\uFF41n\",\"fooField\":\"foo\"}"
    });


    // Test numbers.
    final LinkedHashMap<String,JSONValue> m4 =
         new LinkedHashMap<String,JSONValue>(9);
    m4.put("intZero", new JSONNumber("0"));
    m4.put("floatZero", new JSONNumber("0.0"));
    m4.put("sciZero", new JSONNumber("0e0"));
    m4.put("positiveInt", new JSONNumber(1234));
    m4.put("positiveFloat", new JSONNumber(1234.5));
    m4.put("positiveSci", new JSONNumber("1.2345e+3"));
    m4.put("negativeInt", new JSONNumber(-9876));
    m4.put("negativeFloat", new JSONNumber(-9876.5));
    m4.put("negativeSci", new JSONNumber("-98765e-1"));

    final JSONObject numberObject = new JSONObject(m4);

    argList.add(new Object[]
    {
      "{\"intZero\":0,\"floatZero\":0.0,\"sciZero\":0e0,\"positiveInt\":1234," +
           "\"positiveFloat\":1234.5,\"positiveSci\":1.2345e+3," +
           "\"negativeInt\":-9876,\"negativeFloat\":-9876.5," +
           "\"negativeSci\":-98765e-1}",
      numberObject,
      "{\"floatZero\":0,\"intZero\":0,\"negativeFloat\":-9876.5," +
           "\"negativeInt\":-9876,\"negativeSci\":-9876.5," +
           "\"positiveFloat\":1234.5,\"positiveInt\":1234," +
           "\"positiveSci\":1234.5,\"sciZero\":0}"
    });

    argList.add(new Object[]
    {
      "{ \"intZero\" : 0 , \"floatZero\" : 0.0 , \"sciZero\" : 0e0 , " +
           "\"positiveInt\" : 1234 , \"positiveFloat\" : 1234.5 , " +
           "\"positiveSci\" : 1.2345e+3 , \"negativeInt\" : -9876 , " +
           "\"negativeFloat\" : -9876.5 , \"negativeSci\" : -98765e-1 }",
      numberObject,
      "{\"floatZero\":0,\"intZero\":0,\"negativeFloat\":-9876.5," +
           "\"negativeInt\":-9876,\"negativeSci\":-9876.5," +
           "\"positiveFloat\":1234.5,\"positiveInt\":1234," +
           "\"positiveSci\":1234.5,\"sciZero\":0}"
    });


    // Test arrays.
    final LinkedHashMap<String,JSONValue> m5 =
         new LinkedHashMap<String,JSONValue>(2);
    m5.put("emptyArray", JSONArray.EMPTY_ARRAY);
    m5.put("arrayOfAllTypes", new JSONArray(
         JSONNull.NULL,
         JSONBoolean.TRUE,
         JSONNull.NULL,
         JSONBoolean.FALSE,
         JSONNull.NULL,
         new JSONString("Foo"),
         new JSONNumber(12345),
         new JSONArray(),
         new JSONArray(
              new JSONString("a"),
              new JSONString("B")),
         JSONObject.EMPTY_OBJECT,
         booleanObject));

    final JSONObject arrayObject = new JSONObject(m5);

    argList.add(new Object[]
    {
      "{\"emptyArray\":[],\"arrayOfAllTypes\":[null,true,null,false,null," +
           "\"Foo\",12345,[],[\"a\",\"B\"],{},{\"trueField\":true," +
           "\"falseField\":false}]}",
      arrayObject,
      "{\"arrayOfAllTypes\":[null,true,null,false,null,\"foo\",12345,[]," +
           "[\"a\",\"b\"],{},{\"falseField\":false,\"trueField\":true}]," +
           "\"emptyArray\":[]}"
    });

    argList.add(new Object[]
    {
      "{ \"emptyArray\" : [ ] , \"arrayOfAllTypes\" : [ null , true , null , " +
           "false , null , \"Foo\" , 12345 , [ ] , [ \"a\" , \"B\" ] , { } , " +
           "{ \"trueField\" : true , \"falseField\" : false } ] }",
      arrayObject,
      "{\"arrayOfAllTypes\":[null,true,null,false,null,\"foo\",12345,[]," +
           "[\"a\",\"b\"],{},{\"falseField\":false,\"trueField\":true}]," +
           "\"emptyArray\":[]}"
    });


    // Test objects.
    final LinkedHashMap<String,JSONValue> m6 =
         new LinkedHashMap<String,JSONValue>(7);
    m6.put("emptyObject", JSONObject.EMPTY_OBJECT);
    m6.put("nullObject", nullObject);
    m6.put("booleanObject", booleanObject);
    m6.put("stringObject", stringObject);
    m6.put("numberObject", numberObject);
    m6.put("arrayObject", arrayObject);
    m6.put("Field with \u0000 weird \" characters",
         new JSONString("In\tthe\nname"));

    final JSONObject objectObject = new JSONObject(m6);

    argList.add(new Object[]
    {
      "{\"emptyObject\":{},\"nullObject\":{\"fieldName\":null}," +
           "\"booleanObject\":{\"trueField\":true,\"falseField\":false}," +
           "\"stringObject\":{\"emptyField\":\"\",\"fooField\":\"Foo\"," +
           "\"escapedField\":\"a\\\"B\\\\c\\/d\\bE\\ff\\ng\\rH\\ti\\u0000j" +
           "\u00E1k\u0201l\u1E01m\uFF41n\"}," +
           "\"numberObject\":{\"intZero\":0,\"floatZero\":0.0,\"sciZero\":" +
           "0e0,\"positiveInt\":1234,\"positiveFloat\":1234.5," +
           "\"positiveSci\":1.2345e+3,\"negativeInt\":-9876," +
           "\"negativeFloat\":-9876.5,\"negativeSci\":-98765e-1}," +
           "\"arrayObject\":{\"emptyArray\":[],\"arrayOfAllTypes\":[null," +
           "true,null,false,null,\"Foo\",12345,[],[\"a\",\"B\"],{}," +
           "{\"trueField\":true,\"falseField\":false}]}," +
           "\"Field with \\u0000 weird \\\" characters\":\"In\\tthe\\nname\"}",
      objectObject,
      "{\"Field with \\u0000 weird \\u0022 characters\":" +
           "\"in\\u0009the\\u000Aname\",\"arrayObject\":{\"arrayOfAllTypes\":" +
           "[null,true,null,false,null,\"foo\",12345,[],[\"a\",\"b\"],{}," +
           "{\"falseField\":false,\"trueField\":true}],\"emptyArray\":[]}," +
           "\"booleanObject\":{\"falseField\":false,\"trueField\":true}," +
           "\"emptyObject\":{},\"nullObject\":{\"fieldName\":null}," +
           "\"numberObject\":{\"floatZero\":0,\"intZero\":0," +
           "\"negativeFloat\":-9876.5,\"negativeInt\":-9876," +
           "\"negativeSci\":-9876.5,\"positiveFloat\":1234.5," +
           "\"positiveInt\":1234,\"positiveSci\":1234.5,\"sciZero\":0}," +
           "\"stringObject\":{\"emptyField\":\"\",\"escapedField\":" +
           "\"a\\u0022b\\u005Cc/d\\u0008e\\u000Cf\\u000Ag\\u000Dh\\u0009i" +
           "\\u0000j\\u00E1k\\u0201l\\u1E01m\\uFF41n\",\"fooField\":\"foo\"}}"
    });

    argList.add(new Object[]
    {
      "{ \"emptyObject\" : { } , \"nullObject\" : { \"fieldName\" : null } , " +
           "\"booleanObject\" : { \"trueField\" : true , \"falseField\" : " +
           "false } , \"stringObject\" : { \"emptyField\" : \"\" , " +
           "\"fooField\" : \"Foo\" , \"escapedField\" : \"a\\\"B\\\\c\\/d" +
           "\\bE\\ff\\ng\\rH\\ti\\u0000j\u00E1k\u0201l\u1E01m\uFF41n\" } , " +
           "\"numberObject\" : { \"intZero\" : 0 , \"floatZero\" : 0.0 , " +
           "\"sciZero\" : 0e0 , \"positiveInt\" : 1234 , " +
           "\"positiveFloat\" : 1234.5 , \"positiveSci\" : 1.2345e+3 , " +
           "\"negativeInt\" : -9876 , \"negativeFloat\" : -9876.5 , " +
           "\"negativeSci\" : -98765e-1 } , " +
           "\"arrayObject\" : { \"emptyArray\" : [ ] , \"arrayOfAllTypes\" : " +
           "[ null , true , null , false , null , \"Foo\" , 12345 , [ ] , " +
           "[ \"a\" , \"B\" ] , { } , { \"trueField\" : true , " +
           "\"falseField\" : false } ] } , " +
           "\"Field with \\u0000 weird \\\" characters\" : " +
           "\"In\\tthe\\nname\" }",
      objectObject,
      "{\"Field with \\u0000 weird \\u0022 characters\":" +
           "\"in\\u0009the\\u000Aname\",\"arrayObject\":{\"arrayOfAllTypes\":" +
           "[null,true,null,false,null,\"foo\",12345,[],[\"a\",\"b\"],{}," +
           "{\"falseField\":false,\"trueField\":true}],\"emptyArray\":[]}," +
           "\"booleanObject\":{\"falseField\":false,\"trueField\":true}," +
           "\"emptyObject\":{},\"nullObject\":{\"fieldName\":null}," +
           "\"numberObject\":{\"floatZero\":0,\"intZero\":0," +
           "\"negativeFloat\":-9876.5,\"negativeInt\":-9876," +
           "\"negativeSci\":-9876.5,\"positiveFloat\":1234.5," +
           "\"positiveInt\":1234,\"positiveSci\":1234.5,\"sciZero\":0}," +
           "\"stringObject\":{\"emptyField\":\"\",\"escapedField\":" +
           "\"a\\u0022b\\u005Cc/d\\u0008e\\u000Cf\\u000Ag\\u000Dh\\u0009i" +
           "\\u0000j\\u00E1k\\u0201l\\u1E01m\\uFF41n\",\"fooField\":\"foo\"}}"
    });


    // Test comments.
    argList.add(new Object[]
    {
      "//\n{//\n// Comment here \r\n}//\n// It's a comment\n//This too\r\n//",
      JSONObject.EMPTY_OBJECT,
      "{}"
    });

    argList.add(new Object[]
    {
      "//\n{//\n// Comment here \r\n# And here.\n}//\n// It's a comment\n" +
           "//This too\r\n//",
      JSONObject.EMPTY_OBJECT,
      "{}"
    });

    argList.add(new Object[]
    {
      "/* before */{/*inside*/}/*after*/",
      JSONObject.EMPTY_OBJECT,
      "{}"
    });

    argList.add(new Object[]
    {
      "// An open curly brace starts an object.\n" +
           "{\n" +
           "  // The next line starts a field definition.\n" +
           "  \"name\"\n" +
           "\n" +
           "  // The colon separates the name of a field from its value.\n" +
           "  :\n" +
           "\n" +
           "  \"value\"\n" +
           "\n" +
          "// A close curly brace ends an object.\n" +
          "}\n" +
          "// And now we're done.",
      new JSONObject(new JSONField("name", "value")),
      "{\"name\":\"value\"}"
    });

    argList.add(new Object[]
    {
      "# An open curly brace starts an object.\n" +
           "{\n" +
           "  # The next line starts a field definition.\n" +
           "  \"name\"\n" +
           "\n" +
           "  # The colon separates the name of a field from its value.\n" +
           "  :\n" +
           "\n" +
           "  \"value\"\n" +
           "\n" +
          "# A close curly brace ends an object.\n" +
          "}\n" +
          "# And now we're done.",
      new JSONObject(new JSONField("name", "value")),
      "{\"name\":\"value\"}"
    });

    argList.add(new Object[]
    {
      "/*\n" +
           " * This comment comes before the object.\n" +
           " */\n" +
           "{\n" +
           "  /* The next line starts a field definition. */\n" +
           "  /* Name's about to start */\"name\"/* That was it */\n" +
           "\n" +
           "  /* The colon separates the name of a field from its value. */\n" +
           "  /*CommentAroundTheColon*/:/*CommentAroundTheColon*/\n" +
           "\n" +
           "  /*value starts*/\"value\"/*value ends*/\n" +
           "\n" +
          "/* A close curly brace ends an object. */\n" +
          "}\n" +
          "/* And now we're done. But a trailing space just for fun. */ ",
      new JSONObject(new JSONField("name", "value")),
      "{\"name\":\"value\"}"
    });

    return argList.iterator();
  }



  /**
   * Retrieves a set of test data that can be used to verify that the JSON
   * parser will properly reject strings that cannot be parsed as JSON objects.
   *
   * @return  A set of test data that can be used to verify that the JSON parser
   *          will properly reject strings that cannot be parsed as JSON
   *          objects.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="invalidObjectStrings")
  public Object[][] getInvalidObjectStrings()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        ""
      },

      new Object[]
      {
        " "
      },

      new Object[]
      {
        "{"
      },

      new Object[]
      {
        "}"
      },

      new Object[]
      {
        "invalid"
      },

      new Object[]
      {
        " invalid "
      },

      new Object[]
      {
        "{ unquotedFieldName:true }"
      },

      new Object[]
      {
        "{ \"unclosedQuote:true }"
      },

      new Object[]
      {
        "{ \"notReallyNull\":notreallynull }"
      },

      new Object[]
      {
        "{ \"notReallyNull\":NULL }"
      },

      new Object[]
      {
        "{ \"notReallyTrue\":truly }"
      },

      new Object[]
      {
        "{ \"notReallyTrue\":TRUE }"
      },

      new Object[]
      {
        "{ \"notReallyFalse\":falsity }"
      },

      new Object[]
      {
        "{ \"notReallyFalse\":FALSE }"
      },

      new Object[]
      {
        "{ \"unquotedString\":unquoted }"
      },

      new Object[]
      {
        "{ \"badNonUnicodeEscape\":\"\\a\\c\\d\" }"
      },

      new Object[]
      {
        "{ \"badUnicodeEscape\":\"\\unothex\" }"
      },

      new Object[]
      {
        "{ \"badNumber\":123abc456 }"
      },

      new Object[]
      {
        "{ \"unclosedArray\":[true,false }"
      },

      new Object[]
      {
        "{ \"arrayWithUnexpectedToken\":[x:y] }"
      },

      new Object[]
      {
        "{ \"arrayWithBadTrailingComma\":[ true, false, ] }"
      },

      new Object[]
      {
        "{ \"unclosedObject\":{\"field\":null }"
      },

      new Object[]
      {
        "{ \"duplicateField\":false, \"duplicateField\":true }"
      },

      new Object[]
      {
        "{ \"badTrailingComma\":null, }"
      },

      new Object[]
      {
        "{ \"noColonAfterFieldName\" null }"
      },

      new Object[]
      {
        "{ \"badTokenAfterFieldName\"] }"
      },

      new Object[]
      {
        "{ \"badTokenAfterColon\":] }"
      },

      new Object[]
      {
        "{ \"badTokenAfterValue\":\"foo\"] }"
      },

      new Object[]
      {
        "{ \"unescapedControlCharacter\" : \"In \u0000 String\" }"
      },

      new Object[]
      {
        "{ /* Unclosed comment }"
      },

      new Object[]
      {
        "{ /"
      },

      new Object[]
      {
        "{ /? }"
      },

      new Object[]
      {
        "{ // No newline between end of comment and close brace }"
      },

      new Object[]
      {
        "{}{}"
      },
    };
  }
}
