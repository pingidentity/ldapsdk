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



import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code JSONArray} class.
 */
public final class JSONArrayTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyArray()
         throws Exception
  {
    final JSONArray a1 = JSONArray.EMPTY_ARRAY;

    assertNotNull(a1.getValues());
    assertTrue(a1.getValues().isEmpty());

    assertTrue(a1.isEmpty());

    assertEquals(a1.size(), 0);

    assertFalse(a1.contains(JSONNull.NULL, false, false, false, false));
    assertFalse(a1.contains(JSONNull.NULL, true, true, true, true));

    assertNotNull(a1.toString());
    assertEquals(a1.toString(), "[ ]");

    assertNotNull(a1.toSingleLineString());
    assertEquals(a1.toSingleLineString(), "[ ]");

    StringBuilder toStringBuffer = new StringBuilder();
    a1.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), "[ ]");

    StringBuilder toSingleLineStringBuffer = new StringBuilder();
    a1.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(), "[ ]");

    assertNotNull(a1.toNormalizedString());
    assertEquals(a1.toNormalizedString(), "[]");

    StringBuilder toNormalizedStringBuffer = new StringBuilder();
    a1.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(), "[]");

    assertNotNull(a1.toNormalizedString(true, true, true));
    assertEquals(a1.toNormalizedString(true, true, true), "[]");

    assertNotNull(a1.toNormalizedString(false, false, false));
    assertEquals(a1.toNormalizedString(false, false, false), "[]");

    final JSONBuffer jsonBuffer = new JSONBuffer();
    a1.appendToJSONBuffer(jsonBuffer);
    assertEquals(jsonBuffer.toString(), "[ ]");

    jsonBuffer.clear();
    a1.appendToJSONBuffer("fieldName", jsonBuffer);
    assertEquals(jsonBuffer.toString(), "\"fieldName\":[ ]");



    final JSONArray a2 = new JSONArray((JSONValue[]) null);

    assertNotNull(a2.getValues());
    assertTrue(a2.getValues().isEmpty());

    assertTrue(a2.isEmpty());

    assertEquals(a2.size(), 0);

    assertFalse(a2.contains(JSONNull.NULL, false, false, false, false));
    assertFalse(a2.contains(JSONNull.NULL, true, true, true, true));

    assertNotNull(a2.toString());
    assertEquals(a2.toString(), "[ ]");

    assertNotNull(a2.toSingleLineString());
    assertEquals(a2.toSingleLineString(), "[ ]");

    toStringBuffer = new StringBuilder();
    a2.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), "[ ]");

    toSingleLineStringBuffer = new StringBuilder();
    a2.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(), "[ ]");

    assertNotNull(a2.toNormalizedString());
    assertEquals(a2.toNormalizedString(), "[]");

    toNormalizedStringBuffer = new StringBuilder();
    a2.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(), "[]");

    assertNotNull(a2.toNormalizedString(true, true, true));
    assertEquals(a2.toNormalizedString(true, true, true), "[]");

    assertNotNull(a2.toNormalizedString(false, false, false));
    assertEquals(a2.toNormalizedString(false, false, false), "[]");

    assertTrue(a1.equals(a2));
    assertTrue(a2.equals(a1));
    assertEquals(a1.hashCode(), a2.hashCode());
    assertEquals(a1.toNormalizedString(), a2.toNormalizedString());

    assertTrue(a1.equals(a2, false, false, false));
    assertTrue(a2.equals(a1, false, false, false));

    assertTrue(a1.equals(a2, false, false, true));
    assertTrue(a2.equals(a1, false, false, true));

    assertTrue(a1.equals(a2, true, true, true));
    assertTrue(a2.equals(a1, true, true, true));


    final JSONArray a3 = new JSONArray((List<JSONValue>) null);

    assertNotNull(a3.getValues());
    assertTrue(a3.getValues().isEmpty());

    assertTrue(a3.isEmpty());

    assertEquals(a3.size(), 0);

    assertFalse(a3.contains(JSONNull.NULL, false, false, false, false));
    assertFalse(a3.contains(JSONNull.NULL, true, true, true, true));

    assertNotNull(a3.toString());
    assertEquals(a3.toString(), "[ ]");

    assertNotNull(a3.toSingleLineString());
    assertEquals(a3.toSingleLineString(), "[ ]");

    toStringBuffer = new StringBuilder();
    a3.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), "[ ]");

    toSingleLineStringBuffer = new StringBuilder();
    a3.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(), "[ ]");

    assertNotNull(a3.toNormalizedString());
    assertEquals(a3.toNormalizedString(), "[]");

    toNormalizedStringBuffer = new StringBuilder();
    a3.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(), "[]");

    assertNotNull(a3.toNormalizedString(true, true, true));
    assertEquals(a3.toNormalizedString(true, true, true), "[]");

    assertNotNull(a3.toNormalizedString(false, false, false));
    assertEquals(a3.toNormalizedString(false, false, false), "[]");

    assertTrue(a1.equals(a3));
    assertTrue(a3.equals(a1));
    assertEquals(a1.hashCode(), a3.hashCode());
    assertEquals(a1.toNormalizedString(), a3.toNormalizedString());

    assertTrue(a1.equals(a3, false, false, false));
    assertTrue(a3.equals(a1, false, false, false));

    assertTrue(a1.equals(a3, false, false, true));
    assertTrue(a3.equals(a1, false, false, true));

    assertTrue(a1.equals(a3, true, true, true));
    assertTrue(a3.equals(a1, true, true, true));
  }



  /**
   * Provides test coverage for a single-element array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleElementArray()
         throws Exception
  {
    final JSONArray a1 = new JSONArray(new JSONString("foo"));

    assertNotNull(a1.getValues());
    assertEquals(a1.getValues().size(), 1);
    assertEquals(a1.getValues().get(0), new JSONString("foo"));

    assertFalse(a1.isEmpty());

    assertEquals(a1.size(), 1);

    assertTrue(a1.contains(new JSONString("foo"), false, false, false, false));
    assertTrue(a1.contains(new JSONString("foo"), true, true, true, true));

    assertFalse(a1.contains(new JSONString("Foo"), false, false, false, false));
    assertTrue(a1.contains(new JSONString("Foo"), true, true, true, true));

    assertTrue(a1.equals(a1));
    assertEquals(a1.hashCode(), a1.hashCode());
    assertEquals(a1.toNormalizedString(), a1.toNormalizedString());
    assertTrue(a1.equals(a1, false, false, false));
    assertTrue(a1.equals(a1, true, true, true));

    assertNotNull(a1.toString());
    assertEquals(a1.toString(), "[ \"foo\" ]");

    assertNotNull(a1.toSingleLineString());
    assertEquals(a1.toSingleLineString(), "[ \"foo\" ]");

    StringBuilder toStringBuffer = new StringBuilder();
    a1.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), "[ \"foo\" ]");

    StringBuilder toSingleLineStringBuffer = new StringBuilder();
    a1.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(), "[ \"foo\" ]");

    assertNotNull(a1.toNormalizedString());
    assertEquals(a1.toNormalizedString(), "[\"foo\"]");

    StringBuilder toNormalizedStringBuffer = new StringBuilder();
    a1.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(), "[\"foo\"]");

    assertNotNull(a1.toNormalizedString(true, true, true));
    assertEquals(a1.toNormalizedString(true, true, true), "[\"foo\"]");

    assertNotNull(a1.toNormalizedString(false, false, false));
    assertEquals(a1.toNormalizedString(false, false, false), "[\"foo\"]");

    final JSONBuffer jsonBuffer = new JSONBuffer();
    a1.appendToJSONBuffer(jsonBuffer);
    assertEquals(jsonBuffer.toString(), "[ \"foo\" ]");

    jsonBuffer.clear();
    a1.appendToJSONBuffer("fieldName", jsonBuffer);
    assertEquals(jsonBuffer.toString(), "\"fieldName\":[ \"foo\" ]");


    final JSONArray a2 = new JSONArray(new JSONString("bar"));

    assertNotNull(a2.getValues());
    assertEquals(a2.getValues().size(), 1);
    assertEquals(a2.getValues().get(0), new JSONString("bar"));

    assertFalse(a2.isEmpty());

    assertEquals(a2.size(), 1);

    assertTrue(a2.contains(new JSONString("bar"), false, false, false, false));
    assertTrue(a2.contains(new JSONString("bar"), true, true, true, true));

    assertFalse(a2.contains(new JSONString("Bar"), false, false, false, false));
    assertTrue(a2.contains(new JSONString("Bar"), true, true, true, true));

    assertTrue(a2.equals(a2));
    assertEquals(a2.hashCode(), a2.hashCode());
    assertEquals(a2.toNormalizedString(), a2.toNormalizedString());
    assertTrue(a2.equals(a2, false, false, false));
    assertTrue(a2.equals(a2, true, true, true));

    assertNotNull(a2.toString());
    assertEquals(a2.toString(), "[ \"bar\" ]");

    assertNotNull(a2.toSingleLineString());
    assertEquals(a2.toSingleLineString(), "[ \"bar\" ]");

    toStringBuffer = new StringBuilder();
    a2.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), "[ \"bar\" ]");

    toSingleLineStringBuffer = new StringBuilder();
    a2.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(), "[ \"bar\" ]");

    assertNotNull(a2.toNormalizedString());
    assertEquals(a2.toNormalizedString(), "[\"bar\"]");

    toNormalizedStringBuffer = new StringBuilder();
    a2.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(), "[\"bar\"]");

    assertNotNull(a2.toNormalizedString(true, true, true));
    assertEquals(a2.toNormalizedString(true, true, true), "[\"bar\"]");

    assertNotNull(a2.toNormalizedString(false, false, false));
    assertEquals(a2.toNormalizedString(false, false, false), "[\"bar\"]");

    assertFalse(a1.equals(a2));
    assertFalse(a2.equals(a1));

    assertFalse(a1.equals(a2, false, false, false));
    assertFalse(a1.equals(a2, true, true, true));


    final JSONArray a3 = new JSONArray(new JSONString("FOO"));

    assertNotNull(a3.getValues());
    assertEquals(a3.getValues().size(), 1);
    assertEquals(a3.getValues().get(0), new JSONString("FOO"));

    assertFalse(a3.isEmpty());

    assertEquals(a3.size(), 1);

    assertTrue(a3.contains(new JSONString("FOO"), false, false, false, false));
    assertTrue(a3.contains(new JSONString("FOO"), true, true, true, true));

    assertFalse(a3.contains(new JSONString("Foo"), false, false, false, false));
    assertTrue(a3.contains(new JSONString("Foo"), true, true, true, true));

    assertTrue(a3.equals(a3));
    assertEquals(a3.hashCode(), a3.hashCode());
    assertEquals(a3.toNormalizedString(), a3.toNormalizedString());
    assertTrue(a3.equals(a3, false, false, false));
    assertTrue(a3.equals(a3, true, true, true));

    assertNotNull(a3.toString());
    assertEquals(a3.toString(), "[ \"FOO\" ]");

    assertNotNull(a3.toSingleLineString());
    assertEquals(a3.toSingleLineString(), "[ \"FOO\" ]");

    toStringBuffer = new StringBuilder();
    a3.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), "[ \"FOO\" ]");

    toSingleLineStringBuffer = new StringBuilder();
    a3.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(), "[ \"FOO\" ]");

    assertNotNull(a3.toNormalizedString());
    assertEquals(a3.toNormalizedString(), "[\"foo\"]");

    toNormalizedStringBuffer = new StringBuilder();
    a3.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(), "[\"foo\"]");

    assertNotNull(a3.toNormalizedString(true, true, true));
    assertEquals(a3.toNormalizedString(true, true, true), "[\"foo\"]");

    assertNotNull(a3.toNormalizedString(false, false, false));
    assertEquals(a3.toNormalizedString(false, false, false), "[\"FOO\"]");

    assertFalse(a1.equals(a3));
    assertFalse(a3.equals(a1));

    assertFalse(a2.equals(a3));
    assertFalse(a3.equals(a2));

    assertFalse(a1.equals(a3, false, false, false));
    assertTrue(a1.equals(a3, false, true, false));
    assertTrue(a1.equals(a3, true, true, true));

    assertFalse(a3.equals(a1, false, false, false));
    assertTrue(a3.equals(a1, false, true, false));
    assertTrue(a3.equals(a1, true, true, true));
  }



  /**
   * Provides test coverage for a multi-element array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultiElementArray()
         throws Exception
  {
    final JSONArray a1 = new JSONArray(new JSONString("Foo"),
         new JSONString("Bar"), new JSONString("Baz"));

    assertNotNull(a1.getValues());
    assertEquals(a1.getValues().size(), 3);
    assertEquals(a1.getValues().get(0), new JSONString("Foo"));
    assertEquals(a1.getValues().get(1), new JSONString("Bar"));
    assertEquals(a1.getValues().get(2), new JSONString("Baz"));

    assertFalse(a1.isEmpty());

    assertEquals(a1.size(), 3);

    assertTrue(a1.contains(new JSONString("Foo"), false, false, false, false));
    assertTrue(a1.contains(new JSONString("Foo"), true, true, true, true));

    assertFalse(a1.contains(new JSONString("foo"), false, false, false, false));
    assertTrue(a1.contains(new JSONString("foo"), true, true, true, true));

    assertTrue(a1.contains(new JSONString("Bar"), false, false, false, false));
    assertTrue(a1.contains(new JSONString("Bar"), true, true, true, true));

    assertFalse(a1.contains(new JSONString("bar"), false, false, false, false));
    assertTrue(a1.contains(new JSONString("bar"), true, true, true, true));

    assertTrue(a1.contains(new JSONString("Baz"), false, false, false, false));
    assertTrue(a1.contains(new JSONString("Baz"), true, true, true, true));

    assertFalse(a1.contains(new JSONString("baz"), false, false, false, false));
    assertTrue(a1.contains(new JSONString("baz"), true, true, true, true));

    assertTrue(a1.equals(a1));
    assertEquals(a1.hashCode(), a1.hashCode());
    assertEquals(a1.toNormalizedString(), a1.toNormalizedString());
    assertTrue(a1.equals(a1, false, false, false));
    assertTrue(a1.equals(a1, true, true, true));

    assertNotNull(a1.toString());
    assertEquals(a1.toString(), "[ \"Foo\", \"Bar\", \"Baz\" ]");

    assertNotNull(a1.toSingleLineString());
    assertEquals(a1.toSingleLineString(), "[ \"Foo\", \"Bar\", \"Baz\" ]");

    StringBuilder toStringBuffer = new StringBuilder();
    a1.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), "[ \"Foo\", \"Bar\", \"Baz\" ]");

    StringBuilder toSingleLineStringBuffer = new StringBuilder();
    a1.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(),
         "[ \"Foo\", \"Bar\", \"Baz\" ]");

    assertNotNull(a1.toNormalizedString());
    assertEquals(a1.toNormalizedString(), "[\"foo\",\"bar\",\"baz\"]");

    StringBuilder toNormalizedStringBuffer = new StringBuilder();
    a1.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(),
         "[\"foo\",\"bar\",\"baz\"]");

    assertNotNull(a1.toNormalizedString(true, true, true));
    assertEquals(a1.toNormalizedString(true, true, true),
         "[\"bar\",\"baz\",\"foo\"]");

    assertNotNull(a1.toNormalizedString(false, false, false));
    assertEquals(a1.toNormalizedString(false, false, false),
         "[\"Foo\",\"Bar\",\"Baz\"]");

    final JSONBuffer jsonBuffer = new JSONBuffer();
    a1.appendToJSONBuffer(jsonBuffer);
    assertEquals(jsonBuffer.toString(), "[ \"Foo\", \"Bar\", \"Baz\" ]");

    jsonBuffer.clear();
    a1.appendToJSONBuffer("fieldName", jsonBuffer);
    assertEquals(jsonBuffer.toString(),
         "\"fieldName\":[ \"Foo\", \"Bar\", \"Baz\" ]");
  }



  /**
   * Provides test coverage for an array that embeds other arrays.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmbeddedArrays()
         throws Exception
  {
    final JSONArray a11 = new JSONArray(
         new JSONString("a"),
         new JSONString("b"),
         new JSONString("c"));
    final JSONArray a12 = new JSONArray(
         new JSONNumber(1),
         new JSONNumber(2),
         new JSONNumber(3));
    final JSONArray a1 = new JSONArray(a11, a12);

    assertNotNull(a1.getValues());
    assertEquals(a1.getValues().size(), 2);
    assertEquals(a1.getValues().get(0), a11);
    assertEquals(a1.getValues().get(1), a12);

    assertFalse(a1.isEmpty());

    assertEquals(a1.size(), 2);

    assertTrue(a1.contains(a11, false, false, false, false));
    assertTrue(a1.contains(a11, true, true, true, true));

    assertTrue(a1.contains(a12, false, false, false, false));
    assertTrue(a1.contains(a12, true, true, true, true));

    assertFalse(a1.contains(new JSONString("a"), false, false, false, false));
    assertTrue(a1.contains(new JSONString("a"), false, false, false, true));
    assertTrue(a1.contains(new JSONString("a"), true, true, true, true));

    assertFalse(a1.contains(new JSONString("A"), false, false, false, false));
    assertFalse(a1.contains(new JSONString("A"), false, false, false, true));
    assertTrue(a1.contains(new JSONString("A"), false, true, false, true));
    assertTrue(a1.contains(new JSONString("A"), true, true, true, true));

    assertTrue(a1.equals(a1));
    assertEquals(a1.hashCode(), a1.hashCode());
    assertEquals(a1.toNormalizedString(), a1.toNormalizedString());
    assertTrue(a1.equals(a1, false, false, false));
    assertTrue(a1.equals(a1, true, true, true));

    assertNotNull(a1.toString());
    assertEquals(a1.toString(), "[ [ \"a\", \"b\", \"c\" ], [ 1, 2, 3 ] ]");

    assertNotNull(a1.toSingleLineString());
    assertEquals(a1.toSingleLineString(),
         "[ [ \"a\", \"b\", \"c\" ], [ 1, 2, 3 ] ]");

    StringBuilder toStringBuffer = new StringBuilder();
    a1.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(),
         "[ [ \"a\", \"b\", \"c\" ], [ 1, 2, 3 ] ]");

    StringBuilder toSingleLineStringBuffer = new StringBuilder();
    a1.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(),
         "[ [ \"a\", \"b\", \"c\" ], [ 1, 2, 3 ] ]");

    assertNotNull(a1.toNormalizedString());
    assertEquals(a1.toNormalizedString(), "[[\"a\",\"b\",\"c\"],[1,2,3]]");

    StringBuilder toNormalizedStringBuffer = new StringBuilder();
    a1.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(),
         "[[\"a\",\"b\",\"c\"],[1,2,3]]");

    final JSONBuffer jsonBuffer = new JSONBuffer();
    a1.appendToJSONBuffer(jsonBuffer);
    assertEquals(jsonBuffer.toString(),
         "[ [ \"a\", \"b\", \"c\" ], [ 1, 2, 3 ] ]");

    jsonBuffer.clear();
    a1.appendToJSONBuffer("fieldName", jsonBuffer);
    assertEquals(jsonBuffer.toString(),
         "\"fieldName\":[ [ \"a\", \"b\", \"c\" ], [ 1, 2, 3 ] ]");


    final JSONArray a2 = new JSONArray(a11, a12);
    assertTrue(a1.equals(a2));
    assertTrue(a2.equals(a1));
    assertEquals(a1.hashCode(), a2.hashCode());
    assertEquals(a1.toNormalizedString(), a2.toNormalizedString());
    assertTrue(a1.equals(a2, false, false, false));
    assertTrue(a2.equals(a1, false, false, false));
    assertTrue(a1.equals(a2, true, true, true));
    assertTrue(a2.equals(a1, true, true, true));


    final JSONArray a3 = new JSONArray(a12, a11);
    assertFalse(a1.equals(a3));
    assertFalse(a3.equals(a1));
    assertFalse(a1.equals(a3, false, false, false));
    assertFalse(a3.equals(a1, false, false, false));
    assertTrue(a1.equals(a3, false, false, true));
    assertTrue(a3.equals(a1, false, false, true));
    assertTrue(a1.equals(a3, true, true, true));
    assertTrue(a3.equals(a1, true, true, true));
  }



  /**
   * Tests the behavior of the {@code equals} method when provided with a
   * {@code null} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNull()
         throws Exception
  {
    final JSONArray a1 = new JSONArray(new JSONString("foo"));
    assertFalse(a1.equals(null));

    final JSONArray a2 = null;
    assertFalse(a1.equals(a2));

    final String s = null;
    assertFalse(a1.equals(s));
  }



  /**
   * Tests the behavior of the {@code equals} method when provided with an
   * argument that isn't an array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNotArray()
         throws Exception
  {
    final JSONArray a1 = new JSONArray(new JSONString("foo"));
    assertFalse(a1.equals("foo"));
  }



  /**
   * Tests the behavior of the enhanced equals method for arrays that have
   * different numbers of elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsDifferentNumberOfValues()
         throws Exception
  {
    final JSONArray a1 = new JSONArray(
         new JSONString("a"),
         new JSONString("b"),
         new JSONString("c"));
    final JSONArray a2 = new JSONArray(
         new JSONString("a"),
         new JSONString("b"));

    assertFalse(a1.equals(a2));
    assertFalse(a2.equals(a1));

    assertFalse(a1.equals(a2, false, false, false));
    assertFalse(a1.equals(a2, true, true, true));

    assertFalse(a2.equals(a1, false, false, false));
    assertFalse(a2.equals(a1, true, true, true));
  }



  /**
   * Tests the behavior of the enhanced equals method for arrays that have
   * different numbers of elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsPartiallyDifferentValues()
         throws Exception
  {
    final JSONArray a1 = new JSONArray(
         new JSONString("a"),
         new JSONString("b"),
         new JSONString("c"));
    final JSONArray a2 = new JSONArray(
         new JSONString("a"),
         new JSONString("c"),
         new JSONString("B"));

    assertFalse(a1.equals(a2));
    assertFalse(a2.equals(a1));

    assertFalse(a1.equals(a2, false, false, false));
    assertFalse(a1.equals(a2, false, true, false));
    assertFalse(a1.equals(a2, false, false, true));
    assertTrue(a1.equals(a2, false, true, true));
    assertTrue(a1.equals(a2, true, true, true));

    assertFalse(a2.equals(a1, false, false, false));
    assertFalse(a2.equals(a1, false, true, false));
    assertFalse(a2.equals(a1, false, false, true));
    assertTrue(a2.equals(a1, false, true, true));
    assertTrue(a2.equals(a1, true, true, true));
  }
}
