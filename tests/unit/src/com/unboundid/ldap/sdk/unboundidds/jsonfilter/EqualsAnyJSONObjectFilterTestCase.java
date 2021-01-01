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
package com.unboundid.ldap.sdk.unboundidds.jsonfilter;



import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONException;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNull;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;



/**
 * This class provides a set of test cases for the {@code EqualsAnyFilter}
 * class.
 */
public final class EqualsAnyJSONObjectFilterTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the default constructor.  This constructor is
   * invoked by a static block in the {@code JSONObjectFilter} class, but
   * EMMA doesn't register that for some reason.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInternalConstructor()
         throws Exception
  {
    final EqualsAnyJSONObjectFilter f = new EqualsAnyJSONObjectFilter();
    assertNull(f.getField());
    assertNull(f.getValues());
    assertFalse(f.caseSensitive());
  }



  /**
   * Tests the behavior of the equals any filter with a number of cases and
   * values specified in an array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsAnyArray()
         throws Exception
  {
    EqualsAnyJSONObjectFilter f = new EqualsAnyJSONObjectFilter("test-field",
         new JSONString("foo"), new JSONString("bar"), new JSONNumber(1234),
         JSONBoolean.TRUE, JSONNull.NULL, JSONArray.EMPTY_ARRAY,
         JSONObject.EMPTY_OBJECT);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "equalsAny"),
              new JSONField("field", "test-field"),
              new JSONField("values", new JSONArray(
                   new JSONString("foo"),
                   new JSONString("bar"),
                   new JSONNumber(1234),
                   JSONBoolean.TRUE,
                   JSONNull.NULL,
                   JSONArray.EMPTY_ARRAY,
                   JSONObject.EMPTY_OBJECT))));

    f = (EqualsAnyJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(), Collections.singletonList("test-field"));

    assertNotNull(f.getValues());
    assertEquals(f.getValues(),
         Arrays.asList(new JSONString("foo"), new JSONString("bar"),
              new JSONNumber(1234), JSONBoolean.TRUE, JSONNull.NULL,
              JSONArray.EMPTY_ARRAY, JSONObject.EMPTY_OBJECT));

    assertFalse(f.caseSensitive());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "equalsAny");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Arrays.asList("field", "values")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Collections.singletonList("caseSensitive")));

    assertFalse(f.matchesJSONObject(JSONObject.EMPTY_OBJECT));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "foo"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FOO"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "bar"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "baz"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 1234))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", true))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", JSONNull.NULL))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", JSONArray.EMPTY_ARRAY))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", JSONObject.EMPTY_OBJECT))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("Test-Field", "foo"))));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(new JSONString("foo"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(new JSONString("FOO"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(new JSONString("bar"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(new JSONString("baz"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(new JSONNumber(1234))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(JSONBoolean.TRUE)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(JSONNull.NULL)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(JSONArray.EMPTY_ARRAY)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(JSONObject.EMPTY_OBJECT)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("foo"),
              new JSONString("bar"),
              new JSONNumber(1234),
              JSONBoolean.TRUE,
              JSONNull.NULL,
              JSONArray.EMPTY_ARRAY,
              JSONObject.EMPTY_OBJECT)))));


    f.setCaseSensitive(true);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "equalsAny"),
              new JSONField("field", "test-field"),
              new JSONField("values", new JSONArray(
                   new JSONString("foo"),
                   new JSONString("bar"),
                   new JSONNumber(1234),
                   JSONBoolean.TRUE,
                   JSONNull.NULL,
                   JSONArray.EMPTY_ARRAY,
                   JSONObject.EMPTY_OBJECT)),
              new JSONField("caseSensitive", true)));

    f = (EqualsAnyJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertTrue(f.caseSensitive());

    assertFalse(f.matchesJSONObject(JSONObject.EMPTY_OBJECT));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "foo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FOO"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "bar"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "baz"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 1234))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", true))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", JSONNull.NULL))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", JSONArray.EMPTY_ARRAY))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", JSONObject.EMPTY_OBJECT))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("Test-Field", "foo"))));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(new JSONString("foo"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(new JSONString("FOO"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(new JSONString("bar"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(new JSONString("baz"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(new JSONNumber(1234))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(JSONBoolean.TRUE)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(JSONNull.NULL)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(JSONArray.EMPTY_ARRAY)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(JSONObject.EMPTY_OBJECT)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("foo"),
                   new JSONString("bar"),
                   new JSONNumber(1234),
                   JSONBoolean.TRUE,
                   JSONNull.NULL,
                   JSONArray.EMPTY_ARRAY,
                   JSONObject.EMPTY_OBJECT)))));
  }



  /**
   * Tests the behavior of the equals any filter with a number of cases and
   * values specified in a list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsAnyList()
         throws Exception
  {
    EqualsAnyJSONObjectFilter f = new EqualsAnyJSONObjectFilter("test-field",
         Arrays.asList(new JSONString("foo"), new JSONString("bar"),
              new JSONNumber(1234), JSONBoolean.TRUE, JSONNull.NULL,
              JSONArray.EMPTY_ARRAY, JSONObject.EMPTY_OBJECT));

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "equalsAny"),
              new JSONField("field", "test-field"),
              new JSONField("values", new JSONArray(
                   new JSONString("foo"),
                   new JSONString("bar"),
                   new JSONNumber(1234),
                   JSONBoolean.TRUE,
                   JSONNull.NULL,
                   JSONArray.EMPTY_ARRAY,
                   JSONObject.EMPTY_OBJECT))));

    f = (EqualsAnyJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(), Collections.singletonList("test-field"));

    assertNotNull(f.getValues());
    assertEquals(f.getValues(),
         Arrays.asList(new JSONString("foo"), new JSONString("bar"),
              new JSONNumber(1234), JSONBoolean.TRUE, JSONNull.NULL,
              JSONArray.EMPTY_ARRAY, JSONObject.EMPTY_OBJECT));

    assertFalse(f.caseSensitive());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "equalsAny");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Arrays.asList("field", "values")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Collections.singletonList("caseSensitive")));

    assertFalse(f.matchesJSONObject(JSONObject.EMPTY_OBJECT));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "foo"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FOO"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "bar"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "baz"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 1234))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", true))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", JSONNull.NULL))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", JSONArray.EMPTY_ARRAY))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", JSONObject.EMPTY_OBJECT))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("Test-Field", "foo"))));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(new JSONString("foo"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(new JSONString("FOO"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(new JSONString("bar"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(new JSONString("baz"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(new JSONNumber(1234))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(JSONBoolean.TRUE)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(JSONNull.NULL)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(JSONArray.EMPTY_ARRAY)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(JSONObject.EMPTY_OBJECT)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("foo"),
              new JSONString("bar"),
              new JSONNumber(1234),
              JSONBoolean.TRUE,
              JSONNull.NULL,
              JSONArray.EMPTY_ARRAY,
              JSONObject.EMPTY_OBJECT)))));


    f.setCaseSensitive(true);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "equalsAny"),
              new JSONField("field", "test-field"),
              new JSONField("values", new JSONArray(
                   new JSONString("foo"),
                   new JSONString("bar"),
                   new JSONNumber(1234),
                   JSONBoolean.TRUE,
                   JSONNull.NULL,
                   JSONArray.EMPTY_ARRAY,
                   JSONObject.EMPTY_OBJECT)),
              new JSONField("caseSensitive", true)));

    f = (EqualsAnyJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertTrue(f.caseSensitive());

    assertFalse(f.matchesJSONObject(JSONObject.EMPTY_OBJECT));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "foo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FOO"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "bar"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "baz"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 1234))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", true))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", JSONNull.NULL))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", JSONArray.EMPTY_ARRAY))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", JSONObject.EMPTY_OBJECT))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("Test-Field", "foo"))));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(new JSONString("foo"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(new JSONString("FOO"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(new JSONString("bar"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(new JSONString("baz"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(new JSONNumber(1234))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(JSONBoolean.TRUE)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(JSONNull.NULL)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(JSONArray.EMPTY_ARRAY)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(JSONObject.EMPTY_OBJECT)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("foo"),
                   new JSONString("bar"),
                   new JSONNumber(1234),
                   JSONBoolean.TRUE,
                   JSONNull.NULL,
                   JSONArray.EMPTY_ARRAY,
                   JSONObject.EMPTY_OBJECT)))));
  }



  /**
   * Provides test coverage for the methods that can be used to get and set the
   * target field name for a filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetField()
         throws Exception
  {
    final EqualsAnyJSONObjectFilter f =
         new EqualsAnyJSONObjectFilter("test-field-name", JSONNull.NULL);
    assertNotNull(f.getField());
    assertEquals(f.getField(),
         Collections.singletonList("test-field-name"));
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "equalsAny"),
              new JSONField("field", "test-field-name"),
              new JSONField("values", new JSONArray(JSONNull.NULL))));

    f.setField("different-field-name");
    assertNotNull(f.getField());
    assertEquals(f.getField(),
         Collections.singletonList("different-field-name"));
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "equalsAny"),
              new JSONField("field", "different-field-name"),
              new JSONField("values", new JSONArray(JSONNull.NULL))));

    f.setField("first", "second", "third");
    assertNotNull(f.getField());
    assertEquals(f.getField(), Arrays.asList("first", "second", "third"));
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "equalsAny"),
              new JSONField("field", new JSONArray(
                   new JSONString("first"),
                   new JSONString("second"),
                   new JSONString("third"))),
              new JSONField("values", new JSONArray(JSONNull.NULL))));

    try
    {
      f.setField();
      fail("Expected an exception with setFieldName of empty");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected
    }
  }



  /**
   * Provides test coverage for the methods that can be used to get and set the
   * target values for a filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetValues()
         throws Exception
  {
    final EqualsAnyJSONObjectFilter f =
         new EqualsAnyJSONObjectFilter("test-field-name", JSONNull.NULL);
    assertNotNull(f.getValues());
    assertEquals(f.getValues(),
         Collections.<JSONValue>singletonList(JSONNull.NULL));

    f.setValues(new JSONString("foo"));
    assertNotNull(f.getValues());
    assertEquals(f.getValues(),
         Collections.<JSONValue>singletonList(new JSONString("foo")));

    f.setValues(new JSONString("foo"), new JSONString("bar"));
    assertNotNull(f.getValues());
    assertEquals(f.getValues(),
         Arrays.<JSONValue>asList(new JSONString("foo"),
              new JSONString("bar")));

    f.setValues("abc", "def", "ghi");
    assertNotNull(f.getValues());
    assertEquals(f.getValues(),
         Arrays.<JSONValue>asList(new JSONString("abc"),
              new JSONString("def"), new JSONString("ghi")));

    try
    {
      f.setValues(new JSONValue[0]);
      fail("Expected an exception with setValues of empty");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected
    }
  }



  /**
   * Tests the behavior of the decode method when the values element is not an
   * array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { JSONException.class })
  public void testDecodeValuesNotArray()
         throws Exception
  {
    JSONObjectFilter.decode(new JSONObject(
         new JSONField("filterType", "equalsAny"),
         new JSONField("field", "test-field"),
         new JSONField("values", "foo")));
  }



  /**
   * Provides test coverage for the convenience constructors that can be used to
   * create an equalsAny filter without having to provide a list of
   * {@code JSONValue} objects.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConvenienceConstructor()
         throws Exception
  {
    assertEquals(
         new EqualsAnyJSONObjectFilter("foo", "bar", "baz"),
         new EqualsAnyJSONObjectFilter("foo", new JSONString("bar"),
              new JSONString("baz")));
  }
}
