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
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNull;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides a set of test cases for the {@code EqualsFilter} class.
 */
public final class EqualsJSONObjectFilterTestCase
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
    final EqualsJSONObjectFilter f = new EqualsJSONObjectFilter();
    assertNull(f.getField());
    assertNull(f.getValue());
    assertFalse(f.caseSensitive());
  }



  /**
   * Provides test coverage for the case in which a filter references a
   * top-level field and a string value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTopLevelFieldString()
         throws Exception
  {
    EqualsJSONObjectFilter f =
         new EqualsJSONObjectFilter("top-level-field", new JSONString("foo"));

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "equals"),
              new JSONField("field", "top-level-field"),
              new JSONField("value", "foo")));

    f = (EqualsJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(),
         Collections.singletonList("top-level-field"));

    assertNotNull(f.getValue());
    assertEquals(f.getValue(), new JSONString("foo"));

    assertFalse(f.caseSensitive());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "equals");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Arrays.asList("field", "value")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Collections.singletonList("caseSensitive")));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", "foo"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", "Foo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("Top-Level-Field", "foo"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONString("foo"), new JSONString("bar"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONString("Bar"), new JSONString("Foo"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", 1234))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONNumber(1234), new JSONNumber(5678))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONNumber(1234), new JSONNumber(5678),
              new JSONString("foo"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", true))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", false))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", JSONNull.NULL))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", JSONArray.EMPTY_ARRAY))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", JSONObject.EMPTY_OBJECT))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONObject(
              new JSONField("top-level-field", "foo"))))));


    f.setCaseSensitive(true);
    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "equals"),
              new JSONField("field", "top-level-field"),
              new JSONField("value", "foo"),
              new JSONField("caseSensitive", true)));

    f = (EqualsJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(),
         Collections.singletonList("top-level-field"));

    assertNotNull(f.getValue());
    assertEquals(f.getValue(), new JSONString("foo"));

    assertTrue(f.caseSensitive());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "equals");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Arrays.asList("field", "value")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Collections.singletonList("caseSensitive")));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", "foo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", "Foo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("Top-Level-Field", "foo"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONString("foo"), new JSONString("bar"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONString("Bar"), new JSONString("Foo"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", 1234))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONNumber(1234), new JSONNumber(5678))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONNumber(1234), new JSONNumber(5678),
              new JSONString("foo"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", true))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", false))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", JSONNull.NULL))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", JSONArray.EMPTY_ARRAY))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", JSONObject.EMPTY_OBJECT))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONObject(
              new JSONField("top-level-field", "foo"))))));
  }



  /**
   * Provides test coverage for the case in which a filter references a
   * top-level field and a Boolean value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTopLevelFieldBoolean()
         throws Exception
  {
    EqualsJSONObjectFilter f =
         new EqualsJSONObjectFilter("top-level-field", JSONBoolean.TRUE);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "equals"),
              new JSONField("field", "top-level-field"),
              new JSONField("value", true)));

    f = (EqualsJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(),
         Collections.singletonList("top-level-field"));

    assertNotNull(f.getValue());
    assertEquals(f.getValue(), new JSONBoolean(true));

    assertFalse(f.caseSensitive());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "equals");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Arrays.asList("field", "value")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Collections.singletonList("caseSensitive")));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", true))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", false))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              JSONBoolean.TRUE, JSONBoolean.FALSE)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              JSONBoolean.FALSE, JSONBoolean.TRUE)))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONObject(
              new JSONField("top-level-field", true))))));


    f = new EqualsJSONObjectFilter("top-level-field", JSONBoolean.FALSE);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "equals"),
              new JSONField("field", "top-level-field"),
              new JSONField("value", false)));

    f = (EqualsJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(),
         Collections.singletonList("top-level-field"));

    assertNotNull(f.getValue());
    assertEquals(f.getValue(), new JSONBoolean(false));

    assertFalse(f.caseSensitive());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "equals");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Arrays.asList("field", "value")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Collections.singletonList("caseSensitive")));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", true))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", false))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              JSONBoolean.TRUE, JSONBoolean.FALSE)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              JSONBoolean.FALSE, JSONBoolean.TRUE)))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONObject(
              new JSONField("top-level-field", true))))));
  }



  /**
   * Provides test coverage for the case in which a filter references a
   * top-level field and a {@code JSONNumber} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTopLevelFieldNumber()
         throws Exception
  {
    EqualsJSONObjectFilter f =
         new EqualsJSONObjectFilter("top-level-field", new JSONNumber(1234));

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "equals"),
              new JSONField("field", "top-level-field"),
              new JSONField("value", 1234)));

    f = (EqualsJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(),
         Collections.singletonList("top-level-field"));

    assertNotNull(f.getValue());
    assertEquals(f.getValue(), new JSONNumber(1234));

    assertFalse(f.caseSensitive());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "equals");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Arrays.asList("field", "value")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Collections.singletonList("caseSensitive")));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", 1234))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", 1234.0))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", 5678))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONNumber("1234.0"), new JSONNumber("5678"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONNumber("5678"), new JSONNumber("1.234e3"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONObject(
              new JSONField("top-level-field", new JSONNumber(1234)))))));
  }



  /**
   * Provides test coverage for the case in which a filter references a
   * top-level field and a {@code JSONNull} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTopLevelFieldNull()
         throws Exception
  {
    EqualsJSONObjectFilter f =
         new EqualsJSONObjectFilter("top-level-field", JSONNull.NULL);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "equals"),
              new JSONField("field", "top-level-field"),
              new JSONField("value", JSONNull.NULL)));

    f = (EqualsJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(),
         Collections.singletonList("top-level-field"));

    assertNotNull(f.getValue());
    assertEquals(f.getValue(), JSONNull.NULL);

    assertFalse(f.caseSensitive());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "equals");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Arrays.asList("field", "value")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Collections.singletonList("caseSensitive")));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", JSONNull.NULL))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONNull()))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              JSONNull.NULL, JSONBoolean.TRUE)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              JSONBoolean.TRUE, JSONNull.NULL)))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONObject(
              new JSONField("top-level-field", JSONNull.NULL))))));
  }



  /**
   * Provides test coverage for the case in which a filter references a
   * top-level field and an array value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTopLevelFieldArray()
         throws Exception
  {
    EqualsJSONObjectFilter f =
         new EqualsJSONObjectFilter("top-level-field", new JSONArray(
              new JSONString("foo"),
              new JSONNumber(1234),
              JSONBoolean.TRUE,
              JSONNull.NULL));

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "equals"),
              new JSONField("field", "top-level-field"),
              new JSONField("value", new JSONArray(
                   new JSONString("foo"),
                   new JSONNumber(1234),
                   JSONBoolean.TRUE,
                   JSONNull.NULL))));

    f = (EqualsJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(),
         Collections.singletonList("top-level-field"));

    assertNotNull(f.getValue());
    assertEquals(f.getValue(),
         new JSONArray(
              new JSONString("foo"),
              new JSONNumber(1234),
              JSONBoolean.TRUE,
              JSONNull.NULL));

    assertFalse(f.caseSensitive());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "equals");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Arrays.asList("field", "value")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Collections.singletonList("caseSensitive")));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", "foo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", 1234))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", true))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", JSONNull.NULL))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONString("foo"),
              new JSONNumber(1234),
              JSONBoolean.TRUE,
              JSONNull.NULL)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONString("FOO"),
              new JSONNumber(1234),
              JSONBoolean.TRUE,
              JSONNull.NULL)))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              JSONNull.NULL,
              JSONBoolean.TRUE,
              new JSONNumber(1234),
              new JSONString("foo"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONString("bar"),
              new JSONArray(
                   new JSONString("foo"),
                   new JSONNumber(1234),
                   JSONBoolean.TRUE,
                   JSONNull.NULL))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONObject(
              new JSONField("top-level-field", new JSONArray(
                   new JSONString("foo"),
                   new JSONNumber(1234),
                   JSONBoolean.TRUE,
                   JSONNull.NULL)))))));

    f.setCaseSensitive(true);
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONString("foo"),
              new JSONNumber(1234),
              JSONBoolean.TRUE,
              JSONNull.NULL)))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONString("FOO"),
              new JSONNumber(1234),
              JSONBoolean.TRUE,
              JSONNull.NULL)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONString("bar"),
              new JSONArray(
                   new JSONString("foo"),
                   new JSONNumber(1234),
                   JSONBoolean.TRUE,
                   JSONNull.NULL))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONString("bar"),
              new JSONArray(
                   new JSONString("Foo"),
                   new JSONNumber(1234),
                   JSONBoolean.TRUE,
                   JSONNull.NULL))))));
  }



  /**
   * Provides test coverage for the case in which a filter references a
   * top-level field and an object value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTopLevelFieldObject()
         throws Exception
  {
    EqualsJSONObjectFilter f =
         new EqualsJSONObjectFilter("top-level-field", new JSONObject(
              new JSONField("a", true),
              new JSONField("b", false)));

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "equals"),
              new JSONField("field", "top-level-field"),
              new JSONField("value", new JSONObject(
                   new JSONField("a", true),
                   new JSONField("b", false)))));

    f = (EqualsJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(),
         Collections.singletonList("top-level-field"));

    assertNotNull(f.getValue());
    assertEquals(f.getValue(),
         new JSONObject(
              new JSONField("a", true),
              new JSONField("b", false)));

    assertFalse(f.caseSensitive());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "equals");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Arrays.asList("field", "value")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Collections.singletonList("caseSensitive")));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", true),
         new JSONField("b", false))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONObject(
              new JSONField("a", true),
              new JSONField("b", false))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONObject(
              new JSONField("b", false),
              new JSONField("a", true))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONObject(
              new JSONField("a", false),
              new JSONField("b", true))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONObject(
                   new JSONField("a", true),
                   new JSONField("b", false)),
              new JSONObject(
                   new JSONField("a", "foo"),
                   new JSONField("b", "bar")))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONObject(
                   new JSONField("a", "foo"),
                   new JSONField("b", "bar")),
              new JSONObject(
                   new JSONField("a", true),
                   new JSONField("b", false)))))));
  }



  /**
   * Provides test coverage for the case in which a filter references a
   * non-top-level-field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultiLevelFields()
         throws Exception
  {
    EqualsJSONObjectFilter f = new EqualsJSONObjectFilter(
         Arrays.asList("top-level-field", "second-level-field"),
         new JSONString("foo"));

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "equals"),
              new JSONField("field", new JSONArray(
                   new JSONString("top-level-field"),
                   new JSONString("second-level-field"))),
              new JSONField("value", "foo")));

    f = (EqualsJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(),
         Arrays.asList("top-level-field", "second-level-field"));

    assertNotNull(f.getValue());
    assertEquals(f.getValue(), new JSONString("foo"));

    assertFalse(f.caseSensitive());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "equals");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Arrays.asList("field", "value")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Collections.singletonList("caseSensitive")));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", "foo"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONObject(
              new JSONField("second-level-field", "foo"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONObject(
              new JSONField("second-level-field", "FOO"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONObject(
              new JSONField("second-level-field", "bar"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONObject(new JSONField("second-level-field", "foo")),
              new JSONObject(new JSONField("second-level-field", "bar")))))));


    f = new EqualsJSONObjectFilter(
         Arrays.asList("top-level-field", "second-level-field",
              "third-level-field"),
         new JSONString("foo"));
    f.setCaseSensitive(true);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "equals"),
              new JSONField("field", new JSONArray(
                   new JSONString("top-level-field"),
                   new JSONString("second-level-field"),
                   new JSONString("third-level-field"))),
              new JSONField("value", "foo"),
              new JSONField("caseSensitive", true)));

    f = (EqualsJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(),
         Arrays.asList("top-level-field", "second-level-field",
              "third-level-field"));

    assertNotNull(f.getValue());
    assertEquals(f.getValue(), new JSONString("foo"));

    assertTrue(f.caseSensitive());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "equals");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Arrays.asList("field", "value")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Collections.singletonList("caseSensitive")));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", "foo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONObject(
              new JSONField("second-level-field", "foo"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONObject(
              new JSONField("second-level-field", new JSONObject(
                   new JSONField("third-level-field", "foo"))))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONObject(
              new JSONField("second-level-field", new JSONObject(
                   new JSONField("third-level-field", "FOO"))))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONObject(new JSONField(
                   "second-level-field", new JSONObject(
                   new JSONField("third-level-field", "foo")))),
              new JSONObject(new JSONField(
                   "second-level-field", new JSONObject(
                   new JSONField("third-level-field", "bar")))))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONObject(
                   new JSONField("second-level-field", new JSONArray(
                        new JSONObject(new JSONField("third-level-field",
                             "foo"))))),
              new JSONObject(
                   new JSONField("second-level-field", new JSONArray(
                        new JSONObject(new JSONField("third-level-field",
                             "bar"))))))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONObject(
                   new JSONField("second-level-field", new JSONArray(
                        new JSONObject(new JSONField("third-level-field",
                             new JSONArray(new JSONString("foo"))))))),
              new JSONObject(
                   new JSONField("second-level-field", new JSONArray(
                        new JSONObject(new JSONField("third-level-field",
                             new JSONArray(new JSONString("bar"))))))))))));
  }



  /**
   * Provides test coverage for the methods that can be used to get and set the
   * target field for a filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetField()
         throws Exception
  {
    final EqualsJSONObjectFilter f =
         new EqualsJSONObjectFilter("test-field-name", JSONNull.NULL);
    assertNotNull(f.getField());
    assertEquals(f.getField(),
         Collections.singletonList("test-field-name"));

    f.setField("different-field-name");
    assertNotNull(f.getField());
    assertEquals(f.getField(),
         Collections.singletonList("different-field-name"));

    f.setField("first", "second", "third");
    assertNotNull(f.getField());
    assertEquals(f.getField(),
         Arrays.asList("first", "second", "third"));

    try
    {
      f.setField();
      fail("Expected an exception with setField of empty");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected
    }
  }



  /**
   * Provides test coverage for the methods that can be used to get and set the
   * target value for a filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetValue()
         throws Exception
  {
    final EqualsJSONObjectFilter f =
         new EqualsJSONObjectFilter("test-field-name", JSONNull.NULL);
    assertNotNull(f.getValue());

    f.setValue(new JSONString("foo"));
    assertNotNull(f.getValue());
    assertEquals(f.getValue(), new JSONString("foo"));

    f.setValue("bar");
    assertNotNull(f.getValue());
    assertEquals(f.getValue(), new JSONString("bar"));

    f.setValue(JSONBoolean.TRUE);
    assertNotNull(f.getValue());
    assertEquals(f.getValue(), JSONBoolean.TRUE);

    f.setValue(false);
    assertNotNull(f.getValue());
    assertEquals(f.getValue(), JSONBoolean.FALSE);

    f.setValue(1234);
    assertNotNull(f.getValue());
    assertEquals(f.getValue(), new JSONNumber(1234));

    f.setValue(true);
    assertNotNull(f.getValue());
    assertEquals(f.getValue(), JSONBoolean.TRUE);

    f.setValue(1234.5);
    assertNotNull(f.getValue());
    assertEquals(f.getValue(), new JSONNumber(1234.5));
  }



  /**
   * Provides test coverage for the convenience constructors that can be used to
   * create an equals filter without having to provide a JSONValue as the value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConvenienceConstructors()
         throws Exception
  {
    assertEquals(
         new EqualsJSONObjectFilter("foo", "bar"),
         new EqualsJSONObjectFilter("foo", new JSONString("bar")));

    assertEquals(
         new EqualsJSONObjectFilter("foo", true),
         new EqualsJSONObjectFilter("foo", JSONBoolean.TRUE));

    assertEquals(
         new EqualsJSONObjectFilter("foo", false),
         new EqualsJSONObjectFilter("foo", JSONBoolean.FALSE));

    assertEquals(
         new EqualsJSONObjectFilter("foo", 1234),
         new EqualsJSONObjectFilter("foo", new JSONNumber(1234)));

    assertEquals(
         new EqualsJSONObjectFilter("foo", 1234.5),
         new EqualsJSONObjectFilter("foo", new JSONNumber(1234.5)));
  }
}
