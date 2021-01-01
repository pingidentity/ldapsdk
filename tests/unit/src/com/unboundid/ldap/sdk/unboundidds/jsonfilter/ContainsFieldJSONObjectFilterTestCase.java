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
import java.util.EnumSet;
import java.util.HashSet;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONException;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNull;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides a set of test cases for the {@code ContainsFieldFilter}
 * class.
 */
public final class ContainsFieldJSONObjectFilterTestCase
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
    final ContainsFieldJSONObjectFilter f = new ContainsFieldJSONObjectFilter();
    assertNull(f.getField());
    assertNull(f.getExpectedType());
  }



  /**
   * Tests the behavior of this filter for a top-level field without an
   * expected type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTopLevelFieldWithoutExpectedType()
         throws Exception
  {
    ContainsFieldJSONObjectFilter f =
         new ContainsFieldJSONObjectFilter("top-level-field");

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "containsField"),
              new JSONField("field", "top-level-field")));

    assertNotNull(JSONObjectFilter.decode(f.toJSONObject()));
    assertTrue(JSONObjectFilter.decode(f.toJSONObject()) instanceof
         ContainsFieldJSONObjectFilter);
    f = (ContainsFieldJSONObjectFilter)
         JSONObjectFilter.decode(f.toJSONObject());

    assertNotNull(f.getField());
    assertFalse(f.getField().isEmpty());
    assertEquals(f.getField(),
         Collections.singletonList("top-level-field"));

    assertNotNull(f.getExpectedType());
    assertEquals(f.getExpectedType(), EnumSet.allOf(ExpectedValueType.class));

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "containsField");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Collections.singletonList("field")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Collections.singletonList("expectedType")));

    assertNotNull(f.toString());

    final StringBuilder toStringBuffer = new StringBuilder();
    f.toString(toStringBuffer);
    assertTrue(toStringBuffer.length() > 0);

    assertEquals(toStringBuffer.toString(), f.toString());

    final JSONObject toJSONObject = f.toJSONObject();
    final JSONObject toStringObject = new JSONObject(f.toString());
    assertEquals(toStringObject, toJSONObject);

    assertFalse(f.matchesJSONObject(new JSONObject()));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", 1234))));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", "foo"))));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field",
              new JSONArray(new JSONString("foo"), new JSONString("bar"))))));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", 1234),
         new JSONField("another-top-level-field", 5678))));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("embeddedObject", new JSONObject(
              new JSONField("top-level-field", false))))));
  }



  /**
   * Tests the behavior of this filter for a top-level field with an expected
   * type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTopLevelFieldWithExpectedType()
         throws Exception
  {
    ContainsFieldJSONObjectFilter f =
         new ContainsFieldJSONObjectFilter("top-level-field");
    f.setExpectedType(ExpectedValueType.NON_EMPTY_ARRAY,
         ExpectedValueType.STRING);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "containsField"),
              new JSONField("field", "top-level-field"),
              new JSONField("expectedType", new JSONArray(
                   new JSONString("non-empty-array"),
                   new JSONString("string")))));

    assertNotNull(JSONObjectFilter.decode(f.toJSONObject()));
    assertTrue(JSONObjectFilter.decode(f.toJSONObject()) instanceof
         ContainsFieldJSONObjectFilter);
    f = (ContainsFieldJSONObjectFilter)
         JSONObjectFilter.decode(f.toJSONObject());

    assertNotNull(f.getField());
    assertFalse(f.getField().isEmpty());
    assertEquals(f.getField(),
         Collections.singletonList("top-level-field"));

    assertNotNull(f.getExpectedType());
    assertEquals(f.getExpectedType(),
         EnumSet.of(ExpectedValueType.NON_EMPTY_ARRAY,
              ExpectedValueType.STRING));

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "containsField");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Collections.singletonList("field")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Collections.singletonList("expectedType")));

    assertNotNull(f.toString());

    final StringBuilder toStringBuffer = new StringBuilder();
    f.toString(toStringBuffer);
    assertTrue(toStringBuffer.length() > 0);

    assertEquals(toStringBuffer.toString(), f.toString());

    final JSONObject toJSONObject = f.toJSONObject();
    final JSONObject toStringObject = new JSONObject(f.toString());
    assertEquals(toStringObject, toJSONObject);

    assertFalse(f.matchesJSONObject(new JSONObject()));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", 1234))));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", "foo"))));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field",
              new JSONArray(new JSONString("foo"), new JSONString("bar"))))));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", "foo"),
         new JSONField("another-top-level-field", 5678))));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("embeddedObject", new JSONObject(
              new JSONField("top-level-field", false))))));
  }



  /**
   * Tests the behavior of this filter for a second-level field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecondLevelField()
         throws Exception
  {
    ContainsFieldJSONObjectFilter f =
         new ContainsFieldJSONObjectFilter("top-level-field",
         "second-level-field");
    f.setExpectedType(ExpectedValueType.STRING);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "containsField"),
              new JSONField("field",
                   new JSONArray(new JSONString("top-level-field"),
                        new JSONString("second-level-field"))),
              new JSONField("expectedType", "string")));

    assertNotNull(JSONObjectFilter.decode(f.toJSONObject()));
    assertTrue(JSONObjectFilter.decode(f.toJSONObject()) instanceof
         ContainsFieldJSONObjectFilter);
    f = (ContainsFieldJSONObjectFilter)
         JSONObjectFilter.decode(f.toJSONObject());

    assertNotNull(f.getField());
    assertFalse(f.getField().isEmpty());
    assertEquals(f.getField(),
         Arrays.asList("top-level-field", "second-level-field"));

    assertNotNull(f.getExpectedType());
    assertEquals(f.getExpectedType(), EnumSet.of(ExpectedValueType.STRING));

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "containsField");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Collections.singletonList("field")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Collections.singletonList("expectedType")));

    assertNotNull(f.toString());

    final StringBuilder toStringBuffer = new StringBuilder();
    f.toString(toStringBuffer);
    assertTrue(toStringBuffer.length() > 0);

    assertEquals(toStringBuffer.toString(), f.toString());

    final JSONObject toJSONObject = f.toJSONObject();
    final JSONObject toStringObject = new JSONObject(f.toString());
    assertEquals(toStringObject, toJSONObject);

    assertFalse(f.matchesJSONObject(new JSONObject()));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", "foo"))));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("second-level-field", "foo"))));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field",
              new JSONArray(new JSONString("second-level-field"))))));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONObject(
              new JSONField("second-level-field", "foo"))))));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONObject(
              new JSONField("second-level-field", 1234))))));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("second-level-field", new JSONObject(
              new JSONField("second-level-field", "foo"))))));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONObject(new JSONField("second-level-field", "foo")),
              new JSONObject(new JSONField("second-level-field", "bar")))))));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONObject(new JSONField("some-other-field", "foo")),
              new JSONObject(new JSONField("second-level-field", "bar")))))));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONObject(new JSONField("some-other-field", "foo")),
              new JSONObject(new JSONField("another-field", "bar")))))));
  }



  /**
   * Tests the behavior of this filter for a third-level field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testThirdLevelField()
         throws Exception
  {
    ContainsFieldJSONObjectFilter f =
         new ContainsFieldJSONObjectFilter("top-level-field",
         "second-level-field", "third-level-field");
    f.setExpectedType(ExpectedValueType.BOOLEAN);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "containsField"),
              new JSONField("field",
                   new JSONArray(new JSONString("top-level-field"),
                        new JSONString("second-level-field"),
                        new JSONString("third-level-field"))),
              new JSONField("expectedType", "boolean")));

    assertNotNull(JSONObjectFilter.decode(f.toJSONObject()));
    assertTrue(JSONObjectFilter.decode(f.toJSONObject()) instanceof
         ContainsFieldJSONObjectFilter);
    f = (ContainsFieldJSONObjectFilter)
         JSONObjectFilter.decode(f.toJSONObject());

    assertNotNull(f.getField());
    assertFalse(f.getField().isEmpty());
    assertEquals(f.getField(),
         Arrays.asList("top-level-field", "second-level-field",
              "third-level-field"));

    assertNotNull(f.getExpectedType());
    assertEquals(f.getExpectedType(), EnumSet.of(ExpectedValueType.BOOLEAN));

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "containsField");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Collections.singletonList("field")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Collections.singletonList("expectedType")));

    assertNotNull(f.toString());

    final StringBuilder toStringBuffer = new StringBuilder();
    f.toString(toStringBuffer);
    assertTrue(toStringBuffer.length() > 0);

    assertEquals(toStringBuffer.toString(), f.toString());

    final JSONObject toJSONObject = f.toJSONObject();
    final JSONObject toStringObject = new JSONObject(f.toString());
    assertEquals(toStringObject, toJSONObject);

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONObject(
              new JSONField("second-level-field", new JSONObject(
                   new JSONField("third-level-field", true))))))));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONObject(
              new JSONField("second-level-field", new JSONObject(
                   new JSONField("third-level-field", "not boolean"))))))));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("top-level-field", new JSONArray(
              new JSONObject(new JSONField("second-level-field", new JSONArray(
                   new JSONObject(new JSONField("third-level-field",
                        true))))))))));
  }



  /**
   * Provides test coverage for the methods used to get and set the target
   * field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetField()
         throws Exception
  {
    ContainsFieldJSONObjectFilter f =
         new ContainsFieldJSONObjectFilter("field-name");
    assertEquals(f.getField(), Collections.singletonList("field-name"));
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "containsField"),
              new JSONField("field", "field-name")));

    f.setField("different-name");
    assertEquals(f.getField(), Collections.singletonList("different-name"));
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "containsField"),
              new JSONField("field", "different-name")));

    f.setField("first", "second");
    assertEquals(f.getField(), Arrays.asList("first", "second"));
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "containsField"),
              new JSONField("field", new JSONArray(
                   new JSONString("first"), new JSONString("second")))));

    try
    {
      f.setField();
      fail("Expected an exception from setField()");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the methods used to get and set the target
   * expected data type(s).
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetExpectedType()
         throws Exception
  {
    ContainsFieldJSONObjectFilter f =
         new ContainsFieldJSONObjectFilter("field-name");
    assertEquals(f.getExpectedType(), EnumSet.allOf(ExpectedValueType.class));
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "containsField"),
              new JSONField("field", "field-name")));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", "foo"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", true))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", false))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", 1234))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", JSONNull.NULL))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray()))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray(JSONBoolean.TRUE)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONObject()))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name",
              new JSONObject(new JSONField("foo", "bar"))))));

    f.setExpectedType(ExpectedValueType.STRING);
    assertEquals(f.getExpectedType(), EnumSet.of(ExpectedValueType.STRING));
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "containsField"),
              new JSONField("field", "field-name"),
              new JSONField("expectedType", "string")));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", "foo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", true))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", false))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", 1234))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", JSONNull.NULL))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray()))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray(JSONBoolean.TRUE)))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONObject()))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name",
              new JSONObject(new JSONField("foo", "bar"))))));

    f.setExpectedType();
    assertEquals(f.getExpectedType(), EnumSet.allOf(ExpectedValueType.class));
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "containsField"),
              new JSONField("field", "field-name")));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", "foo"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", true))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", false))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", 1234))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", JSONNull.NULL))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray()))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray(JSONBoolean.TRUE)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONObject()))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name",
              new JSONObject(new JSONField("foo", "bar"))))));

    f.setExpectedType(ExpectedValueType.BOOLEAN);
    assertEquals(f.getExpectedType(), EnumSet.of(ExpectedValueType.BOOLEAN));
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "containsField"),
              new JSONField("field", "field-name"),
              new JSONField("expectedType", "boolean")));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", "foo"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", true))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", false))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", 1234))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", JSONNull.NULL))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray()))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray(JSONBoolean.TRUE)))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONObject()))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name",
              new JSONObject(new JSONField("foo", "bar"))))));

    f.setExpectedType(ExpectedValueType.NUMBER);
    assertEquals(f.getExpectedType(), EnumSet.of(ExpectedValueType.NUMBER));
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "containsField"),
              new JSONField("field", "field-name"),
              new JSONField("expectedType", "number")));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", "foo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", true))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", false))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", 1234))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", JSONNull.NULL))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray()))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray(JSONBoolean.TRUE)))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONObject()))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name",
              new JSONObject(new JSONField("foo", "bar"))))));

    f.setExpectedType(ExpectedValueType.NULL);
    assertEquals(f.getExpectedType(), EnumSet.of(ExpectedValueType.NULL));
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "containsField"),
              new JSONField("field", "field-name"),
              new JSONField("expectedType", "null")));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", "foo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", true))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", false))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", 1234))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", JSONNull.NULL))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray()))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray(JSONBoolean.TRUE)))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONObject()))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name",
              new JSONObject(new JSONField("foo", "bar"))))));

    f.setExpectedType(ExpectedValueType.EMPTY_ARRAY);
    assertEquals(f.getExpectedType(),
         EnumSet.of(ExpectedValueType.EMPTY_ARRAY));
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "containsField"),
              new JSONField("field", "field-name"),
              new JSONField("expectedType", "empty-array")));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", "foo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", true))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", false))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", 1234))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", JSONNull.NULL))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray()))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray(JSONBoolean.TRUE)))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONObject()))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name",
              new JSONObject(new JSONField("foo", "bar"))))));

    f.setExpectedType(ExpectedValueType.NON_EMPTY_ARRAY);
    assertEquals(f.getExpectedType(),
         EnumSet.of(ExpectedValueType.NON_EMPTY_ARRAY));
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "containsField"),
              new JSONField("field", "field-name"),
              new JSONField("expectedType", "non-empty-array")));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", "foo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", true))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", false))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", 1234))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", JSONNull.NULL))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray()))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray(JSONBoolean.TRUE)))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONObject()))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name",
              new JSONObject(new JSONField("foo", "bar"))))));

    f.setExpectedType(ExpectedValueType.OBJECT);
    assertEquals(f.getExpectedType(), EnumSet.of(ExpectedValueType.OBJECT));
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "containsField"),
              new JSONField("field", "field-name"),
              new JSONField("expectedType", "object")));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", "foo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", true))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", false))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", 1234))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", JSONNull.NULL))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray()))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray(JSONBoolean.TRUE)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONObject()))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name",
              new JSONObject(new JSONField("foo", "bar"))))));

    f.setExpectedType((ExpectedValueType[]) null);
    assertEquals(f.getExpectedType(), EnumSet.allOf(ExpectedValueType.class));
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "containsField"),
              new JSONField("field", "field-name")));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", "foo"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", true))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", false))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", 1234))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", JSONNull.NULL))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray()))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray(JSONBoolean.TRUE)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONObject()))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name",
              new JSONObject(new JSONField("foo", "bar"))))));

    f.setExpectedType(ExpectedValueType.BOOLEAN, ExpectedValueType.NUMBER,
         ExpectedValueType.STRING);
    assertEquals(f.getExpectedType(),
         EnumSet.of(ExpectedValueType.BOOLEAN, ExpectedValueType.NUMBER,
              ExpectedValueType.STRING));
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "containsField"),
              new JSONField("field", "field-name"),
              new JSONField("expectedType", new JSONArray(
                   new JSONString("boolean"),
                   new JSONString("number"),
                   new JSONString("string")))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", "foo"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", true))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", false))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", 1234))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", JSONNull.NULL))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray()))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONArray(JSONBoolean.TRUE)))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name", new JSONObject()))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("field-name",
              new JSONObject(new JSONField("foo", "bar"))))));
  }



  /**
   * Provides test coverage for the {@code decodeFilter} method for an object
   * that includes an unsupported expected type value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { JSONException.class})
  public void testDecodeFilterInvalidType()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("filterType", "containsField"),
         new JSONField("field", "test-field"),
         new JSONField("expectedType", "unrecognized"));
    JSONObjectFilter.decode(o);
  }
}
