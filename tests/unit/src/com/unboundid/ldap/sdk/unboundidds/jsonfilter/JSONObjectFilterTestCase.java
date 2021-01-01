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

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONException;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNull;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides test coverage for the {@code JSONObjectFilter} class.
 */
public final class JSONObjectFilterTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the {@code getStrings} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetStrings()
         throws Exception
  {
    // A filter that will be used just to invoke the protected methods.
    final ContainsFieldJSONObjectFilter f =
         new ContainsFieldJSONObjectFilter("name");


    // Test the case in which an object has a single string for the target
    // field.
    JSONObject o = new JSONObject(new JSONField("a", "b"));
    assertNotNull(f.getStrings(o, "a", true, null));
    assertFalse(f.getStrings(o, "a", true, null).isEmpty());
    assertEquals(f.getStrings(o, "a", true, null),
         Collections.singletonList("b"));


    // Test the case in which an object has an array of strings for the target
    // field.
    o = new JSONObject(new JSONField("a", new JSONArray(
         new JSONString("b"),
         new JSONString("c"),
         new JSONString("d"))));
    assertNotNull(f.getStrings(o, "a", true, null));
    assertFalse(f.getStrings(o, "a", true, null).isEmpty());
    assertEquals(f.getStrings(o, "a", true, null),
         Arrays.asList("b", "c", "d"));


    // Test the case in which an object has an empty array, when that is
    // allowed.
    o = new JSONObject(new JSONField("a", JSONArray.EMPTY_ARRAY));
    assertNotNull(f.getStrings(o, "a", true, null));
    assertTrue(f.getStrings(o, "a", true, null).isEmpty());


    // Test the case in which an object has an empty array, when that is not
    // allowed.
    o = new JSONObject(new JSONField("a", JSONArray.EMPTY_ARRAY));
    try
    {
      f.getStrings(o, "a", false, null);
      fail("Expected an exception from getStrings with empty array");
    }
    catch (final JSONException e)
    {
      // This is expected.
    }


    // Test the case in which an object has a value that is neither a string
    // nor an array.
    o = new JSONObject(new JSONField("a", JSONBoolean.TRUE));
    try
    {
      f.getStrings(o, "a", false, null);
      fail("Expected an exception from getStrings with true");
    }
    catch (final JSONException e)
    {
      // This is expected.
    }


    // Test the case in which an object has a value that has an array
    // containing a non-string element.
    o = new JSONObject(new JSONField("a", new JSONArray(
         new JSONString("foo"),
         JSONNull.NULL,
         new JSONString("bar"))));
    try
    {
      f.getStrings(o, "a", false, null);
      fail("Expected an exception from getStrings with non-string array");
    }
    catch (final JSONException e)
    {
      // This is expected.
    }


    // Test the case in which an object does not have the target field when that
    // is allowed.
    assertNotNull(f.getStrings(JSONObject.EMPTY_OBJECT, "a", false,
         Collections.<String>emptyList()));
    assertTrue(f.getStrings(JSONObject.EMPTY_OBJECT, "a", false,
         Collections.<String>emptyList()).isEmpty());


    // Test the case in which an object does not have the target field when that
    // is not allowed.
    try
    {
      f.getStrings(JSONObject.EMPTY_OBJECT, "a", false, null);
      fail("Expected an exception from getStrings with nonexistent field");
    }
    catch (final JSONException e)
    {
      // This is expected.
    }
  }



  /**
   * Provides test coverage for the {@code getString} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetString()
         throws Exception
  {
    // A filter that will be used just to invoke the protected methods.
    final ContainsFieldJSONObjectFilter f =
         new ContainsFieldJSONObjectFilter("name");


    // Test the case in which an object has a single string for the target
    // field.
    JSONObject o = new JSONObject(new JSONField("a", "b"));
    assertNotNull(f.getString(o, "a", null, true));
    assertEquals(f.getString(o, "a", null, true), "b");


    // Test the case in which an object does not contain the specified field
    // but that is OK and there is no default.
    assertNull(f.getString(JSONObject.EMPTY_OBJECT, "a", null, false));


    // Test the case in which an object does not contain the specified field
    // but that is OK and there is a default.
    assertNotNull(f.getString(JSONObject.EMPTY_OBJECT, "a", "default", false));
    assertEquals(f.getString(JSONObject.EMPTY_OBJECT, "a", "default", false),
         "default");


    // Test the case in which an object does not contain the specified field
    // but that is not OK.
    try
    {
      f.getString(JSONObject.EMPTY_OBJECT, "a", null, true);
      fail("Expected an exception from getString with a nonexistent field");
    }
    catch (final JSONException e)
    {
      // This is expected.
    }


    // Test the case in which an object has an empty array for the target
    // field.
    o = new JSONObject(new JSONField("a", JSONArray.EMPTY_ARRAY));
    try
    {
      f.getString(o, "a", null, true);
      fail("Expected an exception from getString with an empty array");
    }
    catch (final JSONException e)
    {
      // This is expected.
    }


    // Test the case in which an object has a single-string array for the target
    // field.
    o = new JSONObject(new JSONField("a", new JSONArray(new JSONString("b"))));
    try
    {
      f.getString(o, "a", null, true);
      fail("Expected an exception from getString with a single-string array");
    }
    catch (final JSONException e)
    {
      // This is expected.
    }


    // Test the case in which an object has a non-string, non-array value for
    // the target field.
    o = new JSONObject(new JSONField("a", JSONBoolean.TRUE));
    try
    {
      f.getString(o, "a", null, true);
      fail("Expected an exception from getString with a boolean");
    }
    catch (final JSONException e)
    {
      // This is expected.
    }
  }



  /**
   * Provides test coverage for the {@code getBoolean} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetBoolean()
         throws Exception
  {
    // A filter that will be used just to invoke the protected methods.
    final ContainsFieldJSONObjectFilter f =
         new ContainsFieldJSONObjectFilter("name");


    // Test the case in which an object has a Boolean value of true.
    JSONObject o = new JSONObject(new JSONField("a", true));
    assertTrue(f.getBoolean(o, "a", null));


    // Test the case in which an object has a Boolean value of false.
    o = new JSONObject(new JSONField("a", false));
    assertFalse(f.getBoolean(o, "a", false));


    // Test the case in which an object is missing the target field and there
    // is a default value of true.
    assertTrue(f.getBoolean(JSONObject.EMPTY_OBJECT, "a", true));


    // Test the case in which an object is missing the target field and there
    // is a default value of false.
    assertFalse(f.getBoolean(JSONObject.EMPTY_OBJECT, "a", false));


    // Test the case in which an object is missing the target field and there
    // is no default value.
    try
    {
      f.getBoolean(JSONObject.EMPTY_OBJECT, "a", null);
      fail("Expected an exception for a missing field");
    }
    catch (final JSONException e)
    {
      // This is expected.
    }


    // Test the cse in which an object has a non-Boolean value for the target
    // field.
    o = new JSONObject(new JSONField("a", new JSONString("true")));
    try
    {
      f.getBoolean(o, "a", null);
      fail("Expected an exception for a non-Boolean field");
    }
    catch (final JSONException e)
    {
      // This is expected.
    }
  }



  /**
   * Provides test coverage for the {@code getFilters} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetFilters()
         throws Exception
  {
    // A filter that will be used just to invoke the protected methods.
    final ContainsFieldJSONObjectFilter f =
         new ContainsFieldJSONObjectFilter("name");


    // Test the case in which an object has a single filter for the target
    // field.
    JSONObject o = new JSONObject(new JSONField("a",
         new JSONArray(f.toJSONObject())));
    assertNotNull(f.getFilters(o, "a"));
    assertEquals(f.getFilters(o, "a"), Collections.singletonList(f));


    // Test the case in which an object has a non-empty array of filters for the
    // target field.
    o = new JSONObject(new JSONField("a", new JSONArray(
         f.toJSONObject(),
         new EqualsJSONObjectFilter("b", new JSONString("c")).toJSONObject())));
    assertNotNull(f.getFilters(o, "a"));
    assertEquals(f.getFilters(o, "a"),
         Arrays.asList(f,
              new EqualsJSONObjectFilter("b", new JSONString("c"))));


    // Test the case in which an object has an empty array of filters for the
    // target field.
    o = new JSONObject(new JSONField("a", JSONArray.EMPTY_ARRAY));
    assertNotNull(f.getFilters(o, "a"));
    assertEquals(f.getFilters(o, "a"), Collections.emptyList());


    // Test the case in which an object is missing the target field.
    try
    {
      f.getFilters(JSONObject.EMPTY_OBJECT, "a");
      fail("Expected an exception for a missing field");
    }
    catch (final JSONException e)
    {
      // This is expected.
    }


    // Test the case in which an object has a non-array value for the target
    // field.
    o = new JSONObject(new JSONField("a", JSONBoolean.TRUE));
    try
    {
      f.getFilters(o, "a");
      fail("Expected an exception for a non-array value");
    }
    catch (final JSONException e)
    {
      // This is expected.
    }


    // Test the case in which an object has an array containing an element that
    // is not an object.
    o = new JSONObject(new JSONField("a", new JSONArray(
         new JSONString("foo"))));
    try
    {
      f.getFilters(o, "a");
      fail("Expected an exception for an array with a non-object element");
    }
    catch (final JSONException e)
    {
      // This is expected.
    }


    // Test the case in which an object has an array containing an object that
    // is not a valid filter.
    o = new JSONObject(new JSONField("a", JSONObject.EMPTY_OBJECT));
    try
    {
      f.getFilters(o, "a");
      fail("Expected an exception for an array with a non-filter object");
    }
    catch (final JSONException e)
    {
      // This is expected.
    }
  }



  /**
   * Provides test coverage for the {@code getValues} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValues()
         throws Exception
  {
    // Test the case in which a target top-level field does not exist.
    assertNotNull(JSONObjectFilter.getValues(JSONObject.EMPTY_OBJECT,
         Collections.singletonList("a")));
    assertEquals(
         JSONObjectFilter.getValues(JSONObject.EMPTY_OBJECT,
              Collections.singletonList("a")),
         Collections.emptyList());


    // Test the case in which an object has a single value for a top-level
    // field.
    JSONObject o = new JSONObject(new JSONField("a", "b"));
    assertNotNull(JSONObjectFilter.getValues(o,
         Collections.singletonList("a")));
    assertEquals(JSONObjectFilter.getValues(o, Collections.singletonList("a")),
         Collections.singletonList(new JSONString("b")));


    // Test the case in which an object has an array value for a top-level
    // field.
    o = new JSONObject(new JSONField("a", new JSONArray(
         new JSONString("b"),
         new JSONString("c"),
         new JSONString("d"))));
    assertNotNull(JSONObjectFilter.getValues(o,
         Collections.singletonList("a")));
    assertEquals(JSONObjectFilter.getValues(o, Collections.singletonList("a")),
         Collections.singletonList(new JSONArray(new JSONString("b"),
              new JSONString("c"), new JSONString("d"))));


    // Test the case in which the first level of a two-level field does not
    // exist.
    assertNotNull(JSONObjectFilter.getValues(JSONObject.EMPTY_OBJECT,
         Arrays.asList("a", "b")));
    assertEquals(
         JSONObjectFilter.getValues(JSONObject.EMPTY_OBJECT,
              Arrays.asList("a", "b")),
         Collections.emptyList());


    // Test the case in which the first level of a two-level field exists but
    // has a simple value that isn't an object or an array.
    assertNotNull(JSONObjectFilter.getValues(
         new JSONObject(new JSONField("a", JSONBoolean.TRUE)),
         Arrays.asList("a", "b")));


    // Test the case in which the first level of a two-level field exists but
    // is an object that doesn't have the second-level field.
    assertNotNull(
         JSONObjectFilter.getValues(
              new JSONObject(new JSONField("a", new JSONObject(
                   new JSONField("x", "x")))),
              Arrays.asList("a", "b")));
    assertEquals(
         JSONObjectFilter.getValues(
              new JSONObject(new JSONField("a", new JSONObject(
                   new JSONField("x", "y")))),
              Arrays.asList("a", "b")),
         Collections.emptyList());


    // Test the case in which the first level of a two-level field exists and
    // is an object that has the second-level field.
    assertNotNull(
         JSONObjectFilter.getValues(
              new JSONObject(new JSONField("a", new JSONObject(
                   new JSONField("b", "x")))),
              Arrays.asList("a", "b")));
    assertEquals(
         JSONObjectFilter.getValues(
              new JSONObject(new JSONField("a", new JSONObject(
                   new JSONField("b", "x")))),
              Arrays.asList("a", "b")),
         Collections.singletonList(new JSONString("x")));


    // Test the case in which the first level of a two-level field exists and
    // is an empty array.
    assertNotNull(
         JSONObjectFilter.getValues(
              new JSONObject(new JSONField("a", JSONArray.EMPTY_ARRAY)),
              Arrays.asList("a", "b")));
    assertEquals(
         JSONObjectFilter.getValues(
              new JSONObject(new JSONField("a", JSONArray.EMPTY_ARRAY)),
              Arrays.asList("a", "b")),
         Collections.emptyList());


    // Test the case in which the first level of a two-level field exists and
    // is an array that doesn't contain any objects.
    assertNotNull(
         JSONObjectFilter.getValues(
              new JSONObject(new JSONField("a", new JSONArray(
                   JSONBoolean.TRUE, JSONNull.NULL))),
              Arrays.asList("a", "b")));
    assertEquals(
         JSONObjectFilter.getValues(
              new JSONObject(new JSONField("a", new JSONArray(
                   JSONBoolean.TRUE, JSONNull.NULL))),
              Arrays.asList("a", "b")),
         Collections.emptyList());


    // Test the case in which the first level of a two-level field exists and
    // is an array that contains an object without the target field.
    assertNotNull(
         JSONObjectFilter.getValues(
              new JSONObject(new JSONField("a", new JSONArray(
                   JSONBoolean.TRUE, JSONNull.NULL, JSONObject.EMPTY_OBJECT))),
              Arrays.asList("a", "b")));
    assertEquals(
         JSONObjectFilter.getValues(
              new JSONObject(new JSONField("a", new JSONArray(
                   JSONBoolean.TRUE, JSONNull.NULL, JSONObject.EMPTY_OBJECT))),
              Arrays.asList("a", "b")),
         Collections.emptyList());


    // Test the case in which the first level of a two-level field exists and
    // is an array that contains multiple objects with the target field.
    assertNotNull(
         JSONObjectFilter.getValues(
              new JSONObject(new JSONField("a", new JSONArray(
                   JSONBoolean.TRUE, JSONNull.NULL, JSONObject.EMPTY_OBJECT,
                   new JSONObject(new JSONField("b", "x")),
                   new JSONObject(new JSONField("b", "y")),
                   new JSONObject(new JSONField("b", "z"))))),
              Arrays.asList("a", "b")));
    assertEquals(
         JSONObjectFilter.getValues(
              new JSONObject(new JSONField("a", new JSONArray(
                   JSONBoolean.TRUE, JSONNull.NULL, JSONObject.EMPTY_OBJECT,
                   new JSONObject(new JSONField("b", "x")),
                   new JSONObject(new JSONField("b", "y")),
                   new JSONObject(new JSONField("b", "z"))))),
              Arrays.asList("a", "b")),
         Arrays.asList(
              new JSONString("x"),
              new JSONString("y"),
              new JSONString("z")));


    // Test the case in which the first level of a two-level field exists and
    // is an object containing the second-level field whose value is an array.
    assertNotNull(
         JSONObjectFilter.getValues(
              new JSONObject(new JSONField("a", new JSONObject(
                   new JSONField("b", new JSONArray(
                        new JSONString("x"),
                        new JSONString("y"),
                        new JSONString("z")))))),
              Arrays.asList("a", "b")));
    assertEquals(
         JSONObjectFilter.getValues(
              new JSONObject(new JSONField("a", new JSONObject(
                   new JSONField("b", new JSONArray(
                        new JSONString("x"),
                        new JSONString("y"),
                        new JSONString("z")))))),
              Arrays.asList("a", "b")),
         Collections.singletonList(new JSONArray(
              new JSONString("x"),
              new JSONString("y"),
              new JSONString("z"))));


    // Test the case in which the first level of a two-level field exists and
    // is an array of objects, and each of those objects contains the
    // second-level field with array values.
    assertNotNull(
         JSONObjectFilter.getValues(
              new JSONObject(new JSONField("a", new JSONArray(
                   new JSONObject(new JSONField("b", new JSONArray(
                        new JSONString("1a"),
                        new JSONString("1b"),
                        new JSONString("1c")))),
                   new JSONObject(new JSONField("b", new JSONArray(
                        new JSONString("2a"),
                        new JSONString("2b"),
                        new JSONString("2c")))),
                   new JSONObject(new JSONField("b", new JSONArray(
                        new JSONString("3a"),
                        new JSONString("3b"),
                        new JSONString("3c"))))))),
              Arrays.asList("a", "b")));
    assertEquals(
         JSONObjectFilter.getValues(
              new JSONObject(new JSONField("a", new JSONArray(
                   new JSONObject(new JSONField("b", new JSONArray(
                        new JSONString("1a"),
                        new JSONString("1b"),
                        new JSONString("1c")))),
                   new JSONObject(new JSONField("b", new JSONArray(
                        new JSONString("2a"),
                        new JSONString("2b"),
                        new JSONString("2c")))),
                   new JSONObject(new JSONField("b", new JSONArray(
                        new JSONString("3a"),
                        new JSONString("3b"),
                        new JSONString("3c"))))))),
              Arrays.asList("a", "b")),
         Arrays.asList(
              new JSONArray(
                   new JSONString("1a"),
                   new JSONString("1b"),
                   new JSONString("1c")),
              new JSONArray(
                   new JSONString("2a"),
                   new JSONString("2b"),
                   new JSONString("2c")),
              new JSONArray(
                   new JSONString("3a"),
                   new JSONString("3b"),
                   new JSONString("3c"))));


    // Test the case in which a three-level field references exactly one
    // element.
    assertNotNull(
         JSONObjectFilter.getValues(
              new JSONObject(new JSONField("a", new JSONObject(
                   new JSONField("b", new JSONObject(
                        new JSONField("c", "foo")))))),
              Arrays.asList("a", "b", "c")));
    assertEquals(
         JSONObjectFilter.getValues(
              new JSONObject(new JSONField("a", new JSONObject(
                   new JSONField("b", new JSONObject(
                        new JSONField("c", "foo")))))),
              Arrays.asList("a", "b", "c")),
         Collections.singletonList(new JSONString("foo")));


    // Test the case in which the first and second elements of a three-level
    // field reference arrays.
    assertNotNull(
         JSONObjectFilter.getValues(
              new JSONObject(new JSONField("a", new JSONArray(
                   new JSONObject(
                        new JSONField("b", new JSONArray(
                             new JSONObject(
                                  new JSONField("c", "first")),
                             new JSONObject(
                                  new JSONField("c", "second"))))),
                   new JSONObject(
                        new JSONField("b", new JSONArray(
                             new JSONObject(
                                  new JSONField("c", "third")),
                             new JSONObject(
                                  new JSONField("c", "fourth")))))))),
              Arrays.asList("a", "b", "c")));
    assertEquals(
         JSONObjectFilter.getValues(
              new JSONObject(new JSONField("a", new JSONArray(
                   new JSONObject(
                        new JSONField("b", new JSONArray(
                             new JSONObject(
                                  new JSONField("c", "first")),
                             new JSONObject(
                                  new JSONField("c", "second"))))),
                   new JSONObject(
                        new JSONField("b", new JSONArray(
                             new JSONObject(
                                  new JSONField("c", "third")),
                             new JSONArray(
                                  new JSONObject(
                                       new JSONField("c", "fourth"))))))))),
              Arrays.asList("a", "b", "c")),
         Arrays.asList(
              new JSONString("first"),
              new JSONString("second"),
              new JSONString("third"),
              new JSONString("fourth")));
  }



  /**
   * Tests the behavior of the {@code decode} method with an object that does
   * not have a filterType field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { JSONException.class })
  public void testDecodeMissingFilterType()
         throws Exception
  {
    JSONObjectFilter.decode(JSONObject.EMPTY_OBJECT);
  }



  /**
   * Tests the behavior of the {@code decode} method with an object that has a
   * filterType field whose value is not a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { JSONException.class })
  public void testDecodeFilterTypeNotString()
         throws Exception
  {
    JSONObjectFilter.decode(new JSONObject(
         new JSONField("filterType", true)));
  }



  /**
   * Tests the behavior of the {@code decode} method with an object that has a
   * filterType field whose value is an unrecognized string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { JSONException.class })
  public void testDecodeFilterTypeUnrecognizedString()
         throws Exception
  {
    JSONObjectFilter.decode(new JSONObject(
         new JSONField("filterType", "unrecognized")));
  }



  /**
   * Tests the behavior of the {@code decode} method with an object that is
   * missing a required field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { JSONException.class })
  public void testDecodeMissingRequiredField()
         throws Exception
  {
    JSONObjectFilter.decode(new JSONObject(
         new JSONField("filterType", "equals"),
         new JSONField("field", "missing-value")));
  }



  /**
   * Tests the behavior of the {@code decode} method with an object that
   * contains a non-allowed field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { JSONException.class })
  public void testDecodeContainsNonAllowedField()
         throws Exception
  {
    JSONObjectFilter.decode(new JSONObject(
         new JSONField("filterType", "equals"),
         new JSONField("field", "foo"),
         new JSONField("value", "bar"),
         new JSONField("not-allowed", "who-cares")));
  }



  /**
   * Provides test coverage for the {@code toLDAPFilter} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToLDAPFilter()
         throws Exception
  {
    final JSONObjectFilter jsonFilter =
         new EqualsJSONObjectFilter("foo", new JSONString("bar"));

    final Filter ldapFilter = jsonFilter.toLDAPFilter("jsonAttr");
    assertNotNull(ldapFilter);

    assertEquals(ldapFilter.getFilterType(),
         Filter.FILTER_TYPE_EXTENSIBLE_MATCH);

    assertNotNull(ldapFilter.getAttributeName());
    assertEquals(ldapFilter.getAttributeName(), "jsonAttr");

    assertNotNull(ldapFilter.getMatchingRuleID());
    assertEquals(ldapFilter.getMatchingRuleID(),
         "jsonObjectFilterExtensibleMatch");

    assertFalse(ldapFilter.getDNAttributes());

    assertNotNull(ldapFilter.getAssertionValue());
    assertEquals(new JSONObject(ldapFilter.getAssertionValue()),
         jsonFilter.toJSONObject());
  }



  /**
   * Provides test coverage for the {@code equals} and {@code hashCode} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEquals()
         throws Exception
  {
    final EqualsJSONObjectFilter f =
         new EqualsJSONObjectFilter("foo", new JSONString("bar"));

    assertFalse(f.equals(null));

    assertTrue(f.equals(f));
    assertEquals(f.hashCode(), f.hashCode());

    assertFalse(f.equals(f.toString()));

    assertEquals(f, new EqualsJSONObjectFilter("foo", new JSONString("bar")));
    assertEquals(f.hashCode(),
         new EqualsJSONObjectFilter("foo", new JSONString("bar")).hashCode());
  }



  /**
   * Tests the {@code fieldPathToName} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFieldPathToName()
         throws Exception
  {
    assertNotNull(JSONObjectFilter.fieldPathToName(null));
    assertEquals(JSONObjectFilter.fieldPathToName(null), "null");

    assertNotNull(
         JSONObjectFilter.fieldPathToName(Collections.<String>emptyList()));
    assertEquals(
         JSONObjectFilter.fieldPathToName(Collections.<String>emptyList()),
         "");

    assertNotNull(
         JSONObjectFilter.fieldPathToName(Collections.singletonList("foo")));
    assertEquals(
         JSONObjectFilter.fieldPathToName(Collections.singletonList("foo")),
         "\"foo\"");

    assertNotNull(
         JSONObjectFilter.fieldPathToName(Arrays.asList("foo", "bar")));
    assertEquals(
         JSONObjectFilter.fieldPathToName(Arrays.asList("foo", "bar")),
         "\"foo\".\"bar\"");
  }
}
