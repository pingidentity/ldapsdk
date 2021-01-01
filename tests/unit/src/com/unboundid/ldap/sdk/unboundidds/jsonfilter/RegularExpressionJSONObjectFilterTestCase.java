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
import java.util.regex.Pattern;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONException;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNull;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides a set of test cases for the
 * {@code RegularExpressionFilter} class.
 */
public final class RegularExpressionJSONObjectFilterTestCase
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
    final RegularExpressionJSONObjectFilter f =
         new RegularExpressionJSONObjectFilter();
    assertNull(f.getField());
    assertNull(f.getRegularExpression());
    assertFalse(f.matchAllElements());
  }



  /**
   * Tests the regular expression filter with a valid string regex.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringRegex()
         throws Exception
  {
    RegularExpressionJSONObjectFilter f =
         new RegularExpressionJSONObjectFilter("a", "[a-zA-Z][a-zA-Z0-9]*");

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "regularExpression"),
              new JSONField("field", "a"),
              new JSONField("regularExpression", "[a-zA-Z][a-zA-Z0-9]*")));

    f = (RegularExpressionJSONObjectFilter)
         JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(), Collections.singletonList("a"));

    assertNotNull(f.getRegularExpression());
    assertEquals(f.getRegularExpression().pattern(), "[a-zA-Z][a-zA-Z0-9]*");

    assertFalse(f.matchAllElements());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "regularExpression");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Arrays.asList("field", "regularExpression")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         Collections.singletonList("matchAllElements"));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "abc"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("b", "abc"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "abc123"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "a"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "ABC123"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "A"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "123abc"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", ""))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "abc!"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", JSONArray.EMPTY_ARRAY))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", new JSONArray(
              new JSONString("abc"),
              new JSONString("def456"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", new JSONArray(
              new JSONString("abc"),
              new JSONString("def456"),
              JSONNull.NULL)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", new JSONArray(
              new JSONString("abc"),
              new JSONString("456def"))))));


    f.setMatchAllElements(true);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "regularExpression"),
              new JSONField("field", "a"),
              new JSONField("regularExpression", "[a-zA-Z][a-zA-Z0-9]*"),
              new JSONField("matchAllElements", true)));

    f = (RegularExpressionJSONObjectFilter)
         JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertTrue(f.matchAllElements());

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "abc"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("b", "abc"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "abc123"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "a"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "ABC123"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "A"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "123abc"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", ""))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "abc!"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", JSONArray.EMPTY_ARRAY))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", new JSONArray(
              new JSONString("abc"),
              new JSONString("def456"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", new JSONArray(
              new JSONString("abc"),
              new JSONString("def456"),
              JSONNull.NULL)))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", new JSONArray(
              new JSONString("abc"),
              new JSONString("456def"))))));
  }



  /**
   * Tests the regular expression filter with a pattern regex.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPatternRegex()
         throws Exception
  {
    RegularExpressionJSONObjectFilter f =
         new RegularExpressionJSONObjectFilter("a",
              Pattern.compile("[a-zA-Z][a-zA-Z0-9]*"));

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "regularExpression"),
              new JSONField("field", "a"),
              new JSONField("regularExpression", "[a-zA-Z][a-zA-Z0-9]*")));

    f = (RegularExpressionJSONObjectFilter)
         JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(), Collections.singletonList("a"));

    assertNotNull(f.getRegularExpression());
    assertEquals(f.getRegularExpression().pattern(), "[a-zA-Z][a-zA-Z0-9]*");

    assertFalse(f.matchAllElements());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "regularExpression");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Arrays.asList("field", "regularExpression")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         Collections.singletonList("matchAllElements"));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "abc"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("b", "abc"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "abc123"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "a"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "ABC123"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "A"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "123abc"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", ""))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "abc!"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", JSONArray.EMPTY_ARRAY))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", new JSONArray(
              new JSONString("abc"),
              new JSONString("def456"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", new JSONArray(
              new JSONString("abc"),
              new JSONString("def456"),
              JSONNull.NULL)))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", new JSONArray(
              new JSONString("abc"),
              new JSONString("456def"))))));


    f.setMatchAllElements(true);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "regularExpression"),
              new JSONField("field", "a"),
              new JSONField("regularExpression", "[a-zA-Z][a-zA-Z0-9]*"),
              new JSONField("matchAllElements", true)));

    f = (RegularExpressionJSONObjectFilter)
         JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertTrue(f.matchAllElements());

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "abc"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("b", "abc"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "abc123"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "a"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "ABC123"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "A"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "123abc"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", ""))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "abc!"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", JSONArray.EMPTY_ARRAY))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", new JSONArray(
              new JSONString("abc"),
              new JSONString("def456"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", new JSONArray(
              new JSONString("abc"),
              new JSONString("def456"),
              JSONNull.NULL)))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", new JSONArray(
              new JSONString("abc"),
              new JSONString("456def"))))));
  }



  /**
   * Tests the behavior of the constructor that takes a string regex with a
   * malformed value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { JSONException.class })
  public void testConstructorMalformedRegex()
         throws Exception
  {
    new RegularExpressionJSONObjectFilter("a", "[invalid");
  }



  /**
   * Provides test coverage for the methods that can be used to get and set the
   * target field for a filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetField()
         throws Exception
  {
    RegularExpressionJSONObjectFilter f =
         new RegularExpressionJSONObjectFilter("a", "[a-zA-Z][a-zA-Z0-9]*");
    assertNotNull(f.getField());
    assertEquals(f.getField(),
         Collections.singletonList("a"));

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "regularExpression"),
              new JSONField("field", "a"),
              new JSONField("regularExpression", "[a-zA-Z][a-zA-Z0-9]*")));


    f.setField("b");
    assertNotNull(f.getField());
    assertEquals(f.getField(),
         Collections.singletonList("b"));

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "regularExpression"),
              new JSONField("field", "b"),
              new JSONField("regularExpression", "[a-zA-Z][a-zA-Z0-9]*")));


    f.setField("first", "second", "third");
    assertNotNull(f.getField());
    assertEquals(f.getField(),
         Arrays.asList("first", "second", "third"));

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "regularExpression"),
              new JSONField("field", new JSONArray(
                   new JSONString("first"),
                   new JSONString("second"),
                   new JSONString("third"))),
              new JSONField("regularExpression", "[a-zA-Z][a-zA-Z0-9]*")));

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
   * regular expression for a filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetRegularExpression()
         throws Exception
  {
    RegularExpressionJSONObjectFilter f =
         new RegularExpressionJSONObjectFilter("a", "[a-zA-Z][a-zA-Z0-9]*");
    assertNotNull(f.getRegularExpression());
    assertEquals(f.getRegularExpression().pattern(), "[a-zA-Z][a-zA-Z0-9]*");

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "regularExpression"),
              new JSONField("field", "a"),
              new JSONField("regularExpression", "[a-zA-Z][a-zA-Z0-9]*")));


    f.setRegularExpression("[a-zA-Z0-9]+");
    assertNotNull(f.getRegularExpression());
    assertEquals(f.getRegularExpression().pattern(), "[a-zA-Z0-9]+");

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "regularExpression"),
              new JSONField("field", "a"),
              new JSONField("regularExpression", "[a-zA-Z0-9]+")));


    f.setRegularExpression(Pattern.compile("[a-zA-Z0-9]*"));
    assertNotNull(f.getRegularExpression());
    assertEquals(f.getRegularExpression().pattern(), "[a-zA-Z0-9]*");

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "regularExpression"),
              new JSONField("field", "a"),
              new JSONField("regularExpression", "[a-zA-Z0-9]*")));


    try
    {
      f.setRegularExpression((String) null);
      fail("Expected an exception with setRegularExpression of string null");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected
    }


    try
    {
      f.setRegularExpression("[invalid");
      fail("Expected an exception with setRegularExpression of string invalid");
    }
    catch (final JSONException e)
    {
      // This was expected
    }


    try
    {
      f.setRegularExpression((Pattern) null);
      fail("Expected an exception with setRegularExpression of pattern null");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected
    }
  }



  /**
   * Tests the behavior of the decode method when provided with a malformed
   * regular expression.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { JSONException.class })
  public void testDecodeMalformedRegex()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("filterType", "regularExpression"),
         new JSONField("field", "a"),
         new JSONField("regularExpression", "[malformed"));
    JSONObjectFilter.decode(o);
  }
}
