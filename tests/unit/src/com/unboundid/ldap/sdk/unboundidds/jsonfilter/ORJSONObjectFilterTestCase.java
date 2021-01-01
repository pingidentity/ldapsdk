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
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONException;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNull;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides a set of test cases for the {@code ORFilter} class.
 */
public final class ORJSONObjectFilterTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of an OR filter with zero components.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testZeroComponents()
         throws Exception
  {
    ORJSONObjectFilter f = new ORJSONObjectFilter();

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "or"),
              new JSONField("orFilters", JSONArray.EMPTY_ARRAY)));

    f = (ORJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getORFilters());
    assertEquals(f.getORFilters(), Collections.emptyList());

    assertFalse(f.exclusive());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "or");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Collections.singletonList("orFilters")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Collections.singletonList("exclusive")));

    assertFalse(f.matchesJSONObject(JSONObject.EMPTY_OBJECT));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "foo"),
         new JSONField("b", 1234),
         new JSONField("c", true),
         new JSONField("d", false),
         new JSONField("e", JSONNull.NULL),
         new JSONField("f", JSONArray.EMPTY_ARRAY),
         new JSONField("g", new JSONArray(
              new JSONString("foo"), new JSONString("bar"))),
         new JSONField("h", JSONObject.EMPTY_OBJECT),
         new JSONField("i", new JSONObject(
              new JSONField("j", "k"))))));


    f.setExclusive(true);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "or"),
              new JSONField("orFilters", JSONArray.EMPTY_ARRAY),
              new JSONField("exclusive", true)));

    f = (ORJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertTrue(f.exclusive());

    assertFalse(f.matchesJSONObject(JSONObject.EMPTY_OBJECT));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "foo"),
         new JSONField("b", 1234),
         new JSONField("c", true),
         new JSONField("d", false),
         new JSONField("e", JSONNull.NULL),
         new JSONField("f", JSONArray.EMPTY_ARRAY),
         new JSONField("g", new JSONArray(
              new JSONString("foo"), new JSONString("bar"))),
         new JSONField("h", JSONObject.EMPTY_OBJECT),
         new JSONField("i", new JSONObject(
              new JSONField("j", "k"))))));
  }



  /**
   * Tests the behavior of an OR filter with one component.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOneComponent()
         throws Exception
  {
    final EqualsJSONObjectFilter equalsFilter =
         new EqualsJSONObjectFilter("a", new JSONString("b"));
    ORJSONObjectFilter f = new ORJSONObjectFilter(equalsFilter);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "or"),
              new JSONField("orFilters",
                   new JSONArray(equalsFilter.toJSONObject()))));

    f = (ORJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getORFilters());
    assertEquals(f.getORFilters(), Collections.singletonList(equalsFilter));

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "or");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Collections.singletonList("orFilters")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Collections.singletonList("exclusive")));

    assertFalse(f.matchesJSONObject(JSONObject.EMPTY_OBJECT));

    assertTrue(f.matchesJSONObject(new JSONObject(new JSONField("a", "b"))));

    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("a", "x"))));

    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("x", "b"))));

    assertTrue(f.matchesJSONObject(new JSONObject(new JSONField("a",
         new JSONArray(new JSONNumber(1234), new JSONString("b"),
              JSONNull.NULL)))));

    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("a", 1234))));


    f.setExclusive(true);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "or"),
              new JSONField("orFilters",
                   new JSONArray(equalsFilter.toJSONObject())),
              new JSONField("exclusive", true)));

    f = (ORJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertTrue(f.exclusive());

    assertFalse(f.matchesJSONObject(JSONObject.EMPTY_OBJECT));

    assertTrue(f.matchesJSONObject(new JSONObject(new JSONField("a", "b"))));

    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("a", "x"))));

    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("x", "b"))));

    assertTrue(f.matchesJSONObject(new JSONObject(new JSONField("a",
         new JSONArray(new JSONNumber(1234), new JSONString("b"),
              JSONNull.NULL)))));

    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("a", 1234))));
  }



  /**
   * Tests the behavior of an OR filter with multiple components.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleComponents()
         throws Exception
  {
    final EqualsJSONObjectFilter f1 =
         new EqualsJSONObjectFilter("a", new JSONString("b"));
    final EqualsJSONObjectFilter f2 =
         new EqualsJSONObjectFilter("c", new JSONString("d"));
    final EqualsJSONObjectFilter f3 =
         new EqualsJSONObjectFilter("e", new JSONString("f"));
    ORJSONObjectFilter f = new ORJSONObjectFilter(f1, f2, f3);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "or"),
              new JSONField("orFilters", new JSONArray(
                   f1.toJSONObject(),
                   f2.toJSONObject(),
                   f3.toJSONObject()))));

    f = (ORJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getORFilters());
    assertEquals(f.getORFilters(), Arrays.asList(f1, f2, f3));

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "or");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Collections.singletonList("orFilters")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Collections.singletonList("exclusive")));

    assertFalse(f.matchesJSONObject(JSONObject.EMPTY_OBJECT));

    assertTrue(f.matchesJSONObject(new JSONObject(new JSONField("a", "b"))));

    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("a", "x"))));

    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("x", "b"))));

    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("a",
         new JSONArray(new JSONNumber(1234), new JSONString("a"),
              JSONNull.NULL)))));

    assertTrue(f.matchesJSONObject(new JSONObject(new JSONField("a",
         new JSONArray(new JSONNumber(1234), new JSONString("b"),
              JSONNull.NULL)))));

    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("a", 1234))));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "b"),
         new JSONField("c", "d"),
         new JSONField("e", "f"))));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "b"),
         new JSONField("c", "d"),
         new JSONField("e", "f"),
         new JSONField("g", "h"),
         new JSONField("i", "j"))));


    f.setExclusive(true);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "or"),
              new JSONField("orFilters", JSONArray.EMPTY_ARRAY),
              new JSONField("orFilters", new JSONArray(
                   f1.toJSONObject(),
                   f2.toJSONObject(),
                   f3.toJSONObject())),
              new JSONField("exclusive", true)));

    f = (ORJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertTrue(f.exclusive());

    assertFalse(f.matchesJSONObject(JSONObject.EMPTY_OBJECT));

    assertTrue(f.matchesJSONObject(new JSONObject(new JSONField("a", "b"))));

    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("a", "x"))));

    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("x", "b"))));

    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("a",
         new JSONArray(new JSONNumber(1234), new JSONString("a"),
              JSONNull.NULL)))));

    assertTrue(f.matchesJSONObject(new JSONObject(new JSONField("a",
         new JSONArray(new JSONNumber(1234), new JSONString("b"),
              JSONNull.NULL)))));

    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("a", 1234))));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "b"),
         new JSONField("c", "d"),
         new JSONField("e", "f"))));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", "b"),
         new JSONField("c", "d"),
         new JSONField("e", "f"),
         new JSONField("g", "h"),
         new JSONField("i", "j"))));
  }



  /**
   * Tests the behavior of the methods that can be used to get and set the
   * filters to include in this OR filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetORFilters()
         throws Exception
  {
    final ORJSONObjectFilter f = new ORJSONObjectFilter();
    assertNotNull(f.getORFilters());
    assertEquals(f.getORFilters(), Collections.emptyList());

    final EqualsJSONObjectFilter eq =
         new EqualsJSONObjectFilter("a", new JSONString("b"));
    f.setORFilters(eq);
    assertNotNull(f.getORFilters());
    assertEquals(f.getORFilters(), Collections.singletonList(eq));

    final GreaterThanJSONObjectFilter gt =
         new GreaterThanJSONObjectFilter("a", 1234);
    f.setORFilters(eq, gt);
    assertNotNull(f.getORFilters());
    assertEquals(f.getORFilters(), Arrays.asList(eq, gt));

    f.setORFilters((JSONObjectFilter[]) null);
    assertNotNull(f.getORFilters());
    assertEquals(f.getORFilters(), Collections.emptyList());
  }



  /**
   * Tests the behavior of the AND filter logic when trying to decode a
   * malformed embedded filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { JSONException.class })
  public void testDecodeMalformedFilter()
         throws Exception
  {
    JSONObjectFilter.decode(new JSONObject(
         new JSONField("filterType", "or"),
         new JSONField("orFilters", new JSONArray(JSONObject.EMPTY_OBJECT))));
  }
}
