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
 * This class provides a set of test cases for the {@code ANDFilter} class.
 */
public final class ANDJSONObjectFilterTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of an AND filter with zero components.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testZeroComponents()
         throws Exception
  {
    ANDJSONObjectFilter f = new ANDJSONObjectFilter();

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "and"),
              new JSONField("andFilters", JSONArray.EMPTY_ARRAY)));

    f = (ANDJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getANDFilters());
    assertEquals(f.getANDFilters(), Collections.emptyList());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "and");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Collections.singletonList("andFilters")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(), Collections.emptySet());

    assertTrue(f.matchesJSONObject(JSONObject.EMPTY_OBJECT));

    assertTrue(f.matchesJSONObject(new JSONObject(
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
   * Tests the behavior of an AND filter with one component.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOneComponent()
         throws Exception
  {
    final EqualsJSONObjectFilter equalsFilter =
         new EqualsJSONObjectFilter("a", new JSONString("b"));
    ANDJSONObjectFilter f = new ANDJSONObjectFilter(equalsFilter);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "and"),
              new JSONField("andFilters",
                   new JSONArray(equalsFilter.toJSONObject()))));

    f = (ANDJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getANDFilters());
    assertEquals(f.getANDFilters(), Collections.singletonList(equalsFilter));

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "and");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Collections.singletonList("andFilters")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(), Collections.emptySet());

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
   * Tests the behavior of an AND filter with multiple components.
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
    ANDJSONObjectFilter f = new ANDJSONObjectFilter(f1, f2, f3);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "and"),
              new JSONField("andFilters", new JSONArray(
                   f1.toJSONObject(),
                   f2.toJSONObject(),
                   f3.toJSONObject()))));

    f = (ANDJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getANDFilters());
    assertEquals(f.getANDFilters(), Arrays.asList(f1, f2, f3));

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "and");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Collections.singletonList("andFilters")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(), Collections.emptySet());

    assertFalse(f.matchesJSONObject(JSONObject.EMPTY_OBJECT));

    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("a", "b"))));

    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("a", "x"))));

    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("x", "b"))));

    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("a",
         new JSONArray(new JSONNumber(1234), new JSONString("a"),
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
  }



  /**
   * Tests the behavior of the methods that can be used to get and set the
   * filters to include in this AND filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetANDFilters()
         throws Exception
  {
    final ANDJSONObjectFilter f = new ANDJSONObjectFilter();
    assertNotNull(f.getANDFilters());
    assertEquals(f.getANDFilters(), Collections.emptyList());

    final EqualsJSONObjectFilter eq =
         new EqualsJSONObjectFilter("a", new JSONString("b"));
    f.setANDFilters(eq);
    assertNotNull(f.getANDFilters());
    assertEquals(f.getANDFilters(), Collections.singletonList(eq));

    final GreaterThanJSONObjectFilter gt =
         new GreaterThanJSONObjectFilter("a", 1234);
    f.setANDFilters(eq, gt);
    assertNotNull(f.getANDFilters());
    assertEquals(f.getANDFilters(), Arrays.asList(eq, gt));

    f.setANDFilters((JSONObjectFilter[]) null);
    assertNotNull(f.getANDFilters());
    assertEquals(f.getANDFilters(), Collections.emptyList());
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
         new JSONField("filterType", "and"),
         new JSONField("andFilters", new JSONArray(JSONObject.EMPTY_OBJECT))));
  }
}
