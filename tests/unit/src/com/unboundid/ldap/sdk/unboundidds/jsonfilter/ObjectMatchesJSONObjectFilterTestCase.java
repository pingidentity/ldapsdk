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
import java.util.HashSet;
import java.util.Collections;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONException;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides a set of test cases for the {@code ObjectMatchesFilter}
 * class.
 */
public final class ObjectMatchesJSONObjectFilterTestCase
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
    final ObjectMatchesJSONObjectFilter f = new ObjectMatchesJSONObjectFilter();
    assertNull(f.getField());
    assertNull(f.getFilter());
  }



  /**
   * Tests the behavior of an object matches filter under a variety of
   * conditions with a simple filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectMatchesSimpleFilter()
         throws Exception
  {
    EqualsJSONObjectFilter equalsFilter =
         new EqualsJSONObjectFilter("b", new JSONString("c"));
    ObjectMatchesJSONObjectFilter f =
         new ObjectMatchesJSONObjectFilter("a", equalsFilter);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "objectMatches"),
              new JSONField("field", "a"),
              new JSONField("filter", equalsFilter.toJSONObject())));

    f = (ObjectMatchesJSONObjectFilter)
         JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(), Collections.singletonList("a"));

    assertNotNull(f.getFilter());
    assertEquals(f.getFilter(), equalsFilter);

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "objectMatches");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Arrays.asList("field", "filter")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(), Collections.emptySet());

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", new JSONObject(
              new JSONField("b", "c"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("b", "c"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", new JSONObject(
              new JSONField("a", new JSONObject(
                   new JSONField("b", "c"))))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", new JSONArray(
              new JSONObject(
                   new JSONField("b", "c")),
              new JSONObject(
                   new JSONField("b", "d")))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", new JSONObject(
              new JSONField("b", new JSONArray(
                   new JSONString("c"), new JSONString("d"))))))));


    equalsFilter = new EqualsJSONObjectFilter(Arrays.asList("a", "b"),
         new JSONString("c"));
    f = new ObjectMatchesJSONObjectFilter("a", equalsFilter);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "objectMatches"),
              new JSONField("field", "a"),
              new JSONField("filter", equalsFilter.toJSONObject())));

    f = (ObjectMatchesJSONObjectFilter)
         JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", new JSONObject(
              new JSONField("b", "c"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("b", "c"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", new JSONObject(
              new JSONField("a", new JSONObject(
                   new JSONField("b", "c"))))))));
  }



  /**
   * Tests the behavior of an object matches filter under a variety of
   * conditions with a compound filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectMatchesCompoundFilter()
         throws Exception
  {
    final ANDJSONObjectFilter andFilter = new ANDJSONObjectFilter(
         new EqualsJSONObjectFilter("one", new JSONString("uno")),
         new EqualsJSONObjectFilter("two", new JSONString("dos")));
    ObjectMatchesJSONObjectFilter f =
         new ObjectMatchesJSONObjectFilter("a", andFilter);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "objectMatches"),
              new JSONField("field", "a"),
              new JSONField("filter", andFilter.toJSONObject())));

    f = (ObjectMatchesJSONObjectFilter)
         JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(), Collections.singletonList("a"));

    assertNotNull(f.getFilter());
    assertEquals(f.getFilter(), andFilter);

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "objectMatches");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Arrays.asList("field", "filter")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(), Collections.emptySet());


    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", new JSONObject(
              new JSONField("one", "uno"),
              new JSONField("two", "dos"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("a", new JSONArray(
              new JSONObject(
                   new JSONField("language", "Spanish"),
                   new JSONField("one", "uno"),
                   new JSONField("two", "dos")),
              new JSONObject(
                   new JSONField("language", "French"),
                   new JSONField("one", "une"),
                   new JSONField("two", "deux")),
              new JSONObject(
                   new JSONField("language", "Italian"),
                   new JSONField("one", "una"),
                   new JSONField("two", "due")))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("a", new JSONArray(
              new JSONObject(
                   new JSONField("one", "uno"),
                   new JSONField("two", "due")),
              new JSONObject(
                   new JSONField("one", "une"),
                   new JSONField("two", "dos")),
              new JSONObject(
                   new JSONField("one", "una"),
                   new JSONField("two", "deux")))))));
  }



  /**
   * Provides test coverage for the methods that can be used to get and set
   * the field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetField()
         throws Exception
  {
    final EqualsJSONObjectFilter equalsFilter =
         new EqualsJSONObjectFilter("b", new JSONString("c"));
    ObjectMatchesJSONObjectFilter f =
         new ObjectMatchesJSONObjectFilter("a", equalsFilter);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "objectMatches"),
              new JSONField("field", "a"),
              new JSONField("filter", equalsFilter.toJSONObject())));

    f = (ObjectMatchesJSONObjectFilter)
         JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(), Collections.singletonList("a"));


    f.setField("x");

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "objectMatches"),
              new JSONField("field", "x"),
              new JSONField("filter", equalsFilter.toJSONObject())));

    f = (ObjectMatchesJSONObjectFilter)
         JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(), Collections.singletonList("x"));


    f.setField("one", "two", "three");

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "objectMatches"),
              new JSONField("field", new JSONArray(
                   new JSONString("one"),
                   new JSONString("two"),
                   new JSONString("three"))),
              new JSONField("filter", equalsFilter.toJSONObject())));

    f = (ObjectMatchesJSONObjectFilter)
         JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(), Arrays.asList("one", "two", "three"));


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
   * Tests the behavior of the methods that can be used to get and set the
   * object filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetFilter()
         throws Exception
  {
    JSONObjectFilter objectFilter =
         new EqualsJSONObjectFilter("b", new JSONString("c"));
    ObjectMatchesJSONObjectFilter f =
         new ObjectMatchesJSONObjectFilter("a", objectFilter);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "objectMatches"),
              new JSONField("field", "a"),
              new JSONField("filter", objectFilter.toJSONObject())));

    f = (ObjectMatchesJSONObjectFilter)
         JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getFilter());
    assertEquals(f.getFilter(), objectFilter);


    objectFilter = new ANDJSONObjectFilter(
         new EqualsJSONObjectFilter("one", new JSONString("uno")),
         new EqualsJSONObjectFilter("two", new JSONString("dos")));
    f.setFilter(objectFilter);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "objectMatches"),
              new JSONField("field", "a"),
              new JSONField("filter", objectFilter.toJSONObject())));

    f = (ObjectMatchesJSONObjectFilter)
         JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getFilter());
    assertEquals(f.getFilter(), objectFilter);


    try
    {
      f.setFilter(null);
      fail("Expected an exception with setFilter null");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected
    }
  }



  /**
   * Tests the behavior of the decode method with a malformed object filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { JSONException.class })
  public void testDecodeMissingObjectFilter()
         throws Exception
  {
    new ObjectMatchesJSONObjectFilter().decodeFilter(new JSONObject(
         new JSONField("filterType", "objectMatches"),
         new JSONField("field", "a")));
  }



  /**
   * Tests the behavior of the decode method with a malformed object filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { JSONException.class })
  public void testDecodeObjectFilterNotObject()
         throws Exception
  {
    JSONObjectFilter.decode(new JSONObject(
         new JSONField("filterType", "objectMatches"),
         new JSONField("field", "a"),
         new JSONField("filter", "foo")));
  }



  /**
   * Tests the behavior of the decode method with a malformed object filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { JSONException.class })
  public void testDecodeMalformedObjectFilter()
         throws Exception
  {
    JSONObjectFilter.decode(new JSONObject(
         new JSONField("filterType", "objectMatches"),
         new JSONField("field", "a"),
         new JSONField("filter", JSONObject.EMPTY_OBJECT)));
  }
}
