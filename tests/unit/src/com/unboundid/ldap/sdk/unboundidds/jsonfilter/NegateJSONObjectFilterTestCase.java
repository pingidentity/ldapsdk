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



import java.util.HashSet;
import java.util.Collections;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.json.JSONException;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides a set of test cases for the {@code NegateFilter} class.
 */
public final class NegateJSONObjectFilterTestCase
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
    final NegateJSONObjectFilter f = new NegateJSONObjectFilter();
    assertNull(f.getNegateFilter());
  }



  /**
   * Tests the behavior of a negate filter under normal conditions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNegateFilter()
         throws Exception
  {
    final EqualsJSONObjectFilter equalsFilter =
         new EqualsJSONObjectFilter("a", new JSONString("b"));
    NegateJSONObjectFilter f = new NegateJSONObjectFilter(equalsFilter);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "negate"),
              new JSONField("negateFilter", equalsFilter.toJSONObject())));

    f = (NegateJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getNegateFilter());
    assertEquals(f.getNegateFilter(), equalsFilter);

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "negate");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Collections.singletonList("negateFilter")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(), Collections.emptySet());

    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("a", "b"))));
    assertTrue(f.matchesJSONObject(new JSONObject(new JSONField("a", 1234))));
    assertTrue(f.matchesJSONObject(new JSONObject(new JSONField("a", true))));
    assertTrue(f.matchesJSONObject(new JSONObject(new JSONField("b", "a"))));
    assertTrue(f.matchesJSONObject(new JSONObject(new JSONField("b", "b"))));
    assertTrue(f.matchesJSONObject(new JSONObject()));


    final ANDJSONObjectFilter andFilter = new ANDJSONObjectFilter();
    f.setNegateFilter(andFilter);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "negate"),
              new JSONField("negateFilter", andFilter.toJSONObject())));

    f = (NegateJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("a", "b"))));
    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("a", 1234))));
    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("a", true))));
    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("b", "a"))));
    assertFalse(f.matchesJSONObject(new JSONObject(new JSONField("b", "b"))));
    assertFalse(f.matchesJSONObject(new JSONObject()));


    final ORJSONObjectFilter orFilter = new ORJSONObjectFilter();
    f.setNegateFilter(orFilter);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "negate"),
              new JSONField("negateFilter", orFilter.toJSONObject())));

    f = (NegateJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertTrue(f.matchesJSONObject(new JSONObject(new JSONField("a", "b"))));
    assertTrue(f.matchesJSONObject(new JSONObject(new JSONField("a", 1234))));
    assertTrue(f.matchesJSONObject(new JSONObject(new JSONField("a", true))));
    assertTrue(f.matchesJSONObject(new JSONObject(new JSONField("b", "a"))));
    assertTrue(f.matchesJSONObject(new JSONObject(new JSONField("b", "b"))));
    assertTrue(f.matchesJSONObject(new JSONObject()));

    try
    {
      f.setNegateFilter(null);
      fail("Expected an exception from setNegateFilter(null)");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected
    }
  }



  /**
   * Tests the behavior of the decode method with a malformed negate filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { JSONException.class })
  public void testDecodeMissingNegateFilter()
         throws Exception
  {
    new NegateJSONObjectFilter().decodeFilter(new JSONObject(
         new JSONField("filterType", "negate")));
  }



  /**
   * Tests the behavior of the decode method with a malformed negate filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { JSONException.class })
  public void testDecodeNegateFilterNotObject()
         throws Exception
  {
    JSONObjectFilter.decode(new JSONObject(
         new JSONField("filterType", "negate"),
         new JSONField("negateFilter", "foo")));
  }



  /**
   * Tests the behavior of the decode method with a malformed negate filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { JSONException.class })
  public void testDecodeMalformedNegateFilter()
         throws Exception
  {
    JSONObjectFilter.decode(new JSONObject(
         new JSONField("filterType", "negate"),
         new JSONField("negateFilter", JSONObject.EMPTY_OBJECT)));
  }
}
