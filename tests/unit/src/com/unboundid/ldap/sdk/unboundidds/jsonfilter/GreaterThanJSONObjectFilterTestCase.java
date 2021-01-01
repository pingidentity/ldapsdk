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
import com.unboundid.util.json.JSONValue;



/**
 * This class provides a set of test cases for the {@code GreaterThanFilter}
 * class.
 */
public final class GreaterThanJSONObjectFilterTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the greater-than filter with a numeric value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGreaterThanNumber()
         throws Exception
  {
    GreaterThanJSONObjectFilter f =
         new GreaterThanJSONObjectFilter("test-field", 5678);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "greaterThan"),
              new JSONField("field", "test-field"),
              new JSONField("value", 5678)));

    f = (GreaterThanJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(), Collections.singletonList("test-field"));

    assertNotNull(f.getValue());
    assertEquals(f.getValue(), new JSONNumber(5678));

    assertFalse(f.allowEquals());

    assertFalse(f.matchAllElements());

    assertFalse(f.caseSensitive());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "greaterThan");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Arrays.asList("field", "value")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Arrays.asList("allowEquals", "matchAllElements",
              "caseSensitive")));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 5679))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "foo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", Boolean.TRUE))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("Test-Field", 5679))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 9999))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 10000))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 999))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 5678.5))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 5678))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 5678.0))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "foo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "5679"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONNumber(5679))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONNumber(5678), new JSONNumber(5679),
              new JSONNumber(10000))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONNumber(1234), new JSONNumber(5679),
              new JSONNumber(10000))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONNumber(5679), new JSONNumber(10000))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONNumber(5679), new JSONNumber(10000),
              new JSONString("foo"), JSONNull.NULL)))));


    f.setMatchAllElements(true);

    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "greaterThan"),
              new JSONField("field", "test-field"),
              new JSONField("value", 5678),
              new JSONField("matchAllElements", true)));

    f = (GreaterThanJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertTrue(f.matchAllElements());

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 5679))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "foo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", Boolean.TRUE))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("Test-Field", 5679))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 9999))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 10000))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 999))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 5679))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 5678.5))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 5678))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 5678.0))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "foo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "5679"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONNumber(5679))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONNumber(5678), new JSONNumber(5679),
              new JSONNumber(10000))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONNumber(1234), new JSONNumber(5679),
              new JSONNumber(10000))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONNumber(5679), new JSONNumber(10000))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONNumber(5679), new JSONNumber(10000),
              new JSONString("foo"), JSONNull.NULL)))));


    f.setAllowEquals(true);

    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "greaterThan"),
              new JSONField("field", "test-field"),
              new JSONField("value", 5678),
              new JSONField("matchAllElements", true),
              new JSONField("allowEquals", true)));

    f = (GreaterThanJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertTrue(f.allowEquals());

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 5679))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "foo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", Boolean.TRUE))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("Test-Field", 5679))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 9999))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 10000))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 999))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 5679))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 5678.5))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 5678))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 5678.0))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "foo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "5679"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONNumber(5679))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONNumber(5678), new JSONNumber(5679),
              new JSONNumber(10000))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONNumber(1234), new JSONNumber(5679),
              new JSONNumber(10000))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONNumber(5679), new JSONNumber(10000))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONNumber(5679), new JSONNumber(10000),
              new JSONString("foo"), JSONNull.NULL)))));
  }



  /**
   * Tests the behavior of the greater-than filter with a string value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGreaterThanString()
         throws Exception
  {
    GreaterThanJSONObjectFilter f =
         new GreaterThanJSONObjectFilter("test-field", "foo");

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "greaterThan"),
              new JSONField("field", "test-field"),
              new JSONField("value", "foo")));

    f = (GreaterThanJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(), Collections.singletonList("test-field"));

    assertNotNull(f.getValue());
    assertEquals(f.getValue(), new JSONString("foo"));

    assertFalse(f.allowEquals());

    assertFalse(f.matchAllElements());

    assertFalse(f.caseSensitive());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "greaterThan");

    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Arrays.asList("field", "value")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Arrays.asList("allowEquals", "matchAllElements",
              "caseSensitive")));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "goo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 1234))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", Boolean.TRUE))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("Test-Field", "goo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "foo"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "fro"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "fool"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "fo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "f"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "go"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "g"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "GOO"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FOO"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FRO"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FOOL"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FO"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "F"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "GO"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "G"))));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("goo"),
              new JSONString("fool"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("foo"),
              new JSONString("fool"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("boo"),
              new JSONString("goo"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("GOO"),
              new JSONString("FOOL"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("FOO"),
              new JSONString("FOOL"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("BOO"),
              new JSONString("GOO"))))));


    f.setMatchAllElements(true);

    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "greaterThan"),
              new JSONField("field", "test-field"),
              new JSONField("value", "foo"),
              new JSONField("matchAllElements", true)));

    f = (GreaterThanJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertTrue(f.matchAllElements());

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "goo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 1234))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", Boolean.TRUE))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("Test-Field", "goo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "foo"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "fro"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "fool"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "fo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "f"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "go"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "g"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "GOO"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FOO"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FRO"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FOOL"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FO"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "F"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "GO"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "G"))));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("goo"),
              new JSONString("fool"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("foo"),
              new JSONString("fool"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("boo"),
              new JSONString("goo"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("GOO"),
              new JSONString("FOOL"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("FOO"),
              new JSONString("FOOL"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("BOO"),
              new JSONString("GOO"))))));


    f.setAllowEquals(true);

    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "greaterThan"),
              new JSONField("field", "test-field"),
              new JSONField("value", "foo"),
              new JSONField("matchAllElements", true),
              new JSONField("allowEquals", true)));

    f = (GreaterThanJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertTrue(f.allowEquals());

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "goo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 1234))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", Boolean.TRUE))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("Test-Field", "goo"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "foo"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "fro"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "fool"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "fo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "f"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "go"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "g"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "GOO"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FOO"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FRO"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FOOL"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FO"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "F"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "GO"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "G"))));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("goo"),
              new JSONString("fool"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("foo"),
              new JSONString("fool"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("boo"),
              new JSONString("goo"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("GOO"),
              new JSONString("FOOL"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("FOO"),
              new JSONString("FOOL"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("BOO"),
              new JSONString("GOO"))))));


    f.setCaseSensitive(true);

    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "greaterThan"),
              new JSONField("field", "test-field"),
              new JSONField("value", "foo"),
              new JSONField("matchAllElements", true),
              new JSONField("allowEquals", true),
              new JSONField("caseSensitive", true)));

    f = (GreaterThanJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertTrue(f.caseSensitive());

    // NOTE:  All uppercase characters are considered "less than" all lowercase.

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "goo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 1234))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", Boolean.TRUE))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("Test-Field", "goo"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "foo"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "fro"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "fool"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "fo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "f"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "go"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "g"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "GOO"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FOO"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FRO"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FOOL"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FO"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "F"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "GO"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "G"))));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("goo"),
              new JSONString("fool"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("foo"),
              new JSONString("fool"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("boo"),
              new JSONString("goo"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("GOO"),
              new JSONString("FOOL"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("FOO"),
              new JSONString("FOOL"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("BOO"),
              new JSONString("GOO"))))));


    f.setAllowEquals(false);

    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "greaterThan"),
              new JSONField("field", "test-field"),
              new JSONField("value", "foo"),
              new JSONField("matchAllElements", true),
              new JSONField("caseSensitive", true)));

    f = (GreaterThanJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertFalse(f.allowEquals());

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "goo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", 1234))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", Boolean.TRUE))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("Test-Field", "goo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "foo"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "fro"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "fool"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "fo"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "f"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "go"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "g"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "GOO"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FOO"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FRO"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FOOL"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "FO"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "F"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "GO"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "G"))));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("goo"),
              new JSONString("fool"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("foo"),
              new JSONString("fool"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("boo"),
              new JSONString("goo"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("GOO"),
              new JSONString("FOOL"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("FOO"),
              new JSONString("FOOL"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("BOO"),
              new JSONString("GOO"))))));
  }



  /**
   * Provides test coverage for the various constructors available for
   * greater-than filters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructors()
         throws Exception
  {
    GreaterThanJSONObjectFilter f = new GreaterThanJSONObjectFilter();
    assertNull(f.getField());
    assertNull(f.getValue());
    assertFalse(f.allowEquals());
    assertFalse(f.matchAllElements());
    assertFalse(f.caseSensitive());

    f = new GreaterThanJSONObjectFilter("a", 1234);
    assertEquals(f.getField(), Collections.singletonList("a"));
    assertEquals(f.getValue(), new JSONNumber(1234));
    assertFalse(f.allowEquals());
    assertFalse(f.matchAllElements());
    assertFalse(f.caseSensitive());
    assertNotNull(f.toJSONObject());

    f = new GreaterThanJSONObjectFilter("a", 1234.5);
    assertEquals(f.getField(), Collections.singletonList("a"));
    assertEquals(f.getValue(), new JSONNumber(1234.5));
    assertFalse(f.allowEquals());
    assertFalse(f.matchAllElements());
    assertFalse(f.caseSensitive());
    assertNotNull(f.toJSONObject());

    f = new GreaterThanJSONObjectFilter("a", "foo");
    assertEquals(f.getField(), Collections.singletonList("a"));
    assertEquals(f.getValue(), new JSONString("foo"));
    assertFalse(f.allowEquals());
    assertFalse(f.matchAllElements());
    assertFalse(f.caseSensitive());
    assertNotNull(f.toJSONObject());

    f = new GreaterThanJSONObjectFilter("a", new JSONNumber("1.234e3"));
    assertEquals(f.getField(), Collections.singletonList("a"));
    assertEquals(f.getValue(), new JSONNumber(1234));
    assertFalse(f.allowEquals());
    assertFalse(f.matchAllElements());
    assertFalse(f.caseSensitive());
    assertNotNull(f.toJSONObject());

    try
    {
      f = new GreaterThanJSONObjectFilter("a", JSONNull.NULL);
      fail("Expected an exception from greaterThan with null");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }

    f = new GreaterThanJSONObjectFilter(Arrays.asList("a", "b", "c"),
         new JSONString("bar"));
    assertEquals(f.getField(), Arrays.asList("a", "b", "c"));
    assertEquals(f.getValue(), new JSONString("bar"));
    assertFalse(f.allowEquals());
    assertFalse(f.matchAllElements());
    assertFalse(f.caseSensitive());
    assertNotNull(f.toJSONObject());

    try
    {
      f = new GreaterThanJSONObjectFilter(Arrays.asList("a", "b", "c"),
           JSONBoolean.TRUE);
      fail("Expected an exception from greaterThan with true");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the methods that can be used to get and set the
   * field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetField()
         throws Exception
  {
    final GreaterThanJSONObjectFilter f =
         new GreaterThanJSONObjectFilter("a", 1234);
    assertEquals(f.getField(), Collections.singletonList("a"));

    f.setField("b");
    assertEquals(f.getField(), Collections.singletonList("b"));

    f.setField("c", "d");
    assertEquals(f.getField(), Arrays.asList("c", "d"));

    f.setField("e", "f", "g");
    assertEquals(f.getField(), Arrays.asList("e", "f", "g"));

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
   * Provides test coverage for the methods that can be used to get and set the
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetValue()
         throws Exception
  {
    final GreaterThanJSONObjectFilter f =
         new GreaterThanJSONObjectFilter("a", 1234);
    assertEquals(f.getValue(), new JSONNumber(1234));

    f.setValue(5678);
    assertEquals(f.getValue(), new JSONNumber(5678));

    f.setValue(1234.5);
    assertEquals(f.getValue(), new JSONNumber(1234.5));

    f.setValue("foo");
    assertEquals(f.getValue(), new JSONString("foo"));

    f.setValue(new JSONNumber("1.234e3"));
    assertEquals(f.getValue(), new JSONNumber(1234));

    f.setValue(new JSONString("1.234e3"));
    assertEquals(f.getValue(), new JSONString("1.234e3"));

    try
    {
      f.setValue((String) null);
      fail("Expected an exception from setValue String null");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }

    try
    {
      f.setValue((JSONValue) null);
      fail("Expected an exception from setValue JSONValue null");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }

    try
    {
      f.setValue(JSONBoolean.TRUE);
      fail("Expected an exception from setValue true");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }
  }
}
