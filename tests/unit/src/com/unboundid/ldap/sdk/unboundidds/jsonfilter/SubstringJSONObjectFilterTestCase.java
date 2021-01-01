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
import java.util.List;

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



/**
 * This class provides a set of test cases for the {@code SubstringFilter}
 * class.
 */
public final class SubstringJSONObjectFilterTestCase
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
    final SubstringJSONObjectFilter f = new SubstringJSONObjectFilter();
    assertNull(f.getField());
    assertNull(f.getStartsWith());
    assertNull(f.getContains());
    assertNull(f.getEndsWith());
    assertFalse(f.caseSensitive());
  }



  /**
   * Tests the behavior of a filter that only uses the startsWith component.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStartsWith()
         throws Exception
  {
    SubstringJSONObjectFilter f =
         new SubstringJSONObjectFilter("test-field", "abc", null, null);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "substring"),
              new JSONField("field", "test-field"),
              new JSONField("startsWith", "abc")));

    f = (SubstringJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(), Collections.singletonList("test-field"));

    assertNotNull(f.getStartsWith());
    assertEquals(f.getStartsWith(), "abc");

    assertNotNull(f.getContains());
    assertTrue(f.getContains().isEmpty());

    assertNull(f.getEndsWith());

    assertFalse(f.caseSensitive());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "substring");


    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Collections.singletonList("field")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Arrays.asList("startsWith", "contains", "endsWith",
              "caseSensitive")));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "abc"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "Abc"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "ABC"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "ab"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "abcdefghijkl"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "AbCdEfGhIjKl"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "ABCDEFGHIJKL"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "defabcghi"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("Test-Field", "abc"))));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", JSONArray.EMPTY_ARRAY))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("abcdef"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("abc"),
              new JSONString("DEF"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("def"),
              new JSONString("ABC"))))));


         f.setCaseSensitive(true);
    assertTrue(f.caseSensitive());

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "substring"),
              new JSONField("field", "test-field"),
              new JSONField("startsWith", "abc"),
              new JSONField("caseSensitive", true)));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "abc"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "Abc"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "ABC"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "abcdefghijkl"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "AbCdEfGhIjKl"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "ABCDEFGHIJKL"))));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", JSONArray.EMPTY_ARRAY))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("abcdef"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("abc"),
              new JSONString("DEF"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              JSONBoolean.TRUE,
              new JSONString("abc"),
              JSONNull.NULL,
              new JSONString("DEF"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("def"),
              new JSONString("ABC"))))));
  }



  /**
   * Tests the behavior of a filter that only uses the endsWith component.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEndsWith()
         throws Exception
  {
    SubstringJSONObjectFilter f =
         new SubstringJSONObjectFilter("test-field", null, null, "jkl");

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "substring"),
              new JSONField("field", "test-field"),
              new JSONField("endsWith", "jkl")));

    f = (SubstringJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(), Collections.singletonList("test-field"));

    assertNull(f.getStartsWith());

    assertNotNull(f.getContains());
    assertTrue(f.getContains().isEmpty());

    assertNotNull(f.getEndsWith());
    assertEquals(f.getEndsWith(), "jkl");

    assertFalse(f.caseSensitive());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "substring");


    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Collections.singletonList("field")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Arrays.asList("startsWith", "contains", "endsWith",
              "caseSensitive")));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "jkl"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "jkL"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "JKL"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "kl"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "abcdefghijkl"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "AbCdEfGhIjKl"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "ABCDEFGHIJKL"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "defjklghi"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("Test-Field", "jkl"))));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", JSONArray.EMPTY_ARRAY))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("ghijkl"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              JSONNull.NULL,
              new JSONString("ghi"),
              new JSONNumber(1234),
              new JSONString("JKL"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("jkl"),
              new JSONString("GHI"))))));


    f.setCaseSensitive(true);
    assertTrue(f.caseSensitive());

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "substring"),
              new JSONField("field", "test-field"),
              new JSONField("endsWith", "jkl"),
              new JSONField("caseSensitive", true)));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "jkl"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "jkL"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "JKL"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "abcdefghijkl"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "AbCdEfGhIjKl"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "ABCDEFGHIJKL"))));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", JSONArray.EMPTY_ARRAY))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("ghijkl"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("ghi"),
              new JSONString("JKL"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("jkl"),
              new JSONString("GHI"))))));
  }



  /**
   * Tests the behavior of a filter that only uses a single contains component.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleContains()
         throws Exception
  {
    SubstringJSONObjectFilter f =
         new SubstringJSONObjectFilter("test-field", null, "defghi", null);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "substring"),
              new JSONField("field", "test-field"),
              new JSONField("contains", "defghi")));

    f = (SubstringJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(), Collections.singletonList("test-field"));

    assertNull(f.getStartsWith());

    assertNotNull(f.getContains());
    assertEquals(f.getContains(), Collections.singletonList("defghi"));

    assertNull(f.getEndsWith());

    assertFalse(f.caseSensitive());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "substring");


    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Collections.singletonList("field")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Arrays.asList("startsWith", "contains", "endsWith",
              "caseSensitive")));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "defghi"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "DeFgHi"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "DEFGHI"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "defabcghijkl"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "defghijkl"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "ABCDEFGHI"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "abcdefghijkl"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "ABCDEFGHIJKL"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("Test-Field", "defghi"))));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", JSONArray.EMPTY_ARRAY))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("defghi"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("ahcDEFghiJKL"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("abcdef"),
              new JSONString("ghijkl"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("abcjkl"),
              new JSONString("defghi"))))));


    f.setCaseSensitive(true);
    assertTrue(f.caseSensitive());

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "substring"),
              new JSONField("field", "test-field"),
              new JSONField("contains", "defghi"),
              new JSONField("caseSensitive", true)));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "defghi"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "DeFgHi"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "DEFGHI"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "defghijkl"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "ABCDEFGHI"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "abcdefghijkl"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "ABCDEFGHIJKL"))));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", JSONArray.EMPTY_ARRAY))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("defghi"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("ahcDEFghiJKL"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("abcdef"),
              new JSONString("ghijkl"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("abcjkl"),
              new JSONString("defghi"))))));
  }



  /**
   * Tests the behavior of a filter that only uses multiple contains components.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleContains()
         throws Exception
  {
    SubstringJSONObjectFilter f = new SubstringJSONObjectFilter(
         Collections.singletonList("test-field"), null,
         Arrays.asList("aba", "bab"), null);

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "substring"),
              new JSONField("field", "test-field"),
              new JSONField("contains", new JSONArray(
                   new JSONString("aba"),
                   new JSONString("bab")))));

    f = (SubstringJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(), Collections.singletonList("test-field"));

    assertNull(f.getStartsWith());

    assertNotNull(f.getContains());
    assertEquals(f.getContains(), Arrays.asList("aba", "bab"));

    assertNull(f.getEndsWith());

    assertFalse(f.caseSensitive());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "substring");


    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Collections.singletonList("field")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Arrays.asList("startsWith", "contains", "endsWith",
              "caseSensitive")));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "ababab"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "ABABAB"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "abaxbab"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "ABAxBAB"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "xabaxbabx"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "xABAxBABx"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "abab"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "bababa"))));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", JSONArray.EMPTY_ARRAY))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("aBABab"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("aba"),
              new JSONString("bab"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("ABAab"),
              new JSONString("BABab"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("AbAbAbAbA"),
              new JSONString("BaBaBaBaB"))))));


    f.setCaseSensitive(true);
    assertTrue(f.caseSensitive());

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "substring"),
              new JSONField("field", "test-field"),
              new JSONField("contains", new JSONArray(
                   new JSONString("aba"),
                   new JSONString("bab"))),
              new JSONField("caseSensitive", true)));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "ababab"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "ABABAB"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "abaxbab"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "ABAxBAB"))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "xabaxbabx"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "xABAxBABx"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "abab"))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", "bababa"))));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", JSONArray.EMPTY_ARRAY))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("ababab"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("aba"),
              new JSONString("bab"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("ABAab"),
              new JSONString("BABab"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("AbAbAbAbA"),
              new JSONString("BaBaBaBaB"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("test-field", new JSONArray(
              new JSONString("ababababa"),
              new JSONString("BaBaBaBaB"))))));
  }



  /**
   * Tests the behavior of a filter that includes all substring components.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllComponents()
         throws Exception
  {
    SubstringJSONObjectFilter f = new SubstringJSONObjectFilter(
         Arrays.asList("first", "second"), "abc", Arrays.asList("def", "ghi"),
         "jkl");

    assertNotNull(f.toJSONObject());
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "substring"),
              new JSONField("field", new JSONArray(
                   new JSONString("first"),
                   new JSONString("second"))),
              new JSONField("startsWith", "abc"),
              new JSONField("contains", new JSONArray(
                   new JSONString("def"),
                   new JSONString("ghi"))),
              new JSONField("endsWith", "jkl")));

    f = (SubstringJSONObjectFilter) JSONObjectFilter.decode(f.toJSONObject());
    assertNotNull(f);

    assertNotNull(f.getField());
    assertEquals(f.getField(), Arrays.asList("first", "second"));

    assertNotNull(f.getStartsWith());
    assertEquals(f.getStartsWith(), "abc");

    assertNotNull(f.getContains());
    assertEquals(f.getContains(), Arrays.asList("def", "ghi"));

    assertNotNull(f.getEndsWith());
    assertEquals(f.getEndsWith(), "jkl");

    assertFalse(f.caseSensitive());

    assertNotNull(f.getFilterType());
    assertEquals(f.getFilterType(), "substring");


    assertNotNull(f.getRequiredFieldNames());
    assertEquals(f.getRequiredFieldNames(),
         new HashSet<String>(Collections.singletonList("field")));

    assertNotNull(f.getOptionalFieldNames());
    assertEquals(f.getOptionalFieldNames(),
         new HashSet<String>(Arrays.asList("startsWith", "contains", "endsWith",
              "caseSensitive")));

    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("first", new JSONObject(
              new JSONField("second", "abcdefghijkl"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("first", new JSONObject(
              new JSONField("second", "AbcDefGhiJkl"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("first", new JSONObject(
              new JSONField("second", "abcghidefjkl"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("first", new JSONObject(
              new JSONField("second", "abcXXXdefXXXghiXXXjkl"))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("first", new JSONObject(
              new JSONField("second", "ABCxxxDEFxxxGHIxxxJKL"))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("first", new JSONObject(
              new JSONField("second", "xxxABCxxxDEFxxxGHIxxxJKLxxx"))))));

    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("first", new JSONObject(
              new JSONField("second", JSONArray.EMPTY_ARRAY))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("first", new JSONObject(
              new JSONField("second", new JSONArray(
              new JSONString("abcdefghijkl"))))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("first", new JSONObject(
              new JSONField("second", new JSONArray(
                   new JSONString("abcdefghijkl"),
                   new JSONString("mnopqrstuvwx"))))))));
    assertTrue(f.matchesJSONObject(new JSONObject(
         new JSONField("first", new JSONObject(
              new JSONField("second", new JSONArray(
                   new JSONString("mnopqrstuvwx"),
                   new JSONString("abcdefghijkl"))))))));
    assertFalse(f.matchesJSONObject(new JSONObject(
         new JSONField("first", new JSONObject(
              new JSONField("second", new JSONArray(
                   new JSONString("abc"),
                   new JSONString("def"),
                   new JSONString("ghi"),
                   new JSONString("jkl"))))))));
  }



  /**
   * Tests the behavior of the methods used to get and set the field name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetFields()
         throws Exception
  {
    final SubstringJSONObjectFilter f =
         new SubstringJSONObjectFilter("a", "b", "c", "d");
    f.setCaseSensitive(true);

    assertNotNull(f.getField());
    assertEquals(f.getField(), Collections.singletonList("a"));
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "substring"),
              new JSONField("field", "a"),
              new JSONField("startsWith", "b"),
              new JSONField("contains", "c"),
              new JSONField("endsWith", "d"),
              new JSONField("caseSensitive", true)));

    f.setField("different");
    assertNotNull(f.getField());
    assertEquals(f.getField(), Collections.singletonList("different"));
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "substring"),
              new JSONField("field", "different"),
              new JSONField("startsWith", "b"),
              new JSONField("contains", "c"),
              new JSONField("endsWith", "d"),
              new JSONField("caseSensitive", true)));

    f.setField("first", "second");
    assertNotNull(f.getField());
    assertEquals(f.getField(), Arrays.asList("first", "second"));
    assertEquals(f.toJSONObject(),
         new JSONObject(
              new JSONField("filterType", "substring"),
              new JSONField("field", new JSONArray(
                   new JSONString("first"),
                   new JSONString("second"))),
              new JSONField("startsWith", "b"),
              new JSONField("contains", "c"),
              new JSONField("endsWith", "d"),
              new JSONField("caseSensitive", true)));

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
   * Tests the behavior of the methods used to get and set the substring
   * components.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetSubstringComponents()
         throws Exception
  {
    final SubstringJSONObjectFilter f =
         new SubstringJSONObjectFilter("a", "b", "c", "d");
    f.setCaseSensitive(true);

    assertEquals(f.getStartsWith(), "b");
    assertEquals(f.getContains(), Arrays.asList("c"));
    assertEquals(f.getEndsWith(), "d");

    f.setSubstringComponents("a", (String) null, null);
    assertEquals(f.getStartsWith(), "a");
    assertEquals(f.getContains(), Collections.emptyList());
    assertNull(f.getEndsWith());

    f.setSubstringComponents(null, "a", null);
    assertNull(f.getStartsWith());
    assertEquals(f.getContains(), Collections.singletonList("a"));
    assertNull(f.getEndsWith());

    f.setSubstringComponents(null, (String) null, "a");
    assertNull(f.getStartsWith());
    assertEquals(f.getContains(), Collections.emptyList());
    assertEquals(f.getEndsWith(), "a");

    f.setSubstringComponents("a", Arrays.asList("b", "c"), "d");
    assertEquals(f.getStartsWith(), "a");
    assertEquals(f.getContains(), Arrays.asList("b", "c"));
    assertEquals(f.getEndsWith(), "d");

    try
    {
      f.setSubstringComponents(null, (String) null, null);
      fail("Expected an exception from setSubstringCompoennts nulls");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }

    try
    {
      f.setSubstringComponents(null, (List<String>) null, null);
      fail("Expected an exception from setSubstringCompoennts nulls");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior of the decode method with a JSON object that doesn't
   * include any of the substring components.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { JSONException.class })
  public void testDecodeNoSubstringComponents()
         throws Exception
  {
    final JSONObject o = new JSONObject(
              new JSONField("filterType", "substring"),
              new JSONField("field", "test-field"),
              new JSONField("caseSensitive", true));
    JSONObjectFilter.decode(o);
  }
}
