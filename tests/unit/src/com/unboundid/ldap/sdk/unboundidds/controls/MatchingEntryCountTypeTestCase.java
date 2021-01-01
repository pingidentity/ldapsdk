/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.HashSet;
import java.util.Set;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the matching entry count type
 * enum.
 */
public final class MatchingEntryCountTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the enum methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEnum()
         throws Exception
  {
    for (final MatchingEntryCountType t : MatchingEntryCountType.values())
    {
      assertEquals(MatchingEntryCountType.valueOf(t.getBERType()), t);

      assertEquals(MatchingEntryCountType.valueOf(t.name()), t);
    }

    assertNull(MatchingEntryCountType.valueOf((byte) 0x12));

    try
    {
      MatchingEntryCountType.valueOf("undefined");
      fail("Expected an exception for a valueOf call with an undefined name");
    }
    catch (final Exception e)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the {@code isMoreSpecificThan} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIsMoreSpecificThan()
         throws Exception
  {
    assertFalse(MatchingEntryCountType.EXAMINED_COUNT.isMoreSpecificThan(
         MatchingEntryCountType.EXAMINED_COUNT));
    assertTrue(MatchingEntryCountType.EXAMINED_COUNT.isMoreSpecificThan(
         MatchingEntryCountType.UNEXAMINED_COUNT));
    assertTrue(MatchingEntryCountType.EXAMINED_COUNT.isMoreSpecificThan(
         MatchingEntryCountType.UPPER_BOUND));
    assertTrue(MatchingEntryCountType.EXAMINED_COUNT.isMoreSpecificThan(
         MatchingEntryCountType.UNKNOWN));

    assertFalse(MatchingEntryCountType.UNEXAMINED_COUNT.isMoreSpecificThan(
         MatchingEntryCountType.EXAMINED_COUNT));
    assertFalse(MatchingEntryCountType.UNEXAMINED_COUNT.isMoreSpecificThan(
         MatchingEntryCountType.UNEXAMINED_COUNT));
    assertTrue(MatchingEntryCountType.UNEXAMINED_COUNT.isMoreSpecificThan(
         MatchingEntryCountType.UPPER_BOUND));
    assertTrue(MatchingEntryCountType.UNEXAMINED_COUNT.isMoreSpecificThan(
         MatchingEntryCountType.UNKNOWN));

    assertFalse(MatchingEntryCountType.UPPER_BOUND.isMoreSpecificThan(
         MatchingEntryCountType.EXAMINED_COUNT));
    assertFalse(MatchingEntryCountType.UPPER_BOUND.isMoreSpecificThan(
         MatchingEntryCountType.UNEXAMINED_COUNT));
    assertFalse(MatchingEntryCountType.UPPER_BOUND.isMoreSpecificThan(
         MatchingEntryCountType.UPPER_BOUND));
    assertTrue(MatchingEntryCountType.UPPER_BOUND.isMoreSpecificThan(
         MatchingEntryCountType.UNKNOWN));

    assertFalse(MatchingEntryCountType.UNKNOWN.isMoreSpecificThan(
         MatchingEntryCountType.EXAMINED_COUNT));
    assertFalse(MatchingEntryCountType.UNKNOWN.isMoreSpecificThan(
         MatchingEntryCountType.UNEXAMINED_COUNT));
    assertFalse(MatchingEntryCountType.UNKNOWN.isMoreSpecificThan(
         MatchingEntryCountType.UPPER_BOUND));
    assertFalse(MatchingEntryCountType.UNKNOWN.isMoreSpecificThan(
         MatchingEntryCountType.UNKNOWN));
  }



  /**
   * Provides test coverage for the {@code isLessSpecificThan} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIsLessSpecificThan()
         throws Exception
  {
    assertFalse(MatchingEntryCountType.EXAMINED_COUNT.isLessSpecificThan(
         MatchingEntryCountType.EXAMINED_COUNT));
    assertFalse(MatchingEntryCountType.EXAMINED_COUNT.isLessSpecificThan(
         MatchingEntryCountType.UNEXAMINED_COUNT));
    assertFalse(MatchingEntryCountType.EXAMINED_COUNT.isLessSpecificThan(
         MatchingEntryCountType.UPPER_BOUND));
    assertFalse(MatchingEntryCountType.EXAMINED_COUNT.isLessSpecificThan(
         MatchingEntryCountType.UNKNOWN));

    assertTrue(MatchingEntryCountType.UNEXAMINED_COUNT.isLessSpecificThan(
         MatchingEntryCountType.EXAMINED_COUNT));
    assertFalse(MatchingEntryCountType.UNEXAMINED_COUNT.isLessSpecificThan(
         MatchingEntryCountType.UNEXAMINED_COUNT));
    assertFalse(MatchingEntryCountType.UNEXAMINED_COUNT.isLessSpecificThan(
         MatchingEntryCountType.UPPER_BOUND));
    assertFalse(MatchingEntryCountType.UNEXAMINED_COUNT.isLessSpecificThan(
         MatchingEntryCountType.UNKNOWN));

    assertTrue(MatchingEntryCountType.UPPER_BOUND.isLessSpecificThan(
         MatchingEntryCountType.EXAMINED_COUNT));
    assertTrue(MatchingEntryCountType.UPPER_BOUND.isLessSpecificThan(
         MatchingEntryCountType.UNEXAMINED_COUNT));
    assertFalse(MatchingEntryCountType.UPPER_BOUND.isLessSpecificThan(
         MatchingEntryCountType.UPPER_BOUND));
    assertFalse(MatchingEntryCountType.UPPER_BOUND.isLessSpecificThan(
         MatchingEntryCountType.UNKNOWN));

    assertTrue(MatchingEntryCountType.UNKNOWN.isLessSpecificThan(
         MatchingEntryCountType.EXAMINED_COUNT));
    assertTrue(MatchingEntryCountType.UNKNOWN.isLessSpecificThan(
         MatchingEntryCountType.UNEXAMINED_COUNT));
    assertTrue(MatchingEntryCountType.UNKNOWN.isLessSpecificThan(
         MatchingEntryCountType.UPPER_BOUND));
    assertFalse(MatchingEntryCountType.UNKNOWN.isLessSpecificThan(
         MatchingEntryCountType.UNKNOWN));
  }



  /**
   * Tests the {@code forName} method with automated tests based on the actual
   * name of the enum values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForNameAutomated()
         throws Exception
  {
    for (final MatchingEntryCountType value : MatchingEntryCountType.values())
    {
      for (final String name : getNames(value.name()))
      {
        assertNotNull(MatchingEntryCountType.forName(name));
        assertEquals(MatchingEntryCountType.forName(name), value);
      }
    }

    assertNull(MatchingEntryCountType.forName("some undefined name"));
  }



  /**
   * Retrieves a set of names for testing the {@code forName} method based on
   * the provided set of names.
   *
   * @param  baseNames  The base set of names to use to generate the full set of
   *                    names.  It must not be {@code null} or empty.
   *
   * @return  The full set of names to use for testing.
   */
  private static Set<String> getNames(final String... baseNames)
  {
    final HashSet<String> nameSet = new HashSet<>(10);
    for (final String name : baseNames)
    {
      nameSet.add(name);
      nameSet.add(name.toLowerCase());
      nameSet.add(name.toUpperCase());

      final String nameWithDashesInsteadOfUnderscores = name.replace('_', '-');
      nameSet.add(nameWithDashesInsteadOfUnderscores);
      nameSet.add(nameWithDashesInsteadOfUnderscores.toLowerCase());
      nameSet.add(nameWithDashesInsteadOfUnderscores.toUpperCase());

      final String nameWithUnderscoresInsteadOfDashes = name.replace('-', '_');
      nameSet.add(nameWithUnderscoresInsteadOfDashes);
      nameSet.add(nameWithUnderscoresInsteadOfDashes.toLowerCase());
      nameSet.add(nameWithUnderscoresInsteadOfDashes.toUpperCase());

      final StringBuilder nameWithoutUnderscoresOrDashes = new StringBuilder();
      for (final char c : name.toCharArray())
      {
        if ((c != '-') && (c != '_'))
        {
          nameWithoutUnderscoresOrDashes.append(c);
        }
      }
      nameSet.add(nameWithoutUnderscoresOrDashes.toString());
      nameSet.add(nameWithoutUnderscoresOrDashes.toString().toLowerCase());
      nameSet.add(nameWithoutUnderscoresOrDashes.toString().toUpperCase());
    }

    return nameSet;
  }
}
