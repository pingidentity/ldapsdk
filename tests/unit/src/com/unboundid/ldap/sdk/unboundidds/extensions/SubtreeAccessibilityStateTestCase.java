/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.HashSet;
import java.util.Set;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the set subtree accessibility
 * state enum.
 */
public final class SubtreeAccessibilityStateTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the valueOf method that takes an integer argument for
   * all defined accessibility types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValueOfIntDefined()
         throws Exception
  {
    for (final SubtreeAccessibilityState s : SubtreeAccessibilityState.values())
    {
      assertEquals(SubtreeAccessibilityState.valueOf(s.intValue()), s);
    }
  }



  /**
   * Tests the behavior of the valueOf method that takes a string argument for
   * all defined accessibility types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValueOfStringDefined()
         throws Exception
  {
    for (final SubtreeAccessibilityState s : SubtreeAccessibilityState.values())
    {
      assertEquals(SubtreeAccessibilityState.valueOf(s.name()), s);
    }
  }



  /**
   * Tests the behavior of the valueOf method for an undefined accessibility
   * type integer value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValueOfIntUndefined()
         throws Exception
  {
    assertNull(SubtreeAccessibilityState.valueOf(1234));
  }



  /**
   * Tests the behavior of the valueOf method for an undefined accessibility
   * type string value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IllegalArgumentException.class })
  public void testValueOfStringUndefined()
         throws Exception
  {
    SubtreeAccessibilityState.valueOf("undefined");
  }



  /**
   * Tests the behavior of the forName method for all defined accessibility
   * types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForNameDefined()
         throws Exception
  {
    for (final SubtreeAccessibilityState s : SubtreeAccessibilityState.values())
    {
      assertEquals(SubtreeAccessibilityState.forName(s.getStateName()), s);
      assertEquals(SubtreeAccessibilityState.forName(s.name()), s);
      assertNotNull(s.toString());
    }
  }



  /**
   * Tests the behavior of the forName method for an undefined accessibility
   * type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForNameUndefined()
         throws Exception
  {
    assertNull(SubtreeAccessibilityState.forName("undefined"));
  }



  /**
   * Tests the isAccessible/isHidden/isReadOnly methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIsStateMethods()
         throws Exception
  {
    assertTrue(SubtreeAccessibilityState.ACCESSIBLE.isAccessible());
    assertFalse(SubtreeAccessibilityState.ACCESSIBLE.isHidden());
    assertFalse(SubtreeAccessibilityState.ACCESSIBLE.isReadOnly());

    assertFalse(SubtreeAccessibilityState.HIDDEN.isAccessible());
    assertTrue(SubtreeAccessibilityState.HIDDEN.isHidden());
    assertFalse(SubtreeAccessibilityState.HIDDEN.isReadOnly());

    assertFalse(
         SubtreeAccessibilityState.READ_ONLY_BIND_ALLOWED.isAccessible());
    assertFalse(SubtreeAccessibilityState.READ_ONLY_BIND_ALLOWED.isHidden());
    assertTrue(SubtreeAccessibilityState.READ_ONLY_BIND_ALLOWED.isReadOnly());

    assertFalse(
         SubtreeAccessibilityState.READ_ONLY_BIND_DENIED.isAccessible());
    assertFalse(SubtreeAccessibilityState.READ_ONLY_BIND_DENIED.isHidden());
    assertTrue(SubtreeAccessibilityState.READ_ONLY_BIND_DENIED.isReadOnly());
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
    for (final SubtreeAccessibilityState value :
         SubtreeAccessibilityState.values())
    {
      for (final String name : getNames(value.name()))
      {
        assertNotNull(SubtreeAccessibilityState.forName(name));
        assertEquals(SubtreeAccessibilityState.forName(name), value);
      }
    }

    assertNull(SubtreeAccessibilityState.forName("some undefined name"));
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
