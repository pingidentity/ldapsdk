/*
 * Copyright 2007-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2025 Ping Identity Corporation
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
 * Copyright (C) 2007-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.util.HashSet;
import java.util.Set;

import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the DisconnectType class.
 */
public class DisconnectTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for all methods in the disconnect type class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefinedDisconnectTypes()
         throws Exception
  {
    for (DisconnectType t : DisconnectType.values())
    {
      assertNotNull(t.name());
      assertNotNull(t.getDescription());
      assertNotNull(t.toString());

      assertEquals(DisconnectType.forName(t.name().toLowerCase()), t);
      assertEquals(DisconnectType.forName(t.name()), t);
      assertEquals(DisconnectType.valueOf(t.name()), t);
    }
  }



  /**
   * Ensures that {@code forName} returns {@code null} for an undefined type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForNameUndefined()
         throws Exception
  {
    assertNull(DisconnectType.forName("undefined"));
  }



  /**
   * Tests the {@code isExpected} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIsExpected()
         throws Exception
  {
    for (DisconnectType t : DisconnectType.values())
    {
      DisconnectType.isExpected(t);
    }
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
    for (final DisconnectType value : DisconnectType.values())
    {
      for (final String name : getNames(value.name()))
      {
        assertNotNull(DisconnectType.forName(name));
        assertEquals(DisconnectType.forName(name), value);
      }
    }

    assertNull(DisconnectType.forName("some undefined name"));
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
