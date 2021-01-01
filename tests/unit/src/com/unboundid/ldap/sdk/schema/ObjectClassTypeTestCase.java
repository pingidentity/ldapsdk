/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.schema;



import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the ObjectClassType enum.
 */
public class ObjectClassTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the {@code ABSTRACT} element.
   */
  @Test()
  public void testAbstract()
  {
    assertEquals(ObjectClassType.ABSTRACT.getName(), "ABSTRACT");

    assertEquals(ObjectClassType.ABSTRACT.toString(), "ABSTRACT");

    assertEquals(ObjectClassType.valueOf("ABSTRACT"),
                 ObjectClassType.ABSTRACT);

    assertEquals(ObjectClassType.forName("ABSTRACT"),
         ObjectClassType.ABSTRACT);
  }



  /**
   * Tests the {@code AUXILIARY} element.
   */
  @Test()
  public void testAuxiliary()
  {
    assertEquals(ObjectClassType.AUXILIARY.getName(), "AUXILIARY");

    assertEquals(ObjectClassType.AUXILIARY.toString(), "AUXILIARY");

    assertEquals(ObjectClassType.valueOf("AUXILIARY"),
                 ObjectClassType.AUXILIARY);

    assertEquals(ObjectClassType.forName("AUXILIARY"),
         ObjectClassType.AUXILIARY);
  }



  /**
   * Tests the {@code STRUCTURAL} element.
   */
  @Test()
  public void testStructural()
  {
    assertEquals(ObjectClassType.STRUCTURAL.getName(), "STRUCTURAL");

    assertEquals(ObjectClassType.STRUCTURAL.toString(), "STRUCTURAL");

    assertEquals(ObjectClassType.valueOf("STRUCTURAL"),
                 ObjectClassType.STRUCTURAL);

    assertEquals(ObjectClassType.forName("STRUCTURAL"),
         ObjectClassType.STRUCTURAL);
  }



  /**
   * Tests the {@code values} method.
   */
  @Test()
  public void testValues()
  {
    TreeSet<ObjectClassType> expectedSet = new TreeSet<ObjectClassType>();
    expectedSet.add(ObjectClassType.ABSTRACT);
    expectedSet.add(ObjectClassType.AUXILIARY);
    expectedSet.add(ObjectClassType.STRUCTURAL);

    TreeSet<ObjectClassType> valuesSet = new TreeSet<ObjectClassType>();
    for (ObjectClassType type : ObjectClassType.values())
    {
      valuesSet.add(type);
    }

    assertEquals(valuesSet, expectedSet);
  }



  /**
   * Tests the behavior of the {@code forName} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForName()
         throws Exception
  {
    for (final ObjectClassType usage : ObjectClassType.values())
    {
      assertEquals(ObjectClassType.forName(usage.getName()), usage);
      assertEquals(ObjectClassType.forName(usage.getName().toLowerCase()),
           usage);
      assertEquals(ObjectClassType.forName(usage.getName().toUpperCase()),
           usage);
    }

    assertNull(ObjectClassType.forName("undefined"));
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
    for (final ObjectClassType value : ObjectClassType.values())
    {
      for (final String name : getNames(value.name(), value.getName()))
      {
        assertNotNull(ObjectClassType.forName(name));
        assertEquals(ObjectClassType.forName(name), value);
      }
    }

    assertNull(ObjectClassType.forName("some undefined name"));
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
