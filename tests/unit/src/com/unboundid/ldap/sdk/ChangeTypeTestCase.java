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
package com.unboundid.ldap.sdk;



import java.util.HashSet;
import java.util.Set;

import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the ChangeType class.
 */
public class ChangeTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the {@code getName} method.
   */
  @Test()
  public void testGetName()
  {
    assertEquals(ChangeType.ADD.getName(), "add");
    assertEquals(ChangeType.DELETE.getName(), "delete");
    assertEquals(ChangeType.MODIFY.getName(), "modify");
    assertEquals(ChangeType.MODIFY_DN.getName(), "moddn");
  }



  /**
   * Tests the {@code forName} method.
   */
  @Test()
  public void testForName()
  {
    assertEquals(ChangeType.forName("add"), ChangeType.ADD);
    assertEquals(ChangeType.forName("delete"), ChangeType.DELETE);
    assertEquals(ChangeType.forName("modify"), ChangeType.MODIFY);
    assertEquals(ChangeType.forName("moddn"), ChangeType.MODIFY_DN);
    assertEquals(ChangeType.forName("modrdn"), ChangeType.MODIFY_DN);

    assertEquals(ChangeType.forName("ADD"), ChangeType.ADD);
    assertEquals(ChangeType.forName("DELETE"), ChangeType.DELETE);
    assertEquals(ChangeType.forName("MODIFY"), ChangeType.MODIFY);
    assertEquals(ChangeType.forName("MODDN"), ChangeType.MODIFY_DN);
    assertEquals(ChangeType.forName("MODRDN"), ChangeType.MODIFY_DN);

    assertEquals(ChangeType.forName("aDd"), ChangeType.ADD);
    assertEquals(ChangeType.forName("dElEtE"), ChangeType.DELETE);
    assertEquals(ChangeType.forName("mOdIfY"), ChangeType.MODIFY);
    assertEquals(ChangeType.forName("mOdDn"), ChangeType.MODIFY_DN);
    assertEquals(ChangeType.forName("mOdRdN"), ChangeType.MODIFY_DN);

    assertNull(ChangeType.forName("invalid"));
  }



  /**
   * Tests the {@code valueOf} method.
   */
  @Test()
  public void testValueOf()
  {
    assertEquals(ChangeType.valueOf("ADD"), ChangeType.ADD);
    assertEquals(ChangeType.valueOf("DELETE"), ChangeType.DELETE);
    assertEquals(ChangeType.valueOf("MODIFY"), ChangeType.MODIFY);
    assertEquals(ChangeType.valueOf("MODIFY_DN"), ChangeType.MODIFY_DN);
  }



  /**
   * Tests the {@code toString} method.
   */
  @Test()
  public void testToString()
  {
    assertEquals(ChangeType.ADD.toString(), "add");
    assertEquals(ChangeType.DELETE.toString(), "delete");
    assertEquals(ChangeType.MODIFY.toString(), "modify");
    assertEquals(ChangeType.MODIFY_DN.toString(), "moddn");
  }



  /**
   * Tests the {@code values} method.
   */
  @Test()
  public void testValues()
  {
    assertEquals(ChangeType.values().length, 4);
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
    for (final ChangeType value : ChangeType.values())
    {
      for (final String name : getNames(value.name(), value.getName()))
      {
        assertNotNull(ChangeType.forName(name));
        assertEquals(ChangeType.forName(name), value);
      }
    }

    assertNull(ChangeType.forName("some undefined name"));
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
