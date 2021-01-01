/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code AttributeRight} enum.
 */
public class AttributeRightTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the getName method.
   *
   * @param  r  The attribute right to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="attributeRights")
  public void testGetName(AttributeRight r)
         throws Exception
  {
    assertNotNull(r.getName());
  }



  /**
   * Provides test coverage for the forName method with a valid name.
   *
   * @param  r  The attribute right to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="attributeRights")
  public void testForNameValid(AttributeRight r)
         throws Exception
  {
    assertEquals(AttributeRight.forName(r.getName()), r);
    assertEquals(AttributeRight.forName(r.getName().toUpperCase()), r);
    assertEquals(AttributeRight.forName(r.getName().toLowerCase()), r);
  }



  /**
   * Provides test coverage for the forName method with an invalid name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForNameInvalid()
         throws Exception
  {
    assertNull(AttributeRight.forName("invalid"));
  }



  /**
   * Provides test coverage for the toString method.
   *
   * @param  r  The attribute right to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="attributeRights")
  public void testToString(AttributeRight r)
         throws Exception
  {
    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for the name method.
   *
   * @param  r  The attribute right to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="attributeRights")
  public void testName(AttributeRight r)
         throws Exception
  {
    assertNotNull(r.name());
  }



  /**
   * Provides test coverage for the valueOf method with a valid name.
   *
   * @param  r  The attribute right to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="attributeRights")
  public void testValueOfValid(AttributeRight r)
         throws Exception
  {
    assertNotNull(AttributeRight.valueOf(r.name()));
  }



  /**
   * Provides test coverage for the valueOf method with an invalid name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IllegalArgumentException.class })
  public void testValueOfInvalid()
         throws Exception
  {
    AttributeRight.valueOf("invalid");
  }



  /**
   * Provides test coverage for the values method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValues()
         throws Exception
  {
    assertNotNull(AttributeRight.values());
    assertFalse(AttributeRight.values().length == 0);
  }



  /**
   * Retrieves a set of attribute rights for testing purposes.
   *
   * @return  A set of attribute rights for testing purposes.
   */
  @DataProvider(name = "attributeRights")
  public Object[][] getAttributeRights()
  {
    Object[][] allRights = new Object[AttributeRight.values().length][1];
    for (int i=0; i < allRights.length; i++)
    {
      allRights[i][0] = AttributeRight.values()[i];
    }

    return allRights;
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
    for (final AttributeRight value : AttributeRight.values())
    {
      for (final String name : getNames(value.name(), value.getName()))
      {
        assertNotNull(AttributeRight.forName(name));
        assertEquals(AttributeRight.forName(name), value);
      }
    }

    assertNull(AttributeRight.forName("some undefined name"));
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
