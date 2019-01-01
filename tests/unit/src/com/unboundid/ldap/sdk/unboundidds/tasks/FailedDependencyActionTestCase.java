/*
 * Copyright 2008-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2019 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tasks;



import java.util.HashSet;
import java.util.Set;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the FailedDependencyAction class.
 */
public class FailedDependencyActionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic coverage for FailedDependencyAction values.
   *
   * @param  a  The failed dependency action value to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "failedDependencyActions")
  public void testFailedDependencyAction(final FailedDependencyAction a)
         throws Exception
  {
    assertNotNull(a);

    assertEquals(FailedDependencyAction.valueOf(a.name()), a);

    assertEquals(FailedDependencyAction.forName(a.getName()), a);

    assertNotNull(a.getName());
    assertNotNull(a.toString());
  }



  /**
   * Retrieves the set of defined failed dependency actions.
   *
   * @return  The set of defined failed dependency actions.
   */
  @DataProvider(name = "failedDependencyActions")
  public Object[][] getFailedDependencyActions()
  {
    FailedDependencyAction[] values = FailedDependencyAction.values();
    Object[][] returnArray = new Object[values.length][1];
    for (int i=0; i < values.length; i++)
    {
      returnArray[i][0] = values[i];
    }

    return returnArray;
  }



  /**
   * Tests the {@code forName} method with an invalid value.
   */
  @Test()
  public void testForNameInvalid()
  {
    assertNull(FailedDependencyAction.forName("invalid"));
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
    for (final FailedDependencyAction value : FailedDependencyAction.values())
    {
      for (final String name : getNames(value.name(), value.getName()))
      {
        assertNotNull(FailedDependencyAction.forName(name));
        assertEquals(FailedDependencyAction.forName(name), value);
      }
    }

    assertNull(FailedDependencyAction.forName("some undefined name"));
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
