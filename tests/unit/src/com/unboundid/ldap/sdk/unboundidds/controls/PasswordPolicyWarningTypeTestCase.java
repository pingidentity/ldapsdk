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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the PasswordPolicyWarningType
 * enum.
 */
public class PasswordPolicyWarningTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the {@code TIME_BEFORE_EXPIRATION} element.
   */
  @Test()
  public void testTimeBeforeExpiration()
  {
    assertEquals(PasswordPolicyWarningType.TIME_BEFORE_EXPIRATION.getName(),
                 "time before expiration");

    assertEquals(PasswordPolicyWarningType.TIME_BEFORE_EXPIRATION.toString(),
                 "time before expiration");

    assertEquals(PasswordPolicyWarningType.valueOf("TIME_BEFORE_EXPIRATION"),
                 PasswordPolicyWarningType.TIME_BEFORE_EXPIRATION);
  }



  /**
   * Tests the {@code GRACE_LOGINS_REMAINING} element.
   */
  @Test()
  public void testGraceLoginsRemaining()
  {
    assertEquals(PasswordPolicyWarningType.GRACE_LOGINS_REMAINING.getName(),
                 "grace logins remaining");

    assertEquals(PasswordPolicyWarningType.GRACE_LOGINS_REMAINING.toString(),
                 "grace logins remaining");

    assertEquals(PasswordPolicyWarningType.valueOf("GRACE_LOGINS_REMAINING"),
                 PasswordPolicyWarningType.GRACE_LOGINS_REMAINING);
  }



  /**
   * Tests the {@code values} method.
   */
  @Test()
  public void testValues()
  {
    TreeSet<PasswordPolicyWarningType> expectedTypes =
         new TreeSet<PasswordPolicyWarningType>();
    expectedTypes.add(PasswordPolicyWarningType.TIME_BEFORE_EXPIRATION);
    expectedTypes.add(PasswordPolicyWarningType.GRACE_LOGINS_REMAINING);

    TreeSet<PasswordPolicyWarningType> gotTypes =
         new TreeSet<PasswordPolicyWarningType>();
    for (PasswordPolicyWarningType wt : PasswordPolicyWarningType.values())
    {
      gotTypes.add(wt);
    }

    assertEquals(gotTypes, expectedTypes);
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
    for (final PasswordPolicyWarningType value :
         PasswordPolicyWarningType.values())
    {
      for (final String name : getNames(value.name(), value.getName()))
      {
        assertNotNull(PasswordPolicyWarningType.forName(name));
        assertEquals(PasswordPolicyWarningType.forName(name), value);
      }
    }

    assertNull(PasswordPolicyWarningType.forName("some undefined name"));
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
