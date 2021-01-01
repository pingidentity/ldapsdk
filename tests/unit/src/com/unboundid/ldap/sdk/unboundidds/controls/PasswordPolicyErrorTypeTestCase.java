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
 * This class provides a set of test cases for the PasswordPolicyErrorType
 * enum.
 */
public class PasswordPolicyErrorTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the {@code PASSWORD_EXPIRED} element.
   */
  @Test()
  public void testPasswordExpired()
  {
    assertEquals(PasswordPolicyErrorType.PASSWORD_EXPIRED.getName(),
                 "password expired");

    assertEquals(PasswordPolicyErrorType.PASSWORD_EXPIRED.intValue(), 0);

    assertEquals(PasswordPolicyErrorType.PASSWORD_EXPIRED.toString(),
                 "password expired");

    assertEquals(PasswordPolicyErrorType.valueOf("PASSWORD_EXPIRED"),
                 PasswordPolicyErrorType.PASSWORD_EXPIRED);
  }



  /**
   * Tests the {@code ACCOUNT_LOCKED} element.
   */
  @Test()
  public void testAccountLocked()
  {
    assertEquals(PasswordPolicyErrorType.ACCOUNT_LOCKED.getName(),
                 "account locked");

    assertEquals(PasswordPolicyErrorType.ACCOUNT_LOCKED.intValue(), 1);

    assertEquals(PasswordPolicyErrorType.ACCOUNT_LOCKED.toString(),
                 "account locked");

    assertEquals(PasswordPolicyErrorType.valueOf("ACCOUNT_LOCKED"),
                 PasswordPolicyErrorType.ACCOUNT_LOCKED);
  }



  /**
   * Tests the {@code CHANGE_AFTER_RESET} element.
   */
  @Test()
  public void testChangeAfterReset()
  {
    assertEquals(PasswordPolicyErrorType.CHANGE_AFTER_RESET.getName(),
                 "change after reset");

    assertEquals(PasswordPolicyErrorType.CHANGE_AFTER_RESET.intValue(), 2);

    assertEquals(PasswordPolicyErrorType.CHANGE_AFTER_RESET.toString(),
                 "change after reset");

    assertEquals(PasswordPolicyErrorType.valueOf("CHANGE_AFTER_RESET"),
                 PasswordPolicyErrorType.CHANGE_AFTER_RESET);
  }



  /**
   * Tests the {@code PASSWORD_MOD_NOT_ALLOWED} element.
   */
  @Test()
  public void testPasswordModNotAllowed()
  {
    assertEquals(PasswordPolicyErrorType.PASSWORD_MOD_NOT_ALLOWED.getName(),
                 "password mod not allowed");

    assertEquals(PasswordPolicyErrorType.PASSWORD_MOD_NOT_ALLOWED.intValue(),
                 3);

    assertEquals(PasswordPolicyErrorType.PASSWORD_MOD_NOT_ALLOWED.toString(),
                 "password mod not allowed");

    assertEquals(PasswordPolicyErrorType.valueOf("PASSWORD_MOD_NOT_ALLOWED"),
                 PasswordPolicyErrorType.PASSWORD_MOD_NOT_ALLOWED);
  }



  /**
   * Tests the {@code MUST_SUPPLY_OLD_PASSWORD} element.
   */
  @Test()
  public void testMustSupplyOldPassword()
  {
    assertEquals(PasswordPolicyErrorType.MUST_SUPPLY_OLD_PASSWORD.getName(),
                 "must supply old password");

    assertEquals(PasswordPolicyErrorType.MUST_SUPPLY_OLD_PASSWORD.intValue(),
                 4);

    assertEquals(PasswordPolicyErrorType.MUST_SUPPLY_OLD_PASSWORD.toString(),
                 "must supply old password");

    assertEquals(PasswordPolicyErrorType.valueOf("MUST_SUPPLY_OLD_PASSWORD"),
                 PasswordPolicyErrorType.MUST_SUPPLY_OLD_PASSWORD);
  }



  /**
   * Tests the {@code INSUFFICIENT_PASSWORD_QUALITY} element.
   */
  @Test()
  public void testInsufficientPasswordQuality()
  {
    assertEquals(
         PasswordPolicyErrorType.INSUFFICIENT_PASSWORD_QUALITY.getName(),
         "insufficient password quality");

    assertEquals(
         PasswordPolicyErrorType.INSUFFICIENT_PASSWORD_QUALITY.intValue(), 5);

    assertEquals(
         PasswordPolicyErrorType.INSUFFICIENT_PASSWORD_QUALITY.toString(),
         "insufficient password quality");

    assertEquals(
         PasswordPolicyErrorType.valueOf("INSUFFICIENT_PASSWORD_QUALITY"),
         PasswordPolicyErrorType.INSUFFICIENT_PASSWORD_QUALITY);
  }



  /**
   * Tests the {@code PASSWORD_TOO_SHORT} element.
   */
  @Test()
  public void testPasswordTooShort()
  {
    assertEquals(PasswordPolicyErrorType.PASSWORD_TOO_SHORT.getName(),
                 "password too short");

    assertEquals(PasswordPolicyErrorType.PASSWORD_TOO_SHORT.intValue(), 6);

    assertEquals(PasswordPolicyErrorType.PASSWORD_TOO_SHORT.toString(),
                 "password too short");

    assertEquals(PasswordPolicyErrorType.valueOf("PASSWORD_TOO_SHORT"),
                 PasswordPolicyErrorType.PASSWORD_TOO_SHORT);
  }



  /**
   * Tests the {@code PASSWORD_TOO_YOUNG} element.
   */
  @Test()
  public void testPasswordTooYoung()
  {
    assertEquals(PasswordPolicyErrorType.PASSWORD_TOO_YOUNG.getName(),
                 "password too young");

    assertEquals(PasswordPolicyErrorType.PASSWORD_TOO_YOUNG.intValue(), 7);

    assertEquals(PasswordPolicyErrorType.PASSWORD_TOO_YOUNG.toString(),
                 "password too young");

    assertEquals(PasswordPolicyErrorType.valueOf("PASSWORD_TOO_YOUNG"),
                 PasswordPolicyErrorType.PASSWORD_TOO_YOUNG);
  }



  /**
   * Tests the {@code PASSWORD_IN_HISTORY} element.
   */
  @Test()
  public void testPasswordInHistory()
  {
    assertEquals(PasswordPolicyErrorType.PASSWORD_IN_HISTORY.getName(),
                 "password in history");

    assertEquals(PasswordPolicyErrorType.PASSWORD_IN_HISTORY.intValue(), 8);

    assertEquals(PasswordPolicyErrorType.PASSWORD_IN_HISTORY.toString(),
                 "password in history");

    assertEquals(PasswordPolicyErrorType.valueOf("PASSWORD_IN_HISTORY"),
                 PasswordPolicyErrorType.PASSWORD_IN_HISTORY);
  }



  /**
   * Tests the {@code valueOf} method that takes an integer argument.
   */
  @Test()
  public void testValueOf()
  {
    assertEquals(PasswordPolicyErrorType.valueOf(0),
                 PasswordPolicyErrorType.PASSWORD_EXPIRED);
    assertEquals(PasswordPolicyErrorType.valueOf(1),
                 PasswordPolicyErrorType.ACCOUNT_LOCKED);
    assertEquals(PasswordPolicyErrorType.valueOf(2),
                 PasswordPolicyErrorType.CHANGE_AFTER_RESET);
    assertEquals(PasswordPolicyErrorType.valueOf(3),
                 PasswordPolicyErrorType.PASSWORD_MOD_NOT_ALLOWED);
    assertEquals(PasswordPolicyErrorType.valueOf(4),
                 PasswordPolicyErrorType.MUST_SUPPLY_OLD_PASSWORD);
    assertEquals(PasswordPolicyErrorType.valueOf(5),
                 PasswordPolicyErrorType.INSUFFICIENT_PASSWORD_QUALITY);
    assertEquals(PasswordPolicyErrorType.valueOf(6),
                 PasswordPolicyErrorType.PASSWORD_TOO_SHORT);
    assertEquals(PasswordPolicyErrorType.valueOf(7),
                 PasswordPolicyErrorType.PASSWORD_TOO_YOUNG);
    assertEquals(PasswordPolicyErrorType.valueOf(8),
                 PasswordPolicyErrorType.PASSWORD_IN_HISTORY);
    assertEquals(PasswordPolicyErrorType.valueOf(9), null);
  }



  /**
   * Tests the {@code values} method.
   */
  @Test()
  public void testValues()
  {
    TreeSet<PasswordPolicyErrorType> expectedTypes =
         new TreeSet<PasswordPolicyErrorType>();
    expectedTypes.add(PasswordPolicyErrorType.PASSWORD_EXPIRED);
    expectedTypes.add(PasswordPolicyErrorType.ACCOUNT_LOCKED);
    expectedTypes.add(PasswordPolicyErrorType.CHANGE_AFTER_RESET);
    expectedTypes.add(PasswordPolicyErrorType.PASSWORD_MOD_NOT_ALLOWED);
    expectedTypes.add(PasswordPolicyErrorType.MUST_SUPPLY_OLD_PASSWORD);
    expectedTypes.add(PasswordPolicyErrorType.INSUFFICIENT_PASSWORD_QUALITY);
    expectedTypes.add(PasswordPolicyErrorType.PASSWORD_TOO_SHORT);
    expectedTypes.add(PasswordPolicyErrorType.PASSWORD_TOO_YOUNG);
    expectedTypes.add(PasswordPolicyErrorType.PASSWORD_IN_HISTORY);

    TreeSet<PasswordPolicyErrorType> gotTypes =
         new TreeSet<PasswordPolicyErrorType>();
    for (PasswordPolicyErrorType wt : PasswordPolicyErrorType.values())
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
    for (final PasswordPolicyErrorType value : PasswordPolicyErrorType.values())
    {
      for (final String name : getNames(value.name(), value.getName()))
      {
        assertNotNull(PasswordPolicyErrorType.forName(name));
        assertEquals(PasswordPolicyErrorType.forName(name), value);
      }
    }

    assertNull(PasswordPolicyErrorType.forName("some undefined name"));
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
