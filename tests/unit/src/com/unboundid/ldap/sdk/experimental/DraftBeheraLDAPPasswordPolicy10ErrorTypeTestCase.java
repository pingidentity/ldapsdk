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
package com.unboundid.ldap.sdk.experimental;



import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the
 * DraftBeheraLDAPPasswordPolicy10ErrorType enum.
 */
public class DraftBeheraLDAPPasswordPolicy10ErrorTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the {@code PASSWORD_EXPIRED} element.
   */
  @Test()
  public void testPasswordExpired()
  {
    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_EXPIRED.getName(),
         "password expired");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_EXPIRED.intValue(),
         0);

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_EXPIRED.toString(),
         "password expired");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.valueOf("PASSWORD_EXPIRED"),
         DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_EXPIRED);
  }



  /**
   * Tests the {@code ACCOUNT_LOCKED} element.
   */
  @Test()
  public void testAccountLocked()
  {
    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.ACCOUNT_LOCKED.getName(),
         "account locked");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.ACCOUNT_LOCKED.intValue(), 1);

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.ACCOUNT_LOCKED.toString(),
         "account locked");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.valueOf("ACCOUNT_LOCKED"),
         DraftBeheraLDAPPasswordPolicy10ErrorType.ACCOUNT_LOCKED);
  }



  /**
   * Tests the {@code CHANGE_AFTER_RESET} element.
   */
  @Test()
  public void testChangeAfterReset()
  {
    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.CHANGE_AFTER_RESET.getName(),
         "change after reset");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.CHANGE_AFTER_RESET.intValue(),
         2);

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.CHANGE_AFTER_RESET.toString(),
         "change after reset");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.valueOf("CHANGE_AFTER_RESET"),
         DraftBeheraLDAPPasswordPolicy10ErrorType.CHANGE_AFTER_RESET);
  }



  /**
   * Tests the {@code PASSWORD_MOD_NOT_ALLOWED} element.
   */
  @Test()
  public void testPasswordModNotAllowed()
  {
    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_MOD_NOT_ALLOWED.
              getName(),
         "password mod not allowed");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_MOD_NOT_ALLOWED.
              intValue(),
         3);

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_MOD_NOT_ALLOWED.
              toString(),
         "password mod not allowed");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.
              valueOf("PASSWORD_MOD_NOT_ALLOWED"),
         DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_MOD_NOT_ALLOWED);
  }



  /**
   * Tests the {@code MUST_SUPPLY_OLD_PASSWORD} element.
   */
  @Test()
  public void testMustSupplyOldPassword()
  {
    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.MUST_SUPPLY_OLD_PASSWORD.
              getName(),
         "must supply old password");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.MUST_SUPPLY_OLD_PASSWORD.
              intValue(),
         4);

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.MUST_SUPPLY_OLD_PASSWORD.
              toString(),
         "must supply old password");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.
              valueOf("MUST_SUPPLY_OLD_PASSWORD"),
         DraftBeheraLDAPPasswordPolicy10ErrorType.MUST_SUPPLY_OLD_PASSWORD);
  }



  /**
   * Tests the {@code INSUFFICIENT_PASSWORD_QUALITY} element.
   */
  @Test()
  public void testInsufficientPasswordQuality()
  {
    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.INSUFFICIENT_PASSWORD_QUALITY.
              getName(),
         "insufficient password quality");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.INSUFFICIENT_PASSWORD_QUALITY.
              intValue(), 5);

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.INSUFFICIENT_PASSWORD_QUALITY.
              toString(),
         "insufficient password quality");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.
              valueOf("INSUFFICIENT_PASSWORD_QUALITY"),
         DraftBeheraLDAPPasswordPolicy10ErrorType.
              INSUFFICIENT_PASSWORD_QUALITY);
  }



  /**
   * Tests the {@code PASSWORD_TOO_SHORT} element.
   */
  @Test()
  public void testPasswordTooShort()
  {
    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_TOO_SHORT.getName(),
         "password too short");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_TOO_SHORT.intValue(),
         6);

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_TOO_SHORT.toString(),
         "password too short");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.valueOf("PASSWORD_TOO_SHORT"),
         DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_TOO_SHORT);
  }



  /**
   * Tests the {@code PASSWORD_TOO_YOUNG} element.
   */
  @Test()
  public void testPasswordTooYoung()
  {
    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_TOO_YOUNG.getName(),
         "password too young");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_TOO_YOUNG.intValue(),
         7);

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_TOO_YOUNG.toString(),
         "password too young");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.valueOf("PASSWORD_TOO_YOUNG"),
         DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_TOO_YOUNG);
  }



  /**
   * Tests the {@code PASSWORD_IN_HISTORY} element.
   */
  @Test()
  public void testPasswordInHistory()
  {
    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_IN_HISTORY.getName(),
         "password in history");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_IN_HISTORY.
              intValue(),
         8);

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_IN_HISTORY.
              toString(),
         "password in history");

    assertEquals(
         DraftBeheraLDAPPasswordPolicy10ErrorType.
              valueOf("PASSWORD_IN_HISTORY"),
         DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_IN_HISTORY);
  }



  /**
   * Tests the {@code valueOf} method that takes an integer argument.
   */
  @Test()
  public void testValueOf()
  {
    assertEquals(DraftBeheraLDAPPasswordPolicy10ErrorType.valueOf(0),
                 DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_EXPIRED);
    assertEquals(DraftBeheraLDAPPasswordPolicy10ErrorType.valueOf(1),
                 DraftBeheraLDAPPasswordPolicy10ErrorType.ACCOUNT_LOCKED);
    assertEquals(DraftBeheraLDAPPasswordPolicy10ErrorType.valueOf(2),
                 DraftBeheraLDAPPasswordPolicy10ErrorType.CHANGE_AFTER_RESET);
    assertEquals(DraftBeheraLDAPPasswordPolicy10ErrorType.valueOf(3),
                 DraftBeheraLDAPPasswordPolicy10ErrorType.
                      PASSWORD_MOD_NOT_ALLOWED);
    assertEquals(DraftBeheraLDAPPasswordPolicy10ErrorType.valueOf(4),
                 DraftBeheraLDAPPasswordPolicy10ErrorType.
                      MUST_SUPPLY_OLD_PASSWORD);
    assertEquals(DraftBeheraLDAPPasswordPolicy10ErrorType.valueOf(5),
                 DraftBeheraLDAPPasswordPolicy10ErrorType.
                      INSUFFICIENT_PASSWORD_QUALITY);
    assertEquals(DraftBeheraLDAPPasswordPolicy10ErrorType.valueOf(6),
                 DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_TOO_SHORT);
    assertEquals(DraftBeheraLDAPPasswordPolicy10ErrorType.valueOf(7),
                 DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_TOO_YOUNG);
    assertEquals(DraftBeheraLDAPPasswordPolicy10ErrorType.valueOf(8),
                 DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_IN_HISTORY);
    assertEquals(DraftBeheraLDAPPasswordPolicy10ErrorType.valueOf(9), null);
  }



  /**
   * Tests the {@code values} method.
   */
  @Test()
  public void testValues()
  {
    TreeSet<DraftBeheraLDAPPasswordPolicy10ErrorType> expectedTypes =
         new TreeSet<DraftBeheraLDAPPasswordPolicy10ErrorType>();
    expectedTypes.add(DraftBeheraLDAPPasswordPolicy10ErrorType.
         PASSWORD_EXPIRED);
    expectedTypes.add(DraftBeheraLDAPPasswordPolicy10ErrorType.
         ACCOUNT_LOCKED);
    expectedTypes.add(DraftBeheraLDAPPasswordPolicy10ErrorType.
         CHANGE_AFTER_RESET);
    expectedTypes.add(DraftBeheraLDAPPasswordPolicy10ErrorType.
         PASSWORD_MOD_NOT_ALLOWED);
    expectedTypes.add(DraftBeheraLDAPPasswordPolicy10ErrorType.
         MUST_SUPPLY_OLD_PASSWORD);
    expectedTypes.add(DraftBeheraLDAPPasswordPolicy10ErrorType.
         INSUFFICIENT_PASSWORD_QUALITY);
    expectedTypes.add(DraftBeheraLDAPPasswordPolicy10ErrorType.
         PASSWORD_TOO_SHORT);
    expectedTypes.add(DraftBeheraLDAPPasswordPolicy10ErrorType.
         PASSWORD_TOO_YOUNG);
    expectedTypes.add(DraftBeheraLDAPPasswordPolicy10ErrorType.
         PASSWORD_IN_HISTORY);

    TreeSet<DraftBeheraLDAPPasswordPolicy10ErrorType> gotTypes =
         new TreeSet<DraftBeheraLDAPPasswordPolicy10ErrorType>();
    for (DraftBeheraLDAPPasswordPolicy10ErrorType wt :
         DraftBeheraLDAPPasswordPolicy10ErrorType.values())
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
    for (final DraftBeheraLDAPPasswordPolicy10ErrorType value :
         DraftBeheraLDAPPasswordPolicy10ErrorType.values())
    {
      for (final String name : getNames(value.name(), value.getName()))
      {
        assertNotNull(DraftBeheraLDAPPasswordPolicy10ErrorType.forName(name));
        assertEquals(DraftBeheraLDAPPasswordPolicy10ErrorType.forName(name),
             value);
      }
    }

    assertNull(DraftBeheraLDAPPasswordPolicy10ErrorType.forName(
         "some undefined name"));
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
