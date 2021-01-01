/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the password update behavior
 * request control properties.
 */
public final class PasswordUpdateBehaviorRequestControlPropertiesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for the case in which all of the properties have their
   * default null values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultProperties()
         throws Exception
  {
    final PasswordUpdateBehaviorRequestControlProperties properties =
         new PasswordUpdateBehaviorRequestControlProperties();

    assertNull(properties.getIsSelfChange());

    assertNull(properties.getAllowPreEncodedPassword());

    assertNull(properties.getSkipPasswordValidation());

    assertNull(properties.getIgnorePasswordHistory());

    assertNull(properties.getIgnoreMinimumPasswordAge());

    assertNull(properties.getPasswordStorageScheme());

    assertNull(properties.getMustChangePassword());

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the case in which all of the properties are set with
   * non-default values, and in which the Boolean values are all true.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllTrueProperties()
         throws Exception
  {
    final PasswordUpdateBehaviorRequestControlProperties properties =
         new PasswordUpdateBehaviorRequestControlProperties();
    properties.setIsSelfChange(true);
    properties.setAllowPreEncodedPassword(true);
    properties.setSkipPasswordValidation(true);
    properties.setIgnorePasswordHistory(true);
    properties.setIgnoreMinimumPasswordAge(true);
    properties.setPasswordStorageScheme("true");
    properties.setMustChangePassword(true);

    assertNotNull(properties.getIsSelfChange());
    assertEquals(properties.getIsSelfChange(), Boolean.TRUE);

    assertNotNull(properties.getAllowPreEncodedPassword());
    assertEquals(properties.getAllowPreEncodedPassword(), Boolean.TRUE);

    assertNotNull(properties.getSkipPasswordValidation());
    assertEquals(properties.getSkipPasswordValidation(), Boolean.TRUE);

    assertNotNull(properties.getIgnorePasswordHistory());
    assertEquals(properties.getIgnorePasswordHistory(), Boolean.TRUE);

    assertNotNull(properties.getIgnoreMinimumPasswordAge());
    assertEquals(properties.getIgnoreMinimumPasswordAge(), Boolean.TRUE);

    assertNotNull(properties.getPasswordStorageScheme());
    assertEquals(properties.getPasswordStorageScheme(), "true");

    assertNotNull(properties.getMustChangePassword());
    assertEquals(properties.getMustChangePassword(), Boolean.TRUE);

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the case in which all of the properties are set with
   * non-default values, and in which the Boolean values are all false.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllFalseProperties()
         throws Exception
  {
    final PasswordUpdateBehaviorRequestControlProperties properties =
         new PasswordUpdateBehaviorRequestControlProperties();
    properties.setIsSelfChange(false);
    properties.setAllowPreEncodedPassword(false);
    properties.setSkipPasswordValidation(false);
    properties.setIgnorePasswordHistory(false);
    properties.setIgnoreMinimumPasswordAge(false);
    properties.setPasswordStorageScheme("false");
    properties.setMustChangePassword(false);

    assertNotNull(properties.getIsSelfChange());
    assertEquals(properties.getIsSelfChange(), Boolean.FALSE);

    assertNotNull(properties.getAllowPreEncodedPassword());
    assertEquals(properties.getAllowPreEncodedPassword(), Boolean.FALSE);

    assertNotNull(properties.getSkipPasswordValidation());
    assertEquals(properties.getSkipPasswordValidation(), Boolean.FALSE);

    assertNotNull(properties.getIgnorePasswordHistory());
    assertEquals(properties.getIgnorePasswordHistory(), Boolean.FALSE);

    assertNotNull(properties.getIgnoreMinimumPasswordAge());
    assertEquals(properties.getIgnoreMinimumPasswordAge(), Boolean.FALSE);

    assertNotNull(properties.getPasswordStorageScheme());
    assertEquals(properties.getPasswordStorageScheme(), "false");

    assertNotNull(properties.getMustChangePassword());
    assertEquals(properties.getMustChangePassword(), Boolean.FALSE);

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the case in which only the isSelfChange property is
   * set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIsSelfChange()
         throws Exception
  {
    final PasswordUpdateBehaviorRequestControlProperties properties =
         new PasswordUpdateBehaviorRequestControlProperties();
    properties.setIsSelfChange(true);

    assertNotNull(properties.getIsSelfChange());
    assertEquals(properties.getIsSelfChange(), Boolean.TRUE);

    assertNull(properties.getAllowPreEncodedPassword());

    assertNull(properties.getSkipPasswordValidation());

    assertNull(properties.getIgnorePasswordHistory());

    assertNull(properties.getIgnoreMinimumPasswordAge());

    assertNull(properties.getPasswordStorageScheme());

    assertNull(properties.getMustChangePassword());

    assertNotNull(properties.toString());

    properties.setIsSelfChange(false);

    assertNotNull(properties.getIsSelfChange());
    assertEquals(properties.getIsSelfChange(), Boolean.FALSE);

    assertNull(properties.getAllowPreEncodedPassword());

    assertNull(properties.getSkipPasswordValidation());

    assertNull(properties.getIgnorePasswordHistory());

    assertNull(properties.getIgnoreMinimumPasswordAge());

    assertNull(properties.getPasswordStorageScheme());

    assertNull(properties.getMustChangePassword());

    assertNotNull(properties.toString());

    properties.setIsSelfChange(null);

    assertNull(properties.getIsSelfChange());

    assertNull(properties.getAllowPreEncodedPassword());

    assertNull(properties.getSkipPasswordValidation());

    assertNull(properties.getIgnorePasswordHistory());

    assertNull(properties.getIgnoreMinimumPasswordAge());

    assertNull(properties.getPasswordStorageScheme());

    assertNull(properties.getMustChangePassword());

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the case in which only the allowPreEncodedPassword
   * property is set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllowPreEncodedPassword()
         throws Exception
  {
    final PasswordUpdateBehaviorRequestControlProperties properties =
         new PasswordUpdateBehaviorRequestControlProperties();
    properties.setAllowPreEncodedPassword(true);

    assertNull(properties.getIsSelfChange());

    assertNotNull(properties.getAllowPreEncodedPassword());
    assertEquals(properties.getAllowPreEncodedPassword(), Boolean.TRUE);

    assertNull(properties.getSkipPasswordValidation());

    assertNull(properties.getIgnorePasswordHistory());

    assertNull(properties.getIgnoreMinimumPasswordAge());

    assertNull(properties.getPasswordStorageScheme());

    assertNull(properties.getMustChangePassword());

    assertNotNull(properties.toString());

    properties.setAllowPreEncodedPassword(false);

    assertNull(properties.getIsSelfChange());

    assertNotNull(properties.getAllowPreEncodedPassword());
    assertEquals(properties.getAllowPreEncodedPassword(), Boolean.FALSE);

    assertNull(properties.getSkipPasswordValidation());

    assertNull(properties.getIgnorePasswordHistory());

    assertNull(properties.getIgnoreMinimumPasswordAge());

    assertNull(properties.getPasswordStorageScheme());

    assertNull(properties.getMustChangePassword());

    assertNotNull(properties.toString());

    properties.setAllowPreEncodedPassword(null);

    assertNull(properties.getIsSelfChange());

    assertNull(properties.getAllowPreEncodedPassword());

    assertNull(properties.getSkipPasswordValidation());

    assertNull(properties.getIgnorePasswordHistory());

    assertNull(properties.getIgnoreMinimumPasswordAge());

    assertNull(properties.getPasswordStorageScheme());

    assertNull(properties.getMustChangePassword());

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the case in which only the skipPasswordValidation
   * property is set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSkipPasswordValidation()
         throws Exception
  {
    final PasswordUpdateBehaviorRequestControlProperties properties =
         new PasswordUpdateBehaviorRequestControlProperties();
    properties.setSkipPasswordValidation(true);

    assertNull(properties.getIsSelfChange());

    assertNull(properties.getAllowPreEncodedPassword());

    assertNotNull(properties.getSkipPasswordValidation());
    assertEquals(properties.getSkipPasswordValidation(), Boolean.TRUE);

    assertNull(properties.getIgnorePasswordHistory());

    assertNull(properties.getIgnoreMinimumPasswordAge());

    assertNull(properties.getPasswordStorageScheme());

    assertNull(properties.getMustChangePassword());

    assertNotNull(properties.toString());

    properties.setSkipPasswordValidation(false);

    assertNull(properties.getIsSelfChange());

    assertNull(properties.getAllowPreEncodedPassword());

    assertNotNull(properties.getSkipPasswordValidation());
    assertEquals(properties.getSkipPasswordValidation(), Boolean.FALSE);

    assertNull(properties.getIgnorePasswordHistory());

    assertNull(properties.getIgnoreMinimumPasswordAge());

    assertNull(properties.getPasswordStorageScheme());

    assertNull(properties.getMustChangePassword());

    assertNotNull(properties.toString());

    properties.setSkipPasswordValidation(null);

    assertNull(properties.getIsSelfChange());

    assertNull(properties.getAllowPreEncodedPassword());

    assertNull(properties.getSkipPasswordValidation());

    assertNull(properties.getIgnorePasswordHistory());

    assertNull(properties.getIgnoreMinimumPasswordAge());

    assertNull(properties.getPasswordStorageScheme());

    assertNull(properties.getMustChangePassword());

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the case in which only the ignorePasswordHistory
   * property is set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIgnorePasswordHistory()
         throws Exception
  {
    final PasswordUpdateBehaviorRequestControlProperties properties =
         new PasswordUpdateBehaviorRequestControlProperties();
    properties.setIgnorePasswordHistory(true);

    assertNull(properties.getIsSelfChange());

    assertNull(properties.getAllowPreEncodedPassword());

    assertNull(properties.getSkipPasswordValidation());

    assertNotNull(properties.getIgnorePasswordHistory());
    assertEquals(properties.getIgnorePasswordHistory(), Boolean.TRUE);

    assertNull(properties.getIgnoreMinimumPasswordAge());

    assertNull(properties.getPasswordStorageScheme());

    assertNull(properties.getMustChangePassword());

    assertNotNull(properties.toString());

    properties.setIgnorePasswordHistory(false);

    assertNull(properties.getIsSelfChange());

    assertNull(properties.getAllowPreEncodedPassword());

    assertNull(properties.getSkipPasswordValidation());

    assertNotNull(properties.getIgnorePasswordHistory());
    assertEquals(properties.getIgnorePasswordHistory(), Boolean.FALSE);

    assertNull(properties.getIgnoreMinimumPasswordAge());

    assertNull(properties.getPasswordStorageScheme());

    assertNull(properties.getMustChangePassword());

    assertNotNull(properties.toString());

    properties.setIgnorePasswordHistory(null);

    assertNull(properties.getIsSelfChange());

    assertNull(properties.getAllowPreEncodedPassword());

    assertNull(properties.getSkipPasswordValidation());

    assertNull(properties.getIgnorePasswordHistory());

    assertNull(properties.getIgnoreMinimumPasswordAge());

    assertNull(properties.getPasswordStorageScheme());

    assertNull(properties.getMustChangePassword());

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the case in which only the ignoreMinimumPasswordAge
   * property is set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIgnoreMinimumPasswordAge()
         throws Exception
  {
    final PasswordUpdateBehaviorRequestControlProperties properties =
         new PasswordUpdateBehaviorRequestControlProperties();
    properties.setIgnoreMinimumPasswordAge(true);

    assertNull(properties.getIsSelfChange());

    assertNull(properties.getAllowPreEncodedPassword());

    assertNull(properties.getSkipPasswordValidation());

    assertNull(properties.getIgnorePasswordHistory());

    assertNotNull(properties.getIgnoreMinimumPasswordAge());
    assertEquals(properties.getIgnoreMinimumPasswordAge(), Boolean.TRUE);

    assertNull(properties.getPasswordStorageScheme());

    assertNull(properties.getMustChangePassword());

    assertNotNull(properties.toString());

    properties.setIgnoreMinimumPasswordAge(false);

    assertNull(properties.getIsSelfChange());

    assertNull(properties.getAllowPreEncodedPassword());

    assertNull(properties.getSkipPasswordValidation());

    assertNull(properties.getIgnorePasswordHistory());

    assertNotNull(properties.getIgnoreMinimumPasswordAge());
    assertEquals(properties.getIgnoreMinimumPasswordAge(), Boolean.FALSE);

    assertNull(properties.getPasswordStorageScheme());

    assertNull(properties.getMustChangePassword());

    assertNotNull(properties.toString());

    properties.setIgnoreMinimumPasswordAge(null);

    assertNull(properties.getIsSelfChange());

    assertNull(properties.getAllowPreEncodedPassword());

    assertNull(properties.getSkipPasswordValidation());

    assertNull(properties.getIgnorePasswordHistory());

    assertNull(properties.getIgnoreMinimumPasswordAge());

    assertNull(properties.getPasswordStorageScheme());

    assertNull(properties.getMustChangePassword());

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the case in which only the passwordStorageScheme
   * property is set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordStorageScheme()
         throws Exception
  {
    final PasswordUpdateBehaviorRequestControlProperties properties =
         new PasswordUpdateBehaviorRequestControlProperties();
    properties.setPasswordStorageScheme("PBKDF2");

    assertNull(properties.getIsSelfChange());

    assertNull(properties.getAllowPreEncodedPassword());

    assertNull(properties.getSkipPasswordValidation());

    assertNull(properties.getIgnorePasswordHistory());

    assertNull(properties.getIgnoreMinimumPasswordAge());

    assertNotNull(properties.getPasswordStorageScheme());
    assertEquals(properties.getPasswordStorageScheme(), "PBKDF2");

    assertNull(properties.getMustChangePassword());

    assertNotNull(properties.toString());

    properties.setPasswordStorageScheme("SSHA512");

    assertNull(properties.getIsSelfChange());

    assertNull(properties.getAllowPreEncodedPassword());

    assertNull(properties.getSkipPasswordValidation());

    assertNull(properties.getIgnorePasswordHistory());

    assertNull(properties.getIgnoreMinimumPasswordAge());

    assertNotNull(properties.getPasswordStorageScheme());
    assertEquals(properties.getPasswordStorageScheme(), "SSHA512");

    assertNull(properties.getMustChangePassword());

    assertNotNull(properties.toString());

    properties.setPasswordStorageScheme(null);

    assertNull(properties.getIsSelfChange());

    assertNull(properties.getAllowPreEncodedPassword());

    assertNull(properties.getSkipPasswordValidation());

    assertNull(properties.getIgnorePasswordHistory());

    assertNull(properties.getIgnoreMinimumPasswordAge());

    assertNull(properties.getPasswordStorageScheme());

    assertNull(properties.getMustChangePassword());

    assertNotNull(properties.toString());
  }



  /**
   * Tests the behavior for the case in which only the mustChangePassword
   * property is set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMustChangePassword()
         throws Exception
  {
    final PasswordUpdateBehaviorRequestControlProperties properties =
         new PasswordUpdateBehaviorRequestControlProperties();
    properties.setMustChangePassword(true);

    assertNull(properties.getIsSelfChange());

    assertNull(properties.getAllowPreEncodedPassword());

    assertNull(properties.getSkipPasswordValidation());

    assertNull(properties.getIgnorePasswordHistory());

    assertNull(properties.getIgnoreMinimumPasswordAge());

    assertNull(properties.getPasswordStorageScheme());

    assertNotNull(properties.getMustChangePassword());
    assertEquals(properties.getMustChangePassword(), Boolean.TRUE);

    assertNotNull(properties.toString());

    properties.setMustChangePassword(false);

    assertNull(properties.getIsSelfChange());

    assertNull(properties.getAllowPreEncodedPassword());

    assertNull(properties.getSkipPasswordValidation());

    assertNull(properties.getIgnorePasswordHistory());

    assertNull(properties.getIgnoreMinimumPasswordAge());

    assertNull(properties.getPasswordStorageScheme());

    assertNotNull(properties.getMustChangePassword());
    assertEquals(properties.getMustChangePassword(), Boolean.FALSE);

    assertNotNull(properties.toString());

    properties.setMustChangePassword(null);

    assertNull(properties.getIsSelfChange());

    assertNull(properties.getAllowPreEncodedPassword());

    assertNull(properties.getSkipPasswordValidation());

    assertNull(properties.getIgnorePasswordHistory());

    assertNull(properties.getIgnoreMinimumPasswordAge());

    assertNull(properties.getPasswordStorageScheme());

    assertNull(properties.getMustChangePassword());

    assertNotNull(properties.toString());
  }
}
