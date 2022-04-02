/*
 * Copyright 2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022 Ping Identity Corporation
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
 * Copyright (C) 2022 Ping Identity Corporation
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
 * This class provides a set of test cases for the
 * {@code JSONFormattedControlDecodeBehavior} class.
 */
public final class JSONFormattedControlDecodeBehaviorTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests to ensure that the class provides the expected default values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaults()
         throws Exception
  {
    final JSONFormattedControlDecodeBehavior behavior =
         new JSONFormattedControlDecodeBehavior();

    assertTrue(behavior.throwOnUnparsableObject());

    assertTrue(behavior.throwOnInvalidCriticalControl());

    assertTrue(behavior.throwOnInvalidNonCriticalControl());

    assertFalse(behavior.strict());

    assertNotNull(behavior.toString());
  }



  /**
   * Test the methods for manipulating the {@code throwOnUnparsableObject}
   * variable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testThrowOnUnparsableObject()
         throws Exception
  {
    final JSONFormattedControlDecodeBehavior behavior =
         new JSONFormattedControlDecodeBehavior();

    assertTrue(behavior.throwOnUnparsableObject());
    assertTrue(behavior.throwOnInvalidCriticalControl());
    assertTrue(behavior.throwOnInvalidNonCriticalControl());
    assertFalse(behavior.strict());
    assertNotNull(behavior.toString());

    behavior.setThrowOnUnparsableObject(false);
    assertFalse(behavior.throwOnUnparsableObject());
    assertTrue(behavior.throwOnInvalidCriticalControl());
    assertTrue(behavior.throwOnInvalidNonCriticalControl());
    assertFalse(behavior.strict());
    assertNotNull(behavior.toString());

    behavior.setThrowOnUnparsableObject(true);
    assertTrue(behavior.throwOnUnparsableObject());
    assertTrue(behavior.throwOnInvalidCriticalControl());
    assertTrue(behavior.throwOnInvalidNonCriticalControl());
    assertFalse(behavior.strict());
    assertNotNull(behavior.toString());
  }



  /**
   * Test the methods for manipulating the {@code throwOnInvalidCriticalControl}
   * variable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testThrowOnInvalidCriticalControl()
         throws Exception
  {
    final JSONFormattedControlDecodeBehavior behavior =
         new JSONFormattedControlDecodeBehavior();

    assertTrue(behavior.throwOnUnparsableObject());
    assertTrue(behavior.throwOnInvalidCriticalControl());
    assertTrue(behavior.throwOnInvalidNonCriticalControl());
    assertFalse(behavior.strict());
    assertNotNull(behavior.toString());

    behavior.setThrowOnInvalidCriticalControl(false);
    assertTrue(behavior.throwOnUnparsableObject());
    assertFalse(behavior.throwOnInvalidCriticalControl());
    assertTrue(behavior.throwOnInvalidNonCriticalControl());
    assertFalse(behavior.strict());
    assertNotNull(behavior.toString());

    behavior.setThrowOnInvalidCriticalControl(true);
    assertTrue(behavior.throwOnUnparsableObject());
    assertTrue(behavior.throwOnInvalidCriticalControl());
    assertTrue(behavior.throwOnInvalidNonCriticalControl());
    assertFalse(behavior.strict());
    assertNotNull(behavior.toString());
  }



  /**
   * Test the methods for manipulating the
   * {@code throwOnInvalidNonCriticalControl}  variable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testThrowOnInvalidNonCriticalControl()
         throws Exception
  {
    final JSONFormattedControlDecodeBehavior behavior =
         new JSONFormattedControlDecodeBehavior();

    assertTrue(behavior.throwOnUnparsableObject());
    assertTrue(behavior.throwOnInvalidCriticalControl());
    assertTrue(behavior.throwOnInvalidNonCriticalControl());
    assertFalse(behavior.strict());
    assertNotNull(behavior.toString());

    behavior.setThrowOnInvalidNonCriticalControl(false);
    assertTrue(behavior.throwOnUnparsableObject());
    assertTrue(behavior.throwOnInvalidCriticalControl());
    assertFalse(behavior.throwOnInvalidNonCriticalControl());
    assertFalse(behavior.strict());
    assertNotNull(behavior.toString());

    behavior.setThrowOnInvalidNonCriticalControl(true);
    assertTrue(behavior.throwOnUnparsableObject());
    assertTrue(behavior.throwOnInvalidCriticalControl());
    assertTrue(behavior.throwOnInvalidNonCriticalControl());
    assertFalse(behavior.strict());
    assertNotNull(behavior.toString());
  }



  /**
   * Test the methods for manipulating the {@code strict}  variable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStrict()
         throws Exception
  {
    final JSONFormattedControlDecodeBehavior behavior =
         new JSONFormattedControlDecodeBehavior();

    assertTrue(behavior.throwOnUnparsableObject());
    assertTrue(behavior.throwOnInvalidCriticalControl());
    assertTrue(behavior.throwOnInvalidNonCriticalControl());
    assertFalse(behavior.strict());
    assertNotNull(behavior.toString());

    behavior.setStrict(true);
    assertTrue(behavior.throwOnUnparsableObject());
    assertTrue(behavior.throwOnInvalidCriticalControl());
    assertTrue(behavior.throwOnInvalidNonCriticalControl());
    assertTrue(behavior.strict());
    assertNotNull(behavior.toString());

    behavior.setStrict(false);
    assertTrue(behavior.throwOnUnparsableObject());
    assertTrue(behavior.throwOnInvalidCriticalControl());
    assertTrue(behavior.throwOnInvalidNonCriticalControl());
    assertFalse(behavior.strict());
    assertNotNull(behavior.toString());
  }
}
