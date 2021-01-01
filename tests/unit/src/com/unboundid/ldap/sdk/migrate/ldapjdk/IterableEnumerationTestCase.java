/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import java.util.Arrays;
import java.util.NoSuchElementException;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code IterableEnumeration}
 * class.
 */
public class IterableEnumerationTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the {@code IterableEnumeration} class.
   */
  @Test()
  public void testIterableEnumeration()
  {
    IterableEnumeration<String> e =
         new IterableEnumeration<String>(Arrays.asList("foo", "bar"));

    assertTrue(e.hasMoreElements());
    assertEquals(e.nextElement(), "foo");

    assertTrue(e.hasMoreElements());
    assertEquals(e.nextElement(), "bar");

    assertFalse(e.hasMoreElements());
    try
    {
      e.nextElement();
      fail("Expected an exception when calling nextElement at the end of the " +
           "enumeration");
    }
    catch (NoSuchElementException nsee)
    {
      // This was expected.
    }
  }
}
