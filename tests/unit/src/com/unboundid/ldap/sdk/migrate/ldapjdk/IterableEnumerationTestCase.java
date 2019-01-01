/*
 * Copyright 2009-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2019 Ping Identity Corporation
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
