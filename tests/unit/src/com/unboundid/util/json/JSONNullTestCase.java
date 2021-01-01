/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
package com.unboundid.util.json;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code JSONNull} class.
 */
public final class JSONNullTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the null object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNull()
         throws Exception
  {
    final JSONNull n = new JSONNull();

    assertEquals(n, JSONNull.NULL);

    assertEquals(n.hashCode(), JSONNull.NULL.hashCode());

    assertNotNull(n.toString());
    assertEquals(n.toString(), "null");

    assertNotNull(n.toSingleLineString());
    assertEquals(n.toSingleLineString(), "null");

    final StringBuilder toStringBuffer = new StringBuilder();
    n.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), "null");

    final StringBuilder toSingleLineStringBuffer = new StringBuilder();
    n.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(), "null");

    assertNotNull(n.toNormalizedString());
    assertEquals(n.toNormalizedString(), "null");

    final StringBuilder toNormalizedStringBuffer = new StringBuilder();
    n.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(), "null");

    assertNotNull(n.toNormalizedString(true, true, true));
    assertEquals(n.toNormalizedString(true, true, true), "null");

    assertNotNull(n.toNormalizedString(false, false, false));
    assertEquals(n.toNormalizedString(false, false, false), "null");

    toNormalizedStringBuffer.setLength(0);
    n.toNormalizedString(toNormalizedStringBuffer, true, true, true);
    assertEquals(toNormalizedStringBuffer.toString(), "null");

    toNormalizedStringBuffer.setLength(0);
    n.toNormalizedString(toNormalizedStringBuffer, false, false, false);
    assertEquals(toNormalizedStringBuffer.toString(), "null");

    final JSONBuffer jsonBuffer = new JSONBuffer();
    n.appendToJSONBuffer(jsonBuffer);
    assertEquals(jsonBuffer.toString(), "null");

    jsonBuffer.clear();
    n.appendToJSONBuffer("fieldName", jsonBuffer);
    assertEquals(jsonBuffer.toString(), "\"fieldName\":null");
  }



  /**
   * Tests the {@code equals} method for equality with the same object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIdentity()
         throws Exception
  {
    final JSONNull n = new JSONNull();

    assertTrue(n.equals(n));
    assertEquals(n.hashCode(), n.hashCode());

    assertTrue(JSONNull.NULL.equals(JSONNull.NULL));
    assertEquals(JSONNull.NULL.hashCode(), JSONNull.NULL.hashCode());
  }



  /**
   * Tests the {@code equals} method for equality with an equivalent object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsEquivalent()
         throws Exception
  {
    final JSONNull n1 = new JSONNull();
    final JSONNull n2 = new JSONNull();

    assertTrue(n1.equals(n2));
    assertTrue(n2.equals(n1));
    assertEquals(n1.hashCode(), n2.hashCode());

    assertTrue(n1.equals(JSONNull.NULL));
    assertTrue(JSONNull.NULL.equals(n1));
    assertEquals(n1.hashCode(), JSONNull.NULL.hashCode());
  }



  /**
   * Tests the {@code equals} method for equality with a {@code null} object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNull()
         throws Exception
  {
    final JSONNull n1 = new JSONNull();

    assertFalse(n1.equals(null));

    final JSONNull n2 = null;
    assertFalse(n1.equals(n2));

    final String s = null;
    assertFalse(n1.equals(s));
  }



  /**
   * Tests the {@code equals} method for an object that isn't a {@code JSONNull}
   * object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsDifferentTypeOfObject()
         throws Exception
  {
    final JSONNull n = new JSONNull();

    assertFalse(n.equals("foo"));

    assertFalse(n.equals("null"));

    assertFalse(n.equals(JSONBoolean.TRUE));
  }



  /**
   * Tests the {@code equals} method that takes an extended set of arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsExtended()
         throws Exception
  {
    final JSONNull n1 = new JSONNull();
    final JSONNull n2 = new JSONNull();

    assertTrue(n1.equals(n1, true, true, true));
    assertTrue(n1.equals(n1, false, false, false));
    assertTrue(n1.equals(n2, true, true, true));
    assertTrue(n1.equals(n2, false, false, false));
  }
}
