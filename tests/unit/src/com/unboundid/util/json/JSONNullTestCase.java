/*
 * Copyright 2015-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2017 UnboundID Corp.
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
}
