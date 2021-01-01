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
 * This class provides a set of test cases for the {@code JSONBoolean} class.
 */
public final class JSONBooleanTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the object representing a value of {@code true}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTrue()
         throws Exception
  {
    final JSONBoolean b = new JSONBoolean(true);

    assertTrue(b.booleanValue());

    assertEquals(b, JSONBoolean.TRUE);

    assertEquals(b.hashCode(), JSONBoolean.TRUE.hashCode());

    assertNotNull(b.toString());
    assertEquals(b.toString(), "true");

    assertNotNull(b.toSingleLineString());
    assertEquals(b.toSingleLineString(), "true");

    final StringBuilder toStringBuffer = new StringBuilder();
    b.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), "true");

    final StringBuilder toSingleLineStringBuffer = new StringBuilder();
    b.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(), "true");

    assertNotNull(b.toNormalizedString());
    assertEquals(b.toNormalizedString(), "true");

    final StringBuilder toNormalizedStringBuffer = new StringBuilder();
    b.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(), "true");

    assertNotNull(b.toNormalizedString(true, true, true));
    assertEquals(b.toNormalizedString(true, true, true), "true");

    assertNotNull(b.toNormalizedString(false, false, false));
    assertEquals(b.toNormalizedString(false, false, false), "true");

    toNormalizedStringBuffer.setLength(0);
    b.toNormalizedString(toNormalizedStringBuffer, true, true, true);
    assertEquals(toNormalizedStringBuffer.toString(), "true");

    toNormalizedStringBuffer.setLength(0);
    b.toNormalizedString(toNormalizedStringBuffer, false, false, false);
    assertEquals(toNormalizedStringBuffer.toString(), "true");

    final JSONBuffer jsonBuffer = new JSONBuffer();
    b.appendToJSONBuffer(jsonBuffer);
    assertEquals(jsonBuffer.toString(), "true");

    jsonBuffer.clear();
    b.appendToJSONBuffer("fieldName", jsonBuffer);
    assertEquals(jsonBuffer.toString(), "\"fieldName\":true");
  }



  /**
   * Provides test coverage for the object representing a value of
   * {@code false}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFalse()
         throws Exception
  {
    final JSONBoolean b = new JSONBoolean(false);

    assertFalse(b.booleanValue());

    assertEquals(b, JSONBoolean.FALSE);

    assertEquals(b.hashCode(), JSONBoolean.FALSE.hashCode());

    assertNotNull(b.toString());
    assertEquals(b.toString(), "false");

    assertNotNull(b.toSingleLineString());
    assertEquals(b.toSingleLineString(), "false");

    final StringBuilder toStringBuffer = new StringBuilder();
    b.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), "false");

    final StringBuilder toSingleLineStringBuffer = new StringBuilder();
    b.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(), "false");

    assertNotNull(b.toNormalizedString());
    assertEquals(b.toNormalizedString(), "false");

    final StringBuilder toNormalizedStringBuffer = new StringBuilder();
    b.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(), "false");

    assertNotNull(b.toNormalizedString(true, true, true));
    assertEquals(b.toNormalizedString(true, true, true), "false");

    assertNotNull(b.toNormalizedString(false, false, false));
    assertEquals(b.toNormalizedString(false, false, false), "false");

    toNormalizedStringBuffer.setLength(0);
    b.toNormalizedString(toNormalizedStringBuffer, true, true, true);
    assertEquals(toNormalizedStringBuffer.toString(), "false");

    toNormalizedStringBuffer.setLength(0);
    b.toNormalizedString(toNormalizedStringBuffer, false, false, false);
    assertEquals(toNormalizedStringBuffer.toString(), "false");

    final JSONBuffer jsonBuffer = new JSONBuffer();
    b.appendToJSONBuffer(jsonBuffer);
    assertEquals(jsonBuffer.toString(), "false");

    jsonBuffer.clear();
    b.appendToJSONBuffer("fieldName", jsonBuffer);
    assertEquals(jsonBuffer.toString(), "\"fieldName\":false");
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
    final JSONBoolean t = new JSONBoolean(true);
    assertTrue(t.equals(t));
    assertEquals(t.hashCode(), t.hashCode());

    final JSONBoolean f = new JSONBoolean(false);
    assertTrue(f.equals(f));
    assertEquals(f.hashCode(), f.hashCode());

    assertTrue(JSONBoolean.TRUE.equals(JSONBoolean.TRUE));
    assertEquals(JSONBoolean.TRUE.hashCode(), JSONBoolean.TRUE.hashCode());

    assertTrue(JSONBoolean.FALSE.equals(JSONBoolean.FALSE));
    assertEquals(JSONBoolean.FALSE.hashCode(), JSONBoolean.FALSE.hashCode());
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
    final JSONBoolean t1 = new JSONBoolean(true);
    final JSONBoolean t2 = new JSONBoolean(true);

    assertTrue(t1.equals(t2));
    assertTrue(t2.equals(t1));
    assertEquals(t1.hashCode(), t2.hashCode());

    assertTrue(t1.equals(JSONBoolean.TRUE));
    assertTrue(JSONBoolean.TRUE.equals(t1));
    assertEquals(t1.hashCode(), JSONBoolean.TRUE.hashCode());

    final JSONBoolean f1 = new JSONBoolean(false);
    final JSONBoolean f2 = new JSONBoolean(false);

    assertTrue(f1.equals(f2));
    assertTrue(f2.equals(f1));
    assertEquals(f1.hashCode(), f2.hashCode());

    assertTrue(f1.equals(JSONBoolean.FALSE));
    assertTrue(JSONBoolean.FALSE.equals(f1));
    assertEquals(f1.hashCode(), JSONBoolean.FALSE.hashCode());
  }



  /**
   * Tests the {@code equals} method for equality with a non-equivalent object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNotEquivalent()
         throws Exception
  {
    final JSONBoolean t = new JSONBoolean(true);
    final JSONBoolean f = new JSONBoolean(false);

    assertFalse(t.equals(f));
    assertFalse(f.equals(t));

    assertFalse(t.equals(JSONBoolean.FALSE));

    assertFalse(f.equals(JSONBoolean.TRUE));
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
    final JSONBoolean t1 = new JSONBoolean(true);

    assertFalse(t1.equals(null));

    final JSONBoolean t2 = null;
    assertFalse(t1.equals(t2));

    final String s = null;
    assertFalse(t1.equals(s));
  }



  /**
   * Tests the {@code equals} method for an object that isn't a
   * {@code JSONBoolean} object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsDifferentTypeOfObject()
         throws Exception
  {
    final JSONBoolean t = new JSONBoolean(true);
    final JSONBoolean f = new JSONBoolean(false);

    assertFalse(t.equals("foo"));

    assertFalse(t.equals("true"));

    assertFalse(f.equals("false"));

    assertFalse(t.equals(JSONNull.NULL));
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
    final JSONBoolean t1 = new JSONBoolean(true);
    final JSONBoolean t2 = new JSONBoolean(true);
    final JSONBoolean f1 = new JSONBoolean(false);
    final JSONBoolean f2 = new JSONBoolean(false);

    assertTrue(t1.equals(t1, true, true, true));
    assertTrue(t1.equals(t1, false, false, false));
    assertTrue(t1.equals(t2, true, true, true));
    assertTrue(t1.equals(t2, false, false, false));

    assertTrue(f1.equals(f1, true, true, true));
    assertTrue(f1.equals(f1, false, false, false));
    assertTrue(f1.equals(f2, true, true, true));
    assertTrue(f1.equals(f2, false, false, false));

    assertFalse(t1.equals(f1, true, true, true));
    assertFalse(t1.equals(f1, false, false, false));
    assertFalse(t1.equals(f2, true, true, true));
    assertFalse(t1.equals(f2, false, false, false));
  }
}
