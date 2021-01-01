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
 * This class provides a set of test cases for the {@code JSONField} class.
 */
public final class JSONFieldTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a field with a {@code JSONNull} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullField()
         throws Exception
  {
    final JSONField n1 = new JSONField("nullField", JSONNull.NULL);

    assertNotNull(n1.getName());
    assertEquals(n1.getName(), "nullField");

    assertNotNull(n1.getValue());
    assertTrue(n1.getValue() instanceof JSONNull);
    assertEquals(n1.getValue(), JSONNull.NULL);

    final JSONField n2 = new JSONField("nullField", new JSONNull());

    assertNotNull(n2.getName());
    assertEquals(n2.getName(), "nullField");

    assertNotNull(n2.getValue());
    assertTrue(n2.getValue() instanceof JSONNull);
    assertEquals(n2.getValue(), JSONNull.NULL);

    assertTrue(n1.equals(n2));
    assertTrue(n2.equals(n1));
    assertEquals(n1.hashCode(), n2.hashCode());

    assertNotNull(n1.toString());
    assertEquals(n1.toString(), "\"nullField\":null");

    assertFalse(n1.equals(new JSONField("NullField", JSONNull.NULL)));
  }



  /**
   * Tests the behavior for a field with a {@code JSONBoolean} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBooleanField()
         throws Exception
  {
    final JSONField t1 = new JSONField("trueField", true);

    assertNotNull(t1.getName());
    assertEquals(t1.getName(), "trueField");

    assertNotNull(t1.getValue());
    assertTrue(t1.getValue() instanceof JSONBoolean);
    assertEquals(t1.getValue(), JSONBoolean.TRUE);


    final JSONField t2 = new JSONField("trueField", new JSONBoolean(true));

    assertNotNull(t2.getName());
    assertEquals(t2.getName(), "trueField");

    assertNotNull(t2.getValue());
    assertTrue(t2.getValue() instanceof JSONBoolean);
    assertEquals(t2.getValue(), JSONBoolean.TRUE);

    assertTrue(t1.equals(t2));
    assertTrue(t2.equals(t1));
    assertEquals(t1.hashCode(), t2.hashCode());


    final JSONField f1 = new JSONField("falseField", false);

    assertNotNull(f1.getName());
    assertEquals(f1.getName(), "falseField");

    assertNotNull(f1.getValue());
    assertTrue(f1.getValue() instanceof JSONBoolean);
    assertEquals(f1.getValue(), JSONBoolean.FALSE);


    final JSONField f2 = new JSONField("falseField", new JSONBoolean(false));

    assertNotNull(f2.getName());
    assertEquals(f2.getName(), "falseField");

    assertNotNull(f2.getValue());
    assertTrue(f2.getValue() instanceof JSONBoolean);
    assertEquals(f2.getValue(), JSONBoolean.FALSE);

    assertTrue(f1.equals(f2));
    assertTrue(f2.equals(f1));
    assertEquals(f1.hashCode(), f2.hashCode());

    assertFalse(t1.equals(f1));
    assertFalse(f1.equals(t1));


    assertEquals(t1.toString(), "\"trueField\":true");
    assertEquals(t2.toString(), "\"trueField\":true");
    assertEquals(f1.toString(), "\"falseField\":false");
    assertEquals(f2.toString(), "\"falseField\":false");

    assertFalse(t1.equals(new JSONField("TrueField", true)));
    assertFalse(f1.equals(new JSONField("FalseField", false)));
  }



  /**
   * Tests the behavior for a field with a {@code JSONString} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringField()
         throws Exception
  {
    final JSONField s1 = new JSONField("stringField", "foo");

    assertNotNull(s1.getName());
    assertEquals(s1.getName(), "stringField");

    assertNotNull(s1.getValue());
    assertTrue(s1.getValue() instanceof JSONString);
    assertEquals(s1.getValue(), new JSONString("foo"));


    final JSONField s2 = new JSONField("stringField", new JSONString("foo"));

    assertNotNull(s2.getName());
    assertEquals(s2.getName(), "stringField");

    assertNotNull(s2.getValue());
    assertTrue(s2.getValue() instanceof JSONString);
    assertEquals(s2.getValue(), new JSONString("foo"));

    assertTrue(s1.equals(s2));
    assertTrue(s2.equals(s1));
    assertEquals(s1.hashCode(), s2.hashCode());


    final JSONField s3 = new JSONField("stringField", "Foo");

    assertNotNull(s3.getName());
    assertEquals(s3.getName(), "stringField");

    assertNotNull(s3.getValue());
    assertTrue(s3.getValue() instanceof JSONString);
    assertEquals(s3.getValue(), new JSONString("Foo"));

    assertFalse(s1.equals(s3));
    assertFalse(s3.equals(s1));


    final JSONField s4 = new JSONField("stringField", "bar");

    assertNotNull(s4.getName());
    assertEquals(s4.getName(), "stringField");

    assertNotNull(s4.getValue());
    assertTrue(s4.getValue() instanceof JSONString);
    assertEquals(s4.getValue(), new JSONString("bar"));

    assertFalse(s1.equals(s4));
    assertFalse(s4.equals(s1));
    assertFalse(s2.equals(s4));
    assertFalse(s4.equals(s2));


    final JSONField s5 = new JSONField("StringField", "foo");

    assertNotNull(s5.getName());
    assertEquals(s5.getName(), "StringField");

    assertNotNull(s5.getValue());
    assertTrue(s5.getValue() instanceof JSONString);
    assertEquals(s5.getValue(), new JSONString("foo"));

    assertFalse(s1.equals(s5));
    assertFalse(s5.equals(s1));

    assertEquals(s1.toString(), "\"stringField\":\"foo\"");
    assertEquals(s2.toString(), "\"stringField\":\"foo\"");
    assertEquals(s3.toString(), "\"stringField\":\"Foo\"");
    assertEquals(s4.toString(), "\"stringField\":\"bar\"");
    assertEquals(s5.toString(), "\"StringField\":\"foo\"");
  }



  /**
   * Tests the behavior for a field with a {@code JSONNumber} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNumberField()
         throws Exception
  {
    final JSONField n1 = new JSONField("numberField", 1234);

    assertNotNull(n1.getName());
    assertEquals(n1.getName(), "numberField");

    assertNotNull(n1.getValue());
    assertTrue(n1.getValue() instanceof JSONNumber);
    assertEquals(n1.getValue(), new JSONNumber("1234"));


    final JSONField n2 = new JSONField("numberField", 1234.0);

    assertNotNull(n2.getName());
    assertEquals(n2.getName(), "numberField");

    assertNotNull(n2.getValue());
    assertTrue(n2.getValue() instanceof JSONNumber);
    assertEquals(n2.getValue(), new JSONNumber("1234"));

    assertTrue(n1.equals(n2));
    assertTrue(n2.equals(n1));
    assertEquals(n1.hashCode(), n2.hashCode());


    final JSONField n3 = new JSONField("numberField", 1234.5);

    assertNotNull(n3.getName());
    assertEquals(n3.getName(), "numberField");

    assertNotNull(n3.getValue());
    assertTrue(n3.getValue() instanceof JSONNumber);
    assertEquals(n3.getValue(), new JSONNumber("1234.5"));

    assertFalse(n1.equals(n3));
    assertFalse(n3.equals(n1));


    assertEquals(n1.toString(), "\"numberField\":1234");
    assertEquals(n2.toString(), "\"numberField\":1234.0");
    assertEquals(n3.toString(), "\"numberField\":1234.5");
  }



  /**
   * Provides test coverage for the {@code equals} method for non-equal fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEquals()
         throws Exception
  {
    final JSONField nullField = new JSONField("nullField", JSONNull.NULL);
    final JSONField trueField = new JSONField("trueField", JSONBoolean.TRUE);
    final JSONField falseField = new JSONField("falseField", JSONBoolean.FALSE);
    final JSONField stringField = new JSONField("stringField", "foo");
    final JSONField numberField = new JSONField("numberField", 1234);
    final JSONField arrayField = new JSONField("arrayField",
         new JSONArray(JSONBoolean.TRUE, JSONBoolean.FALSE));
    final JSONField objectField = new JSONField("objectField",
         new JSONObject(nullField, trueField, falseField, stringField,
              numberField, arrayField));

    assertFalse(nullField.equals(null));
    assertFalse(trueField.equals(null));
    assertFalse(falseField.equals(null));
    assertFalse(stringField.equals(null));
    assertFalse(numberField.equals(null));
    assertFalse(arrayField.equals(null));
    assertFalse(objectField.equals(null));

    assertTrue(nullField.equals(nullField));
    assertTrue(trueField.equals(trueField));
    assertTrue(falseField.equals(falseField));
    assertTrue(stringField.equals(stringField));
    assertTrue(numberField.equals(numberField));
    assertTrue(arrayField.equals(arrayField));
    assertTrue(objectField.equals(objectField));

    assertFalse(nullField.equals("foo"));
    assertFalse(trueField.equals("foo"));
    assertFalse(falseField.equals("foo"));
    assertFalse(stringField.equals("foo"));
    assertFalse(numberField.equals("foo"));
    assertFalse(arrayField.equals("foo"));
    assertFalse(objectField.equals("foo"));

    assertFalse(nullField.equals(trueField));
    assertFalse(trueField.equals(falseField));
    assertFalse(falseField.equals(stringField));
    assertFalse(stringField.equals(numberField));
    assertFalse(numberField.equals(arrayField));
    assertFalse(arrayField.equals(objectField));
    assertFalse(objectField.equals(nullField));
  }
}
