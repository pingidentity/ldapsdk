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
package com.unboundid.ldap.sdk.persist;



import java.lang.reflect.Method;
import java.util.LinkedList;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides test coverage for the {@code SetterInfo} class.
 */
public class SetterInfoTestCase
      extends LDAPSDKTestCase
{
  /**
   * Provides a set of test cases for a method with the getter annotation with
   * default values for most fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaults()
         throws Exception
  {
    TestAnnotationsObject o = new TestAnnotationsObject();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("setTestMethodDefaults", String.class);
    assertNotNull(m);

    SetterInfo i = new SetterInfo(m, c);

    assertNotNull(i.getMethod());
    assertEquals(i.getMethod(), m);

    assertNotNull(i.getContainingClass());
    assertEquals(i.getContainingClass(), c);

    assertTrue(i.failOnInvalidValue());

    assertTrue(i.failOnTooManyValues());

    assertNotNull(i.getEncoder());

    assertNotNull(i.getAttributeName());
    assertEquals(i.getAttributeName(), "testMethodDefaults");

    assertFalse(i.supportsMultipleValues());


    // Test the invokeSetter method with an entry containing a valid value for
    // the associated attribute.
    Entry e = new Entry(
         "dn: foo=a,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testAnnotationsStructural",
         "objectClass: testAnnotationsAuxiliary",
         "foo: a",
         "testDefaults: b",
         "testMethodDefaults: abc");

    assertNull(o.getTestMethodDefaults());
    LinkedList<String> failureReasons = new LinkedList<String>();
    assertTrue(i.invokeSetter(o, e, failureReasons),
         concatenateStrings(failureReasons));
    assertNotNull(o.getTestMethodDefaults());
    assertEquals(o.getTestMethodDefaults(), "abc");


    // Tests the invokeSetter method with an entry that does not contain the
    // associated attribute.
    e = new Entry(
         "dn: foo=a,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testAnnotationsStructural",
         "objectClass: testAnnotationsAuxiliary",
         "foo: a",
         "testDefaults: b");

    assertTrue(i.invokeSetter(o, e, failureReasons),
         concatenateStrings(failureReasons));
    assertNull(o.getTestMethodDefaults());
  }



  /**
   * Provides a set of test cases for a method with the getter annotation with
   * non-default values for most fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonDefaults()
         throws Exception
  {
    TestAnnotationsObject o = new TestAnnotationsObject();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("setTestMethodNonDefaults", String.class);
    assertNotNull(m);

    SetterInfo i = new SetterInfo(m, c);

    assertNotNull(i.getMethod());
    assertEquals(i.getMethod(), m);

    assertNotNull(i.getContainingClass());
    assertEquals(i.getContainingClass(), c);

    assertFalse(i.failOnInvalidValue());

    assertFalse(i.failOnTooManyValues());

    assertNotNull(i.getEncoder());

    assertNotNull(i.getAttributeName());
    assertEquals(i.getAttributeName(), "x");

    assertFalse(i.supportsMultipleValues());


    // Test the invokeSetter method with an entry containing a valid value for
    // the associated attribute.
    Entry e = new Entry(
         "dn: foo=a,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testAnnotationsStructural",
         "objectClass: testAnnotationsAuxiliary",
         "foo: a",
         "testDefaults: b",
         "x: abc");

    assertNull(o.getTestMethodNonDefaults());
    LinkedList<String> failureReasons = new LinkedList<String>();
    assertTrue(i.invokeSetter(o, e, failureReasons),
         concatenateStrings(failureReasons));
    assertNotNull(o.getTestMethodNonDefaults());
    assertEquals(o.getTestMethodNonDefaults(), "abc");


    // Tests the invokeSetter method with an entry that does not contain the
    // associated attribute.
    e = new Entry(
         "dn: foo=a,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testAnnotationsStructural",
         "objectClass: testAnnotationsAuxiliary",
         "foo: a",
         "testDefaults: b");

    assertTrue(i.invokeSetter(o, e, failureReasons),
         concatenateStrings(failureReasons));
    assertNull(o.getTestMethodNonDefaults());
  }



  /**
   * Tests the behavior of the {@code SetterInfo} class when provided with a
   * method that does not contain the {@code LDAPSetter} annotation in a
   * class that has the {@code LDAPObject} annotation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testMethodNotAnnotated()
         throws Exception
  {
    TestAnnotationsObject o = new TestAnnotationsObject();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("setTestDefaults", String.class);
    assertNotNull(m);

    new SetterInfo(m, c);
  }



  /**
   * Tests the behavior of the {@code SetterInfo} class when provided with a
   * class that does not contain the {@code LDAPObject} annotation with a method
   * that has the {@code LDAPSetter} annotation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testClassNotAnnotated()
         throws Exception
  {
    TestClassNotAnnotated o = new TestClassNotAnnotated();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("setTestMethodField", String.class);
    assertNotNull(m);

    new SetterInfo(m, c);
  }



  /**
   * Tests the behavior of the {@code SetterInfo} class when provided with a
   * method that has an invalid encoder class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testInvalidEncoder()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("setInvalidEncoder", String.class);
    assertNotNull(m);

    new SetterInfo(m, c);
  }



  /**
   * Tests the behavior of the {@code SetterInfo} class when provided with a
   * method that does not take any arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testMethodWithoutArguments()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("setNoArguments");
    assertNotNull(m);

    new SetterInfo(m, c);
  }



  /**
   * Tests the behavior of the {@code SetterInfo} class when provided with a
   * method that takes multiple arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testMethodWithMultipleArguments()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("setMultipleArguments", String.class,
         String.class);
    assertNotNull(m);

    new SetterInfo(m, c);
  }



  /**
   * Tests the behavior of the {@code SetterInfo} class when provided with a
   * method that takes an unsupported argument type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testMethodWithUnsupportedArgument()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("setUnsupportedArgument", Object.class);
    assertNotNull(m);

    new SetterInfo(m, c);
  }



  /**
   * Tests the behavior of the {@code SetterInfo} class with a method that has
   * an inferred attribute name but the method name does not start with "set".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testSetterWithInvalidInferredAttribute()
         throws Exception
  {
    TestSetterInvalidInferredAttribute o =
         new TestSetterInvalidInferredAttribute();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("assignX", String.class);
    assertNotNull(m);

    new SetterInfo(m, c);
  }



  /**
   * Tests the behavior of the {@code invokeSetter} method with an attribute
   * that contains multiple values when that is not allowed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvokeSetterTooManyValuesNotAllowed()
         throws Exception
  {
    TestAnnotationsObject o = new TestAnnotationsObject();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("setTestMethodDefaults", String.class);
    assertNotNull(m);

    SetterInfo i = new SetterInfo(m, c);

    // Test the invokeSetter method with an entry containing a valid value for
    // the associated attribute.
    Entry e = new Entry(
         "dn: foo=a,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testAnnotationsStructural",
         "objectClass: testAnnotationsAuxiliary",
         "foo: a",
         "testDefaults: b",
         "testMethodDefaults: a",
         "testMethodDefaults: b");

    assertNull(o.getTestMethodDefaults());
    LinkedList<String> failureReasons = new LinkedList<String>();
    assertFalse(i.invokeSetter(o, e, failureReasons));
    assertFalse(failureReasons.isEmpty());
  }



  /**
   * Tests the behavior of the {@code invokeSetter} method with an attribute
   * that contains multiple values when all but the first will be ignored.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvokeSetterTooManyValuesIgnored()
         throws Exception
  {
    TestAnnotationsObject o = new TestAnnotationsObject();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("setTestMethodNonDefaults", String.class);
    assertNotNull(m);

    SetterInfo i = new SetterInfo(m, c);

    // Test the invokeSetter method with an entry containing a valid value for
    // the associated attribute.
    Entry e = new Entry(
         "dn: foo=a,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testAnnotationsStructural",
         "objectClass: testAnnotationsAuxiliary",
         "foo: a",
         "testDefaults: b",
         "x: a",
         "x: b");

    assertNull(o.getTestMethodNonDefaults());
    LinkedList<String> failureReasons = new LinkedList<String>();
    assertTrue(i.invokeSetter(o, e, failureReasons),
         concatenateStrings(failureReasons));
    assertNotNull(o.getTestMethodNonDefaults());
    assertEquals(o.getTestMethodNonDefaults(), "a");
  }



  /**
   * Tests the behavior of the {@code invokeSetter} method with an attribute
   * that contains multiple values when the associated argument type also takes
   * multiple values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvokeSetterTakesMultipleValues()
         throws Exception
  {
    TestAnnotationsObject o = new TestAnnotationsObject();

    Class<?> c = o.getClass();

    final String[] values = { "a", "b", "c" };

    Method m = c.getDeclaredMethod("setTestMethodMultiValued",
         values.getClass());
    assertNotNull(m);

    SetterInfo i = new SetterInfo(m, c);

    assertFalse(i.failOnTooManyValues());
    assertTrue(i.supportsMultipleValues());

    // Test the invokeSetter method with an entry containing a valid value for
    // the associated attribute.
    Entry e = new Entry(
         "dn: foo=a,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testAnnotationsStructural",
         "objectClass: testAnnotationsAuxiliary",
         "foo: a",
         "testDefaults: b",
         "testMethodMultiValued: a",
         "testMethodMultiValued: b",
         "testMethodMultiValued: c");

    assertNull(o.getTestMethodMultiValued());
    LinkedList<String> failureReasons = new LinkedList<String>();
    assertTrue(i.invokeSetter(o, e, failureReasons),
         concatenateStrings(failureReasons));
    assertNotNull(o.getTestMethodMultiValued());
    assertEquals(o.getTestMethodMultiValued().length, 3);
    assertEquals(o.getTestMethodMultiValued()[0], "a");
    assertEquals(o.getTestMethodMultiValued()[1], "b");
    assertEquals(o.getTestMethodMultiValued()[2], "c");

    // Test the invokeSetter method with an entry not containing the associated
    // attribute.
    e = new Entry(
         "dn: foo=a,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testAnnotationsStructural",
         "objectClass: testAnnotationsAuxiliary",
         "foo: a",
         "testDefaults: b");

    assertTrue(i.invokeSetter(o, e, failureReasons),
         concatenateStrings(failureReasons));
    assertNull(o.getTestMethodMultiValued());
  }



  /**
   * Tests the behavior of the {@code invokeSetter} method with a setter method
   * that throws a runtime exception.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvokeSetterThrowsRuntimeException()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("setThrowsRuntimeException", String.class);
    assertNotNull(m);

    SetterInfo i = new SetterInfo(m, c);

    Entry e = new Entry(
         "dn: foo=a,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testAnnotationsStructural",
         "objectClass: testAnnotationsAuxiliary",
         "foo: a",
         "testDefaults: b",
         "throwsRuntimeException: x");

    LinkedList<String> failureReasons = new LinkedList<String>();
    assertFalse(i.invokeSetter(o, e, failureReasons));
    assertFalse(failureReasons.isEmpty());
  }



  /**
   * Tests the behavior of the {@code invokeSetter} method with a setter method
   * that throws an LDAP persist exception.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvokeSetterThrowsPersistException()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("setThrowsPersistException", String.class);
    assertNotNull(m);

    SetterInfo i = new SetterInfo(m, c);

    Entry e = new Entry(
         "dn: foo=a,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testAnnotationsStructural",
         "objectClass: testAnnotationsAuxiliary",
         "foo: a",
         "testDefaults: b",
         "throwsPersistException: x");

    LinkedList<String> failureReasons = new LinkedList<String>();
    assertFalse(i.invokeSetter(o, e, failureReasons));
    assertFalse(failureReasons.isEmpty());
  }
}
