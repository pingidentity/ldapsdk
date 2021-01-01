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

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the {@code GetterInfo} class.
 */
public class GetterInfoTestCase
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

    Method m = c.getDeclaredMethod("getTestMethodDefaults");
    assertNotNull(m);

    GetterInfo i = new GetterInfo(m, c);

    assertNotNull(i.getMethod());
    assertEquals(i.getMethod(), m);

    assertNotNull(i.getContainingClass());
    assertEquals(i.getContainingClass(), c);

    assertTrue(i.includeInAdd());

    assertTrue(i.includeInModify());

    assertFalse(i.includeInRDN());

    assertEquals(i.getFilterUsage(), FilterUsage.CONDITIONALLY_ALLOWED);

    assertNotNull(i.getEncoder());

    assertNotNull(i.getAttributeName());
    assertEquals(i.getAttributeName(), "testMethodDefaults");

    assertNotNull(i.getObjectClasses());
    assertEquals(i.getObjectClasses().length, 1);
    assertEquals(i.getObjectClasses()[0], "testAnnotationsStructural");

    assertNotNull(i.constructAttributeType());


    // Test the encode method when the getter returns null.
    assertNull(o.getTestMethodDefaults());
    assertNull(i.encode(o));


    // Tests the encode method when the getter returns a non-null value.
    o.setTestMethodDefaults("a");
    assertEquals(o.getTestMethodDefaults(), "a");

    Attribute a = i.encode(o);
    assertNotNull(a);
    assertEquals(a.getName(), "testMethodDefaults");
    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("a"));
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

    Method m = c.getDeclaredMethod("getTestMethodNonDefaults");
    assertNotNull(m);

    GetterInfo i = new GetterInfo(m, c);

    assertNotNull(i.getMethod());
    assertEquals(i.getMethod(), m);

    assertNotNull(i.getContainingClass());
    assertEquals(i.getContainingClass(), c);

    assertFalse(i.includeInAdd());

    assertFalse(i.includeInModify());

    assertFalse(i.includeInRDN());

    assertEquals(i.getFilterUsage(), FilterUsage.ALWAYS_ALLOWED);

    assertNotNull(i.getEncoder());

    assertNotNull(i.getAttributeName());
    assertEquals(i.getAttributeName(), "x");

    assertNotNull(i.getObjectClasses());
    assertEquals(i.getObjectClasses().length, 1);
    assertEquals(i.getObjectClasses()[0], "testAnnotationsAuxiliary");

    assertNotNull(i.constructAttributeType());


    // Test the encode method when the getter returns null.
    assertNull(o.getTestMethodNonDefaults());
    assertNull(i.encode(o));


    // Tests the encode method when the getter returns a non-null value.
    o.setTestMethodNonDefaults("a");
    assertEquals(o.getTestMethodNonDefaults(), "a");

    Attribute a = i.encode(o);
    assertNotNull(a);
    assertEquals(a.getName(), "x");
    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("a"));
  }



  /**
   * Provides a set of test cases for a method with the getter annotation with
   * default values for most fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjectWithoutAuxiliaryClasses()
         throws Exception
  {
    TestNullable o = new TestNullable();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("getBooleanMF");
    assertNotNull(m);

    GetterInfo i = new GetterInfo(m, c);

    assertNotNull(i.getMethod());
    assertEquals(i.getMethod(), m);

    assertNotNull(i.getContainingClass());
    assertEquals(i.getContainingClass(), c);

    assertTrue(i.includeInAdd());

    assertTrue(i.includeInModify());

    assertFalse(i.includeInRDN());

    assertEquals(i.getFilterUsage(), FilterUsage.CONDITIONALLY_ALLOWED);

    assertNotNull(i.getEncoder());

    assertNotNull(i.getAttributeName());
    assertEquals(i.getAttributeName(), "booleanMF");

    assertNotNull(i.getObjectClasses());
    assertEquals(i.getObjectClasses().length, 1);
    assertEquals(i.getObjectClasses()[0], "TestNullable");

    assertNotNull(i.constructAttributeType());
  }



  /**
   * Tests the behavior of the {@code GetterInfo} class with a class that has
   * the {@code LDAPObject} annotation but a method that does not have the
   * {@code LDAPGetter} annotation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testMethodNotAnnotated()
         throws Exception
  {
    TestAnnotationsObject o = new TestAnnotationsObject();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("getTestDefaults");
    assertNotNull(m);

    new GetterInfo(m, c);
  }



  /**
   * Tests the behavior of the {@code GetterInfo} class with a method that has
   * the {@code LDAPGetter} annotation but a class that does not have the
   * {@code LDAPObject} annotation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testClassNotAnnotated()
         throws Exception
  {
    TestClassNotAnnotated o = new TestClassNotAnnotated();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("getTestMethodField");
    assertNotNull(m);

    new GetterInfo(m, c);
  }



  /**
   * Tests the behavior of the {@code GetterInfo} class with a method that is
   * declared static.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testStaticMethod()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("getTestStaticMethodField");
    assertNotNull(m);

    new GetterInfo(m, c);
  }



  /**
   * Tests the behavior of the {@code GetterInfo} class with a method that takes
   * an argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testGetterWithArgument()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("getGetterWithArgument", String.class);
    assertNotNull(m);

    new GetterInfo(m, c);
  }



  /**
   * Tests the behavior of the {@code GetterInfo} class with a method that has
   * an unsupported return type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testGetterWithUnsupportedReturnType()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("getUnsupportedReturnType");
    assertNotNull(m);

    new GetterInfo(m, c);
  }



  /**
   * Tests the behavior of the {@code GetterInfo} class with a method that has a
   * void return type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testGetterWithVoidReturnType()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("getVoidReturnType");
    assertNotNull(m);

    new GetterInfo(m, c);
  }



  /**
   * Tests the behavior of the {@code GetterInfo} class with a method that has
   * an invalid encoder class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testGetterWithInvalidEncoder()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("getInvalidEncoder");
    assertNotNull(m);

    new GetterInfo(m, c);
  }



  /**
   * Tests the behavior of the {@code GetterInfo} class with a method that has
   * an invalid object class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testGetterWithInvalidObjectClass()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("getInvalidObjectClass");
    assertNotNull(m);

    new GetterInfo(m, c);
  }



  /**
   * Tests the behavior of the {@code GetterInfo} class with a method that has
   * an inferred attribute name but the method name does not start with "get".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testGetterWithInvalidInferredAttribute()
         throws Exception
  {
    TestGetterInvalidInferredAttribute o =
         new TestGetterInvalidInferredAttribute();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("gimmieABreak");
    assertNotNull(m);

    new GetterInfo(m, c);
  }



  /**
   * Tests the behavior of the {@code encode} method when a runtime exception
   * is thrown.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testEncodeWithRuntimeException()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("getRuntimeException");
    assertNotNull(m);

    GetterInfo i = new GetterInfo(m, c);

    i.encode(o);
  }



  /**
   * Tests the behavior of the {@code encode} method when an LDAP persist
   * exception is thrown.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testEncodeWithPersistException()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();

    Class<?> c = o.getClass();

    Method m = c.getDeclaredMethod("getPersistException");
    assertNotNull(m);

    GetterInfo i = new GetterInfo(m, c);

    i.encode(o);
  }
}
