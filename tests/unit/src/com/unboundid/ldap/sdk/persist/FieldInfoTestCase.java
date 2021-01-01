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



import java.lang.reflect.Field;
import java.util.LinkedList;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides a set of test cases for the {@code FieldInfo} class.
 */
public class FieldInfoTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a field with an annotation with no elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoElements()
         throws Exception
  {
    TestAnnotationsObject o = new TestAnnotationsObject();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("testDefaults");
    assertNotNull(f);

    FieldInfo i = new FieldInfo(f, c);

    assertNotNull(i.getField());
    assertEquals(i.getField(), f);

    assertNotNull(i.getContainingClass());
    assertEquals(i.getContainingClass(), c);

    assertTrue(i.failOnInvalidValue());

    assertTrue(i.failOnTooManyValues());

    assertTrue(i.includeInAdd());

    assertTrue(i.includeInModify());

    assertFalse(i.includeInRDN());

    assertEquals(i.getFilterUsage(), FilterUsage.CONDITIONALLY_ALLOWED);

    assertFalse(i.isRequiredForDecode());

    assertFalse(i.isRequiredForEncode());

    assertNotNull(i.getEncoder());
    assertEquals(i.getEncoder().getClass(), DefaultObjectEncoder.class);

    assertNotNull(i.getAttributeName());
    assertEquals(i.getAttributeName(), "testDefaults");

    assertNotNull(i.getDefaultDecodeValues());
    assertEquals(i.getDefaultDecodeValues().length, 0);

    assertNotNull(i.getDefaultEncodeValues());
    assertEquals(i.getDefaultEncodeValues().length, 0);

    assertFalse(i.supportsMultipleValues());

    assertNotNull(i.constructAttributeType());

    assertNotNull(i.getObjectClasses());
    assertEquals(i.getObjectClasses().length, 1);
    assertEquals(i.getObjectClasses()[0], "testAnnotationsStructural");


    // Test the encode method with no value.
    assertNull(o.getTestDefaults());
    assertNull(i.encode(o, false));


    // Test the encode method with a value.
    o.setTestDefaults("abc");
    assertEquals(o.getTestDefaults(), "abc");
    Attribute a = i.encode(o, false);
    assertNotNull(a);
    assertEquals(a.getName(), "testDefaults");
    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("abc"));


    // Test the decode method with a value.
    Entry e = new Entry(
         "dn: foo=a,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testAnnotationsStructural",
         "objectClass: testAnnotationsAuxiliary",
         "foo: a",
         "testDefaults: b",
         "testMultiValued: c",
         "testMultiValued: d",
         "testMultiValued: e");
    LinkedList<String> failureReasons = new LinkedList<String>();
    assertTrue(i.decode(o, e, failureReasons),
         concatenateStrings(failureReasons));
    assertEquals(o.getTestDefaults(), "b");


    // Test the decode method with no value.
    e = new Entry(
         "dn: foo=a,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testAnnotationsStructural",
         "objectClass: testAnnotationsAuxiliary",
         "foo: a",
         "testMultiValued: c",
         "testMultiValued: d",
         "testMultiValued: e");
    assertTrue(i.decode(o, e, failureReasons),
         concatenateStrings(failureReasons));
    assertNull(o.getTestDefaults());
  }



  /**
   * Tests a field with an annotation with all elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllElements()
         throws Exception
  {
    TestAnnotationsObject o = new TestAnnotationsObject();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("testNonDefaults");
    assertNotNull(f);

    FieldInfo i = new FieldInfo(f, c);

    assertNotNull(i.getField());
    assertEquals(i.getField(), f);

    assertNotNull(i.getContainingClass());
    assertEquals(i.getContainingClass(), c);

    assertFalse(i.failOnInvalidValue());

    assertFalse(i.failOnTooManyValues());

    assertTrue(i.includeInAdd());

    assertFalse(i.includeInModify());

    assertTrue(i.includeInRDN());

    assertEquals(i.getFilterUsage(), FilterUsage.ALWAYS_ALLOWED);

    assertTrue(i.isRequiredForDecode());

    assertTrue(i.isRequiredForEncode());

    assertNotNull(i.getEncoder());
    assertEquals(i.getEncoder().getClass(), DefaultObjectEncoder.class);

    assertNotNull(i.getAttributeName());
    assertEquals(i.getAttributeName(), "foo");

    assertNotNull(i.getDefaultDecodeValues());
    assertEquals(i.getDefaultDecodeValues().length, 1);
    assertEquals(i.getDefaultDecodeValues()[0], "baz");

    assertNotNull(i.getDefaultEncodeValues());
    assertEquals(i.getDefaultEncodeValues().length, 1);
    assertEquals(i.getDefaultEncodeValues()[0], "bar");

    assertFalse(i.supportsMultipleValues());

    assertNotNull(i.constructAttributeType());

    assertNotNull(i.getObjectClasses());
    assertEquals(i.getObjectClasses().length, 1);
    assertEquals(i.getObjectClasses()[0], "testAnnotationsAuxiliary");


    // Test the encode method with no value.
    assertNull(o.getTestNonDefaults());
    Attribute a = i.encode(o, false);
    assertNotNull(a);
    assertEquals(a.getName(), "foo");
    assertTrue(a.hasValue("bar"));


    // Test the encode method with a value.
    o.setTestNonDefaults("abc");
    assertEquals(o.getTestNonDefaults(), "abc");
    a = i.encode(o, false);
    assertNotNull(a);
    assertEquals(a.getName(), "foo");
    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("abc"));


    // Test the decode method with a value.
    Entry e = new Entry(
         "dn: foo=a,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testAnnotationsStructural",
         "objectClass: testAnnotationsAuxiliary",
         "foo: a",
         "testDefaults: b",
         "testMultiValued: c",
         "testMultiValued: d",
         "testMultiValued: e");
    LinkedList<String> failureReasons = new LinkedList<String>();
    assertTrue(i.decode(o, e, failureReasons),
         concatenateStrings(failureReasons));
    assertEquals(o.getTestNonDefaults(), "a");


    // Test the decode method with no value.
    e = new Entry(
         "dn: cn=a,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testAnnotationsStructural",
         "objectClass: testAnnotationsAuxiliary",
         "cn: a",
         "testDefaults: b",
         "testMultiValued: c",
         "testMultiValued: d",
         "testMultiValued: e");
    assertTrue(i.decode(o, e, failureReasons),
         concatenateStrings(failureReasons));
    assertNotNull(o.getTestNonDefaults());
    assertEquals(o.getTestNonDefaults(), "baz");
  }



  /**
   * Tests a field with an annotation with a field that allows multiple values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultiValued()
         throws Exception
  {
    TestAnnotationsObject o = new TestAnnotationsObject();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("testMultiValued");
    assertNotNull(f);

    FieldInfo i = new FieldInfo(f, c);

    assertNotNull(i.getField());
    assertEquals(i.getField(), f);

    assertNotNull(i.getContainingClass());
    assertEquals(i.getContainingClass(), c);

    assertTrue(i.failOnInvalidValue());

    assertFalse(i.failOnTooManyValues());

    assertTrue(i.includeInAdd());

    assertTrue(i.includeInModify());

    assertFalse(i.includeInRDN());

    assertEquals(i.getFilterUsage(), FilterUsage.CONDITIONALLY_ALLOWED);

    assertFalse(i.isRequiredForDecode());

    assertFalse(i.isRequiredForEncode());

    assertNotNull(i.getEncoder());
    assertEquals(i.getEncoder().getClass(), DefaultObjectEncoder.class);

    assertNotNull(i.getAttributeName());
    assertEquals(i.getAttributeName(), "testMultiValued");

    assertNotNull(i.getDefaultDecodeValues());
    assertEquals(i.getDefaultDecodeValues().length, 2);
    assertEquals(i.getDefaultDecodeValues()[0], "c");
    assertEquals(i.getDefaultDecodeValues()[1], "d");

    assertNotNull(i.getDefaultEncodeValues());
    assertEquals(i.getDefaultEncodeValues().length, 2);
    assertEquals(i.getDefaultEncodeValues()[0], "a");
    assertEquals(i.getDefaultEncodeValues()[1], "b");

    assertTrue(i.supportsMultipleValues());

    assertNotNull(i.constructAttributeType());

    assertNotNull(i.getObjectClasses());
    assertEquals(i.getObjectClasses().length, 2);
    assertEquals(i.getObjectClasses()[0], "testAnnotationsStructural");
    assertEquals(i.getObjectClasses()[1], "testAnnotationsAuxiliary");


    // Test the encode method with no value.
    assertNull(o.getTestMultiValued());
    Attribute a = i.encode(o, false);
    assertNotNull(a);
    assertEquals(a.getName(), "testMultiValued");
    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("a"));
    assertTrue(a.hasValue("b"));


    // Test the encode method with a value.
    o.setTestMultiValued("abc");
    assertEquals(o.getTestMultiValued().length, 1);
    assertEquals(o.getTestMultiValued()[0], "abc");
    a = i.encode(o, false);
    assertNotNull(a);
    assertEquals(a.getName(), "testMultiValued");
    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("abc"));


    // Test the decode method with a value.
    Entry e = new Entry(
         "dn: foo=a,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testAnnotationsStructural",
         "objectClass: testAnnotationsAuxiliary",
         "foo: a",
         "testDefaults: b",
         "testMultiValued: c",
         "testMultiValued: d",
         "testMultiValued: e");
    LinkedList<String> failureReasons = new LinkedList<String>();
    assertTrue(i.decode(o, e, failureReasons),
         concatenateStrings(failureReasons));
    assertEquals(o.getTestMultiValued().length, 3);
    assertEquals(o.getTestMultiValued()[0], "c");
    assertEquals(o.getTestMultiValued()[1], "d");
    assertEquals(o.getTestMultiValued()[2], "e");


    // Test the decode method with no value.
    e = new Entry(
         "dn: foo=a,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testAnnotationsStructural",
         "objectClass: testAnnotationsAuxiliary",
         "foo: a",
         "testDefaults: b");
    assertTrue(i.decode(o, e, failureReasons),
         concatenateStrings(failureReasons));
    assertNotNull(o.getTestMultiValued());
    assertEquals(o.getTestMultiValued().length, 2);
    assertEquals(o.getTestMultiValued()[0], "c");
    assertEquals(o.getTestMultiValued()[1], "d");
  }



  /**
   * Tests a field with an annotation in a class without any
   * explicitly-specified object classes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoNamedObjectClasses()
         throws Exception
  {
    TestNullable o = new TestNullable();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("booleanF");
    assertNotNull(f);

    FieldInfo i = new FieldInfo(f, c);

    assertNotNull(i.getField());
    assertEquals(i.getField(), f);

    assertNotNull(i.getContainingClass());
    assertEquals(i.getContainingClass(), c);

    assertTrue(i.failOnInvalidValue());

    assertTrue(i.failOnTooManyValues());

    assertTrue(i.includeInAdd());

    assertTrue(i.includeInModify());

    assertFalse(i.includeInRDN());

    assertEquals(i.getFilterUsage(), FilterUsage.CONDITIONALLY_ALLOWED);

    assertFalse(i.isRequiredForDecode());

    assertFalse(i.isRequiredForEncode());

    assertNotNull(i.getEncoder());
    assertEquals(i.getEncoder().getClass(), DefaultObjectEncoder.class);

    assertNotNull(i.getAttributeName());
    assertEquals(i.getAttributeName(), "booleanF");

    assertNotNull(i.getDefaultDecodeValues());
    assertEquals(i.getDefaultDecodeValues().length, 0);

    assertNotNull(i.getDefaultEncodeValues());
    assertEquals(i.getDefaultEncodeValues().length, 0);

    assertFalse(i.supportsMultipleValues());

    assertNotNull(i.constructAttributeType());

    assertNotNull(i.getObjectClasses());
    assertEquals(i.getObjectClasses().length, 1);
    assertEquals(i.getObjectClasses()[0], "TestNullable");
  }



  /**
   * Tests a field that should not be included in add operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNotInAdd()
         throws Exception
  {
    TestAnnotationsObject o = new TestAnnotationsObject();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("notInAdd");
    assertNotNull(f);

    FieldInfo i = new FieldInfo(f, c);

    assertNotNull(i.getField());
    assertEquals(i.getField(), f);

    assertNotNull(i.getContainingClass());
    assertEquals(i.getContainingClass(), c);

    assertTrue(i.failOnInvalidValue());

    assertTrue(i.failOnTooManyValues());

    assertFalse(i.includeInAdd());

    assertTrue(i.includeInModify());

    assertFalse(i.includeInRDN());

    assertEquals(i.getFilterUsage(), FilterUsage.CONDITIONALLY_ALLOWED);

    assertFalse(i.isRequiredForDecode());

    assertFalse(i.isRequiredForEncode());

    assertNotNull(i.getEncoder());
    assertEquals(i.getEncoder().getClass(), DefaultObjectEncoder.class);

    assertNotNull(i.getAttributeName());
    assertEquals(i.getAttributeName(), "notInAdd");

    assertNotNull(i.getDefaultDecodeValues());
    assertEquals(i.getDefaultDecodeValues().length, 0);

    assertNotNull(i.getDefaultEncodeValues());
    assertEquals(i.getDefaultEncodeValues().length, 0);

    assertFalse(i.supportsMultipleValues());

    assertNotNull(i.constructAttributeType());

    assertNotNull(i.getObjectClasses());
    assertEquals(i.getObjectClasses().length, 1);
    assertEquals(i.getObjectClasses()[0], "testAnnotationsStructural");
  }



  /**
   * Tests the behavior of the {@code FieldInfo} class when provided with a
   * field that is not annotated in a class that is.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testFieldNotAnnotated()
         throws Exception
  {
    TestAnnotationsObject o = new TestAnnotationsObject();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("notAnnotated");
    assertNotNull(f);

    new FieldInfo(f, c);
  }



  /**
   * Tests the behavior of the {@code FieldInfo} class when provided with a
   * field that is annotated in a class that is not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testClassNotAnnotated()
         throws Exception
  {
    TestClassNotAnnotated o = new TestClassNotAnnotated();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("testField");
    assertNotNull(f);

    new FieldInfo(f, c);
  }



  /**
   * Tests the behavior of the {@code FieldInfo} class when provided with a
   * field containing both the lazilyLoad and defaultDecodeValue elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testLazyLoadAndDefaultDecodeValue()
         throws Exception
  {
    TestLazyLoadWithDefaultDecode o = new TestLazyLoadWithDefaultDecode();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("invalid");
    assertNotNull(f);

    new FieldInfo(f, c);
  }



  /**
   * Tests the behavior of the {@code FieldInfo} class when provided with a
   * field containing both the lazilyLoad and defaultEncodeValue elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testLazyLoadAndDefaultEncodeValue()
         throws Exception
  {
    TestLazyLoadWithDefaultEncode o = new TestLazyLoadWithDefaultEncode();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("invalid");
    assertNotNull(f);

    new FieldInfo(f, c);
  }



  /**
   * Tests the behavior of the {@code FieldInfo} class when provided with a
   * field containing both the lazilyLoad and inRDN elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testLazyLoadAndInRDN()
         throws Exception
  {
    TestLazyLoadRDNAttribute o = new TestLazyLoadRDNAttribute();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("invalid");
    assertNotNull(f);

    new FieldInfo(f, c);
  }



  /**
   * Tests the behavior of the {@code FieldInfo} class when provided with a
   * field that is declared final.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testFinalField()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("finalField");
    assertNotNull(f);

    new FieldInfo(f, c);
  }



  /**
   * Tests the behavior of the {@code FieldInfo} class when provided with a
   * field that is declared static.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testStaticField()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("staticField");
    assertNotNull(f);

    new FieldInfo(f, c);
  }



  /**
   * Tests the behavior of the {@code FieldInfo} class when provided with a
   * field that has an invalid encoder class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testInvalidEncoder()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("invalidEncoder");
    assertNotNull(f);

    new FieldInfo(f, c);
  }



  /**
   * Tests the behavior of the {@code FieldInfo} class when provided with a
   * field that isn't supported by the encoder.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testUnsupportedObjectType()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("unsupportedObjectType");
    assertNotNull(f);

    new FieldInfo(f, c);
  }



  /**
   * Tests the behavior of the {@code FieldInfo} class when provided with a
   * single-valued field with multiple default encode values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testSingleValuedFieldMultipleDefaultEncodeValues()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("multipleDefaultEncodeValues");
    assertNotNull(f);

    new FieldInfo(f, c);
  }



  /**
   * Tests the behavior of the {@code FieldInfo} class when provided with a
   * single-valued field with multiple default decode values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testSingleValuedFieldMultipleDefaultDecodeValues()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("multipleDefaultDecodeValues");
    assertNotNull(f);

    new FieldInfo(f, c);
  }



  /**
   * Tests the behavior of the {@code FieldInfo} class when provided with a
   * field whose name isn't a valid LDAP name and no explicitly-specified name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testInvalidLDAPName()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("not_a_valid_ldap_name");
    assertNotNull(f);

    new FieldInfo(f, c);
  }



  /**
   * Tests the behavior of the {@code FieldInfo} class when provided with a
   * field that is associated with an object class that isn't declared in the
   * {@code LDAPObject} annotation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testInvalidObjectClass()
         throws Exception
  {
    TestClassWithInvalidFields o = new TestClassWithInvalidFields();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("undefinedObjectClass");
    assertNotNull(f);

    new FieldInfo(f, c);
  }



  /**
   * Tests the behavior of the {@code encode} method with a field that is
   * required but doesn't have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testRequiredFieldWithoutValue()
         throws Exception
  {
    TestAnnotationsObject o = new TestAnnotationsObject();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("requiredNotInRDN");
    assertNotNull(f);

    FieldInfo i = new FieldInfo(f, c);

    assertNull(o.getRequiredNotInRDN());

    i.encode(o, false);
  }



  /**
   * Tests the behavior of the {@code encode} method with a field that is
   * required but doesn't have a value but with the ignore flag set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequiredFieldWithoutValueIgnored()
         throws Exception
  {
    TestAnnotationsObject o = new TestAnnotationsObject();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("requiredNotInRDN");
    assertNotNull(f);

    FieldInfo i = new FieldInfo(f, c);

    assertNull(o.getRequiredNotInRDN());

    assertNull(i.encode(o, true));
  }



  /**
   * Tests the behavior of the {@code encode} method with a {@code null} object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testEncodeNullObject()
         throws Exception
  {
    TestAnnotationsObject o = new TestAnnotationsObject();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("requiredNotInRDN");
    assertNotNull(f);

    FieldInfo i = new FieldInfo(f, c);

    assertNull(o.getRequiredNotInRDN());

    i.encode(null, false);
  }



  /**
   * Tests the behavior of the {@code decode} method with a multivalued
   * attribute when only a single value is allowed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeMultipleValuesForSingleValuedField()
         throws Exception
  {
    TestAnnotationsObject o = new TestAnnotationsObject();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("testDefaults");
    assertNotNull(f);

    FieldInfo i = new FieldInfo(f, c);

    Entry e = new Entry(
         "dn: foo=a,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testAnnotationsStructural",
         "objectClass: testAnnotationsAuxiliary",
         "foo: a",
         "testDefaults: b",
         "testDefaults: c",
         "requiredNotInRDN: d");

    LinkedList<String> failureReasons = new LinkedList<String>();
    assertFalse(i.decode(o, e, failureReasons));
    assertFalse(failureReasons.isEmpty());
  }



  /**
   * Tests the behavior of the {@code decode} method with an entry that does not
   * contain an attribute for a required attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeMissingRequiredAttribute()
         throws Exception
  {
    TestAnnotationsObject o = new TestAnnotationsObject();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("requiredNotInRDN");
    assertNotNull(f);

    FieldInfo i = new FieldInfo(f, c);

    Entry e = new Entry(
         "dn: foo=a,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testAnnotationsStructural",
         "objectClass: testAnnotationsAuxiliary",
         "foo: a",
         "testDefaults: b");

    LinkedList<String> failureReasons = new LinkedList<String>();
    assertFalse(i.decode(o, e, failureReasons));
    assertFalse(failureReasons.isEmpty());
  }



  /**
   * Tests the behavior of the {@code decode} method with an entry containing an
   * attribute value that cannot be assigned to the associated field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeMalformedValue()
         throws Exception
  {
    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();
    Class<?> c = o.getClass();

    Field f = c.getDeclaredField("intOF");
    assertNotNull(f);

    FieldInfo i = new FieldInfo(f, c);

    Entry e = new Entry(
         "dn: cn=foo,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testStructuralClass",
         "objectClass: testAuxiliaryClass",
         "cn: foo",
         "intOF: invalid");

    LinkedList<String> failureReasons = new LinkedList<String>();
    assertFalse(i.decode(o, e, failureReasons));
    assertFalse(failureReasons.isEmpty());
  }
}
