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



import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ReadOnlyEntry;



/**
 * This class provides test coverage for the {@code LDAPObjectHandler} class.
 */
public class LDAPObjectHandlerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the ability to create an object handler for a valid object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateForValidObject()
         throws Exception
  {
    TestAnnotationsObject o = new TestAnnotationsObject();

    LDAPObjectHandler<TestAnnotationsObject> handler =
         new LDAPObjectHandler<TestAnnotationsObject>(
              TestAnnotationsObject.class);

    assertNotNull(handler);

    assertNotNull(handler.getType());
    assertEquals(handler.getType(), TestAnnotationsObject.class);

    assertNull(handler.getSuperclassHandler());

    assertNotNull(handler.getLDAPObjectAnnotation());

    assertNotNull(handler.getConstructor());

    assertNotNull(handler.getDNField());
    assertEquals(handler.getDNField().getName(), "dnField");

    assertNotNull(handler.getEntryField());
    assertEquals(handler.getEntryField().getName(), "entryField");

    assertNotNull(handler.getDefaultParentDN());

    assertNotNull(handler.getStructuralClass());

    assertNotNull(handler.getAuxiliaryClasses());
    assertEquals(handler.getAuxiliaryClasses().length,
         handler.getLDAPObjectAnnotation().auxiliaryClass().length);

    assertNotNull(handler.getSuperiorClasses());
    assertEquals(handler.getSuperiorClasses().length,
         handler.getLDAPObjectAnnotation().superiorClass().length);

    Map<String,FieldInfo> fields = handler.getFields();
    assertNotNull(fields);
    assertNotNull(fields.get("testdefaults"));
    assertNotNull(fields.get("foo"));
    assertNotNull(fields.get("testmultivalued"));
    assertNotNull(fields.get("requirednotinrdn"));
    assertNotNull(fields.get("notinadd"));
    assertNull(fields.get("notannotated"));
    assertNull(fields.get("dnfield"));
    assertNull(fields.get("entryfield"));
    assertNull(fields.get("testmethoddefaults"));
    assertNull(fields.get("testmethodnondefaults"));
    assertNull(fields.get("testmethodmultivalued"));

    Map<String,GetterInfo> getters = handler.getGetters();
    assertNotNull(getters);
    assertNull(getters.get("testdefaults"));
    assertNull(getters.get("foo"));
    assertNull(getters.get("testmultivalued"));
    assertNull(getters.get("requirednotinrdn"));
    assertNull(getters.get("notinadd"));
    assertNull(getters.get("notannotated"));
    assertNull(getters.get("dnfield"));
    assertNull(getters.get("entryfield"));
    assertNotNull(getters.get("testmethoddefaults"));
    assertNotNull(getters.get("x"));
    assertNotNull(getters.get("testmethodmultivalued"));

    Map<String,SetterInfo> setters = handler.getSetters();
    assertNotNull(setters);
    assertNull(setters.get("testdefaults"));
    assertNull(setters.get("foo"));
    assertNull(setters.get("testmultivalued"));
    assertNull(setters.get("requirednotinrdn"));
    assertNull(setters.get("notinadd"));
    assertNull(setters.get("notannotated"));
    assertNull(setters.get("dnfield"));
    assertNull(setters.get("entryfield"));
    assertNotNull(setters.get("testmethoddefaults"));
    assertNotNull(setters.get("x"));
    assertNotNull(setters.get("testmethodmultivalued"));
  }



  /**
   * Tests the behavior when trying to create a handler for an object that
   * doesn't have the {@code LDAPObject} annotation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithoutAnnotation()
         throws Exception
  {
    new LDAPObjectHandler<TestClassNotAnnotated>(TestClassNotAnnotated.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * an invalid explicitly-defined structural object class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithInvalidExplicitStructuralClass()
         throws Exception
  {
    new LDAPObjectHandler<TestInvalidExplicitStructuralClass>(
         TestInvalidExplicitStructuralClass.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * an invalid implicitly-defined structural object class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithInvalidImplicitStructuralClass()
         throws Exception
  {
    new LDAPObjectHandler<Test_Invalid_Implicit_Structural_Class>(
         Test_Invalid_Implicit_Structural_Class.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * an invalid auxiliary object class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithInvalidAuxiliaryClass()
         throws Exception
  {
    new LDAPObjectHandler<TestInvalidAuxiliaryClass>(
         TestInvalidAuxiliaryClass.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * an invalid superior object class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithInvalidSuperiorClass()
         throws Exception
  {
    new LDAPObjectHandler<TestInvalidSuperiorClass>(
         TestInvalidSuperiorClass.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * an invalid default parent DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithInvalidDefaultParentDN()
         throws Exception
  {
    new LDAPObjectHandler<TestInvalidDefaultParentDN>(
         TestInvalidDefaultParentDN.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * a missing post-decode method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithMissingPostDecodeMethod()
         throws Exception
  {
    new LDAPObjectHandler<TestMissingPostDecodeMethod>(
         TestMissingPostDecodeMethod.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * an invalid post-decode method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithInvalidPostDecodeMethod()
         throws Exception
  {
    new LDAPObjectHandler<TestInvalidPostDecodeMethod>(
         TestInvalidPostDecodeMethod.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * a missing post-encode method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithMissingPostEncodeMethod()
         throws Exception
  {
    new LDAPObjectHandler<TestMissingPostEncodeMethod>(
         TestMissingPostEncodeMethod.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * an invalid post-encode method that does not take any arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithInvalidPostEncodeMethodNoArgs()
         throws Exception
  {
    new LDAPObjectHandler<TestInvalidPostEncodeMethodNoArgs>(
         TestInvalidPostEncodeMethodNoArgs.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * an invalid post-encode method whose argument is not an entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithInvalidPostEncodeMethodArgNotEntry()
         throws Exception
  {
    new LDAPObjectHandler<TestInvalidPostEncodeMethodArgNotEntry>(
         TestInvalidPostEncodeMethodArgNotEntry.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that does
   * not have a default constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithoutDefaultConstructor()
         throws Exception
  {
    new LDAPObjectHandler<TestNoDefaultConstructor>(
         TestNoDefaultConstructor.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * two fields targeting the same attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithConflictingFieldAnnotations()
         throws Exception
  {
    new LDAPObjectHandler<TestConflictingFieldAnnotations>(
         TestConflictingFieldAnnotations.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * a field marked with both the {@code LDAPField} and {@code LDAPDNField}
   * annotations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithConflictingFieldAndDNAnnotations()
         throws Exception
  {
    new LDAPObjectHandler<TestConflictingFieldAndDNAnnotations>(
         TestConflictingFieldAndDNAnnotations.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * a field marked with both the {@code LDAPField} and {@code LDAPEntryField}
   * annotations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithConflictingFieldAndEntryAnnotations()
         throws Exception
  {
    new LDAPObjectHandler<TestConflictingFieldAndEntryAnnotations>(
         TestConflictingFieldAndEntryAnnotations.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * two fields marked with the {@code LDAPDNField} annotation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithMultipleDNFieldAnnotations()
         throws Exception
  {
    new LDAPObjectHandler<TestMultipleDNAnnotations>(
         TestMultipleDNAnnotations.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * two fields marked with the {@code LDAPEntryField} annotation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithMultipleEntryFieldAnnotations()
         throws Exception
  {
    new LDAPObjectHandler<TestMultipleEntryAnnotations>(
         TestMultipleEntryAnnotations.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * a field marked with the {@code LDAPDNField} annotation that is declared
   * final.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithFinalDNFieldAnnotations()
         throws Exception
  {
    new LDAPObjectHandler<TestFinalDNField>(TestFinalDNField.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * a field marked with the {@code LDAPEntryField} annotation that is declared
   * final.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithFinalEntryFieldAnnotations()
         throws Exception
  {
    new LDAPObjectHandler<TestFinalEntryField>(TestFinalEntryField.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * a field marked with the {@code LDAPDNField} annotation that is declared
   * static.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithStaticDNFieldAnnotations()
         throws Exception
  {
    new LDAPObjectHandler<TestStaticDNField>(TestStaticDNField.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * a field marked with the {@code LDAPEntryField} annotation that is declared
   * static.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithStaticEntryFieldAnnotations()
         throws Exception
  {
    new LDAPObjectHandler<TestStaticEntryField>(TestStaticEntryField.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * a field marked with the {@code LDAPDNField} annotation but does not have a
   * type of {@code String}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithDNFieldNotString()
         throws Exception
  {
    new LDAPObjectHandler<TestDNFieldNotString>(TestDNFieldNotString.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * a field marked with the {@code LDAPEntryField} annotation but does not have
   * a type of {@code com.unboundid.ldap.sdk.ReadOnlyEntry}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithEntryFieldNotReadOnlyEntry()
         throws Exception
  {
    new LDAPObjectHandler<TestEntryFieldNotReadOnlyEntry>(
         TestEntryFieldNotReadOnlyEntry.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * a method marked with both the {@code LDAPGetter} and
   * {@code LDAPSetter} annotations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateClassWithMethodMarkedAsGetterAndSetter()
         throws Exception
  {
    new LDAPObjectHandler<TestGetterAndSetterAnnotations>(
         TestGetterAndSetterAnnotations.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * both a field and a getter method configured to target the same attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateConflictingFieldAndGetter()
         throws Exception
  {
    new LDAPObjectHandler<TestConflictingFieldAndGetter>(
         TestConflictingFieldAndGetter.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * both a field and a setter method configured to target the same attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateConflictingFieldAndSetter()
         throws Exception
  {
    new LDAPObjectHandler<TestConflictingFieldAndSetter>(
         TestConflictingFieldAndSetter.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * multiple getters that target the same attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateConflictingGetters()
         throws Exception
  {
    new LDAPObjectHandler<TestConflictingGetters>(TestConflictingGetters.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that has
   * multiple setters that target the same attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateConflictingSetters()
         throws Exception
  {
    new LDAPObjectHandler<TestConflictingSetters>(TestConflictingSetters.class);
  }



  /**
   * Tests the behavior when trying to create a handler for an object that does
   * not define any RDN fields or getters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateWithoutRDN()
         throws Exception
  {
    new LDAPObjectHandler<TestNoRDN>(TestNoRDN.class);
  }



  /**
   * Tests the behavior of the getEntryDN method for an object that has a DN
   * field with a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetEntryDNWithDNFieldWithValue()
         throws Exception
  {
    LDAPObjectHandler<TestBasicObject> handler =
         new LDAPObjectHandler<TestBasicObject>(TestBasicObject.class);

    TestBasicObject o = new TestBasicObject();
    o.setDN("a=1,dc=example,dc=com");

    assertNotNull(handler.getEntryDN(o));
    assertEquals(new DN(handler.getEntryDN(o)),
         new DN("a=1,dc=example,dc=com"));
  }



  /**
   * Tests the behavior of the getEntryDN method for an object that has a DN
   * field with no value and an entry field with a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetEntryDNWithDNFieldWithoutValueEntryFieldWithValue()
         throws Exception
  {
    LDAPObjectHandler<TestBasicObject> handler =
         new LDAPObjectHandler<TestBasicObject>(TestBasicObject.class);

    TestBasicObject o = new TestBasicObject();
    o.setEntry(new ReadOnlyEntry(
         "dn: a=1,dc=example,dc=com",
         "objectClass: top",
         "objectClass: x",
         "objectClass: y",
         "objectClass: z",
         "a: 1",
         "b: 2",
         "c: 3",
         "m: 13",
         "n: 14"));

    assertNotNull(handler.getEntryDN(o));
    assertEquals(new DN(handler.getEntryDN(o)),
         new DN("a=1,dc=example,dc=com"));
  }



  /**
   * Tests the behavior of the getEntryDN method for an object that has DN and
   * entry fields without values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetEntryDNWithFieldsButNotValues()
         throws Exception
  {
    LDAPObjectHandler<TestBasicObject> handler =
         new LDAPObjectHandler<TestBasicObject>(TestBasicObject.class);

    TestBasicObject o = new TestBasicObject();
    assertNull(handler.getEntryDN(o));
  }



  /**
   * Provides test coverage for the {@code decode} method with a basic object
   * and a valid entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeBasicValidEntry()
         throws Exception
  {
    Entry e = new Entry(
         "dn: a=1,dc=example,dc=com",
         "objectClass: top",
         "objectClass: x",
         "objectClass: y",
         "objectClass: z",
         "a: 1",
         "b: 2",
         "c: 3",
         "m: 13",
         "n: 14");

    LDAPObjectHandler<TestBasicObject> handler =
         new LDAPObjectHandler<TestBasicObject>(TestBasicObject.class);
    TestBasicObject o = handler.decode(e);

    assertNotNull(o);

    assertNotNull(o.getA());
    assertEquals(o.getA(), "1");

    assertNotNull(o.getB());
    assertEquals(o.getB(), "2");

    assertNotNull(o.getC());
    assertEquals(o.getC(), "3");

    assertNotNull(o.getM());
    assertEquals(o.getM(), "13");

    assertNotNull(o.getN());
    assertEquals(o.getN(), "14");

    assertNotNull(o.getDN());
    assertEquals(new DN(o.getDN()), new DN("a=1,dc=example,dc=com"));

    assertNotNull(o.getEntry());
    assertTrue(o.getEntry().hasAttributeValue("a", "1"));
    assertTrue(o.getEntry().hasAttributeValue("b", "2"));
    assertTrue(o.getEntry().hasAttributeValue("c", "3"));
    assertTrue(o.getEntry().hasAttributeValue("m", "13"));
    assertTrue(o.getEntry().hasAttributeValue("n", "14"));

    assertNotNull(handler.getEntryDN(o));
    assertEquals(new DN(handler.getEntryDN(o)),
         new DN("a=1,dc=example,dc=com"));

    assertNotNull(handler.getEntry(o));
    assertEquals(new DN(handler.getEntry(o).getDN()),
         new DN("a=1,dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the {@code decode} method with a basic object
   * that throws an exception in the post-decode method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeExceptionInPostDecode()
         throws Exception
  {
    Entry e = new Entry(
         "dn: a=1,dc=example,dc=com",
         "objectClass: top",
         "objectClass: x",
         "objectClass: y",
         "objectClass: z",
         "a: 1",
         "b: 2",
         "c: 3",
         "m: 13",
         "n: 14");

    TestBasicObject o = new TestBasicObject();
    o.throwExceptionInPostDecode = true;

    LDAPObjectHandler<TestBasicObject> handler =
         new LDAPObjectHandler<TestBasicObject>(TestBasicObject.class);
    try
    {
      handler.decode(o, e);
      fail("Expected an exception");
    }
    catch (final LDAPPersistException lpe)
    {
      // This was expected.
      assertNotNull(lpe.getPartiallyDecodedObject());
      assertNotNull(lpe.getExceptionMessage());
    }
  }



  /**
   * Provides test coverage for the {@code decode} method with an object whose
   * constructor throws an exception.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeConstructorThrowsException()
         throws Exception
  {
    Entry e = new Entry(
         "dn: a=1,dc=example,dc=com",
         "objectClass: top",
         "objectClass: x",
         "a: 1");

    LDAPObjectHandler<TestConstructorThrowsException> handler =
         new LDAPObjectHandler<TestConstructorThrowsException>(
              TestConstructorThrowsException.class);

    try
    {
      handler.decode(e);
      fail("Expected an exception");
    }
    catch (final LDAPPersistException lpe)
    {
      // This was expected, and since the failure was in the constructor there
      // won't be a partially-decoded object.
      assertNull(lpe.getPartiallyDecodedObject());
      assertNotNull(lpe.getExceptionMessage());
    }
  }



  /**
   * Provides test coverage for the {@code decode} method with a basic object
   * and an entry missing an attribute marked required for decode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeMissingRequiredForDecode()
         throws Exception
  {
    Entry e = new Entry(
         "dn: a=1,dc=example,dc=com",
         "objectClass: top",
         "objectClass: x",
         "objectClass: y",
         "objectClass: z",
         "a: 1",
         "b: 2",
         "m: 13",
         "n: 14");

    LDAPObjectHandler<TestBasicObject> handler =
         new LDAPObjectHandler<TestBasicObject>(TestBasicObject.class);

    try
    {
      handler.decode(e);
      fail("Expected an exception");
    }
    catch (final LDAPPersistException lpe)
    {
      // This was expected.
      assertNotNull(lpe.getPartiallyDecodedObject());
      assertNotNull(lpe.getExceptionMessage());
    }
  }



  /**
   * Provides test coverage for the {@code encode} method with a valid, complete
   * object and an explicitly-specified parent DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncodeValidObjectWithExplicitParentDN()
         throws Exception
  {
    LDAPObjectHandler<TestBasicObject> handler =
         new LDAPObjectHandler<TestBasicObject>(TestBasicObject.class);

    TestBasicObject o = new TestBasicObject();
    o.setA("eh");
    o.setB("bee");
    o.setC("sea");
    o.setD("dee");
    o.setM("em");
    o.setN("en");
    o.setO("oh");

    assertNull(o.getDN());

    assertNull(o.getEntry());

    Entry e = handler.encode(o, "ou=explicit,dc=example,dc=com");

    assertEquals(e, new Entry(
         "dn: a=eh,ou=explicit,dc=example,dc=com",
         "objectClass: x",
         "objectClass: y",
         "objectClass: z",
         "a: eh",
         "b: bee",
         "c: sea",
         "m: em",
         "n: en",
         "addedInPostEncode: foo"));

    assertNotNull(o.getDN());
    assertEquals(new DN(o.getDN()),
         new DN("a=eh,ou=explicit,dc=example,dc=com"));

    assertNotNull(o.getEntry());
    assertEquals(o.getEntry(), new ReadOnlyEntry(e));
  }



  /**
   * Provides test coverage for the {@code encode} method with a valid, complete
   * object and an explicitly-specified empty parent DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncodeValidObjectWithExplicitEmptyParentDN()
         throws Exception
  {
    LDAPObjectHandler<TestBasicObject> handler =
         new LDAPObjectHandler<TestBasicObject>(TestBasicObject.class);

    TestBasicObject o = new TestBasicObject();
    o.setA("eh");
    o.setB("bee");
    o.setC("sea");
    o.setD("dee");
    o.setM("em");
    o.setN("en");
    o.setO("oh");

    assertNull(o.getDN());

    assertNull(o.getEntry());

    Entry e = handler.encode(o, "");

    assertEquals(e, new Entry(
         "dn: a=eh",
         "objectClass: x",
         "objectClass: y",
         "objectClass: z",
         "a: eh",
         "b: bee",
         "c: sea",
         "m: em",
         "n: en",
         "addedInPostEncode: foo"));

    assertNotNull(o.getDN());
    assertEquals(new DN(o.getDN()),
         new DN("a=eh"));

    assertNotNull(o.getEntry());
    assertEquals(o.getEntry(), new ReadOnlyEntry(e));
  }



  /**
   * Provides test coverage for the {@code encode} method with a valid, complete
   * object and an implicitly-specified parent DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncodeValidObjectWithImplicitParentDN()
         throws Exception
  {
    LDAPObjectHandler<TestBasicObject> handler =
         new LDAPObjectHandler<TestBasicObject>(TestBasicObject.class);

    TestBasicObject o = new TestBasicObject();
    o.setA("eh");
    o.setB("bee");
    o.setC("sea");
    o.setD("dee");
    o.setM("em");
    o.setN("en");
    o.setO("oh");

    assertNull(o.getDN());

    assertNull(o.getEntry());

    Entry e = handler.encode(o, null);

    assertEquals(e, new Entry(
         "dn: a=eh,ou=default,dc=example,dc=com",
         "objectClass: x",
         "objectClass: y",
         "objectClass: z",
         "a: eh",
         "b: bee",
         "c: sea",
         "m: em",
         "n: en",
         "addedInPostEncode: foo"));

    assertNotNull(o.getDN());
    assertEquals(new DN(o.getDN()),
         new DN("a=eh,ou=default,dc=example,dc=com"));

    assertNotNull(o.getEntry());
    assertEquals(o.getEntry(), new ReadOnlyEntry(e));
  }



  /**
   * Provides test coverage for the {@code encode} method with an entry missing
   * a required field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testEncodeObjectMissingRequiredField()
         throws Exception
  {
    LDAPObjectHandler<TestBasicObject> handler =
         new LDAPObjectHandler<TestBasicObject>(TestBasicObject.class);

    TestBasicObject o = new TestBasicObject();
    o.setB("bee");
    o.setC("sea");
    o.setD("dee");
    o.setM("em");
    o.setN("en");
    o.setO("oh");

    handler.encode(o, "dc=example,dc=com");
  }



  /**
   * Provides test coverage for the {@code encode} method with an exception in
   * the post-encode method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testEncodeExceptionInPostEncodeMethod()
         throws Exception
  {
    LDAPObjectHandler<TestBasicObject> handler =
         new LDAPObjectHandler<TestBasicObject>(TestBasicObject.class);

    TestBasicObject o = new TestBasicObject();
    o.setA("eh");
    o.setB("bee");
    o.setC("sea");
    o.setD("dee");
    o.setM("em");
    o.setN("en");
    o.setO("oh");

    o.throwExceptionInPostEncode = true;

    handler.encode(o, "dc=example,dc=com");
  }



  /**
   * Provides test coverage for the {@code constructDN} with the following
   * conditions:
   * <UL>
   *   <LI>A single RDN field with a valid value.</LI>
   *   <LI>No RDN getters.</LI>
   *   <LI>No existing DN field value.</LI>
   *   <LI>No existing entry field value.</LI>
   *   <LI>Explicitly-provided non-empty parent DN.</LI>
   * </UL>
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructDN1()
         throws Exception
  {
    LDAPObjectHandler<TestBasicObject> handler =
         new LDAPObjectHandler<TestBasicObject>(TestBasicObject.class);

    TestBasicObject o = new TestBasicObject();
    o.setA("1");

    HashMap<String,Attribute> attrMap = new HashMap<String,Attribute>();
    attrMap.put("a", new Attribute("a", "1"));

    String constructedDN = handler.constructDN(o, "dc=example,dc=com", attrMap);
    assertNotNull(constructedDN);
    assertEquals(new DN(constructedDN),
         new DN("a=1,dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the {@code constructDN} with the following
   * conditions:
   * <UL>
   *   <LI>A single RDN field with a valid value.</LI>
   *   <LI>No RDN getters.</LI>
   *   <LI>An existing DN field value.</LI>
   *   <LI>No existing entry field value.</LI>
   *   <LI>Explicitly-provided non-empty parent DN.</LI>
   * </UL>
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructDN2()
         throws Exception
  {
    LDAPObjectHandler<TestBasicObject> handler =
         new LDAPObjectHandler<TestBasicObject>(TestBasicObject.class);

    TestBasicObject o = new TestBasicObject();
    o.setA("1");
    o.setDN("a=1,ou=existing-dn,dc=example,dc=com");

    HashMap<String,Attribute> attrMap = new HashMap<String,Attribute>();
    attrMap.put("a", new Attribute("a", "1"));

    String constructedDN = handler.constructDN(o, "dc=example,dc=com", attrMap);
    assertNotNull(constructedDN);
    assertEquals(new DN(constructedDN),
         new DN("a=1,ou=existing-dn,dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the {@code constructDN} with the following
   * conditions:
   * <UL>
   *   <LI>A single RDN field with a valid value.</LI>
   *   <LI>No RDN getters.</LI>
   *   <LI>No existing DN field value.</LI>
   *   <LI>An existing entry field value.</LI>
   *   <LI>Explicitly-provided non-empty parent DN.</LI>
   * </UL>
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructDN3()
         throws Exception
  {
    LDAPObjectHandler<TestBasicObject> handler =
         new LDAPObjectHandler<TestBasicObject>(TestBasicObject.class);

    TestBasicObject o = new TestBasicObject();
    o.setA("1");
    o.setEntry(new ReadOnlyEntry(
         "dn: a=1,ou=existing-entry,dc=example,dc=com",
         "objectClass: top",
         "objectClass: x",
         "objectClass: y",
         "objectClass: z",
         "a: 1",
         "b: 2",
         "c: 3",
         "m: 13",
         "n: 14"));

    HashMap<String,Attribute> attrMap = new HashMap<String,Attribute>();
    attrMap.put("a", new Attribute("a", "1"));

    String constructedDN = handler.constructDN(o, "dc=example,dc=com", attrMap);
    assertNotNull(constructedDN);
    assertEquals(new DN(constructedDN),
         new DN("a=1,ou=existing-entry,dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the {@code constructDN} with the following
   * conditions:
   * <UL>
   *   <LI>A single RDN field with a valid value.</LI>
   *   <LI>No RDN getters.</LI>
   *   <LI>No existing DN field value.</LI>
   *   <LI>No existing entry field value.</LI>
   *   <LI>Explicitly-provided non-empty invalid parent DN.</LI>
   * </UL>
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testConstructDN4()
         throws Exception
  {
    LDAPObjectHandler<TestBasicObject> handler =
         new LDAPObjectHandler<TestBasicObject>(TestBasicObject.class);

    TestBasicObject o = new TestBasicObject();
    o.setA("1");

    HashMap<String,Attribute> attrMap = new HashMap<String,Attribute>();
    attrMap.put("a", new Attribute("a", "1"));

    handler.constructDN(o, "invalid", attrMap);
  }



  /**
   * Provides test coverage for the {@code constructDN} with the following
   * conditions:
   * <UL>
   *   <LI>Multiple RDN fields with valid values.</LI>
   *   <LI>No RDN getters.</LI>
   *   <LI>No existing DN field value.</LI>
   *   <LI>No existing entry field value.</LI>
   *   <LI>Implicitly-provided empty parent DN.</LI>
   * </UL>
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructDN5()
         throws Exception
  {
    LDAPObjectHandler<TestMultipleRDNFields> handler =
         new LDAPObjectHandler<TestMultipleRDNFields>(
              TestMultipleRDNFields.class);

    TestMultipleRDNFields o = new TestMultipleRDNFields();
    o.a = "1";
    o.b = "2";

    HashMap<String,Attribute> attrMap = new HashMap<String,Attribute>();
    attrMap.put("a", new Attribute("a", "1"));
    attrMap.put("b", new Attribute("b", "2"));

    String constructedDN = handler.constructDN(o, null, attrMap);
    assertNotNull(constructedDN);
    assertEquals(new DN(constructedDN),
         new DN("a=1+b=2"));
  }



  /**
   * Provides test coverage for the {@code constructDN} with the following
   * conditions:
   * <UL>
   *   <LI>No RDN fields.</LI>
   *   <LI>One RDN getters with a valid value.</LI>
   *   <LI>No existing DN field value.</LI>
   *   <LI>No existing entry field value.</LI>
   *   <LI>Explicitly-provided empty parent DN.</LI>
   * </UL>
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructDN6()
         throws Exception
  {
    LDAPObjectHandler<TestRDNGetter> handler =
         new LDAPObjectHandler<TestRDNGetter>(TestRDNGetter.class);

    TestRDNGetter o = new TestRDNGetter();
    o.a = "1";

    HashMap<String,Attribute> attrMap = new HashMap<String,Attribute>();
    attrMap.put("a", new Attribute("a", "1"));

    String constructedDN = handler.constructDN(o, "", attrMap);
    assertNotNull(constructedDN);
    assertEquals(new DN(constructedDN),
         new DN("a=1"));
  }



  /**
   * Provides test coverage for the {@code constructDN} with the following
   * conditions:
   * <UL>
   *   <LI>Multiple RDN fields with valid values.</LI>
   *   <LI>Multiple RDN getters with valid values.</LI>
   *   <LI>No existing DN field value.</LI>
   *   <LI>No existing entry field value.</LI>
   *   <LI>Explicitly-provided parent DN.</LI>
   * </UL>
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructDN7()
         throws Exception
  {
    LDAPObjectHandler<TestMinimalObjectMultipleRDNs> handler =
         new LDAPObjectHandler<TestMinimalObjectMultipleRDNs>(
              TestMinimalObjectMultipleRDNs.class);

    TestMinimalObjectMultipleRDNs o = new TestMinimalObjectMultipleRDNs();
    o.a = "1";
    o.b = "2";
    o.c = "3";
    o.d = "4";

    HashMap<String,Attribute> attrMap = new HashMap<String,Attribute>();
    attrMap.put("a", new Attribute("a", "1"));
    attrMap.put("b", new Attribute("b", "2"));
    attrMap.put("c", new Attribute("c", "3"));
    attrMap.put("d", new Attribute("d", "4"));

    String constructedDN = handler.constructDN(o, "dc=example,dc=com", attrMap);
    assertNotNull(constructedDN);
    assertEquals(new DN(constructedDN),
         new DN("a=1+b=2+c=3+d=4,dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the {@code constructDN} with the following
   * conditions:
   * <UL>
   *   <LI>Multiple RDN fields with one missing value.</LI>
   *   <LI>Multiple RDN getters with valid values.</LI>
   *   <LI>No existing DN field value.</LI>
   *   <LI>No existing entry field value.</LI>
   *   <LI>Explicitly-provided parent DN.</LI>
   * </UL>
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testConstructDN8()
         throws Exception
  {
    LDAPObjectHandler<TestMinimalObjectMultipleRDNs> handler =
         new LDAPObjectHandler<TestMinimalObjectMultipleRDNs>(
              TestMinimalObjectMultipleRDNs.class);

    TestMinimalObjectMultipleRDNs o = new TestMinimalObjectMultipleRDNs();
    o.b = "2";
    o.c = "3";
    o.d = "4";

    HashMap<String,Attribute> attrMap = new HashMap<String,Attribute>();
    attrMap.put("b", new Attribute("b", "2"));
    attrMap.put("c", new Attribute("c", "3"));
    attrMap.put("d", new Attribute("d", "4"));

    handler.constructDN(o, "dc=example,dc=com", attrMap);
  }



  /**
   * Provides test coverage for the {@code constructDN} with the following
   * conditions:
   * <UL>
   *   <LI>Multiple RDN fields with valid values.</LI>
   *   <LI>Multiple RDN getters with one missing value.</LI>
   *   <LI>No existing DN field value.</LI>
   *   <LI>No existing entry field value.</LI>
   *   <LI>Explicitly-provided parent DN.</LI>
   * </UL>
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testConstructDN9()
         throws Exception
  {
    LDAPObjectHandler<TestMinimalObjectMultipleRDNs> handler =
         new LDAPObjectHandler<TestMinimalObjectMultipleRDNs>(
              TestMinimalObjectMultipleRDNs.class);

    TestMinimalObjectMultipleRDNs o = new TestMinimalObjectMultipleRDNs();
    o.a = "1";
    o.b = "2";
    o.c = "3";

    HashMap<String,Attribute> attrMap = new HashMap<String,Attribute>();
    attrMap.put("a", new Attribute("a", "1"));
    attrMap.put("b", new Attribute("b", "2"));
    attrMap.put("c", new Attribute("c", "3"));

    handler.constructDN(o, "dc=example,dc=com", attrMap);
  }



  /**
   * Provides test coverage for the {@code constructDN} with the following
   * conditions:
   * <UL>
   *   <LI>No attribute map.</LI>
   *   <LI>All RDN fields and getters populated.</LI>
   *   <LI>No existing DN field value.</LI>
   * </UL>
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructDN10()
         throws Exception
  {
    final LDAPObjectHandler<TestMinimalObjectMultipleRDNs> handler =
         new LDAPObjectHandler<TestMinimalObjectMultipleRDNs>(
              TestMinimalObjectMultipleRDNs.class);

    final TestMinimalObjectMultipleRDNs o = new TestMinimalObjectMultipleRDNs();
    o.a  = "1";
    o.b  = "2";
    o.c  = "3";
    o.d  = "4";
    o.dn = null;

    final String dn = handler.constructDN(o, "dc=example,dc=com");
    assertNotNull(dn);
    assertTrue(DN.equals(dn, "a=1+b=2+c=3+d=4,dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the {@code constructDN} with the following
   * conditions:
   * <UL>
   *   <LI>No attribute map.</LI>
   *   <LI>All RDN fields and getters populated.</LI>
   *   <LI>An existing DN field value.</LI>
   * </UL>
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructDN11()
         throws Exception
  {
    final LDAPObjectHandler<TestMinimalObjectMultipleRDNs> handler =
         new LDAPObjectHandler<TestMinimalObjectMultipleRDNs>(
              TestMinimalObjectMultipleRDNs.class);

    final TestMinimalObjectMultipleRDNs o = new TestMinimalObjectMultipleRDNs();
    o.a  = "1";
    o.b  = "2";
    o.c  = "3";
    o.d  = "4";
    o.dn = "a=1+b=2+c=3+d=4,o=foo";

    final String dn = handler.constructDN(o, "dc=example,dc=com");
    assertNotNull(dn);
    assertTrue(DN.equals(dn, "a=1+b=2+c=3+d=4,o=foo"));
  }



  /**
   * Provides test coverage for the {@code constructDN} with the following
   * conditions:
   * <UL>
   *   <LI>No attribute map.</LI>
   *   <LI>No existing DN field value.</LI>
   *   <LI>Missing an RDN field value.</LI>
   * </UL>
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testConstructDN12()
         throws Exception
  {
    final LDAPObjectHandler<TestMinimalObjectMultipleRDNs> handler =
         new LDAPObjectHandler<TestMinimalObjectMultipleRDNs>(
              TestMinimalObjectMultipleRDNs.class);

    final TestMinimalObjectMultipleRDNs o = new TestMinimalObjectMultipleRDNs();
    o.a  = null;
    o.b  = "2";
    o.c  = "3";
    o.d  = "4";
    o.dn = null;

    handler.constructDN(o, "dc=example,dc=com");
  }



  /**
   * Provides test coverage for the {@code constructDN} with the following
   * conditions:
   * <UL>
   *   <LI>No attribute map.</LI>
   *   <LI>No existing DN field value.</LI>
   *   <LI>Missing an RDN getter value.</LI>
   * </UL>
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testConstructDN13()
         throws Exception
  {
    final LDAPObjectHandler<TestMinimalObjectMultipleRDNs> handler =
         new LDAPObjectHandler<TestMinimalObjectMultipleRDNs>(
              TestMinimalObjectMultipleRDNs.class);

    final TestMinimalObjectMultipleRDNs o = new TestMinimalObjectMultipleRDNs();
    o.a  = "1";
    o.b  = "2";
    o.c  = null;
    o.d  = "4";
    o.dn = null;

    handler.constructDN(o, "dc=example,dc=com");
  }



  /**
   * Provides test coverage for the {@code getModifications} method with a basic
   * object that hasn't changed since it was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetModificationsWithoutChanges()
         throws Exception
  {
    Entry e = new Entry(
         "dn: a=1,dc=example,dc=com",
         "objectClass: top",
         "objectClass: x",
         "objectClass: y",
         "objectClass: z",
         "a: 1",
         "b: 2",
         "c: 3",
         "e: 5",
         "m: 13",
         "n: 14");

    LDAPObjectHandler<TestBasicObject> handler =
         new LDAPObjectHandler<TestBasicObject>(TestBasicObject.class);
    TestBasicObject o = handler.decode(e);

    List<Modification> mods = handler.getModifications(o, true, false);
    assertTrue(mods.isEmpty());

    o.setEntry(null);
    mods = handler.getModifications(o, true, false);
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 8);
    assertEquals(mods.get(0),
         new Modification(ModificationType.REPLACE, "b", "2"));
    assertEquals(mods.get(1),
         new Modification(ModificationType.REPLACE, "c", "3"));
    assertEquals(mods.get(2),
         new Modification(ModificationType.REPLACE, "e", "5"));
    assertEquals(mods.get(3),
         new Modification(ModificationType.REPLACE, "m", "13"));
    assertEquals(mods.get(4),
         new Modification(ModificationType.REPLACE, "n", "14"));
    assertEquals(mods.get(5),
         new Modification(ModificationType.REPLACE, "p"));
    assertEquals(mods.get(6),
         new Modification(ModificationType.REPLACE, "q"));
    assertEquals(mods.get(7),
         new Modification(ModificationType.REPLACE, "rs"));

    o.setEntry(null);
    mods = handler.getModifications(o, false, false);
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 5);
    assertEquals(mods.get(0),
         new Modification(ModificationType.REPLACE, "b", "2"));
    assertEquals(mods.get(1),
         new Modification(ModificationType.REPLACE, "c", "3"));
    assertEquals(mods.get(2),
         new Modification(ModificationType.REPLACE, "e", "5"));
    assertEquals(mods.get(3),
         new Modification(ModificationType.REPLACE, "m", "13"));
    assertEquals(mods.get(4),
         new Modification(ModificationType.REPLACE, "n", "14"));

    mods = handler.getModifications(o, true, false, "a");
    assertTrue(mods.isEmpty());
  }



  /**
   * Provides test coverage for the {@code getModifications} method with a basic
   * object that has been altered since it was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetModificationsWithChanges()
         throws Exception
  {
    Entry e = new Entry(
         "dn: a=1,dc=example,dc=com",
         "objectClass: top",
         "objectClass: x",
         "objectClass: y",
         "objectClass: z",
         "a: 1",
         "b: 2",
         "c: 3",
         "e: 5",
         "m: 13",
         "n: 14");

    LDAPObjectHandler<TestBasicObject> handler =
         new LDAPObjectHandler<TestBasicObject>(TestBasicObject.class);
    TestBasicObject o = handler.decode(e);

    o.setB("foo");
    o.setM("bar");

    List<Modification> mods = handler.getModifications(o, true, false);
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 2);
    assertEquals(mods.get(0),
         new Modification(ModificationType.REPLACE, "b", "foo"));
    assertEquals(mods.get(1),
         new Modification(ModificationType.REPLACE, "m", "bar"));

    mods = handler.getModifications(o, true, false, "b");
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 1);
    assertEquals(mods.get(0),
         new Modification(ModificationType.REPLACE, "b", "foo"));

    o.setEntry(null);
    mods = handler.getModifications(o, true, false);
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 8);
    assertEquals(mods.get(0),
         new Modification(ModificationType.REPLACE, "b", "foo"));
    assertEquals(mods.get(1),
         new Modification(ModificationType.REPLACE, "c", "3"));
    assertEquals(mods.get(2),
         new Modification(ModificationType.REPLACE, "e", "5"));
    assertEquals(mods.get(3),
         new Modification(ModificationType.REPLACE, "m", "bar"));
    assertEquals(mods.get(4),
         new Modification(ModificationType.REPLACE, "n", "14"));
    assertEquals(mods.get(5),
         new Modification(ModificationType.REPLACE, "p"));
    assertEquals(mods.get(6),
         new Modification(ModificationType.REPLACE, "q"));
    assertEquals(mods.get(7),
         new Modification(ModificationType.REPLACE, "rs"));

    mods = handler.getModifications(o, true, false, "b");
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 1);
    assertEquals(mods.get(0),
         new Modification(ModificationType.REPLACE, "b", "foo"));
  }



  /**
   * Provides test coverage for the {@code getModifications} method with a basic
   * object that has been altered to remove values since it was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetModificationsWithRemovals()
         throws Exception
  {
    Entry e = new Entry(
         "dn: a=1,dc=example,dc=com",
         "objectClass: top",
         "objectClass: x",
         "objectClass: y",
         "objectClass: z",
         "a: 1",
         "b: 2",
         "c: 3",
         "e: 5",
         "m: 13",
         "n: 14");

    LDAPObjectHandler<TestBasicObject> handler =
         new LDAPObjectHandler<TestBasicObject>(TestBasicObject.class);
    TestBasicObject o = handler.decode(e);

    o.setB(null);
    o.setM(null);

    List<Modification> mods = handler.getModifications(o, true, false);
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 2);
    assertEquals(mods.get(0),
         new Modification(ModificationType.REPLACE, "b"));
    assertEquals(mods.get(1),
         new Modification(ModificationType.REPLACE, "m"));

    mods = handler.getModifications(o, true, false, "b");
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 1);
    assertEquals(mods.get(0),
         new Modification(ModificationType.REPLACE, "b"));

    mods = handler.getModifications(o, false, false);
    assertTrue(mods.isEmpty());

    mods = handler.getModifications(o, false, false, "b");
    assertTrue(mods.isEmpty());

    o.setEntry(null);
    mods = handler.getModifications(o, true, false);
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 8);
    assertEquals(mods.get(0),
         new Modification(ModificationType.REPLACE, "b"));
    assertEquals(mods.get(1),
         new Modification(ModificationType.REPLACE, "c", "3"));
    assertEquals(mods.get(2),
         new Modification(ModificationType.REPLACE, "e", "5"));
    assertEquals(mods.get(3),
         new Modification(ModificationType.REPLACE, "m"));
    assertEquals(mods.get(4),
         new Modification(ModificationType.REPLACE, "n", "14"));
    assertEquals(mods.get(5),
         new Modification(ModificationType.REPLACE, "p"));
    assertEquals(mods.get(6),
         new Modification(ModificationType.REPLACE, "q"));
    assertEquals(mods.get(7),
         new Modification(ModificationType.REPLACE, "rs"));

    mods = handler.getModifications(o, true, false, "b");
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 1);
    assertEquals(mods.get(0),
         new Modification(ModificationType.REPLACE, "b"));

    mods = handler.getModifications(o, false, false);
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 3);
    assertEquals(mods.get(0),
         new Modification(ModificationType.REPLACE, "c", "3"));
    assertEquals(mods.get(1),
         new Modification(ModificationType.REPLACE, "e", "5"));
    assertEquals(mods.get(2),
         new Modification(ModificationType.REPLACE, "n", "14"));

    mods = handler.getModifications(o, false, false, "b");
    assertTrue(mods.isEmpty());
  }



  /**
   * Provides test coverage for the {@code getModifications} method with a basic
   * object that was originally missing some attributes and has been altered to
   * remove values since it was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetModificationsWithRemovalsAndMissingAttributes()
         throws Exception
  {
    Entry e = new Entry(
         "dn: a=1,dc=example,dc=com",
         "objectClass: top",
         "objectClass: x",
         "objectClass: y",
         "objectClass: z",
         "a: 1",
         "c: 3",
         "e: 5",
         "m: 13");

    LDAPObjectHandler<TestBasicObject> handler =
         new LDAPObjectHandler<TestBasicObject>(TestBasicObject.class);
    TestBasicObject o = handler.decode(e);

    o.setE(null);
    o.setM(null);
    o.setP("foo");

    List<Modification> mods = handler.getModifications(o, true, false);
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 3);
    assertEquals(mods.get(0),
         new Modification(ModificationType.REPLACE, "e"));
    assertEquals(mods.get(1),
         new Modification(ModificationType.REPLACE, "m"));
    assertEquals(mods.get(2),
         new Modification(ModificationType.REPLACE, "p", "foo"));

    mods = handler.getModifications(o, true, false, "b", "e", "n", "p");
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 2);
    assertEquals(mods.get(0),
         new Modification(ModificationType.REPLACE, "e"));
    assertEquals(mods.get(1),
         new Modification(ModificationType.REPLACE, "p", "foo"));

    mods = handler.getModifications(o, false, false);
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 1);
    assertEquals(mods.get(0),
         new Modification(ModificationType.REPLACE, "p", "foo"));

    o.setEntry(null);
    mods = handler.getModifications(o, true, false);
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 8);
    assertEquals(mods.get(0),
         new Modification(ModificationType.REPLACE, "b"));
    assertEquals(mods.get(1),
         new Modification(ModificationType.REPLACE, "c", "3"));
    assertEquals(mods.get(2),
         new Modification(ModificationType.REPLACE, "e"));
    assertEquals(mods.get(3),
         new Modification(ModificationType.REPLACE, "m"));
    assertEquals(mods.get(4),
         new Modification(ModificationType.REPLACE, "n"));
    assertEquals(mods.get(5),
         new Modification(ModificationType.REPLACE, "p", "foo"));
    assertEquals(mods.get(6),
         new Modification(ModificationType.REPLACE, "q"));
    assertEquals(mods.get(7),
         new Modification(ModificationType.REPLACE, "rs"));

    mods = handler.getModifications(o, false, false);
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 2);
    assertEquals(mods.get(0),
         new Modification(ModificationType.REPLACE, "c", "3"));
    assertEquals(mods.get(1),
         new Modification(ModificationType.REPLACE, "p", "foo"));

    mods = handler.getModifications(o, true, false, "b");
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 1);
    assertEquals(mods.get(0),
         new Modification(ModificationType.REPLACE, "b"));

    mods = handler.getModifications(o, false, false, "b");
    assertTrue(mods.isEmpty());
  }



  /**
   * Provides test coverage for the {@code getModifications} method with an
   * object containing only RDN fields and getters, and no entry field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetModificationsWithOnlyRDNsAndNoEntryField()
         throws Exception
  {
    Entry e = new Entry(
         "dn: a=1+b=2+c=3+d=4,dc=example,dc=com",
         "objectClass: top",
         "objectClass: TestMinimalObjectMultipleRDNs",
         "a: 1",
         "b: 2",
         "c: 3",
         "d: 4");

    LDAPObjectHandler<TestMinimalObjectMultipleRDNs> handler =
         new LDAPObjectHandler<TestMinimalObjectMultipleRDNs>(
              TestMinimalObjectMultipleRDNs.class);
    TestMinimalObjectMultipleRDNs o = handler.decode(e);

    assertTrue(handler.getModifications(o, true, false).isEmpty());
  }



  /**
   * Provides test coverage for the {@code createFilter} method with an object
   * that doesn't contain any filter fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateFilterNoFilterFields()
         throws Exception
  {
    TestMinimalObjectMultipleRDNs o = new TestMinimalObjectMultipleRDNs();

    LDAPObjectHandler<TestMinimalObjectMultipleRDNs> handler =
         new LDAPObjectHandler<TestMinimalObjectMultipleRDNs>(
              TestMinimalObjectMultipleRDNs.class);

    handler.createFilter(o);
  }



  /**
   * Provides test coverage for the {@code createFilter} method with an object
   * that has filter fields with all empty values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testCreateFilterAllFilterFieldsEmpty()
         throws Exception
  {
    TestBasicObject o = new TestBasicObject();

    LDAPObjectHandler<TestBasicObject> handler =
         new LDAPObjectHandler<TestBasicObject>(TestBasicObject.class);

    handler.createFilter(o);
  }



  /**
   * Provides test coverage for the {@code createFilter} method with an object
   * that has filter fields that are all populated.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateFilterAllFilterFieldsPopulated()
         throws Exception
  {
    TestBasicObject o = new TestBasicObject();
    o.setA("1");
    o.setB("2");
    o.setM("3");
    o.setN("4");

    LDAPObjectHandler<TestBasicObject> handler =
         new LDAPObjectHandler<TestBasicObject>(TestBasicObject.class);

    Filter f = handler.createFilter(o);
    assertNotNull(f);
    assertEquals(f, Filter.create("(&(objectClass=x)(objectClass=y)" +
         "(objectClass=z)(a=1)(b=2)(m=3)(n=4))"));
  }
}
