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
import java.util.Enumeration;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the {@code LDAPAttribute} class.
 */
public class LDAPAttributeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with an attribute created from an SDK attribute with
   * just a name and no values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithSDKAttributeWithName()
         throws Exception
  {
    LDAPAttribute a = new LDAPAttribute(new Attribute("foo"));

    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertNotNull(a.getBaseName());
    assertEquals(a.getBaseName(), "foo");

    assertNull(a.getSubtypes());

    assertNull(a.getLangSubtype());

    assertFalse(a.hasSubtype("binary"));

    assertFalse(a.hasSubtypes(new String[] { "binary" }));

    assertNotNull(a.getStringValues());
    assertFalse(a.getStringValues().hasMoreElements());

    assertNotNull(a.getStringValueArray());
    assertEquals(a.getStringValueArray().length, 0);

    assertNotNull(a.getByteValues());
    assertFalse(a.getByteValues().hasMoreElements());

    assertNotNull(a.getByteValueArray());
    assertEquals(a.getByteValueArray().length, 0);

    assertEquals(a.size(), 0);

    Attribute attr = a.toAttribute();
    assertEquals(attr.getName(), "foo");
    assertFalse(attr.hasValue());

    assertNotNull(a.toString());
  }



  /**
   * Tests the behavior with an attribute created from an SDK attribute with a
   * name and a single string value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithSDKattributeWithNameAndStringValue()
         throws Exception
  {
    LDAPAttribute a = new LDAPAttribute(new Attribute("foo", "bar"));

    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertNotNull(a.getBaseName());
    assertEquals(a.getBaseName(), "foo");

    assertNull(a.getSubtypes());

    assertNull(a.getLangSubtype());

    assertFalse(a.hasSubtype("binary"));

    assertFalse(a.hasSubtypes(new String[] { "binary" }));

    Enumeration<String> stringValues = a.getStringValues();
    assertNotNull(stringValues);
    assertTrue(stringValues.hasMoreElements());
    assertEquals(stringValues.nextElement(), "bar");
    assertFalse(stringValues.hasMoreElements());

    assertNotNull(a.getStringValueArray());
    assertEquals(a.getStringValueArray().length, 1);

    Enumeration<byte[]> byteValues = a.getByteValues();
    assertNotNull(byteValues);
    assertTrue(byteValues.hasMoreElements());
    assertTrue(Arrays.equals(byteValues.nextElement(), "bar".getBytes()));
    assertFalse(byteValues.hasMoreElements());

    assertNotNull(a.getByteValueArray());
    assertEquals(a.getByteValueArray().length, 1);

    assertEquals(a.size(), 1);

    Attribute attr = a.toAttribute();
    assertEquals(attr.getName(), "foo");
    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("bar"));

    assertNotNull(a.toString());
  }



  /**
   * Tests the behavior with an attribute created from an SDK attribute with a
   * name and a single binary value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithSDKAttributeWithNameAndBinaryValue()
         throws Exception
  {
    LDAPAttribute a = new LDAPAttribute(new Attribute("foo", "bar".getBytes()));

    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertNotNull(a.getBaseName());
    assertEquals(a.getBaseName(), "foo");

    assertNull(a.getSubtypes());

    assertNull(a.getLangSubtype());

    assertFalse(a.hasSubtype("binary"));

    assertFalse(a.hasSubtypes(new String[] { "binary" }));

    Enumeration<String> stringValues = a.getStringValues();
    assertNotNull(stringValues);
    assertTrue(stringValues.hasMoreElements());
    assertEquals(stringValues.nextElement(), "bar");
    assertFalse(stringValues.hasMoreElements());

    assertNotNull(a.getStringValueArray());
    assertEquals(a.getStringValueArray().length, 1);

    Enumeration<byte[]> byteValues = a.getByteValues();
    assertNotNull(byteValues);
    assertTrue(byteValues.hasMoreElements());
    assertTrue(Arrays.equals(byteValues.nextElement(), "bar".getBytes()));
    assertFalse(byteValues.hasMoreElements());

    assertNotNull(a.getByteValueArray());
    assertEquals(a.getByteValueArray().length, 1);

    assertEquals(a.size(), 1);

    Attribute attr = a.toAttribute();
    assertEquals(attr.getName(), "foo");
    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("bar"));

    assertNotNull(a.toString());
  }



  /**
   * Tests the behavior with an attribute created from an SDK attribute with a
   * name and multiple string values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithSDKAttributeWithNameAndStringValues()
         throws Exception
  {
    LDAPAttribute a = new LDAPAttribute(new Attribute("foo", "bar", "baz"));

    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertNotNull(a.getBaseName());
    assertEquals(a.getBaseName(), "foo");

    assertNull(a.getSubtypes());

    assertNull(a.getLangSubtype());

    assertFalse(a.hasSubtype("binary"));

    assertFalse(a.hasSubtypes(new String[] { "binary" }));

    Enumeration<String> stringValues = a.getStringValues();
    assertNotNull(stringValues);
    assertTrue(stringValues.hasMoreElements());
    assertEquals(stringValues.nextElement(), "bar");
    assertTrue(stringValues.hasMoreElements());
    assertEquals(stringValues.nextElement(), "baz");
    assertFalse(stringValues.hasMoreElements());

    assertNotNull(a.getStringValueArray());
    assertEquals(a.getStringValueArray().length, 2);

    Enumeration<byte[]> byteValues = a.getByteValues();
    assertNotNull(byteValues);
    assertTrue(byteValues.hasMoreElements());
    assertTrue(Arrays.equals(byteValues.nextElement(), "bar".getBytes()));
    assertTrue(byteValues.hasMoreElements());
    assertTrue(Arrays.equals(byteValues.nextElement(), "baz".getBytes()));
    assertFalse(byteValues.hasMoreElements());

    assertNotNull(a.getByteValueArray());
    assertEquals(a.getByteValueArray().length, 2);

    assertEquals(a.size(), 2);

    Attribute attr = a.toAttribute();
    assertEquals(attr.getName(), "foo");
    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("bar"));
    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("baz"));

    assertNotNull(a.toString());
  }



  /**
   * Tests the behavior with an attribute created from an LDAP attribute with
   * just a name and no values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithLDAPAttributeWithName()
         throws Exception
  {
    LDAPAttribute a = new LDAPAttribute(new LDAPAttribute("foo"));

    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertNotNull(a.getBaseName());
    assertEquals(a.getBaseName(), "foo");

    assertNull(a.getSubtypes());

    assertNull(a.getLangSubtype());

    assertFalse(a.hasSubtype("binary"));

    assertFalse(a.hasSubtypes(new String[] { "binary" }));

    assertNotNull(a.getStringValues());
    assertFalse(a.getStringValues().hasMoreElements());

    assertNotNull(a.getStringValueArray());
    assertEquals(a.getStringValueArray().length, 0);

    assertNotNull(a.getByteValues());
    assertFalse(a.getByteValues().hasMoreElements());

    assertNotNull(a.getByteValueArray());
    assertEquals(a.getByteValueArray().length, 0);

    assertEquals(a.size(), 0);

    Attribute attr = a.toAttribute();
    assertEquals(attr.getName(), "foo");
    assertFalse(attr.hasValue());

    assertNotNull(a.toString());
  }



  /**
   * Tests the behavior with an attribute created from an LDAP attribute with a
   * name and a single string value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithLDAPattributeWithNameAndStringValue()
         throws Exception
  {
    LDAPAttribute a = new LDAPAttribute(new LDAPAttribute("foo", "bar"));

    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertNotNull(a.getBaseName());
    assertEquals(a.getBaseName(), "foo");

    assertNull(a.getSubtypes());

    assertNull(a.getLangSubtype());

    assertFalse(a.hasSubtype("binary"));

    assertFalse(a.hasSubtypes(new String[] { "binary" }));

    Enumeration<String> stringValues = a.getStringValues();
    assertNotNull(stringValues);
    assertTrue(stringValues.hasMoreElements());
    assertEquals(stringValues.nextElement(), "bar");
    assertFalse(stringValues.hasMoreElements());

    assertNotNull(a.getStringValueArray());
    assertEquals(a.getStringValueArray().length, 1);

    Enumeration<byte[]> byteValues = a.getByteValues();
    assertNotNull(byteValues);
    assertTrue(byteValues.hasMoreElements());
    assertTrue(Arrays.equals(byteValues.nextElement(), "bar".getBytes()));
    assertFalse(byteValues.hasMoreElements());

    assertNotNull(a.getByteValueArray());
    assertEquals(a.getByteValueArray().length, 1);

    assertEquals(a.size(), 1);

    Attribute attr = a.toAttribute();
    assertEquals(attr.getName(), "foo");
    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("bar"));

    assertNotNull(a.toString());
  }



  /**
   * Tests the behavior with an attribute created from an LDAP attribute with a
   * name and a single binary value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithLDAPAttributeWithNameAndBinaryValue()
         throws Exception
  {
    LDAPAttribute a =
         new LDAPAttribute(new LDAPAttribute("foo", "bar".getBytes()));

    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertNotNull(a.getBaseName());
    assertEquals(a.getBaseName(), "foo");

    assertNull(a.getSubtypes());

    assertNull(a.getLangSubtype());

    assertFalse(a.hasSubtype("binary"));

    assertFalse(a.hasSubtypes(new String[] { "binary" }));

    Enumeration<String> stringValues = a.getStringValues();
    assertNotNull(stringValues);
    assertTrue(stringValues.hasMoreElements());
    assertEquals(stringValues.nextElement(), "bar");
    assertFalse(stringValues.hasMoreElements());

    assertNotNull(a.getStringValueArray());
    assertEquals(a.getStringValueArray().length, 1);

    Enumeration<byte[]> byteValues = a.getByteValues();
    assertNotNull(byteValues);
    assertTrue(byteValues.hasMoreElements());
    assertTrue(Arrays.equals(byteValues.nextElement(), "bar".getBytes()));
    assertFalse(byteValues.hasMoreElements());

    assertNotNull(a.getByteValueArray());
    assertEquals(a.getByteValueArray().length, 1);

    assertEquals(a.size(), 1);

    Attribute attr = a.toAttribute();
    assertEquals(attr.getName(), "foo");
    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("bar"));

    assertNotNull(a.toString());
  }



  /**
   * Tests the behavior with an attribute created from an LDAP attribute with a
   * name and multiple string values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithLDAPAttributeWithNameAndStringValues()
         throws Exception
  {
    LDAPAttribute a = new LDAPAttribute(
         new LDAPAttribute("foo", new String[] { "bar", "baz" }));

    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertNotNull(a.getBaseName());
    assertEquals(a.getBaseName(), "foo");

    assertNull(a.getSubtypes());

    assertNull(a.getLangSubtype());

    assertFalse(a.hasSubtype("binary"));

    assertFalse(a.hasSubtypes(new String[] { "binary" }));

    Enumeration<String> stringValues = a.getStringValues();
    assertNotNull(stringValues);
    assertTrue(stringValues.hasMoreElements());
    assertEquals(stringValues.nextElement(), "bar");
    assertTrue(stringValues.hasMoreElements());
    assertEquals(stringValues.nextElement(), "baz");
    assertFalse(stringValues.hasMoreElements());

    assertNotNull(a.getStringValueArray());
    assertEquals(a.getStringValueArray().length, 2);

    Enumeration<byte[]> byteValues = a.getByteValues();
    assertNotNull(byteValues);
    assertTrue(byteValues.hasMoreElements());
    assertTrue(Arrays.equals(byteValues.nextElement(), "bar".getBytes()));
    assertTrue(byteValues.hasMoreElements());
    assertTrue(Arrays.equals(byteValues.nextElement(), "baz".getBytes()));
    assertFalse(byteValues.hasMoreElements());

    assertNotNull(a.getByteValueArray());
    assertEquals(a.getByteValueArray().length, 2);

    assertEquals(a.size(), 2);

    Attribute attr = a.toAttribute();
    assertEquals(attr.getName(), "foo");
    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("bar"));
    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("baz"));

    assertNotNull(a.toString());
  }



  /**
   * Tests the behavior with an attribute created with a name and no values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithName()
         throws Exception
  {
    LDAPAttribute a = new LDAPAttribute("foo");

    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertNotNull(a.getBaseName());
    assertEquals(a.getBaseName(), "foo");

    assertNull(a.getSubtypes());

    assertNull(a.getLangSubtype());

    assertFalse(a.hasSubtype("binary"));

    assertFalse(a.hasSubtypes(new String[] { "binary" }));

    assertNotNull(a.getStringValues());
    assertFalse(a.getStringValues().hasMoreElements());

    assertNotNull(a.getStringValueArray());
    assertEquals(a.getStringValueArray().length, 0);

    assertNotNull(a.getByteValues());
    assertFalse(a.getByteValues().hasMoreElements());

    assertNotNull(a.getByteValueArray());
    assertEquals(a.getByteValueArray().length, 0);

    assertEquals(a.size(), 0);

    Attribute attr = a.toAttribute();
    assertEquals(attr.getName(), "foo");
    assertFalse(attr.hasValue());

    assertNotNull(a.toString());
  }



  /**
   * Tests the behavior with an attribute created with a name a single string
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithNameAndStringValue()
         throws Exception
  {
    LDAPAttribute a = new LDAPAttribute("foo", "bar");

    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertNotNull(a.getBaseName());
    assertEquals(a.getBaseName(), "foo");

    assertNull(a.getSubtypes());

    assertNull(a.getLangSubtype());

    assertFalse(a.hasSubtype("binary"));

    assertFalse(a.hasSubtypes(new String[] { "binary" }));

    Enumeration<String> stringValues = a.getStringValues();
    assertNotNull(stringValues);
    assertTrue(stringValues.hasMoreElements());
    assertEquals(stringValues.nextElement(), "bar");
    assertFalse(stringValues.hasMoreElements());

    assertNotNull(a.getStringValueArray());
    assertEquals(a.getStringValueArray().length, 1);

    Enumeration<byte[]> byteValues = a.getByteValues();
    assertNotNull(byteValues);
    assertTrue(byteValues.hasMoreElements());
    assertTrue(Arrays.equals(byteValues.nextElement(), "bar".getBytes()));
    assertFalse(byteValues.hasMoreElements());

    assertNotNull(a.getByteValueArray());
    assertEquals(a.getByteValueArray().length, 1);

    assertEquals(a.size(), 1);

    Attribute attr = a.toAttribute();
    assertEquals(attr.getName(), "foo");
    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("bar"));

    assertNotNull(a.toString());
  }



  /**
   * Tests the behavior with an attribute created with a name a single binary
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithNameAndBinaryValue()
         throws Exception
  {
    LDAPAttribute a = new LDAPAttribute("foo", "bar".getBytes());

    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertNotNull(a.getBaseName());
    assertEquals(a.getBaseName(), "foo");

    assertNull(a.getSubtypes());

    assertNull(a.getLangSubtype());

    assertFalse(a.hasSubtype("binary"));

    assertFalse(a.hasSubtypes(new String[] { "binary" }));

    Enumeration<String> stringValues = a.getStringValues();
    assertNotNull(stringValues);
    assertTrue(stringValues.hasMoreElements());
    assertEquals(stringValues.nextElement(), "bar");
    assertFalse(stringValues.hasMoreElements());

    assertNotNull(a.getStringValueArray());
    assertEquals(a.getStringValueArray().length, 1);

    Enumeration<byte[]> byteValues = a.getByteValues();
    assertNotNull(byteValues);
    assertTrue(byteValues.hasMoreElements());
    assertTrue(Arrays.equals(byteValues.nextElement(), "bar".getBytes()));
    assertFalse(byteValues.hasMoreElements());

    assertNotNull(a.getByteValueArray());
    assertEquals(a.getByteValueArray().length, 1);

    assertEquals(a.size(), 1);

    Attribute attr = a.toAttribute();
    assertEquals(attr.getName(), "foo");
    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("bar"));

    assertNotNull(a.toString());
  }



  /**
   * Tests the behavior with an attribute created with a name a multiple string
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithNameAndStringValues()
         throws Exception
  {
    LDAPAttribute a = new LDAPAttribute("foo", new String[] { "bar", "baz", });

    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertNotNull(a.getBaseName());
    assertEquals(a.getBaseName(), "foo");

    assertNull(a.getSubtypes());

    assertNull(a.getLangSubtype());

    assertFalse(a.hasSubtype("binary"));

    assertFalse(a.hasSubtypes(new String[] { "binary" }));

    Enumeration<String> stringValues = a.getStringValues();
    assertNotNull(stringValues);
    assertTrue(stringValues.hasMoreElements());
    assertEquals(stringValues.nextElement(), "bar");
    assertTrue(stringValues.hasMoreElements());
    assertEquals(stringValues.nextElement(), "baz");
    assertFalse(stringValues.hasMoreElements());

    assertNotNull(a.getStringValueArray());
    assertEquals(a.getStringValueArray().length, 2);

    Enumeration<byte[]> byteValues = a.getByteValues();
    assertNotNull(byteValues);
    assertTrue(byteValues.hasMoreElements());
    assertTrue(Arrays.equals(byteValues.nextElement(), "bar".getBytes()));
    assertTrue(byteValues.hasMoreElements());
    assertTrue(Arrays.equals(byteValues.nextElement(), "baz".getBytes()));
    assertFalse(byteValues.hasMoreElements());

    assertNotNull(a.getByteValueArray());
    assertEquals(a.getByteValueArray().length, 2);

    assertEquals(a.size(), 2);

    Attribute attr = a.toAttribute();
    assertEquals(attr.getName(), "foo");
    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("bar"));
    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("baz"));

    assertNotNull(a.toString());
  }



  /**
   * Tests the behavior of an attribute name with options.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameWithOptions()
         throws Exception
  {
    LDAPAttribute a = new LDAPAttribute("a;b;c");

    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "a;b;c");

    assertNotNull(a.getBaseName());
    assertEquals(a.getBaseName(), "a");

    assertNotNull(LDAPAttribute.getBaseName("a"));
    assertEquals(LDAPAttribute.getBaseName("a"), "a");

    assertNotNull(LDAPAttribute.getBaseName("a;b;c"));
    assertEquals(LDAPAttribute.getBaseName("a;b;c"), "a");

    assertNotNull(a.getSubtypes());
    assertEquals(a.getSubtypes().length, 2);

    assertNull(LDAPAttribute.getSubtypes("a"));

    assertNotNull(LDAPAttribute.getSubtypes("a;b;c"));
    assertEquals(LDAPAttribute.getSubtypes("a;b;c").length, 2);

    assertTrue(a.hasSubtype("b"));
    assertTrue(a.hasSubtype("c"));
    assertFalse(a.hasSubtype("d"));

    assertTrue(a.hasSubtypes(new String[] { "b" }));
    assertTrue(a.hasSubtypes(new String[] { "c" }));
    assertTrue(a.hasSubtypes(new String[] { "b", "c" }));
    assertTrue(a.hasSubtypes(new String[] { "c", "b" }));
    assertFalse(a.hasSubtypes(new String[] { "d" }));
    assertFalse(a.hasSubtypes(new String[] { "b", "d" }));

    assertNull(a.getLangSubtype());

    a = new LDAPAttribute("a;b;c;lang-en-US");
    assertNotNull(a.getLangSubtype());
    assertEquals(a.getLangSubtype(), "lang-en-US");
  }



  /**
   * Tests the ability to add and remove values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddAndRemoveValues()
         throws Exception
  {
    LDAPAttribute a = new LDAPAttribute("a");

    assertNotNull(a);

    assertEquals(a.size(), 0);

    a.addValue("foo");
    assertEquals(a.size(), 1);

    a.addValue("foo");
    assertEquals(a.size(), 1);

    a.addValue("bar".getBytes());
    assertEquals(a.size(), 2);

    a.addValue("bar".getBytes());
    assertEquals(a.size(), 2);

    a.removeValue("foo");
    assertEquals(a.size(), 1);

    a.removeValue("foo");
    assertEquals(a.size(), 1);

    a.removeValue("bar".getBytes());
    assertEquals(a.size(), 0);

    a.removeValue("bar".getBytes());
    assertEquals(a.size(), 0);
  }
}
