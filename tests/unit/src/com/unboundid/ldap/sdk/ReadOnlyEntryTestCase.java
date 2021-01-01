/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.util.Arrays;

import org.testng.annotations.Test;



/**
 * Provides a set of test cases for the ReadOnlyEntry class.
 */
public class ReadOnlyEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the first constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry("dc=example,dc=com",
                                        new Attribute("foo", "bar"));

    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertTrue(e.hasAttribute("foo"));
    assertEquals(e.getAttributeValue("foo"), "bar");
  }



  /**
   * Provides test coverage for the second constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(new DN("dc=example,dc=com"),
                                        new Attribute("foo", "bar"));

    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertTrue(e.hasAttribute("foo"));
    assertEquals(e.getAttributeValue("foo"), "bar");
  }



  /**
   * Provides test coverage for the third constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    ReadOnlyEntry e =
         new ReadOnlyEntry("dc=example,dc=com",
                           Arrays.asList(new Attribute("foo", "bar")));

    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertTrue(e.hasAttribute("foo"));
    assertEquals(e.getAttributeValue("foo"), "bar");
  }



  /**
   * Provides test coverage for the fourth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4()
         throws Exception
  {
    ReadOnlyEntry e =
         new ReadOnlyEntry(new DN("dc=example,dc=com"),
                           Arrays.asList(new Attribute("foo", "bar")));

    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertTrue(e.hasAttribute("foo"));
    assertEquals(e.getAttributeValue("foo"), "bar");
  }



  /**
   * Provides test coverage for the fifth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5()
         throws Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertTrue(e.hasAttribute("dc"));
    assertEquals(e.getAttributeValue("dc"), "example");
  }



  /**
   * Provides test coverage for the sixth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6()
         throws Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertTrue(e.hasAttribute("dc"));
    assertEquals(e.getAttributeValue("dc"), "example");
  }



  /**
   * Tests the {@code setDN} method that takes a DN string to ensure that it
   * throws an {@code UnsupportedOperationException}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { UnsupportedOperationException.class })
  public void testSetDNString()
         throws Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(new DN("dc=example,dc=com"));
    e.setDN("o=example.com");
  }



  /**
   * Tests the {@code setDN} method that takes a DN object to ensure that it
   * throws an {@code UnsupportedOperationException}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { UnsupportedOperationException.class })
  public void testSetDNObject()
         throws  Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(new DN("dc=example,dc=com"));
    e.setDN(new DN("o=example.com"));
  }



  /**
   * Tests the {@code addAttribute} method that takes an attribute object to
   * ensure that it throws an {@code UnsupportedOperationException}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { UnsupportedOperationException.class })
  public void testAddAttributeObject()
         throws  Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(new DN("dc=example,dc=com"));
    e.addAttribute(new Attribute("description", "foo"));
  }



  /**
   * Tests the {@code addAttribute} method that takes an string name and string
   * value to ensure that it throws an {@code UnsupportedOperationException}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { UnsupportedOperationException.class })
  public void testAddAttributeStringNameStringValue()
         throws  Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(new DN("dc=example,dc=com"));
    e.addAttribute("description", "foo");
  }



  /**
   * Tests the {@code addAttribute} method that takes an string name and byte
   * array value to ensure that it throws an
   * {@code UnsupportedOperationException}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { UnsupportedOperationException.class })
  public void testAddAttributeStringNameByteArrayValue()
         throws  Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(new DN("dc=example,dc=com"));
    e.addAttribute("description", "foo".getBytes("UTF-8"));
  }



  /**
   * Tests the {@code addAttribute} method that takes an string name and
   * multiple string values to ensure that it throws an
   * {@code UnsupportedOperationException}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { UnsupportedOperationException.class })
  public void testAddAttributeStringNameStringValues()
         throws  Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(new DN("dc=example,dc=com"));
    e.addAttribute("description", "foo", "bar", "baz");
  }



  /**
   * Tests the {@code addAttribute} method that takes an string name and
   * multiple byte array values to ensure that it throws an
   * {@code UnsupportedOperationException}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { UnsupportedOperationException.class })
  public void testAddAttributeStringNameByteArrayValues()
         throws  Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(new DN("dc=example,dc=com"));
    e.addAttribute("description", "foo".getBytes("UTF-8"),
                   "bar".getBytes("UTF-8"), "baz".getBytes("UTF-8"));
  }



  /**
   * Tests the {@code removedAttribute} method that takes a string name to
   * ensure that it throws an {@code UnsupportedOperationException}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { UnsupportedOperationException.class })
  public void testRemoveAttributeStringName()
         throws  Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(new DN("dc=example,dc=com"));
    e.removeAttribute("dc");
  }



  /**
   * Tests the {@code removedAttribute} method that takes a string name and
   * string value to ensure that it throws an
   * {@code UnsupportedOperationException}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { UnsupportedOperationException.class })
  public void testRemoveAttributeValueStringNameStringValue()
         throws  Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(new DN("dc=example,dc=com"));
    e.removeAttributeValue("dc", "example");
  }



  /**
   * Tests the {@code removedAttribute} method that takes a string name and
   * byte array value to ensure that it throws an
   * {@code UnsupportedOperationException}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { UnsupportedOperationException.class })
  public void testRemoveAttributeValueStringNameByteArrayValue()
         throws  Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(new DN("dc=example,dc=com"));
    e.removeAttributeValue("dc", "example".getBytes("UTF-8"));
  }



  /**
   * Tests the {@code removedAttribute} method that takes a string name and
   * string value to ensure that it throws an
   * {@code UnsupportedOperationException}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { UnsupportedOperationException.class })
  public void testRemoveAttributeValuesStringNameStringValues()
         throws  Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(new DN("dc=example,dc=com"));
    e.removeAttributeValues("dc", "foo", "bar");
  }



  /**
   * Tests the {@code removedAttribute} method that takes a string name and
   * byte array value to ensure that it throws an
   * {@code UnsupportedOperationException}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { UnsupportedOperationException.class })
  public void testRemoveAttributeValuesStringNameByteArrayValues()
         throws  Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(new DN("dc=example,dc=com"));
    e.removeAttributeValues("dc", "foo".getBytes("UTF-8"),
                            "bar".getBytes("UTF-8"));
  }



  /**
   * Tests the {@code setAttribte} method that takes an attribute object to
   * ensure that it throws an {@code UnsupportedOperationException}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { UnsupportedOperationException.class })
  public void testSetAttributeObject()
         throws  Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(new DN("dc=example,dc=com"));
    e.setAttribute(new Attribute("description", "foo"));
  }



  /**
   * Tests the {@code setAttribte} method that takes a string name and string
   * value to ensure that it throws an {@code UnsupportedOperationException}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { UnsupportedOperationException.class })
  public void testSetAttributeStringNameStringValue()
         throws  Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(new DN("dc=example,dc=com"));
    e.setAttribute("description", "foo");
  }



  /**
   * Tests the {@code setAttribte} method that takes a string name and byte
   * array value to ensure that it throws an
   * {@code UnsupportedOperationException}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { UnsupportedOperationException.class })
  public void testSetAttributeStringNameByteArrayValue()
         throws  Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(new DN("dc=example,dc=com"));
    e.setAttribute("description", "foo".getBytes("UTF-8"));
  }



  /**
   * Tests the {@code setAttribte} method that takes a string name and multiple
   * string values to ensure that it throws an
   * {@code UnsupportedOperationException}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { UnsupportedOperationException.class })
  public void testSetAttributeStringNameStringValues()
         throws  Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(new DN("dc=example,dc=com"));
    e.setAttribute("description", "foo", "bar", "baz");
  }



  /**
   * Tests the {@code setAttribte} method that takes a string name and multiple
   * byte array values to ensure that it throws an
   * {@code UnsupportedOperationException}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { UnsupportedOperationException.class })
  public void testSetAttributeStringNameByteArrayValues()
         throws  Exception
  {
    ReadOnlyEntry e = new ReadOnlyEntry(new DN("dc=example,dc=com"));
    e.setAttribute("description", "foo".getBytes("UTF-8"),
                   "bar".getBytes("UTF-8"), "baz".getBytes("UTF-8"));
  }
}
