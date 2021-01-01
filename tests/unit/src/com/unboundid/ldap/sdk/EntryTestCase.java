/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.matchingrules.CaseExactStringMatchingRule;
import com.unboundid.ldap.matchingrules.CaseIgnoreStringMatchingRule;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.LDAPSDKUsageException;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides a set of test cases for the Entry class.
 */
public class EntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor, which takes only a DN string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    Entry e = new Entry("dc=example,dc=com");
    e = e.duplicate();

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "dc=example,dc=com");
    assertEquals(e.getParentDN(), new DN("dc=com"));
    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertEquals(e.getRDN(), new RDN("dc=example"));
    assertEquals(new DN(e.getParentDNString()), new DN("dc=com"));

    assertFalse(e.hasAttribute("description"));
    assertFalse(e.hasAttribute(new Attribute("description", "foo")));
    assertFalse(e.hasAttributeValue("description", "foo"));
    assertFalse(e.hasAttributeValue("description", "foo".getBytes("UTF-8")));

    assertNull(e.getAttribute("description"));
    assertFalse(e.removeAttribute("description"));
    assertFalse(e.removeAttributeValue("description", "foo"));
    assertFalse(e.removeAttributeValue("description", "foo".getBytes("UTF-8")));

    assertNull(e.getAttributeValue("description"));

    assertNull(e.getAttributeValueBytes("description"));

    assertNull(e.getAttributeValues("description"));

    assertNull(e.getAttributeValueByteArrays("description"));

    assertNull(e.getObjectClassAttribute());
    assertNull(e.getObjectClassValues());

    Entry e2 = new Entry(new DN("dc=example,dc=com"));
    assertEquals(e, e2);
    assertEquals(e.hashCode(), e2.hashCode());

    assertNotNull(e.toLDIF(78));
    assertNotNull(e.toLDIFString(78));
    assertNotNull(e.toString());
  }



  /**
   * Tests the first constructor by providing a {@code null} DN string.
  */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1Null()
  {
    new Entry((String) null);
  }



  /**
   * Tests the second constructor, which takes only a DN object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    Entry e = new Entry(new DN("dc=example,dc=com"));
    e = e.duplicate();

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "dc=example,dc=com");
    assertEquals(new DN(e.getParentDNString()), new DN("dc=com"));
    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertEquals(e.getRDN(), new RDN("dc=example"));
    assertEquals(e.getParentDN(), new DN("dc=com"));

    assertFalse(e.hasAttribute("description"));
    assertFalse(e.hasAttribute(new Attribute("description", "foo")));
    assertFalse(e.hasAttributeValue("description", "foo"));
    assertFalse(e.hasAttributeValue("description", "foo".getBytes("UTF-8")));

    assertNull(e.getAttribute("description"));
    assertFalse(e.removeAttribute("description"));
    assertFalse(e.removeAttributeValue("description", "foo"));
    assertFalse(e.removeAttributeValue("description", "foo".getBytes("UTF-8")));

    assertNull(e.getAttributeValue("description"));

    assertNull(e.getAttributeValueBytes("description"));

    assertNull(e.getAttributeValues("description"));

    assertNull(e.getAttributeValueByteArrays("description"));

    assertNull(e.getObjectClassAttribute());
    assertNull(e.getObjectClassValues());

    Entry e2 = new Entry("dc=example,dc=com");
    assertEquals(e, e2);
    assertEquals(e.hashCode(), e2.hashCode());

    assertNotNull(e.toLDIF(78));
    assertNotNull(e.toLDIFString(78));
    assertNotNull(e.toString());
  }



  /**
   * Tests the second constructor by providing a {@code null} DN object.
  */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2Null()
  {
    new Entry((DN) null);
  }



  /**
   * Tests the third constructor, which takes a DN string and an attribute
   * array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
      new Attribute("description", "foo")
    };

    Entry e = new Entry("dc=example,dc=com", attrs);
    e = e.duplicate();

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "dc=example,dc=com");
    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertEquals(e.getRDN(), new RDN("dc=example"));
    assertEquals(e.getParentDN(), new DN("dc=com"));
    assertEquals(new DN(e.getParentDNString()), new DN("dc=com"));

    assertTrue(e.hasAttribute("description"));
    assertTrue(e.hasAttributeValue("description", "foo"));
    assertTrue(e.hasAttributeValue("description", "foo".getBytes("UTF-8")));
    assertFalse(e.hasAttributeValue("description", "bar"));
    assertFalse(e.hasAttributeValue("description", "bar".getBytes("UTF-8")));

    assertTrue(e.addAttribute("description", "bar"));
    assertTrue(e.hasAttributeValue("description", "bar"));
    assertTrue(e.hasAttributeValue("description", "bar".getBytes("UTF-8")));

    assertFalse(e.removeAttributeValue("description", "baz"));
    assertTrue(e.removeAttributeValue("description", "bar"));
    assertTrue(e.hasAttribute("description"));
    assertTrue(e.hasAttributeValue("description", "foo"));

    assertNotNull(e.getAttribute("description"));

    assertNotNull(e.getAttributeValue("description"));
    assertEquals(e.getAttributeValue("description"), "foo");

    assertNotNull(e.getAttributeValueBytes("description"));
    assertEquals(toUTF8String(e.getAttributeValueBytes("description")), "foo");

    assertNotNull(e.getAttributeValues("description"));
    assertEquals(e.getAttributeValues("description").length, 1);

    assertNotNull(e.getAttributeValueByteArrays("description"));
    assertEquals(e.getAttributeValueByteArrays("description").length, 1);

    assertNotNull(e.getObjectClassAttribute());
    assertTrue(e.getObjectClassAttribute().hasValue("top"));
    assertTrue(e.getObjectClassAttribute().hasValue("domain"));
    assertFalse(e.getObjectClassAttribute().hasValue("example"));

    assertNotNull(e.getObjectClassValues());
    assertEquals(e.getObjectClassValues().length, 2);

    Entry e2 = new Entry(new DN("dc=example,dc=com"), attrs);
    assertEquals(e, e2);
    assertEquals(e.hashCode(), e2.hashCode());

    assertNotNull(e.toLDIF(78));
    assertNotNull(e.toLDIFString(78));
    assertNotNull(e.toString());
  }



  /**
   * Tests the third constructor, with a null DN and non-null set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor3NullDN()
         throws Exception
  {
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
      new Attribute("description", "foo")
    };

    new Entry((String) null, attrs);
  }



  /**
   * Tests the third constructor, with a non-null DN and null set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor3NullAttrs()
         throws Exception
  {
    new Entry("dc=example,dc=com", (Attribute[]) null);
  }



  /**
   * Tests the third constructor, with a null DN and empty set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3EmptyAttrs()
         throws Exception
  {
    Entry e = new Entry("dc=example,dc=com", new Attribute[0]);
    e = e.duplicate();

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "dc=example,dc=com");
    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertEquals(e.getRDN(), new RDN("dc=example"));
    assertEquals(e.getParentDN(), new DN("dc=com"));
    assertEquals(new DN(e.getParentDNString()), new DN("dc=com"));

    assertFalse(e.hasAttribute("description"));
    assertFalse(e.hasAttribute(new Attribute("description", "foo")));
    assertFalse(e.hasAttributeValue("description", "foo"));
    assertFalse(e.hasAttributeValue("description", "foo".getBytes("UTF-8")));

    assertNull(e.getAttribute("description"));
    assertFalse(e.removeAttribute("description"));
    assertFalse(e.removeAttributeValue("description", "foo"));
    assertFalse(e.removeAttributeValue("description", "foo".getBytes("UTF-8")));

    assertNull(e.getAttributeValue("description"));

    assertNull(e.getAttributeValueBytes("description"));

    assertNull(e.getAttributeValues("description"));

    assertNull(e.getAttributeValueByteArrays("description"));

    assertNull(e.getObjectClassAttribute());
    assertNull(e.getObjectClassValues());

    Entry e2 = new Entry(new DN("dc=example,dc=com"));
    assertEquals(e, e2);
    assertEquals(e.hashCode(), e2.hashCode());

    assertNotNull(e.toLDIF(78));
    assertNotNull(e.toLDIFString(78));
    assertNotNull(e.toString());
  }



  /**
   * Tests the third constructor, with a non-null DN and an attribute array
   * containing disconnected values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3DisconnectedAttrs()
         throws Exception
  {
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top"),
      new Attribute("dc", "example"),
      new Attribute("description", "foo"),
      new Attribute("objectclass", "domain")
    };

    Entry e = new Entry("dc=example,dc=com", attrs);
    e = e.duplicate();

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "dc=example,dc=com");
    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertEquals(e.getRDN(), new RDN("dc=example"));
    assertEquals(e.getParentDN(), new DN("dc=com"));
    assertEquals(new DN(e.getParentDNString()), new DN("dc=com"));

    assertTrue(e.hasAttribute("description"));
    assertTrue(e.hasAttributeValue("description", "foo"));
    assertTrue(e.hasAttributeValue("description", "foo".getBytes("UTF-8")));
    assertFalse(e.hasAttributeValue("description", "bar"));
    assertFalse(e.hasAttributeValue("description", "bar".getBytes("UTF-8")));

    assertTrue(e.addAttribute("description", "bar"));
    assertTrue(e.hasAttributeValue("description", "bar"));
    assertTrue(e.hasAttributeValue("description", "bar".getBytes("UTF-8")));

    assertFalse(e.removeAttributeValue("description", "baz"));
    assertTrue(e.removeAttributeValue("description", "bar"));
    assertTrue(e.hasAttribute("description"));
    assertTrue(e.hasAttributeValue("description", "foo"));

    assertTrue(e.hasAttribute("objectClass"));
    assertTrue(e.hasAttributeValue("objectClass", "top"));
    assertTrue(e.hasAttributeValue("objectClass", "domain"));

    assertTrue(e.hasAttribute("objectclass"));
    assertTrue(e.hasAttributeValue("objectclass", "top"));
    assertTrue(e.hasAttributeValue("objectclass", "domain"));

    assertNotNull(e.getAttribute("description"));

    assertNotNull(e.getAttributeValue("description"));
    assertEquals(e.getAttributeValue("description"), "foo");

    assertNotNull(e.getAttributeValueBytes("description"));
    assertEquals(toUTF8String(e.getAttributeValueBytes("description")), "foo");

    assertNotNull(e.getAttributeValues("description"));
    assertEquals(e.getAttributeValues("description").length, 1);

    assertNotNull(e.getAttributeValueByteArrays("description"));
    assertEquals(e.getAttributeValueByteArrays("description").length, 1);

    assertNotNull(e.getObjectClassAttribute());
    assertTrue(e.getObjectClassAttribute().hasValue("top"));
    assertTrue(e.getObjectClassAttribute().hasValue("domain"));
    assertFalse(e.getObjectClassAttribute().hasValue("example"));

    assertNotNull(e.getObjectClassValues());
    assertEquals(e.getObjectClassValues().length, 2);

    Entry e2 = new Entry(new DN("dc=example,dc=com"), attrs);
    assertEquals(e, e2);
    assertEquals(e.hashCode(), e2.hashCode());

    assertNotNull(e.toLDIF(78));
    assertNotNull(e.toLDIFString(78));
    assertNotNull(e.toString());
  }



  /**
   * Tests the fourth constructor, which takes a DN object and an attribute
   * array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4()
         throws Exception
  {
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
      new Attribute("description", "foo")
    };

    Entry e = new Entry(new DN("dc=example,dc=com"), attrs);
    e = e.duplicate();

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "dc=example,dc=com");
    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertEquals(e.getRDN(), new RDN("dc=example"));
    assertEquals(e.getParentDN(), new DN("dc=com"));
    assertEquals(new DN(e.getParentDNString()), new DN("dc=com"));

    assertTrue(e.hasAttribute("description"));
    assertTrue(e.hasAttributeValue("description", "foo"));
    assertTrue(e.hasAttributeValue("description", "foo".getBytes("UTF-8")));
    assertFalse(e.hasAttributeValue("description", "bar"));
    assertFalse(e.hasAttributeValue("description", "bar".getBytes("UTF-8")));

    assertTrue(e.addAttribute("description", "bar"));
    assertTrue(e.hasAttributeValue("description", "bar"));
    assertTrue(e.hasAttributeValue("description", "bar".getBytes("UTF-8")));

    assertFalse(e.removeAttributeValue("description", "baz"));
    assertTrue(e.removeAttributeValue("description", "bar"));
    assertTrue(e.hasAttribute("description"));
    assertTrue(e.hasAttributeValue("description", "foo"));

    assertNotNull(e.getAttribute("description"));

    assertNotNull(e.getAttributeValue("description"));
    assertEquals(e.getAttributeValue("description"), "foo");

    assertNotNull(e.getAttributeValueBytes("description"));
    assertEquals(toUTF8String(e.getAttributeValueBytes("description")), "foo");

    assertNotNull(e.getAttributeValues("description"));
    assertEquals(e.getAttributeValues("description").length, 1);

    assertNotNull(e.getAttributeValueByteArrays("description"));
    assertEquals(e.getAttributeValueByteArrays("description").length, 1);

    assertNotNull(e.getObjectClassAttribute());
    assertTrue(e.getObjectClassAttribute().hasValue("top"));
    assertTrue(e.getObjectClassAttribute().hasValue("domain"));
    assertFalse(e.getObjectClassAttribute().hasValue("example"));

    assertNotNull(e.getObjectClassValues());
    assertEquals(e.getObjectClassValues().length, 2);

    Entry e2 = new Entry("dc=example,dc=com", attrs);
    assertEquals(e, e2);
    assertEquals(e.hashCode(), e2.hashCode());

    assertNotNull(e.toLDIF(78));
    assertNotNull(e.toLDIFString(78));
    assertNotNull(e.toString());
  }



  /**
   * Tests the fourth constructor, with a null DN and non-null set of
   * attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor4NullDN()
         throws Exception
  {
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
      new Attribute("description", "foo")
    };

    new Entry((DN) null, attrs);
  }



  /**
   * Tests the fourth constructor, with a non-null DN and null set of
   * attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor4NullAttrs()
         throws Exception
  {
    new Entry(new DN("dc=example,dc=com"), (Attribute[]) null);
  }



  /**
   * Tests the fourth constructor, with a null DN and empty set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4EmptyAttrs()
         throws Exception
  {
    Entry e = new Entry(new DN("dc=example,dc=com"), new Attribute[0]);
    e = e.duplicate();

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "dc=example,dc=com");
    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertEquals(e.getRDN(), new RDN("dc=example"));
    assertEquals(e.getParentDN(), new DN("dc=com"));
    assertEquals(new DN(e.getParentDNString()), new DN("dc=com"));

    assertFalse(e.hasAttribute("description"));
    assertFalse(e.hasAttribute(new Attribute("description", "foo")));
    assertFalse(e.hasAttributeValue("description", "foo"));
    assertFalse(e.hasAttributeValue("description", "foo".getBytes("UTF-8")));

    assertNull(e.getAttribute("description"));
    assertFalse(e.removeAttribute("description"));
    assertFalse(e.removeAttributeValue("description", "foo"));
    assertFalse(e.removeAttributeValue("description", "foo".getBytes("UTF-8")));

    assertNull(e.getAttributeValue("description"));

    assertNull(e.getAttributeValueBytes("description"));

    assertNull(e.getAttributeValues("description"));

    assertNull(e.getAttributeValueByteArrays("description"));

    assertNull(e.getObjectClassAttribute());
    assertNull(e.getObjectClassValues());

    Entry e2 = new Entry(new DN("dc=example,dc=com"));
    assertEquals(e, e2);
    assertEquals(e.hashCode(), e2.hashCode());

    assertNotNull(e.toLDIF(78));
    assertNotNull(e.toLDIFString(78));
    assertNotNull(e.toString());
  }



  /**
   * Tests the fourth constructor, with a non-null DN and an attribute array
   * containing disconnected values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4DisconnectedAttrs()
         throws Exception
  {
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top"),
      new Attribute("dc", "example"),
      new Attribute("description", "foo"),
      new Attribute("objectclass", "domain")
    };

    Entry e = new Entry(new DN("dc=example,dc=com"), attrs);
    e = e.duplicate();

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "dc=example,dc=com");
    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertEquals(e.getRDN(), new RDN("dc=example"));
    assertEquals(e.getParentDN(), new DN("dc=com"));
    assertEquals(new DN(e.getParentDNString()), new DN("dc=com"));

    assertTrue(e.hasAttribute("description"));
    assertTrue(e.hasAttributeValue("description", "foo"));
    assertTrue(e.hasAttributeValue("description", "foo".getBytes("UTF-8")));
    assertFalse(e.hasAttributeValue("description", "bar"));
    assertFalse(e.hasAttributeValue("description", "bar".getBytes("UTF-8")));

    assertTrue(e.addAttribute("description", "bar"));
    assertTrue(e.hasAttributeValue("description", "bar"));
    assertTrue(e.hasAttributeValue("description", "bar".getBytes("UTF-8")));

    assertFalse(e.removeAttributeValue("description", "baz"));
    assertTrue(e.removeAttributeValue("description", "bar"));
    assertTrue(e.hasAttribute("description"));
    assertTrue(e.hasAttributeValue("description", "foo"));

    assertTrue(e.hasAttribute("objectClass"));
    assertTrue(e.hasAttributeValue("objectClass", "top"));
    assertTrue(e.hasAttributeValue("objectClass", "domain"));

    assertTrue(e.hasAttribute("objectclass"));
    assertTrue(e.hasAttributeValue("objectclass", "top"));
    assertTrue(e.hasAttributeValue("objectclass", "domain"));

    assertNotNull(e.getAttribute("description"));

    assertNotNull(e.getAttributeValue("description"));
    assertEquals(e.getAttributeValue("description"), "foo");

    assertNotNull(e.getAttributeValueBytes("description"));
    assertEquals(toUTF8String(e.getAttributeValueBytes("description")), "foo");

    assertNotNull(e.getAttributeValues("description"));
    assertEquals(e.getAttributeValues("description").length, 1);

    assertNotNull(e.getAttributeValueByteArrays("description"));
    assertEquals(e.getAttributeValueByteArrays("description").length, 1);

    assertNotNull(e.getObjectClassAttribute());
    assertTrue(e.getObjectClassAttribute().hasValue("top"));
    assertTrue(e.getObjectClassAttribute().hasValue("domain"));
    assertFalse(e.getObjectClassAttribute().hasValue("example"));

    assertNotNull(e.getObjectClassValues());
    assertEquals(e.getObjectClassValues().length, 2);

    Entry e2 = new Entry(new DN("dc=example,dc=com"), attrs);
    assertEquals(e, e2);
    assertEquals(e.hashCode(), e2.hashCode());

    assertNotNull(e.toLDIF(78));
    assertNotNull(e.toLDIFString(78));
    assertNotNull(e.toString());
  }



  /**
   * Tests the fifth constructor, which takes a DN string and an attribute
   * list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5()
         throws Exception
  {
    ArrayList<Attribute> attrs = new ArrayList<Attribute>();
    attrs.add(new Attribute("objectClass", "top", "domain"));
    attrs.add(new Attribute("dc", "example"));
    attrs.add(new Attribute("description", "foo"));

    Entry e = new Entry("dc=example,dc=com", attrs);
    e = e.duplicate();

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "dc=example,dc=com");
    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertEquals(e.getRDN(), new RDN("dc=example"));
    assertEquals(e.getParentDN(), new DN("dc=com"));
    assertEquals(new DN(e.getParentDNString()), new DN("dc=com"));

    assertTrue(e.hasAttribute("description"));
    assertTrue(e.hasAttributeValue("description", "foo"));
    assertTrue(e.hasAttributeValue("description", "foo".getBytes("UTF-8")));
    assertFalse(e.hasAttributeValue("description", "bar"));
    assertFalse(e.hasAttributeValue("description", "bar".getBytes("UTF-8")));

    assertTrue(e.addAttribute("description", "bar"));
    assertTrue(e.hasAttributeValue("description", "bar"));
    assertTrue(e.hasAttributeValue("description", "bar".getBytes("UTF-8")));

    assertFalse(e.removeAttributeValue("description", "baz"));
    assertTrue(e.removeAttributeValue("description", "bar"));
    assertTrue(e.hasAttribute("description"));
    assertTrue(e.hasAttributeValue("description", "foo"));

    assertNotNull(e.getAttribute("description"));

    assertNotNull(e.getAttributeValue("description"));
    assertEquals(e.getAttributeValue("description"), "foo");

    assertNotNull(e.getAttributeValueBytes("description"));
    assertEquals(toUTF8String(e.getAttributeValueBytes("description")), "foo");

    assertNotNull(e.getAttributeValues("description"));
    assertEquals(e.getAttributeValues("description").length, 1);

    assertNotNull(e.getAttributeValueByteArrays("description"));
    assertEquals(e.getAttributeValueByteArrays("description").length, 1);

    assertNotNull(e.getObjectClassAttribute());
    assertTrue(e.getObjectClassAttribute().hasValue("top"));
    assertTrue(e.getObjectClassAttribute().hasValue("domain"));
    assertFalse(e.getObjectClassAttribute().hasValue("example"));

    assertNotNull(e.getObjectClassValues());
    assertEquals(e.getObjectClassValues().length, 2);

    Entry e2 = new Entry(new DN("dc=example,dc=com"), attrs);
    assertEquals(e, e2);
    assertEquals(e.hashCode(), e2.hashCode());

    assertNotNull(e.toLDIF(78));
    assertNotNull(e.toLDIFString(78));
    assertNotNull(e.toString());
  }



  /**
   * Tests the fifth constructor, with a null DN and non-null set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor5NullDN()
         throws Exception
  {
    ArrayList<Attribute> attrs = new ArrayList<Attribute>();
    attrs.add(new Attribute("objectClass", "top", "domain"));
    attrs.add(new Attribute("dc", "example"));
    attrs.add(new Attribute("description", "foo"));

    new Entry((String) null, attrs);
  }



  /**
   * Tests the fifth constructor, with a non-null DN and null set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor5NullAttrs()
         throws Exception
  {
    new Entry("dc=example,dc=com", (ArrayList<Attribute>) null);
  }



  /**
   * Tests the fifth constructor, with a null DN and empty set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5EmptyAttrs()
         throws Exception
  {
    Entry e = new Entry("dc=example,dc=com", new ArrayList<Attribute>());
    e = e.duplicate();

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "dc=example,dc=com");
    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertEquals(e.getRDN(), new RDN("dc=example"));
    assertEquals(e.getParentDN(), new DN("dc=com"));
    assertEquals(new DN(e.getParentDNString()), new DN("dc=com"));

    assertFalse(e.hasAttribute("description"));
    assertFalse(e.hasAttribute(new Attribute("description", "foo")));
    assertFalse(e.hasAttributeValue("description", "foo"));
    assertFalse(e.hasAttributeValue("description", "foo".getBytes("UTF-8")));

    assertNull(e.getAttribute("description"));
    assertFalse(e.removeAttribute("description"));
    assertFalse(e.removeAttributeValue("description", "foo"));
    assertFalse(e.removeAttributeValue("description", "foo".getBytes("UTF-8")));

    assertNull(e.getAttributeValue("description"));

    assertNull(e.getAttributeValueBytes("description"));

    assertNull(e.getAttributeValues("description"));

    assertNull(e.getAttributeValueByteArrays("description"));

    assertNull(e.getObjectClassAttribute());
    assertNull(e.getObjectClassValues());

    Entry e2 = new Entry(new DN("dc=example,dc=com"));
    assertEquals(e, e2);
    assertEquals(e.hashCode(), e2.hashCode());

    assertNotNull(e.toLDIF(78));
    assertNotNull(e.toLDIFString(78));
    assertNotNull(e.toString());
  }



  /**
   * Tests the fifth constructor, with a non-null DN and an attribute list
   * containing disconnected values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5DisconnectedAttrs()
         throws Exception
  {
    ArrayList<Attribute> attrs = new ArrayList<Attribute>();
    attrs.add(new Attribute("objectClass", "top"));
    attrs.add(new Attribute("dc", "example"));
    attrs.add(new Attribute("description", "foo"));
    attrs.add(new Attribute("objectClass", "domain"));

    Entry e = new Entry("dc=example,dc=com", attrs);
    e = e.duplicate();

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "dc=example,dc=com");
    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertEquals(e.getRDN(), new RDN("dc=example"));
    assertEquals(e.getParentDN(), new DN("dc=com"));
    assertEquals(new DN(e.getParentDNString()), new DN("dc=com"));

    assertTrue(e.hasAttribute("description"));
    assertTrue(e.hasAttributeValue("description", "foo".getBytes("UTF-8")));
    assertFalse(e.hasAttributeValue("description", "bar"));
    assertFalse(e.hasAttributeValue("description", "bar".getBytes("UTF-8")));

    assertTrue(e.addAttribute("description", "bar"));
    assertTrue(e.hasAttributeValue("description", "bar"));
    assertTrue(e.hasAttributeValue("description", "bar".getBytes("UTF-8")));

    assertFalse(e.removeAttributeValue("description", "baz"));
    assertTrue(e.removeAttributeValue("description", "bar"));
    assertTrue(e.hasAttribute("description"));
    assertTrue(e.hasAttributeValue("description", "foo"));

    assertTrue(e.hasAttribute("objectClass"));
    assertTrue(e.hasAttributeValue("objectClass", "top"));
    assertTrue(e.hasAttributeValue("objectClass", "domain"));

    assertTrue(e.hasAttribute("objectclass"));
    assertTrue(e.hasAttributeValue("objectclass", "top"));
    assertTrue(e.hasAttributeValue("objectclass", "domain"));

    assertNotNull(e.getAttribute("description"));

    assertNotNull(e.getAttributeValue("description"));
    assertEquals(e.getAttributeValue("description"), "foo");

    assertNotNull(e.getAttributeValueBytes("description"));
    assertEquals(toUTF8String(e.getAttributeValueBytes("description")), "foo");

    assertNotNull(e.getAttributeValues("description"));
    assertEquals(e.getAttributeValues("description").length, 1);

    assertNotNull(e.getAttributeValueByteArrays("description"));
    assertEquals(e.getAttributeValueByteArrays("description").length, 1);

    assertNotNull(e.getObjectClassAttribute());
    assertTrue(e.getObjectClassAttribute().hasValue("top"));
    assertTrue(e.getObjectClassAttribute().hasValue("domain"));
    assertFalse(e.getObjectClassAttribute().hasValue("example"));

    assertNotNull(e.getObjectClassValues());
    assertEquals(e.getObjectClassValues().length, 2);

    Entry e2 = new Entry(new DN("dc=example,dc=com"), attrs);
    assertEquals(e, e2);
    assertEquals(e.hashCode(), e2.hashCode());

    assertNotNull(e.toLDIF(78));
    assertNotNull(e.toLDIFString(78));
    assertNotNull(e.toString());
  }



  /**
   * Tests the sixth constructor, which takes a DN object and an attribute
   * list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6()
         throws Exception
  {
    ArrayList<Attribute> attrs = new ArrayList<Attribute>();
    attrs.add(new Attribute("objectClass", "top", "domain"));
    attrs.add(new Attribute("dc", "example"));
    attrs.add(new Attribute("description", "foo"));

    Entry e = new Entry(new DN("dc=example,dc=com"), attrs);
    e = e.duplicate();

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "dc=example,dc=com");
    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertEquals(e.getRDN(), new RDN("dc=example"));
    assertEquals(e.getParentDN(), new DN("dc=com"));
    assertEquals(new DN(e.getParentDNString()), new DN("dc=com"));

    assertTrue(e.hasAttribute("description"));
    assertTrue(e.hasAttributeValue("description", "foo"));
    assertTrue(e.hasAttributeValue("description", "foo".getBytes("UTF-8")));
    assertFalse(e.hasAttributeValue("description", "bar"));
    assertFalse(e.hasAttributeValue("description", "bar".getBytes("UTF-8")));

    assertTrue(e.addAttribute("description", "bar"));
    assertTrue(e.hasAttributeValue("description", "bar"));
    assertTrue(e.hasAttributeValue("description", "bar".getBytes("UTF-8")));

    assertFalse(e.removeAttributeValue("description", "baz"));
    assertTrue(e.removeAttributeValue("description", "bar"));
    assertTrue(e.hasAttribute("description"));
    assertTrue(e.hasAttributeValue("description", "foo"));

    assertNotNull(e.getAttribute("description"));

    assertNotNull(e.getAttributeValue("description"));
    assertEquals(e.getAttributeValue("description"), "foo");

    assertNotNull(e.getAttributeValueBytes("description"));
    assertEquals(toUTF8String(e.getAttributeValueBytes("description")), "foo");

    assertNotNull(e.getAttributeValues("description"));
    assertEquals(e.getAttributeValues("description").length, 1);

    assertNotNull(e.getAttributeValueByteArrays("description"));
    assertEquals(e.getAttributeValueByteArrays("description").length, 1);

    assertNotNull(e.getObjectClassAttribute());
    assertTrue(e.getObjectClassAttribute().hasValue("top"));
    assertTrue(e.getObjectClassAttribute().hasValue("domain"));
    assertFalse(e.getObjectClassAttribute().hasValue("example"));

    assertNotNull(e.getObjectClassValues());
    assertEquals(e.getObjectClassValues().length, 2);

    Entry e2 = new Entry("dc=example,dc=com", attrs);
    assertEquals(e, e2);
    assertEquals(e.hashCode(), e2.hashCode());

    assertNotNull(e.toLDIF(78));
    assertNotNull(e.toLDIFString(78));
    assertNotNull(e.toString());
  }



  /**
   * Tests the sixth constructor, with a null DN and non-null set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor6NullDN()
         throws Exception
  {
    ArrayList<Attribute> attrs = new ArrayList<Attribute>();
    attrs.add(new Attribute("objectClass", "top", "domain"));
    attrs.add(new Attribute("dc", "example"));
    attrs.add(new Attribute("description", "foo"));

    new Entry((DN) null, attrs);
  }



  /**
   * Tests the sixth constructor, with a non-null DN and null set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor6NullAttrs()
         throws Exception
  {
    new Entry(new DN("dc=example,dc=com"), (ArrayList<Attribute>) null);
  }



  /**
   * Tests the sixth constructor, with a null DN and empty set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6EmptyAttrs()
         throws Exception
  {
    Entry e = new Entry(new DN("dc=example,dc=com"),
                        new ArrayList<Attribute>());
    e = e.duplicate();

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "dc=example,dc=com");
    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertEquals(e.getRDN(), new RDN("dc=example"));
    assertEquals(e.getParentDN(), new DN("dc=com"));
    assertEquals(new DN(e.getParentDNString()), new DN("dc=com"));

    assertFalse(e.hasAttribute("description"));
    assertFalse(e.hasAttribute(new Attribute("description", "foo")));
    assertFalse(e.hasAttributeValue("description", "foo"));
    assertFalse(e.hasAttributeValue("description", "foo".getBytes("UTF-8")));

    assertNull(e.getAttribute("description"));
    assertFalse(e.removeAttribute("description"));
    assertFalse(e.removeAttributeValue("description", "foo"));
    assertFalse(e.removeAttributeValue("description", "foo".getBytes("UTF-8")));

    assertNull(e.getAttributeValue("description"));

    assertNull(e.getAttributeValueBytes("description"));

    assertNull(e.getAttributeValues("description"));

    assertNull(e.getAttributeValueByteArrays("description"));

    assertNull(e.getObjectClassAttribute());
    assertNull(e.getObjectClassValues());

    Entry e2 = new Entry("dc=example,dc=com");
    assertEquals(e, e2);
    assertEquals(e.hashCode(), e2.hashCode());

    assertNotNull(e.toLDIF(78));
    assertNotNull(e.toLDIFString(78));
    assertNotNull(e.toString());
  }



  /**
   * Tests the sixth constructor, with a non-null DN and an attribute list
   * containing disconnected values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6DisconnectedAttrs()
         throws Exception
  {
    ArrayList<Attribute> attrs = new ArrayList<Attribute>();
    attrs.add(new Attribute("objectClass", "top"));
    attrs.add(new Attribute("dc", "example"));
    attrs.add(new Attribute("description", "foo"));
    attrs.add(new Attribute("objectClass", "domain"));

    Entry e = new Entry(new DN("dc=example,dc=com"), attrs);
    e = e.duplicate();

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "dc=example,dc=com");
    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertEquals(e.getRDN(), new RDN("dc=example"));
    assertEquals(e.getParentDN(), new DN("dc=com"));
    assertEquals(new DN(e.getParentDNString()), new DN("dc=com"));

    assertTrue(e.hasAttribute("description"));
    assertTrue(e.hasAttributeValue("description", "foo"));
    assertTrue(e.hasAttributeValue("description", "foo".getBytes("UTF-8")));
    assertFalse(e.hasAttributeValue("description", "bar"));
    assertFalse(e.hasAttributeValue("description", "bar".getBytes("UTF-8")));

    assertTrue(e.addAttribute("description", "bar"));
    assertTrue(e.hasAttributeValue("description", "bar"));
    assertTrue(e.hasAttributeValue("description", "bar".getBytes("UTF-8")));

    assertFalse(e.removeAttributeValue("description", "baz"));
    assertTrue(e.removeAttributeValue("description", "bar"));
    assertTrue(e.hasAttribute("description"));
    assertTrue(e.hasAttributeValue("description", "foo"));

    assertTrue(e.hasAttribute("objectClass"));
    assertTrue(e.hasAttributeValue("objectClass", "top"));
    assertTrue(e.hasAttributeValue("objectClass", "domain"));

    assertTrue(e.hasAttribute("objectclass"));
    assertTrue(e.hasAttributeValue("objectclass", "top"));
    assertTrue(e.hasAttributeValue("objectclass", "domain"));

    assertNotNull(e.getAttribute("description"));

    assertNotNull(e.getAttributeValue("description"));
    assertEquals(e.getAttributeValue("description"), "foo");

    assertNotNull(e.getAttributeValueBytes("description"));
    assertEquals(toUTF8String(e.getAttributeValueBytes("description")), "foo");

    assertNotNull(e.getAttributeValues("description"));
    assertEquals(e.getAttributeValues("description").length, 1);

    assertNotNull(e.getAttributeValueByteArrays("description"));
    assertEquals(e.getAttributeValueByteArrays("description").length, 1);

    assertNotNull(e.getObjectClassAttribute());
    assertTrue(e.getObjectClassAttribute().hasValue("top"));
    assertTrue(e.getObjectClassAttribute().hasValue("domain"));
    assertFalse(e.getObjectClassAttribute().hasValue("example"));

    assertNotNull(e.getObjectClassValues());
    assertEquals(e.getObjectClassValues().length, 2);

    Entry e2 = new Entry("dc=example,dc=com", attrs);
    assertEquals(e, e2);
    assertEquals(e.hashCode(), e2.hashCode());

    assertNotNull(e.toLDIF(78));
    assertNotNull(e.toLDIFString(78));
    assertNotNull(e.toString());
  }



  /**
   * Tests the seventh constructor, which creates an entry from an LDIF string
   * representation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor7WithoutVersion()
         throws Exception
  {
    Entry e = new Entry("dn: dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: domain",
                        "dc: example",
                        "description: foo");
    e = e.duplicate();

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "dc=example,dc=com");
    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertEquals(e.getRDN(), new RDN("dc=example"));
    assertEquals(e.getParentDN(), new DN("dc=com"));
    assertEquals(new DN(e.getParentDNString()), new DN("dc=com"));

    assertTrue(e.hasAttribute("description"));
    assertTrue(e.hasAttributeValue("description", "foo"));
    assertTrue(e.hasAttributeValue("description", "foo".getBytes("UTF-8")));
    assertFalse(e.hasAttributeValue("description", "bar"));
    assertFalse(e.hasAttributeValue("description", "bar".getBytes("UTF-8")));

    assertTrue(e.addAttribute("description", "bar"));
    assertTrue(e.hasAttributeValue("description", "bar"));
    assertTrue(e.hasAttributeValue("description", "bar".getBytes("UTF-8")));

    assertFalse(e.removeAttributeValue("description", "baz"));
    assertTrue(e.removeAttributeValue("description", "bar"));
    assertTrue(e.hasAttribute("description"));
    assertTrue(e.hasAttributeValue("description", "foo"));

    assertTrue(e.hasAttribute("objectClass"));
    assertTrue(e.hasAttributeValue("objectClass", "top"));
    assertTrue(e.hasAttributeValue("objectClass", "domain"));

    assertTrue(e.hasAttribute("objectclass"));
    assertTrue(e.hasAttributeValue("objectclass", "top"));
    assertTrue(e.hasAttributeValue("objectclass", "domain"));

    assertNotNull(e.getAttribute("description"));

    assertNotNull(e.getAttributeValue("description"));
    assertEquals(e.getAttributeValue("description"), "foo");

    assertNotNull(e.getAttributeValueBytes("description"));
    assertEquals(toUTF8String(e.getAttributeValueBytes("description")), "foo");

    assertNotNull(e.getAttributeValues("description"));
    assertEquals(e.getAttributeValues("description").length, 1);

    assertNotNull(e.getAttributeValueByteArrays("description"));
    assertEquals(e.getAttributeValueByteArrays("description").length, 1);

    assertNotNull(e.getObjectClassAttribute());
    assertTrue(e.getObjectClassAttribute().hasValue("top"));
    assertTrue(e.getObjectClassAttribute().hasValue("domain"));
    assertFalse(e.getObjectClassAttribute().hasValue("example"));

    assertNotNull(e.getObjectClassValues());
    assertEquals(e.getObjectClassValues().length, 2);

    Entry e2 = new Entry(e.toLDIF(78));
    assertEquals(e, e2);
    assertEquals(e.hashCode(), e2.hashCode());

    assertNotNull(e.toLDIFString(78));
    assertNotNull(e.toString());
  }



  /**
   * Tests the seventh constructor, which creates an entry from an LDIF string
   * representation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor7WithVersion()
         throws Exception
  {
    Entry e = new Entry("version: 1",
                        "dn: dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: domain",
                        "dc: example",
                        "description: foo");
    e = e.duplicate();

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), "dc=example,dc=com");
    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertEquals(e.getRDN(), new RDN("dc=example"));
    assertEquals(e.getParentDN(), new DN("dc=com"));
    assertEquals(new DN(e.getParentDNString()), new DN("dc=com"));

    assertTrue(e.hasAttribute("description"));
    assertTrue(e.hasAttributeValue("description", "foo"));
    assertTrue(e.hasAttributeValue("description", "foo".getBytes("UTF-8")));
    assertFalse(e.hasAttributeValue("description", "bar"));
    assertFalse(e.hasAttributeValue("description", "bar".getBytes("UTF-8")));

    assertTrue(e.addAttribute("description", "bar"));
    assertTrue(e.hasAttributeValue("description", "bar"));
    assertTrue(e.hasAttributeValue("description", "bar".getBytes("UTF-8")));

    assertFalse(e.removeAttributeValue("description", "baz"));
    assertTrue(e.removeAttributeValue("description", "bar"));
    assertTrue(e.hasAttribute("description"));
    assertTrue(e.hasAttributeValue("description", "foo"));

    assertTrue(e.hasAttribute("objectClass"));
    assertTrue(e.hasAttributeValue("objectClass", "top"));
    assertTrue(e.hasAttributeValue("objectClass", "domain"));

    assertTrue(e.hasAttribute("objectclass"));
    assertTrue(e.hasAttributeValue("objectclass", "top"));
    assertTrue(e.hasAttributeValue("objectclass", "domain"));

    assertNotNull(e.getAttribute("description"));

    assertNotNull(e.getAttributeValue("description"));
    assertEquals(e.getAttributeValue("description"), "foo");

    assertNotNull(e.getAttributeValueBytes("description"));
    assertEquals(toUTF8String(e.getAttributeValueBytes("description")), "foo");

    assertNotNull(e.getAttributeValues("description"));
    assertEquals(e.getAttributeValues("description").length, 1);

    assertNotNull(e.getAttributeValueByteArrays("description"));
    assertEquals(e.getAttributeValueByteArrays("description").length, 1);

    assertNotNull(e.getObjectClassAttribute());
    assertTrue(e.getObjectClassAttribute().hasValue("top"));
    assertTrue(e.getObjectClassAttribute().hasValue("domain"));
    assertFalse(e.getObjectClassAttribute().hasValue("example"));

    assertNotNull(e.getObjectClassValues());
    assertEquals(e.getObjectClassValues().length, 2);

    Entry e2 = new Entry(e.toLDIF(78));
    assertEquals(e, e2);
    assertEquals(e.hashCode(), e2.hashCode());

    assertNotNull(e.toLDIFString(78));
    assertNotNull(e.toString());
  }



  /**
   * Tests the {@code getDN} and {@code setDN} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetDN()
         throws Exception
  {
    Entry e = new Entry("dc=example,dc=com");
    assertEquals(e.getDN(), "dc=example,dc=com");
    assertEquals(e.getParsedDN(), new DN("dc=example,dc=com"));
    assertEquals(e.getRDN(), new RDN("dc=example"));
    assertEquals(e.getParentDN(), new DN("dc=com"));
    assertEquals(new DN(e.getParentDNString()), new DN("dc=com"));

    e.setDN("o=example.net");
    assertEquals(e.getDN(), "o=example.net");
    assertEquals(e.getParsedDN(), new DN("o=example.net"));
    assertEquals(e.getRDN(), new RDN("o=example.net"));
    assertNull(e.getParentDN());
    assertNull(e.getParentDNString());

    e.setDN(new DN("o=Example Corp,c=US"));
    assertEquals(e.getDN(), "o=Example Corp,c=US");
    assertEquals(e.getParsedDN(), new DN("o=Example Corp,c=US"));
    assertEquals(e.getRDN(), new RDN("o=Example Corp"));
    assertEquals(e.getParentDN(), new DN("c=US"));
    assertEquals(new DN(e.getParentDNString()), new DN("c=US"));

    e.setDN("invalid");
    assertEquals(e.getDN(), "invalid");

    try
    {
      e.getParsedDN();
      fail("Expected an exception when trying to parse \"invalid\" as a DN");
    }
    catch (LDAPException le)
    {
      // This is expected.
    }
  }



  /**
   * Tests the methods used to manipulate attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeManipulation()
         throws Exception
  {
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
      new Attribute("description", "foo")
    };

    Entry e = new Entry("dc=example,dc=com", attrs);

    assertTrue(e.hasAttribute("objectClass"));
    assertTrue(e.hasAttribute("objectclass"));
    assertTrue(e.hasAttribute("OBJECTCLASS"));
    assertFalse(e.hasAttribute("o"));

    assertTrue(e.hasAttributeValue("objectClass", "top"));
    assertFalse(e.hasAttributeValue("objectClass", "organization"));
    assertTrue(e.hasAttributeValue("OBJECTCLASS", "TOP"));
    assertTrue(e.hasAttributeValue("OBJECTCLASS", "TOP",
         CaseIgnoreStringMatchingRule.getInstance()));
    assertFalse(e.hasAttributeValue("OBJECTCLASS", "TOP",
         CaseExactStringMatchingRule.getInstance()));

    assertTrue(e.hasAttributeValue("objectClass", "top".getBytes("UTF-8")));
    assertTrue(e.hasAttributeValue("objectClass", "domain".getBytes("UTF-8")));
    assertFalse(e.hasAttributeValue("objectClass",
                               "organization".getBytes("UTF-8")));
    assertTrue(e.hasAttributeValue("OBJECTCLASS", "TOP".getBytes("UTF-8")));
    assertTrue(e.hasAttributeValue("OBJECTCLASS", "TOP".getBytes("UTF-8"),
         CaseIgnoreStringMatchingRule.getInstance()));
    assertFalse(e.hasAttributeValue("OBJECTCLASS", "TOP".getBytes("UTF-8"),
         CaseExactStringMatchingRule.getInstance()));

    assertTrue(e.hasAttribute(new Attribute("objectClass", "top", "domain")));
    assertFalse(e.hasAttribute(new Attribute("objectClass", "top")));
    assertFalse(e.hasAttribute(new Attribute("objectClass", "domain")));
    assertFalse(e.hasAttribute(new Attribute("objectClass", "top", "domain",
                                             "extensibleObject")));

    assertNotNull(e.getAttribute("description"));
    assertNotNull(e.getAttribute("DESCRIPTION"));
    assertEquals(e.getAttribute("description"),
                 new Attribute("description", "foo"));

    assertFalse(e.hasAttribute("organization"));
    assertFalse(e.hasAttributeValue("organization", "Example Corp"));
    assertNull(e.getAttribute("organization"));

    assertTrue(e.addAttribute("organization", "Example Corp"));
    assertFalse(e.addAttribute("organization", "Example Corp"));
    assertTrue(e.hasAttribute("organization"));
    assertTrue(e.hasAttributeValue("organization", "Example Corp"));
    assertNotNull(e.getAttribute("organization"));
    assertEquals(e.getAttribute("organization"),
                 new Attribute("organization", "Example Corp"));

    assertFalse(e.addAttribute("organization",
                               "Example Corp".getBytes("UTF-8")));
    assertTrue(e.addAttribute("organization", "Example Inc".getBytes("UTF-8")));
    assertTrue(e.hasAttribute("organization"));
    assertTrue(e.hasAttributeValue("organization", "Example Corp"));
    assertTrue(e.hasAttributeValue("organization", "Example Inc"));
    assertNotNull(e.getAttribute("organization"));
    assertEquals(e.getAttribute("organization"),
                 new Attribute("organization", "Example Corp", "Example Inc"));

    assertTrue(e.addAttribute(new Attribute("description", "bar")));
    assertEquals(e.getAttribute("description"),
                 new Attribute("description", "foo", "bar"));
    assertFalse(e.addAttribute(new Attribute("description", "bar")));

    assertFalse(e.hasAttribute("cn"));
    assertTrue(e.addAttribute(new Attribute("cn", "Example")));
    assertFalse(e.addAttribute("cn", "Example"));
    assertTrue(e.hasAttributeValue("cn", "Example"));

    assertFalse(e.hasAttribute("a"));
    assertTrue(e.addAttribute("a", "b", "c", "d"));
    assertTrue(e.addAttribute("a", "d".getBytes("UTF-8"),
                               "e".getBytes("UTF-8"), "f".getBytes("UTF-8")));
    assertTrue(e.addAttribute("a", "g", "h"));
    assertTrue(e.hasAttributeValue("a", "d"));
    assertTrue(e.hasAttributeValue("a", "e"));
    assertTrue(e.hasAttributeValue("a", "f"));

    assertTrue(e.removeAttributeValue("a", "f"));
    assertFalse(e.removeAttributeValue("a", "f"));

    assertTrue(e.removeAttributeValue("a", "e".getBytes("UTF-8")));
    assertFalse(e.removeAttributeValue("a", "e".getBytes("UTF-8")));

    assertTrue(e.hasAttribute("a"));
    assertTrue(e.removeAttribute("a"));
    assertFalse(e.removeAttribute("a"));

    assertTrue(e.addAttribute("a", "b".getBytes("UTF-8")));
    assertTrue(e.removeAttributeValue("a", "b".getBytes("UTF-8")));
    assertTrue(e.addAttribute("a", "b".getBytes("UTF-8"),
                              "c".getBytes("UTF-8")));
    assertTrue(e.removeAttributeValue("a", "b".getBytes("UTF-8")));
    assertTrue(e.removeAttributeValue("a", "c"));

    assertFalse(e.hasAttribute("a"));
    e.setAttribute(new Attribute("a", "b", "c"));
    assertTrue(e.hasAttributeValue("a", "b"));
    assertTrue(e.hasAttributeValue("a", "c"));

    e.setAttribute("a", Arrays.asList("d", "e"));
    assertFalse(e.hasAttributeValue("a", "b"));
    assertFalse(e.hasAttributeValue("a", "c"));
    assertTrue(e.hasAttributeValue("a", "d"));
    assertTrue(e.hasAttributeValue("a", "e"));

    e.setAttribute("a", "c");
    assertFalse(e.hasAttributeValue("a", "b"));
    assertTrue(e.hasAttributeValue("a", "c"));
    assertFalse(e.hasAttributeValue("a", "d"));
    assertFalse(e.hasAttributeValue("a", "e"));

    e.setAttribute("a", "b".getBytes("UTF-8"));
    assertTrue(e.hasAttributeValue("a", "b"));
    assertFalse(e.hasAttributeValue("a", "c"));

    e.setAttribute("a", "b", "c", "d");
    assertTrue(e.hasAttributeValue("a", "b"));
    assertTrue(e.hasAttributeValue("a", "c"));
    assertTrue(e.hasAttributeValue("a", "d"));

    e.setAttribute("a", "b".getBytes("UTF-8"), "c".getBytes("UTF-8"));
    assertTrue(e.hasAttributeValue("a", "b"));
    assertTrue(e.hasAttributeValue("a", "c"));
    assertFalse(e.hasAttributeValue("a", "d"));

    e.addAttribute("a", "d", "e", "f");
    assertFalse(e.removeAttributeValues("a", "g"));
    assertTrue(e.removeAttributeValues("a", "f"));
    assertTrue(e.removeAttributeValues("a", "e", "f"));
    assertTrue(e.removeAttributeValues("a", "c", "d"));
    assertFalse(e.removeAttributeValues("a", "c", "d", "e", "f"));
    assertTrue(e.removeAttributeValues("a", "b"));

    e.removeAttribute("a");
    e.addAttribute("a", Arrays.asList("b", "c", "d", "e", "f"));
    assertFalse(e.removeAttributeValues("a", "g"));
    assertTrue(e.removeAttributeValues("a", "f"));
    assertTrue(e.removeAttributeValues("a", "e", "f"));
    assertTrue(e.removeAttributeValues("a", "c", "d"));
    assertFalse(e.removeAttributeValues("a", "c", "d", "e", "f"));
    assertTrue(e.removeAttributeValues("a", "b"));

    e.setAttribute("a", "b", "c", "d", "e", "f");
    assertFalse(e.removeAttributeValues("a", "g".getBytes("UTF-8")));
    assertTrue(e.removeAttributeValues("a", "f".getBytes("UTF-8")));
    assertTrue(e.removeAttributeValues("a", "e".getBytes("UTF-8"),
                                       "f".getBytes("UTF-8")));
    assertTrue(e.removeAttributeValues("a", "c".getBytes("UTF-8"),
                                       "d".getBytes("UTF-8")));
    assertFalse(e.removeAttributeValues("a", "c".getBytes("UTF-8"),
                                        "d".getBytes("UTF-8"),
                                        "e".getBytes("UTF-8"),
                                        "f".getBytes("UTF-8")));
    assertTrue(e.removeAttributeValues("a", "b".getBytes("UTF-8")));

    assertFalse(e.removeAttributeValues("nonexistent", "doesntmatter"));
    assertFalse(e.removeAttributeValues("nonexistent",
                                        "doesntmatter".getBytes("UTF-8")));
    assertFalse(e.removeAttributeValues("nonexistent", "doesntmatter1",
                                        "doesntmatter2"));
    assertFalse(e.removeAttributeValues("nonexistent",
                                        "doesntmatter1".getBytes("UTF-8"),
                                        "doesntmatter2".getBytes("UTF-8")));
  }



  /**
   * Tests the {@code getValueAsBoolean} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAttributeValueAsBoolean()
         throws Exception
  {
    // An entry without the target attribute should return null.
    Entry e = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    assertNull(e.getAttributeValueAsBoolean("a"));

    // An entry with the target attribute but without any values should return
    // null.
    e.setAttribute(new Attribute("a"));
    assertNull(e.getAttributeValueAsBoolean("a"));

    // Test values that should return TRUE.
    String[] trueStrs =
    {
      "TRUE",
      "true",
      "T",
      "t",
      "YES",
      "yes",
      "Y",
      "y",
      "ON",
      "on",
      "1",
    };
    for (String s : trueStrs)
    {
      e.setAttribute(new Attribute("a", s));
      assertNotNull(e.getAttributeValueAsBoolean("a"));
      assertTrue(e.getAttributeValueAsBoolean("a"));
    }

    // Test values that should return FALSE.
    String[] falseStrs =
    {
      "FALSE",
      "false",
      "F",
      "f",
      "NO",
      "no",
      "n",
      "n",
      "OFF",
      "off",
      "0",
    };
    for (String s : falseStrs)
    {
      e.setAttribute(new Attribute("a", s));
      assertNotNull(e.getAttributeValueAsBoolean("a"));
      assertFalse(e.getAttributeValueAsBoolean("a"));
    }

    // Test invalid values.
    String[] invalidStrs =
    {
      "",
      "invalid"
    };
    for (String s : invalidStrs)
    {
      e.setAttribute(new Attribute("a", s));
      assertNull(e.getAttributeValueAsBoolean("a"));
    }
  }



  /**
   * Tests the {@code getValueAsDate} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValueAsDate()
         throws Exception
  {
    // An entry without the target attribute should return null.
    Entry e = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    assertNull(e.getAttributeValueAsDate("a"));

    // An entry with the target attribute but without any values should return
    // null.
    e.setAttribute(new Attribute("a"));
    assertNull(e.getAttributeValueAsDate("a"));

    // Test values that should return a valid value.
    LinkedHashMap<String,Date> validValues =
         new LinkedHashMap<String,Date>();
    Date d = new Date();
    validValues.put(encodeGeneralizedTime(d), d);

    for (String s : validValues.keySet())
    {
      e.setAttribute(new Attribute("a", s));
      assertNotNull(e.getAttributeValueAsDate("a"));
      assertEquals(e.getAttributeValueAsDate("a"), validValues.get(s));
    }

    // Test values that should not return a valid value.
    String[] invalidValues =
    {
      "",
      "invalid"
    };

    for (String s : invalidValues)
    {
      e.setAttribute(new Attribute("a", s));
      assertNull(e.getAttributeValueAsDate("a"));
    }
  }



  /**
   * Tests the {@code getValueAsDN} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValueAsDN()
         throws Exception
  {
    // An entry without the target attribute should return null.
    Entry e = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    assertNull(e.getAttributeValueAsDN("a"));

    // An entry with the target attribute but without any values should return
    // null.
    e.setAttribute(new Attribute("a"));
    assertNull(e.getAttributeValueAsDN("a"));

    // Test values that should return a valid value.
    e.setAttribute(new Attribute("a", ""));
    assertEquals(e.getAttributeValueAsDN("a"), DN.NULL_DN);

    e.setAttribute(new Attribute("a", "dc=example,dc=com"));
    assertEquals(e.getAttributeValueAsDN("a"), new DN("dc=example,dc=com"));

    // Test values that should not return a valid value.
    e.setAttribute(new Attribute("a", "invalid"));
    assertNull(e.getAttributeValueAsDN("a"));
  }



  /**
   * Tests the {@code getValueAsInteger} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValueAsInteger()
         throws Exception
  {
    // An entry without the target attribute should return null.
    Entry e = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    assertNull(e.getAttributeValueAsInteger("a"));

    // An entry with the target attribute but without any values should return
    // null.
    e.setAttribute(new Attribute("a"));
    assertNull(e.getAttributeValueAsInteger("a"));

    // Test values that should return a valid value.
    LinkedHashMap<String,Integer> validValues =
         new LinkedHashMap<String,Integer>();
    validValues.put("0", 0);
    validValues.put("1", 1);
    validValues.put("-1", -1);
    validValues.put("1234", 1234);
    validValues.put("-5678", -5678);
    validValues.put("-2147483648", Integer.MIN_VALUE);
    validValues.put("2147483647", Integer.MAX_VALUE);

    for (String s : validValues.keySet())
    {
      e.setAttribute(new Attribute("a", s));
      assertNotNull(e.getAttributeValueAsInteger("a"));
      assertEquals(e.getAttributeValueAsInteger("a"), validValues.get(s));
    }

    // Test values that should not return a valid value.
    String[] invalidValues =
    {
      "",
      "invalid",
      String.valueOf(1L + Integer.MAX_VALUE),
      String.valueOf(-1L + Integer.MIN_VALUE),
      String.valueOf(Long.MAX_VALUE) + '0',
      String.valueOf(Long.MIN_VALUE) + '0'
    };

    for (String s : invalidValues)
    {
      e.setAttribute(new Attribute("a", s));
      assertNull(e.getAttributeValueAsInteger("a"));
    }
  }



  /**
   * Tests the {@code getValueAsLong} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValueAsLong()
         throws Exception
  {
    // An entry without the target attribute should return null.
    Entry e = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    assertNull(e.getAttributeValueAsLong("a"));

    // An entry with the target attribute but without any values should return
    // null.
    e.setAttribute(new Attribute("a"));
    assertNull(e.getAttributeValueAsLong("a"));

    // Test values that should return a valid value.
    LinkedHashMap<String,Long> validValues =
         new LinkedHashMap<String,Long>();
    validValues.put("0", 0L);
    validValues.put("1", 1L);
    validValues.put("-1", -1L);
    validValues.put("1234", 1234L);
    validValues.put("-5678", -5678L);
    validValues.put("-2147483648", Long.valueOf(Integer.MIN_VALUE));
    validValues.put("2147483647", Long.valueOf(Integer.MAX_VALUE));
    validValues.put("-2147483649", (Integer.MIN_VALUE - 1L));
    validValues.put("2147483648", (Integer.MAX_VALUE + 1L));
    validValues.put("-9223372036854775808", Long.MIN_VALUE);
    validValues.put("9223372036854775807", Long.MAX_VALUE);

    for (String s : validValues.keySet())
    {
      e.setAttribute(new Attribute("a", s));
      assertNotNull(e.getAttributeValueAsLong("a"));
      assertEquals(e.getAttributeValueAsLong("a"), validValues.get(s));
    }

    // Test values that should not return a valid value.
    String[] invalidValues =
    {
      "",
      "invalid",
      String.valueOf(Long.MAX_VALUE) + '0',
      String.valueOf(Long.MIN_VALUE) + '0'
    };

    for (String s : invalidValues)
    {
      e.setAttribute(new Attribute("a", s));
      assertNull(e.getAttributeValueAsLong("a"));
    }
  }



  /**
   * Tests the {@code getAttributesWithOptions} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAttributesWithOptions()
         throws Exception
  {
    Entry e = new Entry("dn: uid=test.user,ou=People,dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: person",
                        "objectClass: organizationalPerson",
                        "objectClass: inetOrgPerson",
                        "uid: test.user",
                        "givenName: Test",
                        "givenName;lang-en;lang-es: Test",
                        "sn: User",
                        "sn;lang-en: User",
                        "sn;lang-es: Usuario",
                        "cn: Test User",
                        "cn;lang-en: Test User",
                        "cn;lang-es: Test Usuario",
                        "userPassword: password",
                        "displayName: Testy-Boy",
                        "displayName;lang-en: Testy-Boy",
                        "description;lang-en: This is the description");

    HashSet<String> nullSet  = null;
    HashSet<String> emptySet = new HashSet<String>();
    HashSet<String> enSet    = new HashSet<String>();
    HashSet<String> esSet    = new HashSet<String>();
    HashSet<String> enYesSet = new HashSet<String>();

    enSet.add("lang-en");
    enYesSet.add("lang-en");

    esSet.add("lang-es");
    enYesSet.add("lang-es");

    // Test with a nonexistent attribute.
    List<Attribute> attrs = e.getAttributesWithOptions("nonexistent", nullSet);
    assertEquals(attrs.size(), 0);
    attrs = e.getAttributesWithOptions("nonexistent", emptySet);
    assertEquals(attrs.size(), 0);
    attrs = e.getAttributesWithOptions("nonexistent", enSet);
    assertEquals(attrs.size(), 0);
    attrs = e.getAttributesWithOptions("nonexistent", esSet);
    assertEquals(attrs.size(), 0);
    attrs = e.getAttributesWithOptions("nonexistent", enYesSet);
    assertEquals(attrs.size(), 0);
    attrs = e.getAttributesWithOptions("nonexistent", new HashSet<String>());
    assertEquals(attrs.size(), 0);

    // Test with an attribute that doesn't contain any options.
    attrs = e.getAttributesWithOptions("objectclass", nullSet);
    assertEquals(attrs.size(), 1);
    attrs = e.getAttributesWithOptions("objectclass", emptySet);
    assertEquals(attrs.size(), 1);
    attrs = e.getAttributesWithOptions("objectclass", enSet);
    assertEquals(attrs.size(), 0);
    attrs = e.getAttributesWithOptions("objectclass", esSet);
    assertEquals(attrs.size(), 0);
    attrs = e.getAttributesWithOptions("objectclass", enYesSet);
    assertEquals(attrs.size(), 0);

    // Test with an attribute that only has a value with a single option and
    // no values without any options.
    attrs = e.getAttributesWithOptions("description", nullSet);
    assertEquals(attrs.size(), 1);
    attrs = e.getAttributesWithOptions("description", emptySet);
    assertEquals(attrs.size(), 1);
    attrs = e.getAttributesWithOptions("description", enSet);
    assertEquals(attrs.size(), 1);
    attrs = e.getAttributesWithOptions("description", esSet);
    assertEquals(attrs.size(), 0);
    attrs = e.getAttributesWithOptions("description", enYesSet);
    assertEquals(attrs.size(), 0);

    // Test with an attribute that only has a value without options and a value
    // with a single option.
    attrs = e.getAttributesWithOptions("displayName", nullSet);
    assertEquals(attrs.size(), 2);
    attrs = e.getAttributesWithOptions("displayName", emptySet);
    assertEquals(attrs.size(), 2);
    attrs = e.getAttributesWithOptions("displayName", enSet);
    assertEquals(attrs.size(), 1);
    attrs = e.getAttributesWithOptions("displayName", esSet);
    assertEquals(attrs.size(), 0);
    attrs = e.getAttributesWithOptions("displayName", enYesSet);
    assertEquals(attrs.size(), 0);

    // Test with an attribute that has a value with no options, a value with an
    // English option, and a value with a Spanish option.
    attrs = e.getAttributesWithOptions("sn", nullSet);
    assertEquals(attrs.size(), 3);
    attrs = e.getAttributesWithOptions("sn", emptySet);
    assertEquals(attrs.size(), 3);
    attrs = e.getAttributesWithOptions("sn", enSet);
    assertEquals(attrs.size(), 1);
    attrs = e.getAttributesWithOptions("sn", esSet);
    assertEquals(attrs.size(), 1);
    attrs = e.getAttributesWithOptions("sn", enYesSet);
    assertEquals(attrs.size(), 0);

    // Test with an attribute that has a value with no options, a value with
    // both English and Spanish options.
    attrs = e.getAttributesWithOptions("givenName", nullSet);
    assertEquals(attrs.size(), 2);
    attrs = e.getAttributesWithOptions("givenName", emptySet);
    assertEquals(attrs.size(), 2);
    attrs = e.getAttributesWithOptions("givenName", enSet);
    assertEquals(attrs.size(), 1);
    attrs = e.getAttributesWithOptions("givenName", esSet);
    assertEquals(attrs.size(), 1);
    attrs = e.getAttributesWithOptions("givenName", enYesSet);
    assertEquals(attrs.size(), 1);
  }



  /**
   * Tests the methods involving creating LDIF encoding and decoding.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDIFMethods()
         throws Exception
  {
    Entry e = new Entry("dn: uid=test.user,ou=People,dc=example,dc=com",
                        "objectClass: top",
                        "objectclass: person",
                        "uid: test.user",
                        "objectClass: organizationalPerson",
                        "objectClass:inetOrgPerson",
                        "givenName:    Test",
                        "sn: User",
                        "cn:: VGVzdCBVc2Vy",
                        "description:",
                        "description::Zm9v",
                        "description: bar",
                        "description: Jos\u00e9 Jalape\u00f1o",
                        "carLicense::",
                        "carLicense:: OmZvbw==",
                        "carLicense:: PGZvbw==",
                        "carLicense:: IGZvbw==",
                        "carLicense:: YmFyIA==",
                        "carLicense:: Zm9vAGJhcg==");

    assertEquals(e.getDN(), "uid=test.user,ou=People,dc=example,dc=com");

    Attribute ocAttr = e.getAttribute("objectClass");
    assertNotNull(ocAttr);
    String[] ocValues = ocAttr.getValues();
    assertNotNull(ocValues);
    assertEquals(ocValues.length, 4);

    assertTrue(e.hasAttribute("givenName"));
    assertTrue(e.hasAttributeValue("givenName", "Test"));

    assertTrue(e.hasAttribute("cn"));
    assertTrue(e.hasAttributeValue("cn", "Test User"));

    Attribute descriptionAttr = e.getAttribute("description");
    assertNotNull(descriptionAttr);
    assertEquals(descriptionAttr.getValues().length, 4);
    assertTrue(e.hasAttributeValue("description", ""));
    assertTrue(e.hasAttributeValue("description", "foo"));
    assertTrue(e.hasAttributeValue("description", "bar"));
    assertTrue(e.hasAttributeValue("description", "Jos\u00e9 Jalape\u00f1o"));

    assertTrue(e.hasAttributeValue("carlicense", ""));
    assertTrue(e.hasAttributeValue("carlicense", ":foo"));
    assertTrue(e.hasAttributeValue("carlicense", "<foo"));
    assertTrue(e.hasAttributeValue("carlicense", " foo"));
    assertTrue(e.hasAttributeValue("carlicense", "bar "));
    assertTrue(e.hasAttributeValue("carlicense", "foo\u0000bar"));

    Entry e2 = new Entry(e.toLDIF(78));
    assertEquals(e.hashCode(), e2.hashCode());
    assertEquals(e, e2);
    assertEquals(e.toLDIFString(), e2.toLDIFString());
  }



  /**
   * Tests the {@code equals} method with various conditions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEquals()
         throws Exception
  {
    Entry e = new Entry("dc=example,dc=com");
    e.hashCode();

    assertFalse(e.equals(null));
    assertTrue(e.equals(e));
    assertFalse(e.equals("dc=example,dc=com"));
    assertTrue(e.equals(new Entry("dc=example,dc=com")));
    assertTrue(e.equals(new Entry(new DN("dc=example,dc=com"))));
    assertFalse(e.equals(new Entry("invalid")));
    assertFalse(e.equals(new Entry("dc=example,dc=net")));

    e = new Entry("invalid");
    e.hashCode();
    assertFalse(e.equals(new Entry("dc=example,dc=com")));
    assertTrue(e.equals(new Entry("invalid")));

    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };

    e = new Entry("dc=example,dc=com", attrs);
    e.hashCode();
    assertFalse(e.equals(new Entry("dc=example,dc=com")));
    assertTrue(e.equals(new Entry("dc=example,dc=com", attrs)));

    assertTrue(e.addAttribute("description", "foo"));
    assertFalse(e.equals(new Entry("dc=example,dc=com", attrs)));

    e = new Entry("dc=example,dc=com", attrs);
    e.hashCode();
    assertFalse(e.equals(new Entry("dc=example,dc=com")));
    assertTrue(e.equals(new Entry("dc=example,dc=com", attrs)));

    attrs = new Attribute[]
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
      new Attribute("description", "foo", "bar")
    };

    assertTrue(e.addAttribute("description", "foo"));
    assertFalse(e.equals(new Entry("dc=example,dc=com", attrs)));
  }



  /**
   * Tests the {@code diff} method for the case in which the source and target
   * entries are the same object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDiffIdentity()
         throws Exception
  {
    Entry e = new Entry("dn: dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: domain",
                        "dc: example");

    assertTrue(Entry.diff(e, e, true).isEmpty());
    assertTrue(Entry.diff(e, e, false).isEmpty());

    assertTrue(Entry.diff(e, e, true, true).isEmpty());
    assertTrue(Entry.diff(e, e, false, true).isEmpty());

    assertTrue(Entry.diff(e, e, true, false).isEmpty());
    assertTrue(Entry.diff(e, e, false, false).isEmpty());
  }



  /**
   * Tests the {@code diff} method for the case in which the source and target
   * entries are equivalent entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDiffEquivalent()
         throws Exception
  {
    Entry e1 = new Entry("dn: dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: domain",
                        "dc: example");

    Entry e2 = new Entry("dn: dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: domain",
                        "dc: example");

    assertTrue(Entry.diff(e1, e2, true).isEmpty());
    assertTrue(Entry.diff(e1, e2, false).isEmpty());

    assertTrue(Entry.diff(e2, e1, true).isEmpty());
    assertTrue(Entry.diff(e2, e1, false).isEmpty());

    assertTrue(Entry.diff(e1, e2, true, "dc").isEmpty());
    assertTrue(Entry.diff(e1, e2, false, "dc").isEmpty());

    assertTrue(Entry.diff(e2, e1, true, "dc").isEmpty());
    assertTrue(Entry.diff(e2, e1, false, "dc").isEmpty());

    assertTrue(Entry.diff(e1, e2, true, "dc", "objectClass").isEmpty());
    assertTrue(Entry.diff(e1, e2, false, "dc", "objectClass").isEmpty());

    assertTrue(Entry.diff(e2, e1, true, "dc", "objectClass").isEmpty());
    assertTrue(Entry.diff(e2, e1, false, "dc", "objectClass").isEmpty());

    assertTrue(Entry.diff(e1, e2, true, true).isEmpty());
    assertTrue(Entry.diff(e1, e2, false, true).isEmpty());

    assertTrue(Entry.diff(e2, e1, true, true).isEmpty());
    assertTrue(Entry.diff(e2, e1, false, true).isEmpty());

    assertTrue(Entry.diff(e1, e2, true, true, "dc").isEmpty());
    assertTrue(Entry.diff(e1, e2, false, true, "dc").isEmpty());

    assertTrue(Entry.diff(e2, e1, true, true, "dc").isEmpty());
    assertTrue(Entry.diff(e2, e1, false, true, "dc").isEmpty());

    assertTrue(Entry.diff(e1, e2, true, true, "dc", "objectClass").isEmpty());
    assertTrue(Entry.diff(e1, e2, false, true, "dc", "objectClass").isEmpty());

    assertTrue(Entry.diff(e2, e1, true, true, "dc", "objectClass").isEmpty());
    assertTrue(Entry.diff(e2, e1, false, true, "dc", "objectClass").isEmpty());

    assertTrue(Entry.diff(e1, e2, true, false).isEmpty());
    assertTrue(Entry.diff(e1, e2, false, false).isEmpty());

    assertTrue(Entry.diff(e2, e1, true, false).isEmpty());
    assertTrue(Entry.diff(e2, e1, false, false).isEmpty());

    assertTrue(Entry.diff(e1, e2, true, false, "dc").isEmpty());
    assertTrue(Entry.diff(e1, e2, false, false, "dc").isEmpty());

    assertTrue(Entry.diff(e2, e1, true, false, "dc").isEmpty());
    assertTrue(Entry.diff(e2, e1, false, false, "dc").isEmpty());

    assertTrue(Entry.diff(e1, e2, true, false, "dc", "objectClass").isEmpty());
    assertTrue(Entry.diff(e1, e2, false, false, "dc", "objectClass").isEmpty());

    assertTrue(Entry.diff(e2, e1, true, false, "dc", "objectClass").isEmpty());
    assertTrue(Entry.diff(e2, e1, false, false, "dc", "objectClass").isEmpty());
  }



  /**
   * Tests the {@code diff} method for the case in which the source and target
   * entries have all the same attributes but different DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDiffEquivalentDifferentDNs()
         throws Exception
  {
    Entry e1 = new Entry("dn: dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: organization",
                        "objectClass: dcObject",
                        "dc: example",
                        "o: example.com");

    Entry e2 = new Entry("dn: o=example.com",
                         "objectClass: top",
                         "objectClass: organization",
                         "objectClass: dcObject",
                         "dc: example",
                         "o: example.com");

    assertTrue(Entry.diff(e1, e2, true).isEmpty());
    assertTrue(Entry.diff(e1, e2, false).isEmpty());

    assertTrue(Entry.diff(e2, e1, true).isEmpty());
    assertTrue(Entry.diff(e2, e1, false).isEmpty());

    assertTrue(Entry.diff(e1, e2, true, "dc").isEmpty());
    assertTrue(Entry.diff(e1, e2, false, "dc").isEmpty());

    assertTrue(Entry.diff(e2, e1, true, "dc").isEmpty());
    assertTrue(Entry.diff(e2, e1, false, "dc").isEmpty());

    assertTrue(Entry.diff(e1, e2, true, "dc", "objectClass", "o").isEmpty());
    assertTrue(Entry.diff(e1, e2, false, "dc", "objectClass", "o").isEmpty());

    assertTrue(Entry.diff(e2, e1, true, "dc", "objectClass", "o").isEmpty());
    assertTrue(Entry.diff(e2, e1, false, "dc", "objectClass", "o").isEmpty());

    assertTrue(Entry.diff(e1, e2, true, true).isEmpty());
    assertTrue(Entry.diff(e1, e2, false, true).isEmpty());

    assertTrue(Entry.diff(e2, e1, true, true).isEmpty());
    assertTrue(Entry.diff(e2, e1, false, true).isEmpty());

    assertTrue(Entry.diff(e1, e2, true, true, "dc").isEmpty());
    assertTrue(Entry.diff(e1, e2, false, true, "dc").isEmpty());

    assertTrue(Entry.diff(e2, e1, true, true, "dc").isEmpty());
    assertTrue(Entry.diff(e2, e1, false, true, "dc").isEmpty());

    assertTrue(Entry.diff(e1, e2, true, true, "dc", "objectClass",
         "o").isEmpty());
    assertTrue(Entry.diff(e1, e2, false, true, "dc", "objectClass",
         "o").isEmpty());

    assertTrue(Entry.diff(e2, e1, true, true, "dc", "objectClass",
         "o").isEmpty());
    assertTrue(Entry.diff(e2, e1, false, true, "dc", "objectClass",
         "o").isEmpty());

    assertTrue(Entry.diff(e1, e2, true, false).isEmpty());
    assertTrue(Entry.diff(e1, e2, false, false).isEmpty());

    assertTrue(Entry.diff(e2, e1, true, false).isEmpty());
    assertTrue(Entry.diff(e2, e1, false, false).isEmpty());

    assertTrue(Entry.diff(e1, e2, true, false, "dc").isEmpty());
    assertTrue(Entry.diff(e1, e2, false, false, "dc").isEmpty());

    assertTrue(Entry.diff(e2, e1, true, false, "dc").isEmpty());
    assertTrue(Entry.diff(e2, e1, false, false, "dc").isEmpty());

    assertTrue(Entry.diff(e1, e2, true, false, "dc", "objectClass",
         "o").isEmpty());
    assertTrue(Entry.diff(e1, e2, false, false, "dc", "objectClass",
         "o").isEmpty());

    assertTrue(Entry.diff(e2, e1, true, false, "dc", "objectClass",
         "o").isEmpty());
    assertTrue(Entry.diff(e2, e1, false, false, "dc", "objectClass",
         "o").isEmpty());
  }



  /**
   * Tests the {@code diff} method for the case in which the only difference is
   * in the RDN attribute value and there's only one value for that attribute
   * type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDiffDifferentRDNValueSingle()
         throws Exception
  {
    Entry e1 = new Entry("dn: ou=People,dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: organizationalUnit",
                        "ou: People");

    Entry e2 = new Entry("dn: ou=Users,dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: organizationalUnit",
                        "ou: Users");

    assertTrue(Entry.diff(e1, e2, true).isEmpty());
    assertFalse(Entry.diff(e1, e2, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, false).size(), 2);

    assertTrue(Entry.diff(e2, e1, true).isEmpty());
    assertFalse(Entry.diff(e2, e1, false).isEmpty());
    assertEquals(Entry.diff(e2, e1, false).size(), 2);

    assertTrue(Entry.diff(e1, e2, true, "ou").isEmpty());
    assertFalse(Entry.diff(e1, e2, false, "ou").isEmpty());
    assertEquals(Entry.diff(e1, e2, false, "ou").size(), 2);

    assertTrue(Entry.diff(e2, e1, true, "objectClass").isEmpty());
    assertTrue(Entry.diff(e2, e1, false, "objectClass").isEmpty());

    assertTrue(Entry.diff(e1, e2, true, true).isEmpty());
    assertFalse(Entry.diff(e1, e2, false, true).isEmpty());
    assertEquals(Entry.diff(e1, e2, false, true).size(), 2);

    assertTrue(Entry.diff(e2, e1, true, true).isEmpty());
    assertFalse(Entry.diff(e2, e1, false, true).isEmpty());
    assertEquals(Entry.diff(e2, e1, false, true).size(), 2);

    assertTrue(Entry.diff(e1, e2, true, true, "ou").isEmpty());
    assertFalse(Entry.diff(e1, e2, false, true, "ou").isEmpty());
    assertEquals(Entry.diff(e1, e2, false, true, "ou").size(), 2);

    assertTrue(Entry.diff(e2, e1, true, true, "objectClass").isEmpty());
    assertTrue(Entry.diff(e2, e1, false, true, "objectClass").isEmpty());

    assertTrue(Entry.diff(e1, e2, true, false).isEmpty());
    assertFalse(Entry.diff(e1, e2, false, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, false, false).size(), 1);

    assertTrue(Entry.diff(e2, e1, true, false).isEmpty());
    assertFalse(Entry.diff(e2, e1, false, false).isEmpty());
    assertEquals(Entry.diff(e2, e1, false, false).size(), 1);

    assertTrue(Entry.diff(e1, e2, true, false, "ou").isEmpty());
    assertFalse(Entry.diff(e1, e2, false, false, "ou").isEmpty());
    assertEquals(Entry.diff(e1, e2, false, false, "ou").size(), 1);

    assertTrue(Entry.diff(e2, e1, true, false, "objectClass").isEmpty());
    assertTrue(Entry.diff(e2, e1, false, false, "objectClass").isEmpty());
  }



  /**
   * Tests the {@code diff} method for the case in which the only difference is
   * in the RDN attribute value and there are multiple values for that attribute
   * type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDiffDifferentRDNValueMultiple()
         throws Exception
  {
    Entry e1 = new Entry("dn: ou=People,dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: organizationalUnit",
                        "ou: People",
                        "ou: Alternate OU");

    Entry e2 = new Entry("dn: ou=Users,dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: organizationalUnit",
                        "ou: Users",
                        "ou: Alternate OU");

    assertTrue(Entry.diff(e1, e2, true).isEmpty());
    assertFalse(Entry.diff(e1, e2, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, false).size(), 2);

    assertTrue(Entry.diff(e2, e1, true).isEmpty());
    assertFalse(Entry.diff(e2, e1, false).isEmpty());
    assertEquals(Entry.diff(e2, e1, false).size(), 2);

    assertTrue(Entry.diff(e1, e2, true, "ou").isEmpty());
    assertFalse(Entry.diff(e1, e2, false, "ou").isEmpty());
    assertEquals(Entry.diff(e1, e2, false, "ou").size(), 2);

    assertTrue(Entry.diff(e2, e1, true, "ou").isEmpty());
    assertFalse(Entry.diff(e2, e1, false, "ou").isEmpty());
    assertEquals(Entry.diff(e2, e1, false, "ou").size(), 2);

    assertTrue(Entry.diff(e1, e2, true, "ou", "objectClasses").isEmpty());
    assertFalse(Entry.diff(e1, e2, false, "ou", "objectClasses").isEmpty());
    assertEquals(Entry.diff(e1, e2, false, "ou", "objectClasses").size(), 2);

    assertTrue(Entry.diff(e2, e1, true, "ou", "objectClasses").isEmpty());
    assertFalse(Entry.diff(e2, e1, false, "ou", "objectClasses").isEmpty());
    assertEquals(Entry.diff(e2, e1, false, "ou", "objectClasses").size(), 2);

    assertTrue(Entry.diff(e1, e2, true, true).isEmpty());
    assertFalse(Entry.diff(e1, e2, false, true).isEmpty());
    assertEquals(Entry.diff(e1, e2, false, true).size(), 2);

    assertTrue(Entry.diff(e2, e1, true, true).isEmpty());
    assertFalse(Entry.diff(e2, e1, false, true).isEmpty());
    assertEquals(Entry.diff(e2, e1, false, true).size(), 2);

    assertTrue(Entry.diff(e1, e2, true, true, "ou").isEmpty());
    assertFalse(Entry.diff(e1, e2, false, true, "ou").isEmpty());
    assertEquals(Entry.diff(e1, e2, false, true, "ou").size(), 2);

    assertTrue(Entry.diff(e2, e1, true, true, "ou").isEmpty());
    assertFalse(Entry.diff(e2, e1, false, true, "ou").isEmpty());
    assertEquals(Entry.diff(e2, e1, false, true, "ou").size(), 2);

    assertTrue(Entry.diff(e1, e2, true, true, "ou", "objectClasses").isEmpty());
    assertFalse(Entry.diff(e1, e2, false, true, "ou",
         "objectClasses").isEmpty());
    assertEquals(Entry.diff(e1, e2, false, true, "ou",
         "objectClasses").size(), 2);

    assertTrue(Entry.diff(e2, e1, true, true, "ou",
         "objectClasses").isEmpty());
    assertFalse(Entry.diff(e2, e1, false, true, "ou",
         "objectClasses").isEmpty());
    assertEquals(Entry.diff(e2, e1, false, true, "ou",
         "objectClasses").size(), 2);

    assertTrue(Entry.diff(e1, e2, true, false).isEmpty());
    assertFalse(Entry.diff(e1, e2, false, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, false, false).size(), 1);

    assertTrue(Entry.diff(e2, e1, true, false).isEmpty());
    assertFalse(Entry.diff(e2, e1, false, false).isEmpty());
    assertEquals(Entry.diff(e2, e1, false, false).size(), 1);

    assertTrue(Entry.diff(e1, e2, true, false, "ou").isEmpty());
    assertFalse(Entry.diff(e1, e2, false, false, "ou").isEmpty());
    assertEquals(Entry.diff(e1, e2, false, false, "ou").size(), 1);

    assertTrue(Entry.diff(e2, e1, true, false, "ou").isEmpty());
    assertFalse(Entry.diff(e2, e1, false, false, "ou").isEmpty());
    assertEquals(Entry.diff(e2, e1, false, false, "ou").size(), 1);

    assertTrue(Entry.diff(e1, e2, true, false, "ou",
         "objectClasses").isEmpty());
    assertFalse(Entry.diff(e1, e2, false, false, "ou",
         "objectClasses").isEmpty());
    assertEquals(Entry.diff(e1, e2, false, false, "ou",
         "objectClasses").size(), 1);

    assertTrue(Entry.diff(e2, e1, true, false, "ou",
         "objectClasses").isEmpty());
    assertFalse(Entry.diff(e2, e1, false, false, "ou",
         "objectClasses").isEmpty());
    assertEquals(Entry.diff(e2, e1, false, false, "ou",
         "objectClasses").size(), 1);
  }



  /**
   * Tests the {@code diff} method for the case in which the only difference is
   * in the RDN attribute where each entry has only one value for the RDN
   * attribute type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDiffDifferentRDNAttributeSingle()
         throws Exception
  {
    Entry e1 = new Entry("dn: cn=People,dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: organizationalUnit",
                        "cn: People");

    Entry e2 = new Entry("dn: ou=People,dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: organizationalUnit",
                        "ou: People");

    assertTrue(Entry.diff(e1, e2, true).isEmpty());
    assertFalse(Entry.diff(e1, e2, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, false).size(), 2);

    assertTrue(Entry.diff(e2, e1, true).isEmpty());
    assertFalse(Entry.diff(e2, e1, false).isEmpty());
    assertEquals(Entry.diff(e2, e1, false).size(), 2);

    assertTrue(Entry.diff(e1, e2, true, true).isEmpty());
    assertFalse(Entry.diff(e1, e2, false, true).isEmpty());
    assertEquals(Entry.diff(e1, e2, false, true).size(), 2);

    assertTrue(Entry.diff(e2, e1, true, true).isEmpty());
    assertFalse(Entry.diff(e2, e1, false, true).isEmpty());
    assertEquals(Entry.diff(e2, e1, false, true).size(), 2);

    assertFalse(Entry.diff(e1, e2, true, false).isEmpty());
    assertFalse(Entry.diff(e1, e2, false, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, false, false).size(), 2);

    assertFalse(Entry.diff(e2, e1, true, false).isEmpty());
    assertFalse(Entry.diff(e2, e1, false, false).isEmpty());
    assertEquals(Entry.diff(e2, e1, false, false).size(), 2);
  }



  /**
   * Tests the {@code diff} method for the case in which the only difference is
   * in the RDN attribute where each entry has multiple values for the RDN
   * attribute type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDiffDifferentRDNAttribute()
         throws Exception
  {
    Entry e1 = new Entry("dn: cn=People,dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: organizationalUnit",
                        "cn: People",
                        "cn: Alternate CN");

    Entry e2 = new Entry("dn: ou=People,dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: organizationalUnit",
                        "ou: People",
                        "ou: Alternate OU");

    assertFalse(Entry.diff(e1, e2, true).isEmpty());
    assertEquals(Entry.diff(e1, e2, true).size(), 2);
    assertFalse(Entry.diff(e1, e2, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, false).size(), 2);

    assertFalse(Entry.diff(e2, e1, true).isEmpty());
    assertEquals(Entry.diff(e2, e1, true).size(), 2);
    assertFalse(Entry.diff(e2, e1, false).isEmpty());
    assertEquals(Entry.diff(e2, e1, false).size(), 2);

    assertFalse(Entry.diff(e1, e2, true, true).isEmpty());
    assertEquals(Entry.diff(e1, e2, true, true).size(), 2);
    assertFalse(Entry.diff(e1, e2, false, true).isEmpty());
    assertEquals(Entry.diff(e1, e2, false, true).size(), 2);

    assertFalse(Entry.diff(e2, e1, true, true).isEmpty());
    assertEquals(Entry.diff(e2, e1, true, true).size(), 2);
    assertFalse(Entry.diff(e2, e1, false, true).isEmpty());
    assertEquals(Entry.diff(e2, e1, false, true).size(), 2);

    assertFalse(Entry.diff(e1, e2, true, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, true, false).size(), 2);
    assertFalse(Entry.diff(e1, e2, false, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, false, false).size(), 2);

    assertFalse(Entry.diff(e2, e1, true, false).isEmpty());
    assertEquals(Entry.diff(e2, e1, true, false).size(), 2);
    assertFalse(Entry.diff(e2, e1, false, false).isEmpty());
    assertEquals(Entry.diff(e2, e1, false, false).size(), 2);
  }



  /**
   * Tests the {@code diff} method for the case in which there is a difference
   * in an attribute value in which that value is not in the RDN but another
   * value of the same attribute is.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDiffDifferentValueForRDNType()
         throws Exception
  {
    Entry e1 = new Entry("dn: ou=People,dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: organizationalUnit",
                        "ou: People",
                        "ou: Alternate OU");

    Entry e2 = new Entry("dn: ou=People,dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: organizationalUnit",
                        "ou: People",
                        "ou: Different OU");

    assertFalse(Entry.diff(e1, e2, true).isEmpty());
    assertEquals(Entry.diff(e1, e2, true).size(), 2);
    assertFalse(Entry.diff(e1, e2, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, false).size(), 2);

    assertFalse(Entry.diff(e2, e1, true).isEmpty());
    assertEquals(Entry.diff(e2, e1, true).size(), 2);
    assertFalse(Entry.diff(e2, e1, false).isEmpty());
    assertEquals(Entry.diff(e2, e1, false).size(), 2);

    assertFalse(Entry.diff(e1, e2, true, true).isEmpty());
    assertEquals(Entry.diff(e1, e2, true, true).size(), 2);
    assertFalse(Entry.diff(e1, e2, false, true).isEmpty());
    assertEquals(Entry.diff(e1, e2, false, true).size(), 2);

    assertFalse(Entry.diff(e2, e1, true, true).isEmpty());
    assertEquals(Entry.diff(e2, e1, true, true).size(), 2);
    assertFalse(Entry.diff(e2, e1, false, true).isEmpty());
    assertEquals(Entry.diff(e2, e1, false, true).size(), 2);

    assertFalse(Entry.diff(e1, e2, true, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, true, false).size(), 2);
    assertFalse(Entry.diff(e1, e2, false, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, false, false).size(), 1);

    assertFalse(Entry.diff(e2, e1, true, false).isEmpty());
    assertEquals(Entry.diff(e2, e1, true, false).size(), 2);
    assertFalse(Entry.diff(e2, e1, false, false).isEmpty());
    assertEquals(Entry.diff(e2, e1, false, false).size(), 1);
  }



  /**
   * Tests the {@code diff} method for the case in which there are multiple
   * differences in the attribute type used for the RDN, including the RDN
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDiffDifferentValueForRDNTypeIncludingRDNValue()
         throws Exception
  {
    Entry e1 = new Entry("dn: ou=People,dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: organizationalUnit",
                        "ou: People",
                        "ou: Alternate OU");

    Entry e2 = new Entry("dn: ou=Users,dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: organizationalUnit",
                        "ou: Users",
                        "ou: Different OU");

    assertFalse(Entry.diff(e1, e2, true).isEmpty());
    assertEquals(Entry.diff(e1, e2, true).size(), 2);
    assertFalse(Entry.diff(e1, e2, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, false).size(), 2);

    assertFalse(Entry.diff(e2, e1, true).isEmpty());
    assertEquals(Entry.diff(e2, e1, true).size(), 2);
    assertFalse(Entry.diff(e2, e1, false).isEmpty());
    assertEquals(Entry.diff(e2, e1, false).size(), 2);

    assertFalse(Entry.diff(e1, e2, true, true).isEmpty());
    assertEquals(Entry.diff(e1, e2, true, true).size(), 2);
    assertFalse(Entry.diff(e1, e2, false, true).isEmpty());
    assertEquals(Entry.diff(e1, e2, false, true).size(), 2);

    assertFalse(Entry.diff(e2, e1, true, true).isEmpty());
    assertEquals(Entry.diff(e2, e1, true, true).size(), 2);
    assertFalse(Entry.diff(e2, e1, false, true).isEmpty());
    assertEquals(Entry.diff(e2, e1, false, true).size(), 2);

    assertFalse(Entry.diff(e1, e2, true, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, true, false).size(), 2);
    assertFalse(Entry.diff(e1, e2, false, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, false, false).size(), 1);

    assertFalse(Entry.diff(e2, e1, true, false).isEmpty());
    assertEquals(Entry.diff(e2, e1, true, false).size(), 2);
    assertFalse(Entry.diff(e2, e1, false, false).isEmpty());
    assertEquals(Entry.diff(e2, e1, false, false).size(), 1);
  }



  /**
   * Tests the {@code diff} method with an entry with an invalid DN.  This is
   * just meant to get coverage for the code meant to handle an unparseable DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDiffInvalidDN()
         throws Exception
  {
    Entry e1 = new Entry("dn: dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: domain",
                        "dc: example",
                        "description: This isn't in the target entry");
    e1.setDN("invalid");

    Entry e2 = new Entry("dn: dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: domain",
                        "dc: example");
    e2.setDN("invalid");

    assertFalse(Entry.diff(e1, e2, true).isEmpty());
    assertEquals(Entry.diff(e1, e2, true).size(), 1);
    assertFalse(Entry.diff(e1, e2, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, false).size(), 1);

    assertFalse(Entry.diff(e2, e1, true).isEmpty());
    assertEquals(Entry.diff(e2, e1, true).size(), 1);
    assertFalse(Entry.diff(e2, e1, false).isEmpty());
    assertEquals(Entry.diff(e2, e1, false).size(), 1);

    assertFalse(Entry.diff(e1, e2, true, true).isEmpty());
    assertEquals(Entry.diff(e1, e2, true, true).size(), 1);
    assertFalse(Entry.diff(e1, e2, false, true).isEmpty());
    assertEquals(Entry.diff(e1, e2, false, true).size(), 1);

    assertFalse(Entry.diff(e2, e1, true, true).isEmpty());
    assertEquals(Entry.diff(e2, e1, true, true).size(), 1);
    assertFalse(Entry.diff(e2, e1, false, true).isEmpty());
    assertEquals(Entry.diff(e2, e1, false, true).size(), 1);

    assertFalse(Entry.diff(e1, e2, true, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, true, false).size(), 1);
    assertFalse(Entry.diff(e1, e2, false, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, false, false).size(), 1);

    assertFalse(Entry.diff(e2, e1, true, false).isEmpty());
    assertEquals(Entry.diff(e2, e1, true, false).size(), 1);
    assertFalse(Entry.diff(e2, e1, false, false).isEmpty());
    assertEquals(Entry.diff(e2, e1, false, false).size(), 1);
  }



  /**
   * Tests the {@code diff} method for a simple case in which the only
   * differences are in the RDN attribute and one additional attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDiffSimple()
         throws Exception
  {
    Entry e1 = new Entry("dn: cn=User 1,ou=People,dc=example,dc=com",
                         "objectClass: top",
                         "objectClass: person",
                         "objectClass: organizationalPerson",
                         "objectClass: inetOrgPerson",
                         "givenName: User",
                         "sn: One",
                         "cn: User 1",
                         "userPassword: password");

    Entry e2 = new Entry("dn: cn=User 2,ou=People,dc=example,dc=com",
                         "objectClass: top",
                         "objectClass: person",
                         "objectClass: organizationalPerson",
                         "objectClass: inetOrgPerson",
                         "givenName: User",
                         "sn: Two",
                         "cn: User 2",
                         "userPassword: password");

    assertFalse(Entry.diff(e1, e2, true).isEmpty());
    assertFalse(Entry.diff(e1, e2, false).isEmpty());

    assertFalse(Entry.diff(e2, e1, true).isEmpty());
    assertFalse(Entry.diff(e2, e1, false).isEmpty());

    assertTrue(Entry.diff(e1, e2, true, "givenName").isEmpty());
    assertTrue(Entry.diff(e1, e2, false, "givenName").isEmpty());

    assertTrue(Entry.diff(e2, e1, true, "givenName").isEmpty());
    assertTrue(Entry.diff(e2, e1, false, "givenName").isEmpty());

    assertFalse(Entry.diff(e1, e2, true, "sn").isEmpty());
    assertFalse(Entry.diff(e1, e2, false, "sn").isEmpty());

    assertFalse(Entry.diff(e2, e1, true, "sn").isEmpty());
    assertFalse(Entry.diff(e2, e1, false, "sn").isEmpty());

    assertTrue(Entry.diff(e1, e2, true, "cn").isEmpty());
    assertFalse(Entry.diff(e1, e2, false, "cn").isEmpty());

    assertTrue(Entry.diff(e2, e1, true, "cn").isEmpty());
    assertFalse(Entry.diff(e2, e1, false, "cn").isEmpty());

    assertFalse(Entry.diff(e1, e2, true, true).isEmpty());
    assertFalse(Entry.diff(e1, e2, false, true).isEmpty());

    assertFalse(Entry.diff(e2, e1, true, true).isEmpty());
    assertFalse(Entry.diff(e2, e1, false, true).isEmpty());

    assertTrue(Entry.diff(e1, e2, true, true, "givenName").isEmpty());
    assertTrue(Entry.diff(e1, e2, false, true, "givenName").isEmpty());

    assertTrue(Entry.diff(e2, e1, true, true, "givenName").isEmpty());
    assertTrue(Entry.diff(e2, e1, false, true, "givenName").isEmpty());

    assertFalse(Entry.diff(e1, e2, true, true, "sn").isEmpty());
    assertFalse(Entry.diff(e1, e2, false, true, "sn").isEmpty());

    assertFalse(Entry.diff(e2, e1, true, true, "sn").isEmpty());
    assertFalse(Entry.diff(e2, e1, false, true, "sn").isEmpty());

    assertTrue(Entry.diff(e1, e2, true, true, "cn").isEmpty());
    assertFalse(Entry.diff(e1, e2, false, true, "cn").isEmpty());

    assertTrue(Entry.diff(e2, e1, true, true, "cn").isEmpty());
    assertFalse(Entry.diff(e2, e1, false, true, "cn").isEmpty());

    assertFalse(Entry.diff(e1, e2, true, false).isEmpty());
    assertFalse(Entry.diff(e1, e2, false, false).isEmpty());

    assertFalse(Entry.diff(e2, e1, true, false).isEmpty());
    assertFalse(Entry.diff(e2, e1, false, false).isEmpty());

    assertTrue(Entry.diff(e1, e2, true, false, "givenName").isEmpty());
    assertTrue(Entry.diff(e1, e2, false, false, "givenName").isEmpty());

    assertTrue(Entry.diff(e2, e1, true, false, "givenName").isEmpty());
    assertTrue(Entry.diff(e2, e1, false, false, "givenName").isEmpty());

    assertFalse(Entry.diff(e1, e2, true, false, "sn").isEmpty());
    assertFalse(Entry.diff(e1, e2, false, false, "sn").isEmpty());

    assertFalse(Entry.diff(e2, e1, true, false, "sn").isEmpty());
    assertFalse(Entry.diff(e2, e1, false, false, "sn").isEmpty());

    assertTrue(Entry.diff(e1, e2, true, false, "cn").isEmpty());
    assertFalse(Entry.diff(e1, e2, false, false, "cn").isEmpty());

    assertTrue(Entry.diff(e2, e1, true, false, "cn").isEmpty());
    assertFalse(Entry.diff(e2, e1, false, false, "cn").isEmpty());
  }



  /**
   * Tests the {@code diff} method for a somewhat complex example in which there
   * are a number of differences of various types between the entries.  Also,
   * try to actually perform the resulting modification in the directory and
   * verify that the entry after the modification matches what we expected.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDiffComplexWithLDAPCheck()
         throws Exception
  {
    String entryDN = "givenName=User+sn=1,dc=example,dc=com";

    Entry e1 = new Entry("dn: " + entryDN,
                         "objectClass: top",
                         "objectClass: person",
                         "objectClass: organizationalPerson",
                         "objectClass: inetOrgPerson",
                         "uid: user.1",
                         "givenName: User",
                         "givenName: Yousir",
                         "sn: 1",
                         "sn: One",
                         "cn: User 1",
                         "cn: User One",
                         "cn: Yousir 1",
                         "cn: Yousir One",
                         "displayName: User One",
                         "roomNumber: 1234",
                         "telephoneNumber: +1 123 456 7890",
                         "carLicense: YOUSIR1",
                         "carLicense: U53R 0N3");

    Entry e2 = new Entry("dn: " + entryDN,
                         "objectClass: top",
                         "objectClass: person",
                         "objectClass: organizationalPerson",
                         "objectClass: inetOrgPerson",
                         "uid: user.one",
                         "givenName: User",
                         "sn: 1",
                         "sn: One",
                         "cn: User 1",
                         "cn: User One",
                         "cn: User I",
                         "roomNumber: 5678",
                         "telephoneNumber: +1 123 456 7890",
                         "preferredLanguage: EN-US",
                         "description: This is the first description value",
                         "description: This is the second description value");

    List<Modification> mods = Entry.diff(e1, e2, true);
    assertFalse(mods.isEmpty());

    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();

    try
    {
      conn.add(getTestBaseDN(), getBaseEntryAttributes());

      conn.add(e1);

      Entry originalEntry = conn.getEntry(entryDN);
      assertTrue(e1.equals(originalEntry));
      assertFalse(e2.equals(originalEntry));

      LDAPResult modifyResult = conn.modify(entryDN, mods);
      assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);

      Entry modifiedEntry = conn.getEntry(entryDN);
      assertEquals(modifiedEntry, e2);
      assertFalse(e1.equals(modifiedEntry));
      assertTrue(Entry.diff(e2, modifiedEntry, true).isEmpty());

      mods = Entry.diff(e2, e1, true);
      modifyResult = conn.modify(entryDN, mods);
      assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);

      Entry reModifiedEntry = conn.getEntry(entryDN);
      assertEquals(reModifiedEntry, e1);
      assertTrue(Entry.diff(e1, reModifiedEntry, true).isEmpty());
      assertFalse(e2.equals(reModifiedEntry));
    }
    finally
    {
      try
      {
        conn.delete(e1.getDN());
      } catch (Exception e) {}

      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
    }
  }



  /**
   * Tests the {@code diff} method for a simple case in which the only
   * difference is in an attribute with options.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDiffWithOptions()
         throws Exception
  {
    Entry e1 = new Entry("dn: cn=Test User,ou=People,dc=example,dc=com",
                         "objectClass: top",
                         "objectClass: person",
                         "objectClass: organizationalPerson",
                         "objectClass: inetOrgPerson",
                         "givenName: Test",
                         "sn: User",
                         "cn: Test User",
                         "userPassword: password",
                         "userCertificate;binary: binary-cert-1");

    Entry e2 = new Entry("dn: cn=Test User,ou=People,dc=example,dc=com",
                         "objectClass: top",
                         "objectClass: person",
                         "objectClass: organizationalPerson",
                         "objectClass: inetOrgPerson",
                         "givenName: Test",
                         "sn: User",
                         "cn: Test User",
                         "userPassword: password",
                         "userCertificate;binary: binary-cert-2");

    assertFalse(Entry.diff(e1, e2, true).isEmpty());
    assertFalse(Entry.diff(e1, e2, false).isEmpty());

    assertFalse(Entry.diff(e2, e1, true).isEmpty());
    assertFalse(Entry.diff(e2, e1, false).isEmpty());

    assertTrue(Entry.diff(e1, e2, true, "givenName").isEmpty());
    assertTrue(Entry.diff(e1, e2, false, "givenName").isEmpty());

    assertTrue(Entry.diff(e2, e1, true, "givenName").isEmpty());
    assertTrue(Entry.diff(e2, e1, false, "givenName").isEmpty());

    assertFalse(Entry.diff(e1, e2, true, "userCertificate").isEmpty());
    assertFalse(Entry.diff(e1, e2, false, "userCertificate").isEmpty());

    assertFalse(Entry.diff(e2, e1, true, "userCertificate").isEmpty());
    assertFalse(Entry.diff(e2, e1, false, "userCertificate").isEmpty());

    assertFalse(Entry.diff(e1, e2, true, "userCertificate;binary").isEmpty());
    assertFalse(Entry.diff(e1, e2, false, "userCertificate;binary").isEmpty());

    assertFalse(Entry.diff(e2, e1, true, "userCertificate;binary").isEmpty());
    assertFalse(Entry.diff(e2, e1, false, "userCertificate;binary").isEmpty());


    e1 = new Entry("dn: cn=Test User,ou=People,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: person",
                   "objectClass: organizationalPerson",
                   "objectClass: inetOrgPerson",
                   "givenName: Test",
                   "sn: User",
                   "cn: Test User",
                   "userPassword: password",
                   "userCertificate: binary-cert-1");

    e2 = new Entry("dn: cn=Test User,ou=People,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: person",
                   "objectClass: organizationalPerson",
                   "objectClass: inetOrgPerson",
                   "givenName: Test",
                   "sn: User",
                   "cn: Test User",
                   "userPassword: password",
                   "userCertificate: binary-cert-2");

    assertFalse(Entry.diff(e1, e2, true).isEmpty());
    assertFalse(Entry.diff(e1, e2, false).isEmpty());

    assertFalse(Entry.diff(e2, e1, true).isEmpty());
    assertFalse(Entry.diff(e2, e1, false).isEmpty());

    assertTrue(Entry.diff(e1, e2, true, "givenName").isEmpty());
    assertTrue(Entry.diff(e1, e2, false, "givenName").isEmpty());

    assertTrue(Entry.diff(e2, e1, true, "givenName").isEmpty());
    assertTrue(Entry.diff(e2, e1, false, "givenName").isEmpty());

    assertFalse(Entry.diff(e1, e2, true, "userCertificate").isEmpty());
    assertFalse(Entry.diff(e1, e2, false, "userCertificate").isEmpty());

    assertFalse(Entry.diff(e2, e1, true, "userCertificate").isEmpty());
    assertFalse(Entry.diff(e2, e1, false, "userCertificate").isEmpty());

    assertFalse(Entry.diff(e1, e2, true, "userCertificate;binary").isEmpty());
    assertFalse(Entry.diff(e1, e2, false, "userCertificate;binary").isEmpty());

    assertFalse(Entry.diff(e2, e1, true, "userCertificate;binary").isEmpty());
    assertFalse(Entry.diff(e2, e1, false, "userCertificate;binary").isEmpty());


    e1 = new Entry("dn: cn=Test User,ou=People,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: person",
                   "objectClass: organizationalPerson",
                   "objectClass: inetOrgPerson",
                   "givenName: Test",
                   "sn: User",
                   "cn: Test User",
                   "userPassword: password",
                   "userCertificate: binary-cert");

    e2 = new Entry("dn: cn=Test User,ou=People,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: person",
                   "objectClass: organizationalPerson",
                   "objectClass: inetOrgPerson",
                   "givenName: Test",
                   "sn: User",
                   "cn: Test User",
                   "userPassword: password",
                   "userCertificate;binary: binary-cert");

    assertFalse(Entry.diff(e1, e2, true).isEmpty());
    assertFalse(Entry.diff(e1, e2, false).isEmpty());

    assertFalse(Entry.diff(e2, e1, true).isEmpty());
    assertFalse(Entry.diff(e2, e1, false).isEmpty());

    assertTrue(Entry.diff(e1, e2, true, "givenName").isEmpty());
    assertTrue(Entry.diff(e1, e2, false, "givenName").isEmpty());

    assertTrue(Entry.diff(e2, e1, true, "givenName").isEmpty());
    assertTrue(Entry.diff(e2, e1, false, "givenName").isEmpty());

    assertFalse(Entry.diff(e1, e2, true, "userCertificate").isEmpty());
    assertFalse(Entry.diff(e1, e2, false, "userCertificate").isEmpty());

    assertFalse(Entry.diff(e2, e1, true, "userCertificate").isEmpty());
    assertFalse(Entry.diff(e2, e1, false, "userCertificate").isEmpty());

    assertFalse(Entry.diff(e1, e2, true, "userCertificate;binary").isEmpty());
    assertFalse(Entry.diff(e1, e2, false, "userCertificate;binary").isEmpty());

    assertFalse(Entry.diff(e2, e1, true, "userCertificate;binary").isEmpty());
    assertFalse(Entry.diff(e2, e1, false, "userCertificate;binary").isEmpty());
  }



  /**
   * Tests the {@code diff} method for a case in which an attribute has a
   * caseExactMatch matching rule and two entries differ only in the case of
   * the value for that attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDiffCaseSensitive()
         throws Exception
  {
    // Create a bare-bones schema that defines description to have a
    // caseExactMatch matching rule and a minimal set of attributes in the
    // domain and organizationalUnit object classes.
    final Schema schema = new Schema(new Entry(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( 2.5.4.0 NAME 'objectClass' EQUALITY " +
              "objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 " +
              "X-ORIGIN 'RFC 4512' )",
         "attributeTypes: ( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch " +
              "SUBSTR caseIgnoreSubstringsMatch SYNTAX " +
              "1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'RFC 4519' )",
         "attributeTypes: ( 2.5.4.11 NAME 'ou' SUP name X-ORIGIN 'RFC 4519' )",
         "attributeTypes: ( 2.5.4.13 NAME 'description' EQUALITY " +
              "caseExactMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " +
              "1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'RFC 4519 with " +
              "customization' )",
         "attributeTypes: ( 0.9.2342.19200300.100.1.25 NAME 'dc' EQUALITY " +
              "caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX " +
              "1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE X-ORIGIN " +
              "'RFC 4519' )",
         "objectClasses: ( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass " +
              "X-ORIGIN 'RFC 4512' )",
         "objectClasses: ( 2.5.6.5 NAME 'organizationalUnit' SUP top " +
              "STRUCTURAL MUST ou MAY description X-ORIGIN 'RFC 4519 with " +
              "customization' )",
         "objectClasses: ( 0.9.2342.19200300.100.4.13 NAME 'domain' SUP top " +
              "STRUCTURAL MUST dc X-ORIGIN 'RFC 4524 with customization' )"));

    Entry e1 = new Entry(schema,
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test",
         "description: Differs in Case");
    Entry e2 = new Entry(schema,
         "dn: ou=Test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Test",
         "description: differs in case");

    assertNotNull(e1.getSchema());
    assertNotNull(e2.getSchema());
    assertNotNull(InternalSDKHelper.getEntrySchema(e1));
    assertNotNull(InternalSDKHelper.getEntrySchema(e2));

    assertFalse(Entry.diff(e1, e2, true, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, true, false).size(), 1,
         String.valueOf(Entry.diff(e1, e2, true, false)));
    assertEquals(
         Entry.diff(e1, e2, true, false).get(0).getAttribute().getName(),
         "description");


    final File ldifFile1 = createTempFile(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test",
         "description: Differs in Case");
    final LDIFReader ldifReader1 = new LDIFReader(ldifFile1);
    ldifReader1.setSchema(schema);
    e1 = ldifReader1.readEntry();

    final File ldifFile2 = createTempFile(
         "dn: ou=Test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Test",
         "description: differs in case");
    final LDIFReader ldifReader2 = new LDIFReader(ldifFile2);
    ldifReader2.setSchema(schema);
    e2 = ldifReader2.readEntry();

    assertFalse(Entry.diff(e1, e2, true, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, true, false).size(), 1,
         String.valueOf(Entry.diff(e1, e2, true, false)));
    assertEquals(
         Entry.diff(e1, e2, true, false).get(0).getAttribute().getName(),
         "description");


    e1 = new Entry("ou=test,dc=example,dc=com", schema,
         new Attribute("objectClass", schema, "top", "organizationalUnit"),
         new Attribute("ou", schema, "test"),
         new Attribute("description", schema, "Differs in Case"));
    e2 = new Entry("ou=Test,dc=example,dc=com", schema,
         new Attribute("objectClass", schema, "top", "organizationalUnit"),
         new Attribute("ou", schema, "Test"),
         new Attribute("description", schema, "differs in case"));

    assertFalse(Entry.diff(e1, e2, true, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, true, false).size(), 1,
         String.valueOf(Entry.diff(e1, e2, true, false)));
    assertEquals(
         Entry.diff(e1, e2, true, false).get(0).getAttribute().getName(),
         "description");


    e1 = new Entry("ou=test,dc=example,dc=com", schema);
    e1.addAttribute("objectClass", "top", "organizationalUnit");
    e1.addAttribute("ou", "test");
    e1.addAttribute("description", "Differs in Case");

    e2 = new Entry("ou=Test,dc=example,dc=com", schema);
    e2.addAttribute("objectClass", "top", "organizationalUnit");
    e2.addAttribute("ou", "Test");
    e2.addAttribute("description", "differs in case");

    assertFalse(Entry.diff(e1, e2, true, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, true, false).size(), 1,
         String.valueOf(Entry.diff(e1, e2, true, false)));
    assertEquals(
         Entry.diff(e1, e2, true, false).get(0).getAttribute().getName(),
         "description");


    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setSchema(schema);

    final InMemoryDirectoryServer ds1 = new InMemoryDirectoryServer(cfg);
    ds1.startListening();

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSchema(true);

    final LDAPConnection conn1 = ds1.getConnection(options);
    conn1.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    conn1.add(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test",
         "description: Differs in Case");
    e1 = conn1.getEntry("ou=test,dc=example,dc=com", "objectClass", "ou",
         "description");
    conn1.close();
    ds1.shutDown(true);

    final InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(cfg);
    ds2.startListening();

    final LDAPConnection conn2 = ds2.getConnection(options);
    conn2.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    conn2.add(
         "dn: ou=Test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Test",
         "description: differs in case");
    e2 = conn2.getEntry("ou=test,dc=example,dc=com","objectClass", "ou",
         "description");
    conn2.close();
    ds2.shutDown(true);

    assertFalse(Entry.diff(e1, e2, true, false).isEmpty());
    assertEquals(Entry.diff(e1, e2, true, false).size(), 1,
         String.valueOf(Entry.diff(e1, e2, true, false)));
    assertEquals(
         Entry.diff(e1, e2, true, false).get(0).getAttribute().getName(),
         "description");
  }



  /**
   * Tests the diff method when performing byte-for-byte comparison2.
   *
   * @throws  Exception   If an unexpected problem occurs.
   */
  @Test()
  public void testDiffByteForByte()
         throws Exception
  {
    Entry e1 = new Entry("dn: uid=jdoe,ou=People,dc=example,dc=com",
                         "objectClass: top",
                         "objectClass: person",
                         "objectClass: organizationalPerson",
                         "objectClass: inetOrgPerson",
                         "uid: jdoe",
                         "givenName: John",
                         "sn: Doe",
                         "cn: John Doe",
                         "userPassword: password",
                         "description: description");

    Entry e2 = new Entry("dn: uid=jdoe,ou=People,dc=example,dc=com",
                         "objectClass: top",
                         "objectClass: person",
                         "objectClass: organizationalPerson",
                         "objectClass: inetOrgPerson",
                         "uid: jdoe",
                         "givenName: john",
                         "sn: doe",
                         "cn: john doe",
                         "userPassword: password",
                         "displayName: displayName");

    List<Modification> mods = Entry.diff(e1, e2, false);
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 2, "Mods is " + String.valueOf(mods));
    assertEquals(mods,
         Arrays.asList(
              new Modification(ModificationType.DELETE, "description",
                   "description"),
              new Modification(ModificationType.ADD, "displayName",
                   "displayName")));

    mods = Entry.diff(e1, e2, false, true);
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 2, "Mods is " + String.valueOf(mods));
    assertEquals(mods,
         Arrays.asList(
              new Modification(ModificationType.DELETE, "description",
                   "description"),
              new Modification(ModificationType.ADD, "displayName",
                   "displayName")));

    mods = Entry.diff(e1, e2, false, true, false);
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 2, "Mods is " + String.valueOf(mods));
    assertEquals(mods,
         Arrays.asList(
              new Modification(ModificationType.DELETE, "description",
                   "description"),
              new Modification(ModificationType.ADD, "displayName",
                   "displayName")));

    mods = Entry.diff(e1, e2, false);
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 2, "Mods is " + String.valueOf(mods));
    assertEquals(mods,
         Arrays.asList(
              new Modification(ModificationType.DELETE, "description",
                   "description"),
              new Modification(ModificationType.ADD, "displayName",
                   "displayName")));

    mods = Entry.diff(e1, e2, false, true);
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 2, "Mods is " + String.valueOf(mods));
    assertEquals(mods,
         Arrays.asList(
              new Modification(ModificationType.DELETE, "description",
                   "description"),
              new Modification(ModificationType.ADD, "displayName",
                   "displayName")));

    mods = Entry.diff(e1, e2, false, true, false);
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 2, "Mods is " + String.valueOf(mods));
    assertEquals(mods,
         Arrays.asList(
              new Modification(ModificationType.DELETE, "description",
                   "description"),
              new Modification(ModificationType.ADD, "displayName",
                   "displayName")));

    mods = Entry.diff(e1, e2, false, true, true);
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 8);
    assertEquals(mods,
         Arrays.asList(
              new Modification(ModificationType.DELETE, "description",
                   "description"),
              new Modification(ModificationType.ADD, "displayName",
                   "displayName"),
              new Modification(ModificationType.DELETE, "givenName", "John"),
              new Modification(ModificationType.ADD, "givenName", "john"),
              new Modification(ModificationType.DELETE, "sn", "Doe"),
              new Modification(ModificationType.ADD, "sn", "doe"),
              new Modification(ModificationType.DELETE, "cn", "John Doe"),
              new Modification(ModificationType.ADD, "cn", "john doe")));

    mods = Entry.diff(e1, e2, false, false, true);
    assertFalse(mods.isEmpty());
    assertEquals(mods.size(), 5);
    assertEquals(mods,
         Arrays.asList(
              new Modification(ModificationType.REPLACE, "description"),
              new Modification(ModificationType.REPLACE, "displayName",
                   "displayName"),
              new Modification(ModificationType.REPLACE, "givenName", "john"),
              new Modification(ModificationType.REPLACE, "sn", "doe"),
              new Modification(ModificationType.REPLACE, "cn", "john doe")));
  }



  /**
   * Provides test coverage for the {@code applyModifications} method with a
   * number of simple valid modifications.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testApplyModificationsSimple()
         throws Exception
  {
    Entry source = new Entry(
         "dn: cn=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: untypedObject",
         "objectClass: extensibleObject",
         "cn: test",
         "addSingleValue: one",
         "addMultiValued: one",
         "addMultiValued: two",
         "deleteSingleValue: one",
         "deleteSingleValueByValue: one",
         "deleteMultiValued: one",
         "deleteMultiValued: two",
         "deleteMultiValuedByValue: one",
         "deleteMultiValuedByValue: two",
         "replaceSingleValue: one",
         "replaceMultiValued: one",
         "replaceMultiValued: two",
         "incrementPositive: 1",
         "incrementNegative: 1");

    Entry expected = new Entry(
         "dn: cn=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: untypedObject",
         "objectClass: extensibleObject",
         "cn: test",
         "addSingleValue: one",
         "addSingleValue: x",
         "addMultiValued: one",
         "addMultiValued: two",
         "addMultiValued: x",
         "addMultiValued: y",
         "addMissing: x",
         "deleteMultiValuedByValue: one",
         "replaceSingleValue: x",
         "replaceMultiValued: x",
         "replaceMultiValued: y",
         "replaceMissingWithValue: x",
         "incrementPositive: 5",
         "incrementNegative: -3");

    Entry actual = Entry.applyModifications(source, false,
         new Modification(ModificationType.ADD, "addSingleValue", "x"),
         new Modification(ModificationType.ADD, "addMultiValued", "x", "y"),
         new Modification(ModificationType.ADD, "addMissing", "x"),
         new Modification(ModificationType.DELETE, "deleteSingleValue"),
         new Modification(ModificationType.DELETE,
                          "deleteSingleValueByValue", "one"),
         new Modification(ModificationType.DELETE, "deleteMultiValued"),
         new Modification(ModificationType.DELETE,
                          "deleteMultiValuedByValue", "two"),
         new Modification(ModificationType.REPLACE, "replaceSingleValue", "x"),
         new Modification(ModificationType.REPLACE, "replaceMultiValued",
                          "x", "y"),
         new Modification(ModificationType.REPLACE, "replaceMissingWithValue",
                          "x"),
         new Modification(ModificationType.REPLACE, "replaceMissingNoValues"),
         new Modification(ModificationType.INCREMENT, "incrementPositive", "4"),
         new Modification(ModificationType.INCREMENT, "incrementNegative",
                          "-4"));

    assertEquals(expected, actual);
  }



  /**
   * Tests the ability to process an invalid set of modifications that will be
   * accepted if the lenient flag is true but will be rejected otherwise.
   *
   * @param  mod The modification to process.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testLenientModifications")
  public void testApplyModificationsLenientModifications(final Modification mod)
         throws Exception
  {
    Entry source = new Entry(
         "dn: cn=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: untypedObject",
         "objectClass: extensibleObject",
         "cn: test",
         "addSingleValue: one",
         "addMultiValued: one",
         "addMultiValued: two",
         "deleteSingleValue: one");

    try
    {
      Entry.applyModifications(source, false, mod);
      fail("Expected an exception when applying an invalid modification " +
           "without the lenient flag");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }

    Entry got = Entry.applyModifications(source, true, mod);
    assertEquals(got, source);
  }



  /**
   * Retrieves a set of test modifications that will only succeed if the lenient
   * flag is set.
   *
   * @return  A set of test modifications that will only succeed if the lenient
   *          flag is set.
   */
  @DataProvider(name="testLenientModifications")
  public Object[][] getTestLenientModifications()
  {
    return new Object[][]
    {
      new Object[]
      {
        new Modification(ModificationType.ADD, "addSingleValue")
      },
      new Object[]
      {
        new Modification(ModificationType.ADD, "addMultiValued", "one")
      },
      new Object[]
      {
        new Modification(ModificationType.DELETE, "deleteMissingAttribute")
      },
      new Object[]
      {
        new Modification(ModificationType.DELETE, "deleteSingleValue", "x")
      }
    };
  }



  /**
   * Tests a set of increment modifications that cannot be successfully
   * applied.
   *
   * @param  mod  The modification to apply.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testInvalidIncrementModifications")
  public void testApplyModificationsInvalidIncrementModifications(
                   final Modification mod)
         throws Exception
  {
    Entry source = new Entry(
         "dn: cn=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: untypedObject",
         "objectClass: extensibleObject",
         "cn: test",
         "notInteger: a",
         "singleValued: 1",
         "multiValued: 1",
         "multiValued: 2");

    try
    {
      Entry.applyModifications(source, true, mod);
      fail("Expected an exception when applying an invalid increment " +
           "modification");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Retrieves a set of increment modifications that cannot be successfully
   * applied.
   *
   * @return  A set of increment modifications that cannot be successfully
   *          applied.
   */
  @DataProvider(name="testInvalidIncrementModifications")
  public Object[][] getTestInvalidIncrementModifications()
  {
    return new Object[][]
    {
      new Object[]
      {
        new Modification(ModificationType.INCREMENT,  "missing", "1")
      },
      new Object[]
      {
        new Modification(ModificationType.INCREMENT,  "multiValued", "1")
      },
      new Object[]
      {
        new Modification(ModificationType.INCREMENT,  "notInteger", "1")
      },
      new Object[]
      {
        new Modification(ModificationType.INCREMENT,  "singleValued", "a")
      },
      new Object[]
      {
        new Modification(ModificationType.INCREMENT,  "singleValued")
      },
      new Object[]
      {
        new Modification(ModificationType.INCREMENT,  "singleValued", "1", "2")
      }
    };
  }



  /**
   * Tests the {@code applyModifications} method with an unknown modification
   * type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testApplyModificationsInvalidModificationType()
         throws Exception
  {
    Entry source = new Entry(
         "dn: cn=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: untypedObject",
         "objectClass: extensibleObject",
         "cn: test");

    try
    {
      Entry.applyModifications(source, true,
           new Modification(ModificationType.valueOf(5), "foo", "bar"));
      fail("Expected an exception when applying a modification with an " +
           "invalid modification type.");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Tests the {@code matchesBaseAndScope} method with a string representation
   * of the target DN.
   *
   * @param  targetDN         The target DN for which to make the determination.
   * @param  baseDN           The base DN for which to make the determination.
   * @param  scope            The scope for which to make the determination.
   * @param  expectMatch      Indicates whether to expect a match.
   * @param  expectException  Indicates whether to expect an exception.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testBaseAndScopeData")
  public void testMatchesBaseAndScopeString(String targetDN, String baseDN,
                   SearchScope scope, boolean expectMatch,
                   boolean expectException)
         throws Exception
  {
    try
    {
      Entry e = new Entry(targetDN);
      assertEquals(e.matchesBaseAndScope(baseDN, scope), expectMatch);
    }
    catch (LDAPException le)
    {
      if (! expectException)
      {
        throw le;
      }
    }
  }



  /**
   * Tests the {@code matchesBaseAndScope} method with a parsed representation
   * of the target DN.
   *
   * @param  targetDN         The target DN for which to make the determination.
   * @param  baseDN           The base DN for which to make the determination.
   * @param  scope            The scope for which to make the determination.
   * @param  expectMatch      Indicates whether to expect a match.
   * @param  expectException  Indicates whether to expect an exception.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testBaseAndScopeData")
  public void testMatchesBaseAndScopeDN(String targetDN, String baseDN,
                   SearchScope scope, boolean expectMatch,
                   boolean expectException)
         throws Exception
  {
    try
    {
      Entry e = new Entry(targetDN);
      assertEquals(e.matchesBaseAndScope(new DN(baseDN), scope), expectMatch);
    }
    catch (LDAPException le)
    {
      if (! expectException)
      {
        throw le;
      }
    }
  }



  /**
   * Provides a set of test data for use with the {@code matchesBaseAndScope}
   * methods.
   *
   * @return  A set of test data for use with the {@code matchesBaseAndScope}
   *          methods.
   */
  @DataProvider(name = "testBaseAndScopeData")
  public Object[][] getTestBaseAndScopeData()
  {
    return new Object[][]
    {
      new Object[]
      {
        "dc=example,dc=com",              // Target DN
        "dc=example,dc=com",              // Base DN
        SearchScope.BASE,                 // Scope
        true,                             // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "dc=example,dc=com",              // Target DN
        "dc=example,dc=com",              // Base DN
        SearchScope.ONE,                  // Scope
        false,                            // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "dc=example,dc=com",              // Target DN
        "dc=example,dc=com",              // Base DN
        SearchScope.SUB,                  // Scope
        true,                             // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "dc=example,dc=com",              // Target DN
        "dc=example,dc=com",              // Base DN
        SearchScope.SUBORDINATE_SUBTREE,  // Scope
        false,                            // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "ou=People,dc=example,dc=com",    // Target DN
        "dc=example,dc=com",              // Base DN
        SearchScope.BASE,                 // Scope
        false,                            // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "ou=People,dc=example,dc=com",    // Target DN
        "dc=example,dc=com",              // Base DN
        SearchScope.ONE,                  // Scope
        true,                             // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "ou=People,dc=example,dc=com",    // Target DN
        "dc=example,dc=com",              // Base DN
        SearchScope.SUB,                  // Scope
        true,                             // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "ou=People,dc=example,dc=com",    // Target DN
        "dc=example,dc=com",              // Base DN
        SearchScope.SUBORDINATE_SUBTREE,  // Scope
        true,                             // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "dc=example,dc=com",              // Target DN
        "ou=People,dc=example,dc=com",    // Base DN
        SearchScope.BASE,                 // Scope
        false,                            // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "dc=example,dc=com",              // Target DN
        "ou=People,dc=example,dc=com",    // Base DN
        SearchScope.ONE,                  // Scope
        false,                            // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "dc=example,dc=com",              // Target DN
        "ou=People,dc=example,dc=com",    // Base DN
        SearchScope.SUB,                  // Scope
        false,                            // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "dc=example,dc=com",              // Target DN
        "ou=People,dc=example,dc=com",    // Base DN
        SearchScope.SUBORDINATE_SUBTREE,  // Scope
        false,                            // Expect a match?
        false                             // Expect an exception?
      },

      new Object[]
      {
        "dc=example,dc=com",              // Target DN
        "invalid",                        // Base DN
        SearchScope.BASE,                 // Scope
        false,                            // Expect a match?
        true                              // Expect an exception?
      },

      new Object[]
      {
        "dc=example,dc=com",              // Target DN
        "dc=example,dc=com",              // Base DN
        SearchScope.valueOf(5),           // Scope
        false,                            // Expect a match?
        true                              // Expect an exception?
      }
    };
  }



  /**
   * Provides test coverage for the hasAttribute and getAttribute methods that
   * take a schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAttributeWithSchema()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();

    final Entry e = new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "displayName;lang-en-US: User",
         "displayName;lang-es: Usuario",
         "sn: User",
         "cn: Test User",
         "userPassword: password");

    assertTrue(e.hasAttribute("uid"));
    assertNotNull(e.getAttribute("uid"));
    assertEquals(e.getAttribute("uid").getValue(), "test.user");

    assertTrue(e.hasAttribute("uid", null));
    assertNotNull(e.getAttribute("uid", null));
    assertEquals(e.getAttribute("uid", null).getValue(), "test.user");

    assertTrue(e.hasAttribute("uid", schema));
    assertNotNull(e.getAttribute("uid", schema));
    assertEquals(e.getAttribute("uid", schema).getValue(), "test.user");

    assertFalse(e.hasAttribute("0.9.2342.19200300.100.1.1"));
    assertNull(e.getAttribute("0.9.2342.19200300.100.1.1"));

    assertFalse(e.hasAttribute("0.9.2342.19200300.100.1.1", null));
    assertNull(e.getAttribute("0.9.2342.19200300.100.1.1", null));

    assertTrue(e.hasAttribute("0.9.2342.19200300.100.1.1", schema));
    assertNotNull(e.getAttribute("0.9.2342.19200300.100.1.1", schema));
    assertEquals(e.getAttribute("0.9.2342.19200300.100.1.1", schema).getValue(),
         "test.user");


    assertTrue(e.hasAttribute("displayName;lang-en-US"));
    assertNotNull(e.getAttribute("displayName;lang-en-US"));
    assertEquals(e.getAttribute("displayName;lang-en-US").getValue(), "User");

    assertTrue(e.hasAttribute("displayName;lang-en-US", null));
    assertNotNull(e.getAttribute("displayName;lang-en-US", null));
    assertEquals(e.getAttribute("displayName;lang-en-US", null).getValue(),
         "User");

    assertTrue(e.hasAttribute("displayName;lang-en-US", schema));
    assertNotNull(e.getAttribute("displayName;lang-en-US", schema));
    assertEquals(e.getAttribute("displayName;lang-en-US", schema).getValue(),
         "User");

    assertFalse(e.hasAttribute("2.16.840.1.113730.3.1.241;lang-en-US"));
    assertNull(e.getAttribute("2.16.840.1.113730.3.1.241;lang-en-US"));

    assertFalse(e.hasAttribute("2.16.840.1.113730.3.1.241;lang-en-US", null));
    assertNull(e.getAttribute("2.16.840.1.113730.3.1.241;lang-en-US", null));

    assertTrue(e.hasAttribute("2.16.840.1.113730.3.1.241;lang-en-US", schema));
    assertNotNull(
         e.getAttribute("2.16.840.1.113730.3.1.241;lang-en-US", schema));
    assertEquals(
         e.getAttribute("2.16.840.1.113730.3.1.241;lang-en-US",
              schema).getValue(),
         "User");


    assertFalse(e.hasAttribute("displayName"));
    assertNull(e.getAttribute("displayName"));

    assertFalse(e.hasAttribute("displayName", null));
    assertNull(e.getAttribute("displayName", null));

    assertFalse(e.hasAttribute("displayName", schema));
    assertNull(e.getAttribute("displayName", schema));

    assertFalse(e.hasAttribute("2.16.840.1.113730.3.1.241"));
    assertNull(e.getAttribute("2.16.840.1.113730.3.1.241"));

    assertFalse(e.hasAttribute("2.16.840.1.113730.3.1.241", null));
    assertNull(e.getAttribute("2.16.840.1.113730.3.1.241", null));

    assertFalse(e.hasAttribute("2.16.840.1.113730.3.1.241", schema));
    assertNull(e.getAttribute("2.16.840.1.113730.3.1.241", schema));


    assertFalse(e.hasAttribute("description"));
    assertNull(e.getAttribute("description"));

    assertFalse(e.hasAttribute("description", null));
    assertNull(e.getAttribute("description", null));

    assertFalse(e.hasAttribute("description", schema));
    assertNull(e.getAttribute("description", schema));

    assertFalse(e.hasAttribute("2.5.4.13"));
    assertNull(e.getAttribute("2.5.4.13"));

    assertFalse(e.hasAttribute("2.5.4.13", null));
    assertNull(e.getAttribute("2.5.4.13", null));

    assertFalse(e.hasAttribute("2.5.4.13", schema));
    assertNull(e.getAttribute("2.5.4.13", schema));
  }



  /**
   * Provides test coverage for the {@code mergeEntries} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMergeEntries()
         throws Exception
  {
    final Entry e1 = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final Entry e2 = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo");

    final Entry e3 = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "objectClass: extensibleObject",
         "dc: example",
         "displayName: The display name");

    assertNotNull(Entry.mergeEntries(e1));
    assertEquals(Entry.mergeEntries(e1), e1);

    assertNotNull(Entry.mergeEntries(e2));
    assertEquals(Entry.mergeEntries(e2), e2);

    assertNotNull(Entry.mergeEntries(e3));
    assertEquals(Entry.mergeEntries(e3), e3);

    assertNotNull(Entry.mergeEntries(e1, e1));
    assertEquals(Entry.mergeEntries(e1, e1), e1);

    assertNotNull(Entry.mergeEntries(e2, e2));
    assertEquals(Entry.mergeEntries(e2, e2), e2);

    assertNotNull(Entry.mergeEntries(e3, e3));
    assertEquals(Entry.mergeEntries(e3, e3), e3);

    assertNotNull(Entry.mergeEntries(e1, e2));
    assertEquals(Entry.mergeEntries(e1, e2), e2);

    assertNotNull(Entry.mergeEntries(e1, e3));
    assertEquals(Entry.mergeEntries(e1, e3), e3);

    assertNotNull(Entry.mergeEntries(e1, e2, e3));
    assertEquals(Entry.mergeEntries(e1, e2, e3), new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "objectClass: extensibleObject",
         "dc: example",
         "description: foo",
         "displayName: The display name"));
  }



  /**
   * Provides test coverage for the {@code intersectEntries} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntersectEntries()
         throws Exception
  {
    final Entry e1 = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final Entry e2 = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo");

    final Entry e3 = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "objectClass: extensibleObject",
         "dc: example",
         "displayName: The display name");

    assertNotNull(Entry.intersectEntries(e1));
    assertEquals(Entry.intersectEntries(e1), e1);

    assertNotNull(Entry.intersectEntries(e2));
    assertEquals(Entry.intersectEntries(e2), e2);

    assertNotNull(Entry.intersectEntries(e3));
    assertEquals(Entry.intersectEntries(e3), e3);

    assertNotNull(Entry.intersectEntries(e1, e1));
    assertEquals(Entry.intersectEntries(e1, e1), e1);

    assertNotNull(Entry.intersectEntries(e2, e2));
    assertEquals(Entry.intersectEntries(e2, e2), e2);

    assertNotNull(Entry.intersectEntries(e3, e3));
    assertEquals(Entry.intersectEntries(e3, e3), e3);

    assertNotNull(Entry.intersectEntries(e1, e2));
    assertEquals(Entry.intersectEntries(e1, e2), e1);

    assertNotNull(Entry.intersectEntries(e1, e3));
    assertEquals(Entry.intersectEntries(e1, e3), e1);

    assertNotNull(Entry.intersectEntries(e2, e3));
    assertEquals(Entry.intersectEntries(e2, e3), e1);

    assertNotNull(Entry.intersectEntries(e1, e2, e3));
    assertEquals(Entry.intersectEntries(e1, e2, e3), e1);

    assertNotNull(Entry.intersectEntries(e2, e1));
    assertEquals(Entry.intersectEntries(e2, e1), e1);

    assertNotNull(Entry.intersectEntries(e3, e1));
    assertEquals(Entry.intersectEntries(e3, e1), e1);

    assertNotNull(Entry.intersectEntries(e3, e2));
    assertEquals(Entry.intersectEntries(e3, e2), e1);

    assertNotNull(Entry.intersectEntries(e2, e3, e1));
    assertEquals(Entry.intersectEntries(e2, e3, e1), e1);
  }



  /**
   * Tests the behavior of the {@code applyModifyDN} methods when replacing a
   * single-valued RDN with a new single-valued RDN that targets the same
   * attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testApplyModifyDNReplaceSingleValueSameAttribute()
         throws Exception
  {
    final Entry oldEntry = new Entry(
         "dn: ou=old,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: old");

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=old", false),
         new Entry(
              "dn: ou=old,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: old"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=new", false),
         new Entry(
              "dn: ou=new,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: old",
              "ou: new"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=old", true),
         new Entry(
              "dn: ou=old,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: old"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=new", true),
         new Entry(
              "dn: ou=new,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: new"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=old", false, "o=example.com"),
         new Entry(
              "dn: ou=old,o=example.com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: old"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=new", false, "o=example.com"),
         new Entry(
              "dn: ou=new,o=example.com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: old",
              "ou: new"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=old", true, "o=example.com"),
         new Entry(
              "dn: ou=old,o=example.com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: old"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=new", true, "o=example.com"),
         new Entry(
              "dn: ou=new,o=example.com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: new"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=old", true, ""),
         new Entry(
              "dn: ou=old",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: old"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=new", true, ""),
         new Entry(
              "dn: ou=new",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: new"));
  }



  /**
   * Tests the behavior of the {@code applyModifyDN} methods when replacing a
   * single-valued RDN with a new single-valued RDN that targets a different
   * attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testApplyModifyDNReplaceSingleValueDifferentAttribute()
         throws Exception
  {
    final Entry oldEntry = new Entry(
         "dn: description=old,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: old",
         "description: old");

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=old", false),
         new Entry(
              "dn: ou=old,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: old",
              "description: old"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=old", true),
         new Entry(
              "dn: ou=old,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: old"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=new", false),
         new Entry(
              "dn: ou=new,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: old",
              "ou: new",
              "description: old"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=new", true),
         new Entry(
              "dn: ou=new,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: old",
              "ou: new"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=new", false, "o=example.com"),
         new Entry(
              "dn: ou=new,o=example.com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: old",
              "ou: new",
              "description: old"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=new", true, "o=example.com"),
         new Entry(
              "dn: ou=new,o=example.com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: old",
              "ou: new"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=new", true, ""),
         new Entry(
              "dn: ou=new",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: old",
              "ou: new"));
  }



  /**
   * Tests the behavior of the {@code applyModifyDN} methods when replacing a
   * single-valued RDN with a new multivalued RDN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testApplyModifyDNAddValue()
         throws Exception
  {
    final Entry oldEntry = new Entry(
         "dn: ou=old,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: old");

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=old+ou=new", false),
         new Entry(
              "dn: ou=old+ou=new,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: old",
              "ou: new"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=old+ou=new", true),
         new Entry(
              "dn: ou=old+ou=new,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: old",
              "ou: new"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=old+description=new", false),
         new Entry(
              "dn: ou=old+description=new,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: old",
              "description: new"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=old+description=new", true),
         new Entry(
              "dn: ou=old+description=new,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: old",
              "description: new"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=new+description=new", false),
         new Entry(
              "dn: ou=new+description=new,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: old",
              "ou: new",
              "description: new"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "ou=new+description=new", true),
         new Entry(
              "dn: ou=new+description=new,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: new",
              "description: new"));
  }



  /**
   * Tests the behavior of the {@code applyModifyDN} methods when updating an
   * entry with the zero-length DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testApplyModifyZeroLengthDN()
         throws Exception
  {
    final Entry oldEntry = new Entry(
         "dn: ",
         "objectClass: top",
         "objectClass: ds-root-dse");

    assertEquals(
         Entry.applyModifyDN(oldEntry, "cn=foo", false),
         new Entry(
              "dn: cn=foo",
              "objectClass: top",
              "objectClass: ds-root-dse",
              "cn: foo"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "cn=foo", true),
         new Entry(
              "dn: cn=foo",
              "objectClass: top",
              "objectClass: ds-root-dse",
              "cn: foo"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "cn=foo+description=bar", false),
         new Entry(
              "dn: cn=foo+description=bar",
              "objectClass: top",
              "objectClass: ds-root-dse",
              "cn: foo",
              "description: bar"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "cn=foo+description=bar", true),
         new Entry(
              "dn: cn=foo+description=bar",
              "objectClass: top",
              "objectClass: ds-root-dse",
              "cn: foo",
              "description: bar"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "cn=foo", false, ""),
         new Entry(
              "dn: cn=foo",
              "objectClass: top",
              "objectClass: ds-root-dse",
              "cn: foo"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "cn=foo", true, ""),
         new Entry(
              "dn: cn=foo",
              "objectClass: top",
              "objectClass: ds-root-dse",
              "cn: foo"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "cn=foo+description=bar", false, ""),
         new Entry(
              "dn: cn=foo+description=bar",
              "objectClass: top",
              "objectClass: ds-root-dse",
              "cn: foo",
              "description: bar"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "cn=foo+description=bar", true, ""),
         new Entry(
              "dn: cn=foo+description=bar",
              "objectClass: top",
              "objectClass: ds-root-dse",
              "cn: foo",
              "description: bar"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "cn=foo", false, "o=example.com"),
         new Entry(
              "dn: cn=foo,o=example.com",
              "objectClass: top",
              "objectClass: ds-root-dse",
              "cn: foo"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "cn=foo", true, "o=example.com"),
         new Entry(
              "dn: cn=foo,o=example.com",
              "objectClass: top",
              "objectClass: ds-root-dse",
              "cn: foo"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "cn=foo+description=bar", false,
              "dc=example,dc=com"),
         new Entry(
              "dn: cn=foo+description=bar,dc=example,dc=com",
              "objectClass: top",
              "objectClass: ds-root-dse",
              "cn: foo",
              "description: bar"));

    assertEquals(
         Entry.applyModifyDN(oldEntry, "cn=foo+description=bar", true,
              "dc=example,dc=com"),
         new Entry(
              "dn: cn=foo+description=bar,dc=example,dc=com",
              "objectClass: top",
              "objectClass: ds-root-dse",
              "cn: foo",
              "description: bar"));
  }



  /**
   * Tests the behavior of methods used to obtain the LDIF representation of an
   * entry with attributes that don't have any values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDIFMethodsWithZeroValueAttributes()
         throws Exception
  {
    final Entry e = new Entry("dc=example,dc=com", new Attribute("objectClass"),
         new Attribute("dc"));

    assertEquals(e.toLDIF(),
         new String[]
         {
           "dn: dc=example,dc=com",
           "objectClass: ",
           "dc: ",
         });

    assertEquals(e.toLDIFString(),
         "dn: dc=example,dc=com" + EOL +
         "objectClass: " + EOL +
         "dc: " + EOL);

    final ByteStringBuffer buffer = new ByteStringBuffer();
    e.toLDIF(buffer);
    assertEquals(buffer.toString(),
         "dn: dc=example,dc=com" + EOL +
         "objectClass: " + EOL +
         "dc: " + EOL);
  }
}
