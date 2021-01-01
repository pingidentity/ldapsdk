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



import java.io.ByteArrayInputStream;
import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.protocol.LDAPMessage;



/**
 * This class provides a set of test cases for the SearchResultEntry class.
 */
public class SearchResultEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   */
  @Test()
  public void testConstructor1()
  {
    String dn = "uid=john.doe,ou=People,dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "person", "organizationalPerson",
                    "inetOrgPerson"),
      new Attribute("uid", "john.doe"),
      new Attribute("givenName", "John"),
      new Attribute("sn", "Doe"),
      new Attribute("cn", "John Doe"),
      new Attribute("userPassword", "password")
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(dn, attributes, controls);

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), dn);

    assertNotNull(e.getAttributes());
    assertTrue(e.hasAttribute("uid"));
    assertTrue(e.hasAttributeValue("uid", "john.doe"));
    assertFalse(e.hasAttributeValue("uid", "joan.ode"));

    assertNotNull(e.getControls());
    assertEquals(e.getControls().length, 2);

    assertNotNull(e.getControl("1.2.3.4"));
    assertNotNull(e.getControl("1.2.3.5"));
    assertNull(e.getControl("1.2.3.6"));

    e.getMessageID();

    e.hashCode();
    assertNotNull(e.toString());
  }



  /**
   * Tests the second constructor.
   */
  @Test()
  public void testConstructor2()
  {
    String dn = "uid=john.doe,ou=People,dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "person", "organizationalPerson",
                    "inetOrgPerson"),
      new Attribute("uid", "john.doe"),
      new Attribute("givenName", "John"),
      new Attribute("sn", "Doe"),
      new Attribute("cn", "John Doe"),
      new Attribute("userPassword", "password")
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(dn, Arrays.asList(attributes),
                                                controls);

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), dn);

    assertNotNull(e.getAttributes());
    assertTrue(e.hasAttribute("uid"));
    assertTrue(e.hasAttributeValue("uid", "john.doe"));
    assertFalse(e.hasAttributeValue("uid", "joan.ode"));

    assertNotNull(e.getControls());
    assertEquals(e.getControls().length, 2);

    assertNotNull(e.getControl("1.2.3.4"));
    assertNotNull(e.getControl("1.2.3.5"));
    assertNull(e.getControl("1.2.3.6"));

    e.getMessageID();

    e.hashCode();
    assertNotNull(e.toString());
  }



  /**
   * Tests the third constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    Entry entry = new Entry(
         "dn: uid=john.doe,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: john.doe",
         "givenName: John",
         "sn: Doe",
         "cn: John Doe",
         "userPassword: password");

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(entry, controls);

    assertNotNull(e.getDN());
    assertEquals(e.getDN(), entry.getDN());

    assertNotNull(e.getAttributes());
    assertTrue(e.hasAttribute("uid"));
    assertTrue(e.hasAttributeValue("uid", "john.doe"));
    assertFalse(e.hasAttributeValue("uid", "joan.ode"));

    assertNotNull(e.getControls());
    assertEquals(e.getControls().length, 2);

    assertNotNull(e.getControl("1.2.3.4"));
    assertNotNull(e.getControl("1.2.3.5"));
    assertNull(e.getControl("1.2.3.6"));

    e.getMessageID();

    e.hashCode();
    assertNotNull(e.toString());
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
    String dn = "dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(dn, attributes, controls);

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
    String dn = "dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(dn, attributes, controls);

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
    String dn = "dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(-1, dn, attributes, controls);

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
    String dn = "dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(dn, attributes, controls);

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
    String dn = "dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(-1, dn,
         Arrays.asList(attributes), controls);

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
    String dn = "dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(dn, attributes, controls);

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
    String dn = "dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(dn, attributes, controls);

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
    String dn = "dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(dn, attributes, controls);

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
  public void testRemoveAttributeStringNameStringValue()
         throws  Exception
  {
    String dn = "dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(dn, attributes, controls);

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
  public void testRemoveAttributeStringNameByteArrayValue()
         throws  Exception
  {
    String dn = "dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(dn, attributes, controls);

    e.removeAttributeValue("dc", "example".getBytes("UTF-8"));
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
    String dn = "dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(dn, attributes, controls);

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
    String dn = "dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(dn, attributes, controls);

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
    String dn = "dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(dn, attributes, controls);

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
    String dn = "dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(dn, attributes, controls);

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
    String dn = "dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(dn, attributes, controls);

    e.setAttribute("description", "foo".getBytes("UTF-8"),
                   "bar".getBytes("UTF-8"), "baz".getBytes("UTF-8"));
  }



  /**
   * Tests the {@code equals} method with a null argument.
   */
  @Test()
  public void testEqualsNull()
  {
    String dn = "dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(dn, attributes, controls);

    assertFalse(e.equals(null));
  }



  /**
   * Tests the {@code equals} method with an identity comparison.
   */
  @Test()
  public void testEqualsIdentity()
  {
    String dn = "dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(dn, attributes, controls);

    assertTrue(e.equals(e));
  }



  /**
   * Tests the {@code equals} method with an object that isn't a search result
   * entry.
   */
  @Test()
  public void testEqualsNotEntry()
  {
    String dn = "dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(dn, attributes, controls);

    Entry e2 = new Entry(dn, attributes);
    assertFalse(e.hashCode() == e2.hashCode());
    assertTrue(e2.equals(e));
    assertFalse(e.equals(e2));
  }



  /**
   * Tests the {@code equals} method with an object that is an equivalent search
   * result entry.
   */
  @Test()
  public void testEqualsEquivalentEntry()
  {
    String dn = "dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(dn, attributes, controls);

    SearchResultEntry e2 = new SearchResultEntry(dn, attributes, controls);
    assertEquals(e.hashCode(), e2.hashCode());
    assertTrue(e.equals(e2));
    assertTrue(e2.equals(e));
  }



  /**
   * Tests the {@code equals} method with a search result entry that has an
   * equivalent DN and set of attributes but different number of controls.
   */
  @Test()
  public void testEqualsDifferentControlCount()
  {
    String dn = "dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(dn, attributes, controls);

    SearchResultEntry e2 = new SearchResultEntry(dn, attributes,
                           new Control[0]);
    assertFalse(e.hashCode() == e2.hashCode());
    assertFalse(e.equals(e2));
    assertFalse(e2.equals(e));
  }



  /**
   * Tests the {@code equals} method with a search result entry that has an
   * equivalent DN and set of attributes and same number of controls, but
   * different control content.
   */
  @Test()
  public void testEqualsDifferentControlContent()
  {
    String dn = "dc=example,dc=com";

    Attribute[] attributes =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example"),
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchResultEntry e = new SearchResultEntry(dn, attributes, controls);


    Control[] controls2 =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.6", true, null)
    };

    SearchResultEntry e2 = new SearchResultEntry(dn, attributes, controls2);
    assertFalse(e.hashCode() == e2.hashCode());
    assertFalse(e.equals(e2));
    assertFalse(e2.equals(e));
  }



  /**
   * Tests the {@code readSearchEntryFrom} method with an element containing
   * a response sequence that is too short.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadSearchEntryFromTooShort()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();

    ASN1BufferSequence msgSequence = b.beginSequence();
    b.addInteger(1);

    ASN1BufferSequence opSequence =
         b.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_ENTRY);
    b.addOctetString("dc=example,dc=com");
    opSequence.end();
    msgSequence.end();

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    LDAPMessage.readLDAPResponseFrom(reader, true);
  }



  /**
   * Tests the {@code readBindResultFrom} method with an element containing
   * a response sequence with a malformed attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadSearchEntryFromMalformedAttribute()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();

    ASN1BufferSequence msgSequence = b.beginSequence();
    b.addInteger(1);

    ASN1BufferSequence opSequence =
         b.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_ENTRY);
    b.addOctetString("dc=example,dc=com");

    ASN1BufferSequence attrSequence = b.beginSequence();
    b.addEnumerated(1);
    attrSequence.end();

    opSequence.end();
    msgSequence.end();

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    LDAPMessage.readLDAPResponseFrom(reader, true);
  }
}
