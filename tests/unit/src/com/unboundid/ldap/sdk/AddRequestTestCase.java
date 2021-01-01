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



import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.matchingrules.CaseIgnoreStringMatchingRule;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldif.LDIFException;



/**
 * This class provides a set of test cases for the AddRequest class.
 */
public class AddRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor, which takes a string DN and an attribute
   * array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };

    AddRequest addRequest = new AddRequest("dc=example,dc=com", attrs);
    addRequest = addRequest.duplicate();

    assertNotNull(addRequest.getDN());
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    assertNotNull(addRequest.getAttributes());
    assertEquals(addRequest.getAttributes().size(), 2);

    assertNotNull(addRequest.getAttribute("objectClass"));
    assertNotNull(addRequest.getAttribute("dc"));
    assertNull(addRequest.getAttribute("description"));

    assertTrue(addRequest.hasAttribute("objectClass"));
    assertTrue(addRequest.hasAttribute("dc"));
    assertFalse(addRequest.hasAttribute("description"));

    assertTrue(addRequest.hasAttribute(new Attribute("objectClass", "top",
         "domain")));
    assertTrue(addRequest.hasAttribute(new Attribute("objectClass", "domain",
         "top")));
    assertFalse(addRequest.hasAttribute(new Attribute("objectClass", "top")));
    assertFalse(addRequest.hasAttribute(new Attribute("objectClass",
         "domain")));
    assertFalse(addRequest.hasAttribute(new Attribute("objectClass", "top",
         "domain", "dcObject")));
    assertFalse(addRequest.hasAttribute(new Attribute("objectClass")));
    assertTrue(addRequest.hasAttribute(new Attribute("dc", "example")));
    assertFalse(addRequest.hasAttribute(new Attribute("dc", "foo")));
    assertFalse(addRequest.hasAttribute(new Attribute("dc", "example", "foo")));
    assertFalse(addRequest.hasAttribute(new Attribute("dc")));
    assertFalse(addRequest.hasAttribute(new Attribute("description", "foo")));
    assertFalse(addRequest.hasAttribute(new Attribute("description")));

    assertTrue(addRequest.hasAttributeValue("objectClass", "top"));
    assertTrue(addRequest.hasAttributeValue("objectClass", "domain"));
    assertFalse(addRequest.hasAttributeValue("objectClass", "foo"));
    assertTrue(addRequest.hasAttributeValue("dc", "example"));
    assertFalse(addRequest.hasAttributeValue("dc", "bar"));
    assertFalse(addRequest.hasAttributeValue("description", "baz"));

    CaseIgnoreStringMatchingRule mr =
         CaseIgnoreStringMatchingRule.getInstance();
    assertTrue(addRequest.hasAttributeValue("objectClass", "top", mr));
    assertTrue(addRequest.hasAttributeValue("objectClass", "domain", mr));
    assertFalse(addRequest.hasAttributeValue("objectClass", "foo", mr));
    assertTrue(addRequest.hasAttributeValue("dc", "example", mr));
    assertFalse(addRequest.hasAttributeValue("dc", "bar", mr));
    assertFalse(addRequest.hasAttributeValue("description", "baz", mr));

    assertTrue(addRequest.hasAttributeValue("objectClass",
         "top".getBytes("UTF-8")));
    assertTrue(addRequest.hasAttributeValue("objectClass",
         "domain".getBytes("UTF-8")));
    assertFalse(addRequest.hasAttributeValue("objectClass",
         "foo".getBytes("UTF-8")));
    assertTrue(addRequest.hasAttributeValue("dc", "example".getBytes("UTF-8")));
    assertFalse(addRequest.hasAttributeValue("dc", "bar".getBytes("UTF-8")));
    assertFalse(addRequest.hasAttributeValue("description",
         "baz".getBytes("UTF-8")));

    assertTrue(addRequest.hasAttributeValue("objectClass",
         "top".getBytes("UTF-8"), mr));
    assertTrue(addRequest.hasAttributeValue("objectClass",
         "domain".getBytes("UTF-8"), mr));
    assertFalse(addRequest.hasAttributeValue("objectClass",
         "foo".getBytes("UTF-8"), mr));
    assertTrue(addRequest.hasAttributeValue("dc", "example".getBytes("UTF-8"),
         mr));
    assertFalse(addRequest.hasAttributeValue("dc", "bar".getBytes("UTF-8"),
         mr));
    assertFalse(addRequest.hasAttributeValue("description",
         "baz".getBytes("UTF-8"), mr));

    assertTrue(addRequest.hasObjectClass("top"));
    assertTrue(addRequest.hasObjectClass("domain"));
    assertFalse(addRequest.hasObjectClass("foo"));

    assertNotNull(addRequest.toEntry());

    assertFalse(addRequest.hasControl());
    assertFalse(addRequest.hasControl("1.2.3.4"));
    assertNull(addRequest.getControl("1.2.3.4"));
    assertNotNull(addRequest.getControls());
    assertEquals(addRequest.getControls().length, 0);

    assertNotNull(addRequest.toLDIFChangeRecord());

    assertNotNull(addRequest.toLDIF());
    assertTrue(addRequest.toLDIF().length > 0);

    assertNotNull(addRequest.toLDIFString());

    assertNotNull(addRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    addRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    addRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    assertEquals(addRequest.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST);

    assertNull(addRequest.getIntermediateResponseListener());
    addRequest.setIntermediateResponseListener(
         new TestIntermediateResponseListener());
    assertNotNull(addRequest.getIntermediateResponseListener());
    addRequest.setIntermediateResponseListener(null);
    assertNull(addRequest.getIntermediateResponseListener());


    testEncoding(addRequest);
  }



  /**
   * Tests the second constructor, which takes a string DN, an attribute array,
   * and a set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
       throws Exception
  {
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    AddRequest addRequest =
         new AddRequest("dc=example,dc=com", attrs, controls);
    addRequest = addRequest.duplicate();

    assertNotNull(addRequest.getDN());
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    assertNotNull(addRequest.getAttributes());
    assertEquals(addRequest.getAttributes().size(), 2);

    assertTrue(addRequest.hasControl());
    assertTrue(addRequest.hasControl("1.2.3.4"));
    assertNotNull(addRequest.getControl("1.2.3.4"));
    assertFalse(addRequest.hasControl("1.2.3.6"));
    assertNull(addRequest.getControl("1.2.3.6"));
    assertNotNull(addRequest.getControls());
    assertEquals(addRequest.getControls().length, 2);

    assertNotNull(addRequest.toLDIFChangeRecord());

    assertNotNull(addRequest.toLDIF());
    assertTrue(addRequest.toLDIF().length > 0);

    assertNotNull(addRequest.toLDIFString());

    assertNotNull(addRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    addRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    addRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(addRequest);
  }



  /**
   * Tests the third constructor, which takes a string DN and a collection of
   * attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    ArrayList<Attribute> attrs = new ArrayList<Attribute>(2);
    attrs.add(new Attribute("objectClass", "top", "domain"));
    attrs.add(new Attribute("dc", "example"));

    AddRequest addRequest = new AddRequest("dc=example,dc=com", attrs);
    addRequest = addRequest.duplicate();

    assertNotNull(addRequest.getDN());
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    assertNotNull(addRequest.getAttributes());
    assertEquals(addRequest.getAttributes().size(), 2);

    assertFalse(addRequest.hasControl());
    assertFalse(addRequest.hasControl("1.2.3.4"));
    assertNull(addRequest.getControl("1.2.3.4"));
    assertNotNull(addRequest.getControls());
    assertEquals(addRequest.getControls().length, 0);

    assertNotNull(addRequest.toLDIFChangeRecord());

    assertNotNull(addRequest.toLDIF());
    assertTrue(addRequest.toLDIF().length > 0);

    assertNotNull(addRequest.toLDIFString());

    assertNotNull(addRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    addRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    addRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(addRequest);
  }



  /**
   * Tests the fourth constructor, which takes a string DN, a collection of
   * attributes, and a set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4()
         throws Exception
  {
    ArrayList<Attribute> attrs = new ArrayList<Attribute>(2);
    attrs.add(new Attribute("objectClass", "top", "domain"));
    attrs.add(new Attribute("dc", "example"));

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    AddRequest addRequest =
         new AddRequest("dc=example,dc=com", attrs, controls);
    addRequest = addRequest.duplicate();

    assertNotNull(addRequest.getDN());
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    assertNotNull(addRequest.getAttributes());
    assertEquals(addRequest.getAttributes().size(), 2);

    assertTrue(addRequest.hasControl());
    assertTrue(addRequest.hasControl("1.2.3.4"));
    assertNotNull(addRequest.getControl("1.2.3.4"));
    assertFalse(addRequest.hasControl("1.2.3.6"));
    assertNull(addRequest.getControl("1.2.3.6"));
    assertNotNull(addRequest.getControls());
    assertEquals(addRequest.getControls().length, 2);

    assertNotNull(addRequest.toLDIFChangeRecord());

    assertNotNull(addRequest.toLDIF());
    assertTrue(addRequest.toLDIF().length > 0);

    assertNotNull(addRequest.toLDIFString());

    assertNotNull(addRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    addRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    addRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(addRequest);
  }



  /**
   * Tests the fifth constructor, which takes a DN object and an attribute
   * array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5()
         throws Exception
  {
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };

    AddRequest addRequest = new AddRequest(new DN("dc=example,dc=com"), attrs);
    addRequest = addRequest.duplicate();

    assertNotNull(addRequest.getDN());
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    assertNotNull(addRequest.getAttributes());
    assertEquals(addRequest.getAttributes().size(), 2);

    assertFalse(addRequest.hasControl());
    assertFalse(addRequest.hasControl("1.2.3.4"));
    assertNull(addRequest.getControl("1.2.3.4"));
    assertNotNull(addRequest.getControls());
    assertEquals(addRequest.getControls().length, 0);

    assertNotNull(addRequest.toLDIFChangeRecord());

    assertNotNull(addRequest.toLDIF());
    assertTrue(addRequest.toLDIF().length > 0);

    assertNotNull(addRequest.toLDIFString());

    assertNotNull(addRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    addRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    addRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(addRequest);
  }



  /**
   * Tests the sixth constructor, which takes a DN object, an attribute array,
   * and a set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6()
         throws Exception
  {
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    AddRequest addRequest =
         new AddRequest(new DN("dc=example,dc=com"), attrs, controls);
    addRequest = addRequest.duplicate();

    assertNotNull(addRequest.getDN());
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    assertNotNull(addRequest.getAttributes());
    assertEquals(addRequest.getAttributes().size(), 2);

    assertTrue(addRequest.hasControl());
    assertTrue(addRequest.hasControl("1.2.3.4"));
    assertNotNull(addRequest.getControl("1.2.3.4"));
    assertFalse(addRequest.hasControl("1.2.3.6"));
    assertNull(addRequest.getControl("1.2.3.6"));
    assertNotNull(addRequest.getControls());
    assertEquals(addRequest.getControls().length, 2);

    assertNotNull(addRequest.toLDIFChangeRecord());

    assertNotNull(addRequest.toLDIF());
    assertTrue(addRequest.toLDIF().length > 0);

    assertNotNull(addRequest.toLDIFString());

    assertNotNull(addRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    addRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    addRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(addRequest);
  }



  /**
   * Tests the seventh constructor, which takes a DN object and a collection of
   * attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor7()
         throws Exception
  {
    ArrayList<Attribute> attrs = new ArrayList<Attribute>(2);
    attrs.add(new Attribute("objectClass", "top", "domain"));
    attrs.add(new Attribute("dc", "example"));

    AddRequest addRequest = new AddRequest(new DN("dc=example,dc=com"), attrs);
    addRequest = addRequest.duplicate();

    assertNotNull(addRequest.getDN());
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    assertNotNull(addRequest.getAttributes());
    assertEquals(addRequest.getAttributes().size(), 2);

    assertFalse(addRequest.hasControl());
    assertFalse(addRequest.hasControl("1.2.3.4"));
    assertNull(addRequest.getControl("1.2.3.4"));
    assertNotNull(addRequest.getControls());
    assertEquals(addRequest.getControls().length, 0);

    assertNotNull(addRequest.toLDIFChangeRecord());

    assertNotNull(addRequest.toLDIF());
    assertTrue(addRequest.toLDIF().length > 0);

    assertNotNull(addRequest.toLDIFString());

    assertNotNull(addRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    addRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    addRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(addRequest);
  }



  /**
   * Tests the eighth constructor, which takes a string DN, a collection of
   * attributes, and a set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor8()
         throws Exception
  {
    ArrayList<Attribute> attrs = new ArrayList<Attribute>(2);
    attrs.add(new Attribute("objectClass", "top", "domain"));
    attrs.add(new Attribute("dc", "example"));

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    AddRequest addRequest =
         new AddRequest(new DN("dc=example,dc=com"), attrs, controls);
    addRequest = addRequest.duplicate();

    assertNotNull(addRequest.getDN());
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    assertNotNull(addRequest.getAttributes());
    assertEquals(addRequest.getAttributes().size(), 2);

    assertTrue(addRequest.hasControl());
    assertTrue(addRequest.hasControl("1.2.3.4"));
    assertNotNull(addRequest.getControl("1.2.3.4"));
    assertFalse(addRequest.hasControl("1.2.3.6"));
    assertNull(addRequest.getControl("1.2.3.6"));
    assertNotNull(addRequest.getControls());
    assertEquals(addRequest.getControls().length, 2);

    assertNotNull(addRequest.toLDIFChangeRecord());

    assertNotNull(addRequest.toLDIF());
    assertTrue(addRequest.toLDIF().length > 0);

    assertNotNull(addRequest.toLDIFString());

    assertNotNull(addRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    addRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    addRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(addRequest);
  }



  /**
   * Tests the ninth constructor, which takes an entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor9()
         throws Exception
  {
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };

    Entry entry = new Entry("dc=example,dc=com", attrs);

    AddRequest addRequest = new AddRequest(entry);
    addRequest = addRequest.duplicate();

    assertNotNull(addRequest.getDN());
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    assertNotNull(addRequest.getAttributes());
    assertEquals(addRequest.getAttributes().size(), 2);

    assertFalse(addRequest.hasControl());
    assertFalse(addRequest.hasControl("1.2.3.4"));
    assertNull(addRequest.getControl("1.2.3.4"));
    assertNotNull(addRequest.getControls());
    assertEquals(addRequest.getControls().length, 0);

    assertNotNull(addRequest.toLDIFChangeRecord());

    assertNotNull(addRequest.toLDIF());
    assertTrue(addRequest.toLDIF().length > 0);

    assertNotNull(addRequest.toLDIFString());

    assertNotNull(addRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    addRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    addRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(addRequest);
  }



  /**
   * Tests the tenth constructor, which takes an entry and set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor10()
         throws Exception
  {
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };

    Entry entry = new Entry("dc=example,dc=com", attrs);

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    AddRequest addRequest = new AddRequest(entry, controls);
    addRequest = addRequest.duplicate();

    assertNotNull(addRequest.getDN());
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    assertNotNull(addRequest.getAttributes());
    assertEquals(addRequest.getAttributes().size(), 2);

    assertTrue(addRequest.hasControl());
    assertTrue(addRequest.hasControl("1.2.3.4"));
    assertNotNull(addRequest.getControl("1.2.3.4"));
    assertFalse(addRequest.hasControl("1.2.3.6"));
    assertNull(addRequest.getControl("1.2.3.6"));
    assertNotNull(addRequest.getControls());
    assertEquals(addRequest.getControls().length, 2);

    assertNotNull(addRequest.toLDIFChangeRecord());

    assertNotNull(addRequest.toLDIF());
    assertTrue(addRequest.toLDIF().length > 0);

    assertNotNull(addRequest.toLDIFString());

    assertNotNull(addRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    addRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    addRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(addRequest);
  }



  /**
   * Tests the eleventh constructor, which takes an LDIF representation of the
   * entry.  Use a standard LDIF entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor11LDIFEntry()
         throws Exception
  {
    AddRequest addRequest = new AddRequest("dn: dc=example,dc=com",
                                           "objectClass: top",
                                           "objectClass: domain",
                                           "dc: example");
    addRequest = addRequest.duplicate();

    assertNotNull(addRequest.getDN());
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    assertNotNull(addRequest.getAttributes());
    assertEquals(addRequest.getAttributes().size(), 2);

    assertFalse(addRequest.hasAttribute("control"));
    assertFalse(addRequest.hasAttribute("changetype"));
    assertTrue(addRequest.hasAttribute("objectClass"));
    assertTrue(addRequest.hasAttribute("dc"));

    assertFalse(addRequest.hasControl());
    assertFalse(addRequest.hasControl("1.2.3.4"));
    assertNull(addRequest.getControl("1.2.3.4"));
    assertNotNull(addRequest.getControls());
    assertEquals(addRequest.getControls().length, 0);

    assertNotNull(addRequest.toLDIFChangeRecord());

    assertNotNull(addRequest.toLDIF());
    assertTrue(addRequest.toLDIF().length > 0);

    assertNotNull(addRequest.toLDIFString());

    assertNotNull(addRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    addRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    addRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(addRequest);
  }



  /**
   * Tests the eleventh constructor, which takes an LDIF representation of the
   * entry.  Use an LDIF add change record that doesn't have any controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor11LDIFAddChangeRecordWithoutControls()
         throws Exception
  {
    AddRequest addRequest = new AddRequest("dn: dc=example,dc=com",
                                           "changetype: add",
                                           "objectClass: top",
                                           "objectClass: domain",
                                           "dc: example");
    addRequest = addRequest.duplicate();

    assertNotNull(addRequest.getDN());
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    assertNotNull(addRequest.getAttributes());
    assertEquals(addRequest.getAttributes().size(), 2);

    assertFalse(addRequest.hasAttribute("control"));
    assertFalse(addRequest.hasAttribute("changetype"));
    assertTrue(addRequest.hasAttribute("objectClass"));
    assertTrue(addRequest.hasAttribute("dc"));

    assertFalse(addRequest.hasControl());
    assertFalse(addRequest.hasControl("1.2.3.4"));
    assertNull(addRequest.getControl("1.2.3.4"));
    assertNotNull(addRequest.getControls());
    assertEquals(addRequest.getControls().length, 0);

    assertNotNull(addRequest.toLDIFChangeRecord());

    assertNotNull(addRequest.toLDIF());
    assertTrue(addRequest.toLDIF().length > 0);

    assertNotNull(addRequest.toLDIFString());

    assertNotNull(addRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    addRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    addRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(addRequest);
  }



  /**
   * Tests the eleventh constructor, which takes an LDIF representation of the
   * entry.  Use an LDIF add change record that includes controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor11LDIFAddChangeRecordWithControls()
         throws Exception
  {
    AddRequest addRequest = new AddRequest("dn: dc=example,dc=com",
                                           "control: 1.2.3.4",
                                           "changetype: add",
                                           "objectClass: top",
                                           "objectClass: domain",
                                           "dc: example");
    addRequest = addRequest.duplicate();

    assertNotNull(addRequest.getDN());
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    assertNotNull(addRequest.getAttributes());
    assertEquals(addRequest.getAttributes().size(), 2);

    assertFalse(addRequest.hasAttribute("control"));
    assertFalse(addRequest.hasAttribute("changetype"));
    assertTrue(addRequest.hasAttribute("objectClass"));
    assertTrue(addRequest.hasAttribute("dc"));

    assertTrue(addRequest.hasControl());
    assertTrue(addRequest.hasControl("1.2.3.4"));
    assertNotNull(addRequest.getControl("1.2.3.4"));
    assertNotNull(addRequest.getControls());
    assertEquals(addRequest.getControls().length, 1);

    assertNotNull(addRequest.toLDIFChangeRecord());

    assertNotNull(addRequest.toLDIF());
    assertTrue(addRequest.toLDIF().length > 0);

    assertNotNull(addRequest.toLDIFString());

    assertNotNull(addRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    addRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    addRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(addRequest);
  }



  /**
   * Tests the eleventh constructor, which takes an LDIF representation of the
   * entry.  Use an LDIF add change record that includes controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={ LDIFException.class })
  public void testConstructor11LDIFNotAddChangeRecord()
         throws Exception
  {

    new AddRequest(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");
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
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };

    AddRequest addRequest = new AddRequest("dc=example,dc=com", attrs);
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    addRequest.setDN("o=example.com");
    assertEquals(addRequest.getDN(), "o=example.com");

    addRequest.setDN(new DN("o=example.net"));
    assertEquals(addRequest.getDN(), "o=example.net");

    testEncoding(addRequest);
  }



  /**
   * Tests the methods that interact with the set of attributes in the add
   * request.
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
      new Attribute("dc", "example")
    };

    AddRequest addRequest = new AddRequest("dc=example,dc=com", attrs);
    assertEquals(addRequest.getAttributes().size(), 2);

    attrs = new Attribute[]
    {
      new Attribute("objectClass", "top", "organization", "dcObject"),
      new Attribute("o", "example.com"),
      new Attribute("dc", "example")
    };
    addRequest.setAttributes(attrs);
    assertEquals(addRequest.getAttributes().size(), 3);

    ArrayList<Attribute> attrList = new ArrayList<Attribute>();
    attrList.add(new Attribute("objectClass", "top", "organization"));
    attrList.add(new Attribute("o", "example.net"));
    addRequest.setAttributes(attrList);
    assertEquals(addRequest.getAttributes().size(), 2);

    addRequest.addAttribute(new Attribute("description", "foo"));
    assertEquals(addRequest.getAttributes().size(), 3);

    addRequest.addAttribute(new Attribute("description", "bar"));
    assertEquals(addRequest.getAttributes().size(), 3);

    addRequest.addAttribute("cn", "bar");
    assertEquals(addRequest.getAttributes().size(), 4);

    addRequest.addAttribute("cn", "baz");
    assertEquals(addRequest.getAttributes().size(), 4);

    addRequest.addAttribute("sn", "bat".getBytes("UTF-8"));
    assertEquals(addRequest.getAttributes().size(), 5);

    addRequest.addAttribute("sn", "bag".getBytes("UTF-8"));
    assertEquals(addRequest.getAttributes().size(), 5);

    addRequest.addAttribute("cn", "a", "b");
    assertEquals(addRequest.getAttributes().size(), 5);

    addRequest.addAttribute("cn", "c".getBytes("UTF-8"), "d".getBytes("UTF-8"));
    assertEquals(addRequest.getAttributes().size(), 5);

    assertTrue(addRequest.removeAttribute("description"));
    assertFalse(addRequest.removeAttribute("description"));
    assertEquals(addRequest.getAttributes().size(), 4);

    addRequest.addAttribute("displayName", "first", "second");
    assertEquals(addRequest.getAttributes().size(), 5);

    assertTrue(addRequest.removeAttributeValue("displayName", "first"));
    assertEquals(addRequest.getAttributes().size(), 5);

    assertFalse(addRequest.removeAttributeValue("displayName", "first"));
    assertTrue(addRequest.removeAttribute("displayName",
                                          "second".getBytes("UTF-8")));
    assertEquals(addRequest.getAttributes().size(), 4);

    assertFalse(addRequest.removeAttributeValue("missing", "foo"));
    assertEquals(addRequest.getAttributes().size(), 4);

    addRequest.replaceAttribute(new Attribute("cn", "a", "b"));
    assertEquals(addRequest.getAttributes().size(), 4);

    addRequest.replaceAttribute("description", "c");
    assertEquals(addRequest.getAttributes().size(), 5);

    addRequest.replaceAttribute("description", "d", "e");
    assertEquals(addRequest.getAttributes().size(), 5);

    addRequest.replaceAttribute("carLicense", "f".getBytes("UTF-8"));
    assertEquals(addRequest.getAttributes().size(), 6);

    addRequest.replaceAttribute("carLicense", "g".getBytes("UTF-8"),
                                "h".getBytes("UTF-8"));
    assertEquals(addRequest.getAttributes().size(), 6);

    addRequest.addAttribute("telephoneNumber",
                            "123-456-7890".getBytes("UTF-8"),
                            "123-456-7891".getBytes("UTF-8"));
    assertEquals(addRequest.getAttributes().size(), 7);

    addRequest.replaceAttribute("telephoneNumber", "123-456-7892");
    assertEquals(addRequest.getAttributes().size(), 7);

    assertTrue(addRequest.removeAttributeValue("telephoneNumber",
                                               "123-456-7892"));
    assertEquals(addRequest.getAttributes().size(), 6);

    assertFalse(addRequest.removeAttribute("telephoneNumber",
                                           "123-456-7892".getBytes("UTF-8")));
    assertEquals(addRequest.getAttributes().size(), 6);

    addRequest.replaceAttribute(new Attribute("mobile", "123-456-7893"));
    assertEquals(addRequest.getAttributes().size(), 7);

    addRequest.replaceAttribute("mobile", "123-456-7894");
    assertEquals(addRequest.getAttributes().size(), 7);

    addRequest.replaceAttribute("mobile", "123-456-7895".getBytes("UTF-8"));
    assertEquals(addRequest.getAttributes().size(), 7);

    addRequest.replaceAttribute("homePhone", "123-456-7896", "123-456-7897");
    assertEquals(addRequest.getAttributes().size(), 8);

    addRequest.removeAttribute("homePhone");
    assertEquals(addRequest.getAttributes().size(), 7);

    addRequest.replaceAttribute("homePhone", "123-456-7898".getBytes("UTF-8"),
                                "123-456-7897".getBytes("UTF-8"));
    assertEquals(addRequest.getAttributes().size(), 8);

    testEncoding(addRequest);
  }



  /**
   * Tests the {@code duplicate} method to ensure that no changes in the
   * duplicate are reflected in the original request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDuplicate()
         throws Exception
  {
    List<Attribute> origAttrs = Arrays.asList(
         new Attribute("objectClass", "top", "domain"),
         new Attribute("dc", "example"));

    Control[] origControls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString())
    };

    AddRequest originalRequest = new AddRequest("dn: dc=example,dc=com",
                                                "objectClass: top",
                                                "objectClass: domain",
                                                "dc: example");
    originalRequest.addControls(new Control("1.2.3.4"),
                                new Control("1.2.3.5", true,
                                            new ASN1OctetString()));
    AddRequest duplicateRequest = originalRequest.duplicate();

    assertNotNull(duplicateRequest);
    assertFalse(duplicateRequest == originalRequest);

    assertEquals(duplicateRequest.getDN(), originalRequest.getDN());
    assertEquals(new DN(originalRequest.getDN()),
                 new DN("dc=example,dc=com"));
    assertEquals(new DN(duplicateRequest.getDN()),
                 new DN("dc=example,dc=com"));

    assertEquals(duplicateRequest.getAttributes(),
                 originalRequest.getAttributes());
    assertEquals(originalRequest.getAttributes(), origAttrs);
    assertEquals(duplicateRequest.getAttributes(), origAttrs);

    assertTrue(Arrays.equals(originalRequest.getControls(), origControls));
    assertTrue(Arrays.equals(duplicateRequest.getControls(), origControls));

    duplicateRequest.setDN("o=example.com");
    duplicateRequest.removeAttributeValue("objectClass", "domain");
    duplicateRequest.addAttribute("objectClass", "organization");
    duplicateRequest.removeAttribute("dc");
    duplicateRequest.addAttribute("o", "example.com");
    duplicateRequest.clearControls();

    assertFalse(new DN(duplicateRequest.getDN()).equals(
                            new DN(originalRequest.getDN())));
    assertEquals(new DN(originalRequest.getDN()), new DN("dc=example,dc=com"));
    assertEquals(new DN(duplicateRequest.getDN()), new DN("o=example.com"));

    assertFalse(duplicateRequest.getAttributes().equals(
                     originalRequest.getAttributes()));
    assertTrue(originalRequest.getAttributes().equals(origAttrs));
    assertFalse(duplicateRequest.getAttributes().equals(origAttrs));

    assertTrue(Arrays.equals(originalRequest.getControls(), origControls));
    assertFalse(Arrays.equals(duplicateRequest.getControls(), origControls));

    testEncoding(originalRequest);
    testEncoding(duplicateRequest);
  }



  /**
   * Tests to ensure that the encoding for the provided add request is identical
   * when using the stream-based and non-stream-based ASN.1 encoding mechanisms.
   *
   * @param  addRequest  The add request to be tested.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void testEncoding(final AddRequest addRequest)
          throws Exception
  {
    ASN1Element protocolOpElement = addRequest.encodeProtocolOp();

    ASN1Buffer b = new ASN1Buffer();
    addRequest.writeTo(b);

    assertTrue(Arrays.equals(b.toByteArray(), protocolOpElement.encode()));
  }
}
