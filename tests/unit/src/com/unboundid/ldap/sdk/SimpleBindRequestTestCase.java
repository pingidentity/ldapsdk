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

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.protocol.LDAPMessage;



/**
 * This class provides a set of test cases for the SimpleBindRequest class.
 */
public class SimpleBindRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor, which does not take any arguments.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    SimpleBindRequest bindRequest = new SimpleBindRequest();
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 0);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertEquals(bindRequest.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST);

    bindRequest.getLastMessageID();

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the second constructor, which takes a bind DN and password, using
   * non-null, non-empty values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    SimpleBindRequest bindRequest =
         new SimpleBindRequest("cn=Directory Manager", "password");
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "cn=Directory Manager");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "password");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 0);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the second constructor, which takes a bind DN and password, using
   * null values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NullDNAndPassword()
         throws Exception
  {
    SimpleBindRequest bindRequest =
         new SimpleBindRequest((String) null, (String) null);
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 0);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the second constructor, which takes a bind DN and password, using
   * empty values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2EmptyDNAndPassword()
         throws Exception
  {
    SimpleBindRequest bindRequest = new SimpleBindRequest("", "");
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 0);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the third constructor, which takes a bind DN and password, using
   * non-null, non-empty values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    SimpleBindRequest bindRequest =
         new SimpleBindRequest("cn=Directory Manager",
                               "password".getBytes("UTF-8"));
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "cn=Directory Manager");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "password");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 0);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the third constructor, which takes a bind DN and password, using
   * null values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NullDNAndPassword()
         throws Exception
  {
    SimpleBindRequest bindRequest =
         new SimpleBindRequest((String) null, (byte[]) null);
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 0);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the third constructor, which takes a bind DN and password, using
   * empty values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3EmptyDNAndPassword()
         throws Exception
  {
    SimpleBindRequest bindRequest =
         new SimpleBindRequest("", "".getBytes("UTF-8"));
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 0);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the fourth constructor, which takes a bind DN and password, using
   * non-null, non-empty values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4()
         throws Exception
  {
    SimpleBindRequest bindRequest =
         new SimpleBindRequest(new DN("cn=Directory Manager"), "password");
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "cn=Directory Manager");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "password");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 0);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the fourth constructor, which takes a bind DN and password, using
   * null values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4NullDNAndPassword()
         throws Exception
  {
    SimpleBindRequest bindRequest =
         new SimpleBindRequest((DN) null, (String) null);
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 0);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the fourth constructor, which takes a bind DN and password, using
   * empty values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4EmptyDNAndPassword()
         throws Exception
  {
    SimpleBindRequest bindRequest = new SimpleBindRequest(new DN(""), "");
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 0);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the fifth constructor, which takes a bind DN and password, using
   * non-null, non-empty values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5()
         throws Exception
  {
    SimpleBindRequest bindRequest =
         new SimpleBindRequest(new DN("cn=Directory Manager"),
                               "password".getBytes("UTF-8"));
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "cn=Directory Manager");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "password");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 0);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the fifth constructor, which takes a bind DN and password, using
   * null values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5NullDNAndPassword()
         throws Exception
  {
    SimpleBindRequest bindRequest =
         new SimpleBindRequest((DN) null, (byte[]) null);
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 0);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the fifth constructor, which takes a bind DN and password, using
   * empty values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5EmptyDNAndPassword()
         throws Exception
  {
    SimpleBindRequest bindRequest =
         new SimpleBindRequest(new DN(""), "".getBytes("UTF-8"));
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 0);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the sixth constructor, which takes a bind DN, password, and set of
   * controls, using non-null, non-empty values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString())
    };

    SimpleBindRequest bindRequest =
         new SimpleBindRequest("cn=Directory Manager", "password", controls);
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "cn=Directory Manager");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "password");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 2);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the sixth constructor, which takes a bind DN, password, and set of
   * controls, using null values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6NullValues()
         throws Exception
  {
    SimpleBindRequest bindRequest =
         new SimpleBindRequest((String) null, (String) null, (Control[]) null);
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 0);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the sixth constructor, which takes a bind DN, password, and set of
   * controls, using empty values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6EmptyValues()
         throws Exception
  {
    SimpleBindRequest bindRequest =
         new SimpleBindRequest("", "", new Control[0]);
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 0);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the seventh constructor, which takes a bind DN, password, and set of
   * controls, using non-null, non-empty values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor7()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString())
    };

    SimpleBindRequest bindRequest =
         new SimpleBindRequest("cn=Directory Manager",
                               "password".getBytes("UTF-8"), controls);
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "cn=Directory Manager");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "password");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 2);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the seventh constructor, which takes a bind DN, password, and set of
   * controls, using null values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor7NullValues()
         throws Exception
  {
    SimpleBindRequest bindRequest =
         new SimpleBindRequest((String) null, (byte[]) null, (Control[]) null);
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 0);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the seventh constructor, which takes a bind DN, password, and set of
   * controls, using empty values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor7EmptyValues()
         throws Exception
  {
    SimpleBindRequest bindRequest =
         new SimpleBindRequest("", "".getBytes("UTF-8"), new Control[0]);
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 0);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the eighth constructor, which takes a bind DN, password, and set of
   * controls, using non-null, non-empty values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor8()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString())
    };

    SimpleBindRequest bindRequest =
         new SimpleBindRequest(new DN("cn=Directory Manager"), "password",
                               controls);
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "cn=Directory Manager");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "password");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 2);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the eighth constructor, which takes a bind DN, password, and set of
   * controls, using null values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor8NullValues()
         throws Exception
  {
    SimpleBindRequest bindRequest =
         new SimpleBindRequest((DN) null, (String) null, (Control[]) null);
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 0);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the eighth constructor, which takes a bind DN, password, and set of
   * controls, using empty values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor8EmptyValues()
         throws Exception
  {
    SimpleBindRequest bindRequest =
         new SimpleBindRequest(new DN(""), "", new Control[0]);
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 0);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the ninth constructor, which takes a bind DN, password, and set of
   * controls, using non-null, non-empty values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor9()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString())
    };

    SimpleBindRequest bindRequest =
         new SimpleBindRequest(new DN("cn=Directory Manager"),
                               "password".getBytes("UTF-8"), controls);
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "cn=Directory Manager");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "password");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 2);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the ninth constructor, which takes a bind DN, password, and set of
   * controls, using null values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor9NullValues()
         throws Exception
  {
    SimpleBindRequest bindRequest =
         new SimpleBindRequest((DN) null, (byte[]) null, (Control[]) null);
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 0);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the ninth constructor, which takes a bind DN, password, and set of
   * controls, using empty values.
   *
   * @throws  Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor9EmptyValues()
         throws Exception
  {
    SimpleBindRequest bindRequest =
         new SimpleBindRequest(new DN(""), "".getBytes("UTF-8"),
                               new Control[0]);
    bindRequest = bindRequest.duplicate();

    assertNotNull(bindRequest.getBindDN());
    assertEquals(bindRequest.getBindDN(), "");

    assertNotNull(bindRequest.getPassword());
    assertEquals(bindRequest.getPassword().stringValue(), "");

    assertNotNull(bindRequest.getControls());
    assertEquals(bindRequest.getControls().length, 0);

    assertEquals(bindRequest.getBindType(), "SIMPLE");

    SimpleBindRequest rebindRequest =
         bindRequest.getRebindRequest(getTestHost(), getTestPort());
    assertNotNull(bindRequest.getRebindRequest(getTestHost(),
                                               getTestPort()));
    assertEquals(rebindRequest.getBindDN(),
                 bindRequest.getBindDN());
    assertEquals(rebindRequest.getPassword(),
                 bindRequest.getPassword());

    assertNotNull(bindRequest.encodeProtocolOp());

    assertNotNull(bindRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    bindRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    bindRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the ability of the LDAP SDK to send an anonymous simple bind request
   * and receive the corresponding result.  Note that processing for this test
   * will only be performed if a Directory Server instance is available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendAnonymousBind()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getUnauthenticatedConnection();
    SimpleBindRequest bindRequest = new SimpleBindRequest();

    BindResult bindResult = bindRequest.process(conn, 1);
    assertNotNull(bindResult);
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

    conn.close();
  }



  /**
   * Tests the ability of the LDAP SDK to send a simple bind request to
   * authenticate as an admin user, and receive the corresponding result.  Note
   * that processing for this test will only be performed if a Directory Server
   * instance is available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendAdminBind()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getUnauthenticatedConnection();
    SimpleBindRequest bindRequest =
         new SimpleBindRequest(getTestBindDN(), getTestBindPassword());

    BindResult bindResult = bindRequest.process(conn, 1);
    assertNotNull(bindResult);
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

    conn.close();
  }



  /**
   * Tests the ability of the LDAP SDK to send a simple bind request to
   * authenticate as an admin user with an incorrect password, and receive the
   * corresponding result.  Note that processing for this test will only be
   * performed if a Directory Server instance is available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailedAdminBind()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String password;
    if (getTestBindPassword().equals("wrong"))
    {
      password = "notright";
    }
    else
    {
      password = "wrong";
    }

    LDAPConnection conn = getUnauthenticatedConnection();
    SimpleBindRequest bindRequest =
         new SimpleBindRequest(getTestBindDN(), password);

    BindResult bindResult = bindRequest.process(conn, 1);
    assertNotNull(bindResult);
    assertFalse(bindResult.getResultCode() == ResultCode.SUCCESS);

    conn.close();
  }



  /**
   * Tests to ensure that the LDAP SDK will reject attempts to perform a simple
   * bind with a DN but without a password, when operating in synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRejectBindWithDNButNoPasswordSyncMode()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);

    final LDAPConnection conn = ds.getConnection(options);
    final SimpleBindRequest bindRequest =
         new SimpleBindRequest("cn=Directory Manager", "");

    try
    {
      bindRequest.process(conn, 1);
      fail("Expected an exception when binding with a DN but no password");
    }
    catch (LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.PARAM_ERROR);
    }


    // Reconfigure the connection so that it will allow binds with a DN but no
    // password.
    conn.getConnectionOptions().setBindWithDNRequiresPassword(false);
    try
    {
      bindRequest.process(conn, 1);
    }
    catch (LDAPException le)
    {
      // The server will still likely reject the operation, but we should at
      // least verify that it wasn't a parameter error.
      assertFalse(le.getResultCode() == ResultCode.PARAM_ERROR);
    }

    conn.getConnectionOptions().setBindWithDNRequiresPassword(true);
    conn.close();
  }



  /**
   * Tests to ensure that the LDAP SDK will reject attempts to perform a simple
   * bind with a DN but without a password, when operating in asynchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRejectBindWithDNButNoPasswordAsyncMode()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(false);

    final LDAPConnection conn = ds.getConnection(options);
    final SimpleBindRequest bindRequest =
         new SimpleBindRequest("cn=Directory Manager", "");

    try
    {
      bindRequest.process(conn, 1);
      fail("Expected an exception when binding with a DN but no password");
    }
    catch (LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.PARAM_ERROR);
    }


    // Reconfigure the connection so that it will allow binds with a DN but no
    // password.
    conn.getConnectionOptions().setBindWithDNRequiresPassword(false);
    try
    {
      bindRequest.process(conn, 1);
    }
    catch (LDAPException le)
    {
      // The server will still likely reject the operation, but we should at
      // least verify that it wasn't a parameter error.
      assertFalse(le.getResultCode() == ResultCode.PARAM_ERROR);
    }

    conn.getConnectionOptions().setBindWithDNRequiresPassword(true);
    conn.close();
  }
}
