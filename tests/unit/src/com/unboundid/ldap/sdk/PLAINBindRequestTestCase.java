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

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;



/**
 * This class provides a set of test cases for the PLAINBindRequest class.
 */
public class PLAINBindRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    PLAINBindRequest r = new PLAINBindRequest("u:test.user", "password");
    r = r.duplicate();

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNull(r.getAuthorizationID());

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertEquals(r.getBindType(), "PLAIN");

    assertEquals(r.getSASLMechanismName(), "PLAIN");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    PLAINBindRequest);

    r.getLastMessageID();

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the second constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    PLAINBindRequest r = new PLAINBindRequest("u:test.user",
                                              "password".getBytes("UTF-8"));
    r = r.duplicate();

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNull(r.getAuthorizationID());

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertEquals(r.getBindType(), "PLAIN");

    assertEquals(r.getSASLMechanismName(), "PLAIN");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    PLAINBindRequest);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
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
    PLAINBindRequest r = new PLAINBindRequest("u:test.user",
                                              new ASN1OctetString("password"));
    r = r.duplicate();

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNull(r.getAuthorizationID());

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertEquals(r.getBindType(), "PLAIN");

    assertEquals(r.getSASLMechanismName(), "PLAIN");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    PLAINBindRequest);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the fourth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4()
         throws Exception
  {
    PLAINBindRequest r = new PLAINBindRequest("u:test.user", "u:test2.user",
                                              "password");
    r = r.duplicate();

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "u:test2.user");

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertEquals(r.getBindType(), "PLAIN");

    assertEquals(r.getSASLMechanismName(), "PLAIN");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    PLAINBindRequest);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the fifth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5()
         throws Exception
  {
    PLAINBindRequest r = new PLAINBindRequest("u:test.user", "u:test2.user",
                                              "password".getBytes("UTF-8"));
    r = r.duplicate();

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "u:test2.user");

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertEquals(r.getBindType(), "PLAIN");

    assertEquals(r.getSASLMechanismName(), "PLAIN");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    PLAINBindRequest);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the sixth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6()
         throws Exception
  {
    PLAINBindRequest r = new PLAINBindRequest("u:test.user", "u:test2.user",
                                              new ASN1OctetString("password"));
    r = r.duplicate();

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "u:test2.user");

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertEquals(r.getBindType(), "PLAIN");

    assertEquals(r.getSASLMechanismName(), "PLAIN");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    PLAINBindRequest);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the seventh constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor7()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    PLAINBindRequest r = new PLAINBindRequest("u:test.user", "password",
                                              controls);
    r = r.duplicate();

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNull(r.getAuthorizationID());

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertEquals(r.getBindType(), "PLAIN");

    assertEquals(r.getSASLMechanismName(), "PLAIN");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    PLAINBindRequest);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the eighth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor8()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    PLAINBindRequest r = new PLAINBindRequest("u:test.user",
                                              "password".getBytes("UTF-8"),
                                              controls);
    r = r.duplicate();

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNull(r.getAuthorizationID());

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertEquals(r.getBindType(), "PLAIN");

    assertEquals(r.getSASLMechanismName(), "PLAIN");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    PLAINBindRequest);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the ninth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor9()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    PLAINBindRequest r = new PLAINBindRequest("u:test.user",
                                              new ASN1OctetString("password"),
                                              controls);
    r = r.duplicate();

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNull(r.getAuthorizationID());

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertEquals(r.getBindType(), "PLAIN");

    assertEquals(r.getSASLMechanismName(), "PLAIN");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    PLAINBindRequest);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the tenth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor10()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    PLAINBindRequest r = new PLAINBindRequest("u:test.user", "u:test2.user",
                                              "password", controls);
    r = r.duplicate();

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "u:test2.user");

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertEquals(r.getBindType(), "PLAIN");

    assertEquals(r.getSASLMechanismName(), "PLAIN");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    PLAINBindRequest);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the eleventh constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor11()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    PLAINBindRequest r = new PLAINBindRequest("u:test.user", "u:test2.user",
                                              "password".getBytes("UTF-8"),
                                              controls);
    r = r.duplicate();

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "u:test2.user");

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertEquals(r.getBindType(), "PLAIN");

    assertEquals(r.getSASLMechanismName(), "PLAIN");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    PLAINBindRequest);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the twelfth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor12()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    PLAINBindRequest r = new PLAINBindRequest("u:test.user", "u:test2.user",
                                              new ASN1OctetString("password"),
                                              controls);
    r = r.duplicate();

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:test.user");

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "u:test2.user");

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertEquals(r.getBindType(), "PLAIN");

    assertEquals(r.getSASLMechanismName(), "PLAIN");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    PLAINBindRequest);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the ability of the LDAP SDK to send a SASL PLAIN bind request to
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
    PLAINBindRequest bindRequest =
         new PLAINBindRequest("dn:" + getTestBindDN(), null,
                              getTestBindPassword());

    BindResult bindResult = bindRequest.process(conn, 1);
    assertNotNull(bindResult);
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

    conn.close();
  }
}
