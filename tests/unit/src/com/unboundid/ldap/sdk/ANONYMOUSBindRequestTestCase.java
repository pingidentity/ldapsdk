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

import com.unboundid.ldap.listener.InMemoryDirectoryServer;



/**
 * This class provides a set of test cases for the ANONYMOUSBindRequest class.
 */
public class ANONYMOUSBindRequestTestCase
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
    ANONYMOUSBindRequest r = new ANONYMOUSBindRequest();
    r = r.duplicate();

    assertNull(r.getTraceString());

    assertEquals(r.getBindType(), "ANONYMOUS");

    assertEquals(r.getSASLMechanismName(), "ANONYMOUS");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    ANONYMOUSBindRequest);

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
    ANONYMOUSBindRequest r = new ANONYMOUSBindRequest("foo");
    r = r.duplicate();

    assertNotNull(r.getTraceString());
    assertEquals(r.getTraceString(), "foo");

    assertEquals(r.getBindType(), "ANONYMOUS");

    assertEquals(r.getSASLMechanismName(), "ANONYMOUS");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    ANONYMOUSBindRequest);

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
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    ANONYMOUSBindRequest r = new ANONYMOUSBindRequest(controls);
    r = r.duplicate();

    assertNull(r.getTraceString());

    assertEquals(r.getBindType(), "ANONYMOUS");

    assertEquals(r.getSASLMechanismName(), "ANONYMOUS");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    ANONYMOUSBindRequest);

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
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    ANONYMOUSBindRequest r = new ANONYMOUSBindRequest("foo", controls);
    r = r.duplicate();

    assertNotNull(r.getTraceString());
    assertEquals(r.getTraceString(), "foo");

    assertEquals(r.getBindType(), "ANONYMOUS");

    assertEquals(r.getSASLMechanismName(), "ANONYMOUS");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    ANONYMOUSBindRequest);

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the ability of the LDAP SDK to send a SASL ANONYMOUS bind request to
   * authenticate to the server.  This may or may not fail, based on whether the
   * server has enabled support for the ANONYMOUS mechanism.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendANONYMOUSBindWithoutTrace()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final LDAPConnection conn = ds.getConnection();
    final ANONYMOUSBindRequest bindRequest = new ANONYMOUSBindRequest();

    final BindResult bindResult = bindRequest.process(conn, 1);
    assertNotNull(bindResult);
    assertTrue((bindResult.getResultCode() == ResultCode.SUCCESS) ||
               (bindResult.getResultCode() ==
                     ResultCode.AUTH_METHOD_NOT_SUPPORTED));

    conn.close();
  }



  /**
   * Tests the ability of the LDAP SDK to send a SASL ANONYMOUS bind request to
   * authenticate to the server.  This may or may not fail, based on whether the
   * server has enabled support for the ANONYMOUS mechanism.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendANONYMOUSBindWithTrace()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final LDAPConnection conn = ds.getConnection();
    final ANONYMOUSBindRequest bindRequest =
         new ANONYMOUSBindRequest("This is the trace string.");

    final BindResult bindResult = bindRequest.process(conn, 1);
    assertNotNull(bindResult);
    assertTrue((bindResult.getResultCode() == ResultCode.SUCCESS) ||
               (bindResult.getResultCode() ==
                     ResultCode.AUTH_METHOD_NOT_SUPPORTED));

    conn.close();
  }
}
