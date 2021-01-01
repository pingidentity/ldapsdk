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



/**
 * This class provides a set of test cases for the EXTERNALBindRequest class.
 */
public class EXTERNALBindRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the constructor which does not take any arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultConstructor()
         throws Exception
  {
    EXTERNALBindRequest r = new EXTERNALBindRequest();
    r = r.duplicate();

    assertEquals(r.getBindType(), "EXTERNAL");

    assertEquals(r.getSASLMechanismName(), "EXTERNAL");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    EXTERNALBindRequest);

    assertNull(r.getAuthorizationID());

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
   * Tests the constructor which takes an authorization ID using an empty
   * string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithEmptyAuthZID()
         throws Exception
  {
    EXTERNALBindRequest r = new EXTERNALBindRequest("");
    r = r.duplicate();

    assertEquals(r.getBindType(), "EXTERNAL");

    assertEquals(r.getSASLMechanismName(), "EXTERNAL");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    EXTERNALBindRequest);

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "");

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
   * Tests the constructor which takes an authorization ID using an empty
   * string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithNonEmptyAuthZID()
         throws Exception
  {
    EXTERNALBindRequest r = new EXTERNALBindRequest("u:test.user");
    r = r.duplicate();

    assertEquals(r.getBindType(), "EXTERNAL");

    assertEquals(r.getSASLMechanismName(), "EXTERNAL");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    EXTERNALBindRequest);

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "u:test.user");

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
   * Tests the constructor which takes a set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithControls()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    EXTERNALBindRequest r = new EXTERNALBindRequest(controls);
    r = r.duplicate();

    assertEquals(r.getBindType(), "EXTERNAL");

    assertEquals(r.getSASLMechanismName(), "EXTERNAL");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    EXTERNALBindRequest);

    assertNull(r.getAuthorizationID());

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
   * Tests the constructor which takes an authorization ID and set of controls
   * using an authorization ID that is the empty string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithEmptyAuthZIDAndControls()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    EXTERNALBindRequest r = new EXTERNALBindRequest("", controls);
    r = r.duplicate();

    assertEquals(r.getBindType(), "EXTERNAL");

    assertEquals(r.getSASLMechanismName(), "EXTERNAL");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    EXTERNALBindRequest);

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "");

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
   * Tests the constructor which takes an authorization ID and set of controls
   * using an authorization ID that is a non-empty string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithNonEmptyAuthZIDAndControls()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    EXTERNALBindRequest r = new EXTERNALBindRequest("u:test.user", controls);
    r = r.duplicate();

    assertEquals(r.getBindType(), "EXTERNAL");

    assertEquals(r.getSASLMechanismName(), "EXTERNAL");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getRebindRequest("server.example.com", 389));
    assertTrue(r.getRebindRequest("server.example.com", 389) instanceof
                    EXTERNALBindRequest);

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "u:test.user");

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
   * Tests the ability of the LDAP SDK to send a SASL EXTERNAL bind request to
   * authenticate to the server.  This should fail, since we will be using a
   * clear-text connection with no certificate.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendEXTERNALBind()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getUnauthenticatedConnection();
    EXTERNALBindRequest bindRequest =
         new EXTERNALBindRequest();

    BindResult bindResult = bindRequest.process(conn, 1);
    assertNotNull(bindResult);
    assertEquals(bindResult.getResultCode(), ResultCode.INVALID_CREDENTIALS);

    bindRequest.getLastMessageID();

    conn.close();
  }
}
