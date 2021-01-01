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



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code LDAPConstraints}
 * class.
 */
public class LDAPConstraintsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the default constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultConstructor()
         throws Exception
  {
    LDAPConstraints c = new LDAPConstraints();
    c = c.duplicate();

    assertNotNull(c);

    assertEquals(c.getTimeLimit(), 0);

    assertFalse(c.getReferrals());

    assertNull(c.getBindProc());

    assertNull(c.getRebindProc());

    assertEquals(c.getHopLimit(), 5);

    assertNotNull(c.getClientControls());
    assertEquals(c.getClientControls().length, 0);

    assertNotNull(c.getServerControls());
    assertEquals(c.getServerControls().length, 0);

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the constructor that takes an {@code LDAPBind}
   * object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithLDAPBind()
         throws Exception
  {
    LDAPConstraints c = new LDAPConstraints(10000, true,
         new TestLDAPBind("uid=test,dc=example,dc=com", "password"), 1);
    c = c.duplicate();

    assertNotNull(c);

    assertEquals(c.getTimeLimit(), 10000);

    assertTrue(c.getReferrals());

    assertNotNull(c.getBindProc());

    assertNull(c.getRebindProc());

    assertEquals(c.getHopLimit(), 1);

    assertNotNull(c.getClientControls());
    assertEquals(c.getClientControls().length, 0);

    assertNotNull(c.getServerControls());
    assertEquals(c.getServerControls().length, 0);

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the constructor that takes an {@code LDAPRebind}
   * object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithLDAPRebind()
         throws Exception
  {
    LDAPConstraints c = new LDAPConstraints(5000, false,
         new TestLDAPRebind("uid=test,dc=example,dc=com", "password"), 2);
    c = c.duplicate();

    assertNotNull(c);

    assertEquals(c.getTimeLimit(), 5000);

    assertFalse(c.getReferrals());

    assertNull(c.getBindProc());

    assertNotNull(c.getRebindProc());

    assertEquals(c.getHopLimit(), 2);

    assertNotNull(c.getClientControls());
    assertEquals(c.getClientControls().length, 0);

    assertNotNull(c.getServerControls());
    assertEquals(c.getServerControls().length, 0);

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the methods used to get and set the time limit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetTimeLimit()
         throws Exception
  {
    LDAPConstraints c = new LDAPConstraints();
    c = c.duplicate();

    assertEquals(c.getTimeLimit(), 0);
    assertNotNull(c.toString());

    c.setTimeLimit(1234);
    assertEquals(c.getTimeLimit(), 1234);
    assertNotNull(c.toString());

    c.setTimeLimit(0);
    assertEquals(c.getTimeLimit(), 0);
    assertNotNull(c.toString());

    c.setTimeLimit(4321);
    assertEquals(c.getTimeLimit(), 4321);
    assertNotNull(c.toString());

    c.setTimeLimit(-1234);
    assertEquals(c.getTimeLimit(), 0);
    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the methods used to get and set referral
   * behavior.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetReferrals()
         throws Exception
  {
    LDAPConstraints c = new LDAPConstraints();
    c = c.duplicate();

    assertFalse(c.getReferrals());
    assertNotNull(c.toString());

    c.setReferrals(true);
    assertTrue(c.getReferrals());
    assertNotNull(c.toString());

    c.setReferrals(false);
    assertFalse(c.getReferrals());
    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the methods used to get and set the bind
   * procedure.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetBindProc()
         throws Exception
  {
    LDAPConstraints c = new LDAPConstraints();
    c = c.duplicate();

    assertNull(c.getBindProc());
    assertNotNull(c.toString());

    c.setBindProc(new TestLDAPBind("uid=test,dc=example,dc=com", "password"));
    assertNotNull(c.getBindProc());
    assertNotNull(c.toString());

    c.setBindProc(null);
    assertNull(c.getBindProc());
    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the methods used to get and set the rebind
   * procedure.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetRebindProc()
         throws Exception
  {
    LDAPConstraints c = new LDAPConstraints();
    c = c.duplicate();

    assertNull(c.getRebindProc());
    assertNotNull(c.toString());

    c.setRebindProc(
         new TestLDAPRebind("uid=test,dc=example,dc=com", "password"));
    assertNotNull(c.getRebindProc());
    assertNotNull(c.toString());

    c.setRebindProc(null);
    assertNull(c.getRebindProc());
    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the methods used to get and set the hop limit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetHopLimit()
         throws Exception
  {
    LDAPConstraints c = new LDAPConstraints();
    c = c.duplicate();

    assertEquals(c.getHopLimit(), 5);
    assertNotNull(c.toString());

    c.setHopLimit(0);
    assertEquals(c.getHopLimit(), 0);
    assertNotNull(c.toString());

    c.setHopLimit(10);
    assertEquals(c.getHopLimit(), 10);
    assertNotNull(c.toString());

    c.setHopLimit(-1);
    assertEquals(c.getHopLimit(), 0);
    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the methods used to get and set the client
   * controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetClientControls()
         throws Exception
  {
    LDAPConstraints c = new LDAPConstraints();
    c = c.duplicate();

    assertNotNull(c.getClientControls());
    assertEquals(c.getClientControls().length, 0);
    assertNotNull(c.toString());

    c.setClientControls(new LDAPControl("1.2.3.4", true, null));
    assertNotNull(c.getClientControls());
    assertEquals(c.getClientControls().length, 1);
    assertNotNull(c.toString());

    LDAPControl[] controls = new LDAPControl[0];
    c.setClientControls(controls);
    assertNotNull(c.getClientControls());
    assertEquals(c.getClientControls().length, 0);
    assertNotNull(c.toString());

    controls = new LDAPControl[]
    {
      new LDAPControl("1.2.3.4", true, null),
      new LDAPControl("1.2.3.5", false, new byte[0])
    };
    c.setClientControls(controls);
    assertNotNull(c.getClientControls());
    assertEquals(c.getClientControls().length, 2);
    assertNotNull(c.toString());

    controls = null;
    c.setClientControls(controls);
    assertNotNull(c.getClientControls());
    assertEquals(c.getClientControls().length, 0);
    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the methods used to get and set the server
   * controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetServerControls()
         throws Exception
  {
    LDAPConstraints c = new LDAPConstraints();
    c = c.duplicate();

    assertNotNull(c.getServerControls());
    assertEquals(c.getServerControls().length, 0);
    assertNotNull(c.toString());

    c.setServerControls(new LDAPControl("1.2.3.4", true, null));
    assertNotNull(c.getServerControls());
    assertEquals(c.getServerControls().length, 1);
    assertNotNull(c.toString());

    LDAPControl[] controls = new LDAPControl[0];
    c.setServerControls(controls);
    assertNotNull(c.getServerControls());
    assertEquals(c.getServerControls().length, 0);
    assertNotNull(c.toString());

    controls = new LDAPControl[]
    {
      new LDAPControl("1.2.3.4", true, null),
      new LDAPControl("1.2.3.5", false, new byte[0])
    };
    c.setServerControls(controls);
    assertNotNull(c.getServerControls());
    assertEquals(c.getServerControls().length, 2);
    assertNotNull(c.toString());

    controls = null;
    c.setServerControls(controls);
    assertNotNull(c.getServerControls());
    assertEquals(c.getServerControls().length, 0);
    assertNotNull(c.toString());
  }
}
