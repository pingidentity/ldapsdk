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

import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the {@code LDAPSearchConstraints}
 * class.
 */
public class LDAPSearchConstraintsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a set of constraints created with the default constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultConstructor()
         throws Exception
  {
    LDAPSearchConstraints c = new LDAPSearchConstraints();
    c = c.duplicate();

    assertNotNull(c);

    assertEquals(c.getBatchSize(), 1);

    assertEquals(c.getDereference(), DereferencePolicy.NEVER.intValue());

    assertEquals(c.getMaxResults(), 1000);

    assertEquals(c.getServerTimeLimit(), 0);

    assertEquals(c.getTimeLimit(), 0);

    assertFalse(c.getReferrals());

    assertNull(c.getBindProc());

    assertNull(c.getRebindProc());

    assertEquals(c.getHopLimit(), 5);

    assertNotNull(c.toString());
  }



  /**
   * Tests a set of constraints created with a rebind proc but no server time
   * limit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithRebindProcWithoutServerTimeLimit()
         throws Exception
  {
    LDAPSearchConstraints c = new LDAPSearchConstraints(1234, 1, 2, true, 3,
         new TestLDAPRebind("uid=test,dc=example,dc=com", "password"), 4);
    c = c.duplicate();

    assertNotNull(c);

    assertEquals(c.getBatchSize(), 3);

    assertEquals(c.getDereference(), DereferencePolicy.SEARCHING.intValue());

    assertEquals(c.getMaxResults(), 2);

    assertEquals(c.getServerTimeLimit(), 0);

    assertEquals(c.getTimeLimit(), 1234);

    assertTrue(c.getReferrals());

    assertNull(c.getBindProc());

    assertNotNull(c.getRebindProc());

    assertEquals(c.getHopLimit(), 4);

    assertNotNull(c.toString());
  }



  /**
   * Tests a set of constraints created with a rebind proc but and server time
   * limit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithRebindProcWithServerTimeLimit()
         throws Exception
  {
    LDAPSearchConstraints c = new LDAPSearchConstraints(4321, 60, 2, 3, true, 4,
         new TestLDAPRebind("uid=test,dc=example,dc=com", "password"), 6);
    c = c.duplicate();

    assertNotNull(c);

    assertEquals(c.getBatchSize(), 4);

    assertEquals(c.getDereference(), DereferencePolicy.FINDING.intValue());

    assertEquals(c.getMaxResults(), 3);

    assertEquals(c.getServerTimeLimit(), 60);

    assertEquals(c.getTimeLimit(), 4321);

    assertTrue(c.getReferrals());

    assertNull(c.getBindProc());

    assertNotNull(c.getRebindProc());

    assertEquals(c.getHopLimit(), 6);

    assertNotNull(c.toString());
  }



  /**
   * Tests a set of constraints created with a bind proc but and server time
   * limit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithBindProcWithServerTimeLimit()
         throws Exception
  {
    LDAPSearchConstraints c = new LDAPSearchConstraints(4321, 60, 2, 3, true, 4,
         new TestLDAPBind("uid=test,dc=example,dc=com", "password"), 6);
    c = c.duplicate();

    assertNotNull(c);

    assertEquals(c.getBatchSize(), 4);

    assertEquals(c.getDereference(), DereferencePolicy.FINDING.intValue());

    assertEquals(c.getMaxResults(), 3);

    assertEquals(c.getServerTimeLimit(), 60);

    assertEquals(c.getTimeLimit(), 4321);

    assertTrue(c.getReferrals());

    assertNotNull(c.getBindProc());

    assertNull(c.getRebindProc());

    assertEquals(c.getHopLimit(), 6);

    assertNotNull(c.toString());
  }



  /**
   * Tests the methods for getting and setting the batch size.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetBatchSize()
         throws Exception
  {
    LDAPSearchConstraints c = new LDAPSearchConstraints();
    c = c.duplicate();

    assertEquals(c.getBatchSize(), 1);

    c.setBatchSize(5);
    assertEquals(c.getBatchSize(), 5);

    c.setBatchSize(0);
    assertEquals(c.getBatchSize(), 1);
  }



  /**
   * Tests the methods for getting and setting the dereference policy.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetDeref()
         throws Exception
  {
    LDAPSearchConstraints c = new LDAPSearchConstraints();
    c = c.duplicate();

    assertEquals(c.getDereference(), 0);

    c.setDereference(4);
    assertEquals(c.getDereference(), 4);
  }



  /**
   * Tests the methods for getting and setting the size limit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetMaxResults()
         throws Exception
  {
    LDAPSearchConstraints c = new LDAPSearchConstraints();
    c = c.duplicate();

    assertEquals(c.getMaxResults(), 1000);

    c.setMaxResults(0);
    assertEquals(c.getMaxResults(), 0);

    c.setMaxResults(123);
    assertEquals(c.getMaxResults(), 123);

    c.setMaxResults(-1);
    assertEquals(c.getMaxResults(), 0);
  }



  /**
   * Tests the methods for getting and setting the server size limit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetServerTimeLimit()
         throws Exception
  {
    LDAPSearchConstraints c = new LDAPSearchConstraints();
    c = c.duplicate();

    assertEquals(c.getServerTimeLimit(), 0);

    c.setServerTimeLimit(123);
    assertEquals(c.getServerTimeLimit(), 123);

    c.setServerTimeLimit(-1);
    assertEquals(c.getServerTimeLimit(), 0);
  }
}
