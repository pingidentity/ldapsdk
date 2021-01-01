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



import javax.net.SocketFactory;

import org.testng.annotations.Test;

import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the SingleServerSet class.
 */
public class SingleServerSetTestCase
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
    SingleServerSet serverSet = new SingleServerSet("server.example.com", 389);

    assertEquals(serverSet.getAddress(), "server.example.com");
    assertEquals(serverSet.getPort(), 389);
    assertNotNull(serverSet.getSocketFactory());
    assertNotNull(serverSet.getConnectionOptions());
    assertNotNull(serverSet.toString());
  }



  /**
   * Tests the first constructor with a {@code null} address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NullAddress()
         throws Exception
  {
    new SingleServerSet(null, 389);
  }



  /**
   * Tests the first constructor with an invalid port number.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1PortTooLow()
         throws Exception
  {
    new SingleServerSet("server.example.com", 0);
  }



  /**
   * Tests the first constructor with an invalid port number.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1PortTooHigh()
         throws Exception
  {
    new SingleServerSet("server.example.com", 65536);
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
    SingleServerSet serverSet =
         new SingleServerSet("server.example.com", 389,
                             new LDAPConnectionOptions());

    assertEquals(serverSet.getAddress(), "server.example.com");
    assertEquals(serverSet.getPort(), 389);
    assertNotNull(serverSet.getSocketFactory());
    assertNotNull(serverSet.getConnectionOptions());
    assertNotNull(serverSet.toString());
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
    SingleServerSet serverSet =
         new SingleServerSet("server.example.com", 389,
                             SocketFactory.getDefault());

    assertEquals(serverSet.getAddress(), "server.example.com");
    assertEquals(serverSet.getPort(), 389);
    assertNotNull(serverSet.getSocketFactory());
    assertNotNull(serverSet.getConnectionOptions());
    assertNotNull(serverSet.toString());
  }



  /**
   * Tests the fourth constructor with a {@code null} socket factory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4NullSocketFactory()
         throws Exception
  {
    SingleServerSet serverSet =
         new SingleServerSet("server.example.com", 389, null, null);

    assertEquals(serverSet.getAddress(), "server.example.com");
    assertEquals(serverSet.getPort(), 389);
    assertNotNull(serverSet.getSocketFactory());
    assertNotNull(serverSet.getConnectionOptions());
    assertNotNull(serverSet.toString());
  }



  /**
   * Tests the fourth constructor with a {@code null} address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor4NullAddress()
         throws Exception
  {
    new SingleServerSet(null, 389, null, null);
  }



  /**
   * Tests the fourth constructor with an invalid port number.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor4PortTooLow()
         throws Exception
  {
    new SingleServerSet("server.example.com", 0, null, null);
  }



  /**
   * Tests the fourth constructor with an invalid port number.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor4PortTooHigh()
         throws Exception
  {
    new SingleServerSet("server.example.com", 65536, null, null);
  }



  /**
   * Tests the ability to use the single server set to create a new connection
   * to a Directory Server.  Note that processing for this test will only be
   * performed if a Directory Server instance is available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetConnection()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    SingleServerSet serverSet =
         new SingleServerSet(getTestHost(), getTestPort());
    LDAPConnection conn = serverSet.getConnection();
    assertNotNull(conn);
    assertTrue(conn.isConnected());
    conn.close();
  }



  /**
   * Tests the ability to use the single server set to create a new connection
   * pool.  Note that processing for this test will only be performed if a
   * Directory Server instance is available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithConnectionPool()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    SingleServerSet serverSet =
         new SingleServerSet(getTestHost(), getTestPort());
    SimpleBindRequest bindRequest =
         new SimpleBindRequest(getTestBindDN(), getTestBindPassword());
    LDAPConnectionPool pool =
         new LDAPConnectionPool(serverSet, bindRequest, 2, 5);

    LDAPConnection conn = pool.getConnection();
    assertNotNull(conn);
    assertTrue(conn.isConnected());

    pool.releaseConnection(conn);
    pool.close();
  }
}
