/*
 * Copyright 2008-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2017 UnboundID Corp.
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
 * This class provides a set of test cases for the RoundRobinServerSet class.
 */
public class RoundRobinServerSetTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a single address and port.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Single()
         throws Exception
  {
    String[] addresses = { "server.example.com" };
    int[]    ports     = { 389 };

    RoundRobinServerSet serverSet = new RoundRobinServerSet(addresses, ports);

    assertNotNull(serverSet.getAddresses());
    assertEquals(serverSet.getAddresses().length, 1);

    assertNotNull(serverSet.getPorts());
    assertEquals(serverSet.getPorts().length, 1);

    assertNotNull(serverSet.getSocketFactory());

    assertNotNull(serverSet.getConnectionOptions());

    assertNotNull(serverSet.toString());
  }



  /**
   * Tests the first constructor with multiple addresses and ports.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Multiple()
         throws Exception
  {
    String[] addresses = { "server1.example.com", "server2.example.com" };
    int[]    ports     = { 389, 389 };

    RoundRobinServerSet serverSet = new RoundRobinServerSet(addresses, ports);

    assertNotNull(serverSet.getAddresses());
    assertEquals(serverSet.getAddresses().length, 2);

    assertNotNull(serverSet.getPorts());
    assertEquals(serverSet.getPorts().length, 2);

    assertNotNull(serverSet.getSocketFactory());

    assertNotNull(serverSet.getConnectionOptions());

    assertNotNull(serverSet.toString());
  }



  /**
   * Tests the first constructor with {@code null} sets of addresses and ports.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1Null()
         throws Exception
  {
    new RoundRobinServerSet(null, null);
  }



  /**
   * Tests the first constructor with empty sets of addresses and ports.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1Empty()
         throws Exception
  {
    new RoundRobinServerSet(new String[0], new int[0]);
  }



  /**
   * Tests the first constructor with a mismatch between the numbers of
   * addresses and ports.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1SizeMismatch()
         throws Exception
  {
    String[] addresses = { "server1.example.com", "server2.example.com" };
    int[]    ports     = { 389 };

    new RoundRobinServerSet(addresses, ports);
  }



  /**
   * Tests the second constructor with a single address and port.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Single()
         throws Exception
  {
    String[] addresses = { "server.example.com" };
    int[]    ports     = { 389 };

    RoundRobinServerSet serverSet =
         new RoundRobinServerSet(addresses, ports, new LDAPConnectionOptions());

    assertNotNull(serverSet.getAddresses());
    assertEquals(serverSet.getAddresses().length, 1);

    assertNotNull(serverSet.getPorts());
    assertEquals(serverSet.getPorts().length, 1);

    assertNotNull(serverSet.getSocketFactory());

    assertNotNull(serverSet.getConnectionOptions());

    assertNotNull(serverSet.toString());
  }



  /**
   * Tests the third constructor with a single address and port.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3Single()
         throws Exception
  {
    String[] addresses = { "server.example.com" };
    int[]    ports     = { 389 };

    RoundRobinServerSet serverSet =
         new RoundRobinServerSet(addresses, ports, SocketFactory.getDefault());

    assertNotNull(serverSet.getAddresses());
    assertEquals(serverSet.getAddresses().length, 1);

    assertNotNull(serverSet.getPorts());
    assertEquals(serverSet.getPorts().length, 1);

    assertNotNull(serverSet.getSocketFactory());

    assertNotNull(serverSet.getConnectionOptions());

    assertNotNull(serverSet.toString());
  }



  /**
   * Tests the fourth constructor with multiple addresses and ports.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4Multiple()
         throws Exception
  {
    String[] addresses = { "server1.example.com", "server2.example.com" };
    int[]    ports     = { 389, 389 };

    RoundRobinServerSet serverSet =
         new RoundRobinServerSet(addresses, ports, null, null);

    assertNotNull(serverSet.getAddresses());
    assertEquals(serverSet.getAddresses().length, 2);

    assertNotNull(serverSet.getPorts());
    assertEquals(serverSet.getPorts().length, 2);

    assertNotNull(serverSet.getSocketFactory());

    assertNotNull(serverSet.getConnectionOptions());

    assertNotNull(serverSet.toString());
  }



  /**
   * Tests the fourth constructor with {@code null} sets of addresses and ports.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor4Null()
         throws Exception
  {
    new RoundRobinServerSet(null, null, null, null);
  }



  /**
   * Tests the fourth constructor with empty sets of addresses and ports.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor4Empty()
         throws Exception
  {
    new RoundRobinServerSet(new String[0], new int[0], null, null);
  }



  /**
   * Tests the fourth constructor with a mismatch between the numbers of
   * addresses and ports.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor4SizeMismatch()
         throws Exception
  {
    String[] addresses = { "server1.example.com", "server2.example.com" };
    int[]    ports     = { 389 };

    new RoundRobinServerSet(addresses, ports, null, null);
  }



  /**
   * Tests the ability to use the round robin server set to create a new
   * connection to a Directory Server.  Note that processing for this test will
   * only be performed if a Directory Server instance is available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetConnectionSingle()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String[] addresses = { getTestHost() };
    int[]    ports     = { getTestPort() };

    RoundRobinServerSet serverSet =
         new RoundRobinServerSet(addresses, ports);

    LDAPConnection conn = serverSet.getConnection();
    assertNotNull(conn);
    assertTrue(conn.isConnected());
    conn.close();

    conn = serverSet.getConnection();
    assertNotNull(conn);
    assertTrue(conn.isConnected());
    conn.close();
  }



  /**
   * Tests the ability to use the round robin server set to create a new
   * connection to a Directory Server.  Note that processing for this test will
   * only be performed if a Directory Server instance is available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetConnectionMultiple()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String[] addresses = { getTestHost(), getTestHost() };
    int[]    ports     = { getTestPort(), getTestPort() };

    RoundRobinServerSet serverSet =
         new RoundRobinServerSet(addresses, ports);
    LDAPConnection conn = serverSet.getConnection();
    assertNotNull(conn);
    assertTrue(conn.isConnected());
    conn.close();

    conn = serverSet.getConnection();
    assertNotNull(conn);
    assertTrue(conn.isConnected());
    conn.close();
  }



  /**
   * Tests the ability to use the round robin server set to create a new
   * connection pool.  Note that processing for this test will only be performed
   * if a Directory Server instance is available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithConnectionPoolSingle()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String[] addresses = { getTestHost() };
    int[]    ports     = { getTestPort() };

    RoundRobinServerSet serverSet =
         new RoundRobinServerSet(addresses, ports);
    SimpleBindRequest bindRequest =
         new SimpleBindRequest(getTestBindDN(), getTestBindPassword());
    LDAPConnectionPool pool = new LDAPConnectionPool(serverSet, bindRequest, 2);

    LDAPConnection conn = pool.getConnection();
    assertNotNull(conn);
    assertTrue(conn.isConnected());
    pool.releaseConnection(conn);

    conn = pool.getConnection();
    assertNotNull(conn);
    assertTrue(conn.isConnected());
    pool.releaseConnection(conn);

    pool.close();
  }



  /**
   * Tests the ability to use the round robin server set to create a new
   * connection pool.  Note that processing for this test will only be performed
   * if a Directory Server instance is available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithConnectionPoolMultiple()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    //   Surely no one would try to run a server on port 2.
    String[] addresses = { getTestHost(), getTestHost() };
    int[]    ports     = { 2, getTestPort() };

    RoundRobinServerSet serverSet =
         new RoundRobinServerSet(addresses, ports);
    SimpleBindRequest bindRequest =
         new SimpleBindRequest(getTestBindDN(), getTestBindPassword());
    LDAPConnectionPool pool =
         new LDAPConnectionPool(serverSet, bindRequest, 2, 5);

    LDAPConnection conn = pool.getConnection();
    assertNotNull(conn);
    assertTrue(conn.isConnected());
    pool.releaseConnection(conn);

    conn = pool.getConnection();
    assertNotNull(conn);
    assertTrue(conn.isConnected());
    pool.releaseConnection(conn);

    pool.close();
  }



  /**
   * Tests the ability to use the round robin server set to create a new
   * connection to a Directory Server when the server is not available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetConnectionFailure()
         throws Exception
  {
    //   Surely no one would try to run a server on port 2.
    String[] addresses = { "127.0.0.1", "127.0.0.1" };
    int[]    ports     = { 2, 2 };

    RoundRobinServerSet serverSet = new RoundRobinServerSet(addresses, ports);
    serverSet.getConnection();
  }
}
