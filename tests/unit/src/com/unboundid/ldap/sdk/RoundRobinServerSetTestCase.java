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

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
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

    assertFalse(serverSet.includesAuthentication());

    assertFalse(serverSet.includesPostConnectProcessing());

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

    assertFalse(serverSet.includesAuthentication());

    assertFalse(serverSet.includesPostConnectProcessing());

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

    assertFalse(serverSet.includesAuthentication());

    assertFalse(serverSet.includesPostConnectProcessing());

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

    assertFalse(serverSet.includesAuthentication());

    assertFalse(serverSet.includesPostConnectProcessing());

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

    assertFalse(serverSet.includesAuthentication());

    assertFalse(serverSet.includesPostConnectProcessing());

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

    // Surely no one would try to run a server on port 2.
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
    // Surely no one would try to run a server on port 2.
    String[] addresses = { "127.0.0.1", "127.0.0.1" };
    int[]    ports     = { 2, 2 };

    RoundRobinServerSet serverSet = new RoundRobinServerSet(addresses, ports);
    serverSet.getConnection();
  }



  /**
   * Tests the behavior of the round robin server set when no blacklist will be
   * used.
   *
   * @throws Exception If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutBlacklist()
       throws Exception
  {
    final InMemoryDirectoryServer ds1 =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds1.startListening();

    final InMemoryDirectoryServer ds2 =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds2.startListening();

    final String[] addresses = { "localhost", "localhost" };
    final int[] ports = { ds1.getListenPort(), ds2.getListenPort() };

    System.setProperty(
         RoundRobinServerSet.
              PROPERTY_DEFAULT_BLACKLIST_CHECK_INTERVAL_MILLIS,
         "0");

    try
    {
      final RoundRobinServerSet serverSet =
           new RoundRobinServerSet(addresses, ports);
      assertNull(serverSet.getBlacklistManager());


      // Get two connections with both servers up and verify that the first
      // goes to ds1 and the second to ds2.
      LDAPConnection conn1 = serverSet.getConnection();
      LDAPConnection conn2 = serverSet.getConnection();

      assertEquals(getServerNumber(conn1, ds1, ds2), 1);
      assertEquals(getServerNumber(conn2, ds1, ds2), 2);

      conn1.close();
      conn2.close();


      // Shut down the first instance.  Get two more connections and verify that
      // they both go to the second instance.
      ds1.shutDown(true);

      conn1 = serverSet.getConnection();
      conn2 = serverSet.getConnection();
      assertEquals(getServerNumber(conn1, ds1,ds2), 2);
      assertEquals(getServerNumber(conn2, ds1,ds2), 2);

      conn1.close();
      conn2.close();


      // Shut down the second instance.  Verify that we are unable to get any
      // more connections.
      ds2.shutDown(true);

      try
      {
        serverSet.getConnection();
        fail("Expected an exception when trying to get a connection with " +
             "both servers offline");
      }
      catch (final Exception e)
      {
        // This was expected.
      }


      // Start up the first instance and get two more connections.  Verify that
      // they both go to that instance.
      ds1.startListening();

      conn1 = serverSet.getConnection();
      conn2 = serverSet.getConnection();

      assertEquals(getServerNumber(conn1, ds1,ds2), 1);
      assertEquals(getServerNumber(conn2, ds1,ds2), 1);

      conn1.close();
      conn2.close();


      // Start up the second instance again.  Try to get two more connections
      // and verify that they go to the second and first instances,
      // respectively.
      ds2.startListening();

      conn1 = serverSet.getConnection();
      conn2 = serverSet.getConnection();

      assertEquals(getServerNumber(conn1, ds1,ds2), 2);
      assertEquals(getServerNumber(conn2, ds1,ds2), 1);

      conn1.close();
      conn2.close();
    }
    finally
    {
      System.clearProperty(RoundRobinServerSet.
           PROPERTY_DEFAULT_BLACKLIST_CHECK_INTERVAL_MILLIS);

      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior of the round-robin server set when the blacklist
   * property has a non-numeric value.
   *
   * @throws Exception If an unexpected problem occurs.
   */
  @Test()
  public void testBlacklistPropertyWithNonNumericValue()
       throws Exception
  {
    final InMemoryDirectoryServer ds1 =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds1.startListening();

    final InMemoryDirectoryServer ds2 =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds2.startListening();

    final String[] addresses = { "localhost", "localhost" };
    final int[] ports = { ds1.getListenPort(), ds2.getListenPort() };

    System.setProperty(
         RoundRobinServerSet.
              PROPERTY_DEFAULT_BLACKLIST_CHECK_INTERVAL_MILLIS,
         "invalid");

    try
    {
      final RoundRobinServerSet serverSet =
           new RoundRobinServerSet(addresses, ports);
      assertNotNull(serverSet.getBlacklistManager());
    }
    finally
    {
      System.clearProperty(RoundRobinServerSet.
           PROPERTY_DEFAULT_BLACKLIST_CHECK_INTERVAL_MILLIS);
    }
  }



  /**
   * Tests the behavior of the round robin server set when a blacklist will be
   * used and will remember when a server has been blacklisted.
   *
   * @throws Exception If an unexpected problem occurs.
   */
  @Test()
  public void testBlacklistMemory()
       throws Exception
  {
    final InMemoryDirectoryServer ds1 =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds1.startListening();

    final InMemoryDirectoryServer ds2 =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds2.startListening();

    final String[] addresses = { "localhost", "localhost" };
    final int[] ports = { ds1.getListenPort(), ds2.getListenPort() };

    try
    {
      final RoundRobinServerSet serverSet =
           new RoundRobinServerSet(addresses, ports);
      assertNotNull(serverSet.getBlacklistManager());


      // Get two connections with both servers up and verify that the first
      // goes to ds1 and the second to ds2.
      LDAPConnection conn1 = serverSet.getConnection();
      LDAPConnection conn2 = serverSet.getConnection();

      assertEquals(getServerNumber(conn1, ds1, ds2), 1);
      assertEquals(getServerNumber(conn2, ds1, ds2), 2);

      conn1.close();
      conn2.close();


      // Shut down the first instance.  Get two more connections and verify that
      // they both go to the second instance.
      ds1.shutDown(true);

      conn1 = serverSet.getConnection();
      conn2 = serverSet.getConnection();
      assertEquals(getServerNumber(conn1, ds1,ds2), 2);
      assertEquals(getServerNumber(conn2, ds1,ds2), 2);

      conn1.close();
      conn2.close();


      // Re-start the first instance.  But the blacklist will remember that it's
      // up and will not have had enough time to check the its availability,
      // so both connections will still go to server 2.
      ds1.startListening();

      conn1 = serverSet.getConnection();
      conn2 = serverSet.getConnection();
      assertEquals(getServerNumber(conn1, ds1,ds2), 2);
      assertEquals(getServerNumber(conn2, ds1,ds2), 2);

      conn1.close();
      conn2.close();


      // Shut down the second instance and try to get two more connections.
      // The server set will think that 2 is available and 1 is not, but when it
      // actually tries, it will find the opposite  is true.  As such, both
      // connections should go to the first instance.
      ds2.shutDown(true);

      conn1 = serverSet.getConnection();
      conn2 = serverSet.getConnection();
      assertEquals(getServerNumber(conn1, ds1,ds2), 1);
      assertEquals(getServerNumber(conn2, ds1,ds2), 1);

      conn1.close();
      conn2.close();


      // Re-start the second instance.  Because of the blacklist, new
      // connections should still go to the first instance.
      ds2.startListening();

      conn1 = serverSet.getConnection();
      conn2 = serverSet.getConnection();
      assertEquals(getServerNumber(conn1, ds1,ds2), 1);
      assertEquals(getServerNumber(conn2, ds1,ds2), 1);

      conn1.close();
      conn2.close();


      // Have the blacklist check availability, which will cause it to see that
      // both servers are usable.  When we get two new connections, the first
      // should go to ds1 and the second to ds2.
      serverSet.getBlacklistManager().checkBlacklistedServers();

      conn1 = serverSet.getConnection();
      conn2 = serverSet.getConnection();
      assertEquals(getServerNumber(conn1, ds1,ds2), 1);
      assertEquals(getServerNumber(conn2, ds1,ds2), 2);

      conn1.close();
      conn2.close();


      // Shut down both instances and try to get a connection.  Verify that it
      // fails.  Try to get two connections so that the blacklist will empty
      // on the first attempt but non-empty on the second.
      ds1.shutDown(true);
      ds2.shutDown(true);

      try
      {
        serverSet.getConnection();
        fail("Expected an exception when trying to get a connection when " +
             "both servers are offline.");
      }
      catch (final Exception e)
      {
        // This was expected.
      }

      try
      {
        serverSet.getConnection();
        fail("Expected an exception when trying to get a connection when " +
             "both servers are offline.");
      }
      catch (final Exception e)
      {
        // This was expected.
      }


      // Start the instances and check availability to ensure the background
      // timer thread gets shut down.
      ds1.startListening();
      ds2.startListening();

      serverSet.getBlacklistManager().checkBlacklistedServers();
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Determines the server to which the connection is established.
   *
   * @param  conn  The connection for which to make the determination.
   * @param  ds1   The first directory server instance.
   * @param  ds2   The second directory server instance.
   *
   * @return  1 to indicate that the connection is established to ds1, or 2 to
   *          indicate that the connection is established to ds2.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private int getServerNumber(final LDAPConnection conn,
                              final InMemoryDirectoryServer ds1,
                              final InMemoryDirectoryServer ds2)
          throws Exception
  {
    final int port = conn.getConnectedPort();
    if (port == ds1.getListenPort())
    {
      return 1;
    }
    else if (port == ds2.getListenPort())
    {
      return 2;
    }
    else
    {
      throw new AssertionError("Connected port of '" + port +
           "' does not match either ds1 port of " + ds1.getListenPort() +
           "' or ds2 port of '" + ds2.getListenPort() + "'.");
    }
  }
}
