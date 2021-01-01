/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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



import java.util.Arrays;
import java.util.LinkedList;
import javax.net.SocketFactory;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;



/**
 * This class provides a set of test cases for the fewest connections server
 * set.
 */
public final class FewestConnectionsServerSetTestCase
       extends LDAPSDKTestCase
{
  // The first directory server instance that will be used for testing.
  private InMemoryDirectoryServer ds2 = null;

  // The second directory server instance that will be used for testing.
  private InMemoryDirectoryServer ds1 = null;

  // The ports of the directory server instances.
  private final int[] ports = new int[2];

  // The addresses of the directory server instances.
  private final String[] addresses = new String[2];



  /**
   * Prepares a couple of directory server instances to use in the testing.
   *
   * @throws Exception If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
       throws Exception
  {
    ds1 = new InMemoryDirectoryServer("dc=example,dc=com");
    ds1.startListening();

    ds2 = new InMemoryDirectoryServer("dc=example,dc=com");
    ds2.startListening();

    addresses[0] = "localhost";
    addresses[1] = "localhost";

    ports[0] = ds1.getListenPort();
    ports[1] = ds2.getListenPort();
  }



  /**
   * Cleans up after testing has completed.
   *
   * @throws Exception If an unexpected problem occurs.
   */
  @AfterClass()
  public void cleanUp()
       throws Exception
  {
    ds1.shutDown(true);
    ds2.shutDown(true);
  }



  /**
   * Tests the behavior of the fewest connections server set using the first
   * constructor.
   *
   * @throws Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
       throws Exception
  {
    final FewestConnectionsServerSet set =
         new FewestConnectionsServerSet(addresses, ports);
    assertNotNull(set.getBlacklistManager());

    assertNotNull(set.getAddresses());
    assertTrue(Arrays.equals(set.getAddresses(), addresses));

    assertNotNull(set.getPorts());
    assertTrue(Arrays.equals(set.getPorts(), ports));

    assertNotNull(set.getSocketFactory());

    assertNotNull(set.getConnectionOptions());

    assertFalse(set.includesAuthentication());

    assertFalse(set.includesPostConnectProcessing());

    assertNotNull(set.toString());

    testServerSet(set);
  }



  /**
   * Tests the behavior of the fewest connections server set using the second
   * constructor.
   *
   * @throws Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
       throws Exception
  {
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setUseSynchronousMode(true);

    final FewestConnectionsServerSet set =
         new FewestConnectionsServerSet(addresses, ports, connectionOptions);
    assertNotNull(set.getBlacklistManager());

    assertNotNull(set.getAddresses());
    assertTrue(Arrays.equals(set.getAddresses(), addresses));

    assertNotNull(set.getPorts());
    assertTrue(Arrays.equals(set.getPorts(), ports));

    assertNotNull(set.getSocketFactory());

    assertNotNull(set.getConnectionOptions());

    assertFalse(set.includesAuthentication());

    assertFalse(set.includesPostConnectProcessing());

    assertNotNull(set.toString());

    testServerSet(set);
  }



  /**
   * Tests the behavior of the fewest connections server set using the third
   * constructor.
   *
   * @throws Exception If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
       throws Exception
  {
    final SocketFactory socketFactory = SocketFactory.getDefault();

    final FewestConnectionsServerSet set =
         new FewestConnectionsServerSet(addresses, ports, socketFactory);
    assertNotNull(set.getBlacklistManager());

    assertNotNull(set.getAddresses());
    assertTrue(Arrays.equals(set.getAddresses(), addresses));

    assertNotNull(set.getPorts());
    assertTrue(Arrays.equals(set.getPorts(), ports));

    assertNotNull(set.getSocketFactory());

    assertNotNull(set.getConnectionOptions());

    assertFalse(set.includesAuthentication());

    assertFalse(set.includesPostConnectProcessing());

    assertNotNull(set.toString());

    testServerSet(set);
  }



  /**
   * Tests to ensure that the provided server set works as expected.
   *
   * @param set The server set to be tested.
   *
   * @throws Exception If an unexpected problem occurs.
   */
  private void testServerSet(final FewestConnectionsServerSet set)
       throws Exception
  {
    final LinkedList<LDAPConnection> connList1 = new LinkedList<>();
    final LinkedList<LDAPConnection> connList2 = new LinkedList<>();


    // Use the server set to create connections.  As long as we hold on to all
    // of the connections, each subsequent connection should go to a different
    // server than the previous connection.
    for (int i = 0; i < 10; i++)
    {
      final LDAPConnection conn = set.getConnection();
      assertTrue(conn.isConnected());
      assertEquals(conn.getConnectedAddress(), "localhost");
      switch (getServerNumber(conn))
      {
        case 1:
          connList1.add(conn);
          break;
        case 2:
          connList2.add(conn);
          break;
      }
    }

    assertEquals(connList1.size(), 5);
    assertEquals(connList2.size(), 5);


    // Close three connections in the first set, then create five new
    // connections.  After the first three are created, then each set should
    // have five connections.  After the last two are created, then each set
    // should have six connections.
    for (int i = 0; i < 3; i++)
    {
      final LDAPConnection conn = connList1.remove(0);
      conn.close();
    }

    GetEntryLDAPConnectionPoolHealthCheck healthCheck =
         new GetEntryLDAPConnectionPoolHealthCheck("", 1000L, true, true,
              true, true, true);
    for (int i = 0; i < 3; i++)
    {
      final LDAPConnection conn = set.getConnection(healthCheck);
      assertTrue(conn.isConnected());
      assertEquals(conn.getConnectedAddress(), "localhost");
      assertEquals(getServerNumber(conn), 1);
      connList1.add(conn);
    }

    for (int i = 0; i < 2; i++)
    {
      final LDAPConnection conn = set.getConnection(healthCheck);
      assertTrue(conn.isConnected());
      assertEquals(conn.getConnectedAddress(), "localhost");
      switch (getServerNumber(conn))
      {
        case 1:
          connList1.add(conn);
          break;
        case 2:
          connList2.add(conn);
          break;
      }
    }

    assertEquals(connList1.size(), 6);
    assertEquals(connList2.size(), 6);


    // Close all of the connections in the second set, and then create six new
    // connections.  Ensure that they all go to the second server.
    for (final LDAPConnection conn : connList2)
    {
      conn.close();
    }
    connList2.clear();

    for (int i = 0; i < 6; i++)
    {
      final LDAPConnection conn = set.getConnection(healthCheck);
      assertTrue(conn.isConnected());
      assertEquals(conn.getConnectedAddress(), "localhost");
      assertEquals(getServerNumber(conn), 2);
      connList2.add(conn);
    }

    assertEquals(connList1.size(), 6);
    assertEquals(connList2.size(), 6);


    // Close all of the connections.  Stop the first server instance and verify
    // that all connections get established to the second set.
    while (!connList1.isEmpty())
    {
      final LDAPConnection conn = connList1.remove();
      conn.close();
    }

    while (!connList2.isEmpty())
    {
      final LDAPConnection conn = connList2.remove();
      conn.close();
    }

    ds1.shutDown(true);
    for (int i = 0; i < 10; i++)
    {
      final LDAPConnection conn = set.getConnection();
      assertTrue(conn.isConnected());
      assertEquals(conn.getConnectedAddress(), "localhost");
      assertEquals(getServerNumber(conn), 2);
      connList2.add(conn);
    }
    while (!connList2.isEmpty())
    {
      final LDAPConnection conn = connList2.remove();
      conn.close();
    }


    // Stop the second instance.  Then try to create connections with both
    // servers down.
    ds2.shutDown(true);
    for (int i = 0; i < 10; i++)
    {
      try
      {
        final LDAPConnection conn = set.getConnection(healthCheck);
        conn.close();
        fail("Expected an exception when trying to create a new connection " +
             "with both servers down");
      }
      catch (final LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.CONNECT_ERROR);
      }
    }


    // Start the instances again.  Then try to create connections with a
    // health check that will consider all connections invalid.
    ds1.startListening();
    ds2.startListening();
    healthCheck = new GetEntryLDAPConnectionPoolHealthCheck(
         "ou=missing,dc=example,dc=com", 1000L, true, true, true, true, true);
    for (int i = 0; i < 10; i++)
    {
      try
      {
        final LDAPConnection conn = set.getConnection(healthCheck);
        conn.close();
        fail("Expected an exception when trying to create a new connection " +
             "with a disagreeable health check");
      }
      catch (final LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.SERVER_DOWN);
      }
    }
  }



  /**
   * Tests the behavior of the fewest connections server set when no blacklist
   * will be used.
   *
   * @throws Exception If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutBlacklist()
       throws Exception
  {
    System.setProperty(
         FewestConnectionsServerSet.
              PROPERTY_DEFAULT_BLACKLIST_CHECK_INTERVAL_MILLIS,
         "0");

    try
    {
      final FewestConnectionsServerSet serverSet =
           new FewestConnectionsServerSet(addresses, ports);
      assertNull(serverSet.getBlacklistManager());

      testServerSet(serverSet);


      // Get two connections with both servers up and verify that they go to
      // different servers.
      LDAPConnection conn1 = serverSet.getConnection();
      LDAPConnection conn2 = serverSet.getConnection();
      if (getServerNumber(conn1) == 1)
      {
        assertEquals(getServerNumber(conn2), 2);
      }
      else
      {
        assertEquals(getServerNumber(conn2), 1);
      }

      conn1.close();
      conn2.close();


      // Shut down the first instance.  Get two more connections and verify that
      // they both go to the second instance.
      ds1.shutDown(true);

      conn1 = serverSet.getConnection();
      conn2 = serverSet.getConnection();
      assertEquals(getServerNumber(conn1), 2);
      assertEquals(getServerNumber(conn2), 2);

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
      assertEquals(getServerNumber(conn1), 1);
      assertEquals(getServerNumber(conn2), 1);


      // With the two connections still established, start the second instance.
      // Get four new connections.  Make sure that the first two go to the
      // second instance, and one of the last two goes to server 1 and the other
      // to server 2.
      ds2.startListening();

      final LDAPConnection conn3 = serverSet.getConnection();
      final LDAPConnection conn4 = serverSet.getConnection();
      assertEquals(getServerNumber(conn3), 2);
      assertEquals(getServerNumber(conn4), 2);

      final LDAPConnection conn5 = serverSet.getConnection();
      final LDAPConnection conn6 = serverSet.getConnection();
      if (getServerNumber(conn5) == 1)
      {
        assertEquals(getServerNumber(conn6), 2);
      }
      else
      {
        assertEquals(getServerNumber(conn6), 1);
      }

      conn1.close();
      conn2.close();
      conn3.close();
      conn4.close();
      conn5.close();
      conn6.close();
    }
    finally
    {
      System.clearProperty(
           FewestConnectionsServerSet.
                PROPERTY_DEFAULT_BLACKLIST_CHECK_INTERVAL_MILLIS);
    }
  }



  /**
   * Tests the behavior of the fewest connections server set when the blacklist
   * property has a non-numeric value.
   *
   * @throws Exception If an unexpected problem occurs.
   */
  @Test()
  public void testBlacklistPropertyWithNonNumericValue()
       throws Exception
  {
    System.setProperty(
         FewestConnectionsServerSet.
              PROPERTY_DEFAULT_BLACKLIST_CHECK_INTERVAL_MILLIS,
         "invalid");

    try
    {
      final FewestConnectionsServerSet serverSet =
           new FewestConnectionsServerSet(addresses, ports);
      assertNotNull(serverSet.getBlacklistManager());

      testServerSet(serverSet);

      // Use the blacklist manager to check the blacklisted servers.  This will
      // ensure that the blacklist timer is shut down.
      serverSet.getBlacklistManager().checkBlacklistedServers();
    }
    finally
    {
      System.clearProperty(
           FewestConnectionsServerSet.
                PROPERTY_DEFAULT_BLACKLIST_CHECK_INTERVAL_MILLIS);
    }
  }



  /**
   * Tests the behavior of the server set when there is a blacklist manager
   * that will temporarily remember when a server has been blacklisted.
   *
   * @throws Exception If an unexpected problem occurs.
   */
  @Test()
  public void testBlacklistMemory()
       throws Exception
  {
    final FewestConnectionsServerSet serverSet =
         new FewestConnectionsServerSet(addresses, ports);
    assertNotNull(serverSet.getBlacklistManager());


    // Get two connections while both servers are up set and verify that they go
    // to different servers.
    LDAPConnection conn1 = serverSet.getConnection();
    LDAPConnection conn2 = serverSet.getConnection();
    if (getServerNumber(conn1) == 1)
    {
      assertEquals(getServerNumber(conn2), 2);
    }
    else
    {
      assertEquals(getServerNumber(conn2), 1);
    }

    conn1.close();
    conn2.close();


    // Stop the first instance and try to get two more connections.  Verify that
    // they both go to the second instance.
    ds1.shutDown(true);

    conn1 = serverSet.getConnection();
    conn2 = serverSet.getConnection();
    assertEquals(getServerNumber(conn1), 2);
    assertEquals(getServerNumber(conn2), 2);

    conn1.close();
    conn2.close();


    // Re-start the first instance and try to get two more connections.  The
    // blacklist should remember that the first server was down, and it's not
    // been long enough for the blacklist to have checked them again, so the
    // server set will still assume that it's offline.  Therefore, both
    // connections should still go to server 2.
    ds1.startListening();

    conn1 = serverSet.getConnection();
    conn2 = serverSet.getConnection();
    assertEquals(getServerNumber(conn1), 2);
    assertEquals(getServerNumber(conn2), 2);

    conn1.close();
    conn2.close();


    // Stop the second instance and try to get two more connections.  Server
    // 1 should be blacklisted so it won't be tried initially, but it will be
    // tried as a fallback when the non-blacklisted server isn't available.
    ds2.shutDown(true);

    conn1 = serverSet.getConnection();
    conn2 = serverSet.getConnection();
    assertEquals(getServerNumber(conn1), 1);
    assertEquals(getServerNumber(conn2), 1);

    conn1.close();
    conn2.close();


    // Re-start the second instance and make sure that connections still go to
    // the first instance because of the blacklist.
    ds2.startListening();

    conn1 = serverSet.getConnection();
    conn2 = serverSet.getConnection();
    assertEquals(getServerNumber(conn1), 1);
    assertEquals(getServerNumber(conn2), 1);

    conn1.close();
    conn2.close();


    // Get the blacklist and force a check, which will make both servers
    // available again.  Get two more connections and verify that they go to
    // different servers.
    serverSet.getBlacklistManager().checkBlacklistedServers();

    conn1 = serverSet.getConnection();
    conn2 = serverSet.getConnection();
    if (getServerNumber(conn1) == 1)
    {
      assertEquals(getServerNumber(conn2), 2);
    }
    else
    {
      assertEquals(getServerNumber(conn2), 1);
    }

    conn1.close();
    conn2.close();
  }



  /**
   * Determines the server to which the connection is established.
   *
   * @param  conn  The connection for which to make the determination.
   *
   * @return  1 to indicate that the connection is established to ds1, or 2 to
   *          indicate that the connection is established to ds2.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private int getServerNumber(final LDAPConnection conn)
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
