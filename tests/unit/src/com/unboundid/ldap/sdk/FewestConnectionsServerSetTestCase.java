/*
 * Copyright 2013-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2013-2017 UnboundID Corp.
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
   * @throws  Exception  If an unexpected problem occurs.
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
   * @throws  Exception  If an unexpected problem occurs.
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
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    final FewestConnectionsServerSet set =
         new FewestConnectionsServerSet(addresses, ports);

    assertNotNull(set.getAddresses());
    assertEquals(set.getAddresses(), addresses);

    assertNotNull(set.getPorts());
    assertEquals(set.getPorts(), ports);

    assertNotNull(set.getSocketFactory());

    assertNotNull(set.getConnectionOptions());

    assertNotNull(set.toString());

    testServerSet(set);
  }



  /**
   * Tests the behavior of the fewest connections server set using the second
   * constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setUseSynchronousMode(true);

    final FewestConnectionsServerSet set =
         new FewestConnectionsServerSet(addresses, ports, connectionOptions);

    assertNotNull(set.getAddresses());
    assertEquals(set.getAddresses(), addresses);

    assertNotNull(set.getPorts());
    assertEquals(set.getPorts(), ports);

    assertNotNull(set.getSocketFactory());

    assertNotNull(set.getConnectionOptions());

    assertNotNull(set.toString());

    testServerSet(set);
  }



  /**
   * Tests the behavior of the fewest connections server set using the third
   * constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    final SocketFactory socketFactory = SocketFactory.getDefault();

    final FewestConnectionsServerSet set =
         new FewestConnectionsServerSet(addresses, ports, socketFactory);

    assertNotNull(set.getAddresses());
    assertEquals(set.getAddresses(), addresses);

    assertNotNull(set.getPorts());
    assertEquals(set.getPorts(), ports);

    assertNotNull(set.getSocketFactory());

    assertNotNull(set.getConnectionOptions());

    assertNotNull(set.toString());

    testServerSet(set);
  }



  /**
   * Tests to ensure that the provided server set works as expected.
   *
   * @param  set  The server set to be tested.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private void testServerSet(final FewestConnectionsServerSet set)
          throws Exception
  {
    final LinkedList<LDAPConnection> connList1 =
         new LinkedList<LDAPConnection>();
    final LinkedList<LDAPConnection> connList2 =
         new LinkedList<LDAPConnection>();


    // Use the server set to create and close connections.  As long as there
    // are no previously-established connections, all of them should go to the
    // first server.
    for (int i=0; i < 10; i++)
    {
      final LDAPConnection conn = set.getConnection();
      assertTrue(conn.isConnected());
      assertEquals(conn.getConnectedAddress(), "localhost");
      assertEquals(conn.getConnectedPort(), ds1.getListenPort());
      conn.close();
    }


    // Use the server set to create ten connections.  With no connections
    // established, they should go to alternate servers (evens to server 1,
    // odds to server 2).
    for (int i=0; i < 10; i++)
    {
      final LDAPConnection conn = set.getConnection();
      assertTrue(conn.isConnected());
      assertEquals(conn.getConnectedAddress(), "localhost");

      if ((i % 2) == 0)
      {
        assertEquals(conn.getConnectedPort(), ds1.getListenPort());
        connList1.add(conn);
      }
      else
      {
        assertEquals(conn.getConnectedPort(), ds2.getListenPort());
        connList2.add(conn);
      }
    }
    assertEquals(connList1.size(), 5);
    assertEquals(connList2.size(), 5);


    // Close three connections in the first set, and then create five new
    // connections.  Ensure that the first four connections go to the first
    // set and the fifth to the second set.
    for (int i=0; i < 3; i++)
    {
      connList1.remove().close();
    }

    GetEntryLDAPConnectionPoolHealthCheck healthCheck =
         new GetEntryLDAPConnectionPoolHealthCheck("", 1000L, true, true,
              true, true, true);
    for (int i=0 ; i < 5; i++)
    {
      final LDAPConnection conn = set.getConnection(healthCheck);
      assertTrue(conn.isConnected());
      assertEquals(conn.getConnectedAddress(), "localhost");
      if (i == 4)
      {
        assertEquals(conn.getConnectedPort(), ds2.getListenPort());
        connList2.add(conn);
      }
      else
      {
        assertEquals(conn.getConnectedPort(), ds1.getListenPort());
        connList1.add(conn);
      }
    }
    assertEquals(connList1.size(), 6);
    assertEquals(connList2.size(), 6);


    // Close all of the connections in the second set, and then create ten
    // new connections.  Ensure that the first six connections go to the
    // second set, then alternate between the sets after that.
    while (! connList2.isEmpty())
    {
      final LDAPConnection conn = connList2.remove();
      conn.close();
    }

    for (int i=0; i < 10; i++)
    {
      final LDAPConnection conn = set.getConnection();
      assertTrue(conn.isConnected());
      assertEquals(conn.getConnectedAddress(), "localhost");
      if ((i < 6) || ((i % 2) == 1))
      {
        assertEquals(conn.getConnectedPort(), ds2.getListenPort());
        connList2.add(conn);
      }
      else
      {
        assertEquals(conn.getConnectedPort(), ds1.getListenPort());
        connList1.add(conn);
      }
    }
    assertEquals(connList1.size(), 8);
    assertEquals(connList2.size(), 8);


    // Close all of the connections.  Stop the first server instance and verify
    // that all connections get established to the second set.
    while (! connList1.isEmpty())
    {
      final LDAPConnection conn = connList1.remove();
      conn.close();
    }

    while (! connList2.isEmpty())
    {
      final LDAPConnection conn = connList2.remove();
      conn.close();
    }

    ds1.shutDown(true);
    for (int i=0; i < 10; i++)
    {
      final LDAPConnection conn = set.getConnection();
      assertTrue(conn.isConnected());
      assertEquals(conn.getConnectedAddress(), "localhost");
      assertEquals(conn.getConnectedPort(), ds2.getListenPort());
      connList2.add(conn);
    }
    while (! connList2.isEmpty())
    {
      final LDAPConnection conn = connList2.remove();
      conn.close();
    }


    // Stop the second instance.  Then try to create connections with both
    // servers down.
    ds2.shutDown(true);
    for (int i=0; i < 10; i++)
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
    for (int i=0; i < 10; i++)
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
}
