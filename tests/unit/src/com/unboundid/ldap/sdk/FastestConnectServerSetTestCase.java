/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;



/**
 * This class provides a set of test cases for the fastest connect server set.
 */
public final class FastestConnectServerSetTestCase
       extends LDAPSDKTestCase
{
  /**
   * A flag that indicates whether concurrent connection attempts will be
   * allowed.
   */
  private static final boolean ALLOW_CONCURRENT_CONNECTIONS =
       new LDAPConnectionOptions().allowConcurrentSocketFactoryUse();



  // The first directory instance to be used.
  private InMemoryDirectoryServer ds1;

  // The second directory instance to be  used.
  private InMemoryDirectoryServer ds2;

  // The set of server ports that should be used.
  private int[] ports;

  // The set of server addresses that should be used.
  private String[] addresses;



  /**
   * Set up the in-memory directory instances to use for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    ds1 = new InMemoryDirectoryServer(cfg);
    ds1.startListening();

    ds2 = new InMemoryDirectoryServer(cfg);
    ds2.startListening();

    addresses = new String[] { "127.0.0.1", "127.0.0.1" };
    ports     = new int[] { ds1.getListenPort(), ds2.getListenPort() };
  }



  /**
   * Shuts down the in-memory directory instances.
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
   * Tests the behavior when configured with just addresses and ports.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimal()
         throws Exception
  {
    final FastestConnectServerSet serverSet =
         new FastestConnectServerSet(addresses, ports);

    assertNotNull(serverSet.getAddresses());
    assertEquals(serverSet.getAddresses().length, 2);

    assertNotNull(serverSet.getPorts());
    assertEquals(serverSet.getPorts().length, 2);

    assertNotNull(serverSet.getConnectionOptions());

    assertNotNull(serverSet.getSocketFactory());

    if (ALLOW_CONCURRENT_CONNECTIONS)
    {
      final LDAPConnection conn = serverSet.getConnection();
      assertNotNull(conn);
      assertTrue(conn.isConnected());
      conn.close();
    }
    else
    {
      try
      {
        final LDAPConnection conn = serverSet.getConnection();
        conn.close();
        fail("Expected an exception when trying to get a connection with " +
             "non-concurrent options");
      }
      catch (final LDAPException le)
      {
        // This was expected.
      }
    }

    assertNotNull(serverSet.toString());
  }



  /**
   * Tests the behavior when configured with addresses, ports, and a socket
   * factory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithSocketFactory()
         throws Exception
  {
    final FastestConnectServerSet serverSet =
         new FastestConnectServerSet(addresses, ports,
              SocketFactory.getDefault());

    assertNotNull(serverSet.getAddresses());
    assertEquals(serverSet.getAddresses().length, 2);

    assertNotNull(serverSet.getPorts());
    assertEquals(serverSet.getPorts().length, 2);

    assertNotNull(serverSet.getConnectionOptions());

    assertNotNull(serverSet.getSocketFactory());

    if (ALLOW_CONCURRENT_CONNECTIONS)
    {
      final LDAPConnection conn = serverSet.getConnection();
      assertNotNull(conn);
      assertTrue(conn.isConnected());
      conn.close();
    }
    else
    {
      try
      {
        final LDAPConnection conn = serverSet.getConnection();
        conn.close();
        fail("Expected an exception when trying to get a connection with " +
             "non-concurrent options");
      }
      catch (final LDAPException le)
      {
        // This was expected.
      }
    }

    assertNotNull(serverSet.toString());
  }



  /**
   * Tests the behavior when configured with addresses, ports, and a set of
   * connection options.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithSocketConnectionOptions()
         throws Exception
  {
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    final FastestConnectServerSet serverSet =
         new FastestConnectServerSet(addresses, ports, connectionOptions);

    assertNotNull(serverSet.getAddresses());
    assertEquals(serverSet.getAddresses().length, 2);

    assertNotNull(serverSet.getPorts());
    assertEquals(serverSet.getPorts().length, 2);

    assertNotNull(serverSet.getConnectionOptions());

    assertNotNull(serverSet.getSocketFactory());

    if (ALLOW_CONCURRENT_CONNECTIONS)
    {
      final LDAPConnection conn = serverSet.getConnection();
      assertNotNull(conn);
      assertTrue(conn.isConnected());
      conn.close();
    }
    else
    {
      try
      {
        final LDAPConnection conn = serverSet.getConnection();
        conn.close();
        fail("Expected an exception when trying to get a connection with " +
             "non-concurrent options");
      }
      catch (final LDAPException le)
      {
        // This was expected.
      }
    }

    assertNotNull(serverSet.toString());
  }



  /**
   * Tests the behavior when configured with addresses, ports, and a set of
   * connection options that disallows concurrent socket factory use.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testWithSocketConnectionOptionsForbiddingConcurrentSFUse()
         throws Exception
  {
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setAllowConcurrentSocketFactoryUse(false);

    final FastestConnectServerSet serverSet =
         new FastestConnectServerSet(addresses, ports, connectionOptions);
    serverSet.getConnection();
  }



  /**
   * Tests the behavior of the server set when one of the target servers is
   * down but the other is still up.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithOneServerDown()
         throws Exception
  {
    if (! ALLOW_CONCURRENT_CONNECTIONS)
    {
      return;
    }

    ds1.shutDown(true);

    try
    {
      final FastestConnectServerSet serverSet =
           new FastestConnectServerSet(addresses, ports);

      final LDAPConnection conn = serverSet.getConnection();
      assertNotNull(conn);
      assertTrue(conn.isConnected());
      conn.close();
    }
    finally
    {
      ds1.startListening();
    }
  }



  /**
   * Tests the behavior of the server set when using a health check that will
   * fail the first connection attempt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithOneHealthCheckFailure()
         throws Exception
  {
    if (! ALLOW_CONCURRENT_CONNECTIONS)
    {
      return;
    }

    final FastestConnectServerSet serverSet =
         new FastestConnectServerSet(addresses, ports);

    final FirstConnectionFailsHealthCheck healthCheck =
         new FirstConnectionFailsHealthCheck();

    final LDAPConnection conn = serverSet.getConnection(healthCheck);
    assertNotNull(conn);
    assertTrue(conn.isConnected());
    conn.close();
  }



  /**
   * Tests the behavior of the server set when both of the target servers are
   * down.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithBothServersDown()
         throws Exception
  {
    if (! ALLOW_CONCURRENT_CONNECTIONS)
    {
      return;
    }

    ds1.shutDown(true);
    ds2.shutDown(true);

    try
    {
      final LDAPConnectionOptions connectionOptions =
           new LDAPConnectionOptions();
      connectionOptions.setConnectTimeoutMillis(10000);

      final FastestConnectServerSet serverSet =
           new FastestConnectServerSet(addresses, ports);

      final long startTime = System.currentTimeMillis();
      try
      {
        final LDAPConnection conn = serverSet.getConnection();
        conn.close();
        fail("Expected an exception when trying to get a connection with " +
             "both servers down");
      }
      catch (final LDAPException le)
      {
        // This was expected.
      }

      final long elapsedTime = System.currentTimeMillis() - startTime;
      assertTrue((elapsedTime < 10000L),
           "Elapsed time for connection failure was " + elapsedTime + "ms");
    }
    finally
    {
      ds1.startListening();
      ds2.startListening();
    }
  }
}
