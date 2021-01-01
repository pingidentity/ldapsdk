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



import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.net.SocketFactory;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the FailoverServerSet class.
 */
public class FailoverServerSetTestCase
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

    FailoverServerSet serverSet = new FailoverServerSet(addresses, ports);

    assertFalse(serverSet.reOrderOnFailover());
    assertNull(serverSet.getMaxFailoverConnectionAgeMillis());

    assertNotNull(serverSet.getServerSets());
    assertEquals(serverSet.getServerSets().length, 1);
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

    FailoverServerSet serverSet = new FailoverServerSet(addresses, ports);

    assertFalse(serverSet.reOrderOnFailover());
    assertNull(serverSet.getMaxFailoverConnectionAgeMillis());

    assertNotNull(serverSet.getServerSets());
    assertEquals(serverSet.getServerSets().length, 2);
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
    new FailoverServerSet(null, null);
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
    new FailoverServerSet(new String[0], new int[0]);
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

    new FailoverServerSet(addresses, ports);
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

    FailoverServerSet serverSet =
         new FailoverServerSet(addresses, ports, new LDAPConnectionOptions());

    assertFalse(serverSet.reOrderOnFailover());
    assertNull(serverSet.getMaxFailoverConnectionAgeMillis());

    assertNotNull(serverSet.getServerSets());
    assertEquals(serverSet.getServerSets().length, 1);
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

    FailoverServerSet serverSet =
         new FailoverServerSet(addresses, ports, SocketFactory.getDefault());

    assertFalse(serverSet.reOrderOnFailover());
    assertNull(serverSet.getMaxFailoverConnectionAgeMillis());

    assertNotNull(serverSet.getServerSets());
    assertEquals(serverSet.getServerSets().length, 1);
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

    FailoverServerSet serverSet =
         new FailoverServerSet(addresses, ports, null, null);

    assertFalse(serverSet.reOrderOnFailover());
    assertNull(serverSet.getMaxFailoverConnectionAgeMillis());

    assertNotNull(serverSet.getServerSets());
    assertEquals(serverSet.getServerSets().length, 2);
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
    new FailoverServerSet(null, null, null, null);
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
    new FailoverServerSet(new String[0], new int[0], null, null);
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

    new FailoverServerSet(addresses, ports, null, null);
  }



  /**
   * Tests the fifth constructor with a single server set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5Single()
         throws Exception
  {
    ServerSet[] sets = { new SingleServerSet("server1.example.com", 389) };

    FailoverServerSet serverSet = new FailoverServerSet(sets);

    assertFalse(serverSet.reOrderOnFailover());
    assertNull(serverSet.getMaxFailoverConnectionAgeMillis());

    assertNotNull(serverSet.getServerSets());
    assertEquals(serverSet.getServerSets().length, 1);
    assertNotNull(serverSet.toString());
  }



  /**
   * Tests the fifth constructor with multiple server sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5Multiple()
         throws Exception
  {
    ServerSet[] sets =
    {
      new SingleServerSet("server1.example.com", 389),
      new SingleServerSet("server2.example.com", 389),
    };

    FailoverServerSet serverSet = new FailoverServerSet(sets);

    assertFalse(serverSet.reOrderOnFailover());
    assertNull(serverSet.getMaxFailoverConnectionAgeMillis());

    assertNotNull(serverSet.getServerSets());
    assertEquals(serverSet.getServerSets().length, 2);
    assertNotNull(serverSet.toString());
  }



  /**
   * Tests the fifth constructor with a {@code null} server set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor5Null()
         throws Exception
  {
    new FailoverServerSet((ServerSet[]) null);
  }



  /**
   * Tests the fifth constructor with an empty server set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor5Empty()
         throws Exception
  {
    new FailoverServerSet(new ServerSet[0]);
  }



  /**
   * Tests the sixth constructor with a single server set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6Single()
         throws Exception
  {
    ServerSet[] sets = { new SingleServerSet("server1.example.com", 389) };

    FailoverServerSet serverSet = new FailoverServerSet(Arrays.asList(sets));

    assertFalse(serverSet.reOrderOnFailover());
    assertNull(serverSet.getMaxFailoverConnectionAgeMillis());

    assertNotNull(serverSet.getServerSets());
    assertEquals(serverSet.getServerSets().length, 1);
    assertNotNull(serverSet.toString());
  }



  /**
   * Tests the sixth constructor with multiple server sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6Multiple()
         throws Exception
  {
    ServerSet[] sets =
    {
      new SingleServerSet("server1.example.com", 389),
      new SingleServerSet("server2.example.com", 389),
    };

    FailoverServerSet serverSet = new FailoverServerSet(Arrays.asList(sets));

    assertFalse(serverSet.reOrderOnFailover());
    assertNull(serverSet.getMaxFailoverConnectionAgeMillis());

    assertNotNull(serverSet.getServerSets());
    assertEquals(serverSet.getServerSets().length, 2);
    assertNotNull(serverSet.toString());
  }



  /**
   * Tests the sixth constructor with a {@code null} server set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor6Null()
         throws Exception
  {
    new FailoverServerSet((List<ServerSet>) null);
  }



  /**
   * Tests the sixth constructor with an empty server set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor6Empty()
         throws Exception
  {
    new FailoverServerSet(Collections.<ServerSet>emptyList());
  }



  /**
   * Tests the ability to use the failover server set to create a new connection
   * to a Directory Server.  Note that processing for this test will only be
   * performed if a Directory Server instance is available.
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

    FailoverServerSet serverSet =
         new FailoverServerSet(addresses, ports);

    assertFalse(serverSet.reOrderOnFailover());
    assertNull(serverSet.getMaxFailoverConnectionAgeMillis());

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
   * Tests the ability to use the failover server set to create a new connection
   * to a Directory Server.  Note that processing for this test will only be
   * performed if a Directory Server instance is available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetConnectionSingleWithReOrder()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String[] addresses = { getTestHost() };
    int[]    ports     = { getTestPort() };

    FailoverServerSet serverSet =
         new FailoverServerSet(addresses, ports);

    assertFalse(serverSet.reOrderOnFailover());
    serverSet.setReOrderOnFailover(true);
    assertTrue(serverSet.reOrderOnFailover());

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
   * Tests the ability to use the failover server set to create a new connection
   * to a Directory Server.  Note that processing for this test will only be
   * performed if a Directory Server instance is available.
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

    //   Surely no one would try to run a server on port 2.
    String[] addresses = { getTestHost(), getTestHost() };
    int[]    ports     = { 2, getTestPort() };

    FailoverServerSet serverSet =
         new FailoverServerSet(addresses, ports);

    assertFalse(serverSet.reOrderOnFailover());

    LDAPConnection conn = serverSet.getConnection();
    assertNotNull(conn);
    assertTrue(conn.isConnected());
    conn.close();

    conn = serverSet.getConnection();
    assertNotNull(conn);
    assertTrue(conn.isConnected());
    conn.close();

    // Make sure that the sets haven't been re-ordered.
    final ServerSet[] sets = serverSet.getServerSets();

    assertTrue(sets[0] instanceof SingleServerSet);
    final SingleServerSet set0 = (SingleServerSet) sets[0];
    assertEquals(set0.getPort(), 2);

    assertTrue(sets[1] instanceof SingleServerSet);
    final SingleServerSet set1 = (SingleServerSet) sets[1];
    assertEquals(set1.getPort(), getTestPort());
  }



  /**
   * Tests the ability to use the failover server set to create a new connection
   * to a Directory Server.  Note that processing for this test will only be
   * performed if a Directory Server instance is available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetConnectionMultipleWithReOrder()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    //   Surely no one would try to run a server on port 2.
    String[] addresses = { getTestHost(), getTestHost() };
    int[]    ports     = { 2, getTestPort() };

    FailoverServerSet serverSet =
         new FailoverServerSet(addresses, ports);

    assertFalse(serverSet.reOrderOnFailover());
    serverSet.setReOrderOnFailover(true);
    assertTrue(serverSet.reOrderOnFailover());

    LDAPConnection conn = serverSet.getConnection();
    assertNotNull(conn);
    assertTrue(conn.isConnected());
    conn.close();

    conn = serverSet.getConnection();
    assertNotNull(conn);
    assertTrue(conn.isConnected());
    conn.close();

    // Make sure that the sets have been re-ordered.
    final ServerSet[] sets = serverSet.getServerSets();

    assertTrue(sets[0] instanceof SingleServerSet);
    final SingleServerSet set0 = (SingleServerSet) sets[0];
    assertEquals(set0.getPort(), getTestPort());

    assertTrue(sets[1] instanceof SingleServerSet);
    final SingleServerSet set1 = (SingleServerSet) sets[1];
    assertEquals(set1.getPort(), 2);
  }



  /**
   * Tests the ability to use the failover server set to create a new connection
   * to a Directory Server when the server is not available.
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

    FailoverServerSet serverSet = new FailoverServerSet(addresses, ports);
    serverSet.getConnection();
  }



  /**
   * Tests the ability to use the failover server set to create a new connection
   * to a Directory Server when the server is not available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetConnectionFailureWithReOrder()
         throws Exception
  {
    //   Surely no one would try to run a server on port 2.
    String[] addresses = { "127.0.0.1", "127.0.0.1" };
    int[]    ports     = { 2, 2 };

    FailoverServerSet serverSet = new FailoverServerSet(addresses, ports);

    assertFalse(serverSet.reOrderOnFailover());
    serverSet.setReOrderOnFailover(true);
    assertTrue(serverSet.reOrderOnFailover());

    serverSet.getConnection();
  }



  /**
   * Tests the ability to use the failover server set to create a new connection
   * pool.  Note that processing for this test will only be performed if a
   * Directory Server instance is available.
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

    FailoverServerSet serverSet =
         new FailoverServerSet(addresses, ports);

    assertFalse(serverSet.reOrderOnFailover());

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
   * Tests the ability to use the failover server set to create a new connection
   * pool.  Note that processing for this test will only be performed if a
   * Directory Server instance is available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithConnectionPoolSingleWithReOrder()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String[] addresses = { getTestHost() };
    int[]    ports     = { getTestPort() };

    FailoverServerSet serverSet =
         new FailoverServerSet(addresses, ports);

    assertFalse(serverSet.reOrderOnFailover());
    serverSet.setReOrderOnFailover(true);
    assertTrue(serverSet.reOrderOnFailover());

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
   * Tests the ability to use the failover server set to create a new connection
   * pool.  Note that processing for this test will only be performed if a
   * Directory Server instance is available.
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

    FailoverServerSet serverSet =
         new FailoverServerSet(addresses, ports);

    assertFalse(serverSet.reOrderOnFailover());

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

    // Make sure that the sets haven't been re-ordered.
    final ServerSet[] sets = serverSet.getServerSets();

    assertTrue(sets[0] instanceof SingleServerSet);
    final SingleServerSet set0 = (SingleServerSet) sets[0];
    assertEquals(set0.getPort(), 2);

    assertTrue(sets[1] instanceof SingleServerSet);
    final SingleServerSet set1 = (SingleServerSet) sets[1];
    assertEquals(set1.getPort(), getTestPort());
  }



  /**
   * Tests the ability to use the failover server set to create a new connection
   * pool.  Note that processing for this test will only be performed if a
   * Directory Server instance is available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithConnectionPoolMultipleWithReOrder()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    //   Surely no one would try to run a server on port 2.
    String[] addresses = { getTestHost(), getTestHost() };
    int[]    ports     = { 2, getTestPort() };

    FailoverServerSet serverSet =
         new FailoverServerSet(addresses, ports);

    assertFalse(serverSet.reOrderOnFailover());
    serverSet.setReOrderOnFailover(true);
    assertTrue(serverSet.reOrderOnFailover());

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

    // Make sure that the sets haven been re-ordered.
    final ServerSet[] sets = serverSet.getServerSets();

    assertTrue(sets[0] instanceof SingleServerSet);
    final SingleServerSet set0 = (SingleServerSet) sets[0];
    assertEquals(set0.getPort(), getTestPort());

    assertTrue(sets[1] instanceof SingleServerSet);
    final SingleServerSet set1 = (SingleServerSet) sets[1];
    assertEquals(set1.getPort(), 2);
  }



  /**
   * Tests the behavior of the server set with regard to the maximum failover
   * connection age.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMaxFailoverConnectionAge()
         throws Exception
  {
    // Create two in-memory servers and a failover server set across them.
    final InMemoryDirectoryServer ds1 =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds1.startListening();
    final int port1 = ds1.getListenPort();

    final InMemoryDirectoryServer ds2 =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds2.startListening();
    final int port2 = ds2.getListenPort();

    final String[] addresses =
    {
      "localhost",
      "localhost"
    };

    final int[] ports =
    {
      port1,
      port2
    };

    final FailoverServerSet failoverSet =
         new FailoverServerSet(addresses, ports);


    // Ensure that by default, no maximum age is set for either preferred or
    // failover connections.
    assertNull(failoverSet.getMaxFailoverConnectionAgeMillis());

    LDAPConnection conn = failoverSet.getConnection();
    assertEquals(conn.getConnectedPort(), port1);
    assertNull(conn.getAttachment(
         LDAPConnectionPool.ATTACHMENT_NAME_MAX_CONNECTION_AGE));
    conn.close();

    ds1.shutDown(true);
    conn = failoverSet.getConnection();
    assertEquals(conn.getConnectedPort(), port2);
    assertNull(conn.getAttachment(
         LDAPConnectionPool.ATTACHMENT_NAME_MAX_CONNECTION_AGE));
    conn.close();
    ds1.startListening();


    // Set a positive maximum failover connection age and ensure that it is
    // properly applied only to failover connections.
    failoverSet.setMaxFailoverConnectionAgeMillis(1234L);
    assertNotNull(failoverSet.getMaxFailoverConnectionAgeMillis());
    assertEquals(failoverSet.getMaxFailoverConnectionAgeMillis(),
         Long.valueOf(1234L));

    conn = failoverSet.getConnection();
    assertEquals(conn.getConnectedPort(), port1);
    assertNull(conn.getAttachment(
         LDAPConnectionPool.ATTACHMENT_NAME_MAX_CONNECTION_AGE));
    conn.close();

    ds1.shutDown(true);
    conn = failoverSet.getConnection();
    assertEquals(conn.getConnectedPort(), port2);
    assertNotNull(conn.getAttachment(
         LDAPConnectionPool.ATTACHMENT_NAME_MAX_CONNECTION_AGE));
    assertEquals(
         conn.getAttachment(
              LDAPConnectionPool.ATTACHMENT_NAME_MAX_CONNECTION_AGE),
         1234L);
    conn.close();
    ds1.startListening();


    // Set a negative maximum failover connection age and ensure that it is
    // properly applied only to failover connections.
    failoverSet.setMaxFailoverConnectionAgeMillis(-1234L);
    assertNotNull(failoverSet.getMaxFailoverConnectionAgeMillis());
    assertEquals(failoverSet.getMaxFailoverConnectionAgeMillis(),
         Long.valueOf(0L));

    conn = failoverSet.getConnection();
    assertEquals(conn.getConnectedPort(), port1);
    assertNull(conn.getAttachment(
         LDAPConnectionPool.ATTACHMENT_NAME_MAX_CONNECTION_AGE));
    conn.close();

    ds1.shutDown(true);
    conn = failoverSet.getConnection();
    assertEquals(conn.getConnectedPort(), port2);
    assertNotNull(conn.getAttachment(
         LDAPConnectionPool.ATTACHMENT_NAME_MAX_CONNECTION_AGE));
    assertEquals(
         conn.getAttachment(
              LDAPConnectionPool.ATTACHMENT_NAME_MAX_CONNECTION_AGE),
         0L);
    conn.close();
    ds1.startListening();


    // Set a null maximum failover connection age and ensure that no maximum
    // connection age is set for either preferred or failover connections.
    failoverSet.setMaxFailoverConnectionAgeMillis(null);
    assertNull(failoverSet.getMaxFailoverConnectionAgeMillis());

    conn = failoverSet.getConnection();
    assertEquals(conn.getConnectedPort(), port1);
    assertNull(conn.getAttachment(
         LDAPConnectionPool.ATTACHMENT_NAME_MAX_CONNECTION_AGE));
    conn.close();

    ds1.shutDown(true);
    conn = failoverSet.getConnection();
    assertEquals(conn.getConnectedPort(), port2);
    assertNull(conn.getAttachment(
         LDAPConnectionPool.ATTACHMENT_NAME_MAX_CONNECTION_AGE));
    conn.close();

    ds2.shutDown(true);
  }
}
