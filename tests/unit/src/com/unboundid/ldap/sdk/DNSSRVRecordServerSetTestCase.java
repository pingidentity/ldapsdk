/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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



import java.util.Properties;
import javax.naming.Context;
import javax.net.SocketFactory;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;



/**
 * This class provides a set of test cases for the DNSSRVRecordServerSet class.
 */
public final class DNSSRVRecordServerSetTestCase
       extends LDAPSDKTestCase
{
  /**
   * Performs a basic test using the default settings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaults()
         throws Exception
  {
    final DNSSRVRecordServerSet serverSet = new DNSSRVRecordServerSet(null);

    assertNotNull(serverSet);

    assertNotNull(serverSet.getRecordName());
    assertEquals(serverSet.getRecordName(), "_ldap._tcp");

    assertNotNull(serverSet.getProviderURL());
    assertEquals(serverSet.getProviderURL(), "dns:");

    assertNotNull(serverSet.getJNDIProperties());
    assertTrue(serverSet.getJNDIProperties().containsKey(
         Context.PROVIDER_URL));
    assertTrue(serverSet.getJNDIProperties().containsKey(
         Context.INITIAL_CONTEXT_FACTORY));

    assertEquals(serverSet.getTTLMillis(), (60L * 60L * 1000L));

    assertNull(serverSet.getSocketFactory());

    assertNull(serverSet.getConnectionOptions());

    assertNotNull(serverSet.toString());
  }



  /**
   * Performs a test to ensure that the server set works as expected.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithConnections()
         throws Exception
  {
    // Create two in-memory directory server instances that will be used
    // for testing.  Give each server a base entry with a description that
    // reflects the server being used.  Give each an ou entry that doesn't exist
    // in the other.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    final InMemoryDirectoryServer ds1 = new InMemoryDirectoryServer(cfg);
    ds1.startListening();
    final int port1 = ds1.getListenPort();
    ds1.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: ds1");
    ds1.add(
         "dn: ou=ds1,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: ds1");

    final InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(cfg);
    ds2.startListening();
    final int port2 = ds2.getListenPort();
    ds2.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: ds2");
    ds2.add(
         "dn: ou=ds2,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: ds2");


    // Create a test DNS server that will be used for testing.
    final TestDNSSRVRecordServer dnsServer =
         new TestDNSSRVRecordServer(port1, port2);
    dnsServer.start();
    final int dnsPort = dnsServer.getListenPort();


    // Create a server set that will be used for testing.
    final String recordName = "_ldap._tcp.example.com";
    final String providerURL = "dns://localhost:" + dnsPort;
    final long ttlMillis = 8L * 60L * 60L * 1000L;

    final Properties jndiProperties = new Properties();
    jndiProperties.setProperty("com.example.jndi.dns.recursion", "true");
    jndiProperties.setProperty("com.example.jndi.dns.timeout.initial", "30000");
    jndiProperties.setProperty("com.example.jndi.dns.timeout.retries", "3");

    final DNSSRVRecordServerSet serverSet = new DNSSRVRecordServerSet(
         recordName, providerURL, jndiProperties, ttlMillis,
         SocketFactory.getDefault(), new LDAPConnectionOptions());

    assertNotNull(serverSet);

    assertNotNull(serverSet.getRecordName());
    assertEquals(serverSet.getRecordName(), recordName);

    assertNotNull(serverSet.getProviderURL());
    assertEquals(serverSet.getProviderURL(), providerURL);

    assertNotNull(serverSet.getJNDIProperties());
    assertTrue(serverSet.getJNDIProperties().containsKey(
         Context.PROVIDER_URL));
    assertTrue(serverSet.getJNDIProperties().containsKey(
         Context.INITIAL_CONTEXT_FACTORY));
    assertTrue(serverSet.getJNDIProperties().containsKey(
         "com.example.jndi.dns.recursion"));
    assertTrue(serverSet.getJNDIProperties().containsKey(
         "com.example.jndi.dns.timeout.initial"));
    assertTrue(serverSet.getJNDIProperties().containsKey(
         "com.example.jndi.dns.timeout.retries"));

    assertEquals(serverSet.getTTLMillis(), ttlMillis);

    assertNotNull(serverSet.getSocketFactory());

    assertNotNull(serverSet.getConnectionOptions());

    assertNotNull(serverSet.toString());


    // Test the ability to get a connection with both servers online.  It will
    // always go to the first server because that's the server with the lower
    // priority value.
    LDAPConnection conn = serverSet.getConnection();
    assertNotNull(conn);
    assertValueExists(conn, "dc=example,dc=com", "description", "ds1");
    conn.close();


    // Shut down the first server and verify that we can still get a connection,
    // but this time to the second server.
    ds1.shutDown(true);
    conn = serverSet.getConnection();
    assertNotNull(conn);
    assertValueExists(conn, "dc=example,dc=com", "description", "ds2");
    conn.close();


    // Shut down the second server and verify that we can no longer get a
    // connection.
    ds2.shutDown(true);
    try
    {
      serverSet.getConnection();
      fail("Expected an exception with both servers offline.");
    }
    catch (final Exception e)
    {
      // This was expected.
    }


    // Start both servers and verify that we can again get connections.
    ds1.startListening();
    ds2.startListening();
    conn = serverSet.getConnection();
    assertNotNull(conn);
    assertValueExists(conn, "dc=example,dc=com", "description", "ds1");
    conn.close();


    // Perform the same test with a health check that will match either server.
    GetEntryLDAPConnectionPoolHealthCheck healthCheck =
         new GetEntryLDAPConnectionPoolHealthCheck("dc=example,dc=com", 60000L,
              true, true, true, true, true);
    conn = serverSet.getConnection(healthCheck);
    assertNotNull(conn);
    assertValueExists(conn, "dc=example,dc=com", "description", "ds1");
    conn.close();


    // Perform the same test with a health check that will only match the second
    // server.
    healthCheck = new GetEntryLDAPConnectionPoolHealthCheck(
         "ou=ds2,dc=example,dc=com", 60000L, true, true, true, true, true);
    conn = serverSet.getConnection(healthCheck);
    assertNotNull(conn);
    assertValueExists(conn, "dc=example,dc=com", "description", "ds2");
    conn.close();


    // Perform the same test with a health check that doesn't match either
    // server.
    healthCheck = new GetEntryLDAPConnectionPoolHealthCheck(
         "ou=ds3,dc=example,dc=com", 60000L, true, true, true, true, true);
    try
    {
      serverSet.getConnection(healthCheck);
      fail("Expected an exception with an unsatisfied health check.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Shut down both servers.
    ds1.shutDown(true);
    ds2.shutDown(true);
  }
}
