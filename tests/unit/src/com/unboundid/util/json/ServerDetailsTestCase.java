/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
package com.unboundid.util.json;



import java.util.Arrays;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.FailoverServerSet;
import com.unboundid.ldap.sdk.FastestConnectServerSet;
import com.unboundid.ldap.sdk.FewestConnectionsServerSet;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.RoundRobinServerSet;
import com.unboundid.ldap.sdk.ServerSet;
import com.unboundid.ldap.sdk.SingleServerSet;



/**
 * This class provides a set of test cases for the server details class.
 */
public final class ServerDetailsTestCase
       extends LDAPSDKTestCase
{
  // An in-memory directory server instance that may be used for testing.
  private volatile InMemoryDirectoryServer ds = null;



  /**
   * Prepares an in-memory directory server instance to use for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    // Create the in-memory directory server instance.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    cfg.setListenerConfigs(
         InMemoryListenerConfig.createLDAPConfig("LDAP1", null, 0, null),
         InMemoryListenerConfig.createLDAPConfig("LDAP2", null, 0, null));

    ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();
  }



  /**
   * Cleans up after testing is complete.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void cleanUp()
         throws Exception
  {
    if (ds != null)
    {
      ds.shutDown(true);
      ds = null;
    }
  }



  /**
   * Tests the behavior for the case in which the JSON object does not have the
   * server-details field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testNoDetails()
         throws Exception
  {
    final JSONObject o = new JSONObject();

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the JSON object does has a
   * server-details field whose value is an empty JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testEmptyDetails()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject()));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the server-details references a
   * single server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleServer()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort("LDAP1")))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getServerSet());
    assertTrue(spec.getServerSet() instanceof SingleServerSet);

    final SingleServerSet serverSet = (SingleServerSet) spec.getServerSet();
    assertEquals(serverSet.getAddress(), "localhost");
    assertEquals(serverSet.getPort(), ds.getListenPort("LDAP1"));
  }



  /**
   * Tests the behavior for the case in which the server-details references a
   * single server without an address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSingleServerMissingAddress()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the server-details references a
   * single server without a port.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSingleServerMissingPort()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("port", ds.getListenPort("LDAP1")))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the server-details references a
   * fastest connect set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFastestConnectSet()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("fastest-connect-set", new JSONObject(
                   new JSONField("servers", new JSONArray(
                        new JSONObject(
                             new JSONField("address", "localhost"),
                             new JSONField("port", ds.getListenPort("LDAP1"))),
                        new JSONObject(
                             new JSONField("address", "localhost"),
                             new JSONField("port",
                                  ds.getListenPort("LDAP2"))))))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getServerSet());
    assertTrue(spec.getServerSet() instanceof FastestConnectServerSet);

    final FastestConnectServerSet serverSet =
         (FastestConnectServerSet) spec.getServerSet();

    assertTrue(Arrays.equals(serverSet.getAddresses(),
         new String[] { "localhost", "localhost" }));
    assertTrue(Arrays.equals(serverSet.getPorts(),
         new int[] { ds.getListenPort("LDAP1"), ds.getListenPort("LDAP2") }));
  }



  /**
   * Tests the behavior for the case in which the server-details references a
   * fastest connect set in which there is no servers field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testFastestConnectSetWithoutServers()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("fastest-connect-set", new JSONObject()))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the server-details references a
   * fastest connect set in which the value of the servers field is not an
   * array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testFastestConnectSetServersNotArray()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("fastest-connect-set", new JSONObject(
                   new JSONField("servers", "invalid"))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the server-details references a
   * fastest connect set in which the value of the servers field is an empty
   * array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testFastestConnectSetServersEmptyArray()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("fastest-connect-set", new JSONObject(
                   new JSONField("servers", new JSONArray()))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the server-details references a
   * fastest connect set in which the value of the servers field is an array
   * that contains an invalid element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testFastestConnectSetServersArrayWithInvalidElement()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("fastest-connect-set", new JSONObject(
                   new JSONField("servers", new JSONArray(
                        new JSONString("invalid"))))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the server-details references a
   * fewest connections set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFewestConnectionsSet()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("fewest-connections-set", new JSONObject(
                   new JSONField("servers", new JSONArray(
                        new JSONObject(
                             new JSONField("address", "localhost"),
                             new JSONField("port", ds.getListenPort("LDAP1"))),
                        new JSONObject(
                             new JSONField("address", "localhost"),
                             new JSONField("port",
                                  ds.getListenPort("LDAP2"))))))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getServerSet());
    assertTrue(spec.getServerSet() instanceof FewestConnectionsServerSet);

    final FewestConnectionsServerSet serverSet =
         (FewestConnectionsServerSet) spec.getServerSet();

    assertTrue(Arrays.equals(serverSet.getAddresses(),
         new String[] { "localhost", "localhost" }));
    assertTrue(Arrays.equals(serverSet.getPorts(),
         new int[] { ds.getListenPort("LDAP1"), ds.getListenPort("LDAP2") }));
  }



  /**
   * Tests the behavior for the case in which the server-details references a
   * round-robin set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRoundRobinSet()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("round-robin-set", new JSONObject(
                   new JSONField("servers", new JSONArray(
                        new JSONObject(
                             new JSONField("address", "localhost"),
                             new JSONField("port", ds.getListenPort("LDAP1"))),
                        new JSONObject(
                             new JSONField("address", "localhost"),
                             new JSONField("port",
                                  ds.getListenPort("LDAP2"))))))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getServerSet());
    assertTrue(spec.getServerSet() instanceof RoundRobinServerSet);

    final RoundRobinServerSet serverSet =
         (RoundRobinServerSet) spec.getServerSet();

    assertTrue(Arrays.equals(serverSet.getAddresses(),
         new String[] { "localhost", "localhost" }));
    assertTrue(Arrays.equals(serverSet.getPorts(),
         new int[] { ds.getListenPort("LDAP1"), ds.getListenPort("LDAP2") }));
  }



  /**
   * Tests the behavior for the case in which the server-details references a
   * failover set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailoverSet()
         throws Exception
  {
    final JSONObject singleServerObject = new JSONObject(
         new JSONField("single-server", new JSONObject(
              new JSONField("address", "localhost"),
              new JSONField("port", ds.getListenPort("LDAP1")))));
    final JSONObject fastestConnectSetObject = new JSONObject(
         new JSONField("fastest-connect-set", new JSONObject(
              new JSONField("servers", new JSONArray(
                   new JSONObject(
                        new JSONField("address", "localhost"),
                        new JSONField("port", ds.getListenPort("LDAP1"))),
                   new JSONObject(
                        new JSONField("address", "localhost"),
                        new JSONField("port", ds.getListenPort("LDAP1"))))))));
    final JSONObject fewestConnectionsSetObject = new JSONObject(
         new JSONField("fewest-connections-set", new JSONObject(
              new JSONField("servers", new JSONArray(
                   new JSONObject(
                        new JSONField("address", "localhost"),
                        new JSONField("port", ds.getListenPort("LDAP1"))),
                   new JSONObject(
                        new JSONField("address", "localhost"),
                        new JSONField("port", ds.getListenPort("LDAP1"))))))));
    final JSONObject roundRobinSetObject = new JSONObject(
         new JSONField("round-robin-set", new JSONObject(
              new JSONField("servers", new JSONArray(
                   new JSONObject(
                        new JSONField("address", "localhost"),
                        new JSONField("port", ds.getListenPort("LDAP1"))),
                   new JSONObject(
                        new JSONField("address", "localhost"),
                        new JSONField("port", ds.getListenPort("LDAP1"))))))));
    final JSONObject failoverSetObject = new JSONObject(
         new JSONField("failover-set", new JSONObject(
              new JSONField("failover-order", new JSONArray(
                   new JSONObject(
                        new JSONField("single-server", new JSONObject(
                             new JSONField("address", "localhost"),
                             new JSONField("port",
                                  ds.getListenPort("LDAP1"))))),
                   new JSONObject(
                        new JSONField("single-server", new JSONObject(
                             new JSONField("address", "localhost"),
                             new JSONField("port",
                                  ds.getListenPort("LDAP2"))))))))));

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("failover-set", new JSONObject(
                   new JSONField("failover-order", new JSONArray(
                        fastestConnectSetObject,
                        fewestConnectionsSetObject,
                        roundRobinSetObject,
                        failoverSetObject,
                        singleServerObject)),
                   new JSONField("maximum-failover-connection-age-millis",
                        300000L))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getServerSet());
    assertTrue(spec.getServerSet() instanceof FailoverServerSet);

    final FailoverServerSet serverSet =
         (FailoverServerSet) spec.getServerSet();

    final ServerSet[] failoverSets = serverSet.getServerSets();
    assertEquals(failoverSets.length, 5);
    assertTrue(failoverSets[0] instanceof FastestConnectServerSet);
    assertTrue(failoverSets[1] instanceof FewestConnectionsServerSet);
    assertTrue(failoverSets[2] instanceof RoundRobinServerSet);
    assertTrue(failoverSets[3] instanceof FailoverServerSet);
    assertTrue(failoverSets[4] instanceof SingleServerSet);

    assertEquals(serverSet.getMaxFailoverConnectionAgeMillis().longValue(),
              300000L);
  }



  /**
   * Tests the behavior for the case in which the server-details references a
   * failover set but does not include a failover order.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testFailoverSetNoFailoverOrder()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("failover-set", new JSONObject(
                   new JSONField("maximum-failover-connection-age-millis",
                        300000L))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the server-details references a
   * failover set in which the value of the failover-order field is not an
   * array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testFailoverSetNoFailoverOrderNotArray()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("failover-set", new JSONObject(
                   new JSONField("failover-order", "invalid"),
                   new JSONField("maximum-failover-connection-age-millis",
                        300000L))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the server-details references a
   * failover set in which the value of the failover-order field is an empty
   * array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testFailoverSetNoFailoverOrderEmptyArray()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("failover-set", new JSONObject(
                   new JSONField("failover-order", new JSONArray()),
                   new JSONField("maximum-failover-connection-age-millis",
                        300000L))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the server-details references a
   * failover set in which the value of the failover-order field is an array
   * that contains an invalid element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testFailoverSetNoFailoverOrderArrayWithInvalidElement()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("failover-set", new JSONObject(
                   new JSONField("failover-order", new JSONArray(
                        new JSONString("invalid"))),
                   new JSONField("maximum-failover-connection-age-millis",
                        300000L))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }
}
