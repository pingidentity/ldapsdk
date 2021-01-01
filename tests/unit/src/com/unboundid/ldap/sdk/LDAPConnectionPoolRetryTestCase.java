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



import java.util.EnumSet;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryDirectoryServerSnapshot;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;



/**
 * This class provides a set of test cases for the behavior that allows the
 * LDAP SDK to re-try an operation in a connection pool if the attempt fails
 * because of a connection that is no longer valid.
 */
public final class LDAPConnectionPoolRetryTestCase
       extends LDAPSDKTestCase
{
  // The server set that will be used to create the connection pool.
  private FailoverServerSet serverSet;

  // The in-memory directory server instance that will be used for testing.
  private InMemoryDirectoryServer ds;

  // A snapshot of the base configuration to use for the server.
  private InMemoryDirectoryServerSnapshot snapshot;



  /**
   * Sets up an in-memory directory server instance that can be used for
   * testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    cfg.setListenerConfigs(
         InMemoryListenerConfig.createLDAPConfig("listener1"),
         InMemoryListenerConfig.createLDAPConfig("listener2"));

    ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    ds.addEntries(
         generateDomainEntry("example", "dc=com"),
         generateOrgUnitEntry("People", "dc=example,dc=com"),
         generateUserEntry("test.user", "ou=People,dc=example,dc=com", "Test",
              "User", "password"));
    snapshot = ds.createSnapshot();

    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setUseSynchronousMode(true);

    final String[] listenAddresses =
    {
      "localhost",
      "localhost"
    };

    final int[] listenPorts =
    {
      ds.getListenPort("listener1"),
      ds.getListenPort("listener2")
    };

    serverSet = new FailoverServerSet(listenAddresses, listenPorts,
         connectionOptions);
  }



  /**
   * Shuts down the in-memory directory server instance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void cleanUp()
         throws Exception
  {
    ds.shutDown(true);
  }



  /**
   * Provides test coverage for the {@code getRootDSE} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetRootDSE()
         throws Exception
  {
    final LDAPConnectionPool pool = resetServer();

    // Verify that we can get the root DSE with both listeners active.
    assertNotNull(pool.getRootDSE());

    // Shut down the first listener and verify that the operation still succeeds
    // because of the transparent retry on the second listener.
    ds.shutDown("listener1", true);
    assertNotNull(pool.getRootDSE());

    // Shut down the second listener and restart the first and verify that
    // things still work.
    ds.shutDown("listener2", true);
    ds.startListening("listener1");
    assertNotNull(pool.getRootDSE());

    // Shut down the first listener and verify that the attempt fails.
    ds.shutDown("listener1", true);
    try
    {
      pool.getRootDSE();
      fail("Expected an exception when trying to get the root DSE when both " +
           "listeners are offline.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    pool.close();
  }



  /**
   * Provides test coverage for the {@code getSchema} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSchema()
         throws Exception
  {
    final LDAPConnectionPool pool = resetServer();

    // Verify that we can get the schema with both listeners active.
    assertNotNull(pool.getSchema());

    // Shut down the first listener and verify that the operation still succeeds
    // because of the transparent retry on the second listener.
    ds.shutDown("listener1", true);
    assertNotNull(pool.getSchema());

    // Shut down the second listener and restart the first and verify that
    // things still work.
    ds.shutDown("listener2", true);
    ds.startListening("listener1");
    assertNotNull(pool.getSchema());

    // Shut down the first listener and verify that the attempt fails.
    ds.shutDown("listener1", true);
    try
    {
      pool.getSchema();
      fail("Expected an exception when trying to get the schema when both " +
           "listeners are offline.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    pool.close();
  }



  /**
   * Provides test coverage for the {@code getEntry} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetEntry()
         throws Exception
  {
    final LDAPConnectionPool pool = resetServer();

    // Verify that we can get the entry with both listeners active.
    assertNotNull(pool.getEntry("dc=example,dc=com"));

    // Shut down the first listener and verify that the operation still succeeds
    // because of the transparent retry on the second listener.
    ds.shutDown("listener1", true);
    assertNotNull(pool.getEntry("dc=example,dc=com"));

    // Shut down the second listener and restart the first and verify that
    // things still work.
    ds.shutDown("listener2", true);
    ds.startListening("listener1");
    assertNotNull(pool.getEntry("dc=example,dc=com"));

    // Shut down the first listener and verify that the attempt fails.
    ds.shutDown("listener1", true);
    try
    {
      pool.getEntry("dc=example,dc=com");
      fail("Expected an exception when trying to get the dc=example,dc=com " +
           "entry when both listeners are offline.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    pool.close();
  }



  /**
   * Provides test coverage for the {@code add} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAdd()
         throws Exception
  {
    final LDAPConnectionPool pool = resetServer();

    // Verify that we can perform an add with both listeners active
    pool.add(generateOrgUnitEntry("test1", "dc=example,dc=com"));

    // Shut down the first listener and verify that the operation still succeeds
    // because of the transparent retry on the second listener.
    ds.shutDown("listener1", true);
    pool.add(generateOrgUnitEntry("test2", "dc=example,dc=com"));

    // Shut down the second listener and restart the first and verify that
    // things still work.
    ds.shutDown("listener2", true);
    ds.startListening("listener1");
    pool.add(generateOrgUnitEntry("test3", "dc=example,dc=com"));

    // Shut down the first listener and verify that the attempt fails.
    ds.shutDown("listener1", true);
    try
    {
      pool.add(generateOrgUnitEntry("test4", "dc=example,dc=com"));
      fail("Expected an exception when trying to perform an add when both " +
           "listeners are offline.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    pool.close();
  }



  /**
   * Provides test coverage for the {@code bind} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBind()
         throws Exception
  {
    final LDAPConnectionPool pool = resetServer();

    // Verify that we can perform a bind with both listeners active
    pool.bind("cn=Directory Manager", "password");

    // Shut down the first listener and verify that the operation still succeeds
    // because of the transparent retry on the second listener.
    ds.shutDown("listener1", true);
    pool.bind("cn=Directory Manager", "password");

    // Shut down the second listener and restart the first and verify that
    // things still work.
    ds.shutDown("listener2", true);
    ds.startListening("listener1");
    pool.bind("cn=Directory Manager", "password");

    // Shut down the first listener and verify that the attempt fails.
    ds.shutDown("listener1", true);
    try
    {
      pool.bind("cn=Directory Manager", "password");
      fail("Expected an exception when trying to perform an add when both " +
           "listeners are offline.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    pool.close();
  }



  /**
   * Provides test coverage for the {@code compare} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompare()
         throws Exception
  {
    final LDAPConnectionPool pool = resetServer();

    // Verify that we can perform a compare with both listeners active
    assertTrue(pool.compare("dc=example,dc=com", "dc",
         "example").compareMatched());

    // Shut down the first listener and verify that the operation still succeeds
    // because of the transparent retry on the second listener.
    ds.shutDown("listener1", true);
    assertTrue(pool.compare("dc=example,dc=com", "dc",
         "example").compareMatched());

    // Shut down the second listener and restart the first and verify that
    // things still work.
    ds.shutDown("listener2", true);
    ds.startListening("listener1");
    assertTrue(pool.compare("dc=example,dc=com", "dc",
         "example").compareMatched());

    // Shut down the first listener and verify that the attempt fails.
    ds.shutDown("listener1", true);
    try
    {
      assertTrue(pool.compare("dc=example,dc=com", "dc",
           "example").compareMatched());
      fail("Expected an exception when trying to perform an add when both " +
           "listeners are offline.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    pool.close();
  }



  /**
   * Provides test coverage for the {@code delete} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDelete()
         throws Exception
  {
    final LDAPConnectionPool pool = resetServer();
    pool.add(generateOrgUnitEntry("test1", "dc=example,dc=com"));
    pool.add(generateOrgUnitEntry("test2", "dc=example,dc=com"));
    pool.add(generateOrgUnitEntry("test3", "dc=example,dc=com"));
    pool.add(generateOrgUnitEntry("test4", "dc=example,dc=com"));

    // Verify that we can perform a delete with both listeners active
    pool.delete("ou=test1,dc=example,dc=com");

    // Shut down the first listener and verify that the operation still succeeds
    // because of the transparent retry on the second listener.
    ds.shutDown("listener1", true);
    pool.delete("ou=test2,dc=example,dc=com");

    // Shut down the second listener and restart the first and verify that
    // things still work.
    ds.shutDown("listener2", true);
    ds.startListening("listener1");
    pool.delete("ou=test3,dc=example,dc=com");

    // Shut down the first listener and verify that the attempt fails.
    ds.shutDown("listener1", true);
    try
    {
      pool.delete("ou=test4,dc=example,dc=com");
      fail("Expected an exception when trying to perform an add when both " +
           "listeners are offline.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    pool.close();
  }



  /**
   * Provides test coverage for the {@code processExtendedOperation} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedOperation()
         throws Exception
  {
    final LDAPConnectionPool pool = resetServer();

    // Verify that we can process an extended operation with both listeners
    // active.
    assertResultCodeEquals(
         pool.processExtendedOperation(new WhoAmIExtendedRequest()),
         ResultCode.SUCCESS);

    // Shut down the first listener and verify that the operation still succeeds
    // because of the transparent retry on the second listener.
    ds.shutDown("listener1", true);
    assertResultCodeEquals(
         pool.processExtendedOperation(new WhoAmIExtendedRequest()),
         ResultCode.SUCCESS);

    // Shut down the second listener and restart the first and verify that
    // things still work.
    ds.shutDown("listener2", true);
    ds.startListening("listener1");
    assertResultCodeEquals(
         pool.processExtendedOperation(new WhoAmIExtendedRequest()),
         ResultCode.SUCCESS);

    // Shut down the first listener and verify that the attempt fails.
    ds.shutDown("listener1", true);
    try
    {
      assertResultCodeNot(
           pool.processExtendedOperation(new WhoAmIExtendedRequest()),
           ResultCode.SUCCESS);
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    pool.close();
  }



  /**
   * Provides test coverage for the {@code modify} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModify()
         throws Exception
  {
    final LDAPConnectionPool pool = resetServer();

    // Verify that we can perform a modify with both listeners active
    pool.modify(
         "dn: dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: test 1");

    // Shut down the first listener and verify that the operation still succeeds
    // because of the transparent retry on the second listener.
    ds.shutDown("listener1", true);
    pool.modify(
         "dn: dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: test 2");

    // Shut down the second listener and restart the first and verify that
    // things still work.
    ds.shutDown("listener2", true);
    ds.startListening("listener1");
    pool.modify(
         "dn: dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: test 3");

    // Shut down the first listener and verify that the attempt fails.
    ds.shutDown("listener1", true);
    try
    {
      pool.modify(
           "dn: dc=example,dc=com",
           "changeType: modify",
           "replace: description",
           "description: test 4");
      fail("Expected an exception when trying to perform an add when both " +
           "listeners are offline.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    pool.close();
  }



  /**
   * Provides test coverage for the {@code modifyDN} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDN()
         throws Exception
  {
    final LDAPConnectionPool pool = resetServer();
    pool.add(generateOrgUnitEntry("test1", "dc=example,dc=com"));
    pool.add(generateOrgUnitEntry("test2", "dc=example,dc=com"));
    pool.add(generateOrgUnitEntry("test3", "dc=example,dc=com"));
    pool.add(generateOrgUnitEntry("test4", "dc=example,dc=com"));

    // Verify that we can perform a modify DN with both listeners active
    pool.modifyDN("ou=test1,dc=example,dc=com", "ou=test1b", true);

    // Shut down the first listener and verify that the operation still succeeds
    // because of the transparent retry on the second listener.
    ds.shutDown("listener1", true);
    pool.modifyDN("ou=test2,dc=example,dc=com", "ou=test2b", true);

    // Shut down the second listener and restart the first and verify that
    // things still work.
    ds.shutDown("listener2", true);
    ds.startListening("listener1");
    pool.modifyDN("ou=test3,dc=example,dc=com", "ou=test3b", true);

    // Shut down the first listener and verify that the attempt fails.
    ds.shutDown("listener1", true);
    try
    {
      pool.modifyDN("ou=test4,dc=example,dc=com", "ou=test4b", true);
      fail("Expected an exception when trying to perform an add when both " +
           "listeners are offline.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    pool.close();
  }



  /**
   * Provides test coverage for the {@code search} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearch()
         throws Exception
  {
    final LDAPConnectionPool pool = resetServer();

    // Verify that we can perform a search with both listeners active
    pool.search("dc=example,dc=com", SearchScope.BASE, "(objectClass=*)");

    // Shut down the first listener and verify that the operation still succeeds
    // because of the transparent retry on the second listener.
    ds.shutDown("listener1", true);
    pool.search("dc=example,dc=com", SearchScope.BASE, "(objectClass=*)");

    // Shut down the second listener and restart the first and verify that
    // things still work.
    ds.shutDown("listener2", true);
    ds.startListening("listener1");
    pool.search("dc=example,dc=com", SearchScope.BASE, "(objectClass=*)");

    // Shut down the first listener and verify that the attempt fails.
    ds.shutDown("listener1", true);
    try
    {
      pool.search("dc=example,dc=com", SearchScope.BASE, "(objectClass=*)");
      fail("Expected an exception when trying to perform an add when both " +
           "listeners are offline.");
    }
    catch (final LDAPSearchException le)
    {
      // This was expected.
    }

    pool.close();
  }



  /**
   * Provides test coverage for the {@code searchForEntry} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchForEntry()
         throws Exception
  {
    final LDAPConnectionPool pool = resetServer();

    // Verify that we can perform a search with both listeners active
    pool.searchForEntry("dc=example,dc=com", SearchScope.BASE,
         "(objectClass=*)");

    // Shut down the first listener and verify that the operation still succeeds
    // because of the transparent retry on the second listener.
    ds.shutDown("listener1", true);
    pool.searchForEntry("dc=example,dc=com", SearchScope.BASE,
         "(objectClass=*)");

    // Shut down the second listener and restart the first and verify that
    // things still work.
    ds.shutDown("listener2", true);
    ds.startListening("listener1");
    pool.searchForEntry("dc=example,dc=com", SearchScope.BASE,
         "(objectClass=*)");

    // Shut down the first listener and verify that the attempt fails.
    ds.shutDown("listener1", true);
    try
    {
      pool.searchForEntry("dc=example,dc=com", SearchScope.BASE,
           "(objectClass=*)");
      fail("Expected an exception when trying to perform an add when both " +
           "listeners are offline.");
    }
    catch (final LDAPSearchException le)
    {
      // This was expected.
    }

    pool.close();
  }



  /**
   * Ensures that both listeners are running and that the initial snapshot has
   * been restored.  Also creates a new connection pool established to the
   * server.  The pool will be configured to retry failed operations.
   *
   * @return  The connection pool established to the server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private LDAPConnectionPool resetServer()
          throws Exception
  {
    ds.startListening();
    ds.restoreSnapshot(snapshot);

    final LDAPConnectionPool pool = new LDAPConnectionPool(serverSet,
         new SimpleBindRequest("cn=Directory Manager", "password"), 1, 10);

    assertFalse(pool.retryFailedOperationsDueToInvalidConnections());
    assertEquals(pool.getOperationTypesToRetryDueToInvalidConnections(),
         EnumSet.noneOf(OperationType.class));

    pool.setRetryFailedOperationsDueToInvalidConnections(true);
    assertTrue(pool.retryFailedOperationsDueToInvalidConnections());
    assertEquals(pool.getOperationTypesToRetryDueToInvalidConnections(),
         EnumSet.allOf(OperationType.class));

    pool.setRetryFailedOperationsDueToInvalidConnections(false);
    assertFalse(pool.retryFailedOperationsDueToInvalidConnections());
    assertEquals(pool.getOperationTypesToRetryDueToInvalidConnections(),
         EnumSet.noneOf(OperationType.class));

    pool.setRetryFailedOperationsDueToInvalidConnections(true);
    assertTrue(pool.retryFailedOperationsDueToInvalidConnections());
    assertEquals(pool.getOperationTypesToRetryDueToInvalidConnections(),
         EnumSet.allOf(OperationType.class));

    return pool;
  }
}
