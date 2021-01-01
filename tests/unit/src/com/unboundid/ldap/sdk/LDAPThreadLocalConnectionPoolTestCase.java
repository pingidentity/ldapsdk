/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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



import javax.net.ssl.SSLContext;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedResult;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;



/**
 * This class provides a set of test cases for the
 * {@code LDAPThreadLocalConnectionPool} class.
 */
public class LDAPThreadLocalConnectionPoolTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the ability to create a connection pool using an existing connection.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithConnection()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection(getTestHost(), getTestPort());
    LDAPThreadLocalConnectionPool p = new LDAPThreadLocalConnectionPool(c);

    assertNotNull(p);

    assertNull(p.getConnectionPoolName());
    p.setConnectionPoolName("test");
    assertNotNull(p.getConnectionPoolName());
    assertEquals(p.getConnectionPoolName(), "test");

    assertEquals(p.getMaxConnectionAgeMillis(), 0L);
    p.setMaxConnectionAgeMillis(1000L);
    assertEquals(p.getMaxConnectionAgeMillis(), 1000L);
    p.setMaxConnectionAgeMillis(-1L);
    assertEquals(p.getMaxConnectionAgeMillis(), 0L);

    assertEquals(p.getMinDisconnectIntervalMillis(), 0L);
    p.setMinDisconnectIntervalMillis(10L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 10L);
    p.setMinDisconnectIntervalMillis(-1L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 0L);
    p.setMinDisconnectIntervalMillis(1000L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 1000L);
    p.setMinDisconnectIntervalMillis(0L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 0L);

    assertNotNull(p.getHealthCheck());
    p.setHealthCheck(p.getHealthCheck());

    assertEquals(p.getCurrentAvailableConnections(), -1);
    assertEquals(p.getMaximumAvailableConnections(), -1);

    assertNotNull(p.getConnectionPoolStatistics());

    assertNotNull(p.getRootDSE());

    assertNotNull(p.toString());

    LDAPConnection conn1 = p.getConnection();
    LDAPConnection conn2 = p.getConnection();
    assertSame(conn1, conn2);

    p.releaseConnection(p.getConnection());
    p.releaseConnection(null);
    p.releaseDefunctConnection(p.getConnection());
    p.releaseDefunctConnection(null);

    p.setHealthCheckIntervalMillis(60000L);
    p.doHealthCheck();

    assertFalse(p.isClosed());
    p.close();
    assertTrue(p.isClosed());

    try
    {
      p.getConnection();
      fail("Expected an exception when trying to get a connection after the " +
           "pool has been closed.");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Tests the ability to create a connection pool using an existing connection
   * that is not established.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testCreateWithConnectionNotEstablished()
         throws Exception
  {
    LDAPConnection c = new LDAPConnection();
    new LDAPThreadLocalConnectionPool(c);
  }



  /**
   * Tests the ability to create a connection pool using an existing SSL-based
   * connection.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithSSLConnection()
         throws Exception
  {
    if (! isSSLEnabledDirectoryInstanceAvailable())
    {
      return;
    }

    SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());

    LDAPConnection c = new LDAPConnection(sslUtil.createSSLSocketFactory(),
         getTestHost(), getTestSSLPort());
    LDAPThreadLocalConnectionPool p = new LDAPThreadLocalConnectionPool(c);

    assertNotNull(p);

    assertNull(p.getConnectionPoolName());
    p.setConnectionPoolName("test");
    assertNotNull(p.getConnectionPoolName());
    assertEquals(p.getConnectionPoolName(), "test");

    assertEquals(p.getMaxConnectionAgeMillis(), 0L);
    p.setMaxConnectionAgeMillis(1000L);
    assertEquals(p.getMaxConnectionAgeMillis(), 1000L);
    p.setMaxConnectionAgeMillis(-1L);
    assertEquals(p.getMaxConnectionAgeMillis(), 0L);

    assertEquals(p.getMinDisconnectIntervalMillis(), 0L);
    p.setMinDisconnectIntervalMillis(10L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 10L);
    p.setMinDisconnectIntervalMillis(-1L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 0L);
    p.setMinDisconnectIntervalMillis(1000L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 1000L);
    p.setMinDisconnectIntervalMillis(0L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 0L);

    assertNotNull(p.getHealthCheck());
    p.setHealthCheck(p.getHealthCheck());

    assertEquals(p.getCurrentAvailableConnections(), -1);
    assertEquals(p.getMaximumAvailableConnections(), -1);

    assertNotNull(p.getConnectionPoolStatistics());

    assertNotNull(p.getRootDSE());

    assertNotNull(p.toString());

    LDAPConnection conn1 = p.getConnection();
    LDAPConnection conn2 = p.getConnection();
    assertSame(conn1, conn2);

    p.releaseConnection(p.getConnection());
    p.releaseDefunctConnection(p.getConnection());

    assertFalse(p.isClosed());
    p.close(true, 2);
    assertTrue(p.isClosed());

    try
    {
      p.getConnection();
      fail("Expected an exception when trying to get a connection after the " +
           "pool has been closed.");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Tests the ability to create a connection pool using an existing
   * StartTLS-based connection.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithStartTLSConnection()
         throws Exception
  {
    if (! isSSLEnabledDirectoryInstanceAvailable())
    {
      return;
    }

    SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
    SSLContext sslContext = sslUtil.createSSLContext();

    LDAPConnection c = new LDAPConnection(getTestHost(), getTestPort());

    ExtendedResult r = c.processExtendedOperation(
         new StartTLSExtendedRequest(sslContext));
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    LDAPThreadLocalConnectionPool p = new LDAPThreadLocalConnectionPool(c,
         new StartTLSPostConnectProcessor(sslContext));

    assertNotNull(p);

    assertNull(p.getConnectionPoolName());
    p.setConnectionPoolName("test");
    assertNotNull(p.getConnectionPoolName());
    assertEquals(p.getConnectionPoolName(), "test");

    assertEquals(p.getMaxConnectionAgeMillis(), 0L);
    p.setMaxConnectionAgeMillis(1000L);
    assertEquals(p.getMaxConnectionAgeMillis(), 1000L);
    p.setMaxConnectionAgeMillis(-1L);
    assertEquals(p.getMaxConnectionAgeMillis(), 0L);

    assertEquals(p.getMinDisconnectIntervalMillis(), 0L);
    p.setMinDisconnectIntervalMillis(10L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 10L);
    p.setMinDisconnectIntervalMillis(-1L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 0L);
    p.setMinDisconnectIntervalMillis(1000L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 1000L);
    p.setMinDisconnectIntervalMillis(0L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 0L);

    assertNotNull(p.getHealthCheck());
    p.setHealthCheck(p.getHealthCheck());

    assertEquals(p.getCurrentAvailableConnections(), -1);
    assertEquals(p.getMaximumAvailableConnections(), -1);

    assertNotNull(p.getConnectionPoolStatistics());

    assertNotNull(p.getRootDSE());

    assertNotNull(p.toString());

    LDAPConnection conn1 = p.getConnection();
    LDAPConnection conn2 = p.getConnection();
    assertSame(conn1, conn2);

    p.releaseConnection(p.getConnection());
    p.releaseDefunctConnection(p.getConnection());

    assertFalse(p.isClosed());
    p.close(false, 2);
    assertTrue(p.isClosed());

    try
    {
      p.getConnection();
      fail("Expected an exception when trying to get a connection after the " +
           "pool has been closed.");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Tests the ability to create a connection pool using a server set.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testCreateWithServerSet()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setAutoReconnect(true);
    options.setUseSynchronousMode(true);

    SingleServerSet serverSet =
         new SingleServerSet(getTestHost(), getTestPort(), options);

    LDAPThreadLocalConnectionPool p =
         new LDAPThreadLocalConnectionPool(serverSet,
                  new SimpleBindRequest(getTestBindDN(),
                                        getTestBindPassword()));

    assertNotNull(p);
    assertNotNull(p.toString());

    assertNull(p.getConnectionPoolName());
    p.setConnectionPoolName("test");
    assertNotNull(p.getConnectionPoolName());
    assertEquals(p.getConnectionPoolName(), "test");

    assertEquals(p.getMaxConnectionAgeMillis(), 0L);
    p.setMaxConnectionAgeMillis(1000L);
    assertEquals(p.getMaxConnectionAgeMillis(), 1000L);
    p.setMaxConnectionAgeMillis(-1L);
    assertEquals(p.getMaxConnectionAgeMillis(), 0L);

    assertEquals(p.getMinDisconnectIntervalMillis(), 0L);
    p.setMinDisconnectIntervalMillis(10L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 10L);
    p.setMinDisconnectIntervalMillis(-1L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 0L);
    p.setMinDisconnectIntervalMillis(1000L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 1000L);
    p.setMinDisconnectIntervalMillis(0L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 0L);

    assertNotNull(p.getHealthCheck());
    p.setHealthCheck(p.getHealthCheck());

    assertEquals(p.getCurrentAvailableConnections(), -1);
    assertEquals(p.getMaximumAvailableConnections(), -1);

    assertNotNull(p.getConnectionPoolStatistics());

    assertNotNull(p.getRootDSE());

    assertNotNull(p.toString());

    LDAPConnection conn1 = p.getConnection();
    LDAPConnection conn2 = p.getConnection();
    assertSame(conn1, conn2);

    p.releaseConnection(p.getConnection());
    p.releaseDefunctConnection(p.getConnection());

    assertFalse(p.isClosed());
    p.close(false, 1);
    assertTrue(p.isClosed());

    try
    {
      p.getConnection();
      fail("Expected an exception when trying to get a connection after the " +
           "pool has been closed.");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Tests the ability to create an SSL-based connection pool using a server
   * set.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testCreateWithServerSetSSL()
         throws Exception
  {
    if (! isSSLEnabledDirectoryInstanceAvailable())
    {
      return;
    }

    SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());

    LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setAutoReconnect(true);
    options.setUseSynchronousMode(true);

    SingleServerSet serverSet = new SingleServerSet(getTestHost(),
         getTestSSLPort(), sslUtil.createSSLSocketFactory(), options);

    LDAPThreadLocalConnectionPool p =
         new LDAPThreadLocalConnectionPool(serverSet,
                  new SimpleBindRequest(getTestBindDN(),
                                        getTestBindPassword()));

    assertNotNull(p);
    assertNotNull(p.toString());

    assertNull(p.getConnectionPoolName());
    p.setConnectionPoolName("test");
    assertNotNull(p.getConnectionPoolName());
    assertEquals(p.getConnectionPoolName(), "test");

    assertEquals(p.getMaxConnectionAgeMillis(), 0L);
    p.setMaxConnectionAgeMillis(1000L);
    assertEquals(p.getMaxConnectionAgeMillis(), 1000L);
    p.setMaxConnectionAgeMillis(-1L);
    assertEquals(p.getMaxConnectionAgeMillis(), 0L);

    assertEquals(p.getMinDisconnectIntervalMillis(), 0L);
    p.setMinDisconnectIntervalMillis(10L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 10L);
    p.setMinDisconnectIntervalMillis(-1L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 0L);
    p.setMinDisconnectIntervalMillis(1000L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 1000L);
    p.setMinDisconnectIntervalMillis(0L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 0L);

    assertNotNull(p.getHealthCheck());
    p.setHealthCheck(p.getHealthCheck());

    assertEquals(p.getCurrentAvailableConnections(), -1);
    assertEquals(p.getMaximumAvailableConnections(), -1);

    assertNotNull(p.getConnectionPoolStatistics());

    assertNotNull(p.getRootDSE());

    assertNotNull(p.toString());

    LDAPConnection conn1 = p.getConnection();
    LDAPConnection conn2 = p.getConnection();
    assertSame(conn1, conn2);

    p.releaseConnection(p.getConnection());
    p.releaseDefunctConnection(p.getConnection());

    assertFalse(p.isClosed());
    p.close();
    assertTrue(p.isClosed());

    try
    {
      p.getConnection();
      fail("Expected an exception when trying to get a connection after the " +
           "pool has been closed.");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Tests the ability to create a StartTLS-based connection pool using a server
   * set.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testCreateWithServerSetStartTLS()
         throws Exception
  {
    if (! isSSLEnabledDirectoryInstanceAvailable())
    {
      return;
    }

    SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());

    LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setAutoReconnect(true);
    options.setUseSynchronousMode(true);

    SingleServerSet serverSet = new SingleServerSet(getTestHost(),
         getTestPort(), options);

    LDAPThreadLocalConnectionPool p =
         new LDAPThreadLocalConnectionPool(serverSet,
                  new SimpleBindRequest(getTestBindDN(),
                                        getTestBindPassword()),
                  new StartTLSPostConnectProcessor(sslUtil.createSSLContext()));

    assertNotNull(p);
    assertNotNull(p.toString());

    assertNull(p.getConnectionPoolName());
    p.setConnectionPoolName("test");
    assertNotNull(p.getConnectionPoolName());
    assertEquals(p.getConnectionPoolName(), "test");

    assertEquals(p.getMaxConnectionAgeMillis(), 0L);
    p.setMaxConnectionAgeMillis(1000L);
    assertEquals(p.getMaxConnectionAgeMillis(), 1000L);
    p.setMaxConnectionAgeMillis(-1L);
    assertEquals(p.getMaxConnectionAgeMillis(), 0L);

    assertEquals(p.getMinDisconnectIntervalMillis(), 0L);
    p.setMinDisconnectIntervalMillis(10L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 10L);
    p.setMinDisconnectIntervalMillis(-1L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 0L);
    p.setMinDisconnectIntervalMillis(1000L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 1000L);
    p.setMinDisconnectIntervalMillis(0L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 0L);

    assertNotNull(p.getHealthCheck());
    p.setHealthCheck(p.getHealthCheck());

    assertEquals(p.getCurrentAvailableConnections(), -1);
    assertEquals(p.getMaximumAvailableConnections(), -1);

    assertNotNull(p.getConnectionPoolStatistics());

    assertNotNull(p.getRootDSE());

    assertNotNull(p.toString());

    LDAPConnection conn1 = p.getConnection();
    LDAPConnection conn2 = p.getConnection();
    assertSame(conn1, conn2);

    p.releaseConnection(p.getConnection());
    p.releaseDefunctConnection(p.getConnection());

    assertFalse(p.isClosed());
    p.close();
    assertTrue(p.isClosed());

    try
    {
      p.getConnection();
      fail("Expected an exception when trying to get a connection after the " +
           "pool has been closed.");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Performs a number of basic LDAP operations using this connection pool.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicOperations()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    opts.setUsePooledSchema(true);

    LDAPConnection c = new LDAPConnection(opts, getTestHost(), getTestPort(),
         getTestBindDN(), getTestBindPassword());
    LDAPThreadLocalConnectionPool p = new LDAPThreadLocalConnectionPool(c);

    assertNotNull(p);

    assertNull(p.getConnectionPoolName());
    p.setConnectionPoolName("test");
    assertNotNull(p.getConnectionPoolName());
    assertEquals(p.getConnectionPoolName(), "test");

    assertEquals(p.getMaxConnectionAgeMillis(), 0L);
    p.setMaxConnectionAgeMillis(1000L);
    assertEquals(p.getMaxConnectionAgeMillis(), 1000L);
    p.setMaxConnectionAgeMillis(-1L);
    assertEquals(p.getMaxConnectionAgeMillis(), 0L);

    assertEquals(p.getMinDisconnectIntervalMillis(), 0L);
    p.setMinDisconnectIntervalMillis(10L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 10L);
    p.setMinDisconnectIntervalMillis(-1L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 0L);
    p.setMinDisconnectIntervalMillis(1000L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 1000L);
    p.setMinDisconnectIntervalMillis(0L);
    assertEquals(p.getMinDisconnectIntervalMillis(), 0L);

    assertNotNull(p.getHealthCheck());
    p.setHealthCheck(p.getHealthCheck());

    assertEquals(p.getCurrentAvailableConnections(), -1);
    assertEquals(p.getMaximumAvailableConnections(), -1);

    assertNotNull(p.getConnectionPoolStatistics());

    assertNotNull(p.getRootDSE());

    LDAPResult result = p.add(getTestBaseDN(), getBaseEntryAttributes());
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    result = p.add(
         "dn: ou=People," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    result = p.modify(
         "dn: ou=People," + getTestBaseDN(),
         "changetype: modify",
         "replace: description",
         "description: foo");
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    assertTrue(p.compare("ou=People," + getTestBaseDN(), "description",
                         "foo").compareMatched());

    SearchResult searchResult = p.search(getTestBaseDN(), SearchScope.SUB,
         "(objectClass=*)");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 2);

    result = p.modifyDN("ou=People," + getTestBaseDN(), "ou=Users", true);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    result = p.delete("ou=Users," + getTestBaseDN());
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    result = p.delete(getTestBaseDN());
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    assertFalse(p.isClosed());
    p.close();
    assertTrue(p.isClosed());
  }



  /**
   * Provides test coverage for the {@code releaseAndReAuthenticateConnection}
   * method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReleaseAndReAuthenticateConnection()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=user1", "password1");
    cfg.addAdditionalBindCredentials("cn=user2", "password2");
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();


    // Test a pool that uses unauthenticated connections.
    LDAPThreadLocalConnectionPool pool = new LDAPThreadLocalConnectionPool(
         new SingleServerSet("localhost", ds.getListenPort()), null);
    pool.releaseAndReAuthenticateConnection(null);

    LDAPConnection conn = pool.getConnection();
    assertBoundAs(conn, "");

    conn.bind("cn=user2", "password2");
    assertBoundAs(conn, "cn=user2");

    pool.releaseConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user2");

    pool.releaseAndReAuthenticateConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "");

    conn.bind("", "");
    assertBoundAs(conn, "");

    pool.releaseConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "");

    pool.releaseAndReAuthenticateConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "");

    try
    {
      conn.bind("cn=missing", "invalid");
    } catch (final Exception e) {}
    assertBoundAs(conn, "");

    pool.releaseAndReAuthenticateConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "");

    pool.releaseConnection(conn);
    pool.close();


    // Test a pool that uses connections authenticated with simple binds.
    pool = new LDAPThreadLocalConnectionPool(
         new SingleServerSet("localhost", ds.getListenPort()),
         new SimpleBindRequest("cn=user1", "password1"));

    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");

    conn.bind("cn=user2", "password2");
    assertBoundAs(conn, "cn=user2");

    pool.releaseConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user2");

    pool.releaseAndReAuthenticateConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");

    conn.bind("", "");
    assertBoundAs(conn, "");

    pool.releaseConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "");

    pool.releaseAndReAuthenticateConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");

    try
    {
      conn.bind("cn=missing", "invalid");
    } catch (final Exception e) {}
    assertBoundAs(conn, "");

    pool.releaseAndReAuthenticateConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");

    pool.releaseConnection(conn);
    pool.close();


    // Test a pool that uses connections authenticated with SASL PLAIN binds.
    pool = new LDAPThreadLocalConnectionPool(
         new SingleServerSet("localhost", ds.getListenPort()),
         new PLAINBindRequest("dn:cn=user1", "password1"));

    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");

    conn.bind("cn=user2", "password2");
    assertBoundAs(conn, "cn=user2");

    pool.releaseConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user2");

    pool.releaseAndReAuthenticateConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");

    conn.bind("", "");
    assertBoundAs(conn, "");

    pool.releaseConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "");

    pool.releaseAndReAuthenticateConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");

    try
    {
      conn.bind("cn=missing", "invalid");
      fail("Expected an exception with invalid credentials");
    } catch (final Exception e) {}
    assertBoundAs(conn, "");

    pool.releaseAndReAuthenticateConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");

    ds.shutDown(true);
    pool.releaseAndReAuthenticateConnection(conn);
    pool.close();
  }



  /**
   * Provides test coverage for the {@code bindAndRevertAuthentication} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindAndRevertAuthentication()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=user1", "password1");
    cfg.addAdditionalBindCredentials("cn=user2", "password2");
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();


    // Test a pool that uses unauthenticated connections.
    LDAPThreadLocalConnectionPool pool = new LDAPThreadLocalConnectionPool(
         new SingleServerSet("localhost", ds.getListenPort()), null);
    pool.releaseAndReAuthenticateConnection(null);

    LDAPConnection conn = pool.getConnection();
    assertBoundAs(conn, "");
    pool.releaseConnection(conn);

    pool.bind("cn=user2", "password2");
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user2");
    pool.releaseConnection(conn);

    pool.bindAndRevertAuthentication("cn=user2", "password2");
    conn = pool.getConnection();
    assertBoundAs(conn, "");
    pool.releaseConnection(conn);

    try
    {
      pool.bindAndRevertAuthentication("cn=missing", "invalid");
      fail("Expected an exception with invalid credentials");
    } catch (final Exception e) {}
    conn = pool.getConnection();
    assertBoundAs(conn, "");
    pool.releaseConnection(conn);
    pool.close();


    // Test a pool that uses connections authenticated with simple binds.
    pool = new LDAPThreadLocalConnectionPool(
         new SingleServerSet("localhost", ds.getListenPort()),
         new SimpleBindRequest("cn=user1", "password1"));

    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");
    pool.releaseConnection(conn);

    pool.bind("cn=user2", "password2");
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user2");
    pool.releaseConnection(conn);

    pool.bindAndRevertAuthentication("cn=user2", "password2");
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");
    pool.releaseConnection(conn);

    pool.bindAndRevertAuthentication("", "");
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");
    pool.releaseConnection(conn);

    try
    {
      pool.bindAndRevertAuthentication("cn=missing", "invalid");
      fail("Expected an exception with invalid credentials");
    } catch (final Exception e) {}
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");
    pool.releaseConnection(conn);
    pool.close();


    // Test a pool that uses connections authenticated with SASL PLAIN binds.
    pool = new LDAPThreadLocalConnectionPool(
         new SingleServerSet("localhost", ds.getListenPort()),
         new PLAINBindRequest("dn:cn=user1", "password1"));
    pool.setRetryFailedOperationsDueToInvalidConnections(true);

    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");
    pool.releaseConnection(conn);

    pool.bind("cn=user2", "password2");
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user2");
    pool.releaseConnection(conn);

    pool.bindAndRevertAuthentication("cn=user2", "password2");
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");
    pool.releaseConnection(conn);

    pool.bindAndRevertAuthentication("", "");
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");
    pool.releaseConnection(conn);

    try
    {
      pool.bindAndRevertAuthentication("cn=missing", "invalid");
      fail("Expected an exception with invalid credentials");
    } catch (final Exception e) {}
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");

    ds.shutDown(true);
    pool.releaseConnection(conn);

    try
    {
      pool.bindAndRevertAuthentication("cn=user2", "password2");
      fail("Expected an exception with the server shut down");
    } catch (final Exception e) {}

    ds.startListening();
    pool.bindAndRevertAuthentication("cn=user2", "password2");
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");

    ds.shutDown(true);
    pool.releaseConnection(conn);
    pool.close();
  }



  /**
   * Ensures that the provided connection is bound as the user with the
   * specified DN.
   *
   * @param  conn  The connection to examine.
   * @param  dn    The expected DN of the authenticated user.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private void assertBoundAs(final LDAPConnection conn, final String dn)
          throws Exception
  {
    final WhoAmIExtendedResult whoAmIResult =
         (WhoAmIExtendedResult)
         conn.processExtendedOperation(new WhoAmIExtendedRequest());
    assertResultCodeEquals(whoAmIResult, ResultCode.SUCCESS);

    final String authzID = whoAmIResult.getAuthorizationID();
    assertNotNull(authzID);
    assertTrue(authzID.startsWith("dn:"));
    assertDNsEqual(authzID.substring(3), dn);
  }



  /**
   * Tests to ensure that the connection pool will create a new connection if
   * the current thread has a connection but it is not actually established.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNewConnectionIfExistingNotEstablished()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection(getTestHost(), getTestPort());
    LDAPThreadLocalConnectionPool p = new LDAPThreadLocalConnectionPool(c);

    assertNotNull(p);

    assertNull(p.getConnectionPoolName());
    p.setConnectionPoolName("test");
    assertNotNull(p.getConnectionPoolName());
    assertEquals(p.getConnectionPoolName(), "test");

    c = p.getConnection();
    assertTrue(c.isConnected());
    c.terminate(null);
    assertFalse(c.isConnected());
    p.releaseConnection(c);

    c = p.getConnection();
    assertTrue(c.isConnected());
    p.releaseConnection(c);

    assertFalse(p.isClosed());
    p.close();
    assertTrue(p.isClosed());
  }



  /**
   * Tests the behavior of the connection pool when using a health check that
   * may throw an exception in the
   * {@code ensureConnectionValidAfterAuthentication}  method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPostBindHealthCheckFailure()
         throws Exception
  {
    // Create health checks that will fail and pass, respectively.
    final TestLDAPConnectionPoolHealthCheck failureHealthCheck =
         new TestLDAPConnectionPoolHealthCheck(null,
              new LDAPBindException(new BindResult(1,
                   ResultCode.INVALID_CREDENTIALS, "Health check failure", null,
                   null, null)),
              null, null, null, null);

    final TestLDAPConnectionPoolHealthCheck successHealthCheck =
         new TestLDAPConnectionPoolHealthCheck();


    // Create a new in-memory directory server instance and use it to get a
    // connection pool to that instance.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    final LDAPThreadLocalConnectionPool pool =
         new LDAPThreadLocalConnectionPool(
              new SingleServerSet("127.0.0.1", ds.getListenPort()),
              new SimpleBindRequest("cn=Directory Manager", "password"));
    pool.setHealthCheck(failureHealthCheck);


    // Ensure that an attempt to use the connection pool to get the server root
    // DSE fails because of the health check.
    try
    {
      pool.getRootDSE();
      fail("Expected an exception when trying to get the root DSE for a " +
           "newly-created connection");
    }
    catch (final LDAPBindException lbe)
    {
      assertEquals(lbe.getResultCode(), ResultCode.INVALID_CREDENTIALS);
      assertEquals(lbe.getDiagnosticMessage(), "Health check failure");
    }


    // Replace the health check and verify that the attempt to get the root DSE
    // will now succeed.
    pool.setHealthCheck(successHealthCheck);
    assertNotNull(pool.getRootDSE());


    // Ensure that the bindAndRevertAuthentication method succeeds with the
    // success health check in place.
    pool.bindAndRevertAuthentication("", "");


    // Replace the health check with a failure health check and verify that
    // the bindAndRevertAuthentication method still succeeds even though it
    // destroys the connection behind the scenes.
    pool.setHealthCheck(failureHealthCheck);
    pool.bindAndRevertAuthentication("", "");


    // Clean up after testing has completed.
    pool.setHealthCheck(successHealthCheck);
    pool.close();
    ds.shutDown(true);
  }
}
