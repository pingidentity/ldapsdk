/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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



import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedResult;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases to ensure that the
 * {@code setBindRequest} and {@code setServerSet} methods of the
 * {@code LDAPConnectionPool} and {@code LDAPThreadLocalConnectionPool} classes.
 */
public final class UpdateConnectionPoolBindRequestAndServerSetTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the {@link LDAPConnectionPool#setBindRequest} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetBindRequestForLDAPConnectionPool()
         throws Exception
  {
    // Create an in-memory directory server with three sets of authentication
    // credentials.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=User 1", "password1");
    cfg.addAdditionalBindCredentials("cn=User 2", "password2");
    cfg.addAdditionalBindCredentials("cn=User 3", "password3");

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();


    // Create a connection pool with connections authenticated using the first
    // set of credentials.
    try (LDAPConnectionPool pool =
              new LDAPConnectionPool(
                   new SingleServerSet("127.0.0.1", ds.getListenPort()),
                   new SimpleBindRequest("cn=User 1", "password1"), 1, 1))
    {
      // Ensure that the connection is initially authenticated as User 1.
      LDAPConnection conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, "cn=User 1");
      pool.releaseConnection(conn);


      // Set the bind request to authenticate connections as user 2.
      pool.setBindRequest(new SimpleBindRequest("cn=User 2", "password2"));


      // Make sure that the existing connection is still established as user 1.
      conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, "cn=User 1");


      // Release and re-authenticate the connection and make sure that the
      // connection is now authenticated as user 2.
      pool.releaseAndReAuthenticateConnection(conn);
      conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, "cn=User 2");
      pool.releaseConnection(conn);


      // Set the bind request to null, which should cause connections to be
      // unauthenticated.
      pool.setBindRequest(null);


      // Make sure that the existing connection is unchanged.
      conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, "cn=User 2");


      // Release and re-authenticate the connection and make sure that the
      // connection is now unauthenticated.
      pool.releaseAndReAuthenticateConnection(conn);
      conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, null);


      // Update the bind request to authenticate as user 3.
      pool.setBindRequest(new SimpleBindRequest("cn=User 3", "password3"));


      // Make sure that when a connection is released as defunct, it will be
      // re-established with the nwe credentials.
      pool.releaseDefunctConnection(conn);
      conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, "cn=User 3");
      pool.releaseConnection(conn);
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior of the {@link LDAPConnectionPool#setBindRequest} method
   * for a connection pool created with an already-established connection rather
   * than a server set and a bind request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetBindRequestForLDAPConnectionPoolFromConn()
         throws Exception
  {
    // Create an in-memory directory server with three sets of authentication
    // credentials.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=User 1", "password1");
    cfg.addAdditionalBindCredentials("cn=User 2", "password2");
    cfg.addAdditionalBindCredentials("cn=User 3", "password3");

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();


    // Create a connection pool with connections authenticated using the first
    // set of credentials.
    try (LDAPConnection connection =
              new LDAPConnection("127.0.0.1", ds.getListenPort(),
                   "cn=User 1", "password1");
         LDAPConnectionPool pool = new LDAPConnectionPool(connection, 1, 1))
    {
      // Ensure that the connection is initially authenticated as User 1.
      LDAPConnection conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, "cn=User 1");
      pool.releaseConnection(conn);


      // Set the bind request to authenticate connections as user 2.
      pool.setBindRequest(new SimpleBindRequest("cn=User 2", "password2"));


      // Make sure that the existing connection is still established as user 1.
      conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, "cn=User 1");


      // Release and re-authenticate the connection and make sure that the
      // connection is now authenticated as user 2.
      pool.releaseAndReAuthenticateConnection(conn);
      conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, "cn=User 2");
      pool.releaseConnection(conn);


      // Set the bind request to null, which should cause connections to be
      // unauthenticated.
      pool.setBindRequest(null);


      // Make sure that the existing connection is unchanged.
      conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, "cn=User 2");


      // Release and re-authenticate the connection and make sure that the
      // connection is now unauthenticated.
      pool.releaseAndReAuthenticateConnection(conn);
      conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, null);


      // Update the bind request to authenticate as user 3.
      pool.setBindRequest(new SimpleBindRequest("cn=User 3", "password3"));


      // Make sure that when a connection is released as defunct, it will be
      // re-established with the nwe credentials.
      pool.releaseDefunctConnection(conn);
      conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, "cn=User 3");
      pool.releaseConnection(conn);
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior of the
   * {@link LDAPThreadLocalConnectionPool#setBindRequest} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetBindRequestForLDAPThreadLocalConnectionPool()
         throws Exception
  {
    // Create an in-memory directory server with three sets of authentication
    // credentials.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=User 1", "password1");
    cfg.addAdditionalBindCredentials("cn=User 2", "password2");
    cfg.addAdditionalBindCredentials("cn=User 3", "password3");

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();


    // Create a connection pool with connections authenticated using the first
    // set of credentials.
    try (LDAPThreadLocalConnectionPool pool =
              new LDAPThreadLocalConnectionPool(
                   new SingleServerSet("127.0.0.1", ds.getListenPort()),
                   new SimpleBindRequest("cn=User 1", "password1")))
    {
      // Ensure that the connection is initially authenticated as User 1.
      LDAPConnection conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, "cn=User 1");
      pool.releaseConnection(conn);


      // Set the bind request to authenticate connections as user 2.
      pool.setBindRequest(new SimpleBindRequest("cn=User 2", "password2"));


      // Make sure that the existing connection is still established as user 1.
      conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, "cn=User 1");


      // Release and re-authenticate the connection and make sure that the
      // connection is now authenticated as user 2.
      pool.releaseAndReAuthenticateConnection(conn);
      conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, "cn=User 2");
      pool.releaseConnection(conn);


      // Set the bind request to null, which should cause connections to be
      // unauthenticated.
      pool.setBindRequest(null);


      // Make sure that the existing connection is unchanged.
      conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, "cn=User 2");


      // Release and re-authenticate the connection and make sure that the
      // connection is now unauthenticated.
      pool.releaseAndReAuthenticateConnection(conn);
      conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, null);


      // Update the bind request to authenticate as user 3.
      pool.setBindRequest(new SimpleBindRequest("cn=User 3", "password3"));


      // Make sure that when a connection is released as defunct, it will be
      // re-established with the nwe credentials.
      pool.releaseDefunctConnection(conn);
      conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, "cn=User 3");
      pool.releaseConnection(conn);
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior of the
   * {@link LDAPThreadLocalConnectionPool#setBindRequest} method for a
   * connection pool created with an already-established connection rather than
   * a server set and a bind request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetBindRequestForLDAPThreadLocalConnectionPoolFromConn()
         throws Exception
  {
    // Create an in-memory directory server with three sets of authentication
    // credentials.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=User 1", "password1");
    cfg.addAdditionalBindCredentials("cn=User 2", "password2");
    cfg.addAdditionalBindCredentials("cn=User 3", "password3");

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();


    // Create a connection pool with connections authenticated using the first
    // set of credentials.
    try (LDAPConnection connection =
              new LDAPConnection("127.0.0.1", ds.getListenPort(),
                   "cn=User 1", "password1");
         LDAPThreadLocalConnectionPool pool =
              new LDAPThreadLocalConnectionPool(connection))
    {
      // Ensure that the connection is initially authenticated as User 1.
      LDAPConnection conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, "cn=User 1");
      pool.releaseConnection(conn);


      // Set the bind request to authenticate connections as user 2.
      pool.setBindRequest(new SimpleBindRequest("cn=User 2", "password2"));


      // Make sure that the existing connection is still established as user 1.
      conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, "cn=User 1");


      // Release and re-authenticate the connection and make sure that the
      // connection is now authenticated as user 2.
      pool.releaseAndReAuthenticateConnection(conn);
      conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, "cn=User 2");
      pool.releaseConnection(conn);


      // Set the bind request to null, which should cause connections to be
      // unauthenticated.
      pool.setBindRequest(null);


      // Make sure that the existing connection is unchanged.
      conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, "cn=User 2");


      // Release and re-authenticate the connection and make sure that the
      // connection is now unauthenticated.
      pool.releaseAndReAuthenticateConnection(conn);
      conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, null);


      // Update the bind request to authenticate as user 3.
      pool.setBindRequest(new SimpleBindRequest("cn=User 3", "password3"));


      // Make sure that when a connection is released as defunct, it will be
      // re-established with the nwe credentials.
      pool.releaseDefunctConnection(conn);
      conn = pool.getConnection();
      assertAuthorizationDNEquals(conn, "cn=User 3");
      pool.releaseConnection(conn);
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior of the {@link LDAPConnectionPool#setServerSet} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetServerSetForLDAPConnectionPool()
         throws Exception
  {
    // Create three different in-memory directory server instances to use for
    // testing.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");

    final InMemoryDirectoryServer ds1 =
         new InMemoryDirectoryServer(new InMemoryDirectoryServerConfig(cfg));
    ds1.startListening();

    final InMemoryDirectoryServer ds2 =
         new InMemoryDirectoryServer(new InMemoryDirectoryServerConfig(cfg));
    ds2.startListening();

    final InMemoryDirectoryServer ds3 =
         new InMemoryDirectoryServer(new InMemoryDirectoryServerConfig(cfg));
    ds3.startListening();


    try (LDAPConnectionPool pool =
              new LDAPConnectionPool(
                   new SingleServerSet("127.0.0.1", ds1.getListenPort()),
                   new SimpleBindRequest("cn=Directory Manager", "password"),
                   1, 1))
    {
      // Make sure that the connection is initially established to ds1.
      LDAPConnection conn = pool.getConnection();
      assertEquals(conn.getConnectedPort(), ds1.getListenPort());
      pool.releaseConnection(conn);


      // Update the server so that new connections will be established to ds2.
      pool.setServerSet(new SingleServerSet("127.0.0.1", ds2.getListenPort()));


      // Make sure that the existing connection is still connected to ds1.
      conn = pool.getConnection();
      assertEquals(conn.getConnectedPort(), ds1.getListenPort());


      // Release the connection as defunct and make sure that the new connection
      // is connected to ds2.
      pool.releaseDefunctConnection(conn);
      conn = pool.getConnection();
      assertEquals(conn.getConnectedPort(), ds2.getListenPort());


      // Try to set a null server set.  That should be rejected.
      try
      {
        pool.setServerSet(null);
        fail("Expected an exception when setting a null server set.");
      }
      catch (final LDAPSDKUsageException e)
      {
        // This was expected.
      }


      // It should still be possible to get new connections, and they should
      // still be connected to ds2.
      pool.releaseDefunctConnection(conn);
      conn = pool.getConnection();
      assertEquals(conn.getConnectedPort(), ds2.getListenPort());


      // Set the server set so that new connections will be established to ds3.
      pool.setServerSet(new SingleServerSet("127.0.0.1", ds3.getListenPort()));


      // Make sure that new connections are established to ds3.
      pool.releaseDefunctConnection(conn);
      conn = pool.getConnection();
      assertEquals(conn.getConnectedPort(), ds3.getListenPort());
      pool.releaseConnection(conn);
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
      ds3.shutDown(true);
    }
  }



  /**
   * Tests the behavior of the {@link LDAPConnectionPool#setServerSet} method
   * for a connection pool created with an already-established connection rather
   * than a server set and a bind request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetServerSetForLDAPConnectionPoolFromConn()
         throws Exception
  {
    // Create three different in-memory directory server instances to use for
    // testing.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");

    final InMemoryDirectoryServer ds1 =
         new InMemoryDirectoryServer(new InMemoryDirectoryServerConfig(cfg));
    ds1.startListening();

    final InMemoryDirectoryServer ds2 =
         new InMemoryDirectoryServer(new InMemoryDirectoryServerConfig(cfg));
    ds2.startListening();

    final InMemoryDirectoryServer ds3 =
         new InMemoryDirectoryServer(new InMemoryDirectoryServerConfig(cfg));
    ds3.startListening();


    try (LDAPConnection connection =
              new LDAPConnection("127.0.0.1", ds1.getListenPort(),
                   "cn=Directory Manager", "password");
         LDAPConnectionPool pool = new LDAPConnectionPool(connection, 1, 1))
    {
      // Make sure that the connection is initially established to ds1.
      LDAPConnection conn = pool.getConnection();
      assertEquals(conn.getConnectedPort(), ds1.getListenPort());
      pool.releaseConnection(conn);


      // Update the server so that new connections will be established to ds2.
      pool.setServerSet(new SingleServerSet("127.0.0.1", ds2.getListenPort()));


      // Make sure that the existing connection is still connected to ds1.
      conn = pool.getConnection();
      assertEquals(conn.getConnectedPort(), ds1.getListenPort());


      // Release the connection as defunct and make sure that the new connection
      // is connected to ds2.
      pool.releaseDefunctConnection(conn);
      conn = pool.getConnection();
      assertEquals(conn.getConnectedPort(), ds2.getListenPort());


      // Try to set a null server set.  That should be rejected.
      try
      {
        pool.setServerSet(null);
        fail("Expected an exception when setting a null server set.");
      }
      catch (final LDAPSDKUsageException e)
      {
        // This was expected.
      }


      // It should still be possible to get new connections, and they should
      // still be connected to ds2.
      pool.releaseDefunctConnection(conn);
      conn = pool.getConnection();
      assertEquals(conn.getConnectedPort(), ds2.getListenPort());


      // Set the server set so that new connections will be established to ds3.
      pool.setServerSet(new SingleServerSet("127.0.0.1", ds3.getListenPort()));


      // Make sure that new connections are established to ds3.
      pool.releaseDefunctConnection(conn);
      conn = pool.getConnection();
      assertEquals(conn.getConnectedPort(), ds3.getListenPort());
      pool.releaseConnection(conn);
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
      ds3.shutDown(true);
    }
  }



  /**
   * Tests the behavior of the
   * {@link LDAPThreadLocalConnectionPool#setServerSet} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetServerSetForLDAPThreadLocalConnectionPool()
         throws Exception
  {
    // Create three different in-memory directory server instances to use for
    // testing.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");

    final InMemoryDirectoryServer ds1 =
         new InMemoryDirectoryServer(new InMemoryDirectoryServerConfig(cfg));
    ds1.startListening();

    final InMemoryDirectoryServer ds2 =
         new InMemoryDirectoryServer(new InMemoryDirectoryServerConfig(cfg));
    ds2.startListening();

    final InMemoryDirectoryServer ds3 =
         new InMemoryDirectoryServer(new InMemoryDirectoryServerConfig(cfg));
    ds3.startListening();


    try (LDAPThreadLocalConnectionPool pool =
              new LDAPThreadLocalConnectionPool(
                   new SingleServerSet("127.0.0.1", ds1.getListenPort()),
                   new SimpleBindRequest("cn=Directory Manager", "password")))
    {
      // Make sure that the connection is initially established to ds1.
      LDAPConnection conn = pool.getConnection();
      assertEquals(conn.getConnectedPort(), ds1.getListenPort());
      pool.releaseConnection(conn);


      // Update the server so that new connections will be established to ds2.
      pool.setServerSet(new SingleServerSet("127.0.0.1", ds2.getListenPort()));


      // Make sure that the existing connection is still connected to ds1.
      conn = pool.getConnection();
      assertEquals(conn.getConnectedPort(), ds1.getListenPort());


      // Release the connection as defunct and make sure that the new connection
      // is connected to ds2.
      pool.releaseDefunctConnection(conn);
      conn = pool.getConnection();
      assertEquals(conn.getConnectedPort(), ds2.getListenPort());


      // Try to set a null server set.  That should be rejected.
      try
      {
        pool.setServerSet(null);
        fail("Expected an exception when setting a null server set.");
      }
      catch (final LDAPSDKUsageException e)
      {
        // This was expected.
      }


      // It should still be possible to get new connections, and they should
      // still be connected to ds2.
      pool.releaseDefunctConnection(conn);
      conn = pool.getConnection();
      assertEquals(conn.getConnectedPort(), ds2.getListenPort());


      // Set the server set so that new connections will be established to ds3.
      pool.setServerSet(new SingleServerSet("127.0.0.1", ds3.getListenPort()));


      // Make sure that new connections are established to ds3.
      pool.releaseDefunctConnection(conn);
      conn = pool.getConnection();
      assertEquals(conn.getConnectedPort(), ds3.getListenPort());
      pool.releaseConnection(conn);
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
      ds3.shutDown(true);
    }
  }



  /**
   * Tests the behavior of the
   * {@link LDAPThreadLocalConnectionPool#setServerSet} method for a connection
   * pool created with an already-established connection rather than a server
   * set and a bind request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetServerSetForLDAPThreadLocalConnectionPoolFromConn()
         throws Exception
  {
    // Create three different in-memory directory server instances to use for
    // testing.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");

    final InMemoryDirectoryServer ds1 =
         new InMemoryDirectoryServer(new InMemoryDirectoryServerConfig(cfg));
    ds1.startListening();

    final InMemoryDirectoryServer ds2 =
         new InMemoryDirectoryServer(new InMemoryDirectoryServerConfig(cfg));
    ds2.startListening();

    final InMemoryDirectoryServer ds3 =
         new InMemoryDirectoryServer(new InMemoryDirectoryServerConfig(cfg));
    ds3.startListening();


    try (LDAPConnection connection =
              new LDAPConnection("127.0.0.1", ds1.getListenPort(),
                   "cn=Directory Manager", "password");
         LDAPConnectionPool pool = new LDAPConnectionPool(connection, 1, 1))
    {
      // Make sure that the connection is initially established to ds1.
      LDAPConnection conn = pool.getConnection();
      assertEquals(conn.getConnectedPort(), ds1.getListenPort());
      pool.releaseConnection(conn);


      // Update the server so that new connections will be established to ds2.
      pool.setServerSet(new SingleServerSet("127.0.0.1", ds2.getListenPort()));


      // Make sure that the existing connection is still connected to ds1.
      conn = pool.getConnection();
      assertEquals(conn.getConnectedPort(), ds1.getListenPort());


      // Release the connection as defunct and make sure that the new connection
      // is connected to ds2.
      pool.releaseDefunctConnection(conn);
      conn = pool.getConnection();
      assertEquals(conn.getConnectedPort(), ds2.getListenPort());


      // Try to set a null server set.  That should be rejected.
      try
      {
        pool.setServerSet(null);
        fail("Expected an exception when setting a null server set.");
      }
      catch (final LDAPSDKUsageException e)
      {
        // This was expected.
      }


      // It should still be possible to get new connections, and they should
      // still be connected to ds2.
      pool.releaseDefunctConnection(conn);
      conn = pool.getConnection();
      assertEquals(conn.getConnectedPort(), ds2.getListenPort());


      // Set the server set so that new connections will be established to ds3.
      pool.setServerSet(new SingleServerSet("127.0.0.1", ds3.getListenPort()));


      // Make sure that new connections are established to ds3.
      pool.releaseDefunctConnection(conn);
      conn = pool.getConnection();
      assertEquals(conn.getConnectedPort(), ds3.getListenPort());
      pool.releaseConnection(conn);
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
      ds3.shutDown(true);
    }
  }



  /**
   * Uses the "Who Am I?" extended operation on the provided connection to
   * ensure that it has the specified authorization identity.
   *
   * @param  conn  The connection for which to obtain the authorization
   *               identity.  It must not be {@code null}.
   * @param  dn    The DN of the entry that is expected to be the authorization
   *               identity for the connection.  It may be {@code null} if the
   *               connection should be unauthenticated.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private void assertAuthorizationDNEquals(final LDAPConnection conn,
                                           final String dn)
          throws Exception
  {
    final WhoAmIExtendedResult whoAmIResult = (WhoAmIExtendedResult)
         conn.processExtendedOperation(new WhoAmIExtendedRequest());
    assertResultCodeEquals(whoAmIResult, ResultCode.SUCCESS);

    final String authorizationID = whoAmIResult.getAuthorizationID();
    assertNotNull(authorizationID);
    assertTrue(authorizationID.startsWith("dn:"));

    if (dn == null)
    {
      assertEquals(authorizationID, "dn:");
    }
    else
    {
      final String extractedDN = authorizationID.substring(3);
      assertDNsEqual(extractedDN, dn);
    }
  }
}
