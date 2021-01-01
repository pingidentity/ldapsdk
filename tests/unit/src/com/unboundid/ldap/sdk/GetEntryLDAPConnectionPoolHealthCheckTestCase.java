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



import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the get entry LDAP connection
 * pool health check implementation.
 */
public class GetEntryLDAPConnectionPoolHealthCheckTestCase
       extends LDAPSDKTestCase
{
  /**
   * Adds a test entry to the directory server.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());
    conn.close();
  }



  /**
   * Removes the test entry from the directory server.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void cleanUp()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.delete(getTestBaseDN());
    conn.close();
  }



  /**
   * Tests the get entry health check implementation with all checks enabled.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetEntryHealthCheckAllEnabled()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = new LDAPConnection(getTestHost(), getTestPort(),
         getTestBindDN(), getTestBindPassword());
    LDAPConnectionPool pool = new LDAPConnectionPool(conn, 1, 2);

    LDAPConnectionPoolHealthCheck healthCheck = pool.getHealthCheck();
    assertNotNull(healthCheck);
    assertNotNull(healthCheck.toString());

    GetEntryLDAPConnectionPoolHealthCheck newHealthCheck =
         new GetEntryLDAPConnectionPoolHealthCheck(getTestBaseDN(), 60000L,
                  true, true, true, true, true, true);
    pool.setHealthCheck(newHealthCheck);
    healthCheck = pool.getHealthCheck();
    assertNotNull(healthCheck);
    assertNotNull(healthCheck.toString());
    assertEquals(healthCheck, newHealthCheck);

    assertNotNull(newHealthCheck.getEntryDN());
    assertEquals(new DN(newHealthCheck.getEntryDN()),
                 new DN(getTestBaseDN()));
    assertEquals(newHealthCheck.getMaxResponseTimeMillis(), 60000L);
    assertTrue(newHealthCheck.invokeOnCreate());
    assertTrue(newHealthCheck.invokeAfterAuthentication());
    assertTrue(newHealthCheck.invokeOnCheckout());
    assertTrue(newHealthCheck.invokeOnRelease());
    assertTrue(newHealthCheck.invokeForBackgroundChecks());
    assertTrue(newHealthCheck.invokeOnException());

    LDAPConnection c1 = pool.getConnection();
    assertNotNull(c1);

    healthCheck.ensureNewConnectionValid(c1);
    healthCheck.ensureConnectionValidAfterAuthentication(c1,
         new BindResult(1, ResultCode.SUCCESS, null, null, null, null));
    healthCheck.ensureConnectionValidForCheckout(c1);
    healthCheck.ensureConnectionValidForRelease(c1);
    healthCheck.ensureConnectionValidForContinuedUse(c1);
    healthCheck.ensureConnectionValidAfterException(c1,
         new LDAPException(ResultCode.NO_SUCH_OBJECT));

    try
    {
      healthCheck.ensureConnectionValidAfterException(c1,
           new LDAPException(ResultCode.SERVER_DOWN));
      // Even though the exception indicates that the connection is unusable,
      // the health check will still pass, so we will consider the connection
      // still valid.
    }
    catch (LDAPException le)
    {
      fail(
           "Got an unexpected exception when testing a connection after an " +
                "unacceptable exception",
           le);
    }


    pool.releaseConnection(c1);


    // Remove the test entry from the server and make sure now all of the checks
    // fail.  We'll use a connection that's not part of the pool for this
    // testing, since pooled connections wouldn't be reliable with all health
    // checks failing.
    LDAPConnection adminConnection = getAdminConnection();
    adminConnection.delete(getTestBaseDN());


    try
    {
      healthCheck.ensureNewConnectionValid(adminConnection);
      fail("Expected an exception when testing NewConnectionValid");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }


    try
    {
      healthCheck.ensureConnectionValidAfterAuthentication(adminConnection,
           new BindResult(1, ResultCode.SUCCESS, null, null, null, null));
      fail("Expected an exception when testing " +
           "ConnectionValidAfterAuthentication");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }


    try
    {
      healthCheck.ensureConnectionValidAfterAuthentication(adminConnection,
           new BindResult(1, ResultCode.INVALID_CREDENTIALS, null, null, null,
                null));
    }
    catch (LDAPException le)
    {
      // This was not expected.  The health check should not have done anything
      // if the bind result indicates the bind did not succeed.
      fail(
           "Did not expect an exception after " +
                "ConnectionValidAfterAuthentication with a failed bind",
           le);
    }


    try
    {
      healthCheck.ensureConnectionValidForCheckout(adminConnection);
      fail("Expected an exception when testing ValidForCheckout");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }

    try
    {
      healthCheck.ensureConnectionValidForRelease(adminConnection);
      fail("Expected an exception when testing ValidForRelease");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }

    try
    {
      healthCheck.ensureConnectionValidForContinuedUse(adminConnection);
      fail("Expected an exception when testing ValidForContinuedUse");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }

    try
    {
      healthCheck.ensureConnectionValidAfterException(adminConnection,
           new LDAPException(ResultCode.NO_SUCH_OBJECT));
      // No exception is expected in this case because NO_SUCH_OBJECT isn't a
      // failure result that the SDK believes to indicate that the server is
      // down.
    }
    catch (LDAPException le)
    {
      fail(
           "Got an unexpected exception when testing a connection after an " +
                "unacceptable exception",
           le);
    }

    try
    {
      healthCheck.ensureConnectionValidAfterException(adminConnection,
           new LDAPException(ResultCode.SERVER_DOWN));
      fail("Expected an exception when testing ValidAfterException_91");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }


    // Re-add the test entry and ensure that the health checks no longer fail
    // (except for the one that is supposed to fail).
    adminConnection.add(getTestBaseDN(), getBaseEntryAttributes());

    healthCheck.ensureNewConnectionValid(adminConnection);
    healthCheck.ensureConnectionValidForCheckout(adminConnection);
    healthCheck.ensureConnectionValidForRelease(adminConnection);
    healthCheck.ensureConnectionValidForContinuedUse(adminConnection);
    healthCheck.ensureConnectionValidAfterException(adminConnection,
         new LDAPException(ResultCode.NO_SUCH_OBJECT));

    try
    {
      healthCheck.ensureConnectionValidAfterException(adminConnection,
           new LDAPException(ResultCode.SERVER_DOWN));
      // The entry is there, so the health check will pass.
    }
    catch (LDAPException le)
    {
      fail(
           "Got an unexpected exception when testing a connection after an " +
                "unacceptable exception",
           le);
    }

    adminConnection.close();
    pool.close();
  }



  /**
   * Tests the get entry health check implementation with all checks disabled.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetEntryHealthCheckAllDisabled()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = new LDAPConnection(getTestHost(), getTestPort(),
         getTestBindDN(), getTestBindPassword());
    LDAPConnectionPool pool = new LDAPConnectionPool(conn, 1, 2);

    LDAPConnectionPoolHealthCheck healthCheck = pool.getHealthCheck();
    assertNotNull(healthCheck);
    assertNotNull(healthCheck.toString());

    GetEntryLDAPConnectionPoolHealthCheck newHealthCheck =
         new GetEntryLDAPConnectionPoolHealthCheck(getTestBaseDN(), 60000L,
                  false, false, false, false, false);

    assertNotNull(newHealthCheck.getEntryDN());
    assertEquals(new DN(newHealthCheck.getEntryDN()),
                 new DN(getTestBaseDN()));
    assertEquals(newHealthCheck.getMaxResponseTimeMillis(), 60000L);
    assertFalse(newHealthCheck.invokeOnCreate());
    assertFalse(newHealthCheck.invokeAfterAuthentication());
    assertFalse(newHealthCheck.invokeOnCheckout());
    assertFalse(newHealthCheck.invokeOnRelease());
    assertFalse(newHealthCheck.invokeForBackgroundChecks());
    assertFalse(newHealthCheck.invokeOnException());

    pool.setHealthCheck(newHealthCheck);
    healthCheck = pool.getHealthCheck();
    assertNotNull(healthCheck);
    assertNotNull(healthCheck.toString());
    assertEquals(healthCheck, newHealthCheck);

    LDAPConnection c1 = pool.getConnection();
    assertNotNull(c1);

    healthCheck.ensureNewConnectionValid(c1);
    healthCheck.ensureConnectionValidAfterAuthentication(c1,
         new BindResult(1, ResultCode.SUCCESS, null, null, null, null));
    healthCheck.ensureConnectionValidForCheckout(c1);
    healthCheck.ensureConnectionValidForRelease(c1);
    healthCheck.ensureConnectionValidForContinuedUse(c1);
    healthCheck.ensureConnectionValidAfterException(c1,
         new LDAPException(ResultCode.NO_SUCH_OBJECT));
    healthCheck.ensureConnectionValidAfterException(c1,
         new LDAPException(ResultCode.SERVER_DOWN));


    pool.releaseConnection(c1);


    // Remove the test entry from the server and make sure the results haven't
    // changed since none of the tests will actually be performed.
    LDAPConnection adminConnection = getAdminConnection();
    adminConnection.delete(getTestBaseDN());


    healthCheck.ensureNewConnectionValid(adminConnection);
    healthCheck.ensureConnectionValidForCheckout(adminConnection);
    healthCheck.ensureConnectionValidForRelease(adminConnection);
    healthCheck.ensureConnectionValidForContinuedUse(adminConnection);
    healthCheck.ensureConnectionValidAfterException(adminConnection,
         new LDAPException(ResultCode.NO_SUCH_OBJECT));
    healthCheck.ensureConnectionValidAfterException(adminConnection,
         new LDAPException(ResultCode.SERVER_DOWN));


    // Re-add the test entry and ensure that the health checks still behave
    // correctly.
    adminConnection.add(getTestBaseDN(), getBaseEntryAttributes());

    healthCheck.ensureNewConnectionValid(adminConnection);
    healthCheck.ensureConnectionValidForCheckout(adminConnection);
    healthCheck.ensureConnectionValidForRelease(adminConnection);
    healthCheck.ensureConnectionValidForContinuedUse(adminConnection);
    healthCheck.ensureConnectionValidAfterException(adminConnection,
         new LDAPException(ResultCode.NO_SUCH_OBJECT));
    healthCheck.ensureConnectionValidAfterException(adminConnection,
         new LDAPException(ResultCode.SERVER_DOWN));

    adminConnection.close();
    pool.close();
  }



  /**
   * Tests the get entry health check implementation using the default values
   * for the base DN and timeout.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetEntryHealthUseDefaults()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = new LDAPConnection(getTestHost(), getTestPort(),
         getTestBindDN(), getTestBindPassword());
    LDAPConnectionPool pool = new LDAPConnectionPool(conn, 1, 2);

    LDAPConnectionPoolHealthCheck healthCheck = pool.getHealthCheck();
    assertNotNull(healthCheck);
    assertNotNull(healthCheck.toString());

    GetEntryLDAPConnectionPoolHealthCheck newHealthCheck =
         new GetEntryLDAPConnectionPoolHealthCheck(null, 0L, true, true, true,
                  true, true);

    assertNotNull(newHealthCheck.getEntryDN());
    assertEquals(new DN(newHealthCheck.getEntryDN()), new DN(""));
    assertEquals(newHealthCheck.getMaxResponseTimeMillis(), 30000L);
    assertTrue(newHealthCheck.invokeOnCreate());
    assertFalse(newHealthCheck.invokeAfterAuthentication());
    assertTrue(newHealthCheck.invokeOnCheckout());
    assertTrue(newHealthCheck.invokeOnRelease());
    assertTrue(newHealthCheck.invokeForBackgroundChecks());
    assertTrue(newHealthCheck.invokeOnException());

    pool.setHealthCheck(newHealthCheck);
    healthCheck = pool.getHealthCheck();
    assertNotNull(healthCheck);
    assertNotNull(healthCheck.toString());
    assertEquals(healthCheck, newHealthCheck);

    LDAPConnection c1 = pool.getConnection();
    assertNotNull(c1);

    healthCheck.ensureNewConnectionValid(c1);
    healthCheck.ensureConnectionValidForCheckout(c1);
    healthCheck.ensureConnectionValidForRelease(c1);
    healthCheck.ensureConnectionValidForContinuedUse(c1);
    healthCheck.ensureConnectionValidAfterException(c1,
         new LDAPException(ResultCode.NO_SUCH_OBJECT));

    try
    {
      healthCheck.ensureConnectionValidAfterException(c1,
           new LDAPException(ResultCode.SERVER_DOWN));
      // Even though the exception indicates that the connection is unusable,
      // the health check will still pass, so we will consider the connection
      // still valid.
    }
    catch (LDAPException le)
    {
      fail(
           "Got an unexpected exception when testing a connection after an " +
                "unacceptable exception",
           le);
    }

    pool.releaseConnection(c1);
    pool.close();
  }



  /**
   * Provides test coverage for periodic background health checks.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPeriodicBackgroundHealthChecks()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = new LDAPConnection(getTestHost(), getTestPort(),
         getTestBindDN(), getTestBindPassword());
    LDAPConnectionPool pool = new LDAPConnectionPool(conn, 1, 2);

    LDAPConnectionPoolHealthCheck healthCheck = pool.getHealthCheck();
    assertNotNull(healthCheck);
    assertNotNull(healthCheck.toString());

    GetEntryLDAPConnectionPoolHealthCheck newHealthCheck =
         new GetEntryLDAPConnectionPoolHealthCheck(getTestBaseDN(), 60000L,
                  true, true, true, true, true);
    pool.setHealthCheck(newHealthCheck);
    healthCheck = pool.getHealthCheck();
    assertNotNull(healthCheck);
    assertEquals(healthCheck, newHealthCheck);
    assertNotNull(healthCheck.toString());

    assertNotNull(newHealthCheck.getEntryDN());
    assertEquals(new DN(newHealthCheck.getEntryDN()),
                 new DN(getTestBaseDN()));
    assertEquals(newHealthCheck.getMaxResponseTimeMillis(), 60000L);
    assertTrue(newHealthCheck.invokeOnCreate());
    assertFalse(newHealthCheck.invokeAfterAuthentication());
    assertTrue(newHealthCheck.invokeOnCheckout());
    assertTrue(newHealthCheck.invokeOnRelease());
    assertTrue(newHealthCheck.invokeForBackgroundChecks());
    assertTrue(newHealthCheck.invokeOnException());

    LDAPConnection c1 = pool.getConnection();
    assertNotNull(c1);

    healthCheck.ensureNewConnectionValid(c1);
    healthCheck.ensureConnectionValidForCheckout(c1);
    healthCheck.ensureConnectionValidForRelease(c1);
    healthCheck.ensureConnectionValidForContinuedUse(c1);
    healthCheck.ensureConnectionValidAfterException(c1,
         new LDAPException(ResultCode.NO_SUCH_OBJECT));

    try
    {
      healthCheck.ensureConnectionValidAfterException(c1,
           new LDAPException(ResultCode.SERVER_DOWN));
      // Even though the exception indicates that the connection is unusable,
      // the health check will still pass, so we will consider the connection
      // still valid.
    }
    catch (LDAPException le)
    {
      fail(
           "Got an unexpected exception when testing a connection after an " +
                "unacceptable exception",
           le);
    }


    pool.releaseConnection(c1);


    // Reduce the health check interval to 10 milliseconds, and then sleep for
    // one second to give the health checks ample time to complete.
    pool.setHealthCheckIntervalMillis(10L);
    assertEquals(pool.getHealthCheckIntervalMillis(), 10L);
    Thread.sleep(1000L);


    // Remove the test entry from the server and make sure now all of the checks
    // fail.  Then wait for another second.
    LDAPConnection adminConnection = getAdminConnection();
    adminConnection.delete(getTestBaseDN());
    Thread.sleep(1000L);


    // Re-add the test entry and close the pool.
    adminConnection.add(getTestBaseDN(), getBaseEntryAttributes());

    adminConnection.close();
    pool.close();
  }



  /**
   * Tests this health check with the failover server set.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithFailoverServerSet()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    // Create a health check that will check for the root DSE, which we should
    // be able to get anonymously.
    GetEntryLDAPConnectionPoolHealthCheck healthCheck =
         new GetEntryLDAPConnectionPoolHealthCheck("", 0L, true, true, true,
                  true, true);

    // Create an instance of the server set.
    String[] hosts = { getTestHost() };
    int[]    ports = { getTestPort() };
    FailoverServerSet serverSet = new FailoverServerSet(hosts, ports);

    // Ensure that we can create a connection with the entry in place.
    LDAPConnection conn = serverSet.getConnection(healthCheck);
    assertNotNull(conn);
    conn.close();


    // Temporarily remove the test entry.
    LDAPConnection adminConn = getAdminConnection();
    adminConn.delete(getTestBaseDN());


    // Attempt to perform a health check for an entry that does not exist.
    // We may not have permission to see whether it exists or not without
    // authentication, but in either case it will fail.
    healthCheck = new GetEntryLDAPConnectionPoolHealthCheck(getTestBaseDN(),
         0L, true, true, true, true, true);
    try
    {
      conn = serverSet.getConnection(healthCheck);
      conn.close();
      fail("Expected an exception when used with the failover server set for " +
           "a missing entry.");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }


    // Re-add the base entry and close the connection.
    adminConn.add(getTestBaseDN(), getBaseEntryAttributes());
    adminConn.close();
  }



  /**
   * Tests this health check with the round-robin server set.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithRoundRobinServerSet()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    // Create a health check that will check for the root DSE, which we should
    // be able to get anonymously.
    GetEntryLDAPConnectionPoolHealthCheck healthCheck =
         new GetEntryLDAPConnectionPoolHealthCheck("", 0L, true, true, true,
                  true, true);

    // Create an instance of the server set.
    String[] hosts = { getTestHost() };
    int[]    ports = { getTestPort() };
    RoundRobinServerSet serverSet = new RoundRobinServerSet(hosts, ports);

    // Ensure that we can create a connection with the entry in place.
    LDAPConnection conn = serverSet.getConnection(healthCheck);
    assertNotNull(conn);
    conn.close();


    // Temporarily remove the test entry.
    LDAPConnection adminConn = getAdminConnection();
    adminConn.delete(getTestBaseDN());


    // Attempt to perform a health check for an entry that does not exist.
    // We may not have permission to see whether it exists or not without
    // authentication, but in either case it will fail.
    healthCheck = new GetEntryLDAPConnectionPoolHealthCheck(getTestBaseDN(),
         0L, true, true, true, true, true);
    try
    {
      conn = serverSet.getConnection(healthCheck);
      conn.close();
      fail("Expected an exception when used with the failover server set for " +
           "a missing entry.");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }


    // Re-add the base entry and close the connection.
    adminConn.add(getTestBaseDN(), getBaseEntryAttributes());
    adminConn.close();
  }



  /**
   * Tests this health check with the single server set.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithSingleServerSet()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    // Create a health check that will check for the root DSE, which we should
    // be able to get anonymously.
    GetEntryLDAPConnectionPoolHealthCheck healthCheck =
         new GetEntryLDAPConnectionPoolHealthCheck("", 0L, true, true, true,
                  true, true);

    // Create an instance of the server set.
    SingleServerSet serverSet =
         new SingleServerSet(getTestHost(), getTestPort());

    // Ensure that we can create a connection with the entry in place.
    LDAPConnection conn = serverSet.getConnection(healthCheck);
    assertNotNull(conn);
    conn.close();


    // Temporarily remove the test entry.
    LDAPConnection adminConn = getAdminConnection();
    adminConn.delete(getTestBaseDN());


    // Attempt to perform a health check for an entry that does not exist.
    // We may not have permission to see whether it exists or not without
    // authentication, but in either case it will fail.
    healthCheck = new GetEntryLDAPConnectionPoolHealthCheck(getTestBaseDN(),
         0L, true, true, true, true, true);
    try
    {
      conn = serverSet.getConnection(healthCheck);
      conn.close();
      fail("Expected an exception when used with the failover server set for " +
           "a missing entry.");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }


    // Re-add the base entry and close the connection.
    adminConn.add(getTestBaseDN(), getBaseEntryAttributes());
    adminConn.close();
  }
}
