/*
 * Copyright 2009-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2019 Ping Identity Corporation
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



/**
 * This class provides a test case covering the default LDAP connection pool
 * health check mechanism.
 */
public class LDAPConnectionPoolHealthCheckTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the default health check implementation.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultHealthCheck()
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
      fail("Expected an exception when testing a connection after an " +
           "unacceptable exception");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }

    pool.releaseConnection(c1);
    pool.close();
  }
}
