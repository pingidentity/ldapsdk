/*
 * Copyright 2014-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2014-2020 Ping Identity Corporation
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
 * This class provides a set of test cases for the LDAP connection pool health
 * check result.
 */
public final class LDAPConnectionPoolHealthCheckResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the health check result object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHealthCheckResult()
         throws Exception
  {
    final LDAPConnectionPoolHealthCheckResult r =
         new LDAPConnectionPoolHealthCheckResult(5, 1, 2);
    assertNotNull(r);

    assertEquals(r.getNumExamined(), 5);

    assertEquals(r.getNumExpired(), 1);

    assertEquals(r.getNumDefunct(), 2);

    assertNotNull(r.toString());
  }
}
