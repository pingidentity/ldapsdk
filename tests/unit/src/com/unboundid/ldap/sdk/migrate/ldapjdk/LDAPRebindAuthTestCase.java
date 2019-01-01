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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the {@code LDAPRebindAuth} class.
 */
public class LDAPRebindAuthTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides coverage for the {@code LDAPRebindAuth} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPRebindAuth()
         throws Exception
  {
    LDAPRebindAuth a = new LDAPRebindAuth(
         "uid=test.user,ou=People,dc=example,dc=com", "password");

    assertNotNull(a);

    assertNotNull(a.getDN());
    assertEquals(a.getDN(), "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(a.getPassword());
    assertEquals(a.getPassword(), "password");
  }
}
