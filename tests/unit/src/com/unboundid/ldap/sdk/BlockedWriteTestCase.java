/*
 * Copyright 2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2019 Ping Identity Corporation
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
 * This class provides a set of tests to verify that a blocked connection is
 * properly closed after an expected length of time.
 */
public final class BlockedWriteTestCase
      extends LDAPSDKTestCase
{
  /**
   * Creates a new connection to a server socket that won't ever read anything,
   * then sends a bunch of asynchronous write requests over the connection until
   * one of them fails.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBlockedWrite()
         throws Exception
  {
    final BlackHoleServer blackHoleServer = new BlackHoleServer(0);
    final int blackHoleServerPort = blackHoleServer.getListenPort();
    blackHoleServer.start();

    try (LDAPConnection conn =
              new LDAPConnection("localhost", blackHoleServerPort))
    {
      final AddRequest addRequest = new AddRequest(
           "dn: uid=test.user,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: test.user",
           "givenName: Test",
           "sn: User",
           "cn: Test User",
           "userPassword: password",
           "description: This is a description for the user");
      addRequest.setResponseTimeoutMillis(1000L);

      boolean atLeastOneWriteSucceeded = false;
      LDAPException writeException = null;
      final long startWritingTime = System.currentTimeMillis();
      final long abortWritingTime = startWritingTime + 30_000L;
      while (System.currentTimeMillis() < abortWritingTime)
      {
        try
        {
          conn.asyncAdd(addRequest, null);
          atLeastOneWriteSucceeded = true;
        }
        catch (final LDAPException e)
        {
          writeException = e;
          break;
        }
      }

      final long actualStopTime = System.currentTimeMillis();
      assertTrue(actualStopTime < abortWritingTime);
      assertTrue((actualStopTime - startWritingTime) > 1000L);

      assertTrue(atLeastOneWriteSucceeded);
      assertNotNull(writeException);
      assertEquals(writeException.getResultCode(), ResultCode.SERVER_DOWN);
    }
    finally
    {
      blackHoleServer.shutDown();
    }
  }
}

