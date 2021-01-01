/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import java.util.concurrent.Semaphore;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;



/**
 * This class provides a set of test cases for the concurrent request limiter
 * request handler.
 */
public final class ConcurrentRequestLimiterRequestHandlerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the rate limiter with the default set of operation
   * types and with a semaphore created by the request handler.  All of the
   * operations should be successful.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRateLimiterAllSuccessful()
         throws Exception
  {
    final InMemoryDirectoryServerConfig inMemoryConfig =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    inMemoryConfig.addAdditionalBindCredentials("cn=Directory Manager",
         "password");
    final InMemoryRequestHandler inMemoryRequestHandler =
         new InMemoryRequestHandler(inMemoryConfig);

    final ConcurrentRequestLimiterRequestHandler rateLimiterRequestHandler =
         new ConcurrentRequestLimiterRequestHandler(inMemoryRequestHandler, 1,
              -1L);

    final LDAPListenerConfig listenerConfig =
         new LDAPListenerConfig(0, rateLimiterRequestHandler);

    final LDAPListener listener = new LDAPListener(listenerConfig);
    listener.startListening();

    final LDAPConnection conn = new LDAPConnection("127.0.0.1",
         listener.getListenPort());
    conn.bind("cn=Directory Manager", "password");

    conn.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    conn.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    conn.search("dc=example,dc=com", SearchScope.SUB, "(objectClass=*)");

    conn.compare("dc=example,dc=com", "dc" ,"example");

    conn.modify(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");

    conn.modifyDN("ou=People,dc=example,dc=com", "ou=Users", true);

    conn.delete("ou=Users,dc=example,dc=com");
    conn.delete("dc=example,dc=com");

    conn.processExtendedOperation(new WhoAmIExtendedRequest());

    conn.abandon(InternalSDKHelper.createAsyncRequestID(1, conn));

    conn.close();

    listener.shutDown(true);
  }



  /**
   * Tests the behavior of the rate limiter in the case where all of the
   * operations fail without waiting because no semaphore permit is available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRateLimiterAllFailNoWait()
         throws Exception
  {
    final InMemoryDirectoryServerConfig inMemoryConfig =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    inMemoryConfig.addAdditionalBindCredentials("cn=Directory Manager",
         "password");
    final InMemoryRequestHandler inMemoryRequestHandler =
         new InMemoryRequestHandler(inMemoryConfig);

    final Semaphore semaphore = new Semaphore(1);

    final ConcurrentRequestLimiterRequestHandler rateLimiterRequestHandler =
         new ConcurrentRequestLimiterRequestHandler(inMemoryRequestHandler,
              semaphore, semaphore, semaphore, semaphore, semaphore, semaphore,
              semaphore, semaphore, semaphore, 0L);

    final LDAPListenerConfig listenerConfig =
         new LDAPListenerConfig(0, rateLimiterRequestHandler);

    final LDAPListener listener = new LDAPListener(listenerConfig);
    listener.startListening();

    assertTrue(semaphore.tryAcquire());

    final LDAPConnection conn = new LDAPConnection("127.0.0.1",
         listener.getListenPort());

    try
    {
      conn.bind("cn=Directory Manager", "password");
      fail("Expected an exception when trying to bind");
    }
    catch (final LDAPException le)
    {
      // This is expected.
    }

    try
    {
      conn.add(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");
      fail("Expected an exception when trying to add");
    }
    catch (final LDAPException le)
    {
      // This is expected
    }

    try
    {
      conn.search("dc=example,dc=com", SearchScope.SUB, "(objectClass=*)");
      fail("Expected an exception when trying to search");
    }
    catch (final LDAPException le)
    {
      // This is expected
    }

    try
    {
      conn.compare("dc=example,dc=com", "dc" ,"example");
      fail("Expected an exception when trying to compare");
    }
    catch (final LDAPException le)
    {
      // This is expected
    }

    try
    {
      conn.modify(
           "dn: dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: foo");
      fail("Expected an exception when trying to modify");
    }
    catch (final LDAPException le)
    {
      // This is expected
    }

    try
    {
      conn.modifyDN("ou=People,dc=example,dc=com", "ou=Users", true);
      fail("Expected an exception when trying to modify DN");
    }
    catch (final LDAPException le)
    {
      // This is expected
    }

    try
    {
      conn.delete("dc=example,dc=com");
      fail("Expected an exception when trying to delete");
    }
    catch (final LDAPException le)
    {
      // This is expected
    }


    try
    {
      conn.processExtendedOperation(new WhoAmIExtendedRequest());
    }
    catch (final LDAPException le)
    {
      // This may or may not happen, depending on the nature of the problem.
    }

    conn.abandon(InternalSDKHelper.createAsyncRequestID(1, conn));

    conn.close();

    semaphore.release();

    listener.shutDown(true);
  }



  /**
   * Tests the behavior of the rate limiter in the case where all of the
   * operations fail after a short wait because no semaphore permit is
   * available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRateLimiterAllFailWithWait()
         throws Exception
  {
    final InMemoryDirectoryServerConfig inMemoryConfig =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    inMemoryConfig.addAdditionalBindCredentials("cn=Directory Manager",
         "password");
    final InMemoryRequestHandler inMemoryRequestHandler =
         new InMemoryRequestHandler(inMemoryConfig);

    final Semaphore semaphore = new Semaphore(1);

    final ConcurrentRequestLimiterRequestHandler rateLimiterRequestHandler =
         new ConcurrentRequestLimiterRequestHandler(inMemoryRequestHandler,
              semaphore, semaphore, semaphore, semaphore, semaphore, semaphore,
              semaphore, semaphore, semaphore, 1L);

    final LDAPListenerConfig listenerConfig =
         new LDAPListenerConfig(0, rateLimiterRequestHandler);

    final LDAPListener listener = new LDAPListener(listenerConfig);
    listener.startListening();

    assertTrue(semaphore.tryAcquire());

    final LDAPConnection conn = new LDAPConnection("127.0.0.1",
         listener.getListenPort());

    try
    {
      conn.bind("cn=Directory Manager", "password");
      fail("Expected an exception when trying to bind");
    }
    catch (final LDAPException le)
    {
      // This is expected.
    }

    try
    {
      conn.add(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");
      fail("Expected an exception when trying to add");
    }
    catch (final LDAPException le)
    {
      // This is expected
    }

    try
    {
      conn.search("dc=example,dc=com", SearchScope.SUB, "(objectClass=*)");
      fail("Expected an exception when trying to search");
    }
    catch (final LDAPException le)
    {
      // This is expected
    }

    try
    {
      conn.compare("dc=example,dc=com", "dc" ,"example");
      fail("Expected an exception when trying to compare");
    }
    catch (final LDAPException le)
    {
      // This is expected
    }

    try
    {
      conn.modify(
           "dn: dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: foo");
      fail("Expected an exception when trying to modify");
    }
    catch (final LDAPException le)
    {
      // This is expected
    }

    try
    {
      conn.modifyDN("ou=People,dc=example,dc=com", "ou=Users", true);
      fail("Expected an exception when trying to modify DN");
    }
    catch (final LDAPException le)
    {
      // This is expected
    }

    try
    {
      conn.delete("dc=example,dc=com");
      fail("Expected an exception when trying to delete");
    }
    catch (final LDAPException le)
    {
      // This is expected
    }


    try
    {
      conn.processExtendedOperation(new WhoAmIExtendedRequest());
    }
    catch (final LDAPException le)
    {
      // This may or may not happen, depending on the nature of the problem.
    }

    conn.abandon(InternalSDKHelper.createAsyncRequestID(1, conn));

    conn.close();

    semaphore.release();

    listener.shutDown(true);
  }
}
