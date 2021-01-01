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



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;
import com.unboundid.util.FixedRateBarrier;



/**
 * This class provides a set of test cases for the rate limiter request handler.
 */
public final class RateLimiterRequestHandlerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the rate limiter when created with a specified rate
   * per second.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRateLimiterCreatedWithRatePerSecond()
         throws Exception
  {
    final InMemoryDirectoryServerConfig inMemoryConfig =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    inMemoryConfig.addAdditionalBindCredentials("cn=Directory Manager",
         "password");
    final InMemoryRequestHandler inMemoryRequestHandler =
         new InMemoryRequestHandler(inMemoryConfig);

    final RateLimiterRequestHandler rateLimiterRequestHandler =
         new RateLimiterRequestHandler(inMemoryRequestHandler, 100);

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
   * Tests the behavior of the rate limiter when created with a fixed-rate
   * barrier for the default set of operation types.
   *
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRateLimiterCreatedWithFixedRateBarrierDefaultOperationTypes()
         throws Exception
  {
    final InMemoryDirectoryServerConfig inMemoryConfig =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    inMemoryConfig.addAdditionalBindCredentials("cn=Directory Manager",
         "password");
    final InMemoryRequestHandler inMemoryRequestHandler =
         new InMemoryRequestHandler(inMemoryConfig);

    final FixedRateBarrier rateLimiter = new FixedRateBarrier(1000L, 100);
    final RateLimiterRequestHandler rateLimiterRequestHandler =
         new RateLimiterRequestHandler(inMemoryRequestHandler, rateLimiter);

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
   * Tests the behavior of the rate limiter when created with a fixed-rate
   * barrier for all operation types.
   *
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRateLimiterCreatedWithFixedRateBarrierAllOperationTypes()
         throws Exception
  {
    final InMemoryDirectoryServerConfig inMemoryConfig =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    inMemoryConfig.addAdditionalBindCredentials("cn=Directory Manager",
         "password");
    final InMemoryRequestHandler inMemoryRequestHandler =
         new InMemoryRequestHandler(inMemoryConfig);

    final FixedRateBarrier rateLimiter = new FixedRateBarrier(1000L, 100);
    final RateLimiterRequestHandler rateLimiterRequestHandler =
         new RateLimiterRequestHandler(inMemoryRequestHandler, rateLimiter,
              rateLimiter, rateLimiter, rateLimiter, rateLimiter, rateLimiter,
              rateLimiter, rateLimiter, rateLimiter);

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
}
