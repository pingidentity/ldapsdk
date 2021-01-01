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



import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;



/**
 * This class provides a test case that may be used to test to ensure that
 * response timeouts may be honored for asynchronous operations.
 */
public final class AsyncTimeoutTestCase
       extends LDAPSDKTestCase
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4429652840576206109L;



  /**
   * Tests to ensure that asynchronous operations will time out as expected.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAsyncTimeout()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg = new InMemoryDirectoryServerConfig(
         "dc=example,dc=com");
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);

    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    ds.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    ds.startListening();

    LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setSendBufferSize(1000000);
    options.setReceiveBufferSize(1000000);

    final LDAPConnection conn = ds.getConnection(options);

    ds.setProcessingDelayMillis(5000L);

    final TestAsyncListener asyncListener = new TestAsyncListener();


    // Try an async add operation.
    final AddRequest addRequest = new AddRequest(
         "dn: ou=Test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Test");
    addRequest.setResponseTimeoutMillis(100L);

    assertEquals(conn.getActiveOperationCount(), 0);
    long startTime = System.currentTimeMillis();
    AsyncRequestID asyncID = conn.asyncAdd(addRequest, asyncListener);
    assertEquals(conn.getActiveOperationCount(), 1);
    LDAPResult result = asyncID.get();
    assertTrue((System.currentTimeMillis() - startTime) < 5000L);
    assertResultCodeEquals(result, ResultCode.TIMEOUT);
    assertEquals(conn.getActiveOperationCount(), 0);


    // Reconfigure the connection to abandon on timeout.
    options = conn.getConnectionOptions();
    options.setAbandonOnTimeout(true);
    conn.setConnectionOptions(options);


    // Try an async compare operation.
    final CompareRequest compareRequest =
         new CompareRequest("dc=example,dc=com", "objectClass", "top");
    compareRequest.setResponseTimeoutMillis(100L);

    assertEquals(conn.getActiveOperationCount(), 0);
    startTime = System.currentTimeMillis();
    asyncID = conn.asyncCompare(compareRequest, asyncListener);
    assertEquals(conn.getActiveOperationCount(), 1);
    result = asyncID.get();
    assertTrue((System.currentTimeMillis() - startTime) < 5000L);
    assertResultCodeEquals(result, ResultCode.TIMEOUT);
    assertEquals(conn.getActiveOperationCount(), 0);


    // Try an async modify operation.
    final ModifyRequest modifyRequest = new ModifyRequest(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");
    modifyRequest.setResponseTimeoutMillis(100L);

    assertEquals(conn.getActiveOperationCount(), 0);
    startTime = System.currentTimeMillis();
    asyncID = conn.asyncModify(modifyRequest, asyncListener);
    assertEquals(conn.getActiveOperationCount(), 1);
    result = asyncID.get();
    assertTrue((System.currentTimeMillis() - startTime) < 5000L);
    assertResultCodeEquals(result, ResultCode.TIMEOUT);
    assertEquals(conn.getActiveOperationCount(), 0);


    // Try an async modify DN operation.
    final ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("ou=People,dc=example,dc=com", "ou=Users", true);
    modifyDNRequest.setResponseTimeoutMillis(100L);

    assertEquals(conn.getActiveOperationCount(), 0);
    startTime = System.currentTimeMillis();
    asyncID = conn.asyncModifyDN(modifyDNRequest, asyncListener);
    assertEquals(conn.getActiveOperationCount(), 1);
    result = asyncID.get();
    assertTrue((System.currentTimeMillis() - startTime) < 5000L);
    assertResultCodeEquals(result, ResultCode.TIMEOUT);
    assertEquals(conn.getActiveOperationCount(), 0);


    // Try an async search operation.
    final SearchRequest searchRequest = new SearchRequest(asyncListener,
         "dc=example,dc=com", SearchScope.BASE, "(objectClass=*)");
    searchRequest.setResponseTimeoutMillis(100L);

    assertEquals(conn.getActiveOperationCount(), 0);
    startTime = System.currentTimeMillis();
    asyncID = conn.asyncSearch(searchRequest);
    assertEquals(conn.getActiveOperationCount(), 1);
    result = asyncID.get();
    assertTrue((System.currentTimeMillis() - startTime) < 5000L);
    assertResultCodeEquals(result, ResultCode.TIMEOUT);
    assertEquals(conn.getActiveOperationCount(), 0);


    // Try an async delete operation.
    final DeleteRequest deleteRequest =
         new DeleteRequest("ou=People,dc=example,dc=com");
    deleteRequest.setResponseTimeoutMillis(100L);

    assertEquals(conn.getActiveOperationCount(), 0);
    startTime = System.currentTimeMillis();
    asyncID = conn.asyncDelete(deleteRequest, asyncListener);
    assertEquals(conn.getActiveOperationCount(), 1);
    result = asyncID.get();
    assertTrue((System.currentTimeMillis() - startTime) < 5000L);
    assertResultCodeEquals(result, ResultCode.TIMEOUT);
    assertEquals(conn.getActiveOperationCount(), 0);


    conn.close();
    ds.shutDown(true);
  }
}
