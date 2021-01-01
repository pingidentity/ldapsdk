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
package com.unboundid.ldap.listener;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;



/**
 * This class provides a set of test cases that cover the ability to insert a
 * delay before processing.
 */
public final class InMemoryDirectoryServerDelayTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the ability to insert an arbitrary delay before processing an
   * operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDelayBeforeProcessing()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.add(generateDomainEntry("example", "dc=com"));
    ds.startListening();

    final LDAPConnection conn = ds.getConnection();

    try
    {
      assertEquals(ds.getProcessingDelayMillis(), 0L);
      ds.setProcessingDelayMillis(200L);
      assertEquals(ds.getProcessingDelayMillis(), 200L);

      // Test the bind operation.
      final long bindStartTime = System.currentTimeMillis();
      conn.bind("cn=Directory Manager", "password");
      final long bindEndTime = System.currentTimeMillis();
      assertProcessingDelayExceeds(bindStartTime, bindEndTime, 200L, "bind");

      // Test the extended operation.
      final long extendedStartTime = System.currentTimeMillis();
      conn.processExtendedOperation(new WhoAmIExtendedRequest());
      final long extendedEndTime = System.currentTimeMillis();
      assertProcessingDelayExceeds(extendedStartTime, extendedEndTime, 200L,
           "extended");

      // Test the add operation.
      final long addStartTime = System.currentTimeMillis();
      conn.add(generateOrgUnitEntry("test", "dc=example,dc=com"));
      final long addEndTime = System.currentTimeMillis();
      assertProcessingDelayExceeds(addStartTime, addEndTime, 200L, "add");

      // Test the compare operation.
      final long compareStartTime = System.currentTimeMillis();
      conn.compare("dc=example,dc=com", "dc", "example");
      final long compareEndTime = System.currentTimeMillis();
      assertProcessingDelayExceeds(compareStartTime, compareEndTime, 200L,
           "compare");

      // Test the modify operation.
      final long modifyStartTime = System.currentTimeMillis();
      conn.modify(
           "dn: ou=test,dc=example,dc=com",
           "changeType: modify",
           "replace: description",
           "description: foo");
      final long modifyEndTime = System.currentTimeMillis();
      assertProcessingDelayExceeds(modifyStartTime, modifyEndTime, 200L,
           "modify");

      // Test the modify DN operation.
      final long modifyDNStartTime = System.currentTimeMillis();
      conn.modifyDN("ou=test,dc=example,dc=com", "ou=test 2", true);
      final long modifyDNEndTime = System.currentTimeMillis();
      assertProcessingDelayExceeds(modifyDNStartTime, modifyDNEndTime, 200L,
           "modify DN");

      // Test the search operation.
      final long searchStartTime = System.currentTimeMillis();
      conn.search("dc=example,dc=com", SearchScope.BASE, "(objectClass=*)");
      final long searchEndTime = System.currentTimeMillis();
      assertProcessingDelayExceeds(searchStartTime, searchEndTime, 200L,
           "search");

      // Test the delete operation.
      final long deleteStartTime = System.currentTimeMillis();
      conn.delete("ou=test 2,dc=example,dc=com");
      final long deleteEndTime = System.currentTimeMillis();
      assertProcessingDelayExceeds(deleteStartTime, deleteEndTime, 200L,
           "delete");
    }
    finally
    {
      ds.setProcessingDelayMillis(0L);
      assertEquals(ds.getProcessingDelayMillis(), 0L);

      conn.close();
      ds.shutDown(true);
    }
  }



  /**
   * Tests to ensure that processing time which takes too long will cause a
   * timeout exception to be thrown.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDelayCausesTimeout()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.add(generateDomainEntry("example", "dc=com"));
    ds.startListening();

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setResponseTimeoutMillis(50L);
    options.setAbandonOnTimeout(true);

    final LDAPConnection conn = ds.getConnection(options);

    try
    {
      assertEquals(ds.getProcessingDelayMillis(), 0L);
      ds.setProcessingDelayMillis(200L);
      assertEquals(ds.getProcessingDelayMillis(), 200L);

      // Test the bind operation.
      assertResultCodeEquals(conn,
           new SimpleBindRequest("cn=Directory Manager", "password"),
           ResultCode.TIMEOUT);

      // Test the extended operation.
      assertResultCodeEquals(conn, new WhoAmIExtendedRequest(),
           ResultCode.TIMEOUT);

      // Test the add operation.
      assertResultCodeEquals(conn,
           new AddRequest(generateOrgUnitEntry("test", "dc=example,dc=com")),
           ResultCode.TIMEOUT);

      // Test the compare operation.
      assertResultCodeEquals(conn,
           new CompareRequest("dc=example,dc=com", "dc", "example"),
           ResultCode.TIMEOUT);

      // Test the modify operation.
      assertResultCodeEquals(conn,
           new ModifyRequest(
                "dn: ou=test,dc=example,dc=com",
                "changeType: modify",
                "replace: description",
                "description: foo"),
           ResultCode.TIMEOUT);

      // Test the modify DN operation.
      assertResultCodeEquals(conn,
           new ModifyDNRequest("ou=test,dc=example,dc=com", "ou=test 2", true),
           ResultCode.TIMEOUT);

      // Test the search operation.
      assertResultCodeEquals(conn,
            new SearchRequest("dc=example,dc=com", SearchScope.BASE,
                 "(objectClass=*)"),
           ResultCode.TIMEOUT);

      // Test the delete operation.
      assertResultCodeEquals(conn,
           new DeleteRequest("ou=test 2,dc=example,dc=com"),
           ResultCode.TIMEOUT);
    }
    finally
    {
      ds.setProcessingDelayMillis(0L);
      assertEquals(ds.getProcessingDelayMillis(), 0L);

      conn.close();
      ds.shutDown(true);
    }
  }



  /**
   * Tests to ensure that processing time which takes too long will cause a
   * timeout exception to be thrown when the connection is established in
   * synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDelayCausesTimeoutSynchronousMode()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.add(generateDomainEntry("example", "dc=com"));
    ds.startListening();

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setResponseTimeoutMillis(50L);
    options.setUseSynchronousMode(true);
    options.setAbandonOnTimeout(true);

    final LDAPConnection conn = ds.getConnection(options);

    try
    {
      assertEquals(ds.getProcessingDelayMillis(), 0L);
      ds.setProcessingDelayMillis(200L);
      assertEquals(ds.getProcessingDelayMillis(), 200L);

      // Test the bind operation.
      assertResultCodeEquals(conn,
           new SimpleBindRequest("cn=Directory Manager", "password"),
           ResultCode.TIMEOUT);

      // Test the extended operation.
      assertResultCodeEquals(conn, new WhoAmIExtendedRequest(),
           ResultCode.TIMEOUT);

      // Test the add operation.
      assertResultCodeEquals(conn,
           new AddRequest(generateOrgUnitEntry("test", "dc=example,dc=com")),
           ResultCode.TIMEOUT);

      // Test the compare operation.
      assertResultCodeEquals(conn,
           new CompareRequest("dc=example,dc=com", "dc", "example"),
           ResultCode.TIMEOUT);

      // Test the modify operation.
      assertResultCodeEquals(conn,
           new ModifyRequest(
                "dn: ou=test,dc=example,dc=com",
                "changeType: modify",
                "replace: description",
                "description: foo"),
           ResultCode.TIMEOUT);

      // Test the modify DN operation.
      assertResultCodeEquals(conn,
           new ModifyDNRequest("ou=test,dc=example,dc=com", "ou=test 2", true),
           ResultCode.TIMEOUT);

      // Test the search operation.
      assertResultCodeEquals(conn,
            new SearchRequest("dc=example,dc=com", SearchScope.BASE,
                 "(objectClass=*)"),
           ResultCode.TIMEOUT);

      // Test the delete operation.
      assertResultCodeEquals(conn,
           new DeleteRequest("ou=test 2,dc=example,dc=com"),
           ResultCode.TIMEOUT);
    }
    finally
    {
      ds.setProcessingDelayMillis(0L);
      assertEquals(ds.getProcessingDelayMillis(), 0L);

      conn.close();
      ds.shutDown(true);
    }
  }



  /**
   * Ensures that the time required to process an operation is at least the
   * specified delay time.
   *
   * @param  startTime  The time that processing started for the operation.
   * @param  endTime    The time that processing ended for the operation.
   * @param  delayTime  The expected delay before processing.
   * @param  opType     The type of operation that was processed.
   *
   * @throws  AssertionError  If the total time spent processing the operation
   *                          is less than the delay time.
   */
  private static void assertProcessingDelayExceeds(final long startTime,
                                                   final long endTime,
                                                   final long delayTime,
                                                   final String opType)
          throws AssertionError
  {
    final long elapsedTime = endTime - startTime;
    if (elapsedTime < delayTime)
    {
      throw new AssertionError(opType +
           " processing did not have the expected delay (expectedDelay=" +
           delayTime + ", processingTime=" + elapsedTime);
    }
  }
}
