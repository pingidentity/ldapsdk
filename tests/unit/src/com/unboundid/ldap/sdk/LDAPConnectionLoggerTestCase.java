/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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



import java.util.concurrent.TimeUnit;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.
            TestIntermediateResponseExtendedOperationHandler;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;



/**
 * This class provides test coverage for basic LDAP connection logger
 * functionality.
 */
public final class LDAPConnectionLoggerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests to ensure that connection attempts are logged as expected for
   * connections not using synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectAndDisconnectNonSynchronous()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    final int port = ds.getListenPort();

    final TestLDAPConnectionLogger logger = new TestLDAPConnectionLogger();

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);

    assertEquals(logger.getSuccessfulConnectCount(), 0);
    assertEquals(logger.getFailedConnectCount(), 0);
    assertEquals(logger.getDisconnectCount(), 0);
    assertEquals(logger.getAbandonRequestCount(), 0);
    assertEquals(logger.getAddRequestCount(), 0);
    assertEquals(logger.getAddResultCount(), 0);
    assertEquals(logger.getSimpleBindRequestCount(), 0);
    assertEquals(logger.getSASLBindRequestCount(), 0);
    assertEquals(logger.getBindResultCount(), 0);
    assertEquals(logger.getCompareRequestCount(), 0);
    assertEquals(logger.getCompareResultCount(), 0);
    assertEquals(logger.getDeleteRequestCount(), 0);
    assertEquals(logger.getDeleteResultCount(), 0);
    assertEquals(logger.getExtendedRequestCount(), 0);
    assertEquals(logger.getExtendedResultCount(), 0);
    assertEquals(logger.getModifyRequestCount(), 0);
    assertEquals(logger.getModifyResultCount(), 0);
    assertEquals(logger.getModifyDNRequestCount(), 0);
    assertEquals(logger.getModifyDNResultCount(), 0);
    assertEquals(logger.getSearchRequestCount(), 0);
    assertEquals(logger.getSearchResultEntryCount(), 0);
    assertEquals(logger.getSearchResultReferenceCount(), 0);
    assertEquals(logger.getSearchResultDoneCount(), 0);
    assertEquals(logger.getUnbindRequestCount(), 0);
    assertEquals(logger.getIntermediateResponseCount(), 0);

    try (LDAPConnection connection =
              new LDAPConnection(options, "localhost", port))
    {
      assertTrue(connection.isConnected());

      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);
    }

    assertEquals(logger.getSuccessfulConnectCount(), 1);
    assertEquals(logger.getFailedConnectCount(), 0);
    assertEquals(logger.getDisconnectCount(), 1);
    assertEquals(logger.getAbandonRequestCount(), 0);
    assertEquals(logger.getAddRequestCount(), 0);
    assertEquals(logger.getAddResultCount(), 0);
    assertEquals(logger.getSimpleBindRequestCount(), 0);
    assertEquals(logger.getSASLBindRequestCount(), 0);
    assertEquals(logger.getBindResultCount(), 0);
    assertEquals(logger.getCompareRequestCount(), 0);
    assertEquals(logger.getCompareResultCount(), 0);
    assertEquals(logger.getDeleteRequestCount(), 0);
    assertEquals(logger.getDeleteResultCount(), 0);
    assertEquals(logger.getExtendedRequestCount(), 0);
    assertEquals(logger.getExtendedResultCount(), 0);
    assertEquals(logger.getModifyRequestCount(), 0);
    assertEquals(logger.getModifyResultCount(), 0);
    assertEquals(logger.getModifyDNRequestCount(), 0);
    assertEquals(logger.getModifyDNResultCount(), 0);
    assertEquals(logger.getSearchRequestCount(), 0);
    assertEquals(logger.getSearchResultEntryCount(), 0);
    assertEquals(logger.getSearchResultReferenceCount(), 0);
    assertEquals(logger.getSearchResultDoneCount(), 0);
    assertEquals(logger.getUnbindRequestCount(), 1);
    assertEquals(logger.getIntermediateResponseCount(), 0);

    ds.shutDown(true);

    try (LDAPConnection connection =
              new LDAPConnection(options, "localhost", port))
    {
      assertFalse(connection.isConnected());
      fail("Expected to be unable to get a connection");
    }
    catch (final LDAPException e)
    {
      // This was expected
    }
    finally
    {
      ds.startListening();
    }

    assertEquals(logger.getSuccessfulConnectCount(), 1);
    assertEquals(logger.getFailedConnectCount(), 1);
    assertEquals(logger.getDisconnectCount(), 1);
    assertEquals(logger.getAbandonRequestCount(), 0);
    assertEquals(logger.getAddRequestCount(), 0);
    assertEquals(logger.getAddResultCount(), 0);
    assertEquals(logger.getSimpleBindRequestCount(), 0);
    assertEquals(logger.getSASLBindRequestCount(), 0);
    assertEquals(logger.getBindResultCount(), 0);
    assertEquals(logger.getCompareRequestCount(), 0);
    assertEquals(logger.getCompareResultCount(), 0);
    assertEquals(logger.getDeleteRequestCount(), 0);
    assertEquals(logger.getDeleteResultCount(), 0);
    assertEquals(logger.getExtendedRequestCount(), 0);
    assertEquals(logger.getExtendedResultCount(), 0);
    assertEquals(logger.getModifyRequestCount(), 0);
    assertEquals(logger.getModifyResultCount(), 0);
    assertEquals(logger.getModifyDNRequestCount(), 0);
    assertEquals(logger.getModifyDNResultCount(), 0);
    assertEquals(logger.getSearchRequestCount(), 0);
    assertEquals(logger.getSearchResultEntryCount(), 0);
    assertEquals(logger.getSearchResultReferenceCount(), 0);
    assertEquals(logger.getSearchResultDoneCount(), 0);
    assertEquals(logger.getUnbindRequestCount(), 1);
    assertEquals(logger.getIntermediateResponseCount(), 0);

    try (LDAPConnection connection =
         new LDAPConnection(options, "undefined-host.example.com", 389))
    {
      assertFalse(connection.isConnected());
      fail("Expected to be unable to get a connection");
    }
    catch (final LDAPException e)
    {
      // This was expected
    }

    assertEquals(logger.getSuccessfulConnectCount(), 1);
    assertEquals(logger.getFailedConnectCount(), 2);
    assertEquals(logger.getDisconnectCount(), 1);
    assertEquals(logger.getAbandonRequestCount(), 0);
    assertEquals(logger.getAddRequestCount(), 0);
    assertEquals(logger.getAddResultCount(), 0);
    assertEquals(logger.getSimpleBindRequestCount(), 0);
    assertEquals(logger.getSASLBindRequestCount(), 0);
    assertEquals(logger.getBindResultCount(), 0);
    assertEquals(logger.getCompareRequestCount(), 0);
    assertEquals(logger.getCompareResultCount(), 0);
    assertEquals(logger.getDeleteRequestCount(), 0);
    assertEquals(logger.getDeleteResultCount(), 0);
    assertEquals(logger.getExtendedRequestCount(), 0);
    assertEquals(logger.getExtendedResultCount(), 0);
    assertEquals(logger.getModifyRequestCount(), 0);
    assertEquals(logger.getModifyResultCount(), 0);
    assertEquals(logger.getModifyDNRequestCount(), 0);
    assertEquals(logger.getModifyDNResultCount(), 0);
    assertEquals(logger.getSearchRequestCount(), 0);
    assertEquals(logger.getSearchResultEntryCount(), 0);
    assertEquals(logger.getSearchResultReferenceCount(), 0);
    assertEquals(logger.getSearchResultDoneCount(), 0);
    assertEquals(logger.getUnbindRequestCount(), 1);
    assertEquals(logger.getIntermediateResponseCount(), 0);
  }



  /**
   * Tests to ensure that connection attempts are logged as expected for
   * connections using synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectAndDisconnectSynchronous()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    final int port = ds.getListenPort();

    final TestLDAPConnectionLogger logger = new TestLDAPConnectionLogger();

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);
    options.setConnectionLogger(logger);

    assertEquals(logger.getSuccessfulConnectCount(), 0);
    assertEquals(logger.getFailedConnectCount(), 0);
    assertEquals(logger.getDisconnectCount(), 0);
    assertEquals(logger.getAbandonRequestCount(), 0);
    assertEquals(logger.getAddRequestCount(), 0);
    assertEquals(logger.getAddResultCount(), 0);
    assertEquals(logger.getSimpleBindRequestCount(), 0);
    assertEquals(logger.getSASLBindRequestCount(), 0);
    assertEquals(logger.getBindResultCount(), 0);
    assertEquals(logger.getCompareRequestCount(), 0);
    assertEquals(logger.getCompareResultCount(), 0);
    assertEquals(logger.getDeleteRequestCount(), 0);
    assertEquals(logger.getDeleteResultCount(), 0);
    assertEquals(logger.getExtendedRequestCount(), 0);
    assertEquals(logger.getExtendedResultCount(), 0);
    assertEquals(logger.getModifyRequestCount(), 0);
    assertEquals(logger.getModifyResultCount(), 0);
    assertEquals(logger.getModifyDNRequestCount(), 0);
    assertEquals(logger.getModifyDNResultCount(), 0);
    assertEquals(logger.getSearchRequestCount(), 0);
    assertEquals(logger.getSearchResultEntryCount(), 0);
    assertEquals(logger.getSearchResultReferenceCount(), 0);
    assertEquals(logger.getSearchResultDoneCount(), 0);
    assertEquals(logger.getUnbindRequestCount(), 0);
    assertEquals(logger.getIntermediateResponseCount(), 0);

    try (LDAPConnection connection =
              new LDAPConnection(options, "localhost", port))
    {
      assertTrue(connection.isConnected());

      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);
    }

    assertEquals(logger.getSuccessfulConnectCount(), 1);
    assertEquals(logger.getFailedConnectCount(), 0);
    assertEquals(logger.getDisconnectCount(), 1);
    assertEquals(logger.getAbandonRequestCount(), 0);
    assertEquals(logger.getAddRequestCount(), 0);
    assertEquals(logger.getAddResultCount(), 0);
    assertEquals(logger.getSimpleBindRequestCount(), 0);
    assertEquals(logger.getSASLBindRequestCount(), 0);
    assertEquals(logger.getBindResultCount(), 0);
    assertEquals(logger.getCompareRequestCount(), 0);
    assertEquals(logger.getCompareResultCount(), 0);
    assertEquals(logger.getDeleteRequestCount(), 0);
    assertEquals(logger.getDeleteResultCount(), 0);
    assertEquals(logger.getExtendedRequestCount(), 0);
    assertEquals(logger.getExtendedResultCount(), 0);
    assertEquals(logger.getModifyRequestCount(), 0);
    assertEquals(logger.getModifyResultCount(), 0);
    assertEquals(logger.getModifyDNRequestCount(), 0);
    assertEquals(logger.getModifyDNResultCount(), 0);
    assertEquals(logger.getSearchRequestCount(), 0);
    assertEquals(logger.getSearchResultEntryCount(), 0);
    assertEquals(logger.getSearchResultReferenceCount(), 0);
    assertEquals(logger.getSearchResultDoneCount(), 0);
    assertEquals(logger.getUnbindRequestCount(), 1);
    assertEquals(logger.getIntermediateResponseCount(), 0);

    ds.shutDown(true);

    try (LDAPConnection connection =
              new LDAPConnection(options, "localhost", port))
    {
      assertFalse(connection.isConnected());
      fail("Expected to be unable to get a connection");
    }
    catch (final LDAPException e)
    {
      // This was expected
    }
    finally
    {
      ds.startListening();
    }

    assertEquals(logger.getSuccessfulConnectCount(), 1);
    assertEquals(logger.getFailedConnectCount(), 1);
    assertEquals(logger.getDisconnectCount(), 1);
    assertEquals(logger.getAbandonRequestCount(), 0);
    assertEquals(logger.getAddRequestCount(), 0);
    assertEquals(logger.getAddResultCount(), 0);
    assertEquals(logger.getSimpleBindRequestCount(), 0);
    assertEquals(logger.getSASLBindRequestCount(), 0);
    assertEquals(logger.getBindResultCount(), 0);
    assertEquals(logger.getCompareRequestCount(), 0);
    assertEquals(logger.getCompareResultCount(), 0);
    assertEquals(logger.getDeleteRequestCount(), 0);
    assertEquals(logger.getDeleteResultCount(), 0);
    assertEquals(logger.getExtendedRequestCount(), 0);
    assertEquals(logger.getExtendedResultCount(), 0);
    assertEquals(logger.getModifyRequestCount(), 0);
    assertEquals(logger.getModifyResultCount(), 0);
    assertEquals(logger.getModifyDNRequestCount(), 0);
    assertEquals(logger.getModifyDNResultCount(), 0);
    assertEquals(logger.getSearchRequestCount(), 0);
    assertEquals(logger.getSearchResultEntryCount(), 0);
    assertEquals(logger.getSearchResultReferenceCount(), 0);
    assertEquals(logger.getSearchResultDoneCount(), 0);
    assertEquals(logger.getUnbindRequestCount(), 1);
    assertEquals(logger.getIntermediateResponseCount(), 0);

    try (LDAPConnection connection =
         new LDAPConnection(options, "undefined-host.example.com", 389))
    {
      assertFalse(connection.isConnected());
      fail("Expected to be unable to get a connection");
    }
    catch (final LDAPException e)
    {
      // This was expected
    }

    assertEquals(logger.getSuccessfulConnectCount(), 1);
    assertEquals(logger.getFailedConnectCount(), 2);
    assertEquals(logger.getDisconnectCount(), 1);
    assertEquals(logger.getAbandonRequestCount(), 0);
    assertEquals(logger.getAddRequestCount(), 0);
    assertEquals(logger.getAddResultCount(), 0);
    assertEquals(logger.getSimpleBindRequestCount(), 0);
    assertEquals(logger.getSASLBindRequestCount(), 0);
    assertEquals(logger.getBindResultCount(), 0);
    assertEquals(logger.getCompareRequestCount(), 0);
    assertEquals(logger.getCompareResultCount(), 0);
    assertEquals(logger.getDeleteRequestCount(), 0);
    assertEquals(logger.getDeleteResultCount(), 0);
    assertEquals(logger.getExtendedRequestCount(), 0);
    assertEquals(logger.getExtendedResultCount(), 0);
    assertEquals(logger.getModifyRequestCount(), 0);
    assertEquals(logger.getModifyResultCount(), 0);
    assertEquals(logger.getModifyDNRequestCount(), 0);
    assertEquals(logger.getModifyDNResultCount(), 0);
    assertEquals(logger.getSearchRequestCount(), 0);
    assertEquals(logger.getSearchResultEntryCount(), 0);
    assertEquals(logger.getSearchResultReferenceCount(), 0);
    assertEquals(logger.getSearchResultDoneCount(), 0);
    assertEquals(logger.getUnbindRequestCount(), 1);
    assertEquals(logger.getIntermediateResponseCount(), 0);
  }



  /**
   * Tests to ensure that various operation messages are logged as expected when
   * not using synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOperationLoggingNonSynchronous()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final int port = ds.getListenPort();

    final TestLDAPConnectionLogger logger = new TestLDAPConnectionLogger();

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);

    assertEquals(logger.getSuccessfulConnectCount(), 0);
    assertEquals(logger.getFailedConnectCount(), 0);
    assertEquals(logger.getDisconnectCount(), 0);
    assertEquals(logger.getAbandonRequestCount(), 0);
    assertEquals(logger.getAddRequestCount(), 0);
    assertEquals(logger.getAddResultCount(), 0);
    assertEquals(logger.getSimpleBindRequestCount(), 0);
    assertEquals(logger.getSASLBindRequestCount(), 0);
    assertEquals(logger.getBindResultCount(), 0);
    assertEquals(logger.getCompareRequestCount(), 0);
    assertEquals(logger.getCompareResultCount(), 0);
    assertEquals(logger.getDeleteRequestCount(), 0);
    assertEquals(logger.getDeleteResultCount(), 0);
    assertEquals(logger.getExtendedRequestCount(), 0);
    assertEquals(logger.getExtendedResultCount(), 0);
    assertEquals(logger.getModifyRequestCount(), 0);
    assertEquals(logger.getModifyResultCount(), 0);
    assertEquals(logger.getModifyDNRequestCount(), 0);
    assertEquals(logger.getModifyDNResultCount(), 0);
    assertEquals(logger.getSearchRequestCount(), 0);
    assertEquals(logger.getSearchResultEntryCount(), 0);
    assertEquals(logger.getSearchResultReferenceCount(), 0);
    assertEquals(logger.getSearchResultDoneCount(), 0);
    assertEquals(logger.getUnbindRequestCount(), 0);
    assertEquals(logger.getIntermediateResponseCount(), 0);

    try (LDAPConnection connection =
              new LDAPConnection(options, "localhost", port))
    {
      // Verify that the connect was logged.
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a successful simple bind is logged.
      assertResultCodeEquals(connection,
           new SimpleBindRequest("cn=Directory Manager", "password"),
           ResultCode.SUCCESS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 1);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 1);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed simple bind is logged.
      assertResultCodeEquals(connection,
           new SimpleBindRequest("cn=Directory Manager", "wrong"),
           ResultCode.INVALID_CREDENTIALS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 2);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a successful SASL bind is logged.
      assertResultCodeEquals(connection,
           new PLAINBindRequest("dn:cn=Directory Manager", "password"),
           ResultCode.SUCCESS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 1);
      assertEquals(logger.getBindResultCount(), 3);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed SASL bind is logged.
      assertResultCodeEquals(connection,
           new PLAINBindRequest("dn:cn=Directory Manager", "wrong"),
           ResultCode.INVALID_CREDENTIALS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a successful add is logged.
      assertResultCodeEquals(connection,
           new AddRequest(
                "dn: ou=test,dc=example,dc=com",
                "objectClass: top",
                "objectClass: organizationalUnit",
                "ou: test"),
           ResultCode.SUCCESS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 1);
      assertEquals(logger.getAddResultCount(), 1);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed add is logged.
      assertResultCodeEquals(connection,
           new AddRequest(
                "dn: ou=test,dc=example,dc=com",
                "objectClass: top",
                "objectClass: organizationalUnit",
                "ou: test"),
           ResultCode.ENTRY_ALREADY_EXISTS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a matching compare is logged.
      assertResultCodeEquals(connection,
           new CompareRequest("ou=test,dc=example,dc=com", "ou", "test"),
           ResultCode.COMPARE_TRUE);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 1);
      assertEquals(logger.getCompareResultCount(), 1);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a non-matching compare is logged.
      assertResultCodeEquals(connection,
           new CompareRequest("ou=test,dc=example,dc=com", "ou", "missing"),
           ResultCode.COMPARE_FALSE);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 2);
      assertEquals(logger.getCompareResultCount(), 2);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed compare is logged.
      assertResultCodeEquals(connection,
           new CompareRequest("ou=missing,dc=example,dc=com", "ou", "missing"),
           ResultCode.NO_SUCH_OBJECT);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a successful modify is logged.
      assertResultCodeEquals(connection,
           new ModifyRequest(
                "dn: ou=test,dc=example,dc=com",
                "changetype: modify",
                "replace: description",
                "description: foo"),
           ResultCode.SUCCESS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 1);
      assertEquals(logger.getModifyResultCount(), 1);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed modify is logged.
      assertResultCodeEquals(connection,
           new ModifyRequest(
                "dn: ou=missing,dc=example,dc=com",
                "changetype: modify",
                "replace: description",
                "description: foo"),
           ResultCode.NO_SUCH_OBJECT);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a successful modify DN is logged.
      assertResultCodeEquals(connection,
           new ModifyDNRequest("ou=test,dc=example,dc=com", "ou=test2", true),
           ResultCode.SUCCESS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 1);
      assertEquals(logger.getModifyDNResultCount(), 1);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed modify DN is logged.
      assertResultCodeEquals(connection,
           new ModifyDNRequest("ou=test,dc=example,dc=com", "ou=test2", true),
           ResultCode.NO_SUCH_OBJECT);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 2);
      assertEquals(logger.getModifyDNResultCount(), 2);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a successful search matching a single entry is logged.
      assertNotNull(connection.getEntry("dc=example,dc=com"));
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 2);
      assertEquals(logger.getModifyDNResultCount(), 2);
      assertEquals(logger.getSearchRequestCount(), 1);
      assertEquals(logger.getSearchResultEntryCount(), 1);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 1);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a successful search matching multiple entries is logged.
      assertResultCodeEquals(connection,
           new SearchRequest("dc=example,dc=com", SearchScope.SUB,
                Filter.createPresenceFilter("objectClass")),
           ResultCode.SUCCESS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 2);
      assertEquals(logger.getModifyDNResultCount(), 2);
      assertEquals(logger.getSearchRequestCount(), 2);
      assertEquals(logger.getSearchResultEntryCount(), 3);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 2);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed search is logged.
      assertResultCodeEquals(connection,
           new SearchRequest("ou=missing,dc=example,dc=com", SearchScope.SUB,
                Filter.createPresenceFilter("objectClass")),
           ResultCode.NO_SUCH_OBJECT);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 2);
      assertEquals(logger.getModifyDNResultCount(), 2);
      assertEquals(logger.getSearchRequestCount(), 3);
      assertEquals(logger.getSearchResultEntryCount(), 3);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 3);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a successful delete is logged.
      assertResultCodeEquals(connection,
           new DeleteRequest("ou=test2,dc=example,dc=com"),
           ResultCode.SUCCESS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 1);
      assertEquals(logger.getDeleteResultCount(), 1);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 2);
      assertEquals(logger.getModifyDNResultCount(), 2);
      assertEquals(logger.getSearchRequestCount(), 3);
      assertEquals(logger.getSearchResultEntryCount(), 3);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 3);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed delete is logged.
      assertResultCodeEquals(connection,
           new DeleteRequest("ou=test2,dc=example,dc=com"),
           ResultCode.NO_SUCH_OBJECT);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 2);
      assertEquals(logger.getDeleteResultCount(), 2);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 2);
      assertEquals(logger.getModifyDNResultCount(), 2);
      assertEquals(logger.getSearchRequestCount(), 3);
      assertEquals(logger.getSearchResultEntryCount(), 3);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 3);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);
    }


    // Verify that the unbind and disconnect were logged.
    assertEquals(logger.getSuccessfulConnectCount(), 1);
    assertEquals(logger.getFailedConnectCount(), 0);
    assertEquals(logger.getDisconnectCount(), 1);
    assertEquals(logger.getAbandonRequestCount(), 0);
    assertEquals(logger.getAddRequestCount(), 2);
    assertEquals(logger.getAddResultCount(), 2);
    assertEquals(logger.getSimpleBindRequestCount(), 2);
    assertEquals(logger.getSASLBindRequestCount(), 2);
    assertEquals(logger.getBindResultCount(), 4);
    assertEquals(logger.getCompareRequestCount(), 3);
    assertEquals(logger.getCompareResultCount(), 3);
    assertEquals(logger.getDeleteRequestCount(), 2);
    assertEquals(logger.getDeleteResultCount(), 2);
    assertEquals(logger.getExtendedRequestCount(), 0);
    assertEquals(logger.getExtendedResultCount(), 0);
    assertEquals(logger.getModifyRequestCount(), 2);
    assertEquals(logger.getModifyResultCount(), 2);
    assertEquals(logger.getModifyDNRequestCount(), 2);
    assertEquals(logger.getModifyDNResultCount(), 2);
    assertEquals(logger.getSearchRequestCount(), 3);
    assertEquals(logger.getSearchResultEntryCount(), 3);
    assertEquals(logger.getSearchResultReferenceCount(), 0);
    assertEquals(logger.getSearchResultDoneCount(), 3);
    assertEquals(logger.getUnbindRequestCount(), 1);
    assertEquals(logger.getIntermediateResponseCount(), 0);
  }



  /**
   * Tests to ensure that various operation messages are logged as expected when
   * using synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOperationLoggingSynchronous()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final int port = ds.getListenPort();

    final TestLDAPConnectionLogger logger = new TestLDAPConnectionLogger();

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);
    options.setConnectionLogger(logger);

    assertEquals(logger.getSuccessfulConnectCount(), 0);
    assertEquals(logger.getFailedConnectCount(), 0);
    assertEquals(logger.getDisconnectCount(), 0);
    assertEquals(logger.getAbandonRequestCount(), 0);
    assertEquals(logger.getAddRequestCount(), 0);
    assertEquals(logger.getAddResultCount(), 0);
    assertEquals(logger.getSimpleBindRequestCount(), 0);
    assertEquals(logger.getSASLBindRequestCount(), 0);
    assertEquals(logger.getBindResultCount(), 0);
    assertEquals(logger.getCompareRequestCount(), 0);
    assertEquals(logger.getCompareResultCount(), 0);
    assertEquals(logger.getDeleteRequestCount(), 0);
    assertEquals(logger.getDeleteResultCount(), 0);
    assertEquals(logger.getExtendedRequestCount(), 0);
    assertEquals(logger.getExtendedResultCount(), 0);
    assertEquals(logger.getModifyRequestCount(), 0);
    assertEquals(logger.getModifyResultCount(), 0);
    assertEquals(logger.getModifyDNRequestCount(), 0);
    assertEquals(logger.getModifyDNResultCount(), 0);
    assertEquals(logger.getSearchRequestCount(), 0);
    assertEquals(logger.getSearchResultEntryCount(), 0);
    assertEquals(logger.getSearchResultReferenceCount(), 0);
    assertEquals(logger.getSearchResultDoneCount(), 0);
    assertEquals(logger.getUnbindRequestCount(), 0);
    assertEquals(logger.getIntermediateResponseCount(), 0);

    try (LDAPConnection connection =
              new LDAPConnection(options, "localhost", port))
    {
      // Verify that the connect was logged.
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a successful simple bind is logged.
      assertResultCodeEquals(connection,
           new SimpleBindRequest("cn=Directory Manager", "password"),
           ResultCode.SUCCESS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 1);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 1);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed simple bind is logged.
      assertResultCodeEquals(connection,
           new SimpleBindRequest("cn=Directory Manager", "wrong"),
           ResultCode.INVALID_CREDENTIALS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 2);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a successful SASL bind is logged.
      assertResultCodeEquals(connection,
           new PLAINBindRequest("dn:cn=Directory Manager", "password"),
           ResultCode.SUCCESS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 1);
      assertEquals(logger.getBindResultCount(), 3);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed SASL bind is logged.
      assertResultCodeEquals(connection,
           new PLAINBindRequest("dn:cn=Directory Manager", "wrong"),
           ResultCode.INVALID_CREDENTIALS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a successful add is logged.
      assertResultCodeEquals(connection,
           new AddRequest(
                "dn: ou=test,dc=example,dc=com",
                "objectClass: top",
                "objectClass: organizationalUnit",
                "ou: test"),
           ResultCode.SUCCESS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 1);
      assertEquals(logger.getAddResultCount(), 1);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed add is logged.
      assertResultCodeEquals(connection,
           new AddRequest(
                "dn: ou=test,dc=example,dc=com",
                "objectClass: top",
                "objectClass: organizationalUnit",
                "ou: test"),
           ResultCode.ENTRY_ALREADY_EXISTS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a matching compare is logged.
      assertResultCodeEquals(connection,
           new CompareRequest("ou=test,dc=example,dc=com", "ou", "test"),
           ResultCode.COMPARE_TRUE);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 1);
      assertEquals(logger.getCompareResultCount(), 1);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a non-matching compare is logged.
      assertResultCodeEquals(connection,
           new CompareRequest("ou=test,dc=example,dc=com", "ou", "missing"),
           ResultCode.COMPARE_FALSE);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 2);
      assertEquals(logger.getCompareResultCount(), 2);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed compare is logged.
      assertResultCodeEquals(connection,
           new CompareRequest("ou=missing,dc=example,dc=com", "ou", "missing"),
           ResultCode.NO_SUCH_OBJECT);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a successful modify is logged.
      assertResultCodeEquals(connection,
           new ModifyRequest(
                "dn: ou=test,dc=example,dc=com",
                "changetype: modify",
                "replace: description",
                "description: foo"),
           ResultCode.SUCCESS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 1);
      assertEquals(logger.getModifyResultCount(), 1);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed modify is logged.
      assertResultCodeEquals(connection,
           new ModifyRequest(
                "dn: ou=missing,dc=example,dc=com",
                "changetype: modify",
                "replace: description",
                "description: foo"),
           ResultCode.NO_SUCH_OBJECT);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a successful modify DN is logged.
      assertResultCodeEquals(connection,
           new ModifyDNRequest("ou=test,dc=example,dc=com", "ou=test2", true),
           ResultCode.SUCCESS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 1);
      assertEquals(logger.getModifyDNResultCount(), 1);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed modify DN is logged.
      assertResultCodeEquals(connection,
           new ModifyDNRequest("ou=test,dc=example,dc=com", "ou=test2", true),
           ResultCode.NO_SUCH_OBJECT);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 2);
      assertEquals(logger.getModifyDNResultCount(), 2);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a successful search matching a single entry is logged.
      assertNotNull(connection.getEntry("dc=example,dc=com"));
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 2);
      assertEquals(logger.getModifyDNResultCount(), 2);
      assertEquals(logger.getSearchRequestCount(), 1);
      assertEquals(logger.getSearchResultEntryCount(), 1);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 1);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a successful search matching multiple entries is logged.
      assertResultCodeEquals(connection,
           new SearchRequest("dc=example,dc=com", SearchScope.SUB,
                Filter.createPresenceFilter("objectClass")),
           ResultCode.SUCCESS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 2);
      assertEquals(logger.getModifyDNResultCount(), 2);
      assertEquals(logger.getSearchRequestCount(), 2);
      assertEquals(logger.getSearchResultEntryCount(), 3);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 2);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed search is logged.
      assertResultCodeEquals(connection,
           new SearchRequest("ou=missing,dc=example,dc=com", SearchScope.SUB,
                Filter.createPresenceFilter("objectClass")),
           ResultCode.NO_SUCH_OBJECT);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 2);
      assertEquals(logger.getModifyDNResultCount(), 2);
      assertEquals(logger.getSearchRequestCount(), 3);
      assertEquals(logger.getSearchResultEntryCount(), 3);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 3);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a successful delete is logged.
      assertResultCodeEquals(connection,
           new DeleteRequest("ou=test2,dc=example,dc=com"),
           ResultCode.SUCCESS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 1);
      assertEquals(logger.getDeleteResultCount(), 1);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 2);
      assertEquals(logger.getModifyDNResultCount(), 2);
      assertEquals(logger.getSearchRequestCount(), 3);
      assertEquals(logger.getSearchResultEntryCount(), 3);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 3);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed delete is logged.
      assertResultCodeEquals(connection,
           new DeleteRequest("ou=test2,dc=example,dc=com"),
           ResultCode.NO_SUCH_OBJECT);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 2);
      assertEquals(logger.getSASLBindRequestCount(), 2);
      assertEquals(logger.getBindResultCount(), 4);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 2);
      assertEquals(logger.getDeleteResultCount(), 2);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 2);
      assertEquals(logger.getModifyDNResultCount(), 2);
      assertEquals(logger.getSearchRequestCount(), 3);
      assertEquals(logger.getSearchResultEntryCount(), 3);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 3);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);
    }


    // Verify that the unbind and disconnect were logged.
    assertEquals(logger.getSuccessfulConnectCount(), 1);
    assertEquals(logger.getFailedConnectCount(), 0);
    assertEquals(logger.getDisconnectCount(), 1);
    assertEquals(logger.getAbandonRequestCount(), 0);
    assertEquals(logger.getAddRequestCount(), 2);
    assertEquals(logger.getAddResultCount(), 2);
    assertEquals(logger.getSimpleBindRequestCount(), 2);
    assertEquals(logger.getSASLBindRequestCount(), 2);
    assertEquals(logger.getBindResultCount(), 4);
    assertEquals(logger.getCompareRequestCount(), 3);
    assertEquals(logger.getCompareResultCount(), 3);
    assertEquals(logger.getDeleteRequestCount(), 2);
    assertEquals(logger.getDeleteResultCount(), 2);
    assertEquals(logger.getExtendedRequestCount(), 0);
    assertEquals(logger.getExtendedResultCount(), 0);
    assertEquals(logger.getModifyRequestCount(), 2);
    assertEquals(logger.getModifyResultCount(), 2);
    assertEquals(logger.getModifyDNRequestCount(), 2);
    assertEquals(logger.getModifyDNResultCount(), 2);
    assertEquals(logger.getSearchRequestCount(), 3);
    assertEquals(logger.getSearchResultEntryCount(), 3);
    assertEquals(logger.getSearchResultReferenceCount(), 0);
    assertEquals(logger.getSearchResultDoneCount(), 3);
    assertEquals(logger.getUnbindRequestCount(), 1);
    assertEquals(logger.getIntermediateResponseCount(), 0);
  }



  /**
   * Tests to ensure that various operation messages are logged as expected when
   * operations are invoked asynchronously.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOperationLoggingAsynchronous()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final int port = ds.getListenPort();

    final TestLDAPConnectionLogger logger = new TestLDAPConnectionLogger();

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);

    assertEquals(logger.getSuccessfulConnectCount(), 0);
    assertEquals(logger.getFailedConnectCount(), 0);
    assertEquals(logger.getDisconnectCount(), 0);
    assertEquals(logger.getAbandonRequestCount(), 0);
    assertEquals(logger.getAddRequestCount(), 0);
    assertEquals(logger.getAddResultCount(), 0);
    assertEquals(logger.getSimpleBindRequestCount(), 0);
    assertEquals(logger.getSASLBindRequestCount(), 0);
    assertEquals(logger.getBindResultCount(), 0);
    assertEquals(logger.getCompareRequestCount(), 0);
    assertEquals(logger.getCompareResultCount(), 0);
    assertEquals(logger.getDeleteRequestCount(), 0);
    assertEquals(logger.getDeleteResultCount(), 0);
    assertEquals(logger.getExtendedRequestCount(), 0);
    assertEquals(logger.getExtendedResultCount(), 0);
    assertEquals(logger.getModifyRequestCount(), 0);
    assertEquals(logger.getModifyResultCount(), 0);
    assertEquals(logger.getModifyDNRequestCount(), 0);
    assertEquals(logger.getModifyDNResultCount(), 0);
    assertEquals(logger.getSearchRequestCount(), 0);
    assertEquals(logger.getSearchResultEntryCount(), 0);
    assertEquals(logger.getSearchResultReferenceCount(), 0);
    assertEquals(logger.getSearchResultDoneCount(), 0);
    assertEquals(logger.getUnbindRequestCount(), 0);
    assertEquals(logger.getIntermediateResponseCount(), 0);

    try (LDAPConnection connection =
              new LDAPConnection(options, "localhost", port))
    {
      // Verify that the connect was logged.
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a successful add is logged.
      final AddRequest addRequest = new AddRequest(
           "dn: ou=test,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test");
      AsyncRequestID requestID = connection.asyncAdd(addRequest, null);
      LDAPResult addResult = requestID.get(30L, TimeUnit.SECONDS);
      assertResultCodeEquals(addResult, ResultCode.SUCCESS);

      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 1);
      assertEquals(logger.getAddResultCount(), 1);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed add is logged.
      requestID = connection.asyncAdd(addRequest, null);
      addResult = requestID.get(30L, TimeUnit.SECONDS);
      assertResultCodeEquals(addResult, ResultCode.ENTRY_ALREADY_EXISTS);

      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a matching compare is logged.
      CompareRequest compareRequest =
           new CompareRequest("ou=test,dc=example,dc=com", "ou", "test");
      requestID = connection.asyncCompare(compareRequest, null);
      LDAPResult compareResult = requestID.get(30L, TimeUnit.SECONDS);
      assertResultCodeEquals(compareResult, ResultCode.COMPARE_TRUE);

      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 1);
      assertEquals(logger.getCompareResultCount(), 1);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a non-matching compare is logged.
      compareRequest =
           new CompareRequest("ou=test,dc=example,dc=com", "ou", "missing");
      requestID = connection.asyncCompare(compareRequest, null);
      compareResult = requestID.get(30L, TimeUnit.SECONDS);
      assertResultCodeEquals(compareResult, ResultCode.COMPARE_FALSE);

      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 2);
      assertEquals(logger.getCompareResultCount(), 2);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed compare is logged.
      compareRequest =
           new CompareRequest("ou=missing,dc=example,dc=com", "ou", "missing");
      requestID = connection.asyncCompare(compareRequest, null);
      compareResult = requestID.get(30L, TimeUnit.SECONDS);
      assertResultCodeEquals(compareResult, ResultCode.NO_SUCH_OBJECT);

      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a successful modify is logged.
      ModifyRequest modifyRequest = new ModifyRequest(
           "dn: ou=test,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: foo");
      requestID = connection.asyncModify(modifyRequest, null);
      LDAPResult modifyResult = requestID.get(30L, TimeUnit.SECONDS);
      assertResultCodeEquals(modifyResult, ResultCode.SUCCESS);

      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 1);
      assertEquals(logger.getModifyResultCount(), 1);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed modify is logged.
      modifyRequest = new ModifyRequest(
           "dn: ou=missing,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: foo");
      requestID = connection.asyncModify(modifyRequest, null);
      modifyResult = requestID.get(30L, TimeUnit.SECONDS);
      assertResultCodeEquals(modifyResult, ResultCode.NO_SUCH_OBJECT);

      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a successful modify DN is logged.
      final ModifyDNRequest modifyDNRequest =
           new ModifyDNRequest("ou=test,dc=example,dc=com", "ou=test2", true);
      requestID = connection.asyncModifyDN(modifyDNRequest, null);
      LDAPResult modifyDNResult = requestID.get(30L, TimeUnit.SECONDS);
      assertResultCodeEquals(modifyDNResult, ResultCode.SUCCESS);

      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 1);
      assertEquals(logger.getModifyDNResultCount(), 1);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed modify DN is logged.
      requestID = connection.asyncModifyDN(modifyDNRequest, null);
      modifyDNResult = requestID.get(30L, TimeUnit.SECONDS);
      assertResultCodeEquals(modifyDNResult, ResultCode.NO_SUCH_OBJECT);

      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 2);
      assertEquals(logger.getModifyDNResultCount(), 2);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a successful search is logged.
      SearchRequest searchRequest = new SearchRequest(
           new TestAsyncListener(),  "dc=example,dc=com",
           SearchScope.SUB, Filter.createPresenceFilter("objectClass"));
      requestID = connection.asyncSearch(searchRequest);
      LDAPResult searchResult = requestID.get(30L, TimeUnit.SECONDS);
      assertResultCodeEquals(searchResult, ResultCode.SUCCESS);

      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 2);
      assertEquals(logger.getModifyDNResultCount(), 2);
      assertEquals(logger.getSearchRequestCount(), 1);
      assertEquals(logger.getSearchResultEntryCount(), 2);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 1);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed search is logged.
      searchRequest = new SearchRequest(
           new TestAsyncListener(),  "ou=missing,dc=example,dc=com",
           SearchScope.SUB, Filter.createPresenceFilter("objectClass"));
      requestID = connection.asyncSearch(searchRequest);
      searchResult = requestID.get(30L, TimeUnit.SECONDS);
      assertResultCodeEquals(searchResult, ResultCode.NO_SUCH_OBJECT);

      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 2);
      assertEquals(logger.getModifyDNResultCount(), 2);
      assertEquals(logger.getSearchRequestCount(), 2);
      assertEquals(logger.getSearchResultEntryCount(), 2);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 2);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a successful delete is logged.
      final DeleteRequest deleteRequest =
           new DeleteRequest("ou=test2,dc=example,dc=com");
      requestID = connection.asyncDelete(deleteRequest, null);
      LDAPResult deleteResult = requestID.get(30L, TimeUnit.SECONDS);
      assertResultCodeEquals(deleteResult, ResultCode.SUCCESS);

      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 1);
      assertEquals(logger.getDeleteResultCount(), 1);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 2);
      assertEquals(logger.getModifyDNResultCount(), 2);
      assertEquals(logger.getSearchRequestCount(), 2);
      assertEquals(logger.getSearchResultEntryCount(), 2);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 2);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Verify that a failed delete is logged.
      requestID = connection.asyncDelete(deleteRequest, null);
      deleteResult = requestID.get(30L, TimeUnit.SECONDS);
      assertResultCodeEquals(deleteResult, ResultCode.NO_SUCH_OBJECT);

      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 2);
      assertEquals(logger.getAddResultCount(), 2);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 3);
      assertEquals(logger.getCompareResultCount(), 3);
      assertEquals(logger.getDeleteRequestCount(), 2);
      assertEquals(logger.getDeleteResultCount(), 2);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 2);
      assertEquals(logger.getModifyResultCount(), 2);
      assertEquals(logger.getModifyDNRequestCount(), 2);
      assertEquals(logger.getModifyDNResultCount(), 2);
      assertEquals(logger.getSearchRequestCount(), 2);
      assertEquals(logger.getSearchResultEntryCount(), 2);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 2);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);
    }


    // Verify that the unbind and disconnect were logged.
    assertEquals(logger.getSuccessfulConnectCount(), 1);
    assertEquals(logger.getFailedConnectCount(), 0);
    assertEquals(logger.getDisconnectCount(), 1);
    assertEquals(logger.getAbandonRequestCount(), 0);
    assertEquals(logger.getAddRequestCount(), 2);
    assertEquals(logger.getAddResultCount(), 2);
    assertEquals(logger.getSimpleBindRequestCount(), 0);
    assertEquals(logger.getSASLBindRequestCount(), 0);
    assertEquals(logger.getBindResultCount(), 0);
    assertEquals(logger.getCompareRequestCount(), 3);
    assertEquals(logger.getCompareResultCount(), 3);
    assertEquals(logger.getDeleteRequestCount(), 2);
    assertEquals(logger.getDeleteResultCount(), 2);
    assertEquals(logger.getExtendedRequestCount(), 0);
    assertEquals(logger.getExtendedResultCount(), 0);
    assertEquals(logger.getModifyRequestCount(), 2);
    assertEquals(logger.getModifyResultCount(), 2);
    assertEquals(logger.getModifyDNRequestCount(), 2);
    assertEquals(logger.getModifyDNResultCount(), 2);
    assertEquals(logger.getSearchRequestCount(), 2);
    assertEquals(logger.getSearchResultEntryCount(), 2);
    assertEquals(logger.getSearchResultReferenceCount(), 0);
    assertEquals(logger.getSearchResultDoneCount(), 2);
    assertEquals(logger.getUnbindRequestCount(), 1);
    assertEquals(logger.getIntermediateResponseCount(), 0);
  }



  /**
   * Tests to ensure that abandon requests are logged as expected.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLogAbandon()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final int port = ds.getListenPort();

    final TestLDAPConnectionLogger logger = new TestLDAPConnectionLogger();

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);

    assertEquals(logger.getSuccessfulConnectCount(), 0);
    assertEquals(logger.getFailedConnectCount(), 0);
    assertEquals(logger.getDisconnectCount(), 0);
    assertEquals(logger.getAbandonRequestCount(), 0);
    assertEquals(logger.getAddRequestCount(), 0);
    assertEquals(logger.getAddResultCount(), 0);
    assertEquals(logger.getSimpleBindRequestCount(), 0);
    assertEquals(logger.getSASLBindRequestCount(), 0);
    assertEquals(logger.getBindResultCount(), 0);
    assertEquals(logger.getCompareRequestCount(), 0);
    assertEquals(logger.getCompareResultCount(), 0);
    assertEquals(logger.getDeleteRequestCount(), 0);
    assertEquals(logger.getDeleteResultCount(), 0);
    assertEquals(logger.getExtendedRequestCount(), 0);
    assertEquals(logger.getExtendedResultCount(), 0);
    assertEquals(logger.getModifyRequestCount(), 0);
    assertEquals(logger.getModifyResultCount(), 0);
    assertEquals(logger.getModifyDNRequestCount(), 0);
    assertEquals(logger.getModifyDNResultCount(), 0);
    assertEquals(logger.getSearchRequestCount(), 0);
    assertEquals(logger.getSearchResultEntryCount(), 0);
    assertEquals(logger.getSearchResultReferenceCount(), 0);
    assertEquals(logger.getSearchResultDoneCount(), 0);
    assertEquals(logger.getUnbindRequestCount(), 0);
    assertEquals(logger.getIntermediateResponseCount(), 0);

    try (LDAPConnection connection =
              new LDAPConnection(options, "localhost", port))
    {
      // Verify that the connect was logged.
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Send an abandon request and make sure it is logged.
      connection.abandon(1);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 1);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);
    }


    // Verify that the unbind and disconnect were logged.
    assertEquals(logger.getSuccessfulConnectCount(), 1);
    assertEquals(logger.getFailedConnectCount(), 0);
    assertEquals(logger.getDisconnectCount(), 1);
    assertEquals(logger.getAbandonRequestCount(), 1);
    assertEquals(logger.getAddRequestCount(), 0);
    assertEquals(logger.getAddResultCount(), 0);
    assertEquals(logger.getSimpleBindRequestCount(), 0);
    assertEquals(logger.getSASLBindRequestCount(), 0);
    assertEquals(logger.getBindResultCount(), 0);
    assertEquals(logger.getCompareRequestCount(), 0);
    assertEquals(logger.getCompareResultCount(), 0);
    assertEquals(logger.getDeleteRequestCount(), 0);
    assertEquals(logger.getDeleteResultCount(), 0);
    assertEquals(logger.getExtendedRequestCount(), 0);
    assertEquals(logger.getExtendedResultCount(), 0);
    assertEquals(logger.getModifyRequestCount(), 0);
    assertEquals(logger.getModifyResultCount(), 0);
    assertEquals(logger.getModifyDNRequestCount(), 0);
    assertEquals(logger.getModifyDNResultCount(), 0);
    assertEquals(logger.getSearchRequestCount(), 0);
    assertEquals(logger.getSearchResultEntryCount(), 0);
    assertEquals(logger.getSearchResultReferenceCount(), 0);
    assertEquals(logger.getSearchResultDoneCount(), 0);
    assertEquals(logger.getUnbindRequestCount(), 1);
    assertEquals(logger.getIntermediateResponseCount(), 0);
  }



  /**
   * Tests to ensure that extended operations are logged as expected when not
   * using synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLogExtendedOperationsNonSynchronous()
         throws Exception
  {
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.addAdditionalBindCredentials("cn=Directory Manager", "password");
    config.addExtendedOperationHandler(
         new TestIntermediateResponseExtendedOperationHandler("1.2.3.4",
              "1.2.3.5", "1.2.3.6", 2, 3));

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
    ds.startListening();

    try
    {
      final int port = ds.getListenPort();

      final TestLDAPConnectionLogger logger = new TestLDAPConnectionLogger();

      final LDAPConnectionOptions options = new LDAPConnectionOptions();
      options.setConnectionLogger(logger);

      assertEquals(logger.getSuccessfulConnectCount(), 0);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);

      try (LDAPConnection connection =
                new LDAPConnection(options, "localhost", port))
      {
        // Verify that the connect was logged.
        assertEquals(logger.getSuccessfulConnectCount(), 1);
        assertEquals(logger.getFailedConnectCount(), 0);
        assertEquals(logger.getDisconnectCount(), 0);
        assertEquals(logger.getAbandonRequestCount(), 0);
        assertEquals(logger.getAddRequestCount(), 0);
        assertEquals(logger.getAddResultCount(), 0);
        assertEquals(logger.getSimpleBindRequestCount(), 0);
        assertEquals(logger.getSASLBindRequestCount(), 0);
        assertEquals(logger.getBindResultCount(), 0);
        assertEquals(logger.getCompareRequestCount(), 0);
        assertEquals(logger.getCompareResultCount(), 0);
        assertEquals(logger.getDeleteRequestCount(), 0);
        assertEquals(logger.getDeleteResultCount(), 0);
        assertEquals(logger.getExtendedRequestCount(), 0);
        assertEquals(logger.getExtendedResultCount(), 0);
        assertEquals(logger.getModifyRequestCount(), 0);
        assertEquals(logger.getModifyResultCount(), 0);
        assertEquals(logger.getModifyDNRequestCount(), 0);
        assertEquals(logger.getModifyDNResultCount(), 0);
        assertEquals(logger.getSearchRequestCount(), 0);
        assertEquals(logger.getSearchResultEntryCount(), 0);
        assertEquals(logger.getSearchResultReferenceCount(), 0);
        assertEquals(logger.getSearchResultDoneCount(), 0);
        assertEquals(logger.getUnbindRequestCount(), 0);
        assertEquals(logger.getIntermediateResponseCount(), 0);


        // Authenticate the connection.
        assertResultCodeEquals(connection,
             new SimpleBindRequest("cn=Directory Manager", "password"),
             ResultCode.SUCCESS);
        assertEquals(logger.getSuccessfulConnectCount(), 1);
        assertEquals(logger.getFailedConnectCount(), 0);
        assertEquals(logger.getDisconnectCount(), 0);
        assertEquals(logger.getAbandonRequestCount(), 0);
        assertEquals(logger.getAddRequestCount(), 0);
        assertEquals(logger.getAddResultCount(), 0);
        assertEquals(logger.getSimpleBindRequestCount(), 1);
        assertEquals(logger.getSASLBindRequestCount(), 0);
        assertEquals(logger.getBindResultCount(), 1);
        assertEquals(logger.getCompareRequestCount(), 0);
        assertEquals(logger.getCompareResultCount(), 0);
        assertEquals(logger.getDeleteRequestCount(), 0);
        assertEquals(logger.getDeleteResultCount(), 0);
        assertEquals(logger.getExtendedRequestCount(), 0);
        assertEquals(logger.getExtendedResultCount(), 0);
        assertEquals(logger.getModifyRequestCount(), 0);
        assertEquals(logger.getModifyResultCount(), 0);
        assertEquals(logger.getModifyDNRequestCount(), 0);
        assertEquals(logger.getModifyDNResultCount(), 0);
        assertEquals(logger.getSearchRequestCount(), 0);
        assertEquals(logger.getSearchResultEntryCount(), 0);
        assertEquals(logger.getSearchResultReferenceCount(), 0);
        assertEquals(logger.getSearchResultDoneCount(), 0);
        assertEquals(logger.getUnbindRequestCount(), 0);
        assertEquals(logger.getIntermediateResponseCount(), 0);


        // Send a "Who Am I?" extended request on the connection.
        assertResultCodeEquals(connection,
             new WhoAmIExtendedRequest(),
             ResultCode.SUCCESS);
        assertEquals(logger.getSuccessfulConnectCount(), 1);
        assertEquals(logger.getFailedConnectCount(), 0);
        assertEquals(logger.getDisconnectCount(), 0);
        assertEquals(logger.getAbandonRequestCount(), 0);
        assertEquals(logger.getAddRequestCount(), 0);
        assertEquals(logger.getAddResultCount(), 0);
        assertEquals(logger.getSimpleBindRequestCount(), 1);
        assertEquals(logger.getSASLBindRequestCount(), 0);
        assertEquals(logger.getBindResultCount(), 1);
        assertEquals(logger.getCompareRequestCount(), 0);
        assertEquals(logger.getCompareResultCount(), 0);
        assertEquals(logger.getDeleteRequestCount(), 0);
        assertEquals(logger.getDeleteResultCount(), 0);
        assertEquals(logger.getExtendedRequestCount(), 1);
        assertEquals(logger.getExtendedResultCount(), 1);
        assertEquals(logger.getModifyRequestCount(), 0);
        assertEquals(logger.getModifyResultCount(), 0);
        assertEquals(logger.getModifyDNRequestCount(), 0);
        assertEquals(logger.getModifyDNResultCount(), 0);
        assertEquals(logger.getSearchRequestCount(), 0);
        assertEquals(logger.getSearchResultEntryCount(), 0);
        assertEquals(logger.getSearchResultReferenceCount(), 0);
        assertEquals(logger.getSearchResultDoneCount(), 0);
        assertEquals(logger.getUnbindRequestCount(), 0);
        assertEquals(logger.getIntermediateResponseCount(), 0);


        // Send an extended request that will include intermediate responses.
        assertResultCodeEquals(connection,
             new ExtendedRequest("1.2.3.4"),
             ResultCode.SUCCESS);
        assertEquals(logger.getSuccessfulConnectCount(), 1);
        assertEquals(logger.getFailedConnectCount(), 0);
        assertEquals(logger.getDisconnectCount(), 0);
        assertEquals(logger.getAbandonRequestCount(), 0);
        assertEquals(logger.getAddRequestCount(), 0);
        assertEquals(logger.getAddResultCount(), 0);
        assertEquals(logger.getSimpleBindRequestCount(), 1);
        assertEquals(logger.getSASLBindRequestCount(), 0);
        assertEquals(logger.getBindResultCount(), 1);
        assertEquals(logger.getCompareRequestCount(), 0);
        assertEquals(logger.getCompareResultCount(), 0);
        assertEquals(logger.getDeleteRequestCount(), 0);
        assertEquals(logger.getDeleteResultCount(), 0);
        assertEquals(logger.getExtendedRequestCount(), 2);
        assertEquals(logger.getExtendedResultCount(), 2);
        assertEquals(logger.getModifyRequestCount(), 0);
        assertEquals(logger.getModifyResultCount(), 0);
        assertEquals(logger.getModifyDNRequestCount(), 0);
        assertEquals(logger.getModifyDNResultCount(), 0);
        assertEquals(logger.getSearchRequestCount(), 0);
        assertEquals(logger.getSearchResultEntryCount(), 0);
        assertEquals(logger.getSearchResultReferenceCount(), 0);
        assertEquals(logger.getSearchResultDoneCount(), 0);
        assertEquals(logger.getUnbindRequestCount(), 0);
        assertEquals(logger.getIntermediateResponseCount(), 5);


        // Send an extended request with an unrecognized request OID.
        assertResultCodeEquals(connection,
             new ExtendedRequest("4.3.2.1"),
             ResultCode.UNWILLING_TO_PERFORM);
        assertEquals(logger.getSuccessfulConnectCount(), 1);
        assertEquals(logger.getFailedConnectCount(), 0);
        assertEquals(logger.getDisconnectCount(), 0);
        assertEquals(logger.getAbandonRequestCount(), 0);
        assertEquals(logger.getAddRequestCount(), 0);
        assertEquals(logger.getAddResultCount(), 0);
        assertEquals(logger.getSimpleBindRequestCount(), 1);
        assertEquals(logger.getSASLBindRequestCount(), 0);
        assertEquals(logger.getBindResultCount(), 1);
        assertEquals(logger.getCompareRequestCount(), 0);
        assertEquals(logger.getCompareResultCount(), 0);
        assertEquals(logger.getDeleteRequestCount(), 0);
        assertEquals(logger.getDeleteResultCount(), 0);
        assertEquals(logger.getExtendedRequestCount(), 3);
        assertEquals(logger.getExtendedResultCount(), 3);
        assertEquals(logger.getModifyRequestCount(), 0);
        assertEquals(logger.getModifyResultCount(), 0);
        assertEquals(logger.getModifyDNRequestCount(), 0);
        assertEquals(logger.getModifyDNResultCount(), 0);
        assertEquals(logger.getSearchRequestCount(), 0);
        assertEquals(logger.getSearchResultEntryCount(), 0);
        assertEquals(logger.getSearchResultReferenceCount(), 0);
        assertEquals(logger.getSearchResultDoneCount(), 0);
        assertEquals(logger.getUnbindRequestCount(), 0);
        assertEquals(logger.getIntermediateResponseCount(), 5);
      }


      // Verify that the unbind and disconnect were logged.
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 1);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 1);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 1);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 3);
      assertEquals(logger.getExtendedResultCount(), 3);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 1);
      assertEquals(logger.getIntermediateResponseCount(), 5);
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests to ensure that extended operations are logged as expected when using
   * synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLogExtendedOperationsSynchronous()
         throws Exception
  {
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.addAdditionalBindCredentials("cn=Directory Manager", "password");
    config.addExtendedOperationHandler(
         new TestIntermediateResponseExtendedOperationHandler("1.2.3.4",
              "1.2.3.5", "1.2.3.6", 2, 3));

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
    ds.startListening();

    try
    {
      final int port = ds.getListenPort();

      final TestLDAPConnectionLogger logger = new TestLDAPConnectionLogger();

      final LDAPConnectionOptions options = new LDAPConnectionOptions();
      options.setUseSynchronousMode(true);
      options.setConnectionLogger(logger);

      assertEquals(logger.getSuccessfulConnectCount(), 0);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);

      try (LDAPConnection connection =
                new LDAPConnection(options, "localhost", port))
      {
        // Verify that the connect was logged.
        assertEquals(logger.getSuccessfulConnectCount(), 1);
        assertEquals(logger.getFailedConnectCount(), 0);
        assertEquals(logger.getDisconnectCount(), 0);
        assertEquals(logger.getAbandonRequestCount(), 0);
        assertEquals(logger.getAddRequestCount(), 0);
        assertEquals(logger.getAddResultCount(), 0);
        assertEquals(logger.getSimpleBindRequestCount(), 0);
        assertEquals(logger.getSASLBindRequestCount(), 0);
        assertEquals(logger.getBindResultCount(), 0);
        assertEquals(logger.getCompareRequestCount(), 0);
        assertEquals(logger.getCompareResultCount(), 0);
        assertEquals(logger.getDeleteRequestCount(), 0);
        assertEquals(logger.getDeleteResultCount(), 0);
        assertEquals(logger.getExtendedRequestCount(), 0);
        assertEquals(logger.getExtendedResultCount(), 0);
        assertEquals(logger.getModifyRequestCount(), 0);
        assertEquals(logger.getModifyResultCount(), 0);
        assertEquals(logger.getModifyDNRequestCount(), 0);
        assertEquals(logger.getModifyDNResultCount(), 0);
        assertEquals(logger.getSearchRequestCount(), 0);
        assertEquals(logger.getSearchResultEntryCount(), 0);
        assertEquals(logger.getSearchResultReferenceCount(), 0);
        assertEquals(logger.getSearchResultDoneCount(), 0);
        assertEquals(logger.getUnbindRequestCount(), 0);
        assertEquals(logger.getIntermediateResponseCount(), 0);


        // Authenticate the connection.
        assertResultCodeEquals(connection,
             new SimpleBindRequest("cn=Directory Manager", "password"),
             ResultCode.SUCCESS);
        assertEquals(logger.getSuccessfulConnectCount(), 1);
        assertEquals(logger.getFailedConnectCount(), 0);
        assertEquals(logger.getDisconnectCount(), 0);
        assertEquals(logger.getAbandonRequestCount(), 0);
        assertEquals(logger.getAddRequestCount(), 0);
        assertEquals(logger.getAddResultCount(), 0);
        assertEquals(logger.getSimpleBindRequestCount(), 1);
        assertEquals(logger.getSASLBindRequestCount(), 0);
        assertEquals(logger.getBindResultCount(), 1);
        assertEquals(logger.getCompareRequestCount(), 0);
        assertEquals(logger.getCompareResultCount(), 0);
        assertEquals(logger.getDeleteRequestCount(), 0);
        assertEquals(logger.getDeleteResultCount(), 0);
        assertEquals(logger.getExtendedRequestCount(), 0);
        assertEquals(logger.getExtendedResultCount(), 0);
        assertEquals(logger.getModifyRequestCount(), 0);
        assertEquals(logger.getModifyResultCount(), 0);
        assertEquals(logger.getModifyDNRequestCount(), 0);
        assertEquals(logger.getModifyDNResultCount(), 0);
        assertEquals(logger.getSearchRequestCount(), 0);
        assertEquals(logger.getSearchResultEntryCount(), 0);
        assertEquals(logger.getSearchResultReferenceCount(), 0);
        assertEquals(logger.getSearchResultDoneCount(), 0);
        assertEquals(logger.getUnbindRequestCount(), 0);
        assertEquals(logger.getIntermediateResponseCount(), 0);


        // Send a "Who Am I?" extended request on the connection.
        assertResultCodeEquals(connection,
             new WhoAmIExtendedRequest(),
             ResultCode.SUCCESS);
        assertEquals(logger.getSuccessfulConnectCount(), 1);
        assertEquals(logger.getFailedConnectCount(), 0);
        assertEquals(logger.getDisconnectCount(), 0);
        assertEquals(logger.getAbandonRequestCount(), 0);
        assertEquals(logger.getAddRequestCount(), 0);
        assertEquals(logger.getAddResultCount(), 0);
        assertEquals(logger.getSimpleBindRequestCount(), 1);
        assertEquals(logger.getSASLBindRequestCount(), 0);
        assertEquals(logger.getBindResultCount(), 1);
        assertEquals(logger.getCompareRequestCount(), 0);
        assertEquals(logger.getCompareResultCount(), 0);
        assertEquals(logger.getDeleteRequestCount(), 0);
        assertEquals(logger.getDeleteResultCount(), 0);
        assertEquals(logger.getExtendedRequestCount(), 1);
        assertEquals(logger.getExtendedResultCount(), 1);
        assertEquals(logger.getModifyRequestCount(), 0);
        assertEquals(logger.getModifyResultCount(), 0);
        assertEquals(logger.getModifyDNRequestCount(), 0);
        assertEquals(logger.getModifyDNResultCount(), 0);
        assertEquals(logger.getSearchRequestCount(), 0);
        assertEquals(logger.getSearchResultEntryCount(), 0);
        assertEquals(logger.getSearchResultReferenceCount(), 0);
        assertEquals(logger.getSearchResultDoneCount(), 0);
        assertEquals(logger.getUnbindRequestCount(), 0);
        assertEquals(logger.getIntermediateResponseCount(), 0);


        // Send an extended request that will include intermediate responses.
        assertResultCodeEquals(connection,
             new ExtendedRequest("1.2.3.4"),
             ResultCode.SUCCESS);
        assertEquals(logger.getSuccessfulConnectCount(), 1);
        assertEquals(logger.getFailedConnectCount(), 0);
        assertEquals(logger.getDisconnectCount(), 0);
        assertEquals(logger.getAbandonRequestCount(), 0);
        assertEquals(logger.getAddRequestCount(), 0);
        assertEquals(logger.getAddResultCount(), 0);
        assertEquals(logger.getSimpleBindRequestCount(), 1);
        assertEquals(logger.getSASLBindRequestCount(), 0);
        assertEquals(logger.getBindResultCount(), 1);
        assertEquals(logger.getCompareRequestCount(), 0);
        assertEquals(logger.getCompareResultCount(), 0);
        assertEquals(logger.getDeleteRequestCount(), 0);
        assertEquals(logger.getDeleteResultCount(), 0);
        assertEquals(logger.getExtendedRequestCount(), 2);
        assertEquals(logger.getExtendedResultCount(), 2);
        assertEquals(logger.getModifyRequestCount(), 0);
        assertEquals(logger.getModifyResultCount(), 0);
        assertEquals(logger.getModifyDNRequestCount(), 0);
        assertEquals(logger.getModifyDNResultCount(), 0);
        assertEquals(logger.getSearchRequestCount(), 0);
        assertEquals(logger.getSearchResultEntryCount(), 0);
        assertEquals(logger.getSearchResultReferenceCount(), 0);
        assertEquals(logger.getSearchResultDoneCount(), 0);
        assertEquals(logger.getUnbindRequestCount(), 0);
        assertEquals(logger.getIntermediateResponseCount(), 5);


        // Send an extended request with an unrecognized request OID.
        assertResultCodeEquals(connection,
             new ExtendedRequest("4.3.2.1"),
             ResultCode.UNWILLING_TO_PERFORM);
        assertEquals(logger.getSuccessfulConnectCount(), 1);
        assertEquals(logger.getFailedConnectCount(), 0);
        assertEquals(logger.getDisconnectCount(), 0);
        assertEquals(logger.getAbandonRequestCount(), 0);
        assertEquals(logger.getAddRequestCount(), 0);
        assertEquals(logger.getAddResultCount(), 0);
        assertEquals(logger.getSimpleBindRequestCount(), 1);
        assertEquals(logger.getSASLBindRequestCount(), 0);
        assertEquals(logger.getBindResultCount(), 1);
        assertEquals(logger.getCompareRequestCount(), 0);
        assertEquals(logger.getCompareResultCount(), 0);
        assertEquals(logger.getDeleteRequestCount(), 0);
        assertEquals(logger.getDeleteResultCount(), 0);
        assertEquals(logger.getExtendedRequestCount(), 3);
        assertEquals(logger.getExtendedResultCount(), 3);
        assertEquals(logger.getModifyRequestCount(), 0);
        assertEquals(logger.getModifyResultCount(), 0);
        assertEquals(logger.getModifyDNRequestCount(), 0);
        assertEquals(logger.getModifyDNResultCount(), 0);
        assertEquals(logger.getSearchRequestCount(), 0);
        assertEquals(logger.getSearchResultEntryCount(), 0);
        assertEquals(logger.getSearchResultReferenceCount(), 0);
        assertEquals(logger.getSearchResultDoneCount(), 0);
        assertEquals(logger.getUnbindRequestCount(), 0);
        assertEquals(logger.getIntermediateResponseCount(), 5);
      }


      // Verify that the unbind and disconnect were logged.
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 1);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 1);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 1);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 3);
      assertEquals(logger.getExtendedResultCount(), 3);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 1);
      assertEquals(logger.getIntermediateResponseCount(), 5);
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests to ensure that search result references are logged as expected for
   * connections not using synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchReferenceNonSynchronous()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final int port = ds.getListenPort();

    ds.add(
         "dn: ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ou: Users",
         "ref: ldap://localhost:" + port + "/ou=People,dc=example,dc=com");


    final TestLDAPConnectionLogger logger = new TestLDAPConnectionLogger();

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);

    assertEquals(logger.getSuccessfulConnectCount(), 0);
    assertEquals(logger.getFailedConnectCount(), 0);
    assertEquals(logger.getDisconnectCount(), 0);
    assertEquals(logger.getAbandonRequestCount(), 0);
    assertEquals(logger.getAddRequestCount(), 0);
    assertEquals(logger.getAddResultCount(), 0);
    assertEquals(logger.getSimpleBindRequestCount(), 0);
    assertEquals(logger.getSASLBindRequestCount(), 0);
    assertEquals(logger.getBindResultCount(), 0);
    assertEquals(logger.getCompareRequestCount(), 0);
    assertEquals(logger.getCompareResultCount(), 0);
    assertEquals(logger.getDeleteRequestCount(), 0);
    assertEquals(logger.getDeleteResultCount(), 0);
    assertEquals(logger.getExtendedRequestCount(), 0);
    assertEquals(logger.getExtendedResultCount(), 0);
    assertEquals(logger.getModifyRequestCount(), 0);
    assertEquals(logger.getModifyResultCount(), 0);
    assertEquals(logger.getModifyDNRequestCount(), 0);
    assertEquals(logger.getModifyDNResultCount(), 0);
    assertEquals(logger.getSearchRequestCount(), 0);
    assertEquals(logger.getSearchResultEntryCount(), 0);
    assertEquals(logger.getSearchResultReferenceCount(), 0);
    assertEquals(logger.getSearchResultDoneCount(), 0);
    assertEquals(logger.getUnbindRequestCount(), 0);
    assertEquals(logger.getIntermediateResponseCount(), 0);

    try (LDAPConnection connection =
              new LDAPConnection(options, "localhost", port))
    {
      // Verify that the connect was logged.
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Perform a subtree search that will include a search result reference.
      assertResultCodeEquals(connection,
           new SearchRequest("dc=example,dc=com", SearchScope.SUB,
                Filter.createPresenceFilter("objectClass")),
           ResultCode.SUCCESS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 1);
      assertEquals(logger.getSearchResultEntryCount(), 3);
      assertEquals(logger.getSearchResultReferenceCount(), 1);
      assertEquals(logger.getSearchResultDoneCount(), 1);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);
    }


      // Verify that the unbind and disconnect were logged.
    assertEquals(logger.getSuccessfulConnectCount(), 1);
    assertEquals(logger.getFailedConnectCount(), 0);
    assertEquals(logger.getDisconnectCount(), 1);
    assertEquals(logger.getAbandonRequestCount(), 0);
    assertEquals(logger.getAddRequestCount(), 0);
    assertEquals(logger.getAddResultCount(), 0);
    assertEquals(logger.getSimpleBindRequestCount(), 0);
    assertEquals(logger.getSASLBindRequestCount(), 0);
    assertEquals(logger.getBindResultCount(), 0);
    assertEquals(logger.getCompareRequestCount(), 0);
    assertEquals(logger.getCompareResultCount(), 0);
    assertEquals(logger.getDeleteRequestCount(), 0);
    assertEquals(logger.getDeleteResultCount(), 0);
    assertEquals(logger.getExtendedRequestCount(), 0);
    assertEquals(logger.getExtendedResultCount(), 0);
    assertEquals(logger.getModifyRequestCount(), 0);
    assertEquals(logger.getModifyResultCount(), 0);
    assertEquals(logger.getModifyDNRequestCount(), 0);
    assertEquals(logger.getModifyDNResultCount(), 0);
    assertEquals(logger.getSearchRequestCount(), 1);
    assertEquals(logger.getSearchResultEntryCount(), 3);
    assertEquals(logger.getSearchResultReferenceCount(), 1);
    assertEquals(logger.getSearchResultDoneCount(), 1);
    assertEquals(logger.getUnbindRequestCount(), 1);
    assertEquals(logger.getIntermediateResponseCount(), 0);
  }



  /**
   * Tests to ensure that search result references are logged as expected for
   * connections using synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchReferenceSynchronous()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final int port = ds.getListenPort();

    ds.add(
         "dn: ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ou: Users",
         "ref: ldap://localhost:" + port + "/ou=People,dc=example,dc=com");


    final TestLDAPConnectionLogger logger = new TestLDAPConnectionLogger();

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);
    options.setConnectionLogger(logger);

    assertEquals(logger.getSuccessfulConnectCount(), 0);
    assertEquals(logger.getFailedConnectCount(), 0);
    assertEquals(logger.getDisconnectCount(), 0);
    assertEquals(logger.getAbandonRequestCount(), 0);
    assertEquals(logger.getAddRequestCount(), 0);
    assertEquals(logger.getAddResultCount(), 0);
    assertEquals(logger.getSimpleBindRequestCount(), 0);
    assertEquals(logger.getSASLBindRequestCount(), 0);
    assertEquals(logger.getBindResultCount(), 0);
    assertEquals(logger.getCompareRequestCount(), 0);
    assertEquals(logger.getCompareResultCount(), 0);
    assertEquals(logger.getDeleteRequestCount(), 0);
    assertEquals(logger.getDeleteResultCount(), 0);
    assertEquals(logger.getExtendedRequestCount(), 0);
    assertEquals(logger.getExtendedResultCount(), 0);
    assertEquals(logger.getModifyRequestCount(), 0);
    assertEquals(logger.getModifyResultCount(), 0);
    assertEquals(logger.getModifyDNRequestCount(), 0);
    assertEquals(logger.getModifyDNResultCount(), 0);
    assertEquals(logger.getSearchRequestCount(), 0);
    assertEquals(logger.getSearchResultEntryCount(), 0);
    assertEquals(logger.getSearchResultReferenceCount(), 0);
    assertEquals(logger.getSearchResultDoneCount(), 0);
    assertEquals(logger.getUnbindRequestCount(), 0);
    assertEquals(logger.getIntermediateResponseCount(), 0);

    try (LDAPConnection connection =
              new LDAPConnection(options, "localhost", port))
    {
      // Verify that the connect was logged.
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 0);
      assertEquals(logger.getSearchResultEntryCount(), 0);
      assertEquals(logger.getSearchResultReferenceCount(), 0);
      assertEquals(logger.getSearchResultDoneCount(), 0);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);


      // Perform a subtree search that will include a search result reference.
      assertResultCodeEquals(connection,
           new SearchRequest("dc=example,dc=com", SearchScope.SUB,
                Filter.createPresenceFilter("objectClass")),
           ResultCode.SUCCESS);
      assertEquals(logger.getSuccessfulConnectCount(), 1);
      assertEquals(logger.getFailedConnectCount(), 0);
      assertEquals(logger.getDisconnectCount(), 0);
      assertEquals(logger.getAbandonRequestCount(), 0);
      assertEquals(logger.getAddRequestCount(), 0);
      assertEquals(logger.getAddResultCount(), 0);
      assertEquals(logger.getSimpleBindRequestCount(), 0);
      assertEquals(logger.getSASLBindRequestCount(), 0);
      assertEquals(logger.getBindResultCount(), 0);
      assertEquals(logger.getCompareRequestCount(), 0);
      assertEquals(logger.getCompareResultCount(), 0);
      assertEquals(logger.getDeleteRequestCount(), 0);
      assertEquals(logger.getDeleteResultCount(), 0);
      assertEquals(logger.getExtendedRequestCount(), 0);
      assertEquals(logger.getExtendedResultCount(), 0);
      assertEquals(logger.getModifyRequestCount(), 0);
      assertEquals(logger.getModifyResultCount(), 0);
      assertEquals(logger.getModifyDNRequestCount(), 0);
      assertEquals(logger.getModifyDNResultCount(), 0);
      assertEquals(logger.getSearchRequestCount(), 1);
      assertEquals(logger.getSearchResultEntryCount(), 3);
      assertEquals(logger.getSearchResultReferenceCount(), 1);
      assertEquals(logger.getSearchResultDoneCount(), 1);
      assertEquals(logger.getUnbindRequestCount(), 0);
      assertEquals(logger.getIntermediateResponseCount(), 0);
    }


      // Verify that the unbind and disconnect were logged.
    assertEquals(logger.getSuccessfulConnectCount(), 1);
    assertEquals(logger.getFailedConnectCount(), 0);
    assertEquals(logger.getDisconnectCount(), 1);
    assertEquals(logger.getAbandonRequestCount(), 0);
    assertEquals(logger.getAddRequestCount(), 0);
    assertEquals(logger.getAddResultCount(), 0);
    assertEquals(logger.getSimpleBindRequestCount(), 0);
    assertEquals(logger.getSASLBindRequestCount(), 0);
    assertEquals(logger.getBindResultCount(), 0);
    assertEquals(logger.getCompareRequestCount(), 0);
    assertEquals(logger.getCompareResultCount(), 0);
    assertEquals(logger.getDeleteRequestCount(), 0);
    assertEquals(logger.getDeleteResultCount(), 0);
    assertEquals(logger.getExtendedRequestCount(), 0);
    assertEquals(logger.getExtendedResultCount(), 0);
    assertEquals(logger.getModifyRequestCount(), 0);
    assertEquals(logger.getModifyResultCount(), 0);
    assertEquals(logger.getModifyDNRequestCount(), 0);
    assertEquals(logger.getModifyDNResultCount(), 0);
    assertEquals(logger.getSearchRequestCount(), 1);
    assertEquals(logger.getSearchResultEntryCount(), 3);
    assertEquals(logger.getSearchResultReferenceCount(), 1);
    assertEquals(logger.getSearchResultDoneCount(), 1);
    assertEquals(logger.getUnbindRequestCount(), 1);
    assertEquals(logger.getIntermediateResponseCount(), 0);
  }
}
