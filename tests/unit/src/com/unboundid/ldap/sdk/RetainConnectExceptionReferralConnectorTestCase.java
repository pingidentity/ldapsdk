/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;



/**
 * This class provides a set of test cases for the retain connect exception
 * referral connector.
 */
public final class RetainConnectExceptionReferralConnectorTestCase
       extends LDAPSDKTestCase
{
  // A pair of directory server instances to use for testing.
  private InMemoryDirectoryServer ds1;
  private InMemoryDirectoryServer ds2;



  /**
   * Configures a pair of in-memory directory server instances to use for
   * testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg1 =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg1.addAdditionalBindCredentials("cn=User 1", "password");
    cfg1.addAdditionalBindCredentials("cn=User 2", "password");

    ds1 = new InMemoryDirectoryServer(cfg1);
    ds1.startListening();

    final InMemoryDirectoryServerConfig cfg2 =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg2.addAdditionalBindCredentials("cn=User 1", "password");

    ds2 = new InMemoryDirectoryServer(cfg2);
    ds2.startListening();

    final String referralHost;
    if (ds2.getListenAddress() == null)
    {
      referralHost = "127.0.0.1";
    }
    else
    {
      referralHost = ds2.getListenAddress().getHostAddress();
    }

    final LDAPURL referralURL = new LDAPURL("ldap", referralHost,
         ds2.getListenPort(), new DN("ou=Test,dc=example,dc=com"), null, null,
         null);

    ds1.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    ds1.add(
         "dn: ou=Test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ou: Test",
         "ref: " + referralURL);

    ds2.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    ds2.add(
         "dn: ou=Test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Test");
  }



  /**
   * Cleans up after testing is complete.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void cleanUp()
         throws Exception
  {
    try
    {
      ds1.shutDown(true);
    } catch (final Exception e) {}

    try
    {
      ds2.shutDown(true);
    } catch (final Exception e) {}
  }



  /**
   * Tests the behavior of the referral handler with the default constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultConstructor()
         throws Exception
  {
    final RetainConnectExceptionReferralConnector referralConnector =
         new RetainConnectExceptionReferralConnector();

    try (LDAPConnection conn = ds1.getConnection())
    {
      // Make sure that we can bind as a user that should exist in both servers.
      assertResultCodeEquals(conn,
           new SimpleBindRequest("cn=User 1", "password"),
           ResultCode.SUCCESS);


      // Perform a search without following referrals to ensure that we get a
      // referral result.
      final SearchRequest searchRequest = new SearchRequest(
           "ou=Test,dc=example,dc=com", SearchScope.BASE,
           Filter.createPresenceFilter("objectClass"));
      assertResultCodeEquals(conn, searchRequest, ResultCode.REFERRAL);
      assertNull(referralConnector.getExceptionFromLastConnectAttempt());


      // Update the search request so that it will follow referrals and will
      // use the custom referral connector.
      searchRequest.setFollowReferrals(true);
      searchRequest.setReferralConnector(referralConnector);


      // Perform the search again and verify that the search no longer returns a
      // referral and that we get the expected entry.
      SearchResult searchResult = conn.search(searchRequest);
      assertResultCodeEquals(searchResult, ResultCode.SUCCESS);
      assertEntriesReturnedEquals(searchResult, 1);
      assertReferencesReturnedEquals(searchResult, 0);
      assertNull(referralConnector.getExceptionFromLastConnectAttempt());


      // Shut down the second instance so that the referral connector won't be
      // able to establish a connection and verify that we once again get the
      // referral.
      ds2.shutDown(true);
      try
      {
        searchResult = conn.search(searchRequest);
      }
      catch (final LDAPSearchException e)
      {
        searchResult = e.getSearchResult();
      }

      assertResultCodeEquals(searchResult, ResultCode.REFERRAL);
      assertNotNull(referralConnector.getExceptionFromLastConnectAttempt());
      assertEquals(
           referralConnector.getExceptionFromLastConnectAttempt().
                getResultCode(),
           ResultCode.CONNECT_ERROR);


      // Start the second instance again.  Verify that we can once again
      // automatically follow the referral and that there is no exception from
      // the last connection attempt.
      ds2.startListening();

      searchResult = conn.search(searchRequest);
      assertResultCodeEquals(searchResult, ResultCode.SUCCESS);
      assertEntriesReturnedEquals(searchResult, 1);
      assertReferencesReturnedEquals(searchResult, 0);
      assertNull(referralConnector.getExceptionFromLastConnectAttempt());


      // Re-authenticate the connection as a user that only exists in the first
      // server.
      assertResultCodeEquals(conn,
           new SimpleBindRequest("cn=User 2", "password"),
           ResultCode.SUCCESS);


      // Perform the search again.  This time, the referral connector should
      // fail to authenticate to the second server, so we should get a referral
      // result.
      try
      {
        searchResult = conn.search(searchRequest);
      }
      catch (final LDAPSearchException e)
      {
        searchResult = e.getSearchResult();
      }

      assertResultCodeEquals(searchResult, ResultCode.REFERRAL);
      assertNotNull(referralConnector.getExceptionFromLastConnectAttempt());
      assertEquals(
           referralConnector.getExceptionFromLastConnectAttempt().
                getResultCode(),
           ResultCode.INVALID_CREDENTIALS);


      // Revert the connection to an unauthenticated state with an anonymous
      // simple bind request.
      assertResultCodeEquals(conn,
           new SimpleBindRequest("", ""),
           ResultCode.SUCCESS);


      // Verify that the search once again succeeds after automatically
      // following the referral and that there is no longer any record of a
      // connect exception from the referral connector.
      searchResult = conn.search(searchRequest);
      assertResultCodeEquals(searchResult, ResultCode.SUCCESS);
      assertEntriesReturnedEquals(searchResult, 1);
      assertReferencesReturnedEquals(searchResult, 0);
      assertNull(referralConnector.getExceptionFromLastConnectAttempt());
    }
  }



  /**
   * Tests the behavior when the referral connector wraps a provided connector.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithCustomWrappedConnector()
         throws Exception
  {
    final TestReferralConnector testReferralConnector =
         new TestReferralConnector();
    testReferralConnector.setExceptionToThrow(new LDAPException(
         ResultCode.CONNECT_ERROR, "I feel like failing."));

    final RetainConnectExceptionReferralConnector referralConnector =
         new RetainConnectExceptionReferralConnector(testReferralConnector);


    try (LDAPConnection conn = ds1.getConnection())
    {
      // Create a search request that should trigger a referral, and configure
      // it to use a custom referral handler.
      final SearchRequest searchRequest = new SearchRequest(
           "ou=Test,dc=example,dc=com", SearchScope.BASE,
           Filter.createPresenceFilter("objectClass"));
      searchRequest.setFollowReferrals(true);
      searchRequest.setReferralConnector(referralConnector);


      SearchResult searchResult;
      try
      {
        searchResult = conn.search(searchRequest);
      }
      catch (final LDAPSearchException e)
      {
        searchResult = e.getSearchResult();
      }

      assertResultCodeEquals(searchResult, ResultCode.REFERRAL);
      assertNotNull(referralConnector.getExceptionFromLastConnectAttempt());
      assertEquals(
           referralConnector.getExceptionFromLastConnectAttempt().
                getResultCode(),
           ResultCode.CONNECT_ERROR);
      assertEquals(
           referralConnector.getExceptionFromLastConnectAttempt().getMessage(),
           "I feel like failing.");
    }
  }
}
