/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.controls.SubtreeDeleteRequestControl;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;



/**
 * This class provides a set of test cases to ensure that the LDAP SDK properly
 * handles referrals that are encountered.
 */
public class ReferralTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the SDK when there is a single referral, controlling
   * following via connection options.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleHopViaConnectionOptions()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }


    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());

    conn.add("dn: ou=People," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: People");

    conn.add("dn: ou=Users," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: referral",
             "objectClass: extensibleObject",
             "ou: Users",
             "ref: ldap://" + getTestHost() + ':' + getTestPort() + '/' +
                  "ou=People," + getTestBaseDN());

    Entry userEntry = new Entry(
         "dn: uid=test.user,ou=Users," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password");

    DN expectedDN = new DN("uid=test.user,ou=People," + getTestBaseDN());

    try
    {
      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to add an entry below the referral.
      assertFalse(conn.getConnectionOptions().followReferrals());
      try
      {
        conn.add(userEntry);
        fail("Expected an exception when trying to add below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(), expectedDN);
      }


      // Enable automatic referral following and ensure that the add is
      // successful.
      conn.getConnectionOptions().setFollowReferrals(true);
      assertTrue(conn.getConnectionOptions().followReferrals());
      LDAPResult result = conn.add(userEntry);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to modify the target entry.
      conn.getConnectionOptions().setFollowReferrals(false);
      assertFalse(conn.getConnectionOptions().followReferrals());
      try
      {
        conn.modify("dn: " + userEntry.getDN(),
                    "changetype: modify",
                    "replace: description",
                    "description: foo");
        fail("Expected an exception when trying to modify below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(), expectedDN);
      }


      // Enable automatic referral following and ensure that the modify is
      // successful.
      conn.getConnectionOptions().setFollowReferrals(true);
      assertTrue(conn.getConnectionOptions().followReferrals());
      result = conn.modify("dn: " + userEntry.getDN(),
                           "changetype: modify",
                           "replace: description",
                           "description: foo");
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to perform searches with a base DN at and below
      // the referral.
      conn.getConnectionOptions().setFollowReferrals(false);
      assertFalse(conn.getConnectionOptions().followReferrals());
      try
      {
        conn.search(userEntry.getParentDNString(), SearchScope.SUB,
                    "(objectClass=*)");
        fail("Expected an exception when trying to search at a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(), expectedDN.getParent());
        assertEquals(referralURL.getScope(), SearchScope.SUB);
      }

      try
      {
        conn.search(userEntry.getDN(), SearchScope.BASE, "(objectClass=*)");
        fail("Expected an exception when trying to search below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(), expectedDN);
        assertEquals(referralURL.getScope(), SearchScope.BASE);
      }


      // Ensure that with automatic referral following still disabled, a search
      // with a base DN that is above the referral won't throw an exception but
      // will return a search result reference.
      SearchResult searchResult = conn.search(getTestBaseDN(), SearchScope.SUB,
                                              "(objectClass=*)");
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getReferenceCount(), 1);


      // Enable automatic referral following and ensure that the searches are
      // successful.
      conn.getConnectionOptions().setFollowReferrals(true);
      assertTrue(conn.getConnectionOptions().followReferrals());
      searchResult = conn.search(userEntry.getParentDNString(), SearchScope.SUB,
                                 "(objectClass=*)");
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 2);

      searchResult = conn.search(userEntry.getDN(), SearchScope.BASE,
                                 "(objectClass=*)");
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);


      // Ensure that with automatic referral following still enabled the search
      // above the referral no longer returns a search result reference.
      searchResult = conn.search(getTestBaseDN(), SearchScope.SUB,
                                 "(objectClass=*)");
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getReferenceCount(), 0);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to perform a compare against the target entry.
      conn.getConnectionOptions().setFollowReferrals(false);
      assertFalse(conn.getConnectionOptions().followReferrals());
      try
      {
        conn.compare(userEntry.getDN(), "description", "foo");
        fail("Expected an exception when trying to compare below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(), expectedDN);
      }


      // Enable automatic referral following and ensure that the compare is
      // successful.
      conn.getConnectionOptions().setFollowReferrals(true);
      assertTrue(conn.getConnectionOptions().followReferrals());
      result = conn.compare(userEntry.getDN(), "description", "foo");
      assertEquals(result.getResultCode(), ResultCode.COMPARE_TRUE);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to rename the target entry.
      conn.getConnectionOptions().setFollowReferrals(false);
      assertFalse(conn.getConnectionOptions().followReferrals());
      try
      {
        conn.modifyDN(userEntry.getDN(), "cn=Test User", false);
        fail("Expected an exception when trying to modify below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(), expectedDN);
      }


      // Enable automatic referral following and ensure that the modify DN is
      // successful.
      conn.getConnectionOptions().setFollowReferrals(true);
      assertTrue(conn.getConnectionOptions().followReferrals());
      result = conn.modifyDN(userEntry.getDN(), "cn=Test User", false);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to delete the target entry.
      conn.getConnectionOptions().setFollowReferrals(false);
      assertFalse(conn.getConnectionOptions().followReferrals());
      try
      {
        conn.delete("cn=Test User,ou=Users," + getTestBaseDN());
        fail("Expected an exception when trying to delete below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(),
                     new DN("cn=Test User,ou=People," + getTestBaseDN()));
      }


      // Enable automatic referral following and ensure that the delete is
      // successful.
      conn.getConnectionOptions().setFollowReferrals(true);
      assertTrue(conn.getConnectionOptions().followReferrals());
      result = conn.delete("cn=Test User,ou=Users," + getTestBaseDN());
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to delete the referral entry.
      conn.getConnectionOptions().setFollowReferrals(false);
      assertFalse(conn.getConnectionOptions().followReferrals());
      try
      {
        conn.delete("ou=Users," + getTestBaseDN());
        fail("Expected an exception when trying to delete a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(),
                     new DN("ou=People," + getTestBaseDN()));
      }


      // Leave automatic referral following disabled and ensure that the delete
      // is successful when the ManageDsaIT control is included in the request.
      DeleteRequest deleteRequest =
           new DeleteRequest("ou=Users," + getTestBaseDN());
      deleteRequest.addControl(new ManageDsaITRequestControl());
      result = conn.delete(deleteRequest);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    }
    finally
    {
      DeleteRequest deleteRequest = new DeleteRequest(getTestBaseDN());
      deleteRequest.addControls(new SubtreeDeleteRequestControl(),
                                new ManageDsaITRequestControl());
      conn.delete(deleteRequest);

      conn.close();
    }
  }



  /**
   * Tests the behavior of the SDK when there is a single referral, controlling
   * following via the LDAP request and not the connection options.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleHopViaRequest()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }


    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());

    conn.add("dn: ou=People," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: People");

    conn.add("dn: ou=Users," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: referral",
             "objectClass: extensibleObject",
             "ou: Users",
             "ref: ldap://" + getTestHost() + ':' + getTestPort() + '/' +
                  "ou=People," + getTestBaseDN());

    Entry userEntry = new Entry(
         "dn: uid=test.user,ou=Users," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password");

    DN expectedDN = new DN("uid=test.user,ou=People," + getTestBaseDN());

    try
    {
      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to add an entry below the referral.
      assertFalse(conn.getConnectionOptions().followReferrals());
      AddRequest addRequest = new AddRequest(userEntry);
      assertFalse(addRequest.followReferrals(conn));
      try
      {
        conn.add(addRequest);
        fail("Expected an exception when trying to add below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(), expectedDN);
      }


      // Enable automatic referral following and ensure that the add is
      // successful.
      addRequest.setFollowReferrals(true);
      assertTrue(addRequest.followReferrals(conn));
      LDAPResult result = conn.add(addRequest);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to modify the target entry.
      ModifyRequest modifyRequest = new ModifyRequest(
           "dn: " + userEntry.getDN(),
           "changetype: modify",
           "replace: description",
           "description: foo");
      assertFalse(modifyRequest.followReferrals(conn));
      try
      {
        conn.modify(modifyRequest);
        fail("Expected an exception when trying to modify below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(), expectedDN);
      }


      // Enable automatic referral following and ensure that the modify is
      // successful.
      modifyRequest.setFollowReferrals(true);
      assertTrue(modifyRequest.followReferrals(conn));
      result = conn.modify(modifyRequest);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to perform searches with a base DN at and below
      // the referral.
      SearchRequest subtreeSearch =
           new SearchRequest(userEntry.getParentDNString(), SearchScope.SUB,
                             "(objectClass=*)");
      assertFalse(subtreeSearch.followReferrals(conn));
      try
      {
        conn.search(subtreeSearch);
        fail("Expected an exception when trying to search at a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(), expectedDN.getParent());
        assertEquals(referralURL.getScope(), SearchScope.SUB);
      }

      SearchRequest baseSearch = new SearchRequest(userEntry.getDN(),
           SearchScope.BASE, "(objectClass=*)");
      assertFalse(baseSearch.followReferrals(conn));
      try
      {
        conn.search(baseSearch);
        fail("Expected an exception when trying to search below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(), expectedDN);
        assertEquals(referralURL.getScope(), SearchScope.BASE);
      }


      // Ensure that with automatic referral following still disabled, a search
      // with a base DN that is above the referral won't throw an exception but
      // will return a search result reference.
      SearchRequest topLevelSearch = new SearchRequest(getTestBaseDN(),
           SearchScope.SUB, "(objectClass=*)");
      assertFalse(topLevelSearch.followReferrals(conn));
      SearchResult searchResult = conn.search(topLevelSearch);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getReferenceCount(), 1);


      // Enable automatic referral following and ensure that the searches are
      // successful.
      subtreeSearch.setFollowReferrals(true);
      assertTrue(subtreeSearch.followReferrals(conn));
      searchResult = conn.search(subtreeSearch);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 2);

      baseSearch.setFollowReferrals(true);
      assertTrue(baseSearch.followReferrals(conn));
      searchResult = conn.search(baseSearch);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);


      // Ensure that with automatic referral following still enabled the search
      // above the referral no longer returns a search result reference.
      topLevelSearch.setFollowReferrals(true);
      assertTrue(topLevelSearch.followReferrals(conn));
      searchResult = conn.search(topLevelSearch);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getReferenceCount(), 0);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to perform a compare against the target entry.
      CompareRequest compareRequest = new CompareRequest(userEntry.getDN(),
           "description", "foo");
      assertFalse(compareRequest.followReferrals(conn));
      try
      {
        conn.compare(compareRequest);
        fail("Expected an exception when trying to compare below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(), expectedDN);
      }


      // Enable automatic referral following and ensure that the compare is
      // successful.
      compareRequest.setFollowReferrals(true);
      assertTrue(compareRequest.followReferrals(conn));
      result = conn.compare(compareRequest);
      assertEquals(result.getResultCode(), ResultCode.COMPARE_TRUE);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to rename the target entry.
      ModifyDNRequest modDNRequest = new ModifyDNRequest(userEntry.getDN(),
           "cn=Test User", false);
      assertFalse(modDNRequest.followReferrals(conn));
      try
      {
        conn.modifyDN(modDNRequest);
        fail("Expected an exception when trying to modify below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(), expectedDN);
      }


      // Enable automatic referral following and ensure that the modify DN is
      // successful.
      modDNRequest.setFollowReferrals(true);
      assertTrue(modDNRequest.followReferrals(conn));
      result = conn.modifyDN(modDNRequest);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to delete the target entry.
      DeleteRequest deleteRequest =
           new DeleteRequest("cn=Test User,ou=Users," + getTestBaseDN());
      assertFalse(deleteRequest.followReferrals(conn));
      try
      {
        conn.delete(deleteRequest);
        fail("Expected an exception when trying to delete below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(),
                     new DN("cn=Test User,ou=People," + getTestBaseDN()));
      }


      // Enable automatic referral following and ensure that the delete is
      // successful.
      deleteRequest.setFollowReferrals(true);
      assertTrue(deleteRequest.followReferrals(conn));
      result = conn.delete(deleteRequest);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to delete the referral entry.
      deleteRequest = new DeleteRequest("ou=Users," + getTestBaseDN());
      assertFalse(deleteRequest.followReferrals(conn));
      try
      {
        conn.delete(deleteRequest);
        fail("Expected an exception when trying to delete a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(),
                     new DN("ou=People," + getTestBaseDN()));
      }


      // Leave automatic referral following disabled and ensure that the delete
      // is successful when the ManageDsaIT control is included in the request.
      deleteRequest.addControl(new ManageDsaITRequestControl());
      result = conn.delete(deleteRequest);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    }
    finally
    {
      DeleteRequest deleteRequest = new DeleteRequest(getTestBaseDN());
      deleteRequest.addControls(new SubtreeDeleteRequestControl(),
                                new ManageDsaITRequestControl());
      conn.delete(deleteRequest);

      conn.close();
    }
  }



  /**
   * Tests the behavior of the SDK when it is necessary to follow multiple
   * referral hops.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleHops()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }


    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());

    conn.add("dn: ou=People," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: People");

    conn.add("dn: ou=Persons," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: referral",
             "objectClass: extensibleObject",
             "ou: Persons",
             "ref: ldap://" + getTestHost() + ':' + getTestPort() + '/' +
                  "ou=People," + getTestBaseDN());

    conn.add("dn: ou=Users," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: referral",
             "objectClass: extensibleObject",
             "ou: Users",
             "ref: ldap://" + getTestHost() + ':' + getTestPort() + '/' +
                  "ou=Persons," + getTestBaseDN());

    Entry userEntry = new Entry(
         "dn: uid=test.user,ou=Users," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password");

    DN expectedDN = new DN("uid=test.user,ou=Persons," + getTestBaseDN());

    try
    {
      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to add an entry below the referral.
      assertFalse(conn.getConnectionOptions().followReferrals());
      try
      {
        conn.add(userEntry);
        fail("Expected an exception when trying to add below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(), expectedDN);
      }


      // Enable automatic referral following and ensure that the add is
      // successful.
      conn.getConnectionOptions().setFollowReferrals(true);
      assertTrue(conn.getConnectionOptions().followReferrals());
      LDAPResult result = conn.add(userEntry);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to modify the target entry.
      conn.getConnectionOptions().setFollowReferrals(false);
      assertFalse(conn.getConnectionOptions().followReferrals());
      try
      {
        conn.modify("dn: " + userEntry.getDN(),
                    "changetype: modify",
                    "replace: description",
                    "description: foo");
        fail("Expected an exception when trying to modify below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(), expectedDN);
      }


      // Enable automatic referral following and ensure that the modify is
      // successful.
      conn.getConnectionOptions().setFollowReferrals(true);
      assertTrue(conn.getConnectionOptions().followReferrals());
      result = conn.modify("dn: " + userEntry.getDN(),
                           "changetype: modify",
                           "replace: description",
                           "description: foo");
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to perform searches with a base DN at and below
      // the referral.
      conn.getConnectionOptions().setFollowReferrals(false);
      assertFalse(conn.getConnectionOptions().followReferrals());
      try
      {
        conn.search(userEntry.getParentDNString(), SearchScope.SUB,
                    "(objectClass=*)");
        fail("Expected an exception when trying to search at a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(), expectedDN.getParent());
        assertEquals(referralURL.getScope(), SearchScope.SUB);
      }

      try
      {
        conn.search(userEntry.getDN(), SearchScope.BASE,
                    "(objectClass=*)");
        fail("Expected an exception when trying to search below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(), expectedDN);
        assertEquals(referralURL.getScope(), SearchScope.BASE);
      }


      // Ensure that with automatic referral following still disabled, a search
      // with a base DN that is above the referral won't throw an exception but
      // will return a search result reference.
      SearchResult searchResult = conn.search(getTestBaseDN(), SearchScope.SUB,
                                              "(objectClass=*)");
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getReferenceCount(), 2);


      // Enable automatic referral following and ensure that the searches are
      // successful.
      conn.getConnectionOptions().setFollowReferrals(true);
      assertTrue(conn.getConnectionOptions().followReferrals());
      searchResult = conn.search(userEntry.getParentDNString(),
                                 SearchScope.SUB, "(objectClass=*)");
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 2);

      searchResult = conn.search(userEntry.getDN(), SearchScope.BASE,
                                 "(objectClass=*)");
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);


      // Ensure that with automatic referral following still enabled the search
      // above the referral no longer returns a search result reference.
      searchResult = conn.search(getTestBaseDN(), SearchScope.SUB,
                                 "(objectClass=*)");
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getReferenceCount(), 0);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to perform a compare against the target entry.
      conn.getConnectionOptions().setFollowReferrals(false);
      assertFalse(conn.getConnectionOptions().followReferrals());
      try
      {
        conn.compare(userEntry.getDN(), "description", "foo");
        fail("Expected an exception when trying to compare below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(), expectedDN);
      }


      // Enable automatic referral following and ensure that the compare is
      // successful.
      conn.getConnectionOptions().setFollowReferrals(true);
      assertTrue(conn.getConnectionOptions().followReferrals());
      result = conn.compare(userEntry.getDN(), "description", "foo");
      assertEquals(result.getResultCode(), ResultCode.COMPARE_TRUE);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to rename the target entry.
      conn.getConnectionOptions().setFollowReferrals(false);
      assertFalse(conn.getConnectionOptions().followReferrals());
      try
      {
        conn.modifyDN(userEntry.getDN(), "cn=Test User", false);
        fail("Expected an exception when trying to modify below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(), expectedDN);
      }


      // Enable automatic referral following and ensure that the modify DN is
      // successful.
      conn.getConnectionOptions().setFollowReferrals(true);
      assertTrue(conn.getConnectionOptions().followReferrals());
      result = conn.modifyDN(userEntry.getDN(), "cn=Test User", false);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to delete the target entry.
      conn.getConnectionOptions().setFollowReferrals(false);
      assertFalse(conn.getConnectionOptions().followReferrals());
      try
      {
        conn.delete("cn=Test User,ou=Users," + getTestBaseDN());
        fail("Expected an exception when trying to delete below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(),
                     new DN("cn=Test User,ou=Persons," + getTestBaseDN()));
      }


      // Enable automatic referral following and ensure that the delete is
      // successful.
      conn.getConnectionOptions().setFollowReferrals(true);
      assertTrue(conn.getConnectionOptions().followReferrals());
      result = conn.delete("cn=Test User,ou=Users," + getTestBaseDN());
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to delete the referral entry.
      conn.getConnectionOptions().setFollowReferrals(false);
      assertFalse(conn.getConnectionOptions().followReferrals());
      try
      {
        conn.delete("ou=Users," + getTestBaseDN());
        fail("Expected an exception when trying to delete a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldap");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestPort());
        assertEquals(referralURL.getBaseDN(),
                     new DN("ou=Persons," + getTestBaseDN()));
      }


      // Leave automatic referral following disabled and ensure that the delete
      // is successful when the ManageDsaIT control is included in the request.
      DeleteRequest deleteRequest =
           new DeleteRequest("ou=Users," + getTestBaseDN());
      deleteRequest.addControl(new ManageDsaITRequestControl());
      result = conn.delete(deleteRequest);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    }
    finally
    {
      DeleteRequest deleteRequest = new DeleteRequest(getTestBaseDN());
      deleteRequest.addControls(new SubtreeDeleteRequestControl(),
                                new ManageDsaITRequestControl());
      conn.delete(deleteRequest);

      conn.close();
    }
  }



  /**
   * Tests the behavior of the SDK when referrals are encountered and there is
   * a circular reference.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReferralCircularReference()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }


    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());

    conn.add("dn: ou=People," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: referral",
             "objectClass: extensibleObject",
             "ou: People",
             "ref: ldap://" + getTestHost() + ':' + getTestPort() + '/' +
                  "ou=Users," + getTestBaseDN());

    conn.add("dn: ou=Persons," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: referral",
             "objectClass: extensibleObject",
             "ou: Persons",
             "ref: ldap://" + getTestHost() + ':' + getTestPort() + '/' +
                  "ou=People," + getTestBaseDN());

    conn.add("dn: ou=Users," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: referral",
             "objectClass: extensibleObject",
             "ou: Users",
             "ref: ldap://" + getTestHost() + ':' + getTestPort() + '/' +
                  "ou=Persons," + getTestBaseDN());

    conn.getConnectionOptions().setFollowReferrals(true);
    conn.getConnectionOptions().setReferralHopLimit(3);

    try
    {
      // Ensure that we get an exception when trying to add an entry below
      // a referral.
      try
      {
        conn.add("dn: uid=test.user,ou=Users," + getTestBaseDN(),
                 "objectClass: top",
                 "objectClass: person",
                 "objectClass: organizationalPerson",
                 "objectClass: inetOrgPerson",
                 "uid: test.user",
                 "givenName: Test",
                 "sn: User",
                 "cn: Test User",
                 "userPassword: password");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL_LIMIT_EXCEEDED);
      }


      // Ensure that we get an exception when trying to modify the referral
      // entry.
      try
      {
        conn.modify("dn: ou=Users," + getTestBaseDN(),
                    "changetype: modify",
                    "replace: description",
                    "description: foo");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL_LIMIT_EXCEEDED);
      }


      // Ensure that we get an exception when trying to perform a search with
      // a base DN equal to the referral entry.
      try
      {
        conn.search("ou=Users," + getTestBaseDN(), SearchScope.BASE,
                    "(objectClass=*)");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL_LIMIT_EXCEEDED);
      }


      // Ensure that we get an exception when trying to perform a search with a
      // base DN that is above the referral entry as a result of an intermediate
      // failure when trying to resolve a search result reference.
      try
      {
        conn.search(getTestBaseDN(), SearchScope.SUB, "(objectClass=*)");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL_LIMIT_EXCEEDED);
      }


      // Ensure that we get an exception when trying to compare the referral
      // entry.
      try
      {
        conn.compare("ou=Users," + getTestBaseDN(), "ou", "users");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL_LIMIT_EXCEEDED);
      }


      // Ensure that we get an exception when trying to rename the referral
      // entry.
      try
      {
        conn.modifyDN("ou=Users," + getTestBaseDN(), "ou=New RDN", true);
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL_LIMIT_EXCEEDED);
      }


      // Ensure that we get an exception when trying to delete the referral
      // entry.
      try
      {
        conn.delete("ou=Users," + getTestBaseDN());
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL_LIMIT_EXCEEDED);
      }
    }
    finally
    {
      DeleteRequest deleteRequest = new DeleteRequest(getTestBaseDN());
      deleteRequest.addControl(new SubtreeDeleteRequestControl());
      deleteRequest.addControl(new ManageDsaITRequestControl());
      conn.delete(deleteRequest);

      conn.close();
    }
  }



  /**
   * Tests the behavior of the SDK when there is a single referral, controlling
   * following via connection options, and using SSL to secure communication
   * with the server.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleHopViaConnectionOptionsWithSSL()
         throws Exception
  {
    if (! isSSLEnabledDirectoryInstanceAvailable())
    {
      return;
    }


    final SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
    final LDAPConnection conn = new LDAPConnection(
         sslUtil.createSSLSocketFactory(), getTestHost(), getTestSSLPort(),
         getTestBindDN(), getTestBindPassword());

    conn.add(getTestBaseDN(), getBaseEntryAttributes());

    conn.add("dn: ou=People," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: People");

    conn.add("dn: ou=Users," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: referral",
             "objectClass: extensibleObject",
             "ou: Users",
             "ref: ldaps://" + getTestHost() + ':' + getTestSSLPort() + '/' +
                  "ou=People," + getTestBaseDN());

    Entry userEntry = new Entry(
         "dn: uid=test.user,ou=Users," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password");

    DN expectedDN = new DN("uid=test.user,ou=People," + getTestBaseDN());

    try
    {
      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to add an entry below the referral.
      assertFalse(conn.getConnectionOptions().followReferrals());
      try
      {
        conn.add(userEntry);
        fail("Expected an exception when trying to add below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldaps");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestSSLPort());
        assertEquals(referralURL.getBaseDN(), expectedDN);
      }


      // Enable automatic referral following and ensure that the add is
      // successful.
      conn.getConnectionOptions().setFollowReferrals(true);
      assertTrue(conn.getConnectionOptions().followReferrals());
      LDAPResult result = conn.add(userEntry);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to modify the target entry.
      conn.getConnectionOptions().setFollowReferrals(false);
      assertFalse(conn.getConnectionOptions().followReferrals());
      try
      {
        conn.modify("dn: " + userEntry.getDN(),
                    "changetype: modify",
                    "replace: description",
                    "description: foo");
        fail("Expected an exception when trying to modify below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldaps");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestSSLPort());
        assertEquals(referralURL.getBaseDN(), expectedDN);
      }


      // Enable automatic referral following and ensure that the modify is
      // successful.
      conn.getConnectionOptions().setFollowReferrals(true);
      assertTrue(conn.getConnectionOptions().followReferrals());
      result = conn.modify("dn: " + userEntry.getDN(),
                           "changetype: modify",
                           "replace: description",
                           "description: foo");
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to perform searches with a base DN at and below
      // the referral.
      conn.getConnectionOptions().setFollowReferrals(false);
      assertFalse(conn.getConnectionOptions().followReferrals());
      try
      {
        conn.search(userEntry.getParentDNString(), SearchScope.SUB,
                    "(objectClass=*)");
        fail("Expected an exception when trying to search at a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldaps");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestSSLPort());
        assertEquals(referralURL.getBaseDN(), expectedDN.getParent());
        assertEquals(referralURL.getScope(), SearchScope.SUB);
      }

      try
      {
        conn.search(userEntry.getDN(), SearchScope.BASE, "(objectClass=*)");
        fail("Expected an exception when trying to search below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldaps");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestSSLPort());
        assertEquals(referralURL.getBaseDN(), expectedDN);
        assertEquals(referralURL.getScope(), SearchScope.BASE);
      }


      // Ensure that with automatic referral following still disabled, a search
      // with a base DN that is above the referral won't throw an exception but
      // will return a search result reference.
      SearchResult searchResult = conn.search(getTestBaseDN(), SearchScope.SUB,
                                              "(objectClass=*)");
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getReferenceCount(), 1);


      // Enable automatic referral following and ensure that the searches are
      // successful.
      conn.getConnectionOptions().setFollowReferrals(true);
      assertTrue(conn.getConnectionOptions().followReferrals());
      searchResult = conn.search(userEntry.getParentDNString(), SearchScope.SUB,
                                 "(objectClass=*)");
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 2);

      searchResult = conn.search(userEntry.getDN(), SearchScope.BASE,
                                 "(objectClass=*)");
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);


      // Ensure that with automatic referral following still enabled the search
      // above the referral no longer returns a search result reference.
      searchResult = conn.search(getTestBaseDN(), SearchScope.SUB,
                                 "(objectClass=*)");
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getReferenceCount(), 0);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to perform a compare against the target entry.
      conn.getConnectionOptions().setFollowReferrals(false);
      assertFalse(conn.getConnectionOptions().followReferrals());
      try
      {
        conn.compare(userEntry.getDN(), "description", "foo");
        fail("Expected an exception when trying to compare below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldaps");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestSSLPort());
        assertEquals(referralURL.getBaseDN(), expectedDN);
      }


      // Enable automatic referral following and ensure that the compare is
      // successful.
      conn.getConnectionOptions().setFollowReferrals(true);
      assertTrue(conn.getConnectionOptions().followReferrals());
      result = conn.compare(userEntry.getDN(), "description", "foo");
      assertEquals(result.getResultCode(), ResultCode.COMPARE_TRUE);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to rename the target entry.
      conn.getConnectionOptions().setFollowReferrals(false);
      assertFalse(conn.getConnectionOptions().followReferrals());
      try
      {
        conn.modifyDN(userEntry.getDN(), "cn=Test User", false);
        fail("Expected an exception when trying to modify below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldaps");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestSSLPort());
        assertEquals(referralURL.getBaseDN(), expectedDN);
      }


      // Enable automatic referral following and ensure that the modify DN is
      // successful.
      conn.getConnectionOptions().setFollowReferrals(true);
      assertTrue(conn.getConnectionOptions().followReferrals());
      result = conn.modifyDN(userEntry.getDN(), "cn=Test User", false);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to delete the target entry.
      conn.getConnectionOptions().setFollowReferrals(false);
      assertFalse(conn.getConnectionOptions().followReferrals());
      try
      {
        conn.delete("cn=Test User,ou=Users," + getTestBaseDN());
        fail("Expected an exception when trying to delete below a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldaps");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestSSLPort());
        assertEquals(referralURL.getBaseDN(),
                     new DN("cn=Test User,ou=People," + getTestBaseDN()));
      }


      // Enable automatic referral following and ensure that the delete is
      // successful.
      conn.getConnectionOptions().setFollowReferrals(true);
      assertTrue(conn.getConnectionOptions().followReferrals());
      result = conn.delete("cn=Test User,ou=Users," + getTestBaseDN());
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      // Ensure that with automatic referral following disabled, we get an
      // exception when trying to delete the referral entry.
      conn.getConnectionOptions().setFollowReferrals(false);
      assertFalse(conn.getConnectionOptions().followReferrals());
      try
      {
        conn.delete("ou=Users," + getTestBaseDN());
        fail("Expected an exception when trying to delete a referral");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertEquals(le.getReferralURLs().length, 1);

        LDAPURL referralURL = new LDAPURL(le.getReferralURLs()[0]);
        assertEquals(referralURL.getScheme(), "ldaps");
        assertEquals(referralURL.getHost(), getTestHost());
        assertEquals(referralURL.getPort(), getTestSSLPort());
        assertEquals(referralURL.getBaseDN(),
                     new DN("ou=People," + getTestBaseDN()));
      }


      // Leave automatic referral following disabled and ensure that the delete
      // is successful when the ManageDsaIT control is included in the request.
      DeleteRequest deleteRequest =
           new DeleteRequest("ou=Users," + getTestBaseDN());
      deleteRequest.addControl(new ManageDsaITRequestControl());
      result = conn.delete(deleteRequest);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    }
    finally
    {
      DeleteRequest deleteRequest = new DeleteRequest(getTestBaseDN());
      deleteRequest.addControls(new SubtreeDeleteRequestControl(),
                                new ManageDsaITRequestControl());
      conn.delete(deleteRequest);

      conn.close();
    }
  }



  /**
   * Tests to ensure that the LDAP SDK returns an appropriate result code for
   * the case in which it is configured to automatically follow referrals and
   * it encounters referrals that it cannot follow.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchResultCodeWithUnfollowableSearchResultReference()
         throws Exception
  {
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setFollowReferrals(true);

    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
    ds.startListening();

    try (LDAPConnection conn = ds.getConnection(connectionOptions))
    {
      conn.add(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");

      conn.add(
           "dn: ou=BadRef,dc=example,dc=com",
           "objectClass: top",
           "objectClass: referral",
           "objectClass: extensibleObject",
           "ou: BadRef",
           "ref: The LDAP SDK cannot automatically follow this referral");

      // Test the behavior for a base-level search at the naming context.  The
      // search should succeed with one entry returned (the base entry) and no
      // references.
      SearchResult searchResult = (SearchResult) assertResultCodeEquals(conn,
           new SearchRequest("dc=example,dc=com", SearchScope.BASE,
                Filter.createPresenceFilter("objectClass")),
           ResultCode.SUCCESS);
      assertEntriesReturnedEquals(searchResult, 1);
      assertReferencesReturnedEquals(searchResult, 0);


      // Test the behavior for a subtree search at the naming context.  The
      // search should succeed with one entry (the base entry) and one reference
      // (the bad referral) returned.
      searchResult = (SearchResult) assertResultCodeEquals(conn,
           new SearchRequest("dc=example,dc=com", SearchScope.SUB,
                Filter.createPresenceFilter("objectClass")),
           ResultCode.SUCCESS);
      assertEntriesReturnedEquals(searchResult, 1);
      assertReferencesReturnedEquals(searchResult, 1);


      // Test the behavior for a base-level search at the bad referral entry.
      // The search should fail with a "referral" result code with no entries or
      // references returned.
      searchResult = (SearchResult) assertResultCodeEquals(conn,
           new SearchRequest("ou=BadRef,dc=example,dc=com",
                SearchScope.BASE, Filter.createPresenceFilter("objectClass")),
           ResultCode.REFERRAL);
      assertEntriesReturnedEquals(searchResult, 0);
      assertReferencesReturnedEquals(searchResult, 0);
    }
    finally
    {
      ds.shutDown(true);
    }
  }
}
