/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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

import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.controls.SubtreeDeleteRequestControl;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the LDAPEntrySource class.
 */
public class LDAPEntrySourceTestCase
       extends LDAPSDKTestCase
{
  /**
   * Creates a set of test entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void createTestEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection connection = getAdminConnection();

    LDAPResult r = connection.add(getTestBaseDN(), getBaseEntryAttributes());
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    r = connection.add(
         "dn: ou=People," + getTestBaseDN(),
         "objectClass: top",
         "objectclass: organizationalUnit",
         "ou: People");
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    for (int i=0; i < 250; i++)
    {
      r = connection.add(
           "dn: uid=user." + i + ",ou=People," + getTestBaseDN(),
           "objectClass: top",
           "objectclass: person",
           "objectclass: organizationalPerson",
           "objectclass: inetOrgPerson",
           "uid: user." + i,
           "givenName: User",
           "sn: " + i,
           "cn: User " + i,
           "userPassword: password");
      assertEquals(r.getResultCode(), ResultCode.SUCCESS);
    }

    connection.close();
  }



  /**
   * Deletes the test entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void deleteTestEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection connection = getAdminConnection();

    DeleteRequest deleteRequest = new DeleteRequest(getTestBaseDN());
    deleteRequest.addControl(new SubtreeDeleteRequestControl(true));

    assertEquals(connection.delete(deleteRequest).getResultCode(),
                 ResultCode.SUCCESS);

    connection.close();
  }



  /**
   * Performs a test with a search request that matches all of the entries and
   * reads through all of them.  The connection will not be closed.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(invocationCount=10)
  public void testAllEntriesNoCloseNoDisconnect()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    SearchRequest r = new SearchRequest(getTestBaseDN(), SearchScope.SUB,
         "(objectClass=person)");
    LDAPEntrySource s = new LDAPEntrySource(conn, r, false);

    int count = 0;
    while (true)
    {
      Entry e = s.nextEntry();
      if (e == null)
      {
        break;
      }

      count++;
    }

    assertEquals(count, 250);

    assertNotNull(s.getSearchResult());

    for (int i=0; i < 10; i++)
    {
      assertNull(s.nextEntry());
    }

    assertNotNull(s.getSearchResult());

    s.close();
    for (int i=0; i < 10; i++)
    {
      assertNull(s.nextEntry());
    }

    assertNotNull(s.getSearchResult());

    conn.close();
  }



  /**
   * Performs a test with a search request that matches all of the entries and
   * reads through all of them.  The connection will be closed when the search
   * has completed.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllEntriesDisconnect()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    SearchRequest r = new SearchRequest(getTestBaseDN(), SearchScope.SUB,
         "(objectClass=person)");
    LDAPEntrySource s = new LDAPEntrySource(conn, r, true);

    int count = 0;
    while (true)
    {
      Entry e = s.nextEntry();
      if (e == null)
      {
        break;
      }

      count++;
    }

    assertEquals(count, 250);

    assertNotNull(s.getSearchResult());

    for (int i=0; i < 10; i++)
    {
      assertNull(s.nextEntry());
    }

    assertNotNull(s.getSearchResult());

    s.close();
    for (int i=0; i < 10; i++)
    {
      assertNull(s.nextEntry());
    }

    assertNotNull(s.getSearchResult());
  }



  /**
   * Performs a test with a search request that matches all of the entries but
   * in which only a subset of the entries will be read.  The connection will be
   * not closed when the search has completed.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllEntriesClose()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    SearchRequest r = new SearchRequest(getTestBaseDN(), SearchScope.SUB,
         "(objectClass=*)");
    LDAPEntrySource s = new LDAPEntrySource(conn, r, false);

    assertNotNull(s.nextEntry());
    s.close();

    conn.close();
  }



  /**
   * Performs a test with a search request that does not match any entries.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(invocationCount=10)
  public void testNoMatches()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    SearchRequest r = new SearchRequest(getTestBaseDN(), SearchScope.SUB,
         "(objectClass=groupOfNames)");
    LDAPEntrySource s = new LDAPEntrySource(conn, r, false);
    assertNull(s.nextEntry());

    assertNotNull(s.getSearchResult());

    for (int i=0; i < 10; i++)
    {
      assertNull(s.nextEntry());
    }

    assertNotNull(s.getSearchResult());

    s.close();
    for (int i=0; i < 10; i++)
    {
      assertNull(s.nextEntry());
    }

    assertNotNull(s.getSearchResult());

    conn.close();
  }



  /**
   * Performs a test with a search request that should throw an exception.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchThrowsException()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    SearchRequest r = new SearchRequest("cn=nonexistent," + getTestBaseDN(),
         SearchScope.SUB, "(objectClass=*)");
    LDAPEntrySource s = new LDAPEntrySource(conn, r, false);

    try
    {
      s.nextEntry();
      fail("Expected an exception with a nonexistent base DN.");
    }
    catch (EntrySourceException e)
    {
      // This is expected.
      assertFalse(e.mayContinueReading());
      assertTrue(e.getCause() instanceof LDAPException);
      assertEquals(((LDAPException) e.getCause()).getResultCode(),
                   ResultCode.NO_SUCH_OBJECT);
    }

    assertNotNull(s.getSearchResult());

    for (int i=0; i < 10; i++)
    {
      assertNull(s.nextEntry());
    }

    assertNotNull(s.getSearchResult());

    s.close();
    for (int i=0; i < 10; i++)
    {
      assertNull(s.nextEntry());
    }

    assertNotNull(s.getSearchResult());

    conn.close();
  }



  /**
   * Performs a test with a search request that should return a referral (which
   * will result in an exception).
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchWithReferral()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    conn.add(
         "dn: cn=ref," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "cn: ref",
         "ref: ldap://" + getTestBaseDN() + ':' + getTestPort() + "/o=test");

    SearchRequest r = new SearchRequest(getTestBaseDN(), SearchScope.SUB,
         "(objectClass=*)");
    LDAPEntrySource s = new LDAPEntrySource(conn, r, false);

    int referralCount = 0;
    while (true)
    {
      try
      {
        Entry e = s.nextEntry();
        if (e == null)
        {
          break;
        }
      }
      catch (SearchResultReferenceEntrySourceException e)
      {
        // This is expected for the referral.
        assertNotNull(e.getSearchReference());
        assertTrue(e.mayContinueReading());
        assertNotNull(e.getCause());
        assertTrue(e.getCause() instanceof LDAPException);

        LDAPException le = (LDAPException) e.getCause();
        assertEquals(le.getResultCode(), ResultCode.REFERRAL);
        assertNotNull(le.getReferralURLs());
        assertTrue(le.getReferralURLs().length > 0);

        assertNotNull(e.toString());

        referralCount++;
      }
    }

    assertEquals(referralCount, 1);

    DeleteRequest deleteRequest =
         new DeleteRequest("cn=ref," + getTestBaseDN());
    deleteRequest.addControl(new ManageDsaITRequestControl(true));
    assertEquals(conn.delete(deleteRequest).getResultCode(),
                 ResultCode.SUCCESS);

    s.close();
    for (int i=0; i < 10; i++)
    {
      assertNull(s.nextEntry());
    }

    conn.close();
  }



  /**
   * Ensures that using the LDAP entry source will fail with a search request
   * that contains a listener.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSearchWithListener()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPException(ResultCode.PARAM_ERROR);
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      SearchRequest r = new SearchRequest(new TestSearchResultListener(),
           getTestBaseDN(), SearchScope.SUB, "(objectClass=*)");
      LDAPEntrySource s = new LDAPEntrySource(conn, r, false);
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Ensures that using the LDAP entry source will fail with a {@code null}
   * connection.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNullConnection()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPSDKUsageException("No directory instance available");
    }

    SearchRequest r = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");
    LDAPEntrySource s = new LDAPEntrySource(null, r, false);
  }



  /**
   * Ensures that using the LDAP entry source will fail with a {@code null}
   * request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNullRequest()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPSDKUsageException("No directory instance available");
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      LDAPEntrySource s = new LDAPEntrySource(conn, null, false);
    }
    finally
    {
      conn.close();
    }
  }
}
