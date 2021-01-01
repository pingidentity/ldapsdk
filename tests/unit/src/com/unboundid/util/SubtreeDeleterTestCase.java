/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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
package com.unboundid.util;



import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerSnapshot;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.SingleServerSet;



/**
 * This class provides a set of test cases for the subtree deleter.
 */
public final class SubtreeDeleterTestCase
       extends LDAPSDKTestCase
{
  // A snapshot of an in-memory directory server populated with 1000 user
  // entries (plus two ancestors) in a flat DIT.
  private InMemoryDirectoryServerSnapshot flatDITSnapshot;

  // A snapshot of an in-memory directory server populated with 1365 entries in
  // a highly branched DIT.  It will have one entry at the top, with four
  // entries below it, four entries below each of those, etc. to six levels
  // deep.  This will end up with 4^5 + 4^4 + 4^3 + 4^2 + 4^1 + 4^0 entries,
  // which is 1024 + 256 + 64 + 16 + 4 + 1 = 1365.
  private InMemoryDirectoryServerSnapshot hierarchicalDITSnapshot;



  /**
   * Sets up a couple of data sets for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final InMemoryDirectoryServerSnapshot emptySnapshot = ds.createSnapshot();

    ds.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    for (int i=0; i < 1000; i++)
    {
      ds.add(
           "dn: uid=user." + i + ",ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: user." + i,
           "givenName: User",
           "sn: " + i,
           "cn: User " + i);
    }
    flatDITSnapshot = ds.createSnapshot();

    ds.restoreSnapshot(emptySnapshot);
    for (int a=0; a < 4; a++)
    {
      ds.add(
           "dn: ou=" + a + ",dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: " + a);

      for (int b=0; b < 4; b++)
      {
        ds.add(
             "dn: ou=" + b + ",ou=" + a + ",dc=example,dc=com",
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: " + b);

        for (int c=0; c < 4; c++)
        {
          ds.add(
               "dn: ou=" + c + ",ou=" + b + ",ou=" + a + ",dc=example,dc=com",
               "objectClass: top",
               "objectClass: organizationalUnit",
               "ou: " + c);

          for (int d=0; d < 4; d++)
          {
            ds.add(
                 "dn: ou=" + d + ",ou=" + c + ",ou=" + b + ",ou=" + a +
                      ",dc=example,dc=com",
                 "objectClass: top",
                 "objectClass: organizationalUnit",
                 "ou: " + d);

            for (int e=0; e < 4; e++)
            {
              ds.add(
                   "dn: ou=" + e + ",ou=" + d + ",ou=" + c + ",ou=" + b +
                        ",ou=" + a + ",dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: " + 3);
            }
          }
        }
      }
    }
    hierarchicalDITSnapshot = ds.createSnapshot();
  }



  /**
   * Tests the behavior of all the subtree deleter's getters and setters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGettersAndSetters()
         throws Exception
  {
    // Test the default configuration.
    final SubtreeDeleter sd = new SubtreeDeleter();

    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());


    // Test the flag that indicates whether to delete the base entry.
    sd.setDeleteBaseEntry(false);
    assertFalse(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());

    sd.setDeleteBaseEntry(true);
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());


    // Test the flag that indicates whether to use the set subtree accessibility
    // extended operation, if it's available.
    sd.setUseSetSubtreeAccessibilityOperationIfAvailable(true);
    assertTrue(sd.deleteBaseEntry());
    assertTrue(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());

    sd.setUseSetSubtreeAccessibilityOperationIfAvailable(false);
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());


    // Test the flag that indicates whether to use the simple paged results
    // control, if it's available.
    sd.setUseSimplePagedResultsControlIfAvailable(false);
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertFalse(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());

    sd.setUseSimplePagedResultsControlIfAvailable(true);
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());


    // Test the ability to set the simple paged results control page size.
    sd.setSimplePagedResultsPageSize(12345);
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 12345);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());

    try
    {
      sd.setSimplePagedResultsPageSize(0);
      fail("Expected an exception when trying to set the simple paged " +
           "results page size to an invalid value.");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 12345);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());

    sd.setSimplePagedResultsPageSize(100);
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());


    // Test the flag that indicates whether to use the manage DSA IT request
    // control, if it's available.
    sd.setUseManageDSAITControlIfAvailable(false);
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertFalse(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());

    sd.setUseManageDSAITControlIfAvailable(true);
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());


    // Test the flag that indicates whether to use the permit unindexed search
    // request control, if it's available.
    sd.setUsePermitUnindexedSearchControlIfAvailable(true);
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertTrue(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());

    sd.setUsePermitUnindexedSearchControlIfAvailable(false);
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());


    // Test the flag that indicates whether to use the subentries request
    // control, if it's available.
    sd.setUseSubentriesControlIfAvailable(false);
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertFalse(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());

    sd.setUseSubentriesControlIfAvailable(true);
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());


    // Test the flag that indicates whether to use the return conflict entries
    // request control, if it's available.
    sd.setUseReturnConflictEntriesRequestControlIfAvailable(false);
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertFalse(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());

    sd.setUseReturnConflictEntriesRequestControlIfAvailable(true);
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());


    // Test the flag that indicates whether to use the soft-deleted entry access
    // request control, if it's available.
    sd.setUseSoftDeletedEntryAccessControlIfAvailable(false);
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertFalse(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());

    sd.setUseSoftDeletedEntryAccessControlIfAvailable(true);
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());


    // Test the flag that indicates whether to use the hard delete request
    // control, if it's available.
    sd.setUseHardDeleteControlIfAvailable(false);
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertFalse(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());

    sd.setUseHardDeleteControlIfAvailable(true);
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());


    // Test ability to set the additional search controls.
    sd.setAdditionalSearchControls(
         new Control("1.2.3.4"),
         new Control("1.2.3.5", true),
         new Control("1.2.3.6", true, new ASN1OctetString("foo")));
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertFalse(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());

    sd.setAdditionalSearchControls();
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());


    // Test ability to set the additional delete controls.
    sd.setAdditionalDeleteControls(
         new Control("1.2.3.4"),
         new Control("1.2.3.5", true),
         new Control("1.2.3.6", true, new ASN1OctetString("foo")));
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertFalse(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());

    sd.setAdditionalDeleteControls();
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());


    // Test ability to set the search request size limit.
    sd.setSearchRequestSizeLimit(12345);
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 12345);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());

    sd.setSearchRequestSizeLimit(-1234);
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());


    // Test ability to set the delete rate limiter.
    sd.setDeleteRateLimiter(new FixedRateBarrier(1000L, 100));
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNotNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());

    sd.setDeleteRateLimiter(null);
    assertTrue(sd.deleteBaseEntry());
    assertFalse(sd.useSetSubtreeAccessibilityOperationIfAvailable());
    assertTrue(sd.useSimplePagedResultsControlIfAvailable());
    assertEquals(sd.getSimplePagedResultsPageSize(), 100);
    assertTrue(sd.useManageDSAITControlIfAvailable());
    assertFalse(sd.usePermitUnindexedSearchControlIfAvailable());
    assertTrue(sd.useSubentriesControlIfAvailable());
    assertTrue(sd.useReturnConflictEntriesRequestControlIfAvailable());
    assertTrue(sd.useSoftDeletedEntryAccessControlIfAvailable());
    assertTrue(sd.useHardDeleteControlIfAvailable());
    assertNotNull(sd.getAdditionalSearchControls());
    assertTrue(sd.getAdditionalSearchControls().isEmpty());
    assertNotNull(sd.getAdditionalDeleteControls());
    assertTrue(sd.getAdditionalDeleteControls().isEmpty());
    assertEquals(sd.getSearchRequestSizeLimit(), 0);
    assertNull(sd.getDeleteRateLimiter());
    assertNotNull(sd.toString());
  }



  /**
   * Tests the behavior of the subtree deleter when run with the default
   * settings on a relatively flat DIT.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultSettingsFlatDIT()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    ds.restoreSnapshot(flatDITSnapshot);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryExists(connection, "dc=example,dc=com");

      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      final SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");

      assertNotNull(result);
      assertTrue(result.completelySuccessful(),
           result.toString());

      assertNull(result.getSetSubtreeAccessibilityError());
      assertFalse(result.subtreeInaccessible(),
           result.toString());

      assertNull(result.getSearchError(),
           result.toString());

      assertEquals(result.getEntriesDeleted(), 1002,
           result.toString());

      assertNotNull(result.getDeleteErrors());
      assertTrue(result.getDeleteErrors().isEmpty(),
           result.toString());

      assertEntryMissing(connection, "dc=example,dc=com");
    }
  }



  /**
   * Tests the behavior of the subtree deleter when run with the default
   * settings on a hierarchical DIT.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultSettingsHierarchicalDIT()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    ds.restoreSnapshot(hierarchicalDITSnapshot);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryExists(connection, "dc=example,dc=com");

      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      final SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");

      assertNotNull(result);
      assertTrue(result.completelySuccessful(),
           result.toString());

      assertNull(result.getSetSubtreeAccessibilityError());
      assertFalse(result.subtreeInaccessible(),
           result.toString());

      assertNull(result.getSearchError(),
           result.toString());

      assertEquals(result.getEntriesDeleted(), 1365,
           result.toString());

      assertNotNull(result.getDeleteErrors());
      assertTrue(result.getDeleteErrors().isEmpty(),
           result.toString());

      assertEntryMissing(connection, "dc=example,dc=com");
    }
  }



  /**
   * Tests the behavior of the subtree deleter when using a flat DIT and not
   * using the subtree simple paged results control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFlatDITWithoutSimplePagedResults()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    ds.restoreSnapshot(flatDITSnapshot);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryExists(connection, "dc=example,dc=com");

      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      subtreeDeleter.setUseSimplePagedResultsControlIfAvailable(false);

      final SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");

      assertNotNull(result);
      assertTrue(result.completelySuccessful(),
           result.toString());

      assertNull(result.getSetSubtreeAccessibilityError());
      assertFalse(result.subtreeInaccessible(),
           result.toString());

      assertNull(result.getSearchError(),
           result.toString());

      assertEquals(result.getEntriesDeleted(), 1002,
           result.toString());

      assertNotNull(result.getDeleteErrors());
      assertTrue(result.getDeleteErrors().isEmpty(),
           result.toString());

      assertEntryMissing(connection, "dc=example,dc=com");
    }
  }



  /**
   * Tests the behavior of the subtree deleter when using a hierarchical DIT and
   * not using the simple paged results control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHierarchicalDITWithoutSimplePagedResults()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    ds.restoreSnapshot(hierarchicalDITSnapshot);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryExists(connection, "dc=example,dc=com");

      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      subtreeDeleter.setUseSimplePagedResultsControlIfAvailable(false);

      final SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");

      assertNotNull(result);
      assertTrue(result.completelySuccessful(),
           result.toString());

      assertNull(result.getSetSubtreeAccessibilityError());
      assertFalse(result.subtreeInaccessible(),
           result.toString());

      assertNull(result.getSearchError(),
           result.toString());

      assertEquals(result.getEntriesDeleted(), 1365,
           result.toString());

      assertNotNull(result.getDeleteErrors());
      assertTrue(result.getDeleteErrors().isEmpty(),
           result.toString());

      assertEntryMissing(connection, "dc=example,dc=com");
    }
  }



  /**
   * Tests the behavior of the subtree deleter when not deleting the base entry
   * with a relatively flat DIT.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoNotDeleteBaseEntryFlatDIT()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    ds.restoreSnapshot(flatDITSnapshot);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryExists(connection, "dc=example,dc=com");
      assertEntryExists(connection, "ou=People,dc=example,dc=com");

      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      subtreeDeleter.setDeleteBaseEntry(false);

      final SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");

      assertNotNull(result);
      assertTrue(result.completelySuccessful(),
           result.toString());

      assertNull(result.getSetSubtreeAccessibilityError());
      assertFalse(result.subtreeInaccessible(),
           result.toString());

      assertNull(result.getSearchError(),
           result.toString());

      assertEquals(result.getEntriesDeleted(), 1001,
           result.toString());

      assertNotNull(result.getDeleteErrors());
      assertTrue(result.getDeleteErrors().isEmpty(),
           result.toString());

      assertEntryMissing(connection, "ou=People,dc=example,dc=com");
      assertEntryExists(connection, "dc=example,dc=com");
    }
  }



  /**
   * Tests the behavior of the subtree deleter when not deleting the base entry
   * on a hierarchical DIT.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoNotDeleteBaseEntryHierarchicalDIT()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    ds.restoreSnapshot(hierarchicalDITSnapshot);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryExists(connection, "dc=example,dc=com");
      assertEntryExists(connection, "ou=1,dc=example,dc=com");

      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      subtreeDeleter.setDeleteBaseEntry(false);

      final SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");

      assertNotNull(result);
      assertTrue(result.completelySuccessful(),
           result.toString());

      assertNull(result.getSetSubtreeAccessibilityError());
      assertFalse(result.subtreeInaccessible(),
           result.toString());

      assertNull(result.getSearchError(),
           result.toString());

      assertEquals(result.getEntriesDeleted(), 1364,
           result.toString());

      assertNotNull(result.getDeleteErrors());
      assertTrue(result.getDeleteErrors().isEmpty(),
           result.toString());

      assertEntryMissing(connection, "ou=1,dc=example,dc=com");
      assertEntryExists(connection, "dc=example,dc=com");
    }
  }



  /**
   * Tests the behavior of the subtree deleter when not deleting the base entry
   * and not using simple paged results with a relatively flat DIT.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoNotDeleteBaseEntryWithoutSimplePagedResultsFlatDIT()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    ds.restoreSnapshot(flatDITSnapshot);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryExists(connection, "dc=example,dc=com");
      assertEntryExists(connection, "ou=People,dc=example,dc=com");

      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      subtreeDeleter.setDeleteBaseEntry(false);
      subtreeDeleter.setUseSimplePagedResultsControlIfAvailable(false);

      final SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");

      assertNotNull(result);
      assertTrue(result.completelySuccessful(),
           result.toString());

      assertNull(result.getSetSubtreeAccessibilityError());
      assertFalse(result.subtreeInaccessible(),
           result.toString());

      assertNull(result.getSearchError(),
           result.toString());

      assertEquals(result.getEntriesDeleted(), 1001,
           result.toString());

      assertNotNull(result.getDeleteErrors());
      assertTrue(result.getDeleteErrors().isEmpty(),
           result.toString());

      assertEntryMissing(connection, "ou=People,dc=example,dc=com");
      assertEntryExists(connection, "dc=example,dc=com");
    }
  }



  /**
   * Tests the behavior of the subtree deleter when not deleting the base entry
   * and not using simple paged results with a hierarchical DIT.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoNotDeleteBaseEntryWithoutSimplePagedResultsHierarchicalDIT()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    ds.restoreSnapshot(hierarchicalDITSnapshot);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryExists(connection, "dc=example,dc=com");
      assertEntryExists(connection, "ou=1,dc=example,dc=com");

      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      subtreeDeleter.setDeleteBaseEntry(false);
      subtreeDeleter.setUseSimplePagedResultsControlIfAvailable(false);

      final SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");

      assertNotNull(result);
      assertTrue(result.completelySuccessful(),
           result.toString());

      assertNull(result.getSetSubtreeAccessibilityError());
      assertFalse(result.subtreeInaccessible(),
           result.toString());

      assertNull(result.getSearchError(),
           result.toString());

      assertEquals(result.getEntriesDeleted(), 1364,
           result.toString());

      assertNotNull(result.getDeleteErrors());
      assertTrue(result.getDeleteErrors().isEmpty(),
           result.toString());

      assertEntryMissing(connection, "ou=1,dc=example,dc=com");
      assertEntryExists(connection, "dc=example,dc=com");
    }
  }



  /**
   * Tests the behavior when trying to delete a subtree that contains subentries
   * when using the simple paged results control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithSubentriesWithPagedResults()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    ds.restoreSnapshot(flatDITSnapshot);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryExists(connection, "dc=example,dc=com");

      connection.add(
           "dn: ou=subentry 1,dc=example,dc=com",
           "objectClass: top",
           "objectClass: ldapSubentry",
           "objectClass: extensibleObject",
           "ou: subentry 1");
      connection.add(
           "dn: ou=subentry 2,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: ldapSubentry",
           "objectClass: extensibleObject",
           "ou: subentry 2");
      connection.add(
           "dn: ou=subentry 3,ou=subentry 2,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: ldapSubentry",
           "objectClass: extensibleObject",
           "ou: subentry 3");

      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      final SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");

      assertNotNull(result);
      assertTrue(result.completelySuccessful(),
           result.toString());

      assertNull(result.getSetSubtreeAccessibilityError());
      assertFalse(result.subtreeInaccessible(),
           result.toString());

      assertNull(result.getSearchError(),
           result.toString());

      assertEquals(result.getEntriesDeleted(), 1005,
           result.toString());

      assertNotNull(result.getDeleteErrors());
      assertTrue(result.getDeleteErrors().isEmpty(),
           result.toString());

      assertEntryMissing(connection, "dc=example,dc=com");
    }
  }



  /**
   * Tests the behavior when trying to delete a subtree that contains subentries
   * when using the simple paged results control and not using the LDAP
   * subentries request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithSubentriesWithoutSubentriesControlWithPagedResults()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    ds.restoreSnapshot(flatDITSnapshot);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryExists(connection, "dc=example,dc=com");

      connection.add(
           "dn: ou=subentry 1,dc=example,dc=com",
           "objectClass: top",
           "objectClass: ldapSubentry",
           "objectClass: extensibleObject",
           "ou: subentry 1");
      connection.add(
           "dn: ou=subentry 2,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: ldapSubentry",
           "objectClass: extensibleObject",
           "ou: subentry 2");
      connection.add(
           "dn: ou=subentry 3,ou=subentry 2,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: ldapSubentry",
           "objectClass: extensibleObject",
           "ou: subentry 3");

      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      subtreeDeleter.setUseSubentriesControlIfAvailable(false);

      final SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");

      assertNotNull(result);
      assertFalse(result.completelySuccessful(),
           result.toString());

      assertEquals(result.getEntriesDeleted(), 1000,
           result.toString());

      assertNotNull(result.getDeleteErrors());
      assertFalse(result.getDeleteErrors().isEmpty(),
           result.toString());

      assertEntryExists(connection, "dc=example,dc=com");
    }
  }



  /**
   * Tests the behavior when trying to delete a subtree that contains subentries
   * when not using the simple paged results control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithSubentriesWithoutPagedResults()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    ds.restoreSnapshot(flatDITSnapshot);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryExists(connection, "dc=example,dc=com");

      connection.add(
           "dn: ou=subentry 1,dc=example,dc=com",
           "objectClass: top",
           "objectClass: ldapSubentry",
           "objectClass: extensibleObject",
           "ou: subentry 1");
      connection.add(
           "dn: ou=subentry 2,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: ldapSubentry",
           "objectClass: extensibleObject",
           "ou: subentry 2");
      connection.add(
           "dn: ou=subentry 3,ou=subentry 2,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: ldapSubentry",
           "objectClass: extensibleObject",
           "ou: subentry 3");

      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      subtreeDeleter.setUseSimplePagedResultsControlIfAvailable(false);

      final SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");

      assertNotNull(result);
      assertTrue(result.completelySuccessful(),
           result.toString());

      assertNull(result.getSetSubtreeAccessibilityError());
      assertFalse(result.subtreeInaccessible(),
           result.toString());

      assertNull(result.getSearchError(),
           result.toString());

      assertEquals(result.getEntriesDeleted(), 1005,
           result.toString());

      assertNotNull(result.getDeleteErrors());
      assertTrue(result.getDeleteErrors().isEmpty(),
           result.toString());

      assertEntryMissing(connection, "dc=example,dc=com");
    }
  }



  /**
   * Tests the behavior when trying to delete a subtree that contains subentries
   * when not using the simple paged results control and when not using the LDAP
   * subentries request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithSubentriesWithoutPagedResultsOrSubentriesControl()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    ds.restoreSnapshot(flatDITSnapshot);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryExists(connection, "dc=example,dc=com");

      connection.add(
           "dn: ou=subentry 1,dc=example,dc=com",
           "objectClass: top",
           "objectClass: ldapSubentry",
           "objectClass: extensibleObject",
           "ou: subentry 1");
      connection.add(
           "dn: ou=subentry 2,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: ldapSubentry",
           "objectClass: extensibleObject",
           "ou: subentry 2");
      connection.add(
           "dn: ou=subentry 3,ou=subentry 2,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: ldapSubentry",
           "objectClass: extensibleObject",
           "ou: subentry 3");

      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      subtreeDeleter.setUseSimplePagedResultsControlIfAvailable(false);
      subtreeDeleter.setUseSubentriesControlIfAvailable(false);

      final SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");

      assertNotNull(result);
      assertFalse(result.completelySuccessful(),
           result.toString());

      assertNull(result.getSetSubtreeAccessibilityError());
      assertFalse(result.subtreeInaccessible(),
           result.toString());

      assertNull(result.getSearchError(),
           result.toString());

      assertEquals(result.getEntriesDeleted(), 1000,
           result.toString());

      assertNotNull(result.getDeleteErrors());
      assertFalse(result.getDeleteErrors().isEmpty(),
           result.toString());

      assertEntryExists(connection, "dc=example,dc=com");
    }
  }



  /**
   * Tests the behavior when using the subtree deleter when trying to delete
   * an entry without children.  Test with the simple paged results control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteEntryChildrenWithPagedResults()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, false);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryExists(connection, "dc=example,dc=com");

      // First, try without deleting the base entry itself.
      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      subtreeDeleter.setDeleteBaseEntry(false);

      SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");
      assertTrue(result.completelySuccessful());
      assertEquals(result.getEntriesDeleted(), 0);

      assertEntryExists(connection, "dc=example,dc=com");


      // Next, try with deleting the base entry.
      subtreeDeleter.setDeleteBaseEntry(true);

      result = subtreeDeleter.delete(connection, "dc=example,dc=com");
      assertTrue(result.completelySuccessful());
      assertEquals(result.getEntriesDeleted(), 1);

      assertEntryMissing(connection, "dc=example,dc=com");
    }
  }



  /**
   * Tests the behavior when using the subtree deleter when trying to delete
   * an entry without children.  Test without the simple paged results control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteEntryChildrenWithoutPagedResults()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, false);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryExists(connection, "dc=example,dc=com");

      // First, try without deleting the base entry itself.
      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      subtreeDeleter.setUseSimplePagedResultsControlIfAvailable(false);
      subtreeDeleter.setDeleteBaseEntry(false);

      SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");
      assertTrue(result.completelySuccessful());
      assertEquals(result.getEntriesDeleted(), 0);

      assertEntryExists(connection, "dc=example,dc=com");


      // Next, try with deleting the base entry.
      subtreeDeleter.setDeleteBaseEntry(true);

      result = subtreeDeleter.delete(connection, "dc=example,dc=com");
      assertTrue(result.completelySuccessful());
      assertEquals(result.getEntriesDeleted(), 1);

      assertEntryMissing(connection, "dc=example,dc=com");
    }
  }



  /**
   * Tests the behavior when using the subtree deleter when trying to delete
   * an entry that doesn't exist.  Test with the simple paged results control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteNonexistentEntryWithPagedResults()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryMissing(connection, "dc=example,dc=com");

      // First, try without deleting the base entry itself.
      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      subtreeDeleter.setDeleteBaseEntry(false);

      SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");
      assertTrue(result.completelySuccessful());
      assertEquals(result.getEntriesDeleted(), 0);


      // Next, try with deleting the base entry.
      subtreeDeleter.setDeleteBaseEntry(true);

      result = subtreeDeleter.delete(connection, "dc=example,dc=com");
      assertTrue(result.completelySuccessful());
      assertEquals(result.getEntriesDeleted(), 0);
    }
  }



  /**
   * Tests the behavior when using the subtree deleter when trying to delete
   * an entry that doesn't exist.  Test without the simple paged results
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteNonexistentEntryWithoutPagedResults()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryMissing(connection, "dc=example,dc=com");

      // First, try without deleting the base entry itself.
      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      subtreeDeleter.setUseSimplePagedResultsControlIfAvailable(false);
      subtreeDeleter.setDeleteBaseEntry(false);

      SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");
      assertTrue(result.completelySuccessful());
      assertEquals(result.getEntriesDeleted(), 0);


      // Next, try with deleting the base entry.
      subtreeDeleter.setDeleteBaseEntry(true);

      result = subtreeDeleter.delete(connection, "dc=example,dc=com");
      assertTrue(result.completelySuccessful());
      assertEquals(result.getEntriesDeleted(), 0);
    }
  }



  /**
   * Tests the behavior when trying to delete a subtree without the simple paged
   * results control when using a small size limit and a flat DIT.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFlatDITWithoutPagedResultsWithSmallSizeLimit()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    ds.restoreSnapshot(flatDITSnapshot);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryExists(connection, "dc=example,dc=com");

      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      subtreeDeleter.setUseSimplePagedResultsControlIfAvailable(false);
      subtreeDeleter.setSearchRequestSizeLimit(10);

      final SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");

      assertNotNull(result);
      assertTrue(result.completelySuccessful(),
           result.toString());

      assertNull(result.getSetSubtreeAccessibilityError());
      assertFalse(result.subtreeInaccessible(),
           result.toString());

      assertNull(result.getSearchError(),
           result.toString());

      assertEquals(result.getEntriesDeleted(), 1002,
           result.toString());

      assertNotNull(result.getDeleteErrors());
      assertTrue(result.getDeleteErrors().isEmpty(),
           result.toString());

      assertEntryMissing(connection, "dc=example,dc=com");
    }
  }



  /**
   * Tests the behavior when trying to delete a subtree without the simple paged
   * results control when using a small size limit and a hierarchical DIT.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHierarchicalDITWithoutPagedResultsWithSmallSizeLimit()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    ds.restoreSnapshot(hierarchicalDITSnapshot);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryExists(connection, "dc=example,dc=com");

      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      subtreeDeleter.setUseSimplePagedResultsControlIfAvailable(false);
      subtreeDeleter.setSearchRequestSizeLimit(10);

      final SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");

      assertNotNull(result);
      assertTrue(result.completelySuccessful(),
           result.toString());

      assertNull(result.getSetSubtreeAccessibilityError());
      assertFalse(result.subtreeInaccessible(),
           result.toString());

      assertNull(result.getSearchError(),
           result.toString());

      assertEquals(result.getEntriesDeleted(), 1365,
           result.toString());

      assertNotNull(result.getDeleteErrors());
      assertTrue(result.getDeleteErrors().isEmpty(),
           result.toString());

      assertEntryMissing(connection, "dc=example,dc=com");
    }
  }



  /**
   * Tests the behavior when a rate limiter is in place when using paged
   * results.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRateLimiterWithPagedResults()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    ds.restoreSnapshot(flatDITSnapshot);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryExists(connection, "dc=example,dc=com");

      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();

      // Use a rate limit of 10,000 deletes per second, which won't really slow
      // us down much, but still exercises the code.
      subtreeDeleter.setDeleteRateLimiter(new FixedRateBarrier(1000L, 10_000));

      final SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");

      assertNotNull(result);
      assertTrue(result.completelySuccessful(),
           result.toString());

      assertNull(result.getSetSubtreeAccessibilityError());
      assertFalse(result.subtreeInaccessible(),
           result.toString());

      assertNull(result.getSearchError(),
           result.toString());

      assertEquals(result.getEntriesDeleted(), 1002,
           result.toString());

      assertNotNull(result.getDeleteErrors());
      assertTrue(result.getDeleteErrors().isEmpty(),
           result.toString());

      assertEntryMissing(connection, "dc=example,dc=com");
    }
  }



  /**
   * Tests the behavior when a rate limiter is in place when not using paged
   * results.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRateLimiterWithoutPagedResults()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    ds.restoreSnapshot(flatDITSnapshot);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryExists(connection, "dc=example,dc=com");

      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      subtreeDeleter.setUseSimplePagedResultsControlIfAvailable(false);

      // Use a rate limit of 10,000 deletes per second, which won't really slow
      // us down much, but still exercises the code.
      subtreeDeleter.setDeleteRateLimiter(new FixedRateBarrier(1000L, 10_000));

      final SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");

      assertNotNull(result);
      assertTrue(result.completelySuccessful(),
           result.toString());

      assertNull(result.getSetSubtreeAccessibilityError());
      assertFalse(result.subtreeInaccessible(),
           result.toString());

      assertNull(result.getSearchError(),
           result.toString());

      assertEquals(result.getEntriesDeleted(), 1002,
           result.toString());

      assertNotNull(result.getDeleteErrors());
      assertTrue(result.getDeleteErrors().isEmpty(),
           result.toString());

      assertEntryMissing(connection, "dc=example,dc=com");
    }
  }



  /**
   * Tests the behavior of the subtree deleter when trying it is configured to
   * use a lot of features that aren't on by default and aren't supported by the
   * in-memory directory server.  Everything should still work, and some
   * additional code will get exercised.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithUnsupportedFeaturesUsingPagedResults()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    ds.restoreSnapshot(flatDITSnapshot);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryExists(connection, "dc=example,dc=com");

      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      subtreeDeleter.setUseSetSubtreeAccessibilityOperationIfAvailable(true);
      subtreeDeleter.setUsePermitUnindexedSearchControlIfAvailable(true);

      final SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");

      assertNotNull(result);
      assertTrue(result.completelySuccessful(),
           result.toString());

      assertNull(result.getSetSubtreeAccessibilityError());
      assertFalse(result.subtreeInaccessible(),
           result.toString());

      assertNull(result.getSearchError(),
           result.toString());

      assertEquals(result.getEntriesDeleted(), 1002,
           result.toString());

      assertNotNull(result.getDeleteErrors());
      assertTrue(result.getDeleteErrors().isEmpty(),
           result.toString());

      assertEntryMissing(connection, "dc=example,dc=com");
    }
  }



  /**
   * Tests the behavior of the subtree deleter when trying it is configured to
   * use a lot of features that aren't on by default and aren't supported by the
   * in-memory directory server.  Everything should still work, and some
   * additional code will get exercised.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithUnsupportedFeaturesUsingNotPagedResults()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    ds.restoreSnapshot(flatDITSnapshot);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertEntryExists(connection, "dc=example,dc=com");

      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      subtreeDeleter.setUseSimplePagedResultsControlIfAvailable(false);
      subtreeDeleter.setUseSetSubtreeAccessibilityOperationIfAvailable(true);
      subtreeDeleter.setUsePermitUnindexedSearchControlIfAvailable(true);

      final SubtreeDeleterResult result =
           subtreeDeleter.delete(connection, "dc=example,dc=com");

      assertNotNull(result);
      assertTrue(result.completelySuccessful(),
           result.toString());

      assertNull(result.getSetSubtreeAccessibilityError());
      assertFalse(result.subtreeInaccessible(),
           result.toString());

      assertNull(result.getSearchError(),
           result.toString());

      assertEquals(result.getEntriesDeleted(), 1002,
           result.toString());

      assertNotNull(result.getDeleteErrors());
      assertTrue(result.getDeleteErrors().isEmpty(),
           result.toString());

      assertEntryMissing(connection, "dc=example,dc=com");
    }
  }



  /**
   * Tests the behavior when trying to delete entries from a Ping Identity
   * Directory Server, if an instance is available.  This will be able to
   * take advantage of additional features that server offers, and will use the
   * simple paged results control.  If no Ping Identity Directory Server
   * instance is available, then this test will exit without doing anything.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithPingIdentityDirectoryServerWithPagedResults()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final SingleServerSet serverSet =
         new SingleServerSet(getTestHost(), getTestPort());
    final SimpleBindRequest bindRequest = new SimpleBindRequest(
         getTestBindDN(), getTestBindPassword());
    try (LDAPConnectionPool pool =
              new LDAPConnectionPool(serverSet, bindRequest, 1))
    {
      pool.setRetryFailedOperationsDueToInvalidConnections(true);

      // Add 1000 user entries in a relatively flat DIT.
      pool.add(getTestBaseDN(), getBaseEntryAttributes());
      pool.add(
           "dn: ou=People," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: People");
      for (int i=0; i < 1000; i++)
      {
        pool.add(
             "dn: uid=user." + i + ",ou=People," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: person",
             "objectClass: organizationalPerson",
             "objectClass: inetOrgPerson",
             "uid: user." + i,
             "givenName: User",
             "sn: " + i,
             "cn: User " + i);
      }

      assertEntryExists(pool, getTestBaseDN());
      assertEntryExists(pool, "ou=People," + getTestBaseDN());


      // Create a subtree deleter with everything turned on, and use it to
      // delete the target subtree.
      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      subtreeDeleter.setUseSetSubtreeAccessibilityOperationIfAvailable(true);
      subtreeDeleter.setUsePermitUnindexedSearchControlIfAvailable(true);

      // NOTE:  Some versions of the server don't like it when you try to set
      // subtree accessibility restrictions in a backend that doesn't have any
      // entries, even if you're trying to clear a restriction that you created
      // earlier.  That's being fixed (and it's probably unlikely that you'll
      // actually use the subtree deleter to remove all the data in the server,
      // when there are better ways to do that), but for this test, we'll avoid
      // the problem by not removing the test base entry, but we will remove all
      // entries below it.  We could do this with setDeleteBaseEntry(false), but
      // that's not an option that you're likely to use in conjunction with the
      // set subtree accessibility operation, since it would make the base entry
      // hidden while the subtree delete is in progress.  So instead, we'll just
      // use a base DN that is one level below the actual test base DN.
      final SubtreeDeleterResult result = subtreeDeleter.delete(pool,
           "ou=People," + getTestBaseDN());
      assertTrue(result.completelySuccessful(), result.toString());

      assertNull(result.getSetSubtreeAccessibilityError(), result.toString());
      assertFalse(result.subtreeInaccessible(), result.toString());

      assertNull(result.getSearchError(), result.toString());

      assertEquals(result.getEntriesDeleted(), 1001,
           result.toString());

      assertNotNull(result.getDeleteErrors(), result.toString());
      assertTrue(result.getDeleteErrors().isEmpty(), result.toString());

      assertEntryMissing(pool, "ou=People," + getTestBaseDN());
      assertEntryExists(pool, getTestBaseDN());
      pool.delete(getTestBaseDN());
      assertEntryMissing(pool, getTestBaseDN());
    }
  }



  /**
   * Tests the behavior when trying to delete entries from a Ping Identity
   * Directory Server, if an instance is available.  This will be able to
   * take advantage of additional features that server offers, but will not use
   * the simple paged results control.  If no Ping Identity Directory Server
   * instance is available, then this test will exit without doing anything.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithPingIdentityDirectoryServerWithoutPagedResults()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final SingleServerSet serverSet =
         new SingleServerSet(getTestHost(), getTestPort());
    final SimpleBindRequest bindRequest = new SimpleBindRequest(
         getTestBindDN(), getTestBindPassword());
    try (LDAPConnectionPool pool =
              new LDAPConnectionPool(serverSet, bindRequest, 1))
    {
      pool.setRetryFailedOperationsDueToInvalidConnections(true);

      // Add 1000 user entries in a relatively flat DIT.
      pool.add(getTestBaseDN(), getBaseEntryAttributes());
      pool.add(
           "dn: ou=People," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: People");
      for (int i=0; i < 1000; i++)
      {
        pool.add(
             "dn: uid=user." + i + ",ou=People," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: person",
             "objectClass: organizationalPerson",
             "objectClass: inetOrgPerson",
             "uid: user." + i,
             "givenName: User",
             "sn: " + i,
             "cn: User " + i);
      }

      assertEntryExists(pool, getTestBaseDN());
      assertEntryExists(pool, "ou=People," + getTestBaseDN());


      // Create a subtree deleter with everything turned on except the simple
      // paged results control, and use it to delete the target subtree.
      final SubtreeDeleter subtreeDeleter = new SubtreeDeleter();
      subtreeDeleter.setUseSimplePagedResultsControlIfAvailable(false);
      subtreeDeleter.setUseSetSubtreeAccessibilityOperationIfAvailable(true);
      subtreeDeleter.setUsePermitUnindexedSearchControlIfAvailable(true);

      // NOTE:  Some versions of the server don't like it when you try to set
      // subtree accessibility restrictions in a backend that doesn't have any
      // entries, even if you're trying to clear a restriction that you created
      // earlier.  That's being fixed (and it's probably unlikely that you'll
      // actually use the subtree deleter to remove all the data in the server,
      // when there are better ways to do that), but for this test, we'll avoid
      // the problem by not removing the test base entry, but we will remove all
      // entries below it.  We could do this with setDeleteBaseEntry(false), but
      // that's not an option that you're likely to use in conjunction with the
      // set subtree accessibility operation, since it would make the base entry
      // hidden while the subtree delete is in progress.  So instead, we'll just
      // use a base DN that is one level below the actual test base DN.
      final SubtreeDeleterResult result = subtreeDeleter.delete(pool,
           "ou=People," + getTestBaseDN());
      assertTrue(result.completelySuccessful(), result.toString());

      assertNull(result.getSetSubtreeAccessibilityError(), result.toString());
      assertFalse(result.subtreeInaccessible(), result.toString());

      assertNull(result.getSearchError(), result.toString());

      assertEquals(result.getEntriesDeleted(), 1001,
           result.toString());

      assertNotNull(result.getDeleteErrors(), result.toString());
      assertTrue(result.getDeleteErrors().isEmpty(), result.toString());

      assertEntryMissing(pool, "ou=People," + getTestBaseDN());
      assertEntryExists(pool, getTestBaseDN());
      pool.delete(getTestBaseDN());
      assertEntryMissing(pool, getTestBaseDN());
    }
  }
}
