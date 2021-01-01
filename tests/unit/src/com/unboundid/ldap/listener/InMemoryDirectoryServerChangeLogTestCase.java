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



import java.io.File;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.ChangeLogEntry;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.controls.SubtreeDeleteRequestControl;
import com.unboundid.ldif.LDIFReader;



/**
 * This class provides test coverage for the changelog capabilities of the
 * in-memory directory server.
 */
public final class InMemoryDirectoryServerChangeLogTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic coverage for server behavior without a changelog enabled.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBehaviorWithoutChangeLog()
         throws Exception
  {
    final InMemoryDirectoryServer testDS = getTestDS(true, true);
    final LDAPConnection conn = testDS.getConnection();

    // Ensure that the changelog attributes are not present in the root DSE.
    assertAttributeMissing(conn, "", "changeLog", "firstChangeNumber",
         "lastChangeNumber");

    // Ensure that the changelog base entry does not exist.
    assertEntryMissing(conn, "cn=changelog");

    assertEquals(testDS.countEntries(), 3);
    assertEquals(testDS.countEntries(false), 3);
    assertEquals(testDS.countEntries(true), 3);
    assertEquals(testDS.countEntriesBelow(""), 3);
    assertEquals(testDS.countEntriesBelow("dc=example,dc=com"), 3);

    conn.close();
  }



  /**
   * Provides test coverage to ensure that basic operations result in valid
   * changelog entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testChangeLogOperations()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setMaxChangeLogEntries(5);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    final LDAPConnection conn = ds.getConnection();

    try
    {
      // Test the directory server methods used for counting entries.
      assertEquals(ds.countEntries(), 0);
      assertEquals(ds.countEntries(false), 0);
      assertEquals(ds.countEntries(true), 1);
      assertEquals(ds.countEntriesBelow("dc=example,dc=com"), 0);
      assertEquals(ds.countEntriesBelow("cn=changelog"), 1);
      assertEquals(ds.countEntriesBelow("changeNumber=1,cn=changelog"), 0);


      // Ensure that the changelog attributes are present in the root DSE.
      assertValueExists(conn, "", "changeLog", "cn=changelog");
      assertValueExists(conn, "", "firstChangeNumber", "0");
      assertValueExists(conn, "", "lastChangeNumber", "0");

      // Ensure that the changelog base entry exists.
      assertEntryExists(conn, "cn=changelog");


      // Add an entry to the server and verify that a changelog entry is created
      // for it.
      conn.add(generateDomainEntry("example", "dc=com"));

      assertValueExists(conn, "", "changeLog", "cn=changelog");
      assertValueExists(conn, "", "firstChangeNumber", "1");
      assertValueExists(conn, "", "lastChangeNumber", "1");

      assertEntryExists(conn, "cn=changelog");
      assertEntryExists(conn, "changeNumber=1,cn=changelog");

      assertAttributeExists(conn, "changeNumber=1,cn=changelog", "entryDN",
           "entryUUID",  "creatorsName", "createTimestamp", "modifiersName",
           "modifyTimestamp", "subschemaSubentry");

      ChangeLogEntry changeLogEntry =
           new ChangeLogEntry(conn.getEntry("changeNumber=1,cn=changelog"));
      assertNotNull(changeLogEntry);

      assertEquals(changeLogEntry.getChangeNumber(), 1L);

      assertEquals(new DN(changeLogEntry.getTargetDN()),
           new DN("dc=example,dc=com"));

      assertEquals(changeLogEntry.getChangeType(), ChangeType.ADD);

      assertNotNull(changeLogEntry.getAddAttributes());
      assertTrue(changeLogEntry.getAddAttributes().contains(
           new Attribute("objectClass", "top", "domain")));
      assertTrue(changeLogEntry.getAddAttributes().contains(
           new Attribute("dc", "example")));


      // Add a second entry to the server and verify that a changelog entry is
      // created for it as well.
      conn.add(generateOrgUnitEntry("People", "dc=example,dc=com"));

      assertValueExists(conn, "", "changeLog", "cn=changelog");
      assertValueExists(conn, "", "firstChangeNumber", "1");
      assertValueExists(conn, "", "lastChangeNumber", "2");

      assertEntryExists(conn, "cn=changelog");
      assertEntryExists(conn, "changeNumber=1,cn=changelog");
      assertEntryExists(conn, "changeNumber=2,cn=changelog");

      assertAttributeExists(conn, "changeNumber=2,cn=changelog", "entryDN",
           "entryUUID",  "creatorsName", "createTimestamp", "modifiersName",
           "modifyTimestamp", "subschemaSubentry");

      changeLogEntry =
           new ChangeLogEntry(conn.getEntry("changeNumber=2,cn=changelog"));
      assertNotNull(changeLogEntry);

      assertEquals(changeLogEntry.getChangeNumber(), 2L);

      assertEquals(new DN(changeLogEntry.getTargetDN()),
           new DN("ou=People,dc=example,dc=com"));

      assertEquals(changeLogEntry.getChangeType(), ChangeType.ADD);

      assertNotNull(changeLogEntry.getAddAttributes());
      assertTrue(changeLogEntry.getAddAttributes().contains(
           new Attribute("objectClass", "top", "organizationalUnit")));
      assertTrue(changeLogEntry.getAddAttributes().contains(
           new Attribute("ou", "People")));


      // Add a third entry to the server and verify that a changelog entry is
      // created for it as well.
      conn.add(generateUserEntry("test.user", "ou=People,dc=example,dc=com",
           "Test", "User", "password"));

      assertValueExists(conn, "", "changeLog", "cn=changelog");
      assertValueExists(conn, "", "firstChangeNumber", "1");
      assertValueExists(conn, "", "lastChangeNumber", "3");

      assertEntryExists(conn, "cn=changelog");
      assertEntryExists(conn, "changeNumber=1,cn=changelog");
      assertEntryExists(conn, "changeNumber=2,cn=changelog");
      assertEntryExists(conn, "changeNumber=3,cn=changelog");

      assertAttributeExists(conn, "changeNumber=3,cn=changelog", "entryDN",
           "entryUUID",  "creatorsName", "createTimestamp", "modifiersName",
           "modifyTimestamp", "subschemaSubentry");

      changeLogEntry =
           new ChangeLogEntry(conn.getEntry("changeNumber=3,cn=changelog"));
      assertNotNull(changeLogEntry);

      assertEquals(changeLogEntry.getChangeNumber(), 3L);

      assertEquals(new DN(changeLogEntry.getTargetDN()),
           new DN("uid=test.user,ou=People,dc=example,dc=com"));

      assertEquals(changeLogEntry.getChangeType(), ChangeType.ADD);

      assertNotNull(changeLogEntry.getAddAttributes());
      assertTrue(changeLogEntry.getAddAttributes().contains(
           new Attribute("objectClass", "top", "person", "organizationalPerson",
                "inetOrgPerson")));
      assertTrue(changeLogEntry.getAddAttributes().contains(
           new Attribute("uid", "test.user")));
      assertTrue(changeLogEntry.getAddAttributes().contains(
           new Attribute("givenName", "Test")));
      assertTrue(changeLogEntry.getAddAttributes().contains(
           new Attribute("sn", "User")));
      assertTrue(changeLogEntry.getAddAttributes().contains(
           new Attribute("cn", "Test User")));
      assertTrue(changeLogEntry.getAddAttributes().contains(
           new Attribute("userPassword", "password")));


      // Modify the user entry and verify that a changelog record is created
      // for it.
      conn.modify(
           "dn: uid=test.user,ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: foo");

      assertValueExists(conn, "", "changeLog", "cn=changelog");
      assertValueExists(conn, "", "firstChangeNumber", "1");
      assertValueExists(conn, "", "lastChangeNumber", "4");

      assertEntryExists(conn, "cn=changelog");
      assertEntryExists(conn, "changeNumber=1,cn=changelog");
      assertEntryExists(conn, "changeNumber=2,cn=changelog");
      assertEntryExists(conn, "changeNumber=3,cn=changelog");
      assertEntryExists(conn, "changeNumber=4,cn=changelog");

      assertAttributeExists(conn, "changeNumber=4,cn=changelog", "entryDN",
           "entryUUID",  "creatorsName", "createTimestamp", "modifiersName",
           "modifyTimestamp", "subschemaSubentry");

      changeLogEntry =
           new ChangeLogEntry(conn.getEntry("changeNumber=4,cn=changelog"));
      assertNotNull(changeLogEntry);

      assertEquals(changeLogEntry.getChangeNumber(), 4L);

      assertEquals(new DN(changeLogEntry.getTargetDN()),
           new DN("uid=test.user,ou=People,dc=example,dc=com"));

      assertEquals(changeLogEntry.getChangeType(), ChangeType.MODIFY);

      assertNull(changeLogEntry.getAddAttributes());

      assertNotNull(changeLogEntry.getModifications());
      assertTrue(changeLogEntry.getModifications().contains(
           new Modification(ModificationType.REPLACE, "description", "foo")));


      // Test the directory server methods used for counting entries.
      assertEquals(ds.countEntries(), 3);
      assertEquals(ds.countEntries(false), 3);
      assertEquals(ds.countEntries(true), 8);
      assertEquals(ds.countEntriesBelow("dc=example,dc=com"), 3);
      assertEquals(ds.countEntriesBelow("ou=People,dc=example,dc=com"), 2);
      assertEquals(ds.countEntriesBelow(
           "uid=test.user,ou=People,dc=example,dc=com"), 1);
      assertEquals(ds.countEntriesBelow("cn=missing,dc=example,dc=com"), 0);
      assertEquals(ds.countEntriesBelow("cn=changelog"), 5);
      assertEquals(ds.countEntriesBelow("changeNumber=1,cn=changelog"), 1);
      assertEquals(ds.countEntriesBelow("changeNumber=5,cn=changelog"), 0);


      // Rename the organizationalUnit entry and verify that another changelog
      // record was created for it.  In this case, only one changelog entry
      // should be created even though two entries are impacted.
      conn.modifyDN("ou=People,dc=example,dc=com", "ou=Users", true);

      assertValueExists(conn, "", "changeLog", "cn=changelog");
      assertValueExists(conn, "", "firstChangeNumber", "1");
      assertValueExists(conn, "", "lastChangeNumber", "5");

      assertEntryExists(conn, "cn=changelog");
      assertEntryExists(conn, "changeNumber=1,cn=changelog");
      assertEntryExists(conn, "changeNumber=2,cn=changelog");
      assertEntryExists(conn, "changeNumber=3,cn=changelog");
      assertEntryExists(conn, "changeNumber=4,cn=changelog");
      assertEntryExists(conn, "changeNumber=5,cn=changelog");

      assertAttributeExists(conn, "changeNumber=5,cn=changelog", "entryDN",
           "entryUUID",  "creatorsName", "createTimestamp", "modifiersName",
           "modifyTimestamp", "subschemaSubentry");

      changeLogEntry =
           new ChangeLogEntry(conn.getEntry("changeNumber=5,cn=changelog"));
      assertNotNull(changeLogEntry);

      assertEquals(changeLogEntry.getChangeNumber(), 5L);

      assertEquals(new DN(changeLogEntry.getTargetDN()),
           new DN("ou=People,dc=example,dc=com"));

      assertEquals(changeLogEntry.getChangeType(), ChangeType.MODIFY_DN);

      assertNull(changeLogEntry.getAddAttributes());

      assertNull(changeLogEntry.getModifications());

      assertEquals(new RDN(changeLogEntry.getNewRDN()),
           new RDN("ou=Users"));

      assertTrue(changeLogEntry.deleteOldRDN());

      assertEquals(new DN(changeLogEntry.getNewDN()),
           new DN("ou=Users,dc=example,dc=com"));


      // Delete the user entry and verify that a changelog entry was created
      // for the delete.  At this point, we have hit the changelog entry limit
      // and an old entry should have been removed.
      conn.delete("uid=test.user,ou=Users,dc=example,dc=com");

      assertValueExists(conn, "", "changeLog", "cn=changelog");
      assertValueExists(conn, "", "firstChangeNumber", "2");
      assertValueExists(conn, "", "lastChangeNumber", "6");

      assertEntryExists(conn, "cn=changelog");
      assertEntryMissing(conn, "changeNumber=1,cn=changelog");
      assertEntryExists(conn, "changeNumber=2,cn=changelog");
      assertEntryExists(conn, "changeNumber=3,cn=changelog");
      assertEntryExists(conn, "changeNumber=4,cn=changelog");
      assertEntryExists(conn, "changeNumber=5,cn=changelog");
      assertEntryExists(conn, "changeNumber=6,cn=changelog");

      assertAttributeExists(conn, "changeNumber=6,cn=changelog", "entryDN",
           "entryUUID",  "creatorsName", "createTimestamp", "modifiersName",
           "modifyTimestamp", "subschemaSubentry");

      changeLogEntry =
           new ChangeLogEntry(conn.getEntry("changeNumber=6,cn=changelog"));
      assertNotNull(changeLogEntry);

      assertEquals(changeLogEntry.getChangeNumber(), 6L);

      assertEquals(new DN(changeLogEntry.getTargetDN()),
           new DN("uid=test.user,ou=Users,dc=example,dc=com"));

      assertEquals(changeLogEntry.getChangeType(), ChangeType.DELETE);

      assertNull(changeLogEntry.getAddAttributes());

      assertNull(changeLogEntry.getModifications());

      assertNotNull(changeLogEntry .getDeletedEntryAttributes());
      assertTrue(changeLogEntry.getDeletedEntryAttributes().contains(
           new Attribute("objectClass", "top", "person", "organizationalPerson",
                "inetOrgPerson")));
      assertTrue(changeLogEntry.getDeletedEntryAttributes().contains(
           new Attribute("uid", "test.user")));
      assertTrue(changeLogEntry.getDeletedEntryAttributes().contains(
           new Attribute("givenName", "Test")));
      assertTrue(changeLogEntry.getDeletedEntryAttributes().contains(
           new Attribute("sn", "User")));
      assertTrue(changeLogEntry.getDeletedEntryAttributes().contains(
           new Attribute("cn", "Test User")));
      assertTrue(changeLogEntry.getDeletedEntryAttributes().contains(
           new Attribute("userPassword", "password")));


      // Perform a subtree delete from the base and verify that two new
      // changelog entries are created (one for each entry removed, in
      // descending hierarchical order).
      final DeleteRequest deleteRequest =
           new DeleteRequest("dc=example,dc=com");
      deleteRequest.addControl(new SubtreeDeleteRequestControl());
      conn.delete(deleteRequest);

      assertValueExists(conn, "", "changeLog", "cn=changelog");
      assertValueExists(conn, "", "firstChangeNumber", "4");
      assertValueExists(conn, "", "lastChangeNumber", "8");

      assertEntryExists(conn, "cn=changelog");
      assertEntryMissing(conn, "changeNumber=1,cn=changelog");
      assertEntryMissing(conn, "changeNumber=2,cn=changelog");
      assertEntryMissing(conn, "changeNumber=3,cn=changelog");
      assertEntryExists(conn, "changeNumber=4,cn=changelog");
      assertEntryExists(conn, "changeNumber=5,cn=changelog");
      assertEntryExists(conn, "changeNumber=6,cn=changelog");
      assertEntryExists(conn, "changeNumber=7,cn=changelog");
      assertEntryExists(conn, "changeNumber=8,cn=changelog");

      assertAttributeExists(conn, "changeNumber=7,cn=changelog", "entryDN",
           "entryUUID",  "creatorsName", "createTimestamp", "modifiersName",
           "modifyTimestamp", "subschemaSubentry");

      changeLogEntry =
           new ChangeLogEntry(conn.getEntry("changeNumber=7,cn=changelog"));
      assertNotNull(changeLogEntry);

      assertEquals(changeLogEntry.getChangeNumber(), 7L);

      assertEquals(new DN(changeLogEntry.getTargetDN()),
           new DN("ou=Users,dc=example,dc=com"));

      assertEquals(changeLogEntry.getChangeType(), ChangeType.DELETE);

      assertNull(changeLogEntry.getAddAttributes());

      assertNull(changeLogEntry.getModifications());

      assertNotNull(changeLogEntry .getDeletedEntryAttributes());
      assertTrue(changeLogEntry.getDeletedEntryAttributes().contains(
           new Attribute("objectClass", "top", "organizationalUnit")));
      assertTrue(changeLogEntry.getDeletedEntryAttributes().contains(
           new Attribute("ou", "Users")));

      assertAttributeExists(conn, "changeNumber=8,cn=changelog", "entryDN",
           "entryUUID",  "creatorsName", "createTimestamp", "modifiersName",
           "modifyTimestamp", "subschemaSubentry");

      changeLogEntry =
           new ChangeLogEntry(conn.getEntry("changeNumber=8,cn=changelog"));
      assertNotNull(changeLogEntry);

      assertEquals(changeLogEntry.getChangeNumber(), 8L);

      assertEquals(new DN(changeLogEntry.getTargetDN()),
           new DN("dc=example,dc=com"));

      assertEquals(changeLogEntry.getChangeType(), ChangeType.DELETE);

      assertNull(changeLogEntry.getAddAttributes());

      assertNull(changeLogEntry.getModifications());

      assertNotNull(changeLogEntry .getDeletedEntryAttributes());
      assertTrue(changeLogEntry.getDeletedEntryAttributes().contains(
           new Attribute("objectClass", "top", "domain")));
      assertTrue(changeLogEntry.getDeletedEntryAttributes().contains(
           new Attribute("dc", "example")));
    }
    finally
    {
      conn.close();
      ds.shutDown(true);
    }
  }



  /**
   * Tests to ensure that "cn=changelog" cannot be used as a base DN, regardless
   * of whether a changelog is enabled.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPreventChangelogAsBaseDN()
         throws Exception
  {
    // Create a base configuration to use for testing.
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    // Ensure that the configuration can be used without the changelog base DN.
    new InMemoryDirectoryServer(config);


    // Update the configuration to try to specify only a base DN of
    // "cn=changelog".
    config.setBaseDNs("cn=changelog");

    try
    {
      new InMemoryDirectoryServer(config);
      fail("Expected an exception when trying to use only a changelog base DN");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Update the configuration to try to specify a base DN of "cn=changelog"
    // in conjunction with an allowed base DN.
    config.setBaseDNs("dc=example,dc=com", "cn=changelog");

    try
    {
      new InMemoryDirectoryServer(config);
      fail("Expected an exception when trying to use a changelog base DN in" +
           "conjunction with an allowed base DN");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Verify that it still fails even if the changelog is enabled.
    config.setMaxChangeLogEntries(10);

    try
    {
      new InMemoryDirectoryServer(config);
      fail("Expected an exception when trying to use a changelog base DN in" +
           "when a changelog is enabled.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Tests to ensure that operations targeting the changelog are properly
   * handled.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOperationsTargetingChangelog()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setMaxChangeLogEntries(5);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    try
    {
      final LDAPConnection conn = ds.getConnection();


      // Add an entry to the server and verify that it results in a
      // corresponding changelog entry.
      conn.add(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");

      ds.assertValueExists("", "lastChangeNumber", "1");


      // Verify that we cannot create an entry below the changelog base.
      try
      {
        conn.add(
             "dn: ou=test,cn=changelog",
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: test");
        fail("Expected an exception when trying to add an entry below the " +
             "changelog base DN.");
      }
      catch (final LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
      }


      // Verify that we cannot delete a changelog entry.
      try
      {
        conn.delete("changeNumber=1,cn=changelog");
        fail("Expected an exception when trying to delete a changelog entry.");
      }
      catch (final LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
      }


      // Verify that we cannot modify a changelog entry.
      try
      {
        conn.modify(
             "dn: changeNumber=1,cn=changelog",
             "changetype: modify",
             "replace: targetDN",
             "targetDN: cn=test,dc=example,dc=com");
        fail("Expected an exception when trying to modify a changelog entry.");
      }
      catch (final LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
      }


      // Verify that we cannot rename a changelog entry.
      try
      {
        conn.modifyDN("changeNumber=1,cn=changelog",
             "changeNumber=0", true);
        fail("Expected an exception when trying to rename a changelog entry.");
      }
      catch (final LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
      }


      // Verify that we cannot move an entry below the changelog base DN.
      conn.add(
           "dn: ou=test,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test");

      try
      {
        conn.modifyDN("ou=test,dc=example,dc=com", "ou=test", false,
             "cn=changelog");
        fail("Expected an exception when trying to move an entry to below " +
             "changelog base DN.");
      }
      catch (final LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
      }


      // Verify that a one-level search below the root DSE excludes changelog
      // entries.
      SearchResult searchResult = conn.search("", SearchScope.ONE,
           "(objectClass=*)");
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);
      assertNotNull(searchResult.getSearchEntry("dc=example,dc=com"));
      assertNull(searchResult.getSearchEntry("ou=test,dc=example,dc=com"));
      assertNull(searchResult.getSearchEntry("cn=changelog"));
      assertNull(searchResult.getSearchEntry("changeNumber=1,cn=changelog"));
      assertNull(searchResult.getSearchEntry("changeNumber=2,cn=changelog"));


      // Verify that a subtree search below the root DSE excludes changelog
      // entries.
      searchResult = conn.search("", SearchScope.SUB, "(objectClass=*)");
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 2);
      assertNotNull(searchResult.getSearchEntry("dc=example,dc=com"));
      assertNotNull(searchResult.getSearchEntry("ou=test,dc=example,dc=com"));
      assertNull(searchResult.getSearchEntry("cn=changelog"));
      assertNull(searchResult.getSearchEntry("changeNumber=1,cn=changelog"));
      assertNull(searchResult.getSearchEntry("changeNumber=2,cn=changelog"));


      // Verify that a subordinate subtree search below the root DSE excludes
      // changelog entries.
      searchResult = conn.search("", SearchScope.SUBORDINATE_SUBTREE,
           "(objectClass=*)");
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 2);
      assertNotNull(searchResult.getSearchEntry("dc=example,dc=com"));
      assertNotNull(searchResult.getSearchEntry("ou=test,dc=example,dc=com"));
      assertNull(searchResult.getSearchEntry("cn=changelog"));
      assertNull(searchResult.getSearchEntry("changeNumber=1,cn=changelog"));
      assertNull(searchResult.getSearchEntry("changeNumber=2,cn=changelog"));


      conn.close();
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the LDIF export behavior when a changelog is enabled.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDIFExportWithChangelog()
         throws Exception
  {
    // Create a directory server instance with a changelog enabled.
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.setMaxChangeLogEntries(10);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);

    // Add some entries to the server and verify that changelog records are
    // properly created for them.
    ds.addEntries(
         generateDomainEntry("example", "dc=com"),
         generateOrgUnitEntry("People", "dc=example,dc=com"),
         generateUserEntry("test.user", "ou=People,dc=example,dc=com", "Tets",
              "User", "password"));

    Entry changeLogEntry = ds.getEntry("changeNumber=1,cn=changelog", "*", "+");
    assertNotNull(changeLogEntry);

    changeLogEntry = ds.getEntry("changeNumber=2,cn=changelog", "*", "+");
    assertNotNull(changeLogEntry);

    changeLogEntry = ds.getEntry("changeNumber=3,cn=changelog", "*", "+");
    assertNotNull(changeLogEntry);

    changeLogEntry = ds.getEntry("changeNumber=4,cn=changelog", "*", "+");
    assertNull(changeLogEntry);


    // Write the contents of the server to LDIF, excluding changelog content,
    // as well as generated operational attributes.  Only three entries should
    // be written.
    final File userOnlyPath = createTempFile();
    assertEquals(ds.exportToLDIF(userOnlyPath.getAbsolutePath(), true, true),
         3);

    // Read back the entries and verify they are the ones we expect.
    LDIFReader ldifReader = new LDIFReader(userOnlyPath);
    while (true)
    {
      final Entry e = ldifReader.readEntry();
      if (e == null)
      {
        break;
      }

      assertTrue(e.getParsedDN().isDescendantOf("dc=example,dc=com", true));
      assertFalse(e.getParsedDN().isDescendantOf("cn=changelog", true));
      assertFalse(e.hasAttribute("entryDN"));
      assertFalse(e.hasAttribute("entryUUID"));
      assertFalse(e.hasAttribute("creatorsName"));
      assertFalse(e.hasAttribute("createTimestamp"));
      assertFalse(e.hasAttribute("modifiersName"));
      assertFalse(e.hasAttribute("modifyTimestamp"));
      assertFalse(e.hasAttribute("subschemaSubentry"));
    }

    ldifReader.close();


    // Write a second LDIF file, this time including the changelog content and
    // generated operational attributes.
    final File genDataPath = createTempFile();
    assertEquals(ds.exportToLDIF(genDataPath.getAbsolutePath(), false, false),
         7);

    // Read back the entries and verify they are the ones we expect.
    ldifReader = new LDIFReader(genDataPath);
    boolean changeLogFound = false;
    boolean userFound = false;
    while (true)
    {
      final Entry e = ldifReader.readEntry();
      if (e == null)
      {
        break;
      }

      if (e.getParsedDN().isDescendantOf("dc=example,dc=com", true))
      {
        userFound = true;
      }
      else if (e.getParsedDN().isDescendantOf("cn=changelog", true))
      {
        changeLogFound = true;
      }
      else
      {
        fail("Unexpected entry '" + e.getDN() + "' found in export.");
      }

      assertTrue(e.hasAttribute("entryDN"), e.toLDIFString());
      assertTrue(e.hasAttribute("entryUUID"), e.toLDIFString());
      assertTrue(e.hasAttribute("creatorsName"), e.toLDIFString());
      assertTrue(e.hasAttribute("createTimestamp"), e.toLDIFString());
      assertTrue(e.hasAttribute("modifiersName"), e.toLDIFString());
      assertTrue(e.hasAttribute("modifyTimestamp"), e.toLDIFString());
      assertTrue(e.hasAttribute("subschemaSubentry"), e.toLDIFString());
    }

    assertTrue(userFound);
    assertTrue(changeLogFound);

    ldifReader.close();
  }
}
