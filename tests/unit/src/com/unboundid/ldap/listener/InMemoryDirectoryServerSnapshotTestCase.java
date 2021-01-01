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

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides basic test coverage for the snapshot capabilities of the
 * in-memory directory server.
 */
public final class InMemoryDirectoryServerSnapshotTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for snapshot-related functionality in a server
   * without a changelog configured.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSnapshotWithoutChangelog()
         throws Exception
  {
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);

    ds.startListening();

    try
    {
      // An empty snapshot isn't really empty because it will contain the
      // changelog base entry.
      ds.assertEntryMissing("dc=example,dc=com");
      ds.assertEntryMissing("uid=test.user,ou=People,dc=example,dc=com");
      ds.assertEntryMissing("cn=changelog");
      ds.assertEntryMissing("changeNumber=1,cn=changelog");
      ds.assertEntryMissing("changeNumber=4,cn=changelog");
      ds.assertAttributeMissing("", "firstChangeNumber");
      ds.assertAttributeMissing("", "lastChangeNumber");

      final InMemoryDirectoryServerSnapshot emptySnapshot = ds.createSnapshot();

      assertNotNull(emptySnapshot);
      assertNotNull(emptySnapshot.getEntryMap());
      assertTrue(emptySnapshot.getEntryMap().isEmpty());
      assertNull(emptySnapshot.getEntryMap().get(new DN("dc=example,dc=com")));
      assertNull(emptySnapshot.getEntryMap().get(new DN(
           "uid=test.user,ou=People,dc=example,dc=com")));
      assertNull(emptySnapshot.getEntryMap().get(new DN("cn=changelog")));
      assertNull(emptySnapshot.getEntryMap().get(new DN(
           "changeNumber=1,cn=changelog")));
      assertNull(emptySnapshot.getEntryMap().get(new DN(
           "changeNumber=4,cn=changelog")));
      assertEquals(emptySnapshot.getFirstChangeNumber(), 0L);
      assertEquals(emptySnapshot.getLastChangeNumber(), 0L);


      // Populate the server and perform some operations in it.
      final LDAPConnection conn = ds.getConnection();

      conn.add(generateDomainEntry("example", "dc=com"));
      conn.add(generateOrgUnitEntry("People", "dc=example,dc=com"));
      conn.modify(
           "dn: ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: foo");

      // Verify the current state of the server.
      ds.assertEntryExists("dc=example,dc=com");
      ds.assertEntryMissing("uid=test.user,ou=People,dc=example,dc=com");
      ds.assertEntryMissing("cn=changelog");
      ds.assertEntryMissing("changeNumber=1,cn=changelog");
      ds.assertEntryMissing("changeNumber=4,cn=changelog");
      ds.assertAttributeMissing("", "firstChangeNumber");
      ds.assertAttributeMissing("", "lastChangeNumber");

      // Take a snapshot and verify it.
      final InMemoryDirectoryServerSnapshot nonEmptySnapshot =
           ds.createSnapshot();

      assertNotNull(nonEmptySnapshot);
      assertNotNull(nonEmptySnapshot.getEntryMap());
      assertFalse(nonEmptySnapshot.getEntryMap().isEmpty());
      assertNotNull(nonEmptySnapshot.getEntryMap().get(new DN(
           "dc=example,dc=com")));
      assertNull(nonEmptySnapshot.getEntryMap().get(new DN(
           "uid=test.user,ou=People,dc=example,dc=com")));
      assertNull(nonEmptySnapshot.getEntryMap().get(new DN("cn=changelog")));
      assertNull(nonEmptySnapshot.getEntryMap().get(new DN(
           "changeNumber=1,cn=changelog")));
      assertNull(nonEmptySnapshot.getEntryMap().get(new DN(
           "changeNumber=4,cn=changelog")));
      assertEquals(nonEmptySnapshot.getFirstChangeNumber(), 0L);
      assertEquals(nonEmptySnapshot.getLastChangeNumber(), 0L);


      // Add another entry to the server.
      conn.add(generateUserEntry("test.user", "ou=People,dc=example,dc=com",
           "Test", "User", "password"));

      // Verify the current state of the server.
      ds.assertEntryExists("dc=example,dc=com");
      ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
      ds.assertEntryMissing("cn=changelog");
      ds.assertEntryMissing("changeNumber=1,cn=changelog");
      ds.assertEntryMissing("changeNumber=4,cn=changelog");
      ds.assertAttributeMissing("", "firstChangeNumber");
      ds.assertAttributeMissing("", "lastChangeNumber");


      // Restore the previous snapshot.
      ds.restoreSnapshot(nonEmptySnapshot);

      // Verify the current state of the server after the restore.
      ds.assertEntryExists("dc=example,dc=com");
      ds.assertEntryMissing("uid=test.user,ou=People,dc=example,dc=com");
      ds.assertEntryMissing("cn=changelog");
      ds.assertEntryMissing("changeNumber=1,cn=changelog");
      ds.assertEntryMissing("changeNumber=4,cn=changelog");
      ds.assertAttributeMissing("", "firstChangeNumber");
      ds.assertAttributeMissing("", "lastChangeNumber");


      // Restore the empty snapshot and verify that the server content looks
      // the same as it originally did.
      ds.restoreSnapshot(emptySnapshot);

      ds.assertEntryMissing("dc=example,dc=com");
      ds.assertEntryMissing("uid=test.user,ou=People,dc=example,dc=com");
      ds.assertEntryMissing("cn=changelog");
      ds.assertEntryMissing("changeNumber=1,cn=changelog");
      ds.assertEntryMissing("changeNumber=4,cn=changelog");
      ds.assertAttributeMissing("", "firstChangeNumber");
      ds.assertAttributeMissing("", "lastChangeNumber");


      // Restore the non-empty snapshot and re-verify the server content.
      ds.restoreSnapshot(nonEmptySnapshot);

      // Verify the current state of the server after the restore.
      ds.assertEntryExists("dc=example,dc=com");
      ds.assertEntryMissing("uid=test.user,ou=People,dc=example,dc=com");
      ds.assertEntryMissing("cn=changelog");
      ds.assertEntryMissing("changeNumber=1,cn=changelog");
      ds.assertEntryMissing("changeNumber=4,cn=changelog");
      ds.assertAttributeMissing("", "firstChangeNumber");
      ds.assertAttributeMissing("", "lastChangeNumber");


      conn.close();
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Provides test coverage for snapshot-related functionality in a server with
   * a changelog configured.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSnapshotWithChangelog()
         throws Exception
  {
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.setMaxChangeLogEntries(100);
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);

    ds.startListening();

    try
    {
      // An empty snapshot isn't really empty because it will contain the
      // changelog base entry.
      ds.assertEntryMissing("dc=example,dc=com");
      ds.assertEntryMissing("uid=test.user,ou=People,dc=example,dc=com");
      ds.assertEntryExists("cn=changelog");
      ds.assertEntryMissing("changeNumber=1,cn=changelog");
      ds.assertEntryMissing("changeNumber=4,cn=changelog");
      ds.assertValueExists("", "firstChangeNumber", "0");
      ds.assertValueExists("", "lastChangeNumber", "0");

      final InMemoryDirectoryServerSnapshot emptySnapshot = ds.createSnapshot();

      assertNotNull(emptySnapshot);
      assertNotNull(emptySnapshot.getEntryMap());
      assertFalse(emptySnapshot.getEntryMap().isEmpty());
      assertNull(emptySnapshot.getEntryMap().get(new DN("dc=example,dc=com")));
      assertNull(emptySnapshot.getEntryMap().get(new DN(
           "uid=test.user,ou=People,dc=example,dc=com")));
      assertNotNull(emptySnapshot.getEntryMap().get(new DN("cn=changelog")));
      assertNull(emptySnapshot.getEntryMap().get(new DN(
           "changeNumber=1,cn=changelog")));
      assertNull(emptySnapshot.getEntryMap().get(new DN(
           "changeNumber=4,cn=changelog")));
      assertEquals(emptySnapshot.getFirstChangeNumber(), 0L);
      assertEquals(emptySnapshot.getLastChangeNumber(), 0L);


      // Populate the server and perform some operations in it.
      final LDAPConnection conn = ds.getConnection();

      conn.add(generateDomainEntry("example", "dc=com"));
      conn.add(generateOrgUnitEntry("People", "dc=example,dc=com"));
      conn.modify(
           "dn: ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: foo");

      // Verify the current state of the server.
      ds.assertEntryExists("dc=example,dc=com");
      ds.assertEntryMissing("uid=test.user,ou=People,dc=example,dc=com");
      ds.assertEntryExists("cn=changelog");
      ds.assertEntryExists("changeNumber=1,cn=changelog");
      ds.assertEntryMissing("changeNumber=4,cn=changelog");
      ds.assertValueExists("", "firstChangeNumber", "1");
      ds.assertValueExists("", "lastChangeNumber", "3");

      // Take a snapshot and verify it.
      final InMemoryDirectoryServerSnapshot nonEmptySnapshot =
           ds.createSnapshot();

      assertNotNull(nonEmptySnapshot);
      assertNotNull(nonEmptySnapshot.getEntryMap());
      assertFalse(nonEmptySnapshot.getEntryMap().isEmpty());
      assertNotNull(nonEmptySnapshot.getEntryMap().get(new DN(
           "dc=example,dc=com")));
      assertNull(nonEmptySnapshot.getEntryMap().get(new DN(
           "uid=test.user,ou=People,dc=example,dc=com")));
      assertNotNull(nonEmptySnapshot.getEntryMap().get(new DN("cn=changelog")));
      assertNotNull(nonEmptySnapshot.getEntryMap().get(new DN(
           "changeNumber=1,cn=changelog")));
      assertNull(nonEmptySnapshot.getEntryMap().get(new DN(
           "changeNumber=4,cn=changelog")));
      assertEquals(nonEmptySnapshot.getFirstChangeNumber(), 1L);
      assertEquals(nonEmptySnapshot.getLastChangeNumber(), 3L);


      // Add another entry to the server.
      conn.add(generateUserEntry("test.user", "ou=People,dc=example,dc=com",
           "Test", "User", "password"));

      // Verify the current state of the server.
      ds.assertEntryExists("dc=example,dc=com");
      ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
      ds.assertEntryExists("cn=changelog");
      ds.assertEntryExists("changeNumber=1,cn=changelog");
      ds.assertEntryExists("changeNumber=4,cn=changelog");
      ds.assertValueExists("", "firstChangeNumber", "1");
      ds.assertValueExists("", "lastChangeNumber", "4");


      // Restore the previous snapshot.
      ds.restoreSnapshot(nonEmptySnapshot);

      // Verify the current state of the server after the restore.
      ds.assertEntryExists("dc=example,dc=com");
      ds.assertEntryMissing("uid=test.user,ou=People,dc=example,dc=com");
      ds.assertEntryExists("cn=changelog");
      ds.assertEntryExists("changeNumber=1,cn=changelog");
      ds.assertEntryMissing("changeNumber=4,cn=changelog");
      ds.assertValueExists("", "firstChangeNumber", "1");
      ds.assertValueExists("", "lastChangeNumber", "3");


      // Restore the empty snapshot and verify that the server content looks
      // the same as it originally did.
      ds.restoreSnapshot(emptySnapshot);

      ds.assertEntryMissing("dc=example,dc=com");
      ds.assertEntryMissing("uid=test.user,ou=People,dc=example,dc=com");
      ds.assertEntryExists("cn=changelog");
      ds.assertEntryMissing("changeNumber=1,cn=changelog");
      ds.assertEntryMissing("changeNumber=4,cn=changelog");
      ds.assertValueExists("", "firstChangeNumber", "0");
      ds.assertValueExists("", "lastChangeNumber", "0");


      // Restore the non-empty snapshot and re-verify the server content.
      ds.restoreSnapshot(nonEmptySnapshot);

      // Verify the current state of the server after the restore.
      ds.assertEntryExists("dc=example,dc=com");
      ds.assertEntryMissing("uid=test.user,ou=People,dc=example,dc=com");
      ds.assertEntryExists("cn=changelog");
      ds.assertEntryExists("changeNumber=1,cn=changelog");
      ds.assertEntryMissing("changeNumber=4,cn=changelog");
      ds.assertValueExists("", "firstChangeNumber", "1");
      ds.assertValueExists("", "lastChangeNumber", "3");


      conn.close();
    }
    finally
    {
      ds.shutDown(true);
    }
  }
}
