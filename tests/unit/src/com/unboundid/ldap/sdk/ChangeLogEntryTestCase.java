/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFModifyDNChangeRecord;
import com.unboundid.util.Base64;



/**
 * This class provides a set of test cases for the ChangeLogEntry class.
 */
public class ChangeLogEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the ability to create a changelog entry for an add operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddChangeLogEntry()
         throws Exception
  {
    StringBuilder changes = new StringBuilder();
    changes.append("objectClass: top\n");
    changes.append("objectClass: domain\n");
    changes.append("dc: example\n");

    ChangeLogEntry e = new ChangeLogEntry(new Entry(
       "dn: changeNumber=1,cn=changelog",
       "objectClass: top",
       "objectClass: changeLogEntry",
       "changeNumber: 1",
       "targetDN: dc=example,dc=com",
       "changeType: add",
       "changes:: " + Base64.encode(changes.toString())));

    assertNotNull(e);

    assertEquals(e.getChangeNumber(), 1L);

    assertEquals(new DN(e.getTargetDN()), new DN("dc=example,dc=com"));

    assertEquals(e.getChangeType(), ChangeType.ADD);

    assertNotNull(e.getAddAttributes());
    assertEquals(e.getAddAttributes().size(), 2);

    assertNull(e.getDeletedEntryAttributes());

    assertNull(e.getModifications());

    assertNull(e.getNewRDN());

    assertNull(e.getNewSuperior());

    assertTrue(e.toLDIFChangeRecord() instanceof LDIFAddChangeRecord);
  }



  /**
   * Tests the ability to construct a changelog entry for an add operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructAddChangeLogEntry()
         throws Exception
  {
    final ChangeLogEntry e = ChangeLogEntry.constructChangeLogEntry(1L,
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example")));

    assertNotNull(e);

    assertEquals(e.getChangeNumber(), 1L);

    assertEquals(new DN(e.getTargetDN()), new DN("dc=example,dc=com"));

    assertEquals(e.getChangeType(), ChangeType.ADD);

    assertNotNull(e.getAddAttributes());
    assertEquals(e.getAddAttributes().size(), 2);

    assertNull(e.getDeletedEntryAttributes());

    assertNull(e.getModifications());

    assertNull(e.getNewRDN());

    assertNull(e.getNewSuperior());

    assertTrue(e.toLDIFChangeRecord() instanceof LDIFAddChangeRecord);
  }



  /**
   * Tests the ability to create a changelog entry for a delete operation
   * without any deleted entry attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteChangeLogEntryNoDeletedEntryAttributes()
         throws Exception
  {
    ChangeLogEntry e = new ChangeLogEntry(new Entry(
       "dn: changeNumber=2,cn=changelog",
       "objectClass: top",
       "objectClass: changeLogEntry",
       "changeNumber: 2",
       "targetDN: dc=example,dc=com",
       "changeType: delete"));

    assertNotNull(e);

    assertEquals(e.getChangeNumber(), 2L);

    assertEquals(new DN(e.getTargetDN()), new DN("dc=example,dc=com"));

    assertEquals(e.getChangeType(), ChangeType.DELETE);

    assertNull(e.getAddAttributes());

    assertNull(e.getDeletedEntryAttributes());

    assertNull(e.getModifications());

    assertNull(e.getNewRDN());

    assertNull(e.getNewSuperior());

    assertTrue(e.toLDIFChangeRecord() instanceof LDIFDeleteChangeRecord);
  }



  /**
   * Tests the ability to create a changelog entry for a delete operation
   * that includes deleted entry attributes in the style used by the UnboundID
   * Directory Server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteChangeLogEntryWithUnboundIDDeletedEntryAttributes()
         throws Exception
  {
    // Deleted entry attrs representation:
    // objectClass: organizationalUnit{EOL}
    // objectClass: top{EOL}
    // ou: test{EOL}
    // ds-entry-unique-id:: KfsLjzWeQ4G4tjYwFxyWeg=={EOL}
    // ds-create-time:: AAABHSt20p8={EOL}
    // creatorsName: cn=Directory Manager,cn=Root DNs,cn=config{EOL}
    ChangeLogEntry e = new ChangeLogEntry(new Entry(
       "dn: changeNumber=2,cn=changelog",
       "objectClass: top",
       "objectClass: changeLogEntry",
       "changeNumber: 2",
       "targetDN: ou=test,dc=example,dc=com",
       "changeType: delete",
       "deletedEntryAttrs:: b2JqZWN0Q2xhc3M6IG9yZ2FuaXphdGlvbmFsVW5pdApvYmplY" +
            "3RDbGFzczogdG9wCm91OiB0ZXN0CmRzLWVudHJ5LXVuaXF1ZS1pZDo6IEtmc0xqe" +
            "ldlUTRHNHRqWXdGeHlXZWc9PQpkcy1jcmVhdGUtdGltZTo6IEFBQUJIU3QyMHA4P" +
            "QpjcmVhdG9yc05hbWU6IGNuPURpcmVjdG9yeSBNYW5hZ2VyLGNuPVJvb3QgRE5zL" +
            "GNuPWNvbmZpZwo="));

    assertNotNull(e);

    assertEquals(e.getChangeNumber(), 2L);

    assertEquals(new DN(e.getTargetDN()), new DN("ou=test,dc=example,dc=com"));

    assertEquals(e.getChangeType(), ChangeType.DELETE);

    assertNull(e.getAddAttributes());

    assertNotNull(e.getDeletedEntryAttributes());
    assertEquals(e.getDeletedEntryAttributes().size(), 5);

    assertNull(e.getModifications());

    assertNull(e.getNewRDN());

    assertNull(e.getNewSuperior());

    assertTrue(e.toLDIFChangeRecord() instanceof LDIFDeleteChangeRecord);


    Entry deletedEntry = new Entry(e.getTargetDN(),
                                   e.getDeletedEntryAttributes());
    assertTrue(deletedEntry.hasAttributeValue("objectClass", "top"));
    assertTrue(deletedEntry.hasAttributeValue("objectClass",
                                              "organizationalUnit"));
    assertTrue(deletedEntry.hasAttributeValue("ou", "test"));
    assertTrue(deletedEntry.hasAttributeValue("creatorsName",
                                 "cn=Directory Manager,cn=Root DNs,cn=config"));
    assertTrue(deletedEntry.hasAttribute("ds-entry-unique-id"));
    assertTrue(deletedEntry.hasAttribute("ds-create-time"));
  }



  /**
   * Tests the ability to create a changelog entry for a delete operation
   * that includes deleted entry attributes in the style used by Sun DSEE.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteChangeLogEntryWithDSEEDeletedEntryAttributes()
         throws Exception
  {
    // Deleted entry attrs representation:
    // delete: objectClass{EOL}
    // objectClass: top{EOL}
    // objectClass: person{EOL}
    // objectClass: organizationalPerson{EOL}
    // objectClass: inetOrgPerson{EOL}
    // -{EOL}
    // delete: uid{EOL}
    // uid: user.8{EOL}
    // -{EOL}
    // delete: cn{EOL}
    // cn: Abbas Abbatantuono{EOL}
    // -{EOL}
    // {NUL}
    ChangeLogEntry e = new ChangeLogEntry(new Entry(
       "dn: changeNumber=2,cn=changelog",
       "objectClass: top",
       "objectClass: changeLogEntry",
       "changeNumber: 2",
       "targetDN: ou=test,dc=example,dc=com",
       "changeType: delete",
       "deletedEntryAttrs:: ZGVsZXRlOiBvYmplY3RDbGFzcwpvYmplY3RDbGFzczogdG9wC" +
            "m9iamVjdENsYXNzOiBwZXJzb24Kb2JqZWN0Q2xhc3M6IG9yZ2FuaXphdGlvbmFsU" +
            "GVyc29uCm9iamVjdENsYXNzOiBpbmV0T3JnUGVyc29uCi0KZGVsZXRlOiB1aWQKd" +
            "WlkOiB1c2VyLjgKLQpkZWxldGU6IGNuCmNuOiBBYmJhcyBBYmJhdGFudHVvbm8KL" +
            "QoA"));

    assertNotNull(e);

    assertEquals(e.getChangeNumber(), 2L);

    assertEquals(new DN(e.getTargetDN()), new DN("ou=test,dc=example,dc=com"));

    assertEquals(e.getChangeType(), ChangeType.DELETE);

    assertNull(e.getAddAttributes());

    assertNotNull(e.getDeletedEntryAttributes());
    assertEquals(e.getDeletedEntryAttributes().size(), 3);

    assertNull(e.getModifications());

    assertNull(e.getNewRDN());

    assertNull(e.getNewSuperior());

    assertTrue(e.toLDIFChangeRecord() instanceof LDIFDeleteChangeRecord);


    Entry deletedEntry = new Entry(e.getTargetDN(),
                                   e.getDeletedEntryAttributes());
    assertTrue(deletedEntry.hasAttributeValue("objectClass", "top"));
    assertTrue(deletedEntry.hasAttributeValue("objectClass", "person"));
    assertTrue(deletedEntry.hasAttributeValue("objectClass",
                                              "organizationalPerson"));
    assertTrue(deletedEntry.hasAttributeValue("objectClass",
                                              "inetOrgPerson"));
    assertTrue(deletedEntry.hasAttributeValue("uid", "user.8"));
    assertTrue(deletedEntry.hasAttributeValue("cn", "Abbas Abbatantuono"));
  }



  /**
   * Tests the ability to create a changelog entry for a delete operation
   * that includes deleted entry attributes in the style used by OpenDJ.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteChangeLogEntryWithOpenDJDeletedEntryAttributes()
         throws Exception
  {
    // includedAttributes representation:
    // objectClass: top{EOL}
    // objectClass: person{EOL}
    // objectClass: organizationalPerson{EOL}
    // objectClass: inetOrgPerson{EOL}
    ChangeLogEntry e = new ChangeLogEntry(new Entry(
       "dn: changeNumber=12345,cn=changelog",
       "objectClass: changeLogEntry",
       "objectClass: top",
       "changeNumber: 12345",
       "changeTime: 20200820143342Z",
       "changeType: delete",
       "targetDN: uid=test.user,ou=People,dc=example,dc=com",
       "changeInitiatorsName: cn=Directory Manager,cn=Root DNs,cn=config",
       "changeLogCookie: dc=example,dc=com:00000168830dffc908760000025d " +
            "000001740c4a296d290305eadbc7 000001740c4736b620e40004862c " +
            "00000168b9d9513b17360015af64 000001740c46cce32b0a057f9d1a " +
            "000001740c4a2dee2b1409be1aee 0000016883458f673f1800000010 " +
            "00000168831976a677c3000af13a 000001740c4a050753e40003c4b6 " +
            "000001740c4a1f7253830adf218b 000001687df5eb93584c000d1875 " +
            "000001687c61b07e77eb0009491f 000001740c4805533aa20003c48e " +
            "000001740c478300197b0005ed64;",
       "entryDN: changeNumber=12345,cn=changelog",
       "hasSubordinates: false",
       "includedAttributes:: b2JqZWN0Q2xhc3M6IHRvcApvYmplY3RDbGFzczogcGVyc29u" +
            "Cm9iamVjdENsYXNzOiBvcmdhbml6YXRpb25hbFBlcnNvbgpvYmplY3RDbGFzczog" +
            "aW5ldE9yZ1BlcnNvbgo=",
       "numSubordinates: 0",
       "replicaIdentifier: 11028",
       "replicationCSN: 000001740c4a2dee2b1409be1aee",
       "subschemaSubentry: cn=schema",
       "targetEntryUUID: 44026558-60ec-419f-8f6a-8559d2a7e3ef"));

    assertNotNull(e);

    assertEquals(e.getChangeNumber(), 12_345L);

    assertDNsEqual(e.getTargetDN(),
         "uid=test.user,ou=People,dc=example,dc=com");

    assertEquals(e.getChangeType(), ChangeType.DELETE);

    assertNull(e.getAddAttributes());

    assertNotNull(e.getDeletedEntryAttributes());
    assertEquals(e.getDeletedEntryAttributes().size(), 1);
    assertEquals(e.getDeletedEntryAttributes().get(0),
         new Attribute("objectClass", "top", "person", "organizationalPerson",
              "inetOrgPerson"));

    assertNull(e.getModifications());

    assertNull(e.getNewRDN());

    assertNull(e.getNewSuperior());

    assertTrue(e.toLDIFChangeRecord() instanceof LDIFDeleteChangeRecord);


    Entry deletedEntry = new Entry(e.getTargetDN(),
                                   e.getDeletedEntryAttributes());
    assertTrue(deletedEntry.hasAttributeValue("objectClass", "top"));
    assertTrue(deletedEntry.hasAttributeValue("objectClass", "person"));
    assertTrue(deletedEntry.hasAttributeValue("objectClass",
         "organizationalPerson"));
    assertTrue(deletedEntry.hasAttributeValue("objectClass",
         "inetOrgPerson"));
  }



  /**
   * Tests the ability to construct a changelog entry for a delete operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructDeleteChangeLogEntry()
         throws Exception
  {
    final ChangeLogEntry e = ChangeLogEntry.constructChangeLogEntry(2L,
         new LDIFDeleteChangeRecord("dc=example,dc=com"));

    assertNotNull(e);

    assertEquals(e.getChangeNumber(), 2L);

    assertEquals(new DN(e.getTargetDN()), new DN("dc=example,dc=com"));

    assertEquals(e.getChangeType(), ChangeType.DELETE);

    assertNull(e.getAddAttributes());

    assertNull(e.getDeletedEntryAttributes());

    assertNull(e.getModifications());

    assertNull(e.getNewRDN());

    assertNull(e.getNewSuperior());

    assertTrue(e.toLDIFChangeRecord() instanceof LDIFDeleteChangeRecord);
  }



  /**
   * Tests the ability to create a changelog entry for a modify operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyChangeLogEntry()
         throws Exception
  {
    StringBuilder changes = new StringBuilder();
    changes.append("replace: description\n");
    changes.append("description: foo\n");

    ChangeLogEntry e = new ChangeLogEntry(new Entry(
       "dn: changeNumber=2,cn=changelog",
       "objectClass: top",
       "objectClass: changeLogEntry",
       "changeNumber: 2",
       "targetDN: dc=example,dc=com",
       "changeType: modify",
       "changes:: " + Base64.encode(changes.toString())));

    assertNotNull(e);

    assertEquals(e.getChangeNumber(), 2L);

    assertEquals(new DN(e.getTargetDN()), new DN("dc=example,dc=com"));

    assertEquals(e.getChangeType(), ChangeType.MODIFY);

    assertNull(e.getAddAttributes());

    assertNull(e.getDeletedEntryAttributes());

    assertNotNull(e.getModifications());
    assertEquals(e.getModifications().size(), 1);

    assertNull(e.getNewRDN());

    assertNull(e.getNewSuperior());

    assertTrue(e.toLDIFChangeRecord() instanceof LDIFModifyChangeRecord);
  }



  /**
   * Tests the ability to create a changelog entry for a modify operation in
   * which the set of changes has a null-terminator (which isn't really allowed
   * by the specification but appears to be added by some directory servers).
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyChangeLogEntryWithNullTerminatedChanges()
         throws Exception
  {
    StringBuilder changes = new StringBuilder();
    changes.append("replace: description\n");
    changes.append("description: foo\n");
    changes.append('\u0000');

    ChangeLogEntry e = new ChangeLogEntry(new Entry(
       "dn: changeNumber=2,cn=changelog",
       "objectClass: top",
       "objectClass: changeLogEntry",
       "changeNumber: 2",
       "targetDN: dc=example,dc=com",
       "changeType: modify",
       "changes:: " + Base64.encode(changes.toString())));

    assertNotNull(e);

    assertEquals(e.getChangeNumber(), 2L);

    assertEquals(new DN(e.getTargetDN()), new DN("dc=example,dc=com"));

    assertEquals(e.getChangeType(), ChangeType.MODIFY);

    assertNull(e.getAddAttributes());

    assertNull(e.getDeletedEntryAttributes());

    assertNotNull(e.getModifications());
    assertEquals(e.getModifications().size(), 1);

    assertNull(e.getNewRDN());

    assertNull(e.getNewSuperior());

    assertTrue(e.toLDIFChangeRecord() instanceof LDIFModifyChangeRecord);
  }



  /**
   * Tests the ability to create a changelog entry for a modify operation in
   * which there is no changes attribute.  This is technically invalid, but some
   * servers may construct this type of entry under some circumstances.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyChangeLogEntryWithoutChanges()
         throws Exception
  {
    ChangeLogEntry e = new ChangeLogEntry(new Entry(
       "dn: changeNumber=2,cn=changelog",
       "objectClass: top",
       "objectClass: changeLogEntry",
       "changeNumber: 2",
       "targetDN: dc=example,dc=com",
       "changeType: modify"));

    assertNotNull(e);

    assertEquals(e.getChangeNumber(), 2L);

    assertEquals(new DN(e.getTargetDN()), new DN("dc=example,dc=com"));

    assertEquals(e.getChangeType(), ChangeType.MODIFY);

    assertNull(e.getAddAttributes());

    assertNull(e.getDeletedEntryAttributes());

    assertNull(e.getModifications());

    assertNull(e.getNewRDN());

    assertNull(e.getNewSuperior());
  }



  /**
   * Tests the ability to create a changelog entry for a modify operation in
   * which there is a changes attribute with a zero-length value.  This is
   * technically invalid, but some servers may construct this type of entry
   * under some circumstances.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyChangeLogEntryWithZeroLengthChanges()
         throws Exception
  {
    ChangeLogEntry e = new ChangeLogEntry(new Entry(
       "dn: changeNumber=2,cn=changelog",
       "objectClass: top",
       "objectClass: changeLogEntry",
       "changeNumber: 2",
       "targetDN: dc=example,dc=com",
       "changeType: modify",
       "changes: "));

    assertNotNull(e);

    assertEquals(e.getChangeNumber(), 2L);

    assertEquals(new DN(e.getTargetDN()), new DN("dc=example,dc=com"));

    assertEquals(e.getChangeType(), ChangeType.MODIFY);

    assertNull(e.getAddAttributes());

    assertNull(e.getDeletedEntryAttributes());

    assertNull(e.getModifications());

    assertNull(e.getNewRDN());

    assertNull(e.getNewSuperior());
  }



  /**
   * Tests the ability to construct a changelog entry for a modify operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructModifyChangeLogEntry()
         throws Exception
  {
    final ChangeLogEntry e = ChangeLogEntry.constructChangeLogEntry(2L,
         new LDIFModifyChangeRecord("dc=example,dc=com",
              new Modification(ModificationType.REPLACE, "description",
                   "foo")));

    assertNotNull(e);

    assertEquals(e.getChangeNumber(), 2L);

    assertEquals(new DN(e.getTargetDN()), new DN("dc=example,dc=com"));

    assertEquals(e.getChangeType(), ChangeType.MODIFY);

    assertNull(e.getAddAttributes());

    assertNull(e.getDeletedEntryAttributes());

    assertNotNull(e.getModifications());
    assertEquals(e.getModifications().size(), 1);

    assertNull(e.getNewRDN());

    assertNull(e.getNewSuperior());

    assertTrue(e.toLDIFChangeRecord() instanceof LDIFModifyChangeRecord);
  }



  /**
   * Tests the ability to create a changelog entry for a modify DN operation
   * without a new superior.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNChangeLogEntryNoNewSuperior()
         throws Exception
  {
    ChangeLogEntry e = new ChangeLogEntry(new Entry(
       "dn: changeNumber=3,cn=changelog",
       "objectClass: top",
       "objectClass: changeLogEntry",
       "changeNumber: 3",
       "targetDN: ou=People,dc=example,dc=com",
       "changeType: modrdn",
       "newRDN: ou=Users",
       "deleteOldRDN: TRUE"));

    assertNotNull(e);

    assertEquals(e.getChangeNumber(), 3L);

    assertEquals(new DN(e.getTargetDN()),
         new DN("ou=People,dc=example,dc=com"));

    assertEquals(e.getChangeType(), ChangeType.MODIFY_DN);

    assertNull(e.getAddAttributes());

    assertNull(e.getDeletedEntryAttributes());

    assertNull(e.getModifications());

    assertEquals(new RDN(e.getNewRDN()),
                 new RDN("ou=Users"));

    assertTrue(e.deleteOldRDN());

    assertNull(e.getNewSuperior());

    assertTrue(e.toLDIFChangeRecord() instanceof LDIFModifyDNChangeRecord);
  }



  /**
   * Tests the ability to create a changelog entry for a modify DN operation
   * with a new superior.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNChangeLogEntryWithNewSuperior()
         throws Exception
  {
    ChangeLogEntry e = new ChangeLogEntry(new Entry(
       "dn: changeNumber=3,cn=changelog",
       "objectClass: top",
       "objectClass: changeLogEntry",
       "changeNumber: 3",
       "targetDN: ou=People,dc=example,dc=com",
       "changeType: modrdn",
       "newRDN: ou=Users",
       "deleteOldRDN: FALSE",
       "newSuperior: o=example.com"));

    assertNotNull(e);

    assertEquals(e.getChangeNumber(), 3L);

    assertEquals(new DN(e.getTargetDN()),
         new DN("ou=People,dc=example,dc=com"));

    assertEquals(e.getChangeType(), ChangeType.MODIFY_DN);

    assertNull(e.getAddAttributes());

    assertNull(e.getDeletedEntryAttributes());

    assertNull(e.getModifications());

    assertEquals(new RDN(e.getNewRDN()),
                 new RDN("ou=Users"));

    assertFalse(e.deleteOldRDN());

    assertEquals(new DN(e.getNewSuperior()),
         new DN("o=example.com"));

    assertTrue(e.toLDIFChangeRecord() instanceof LDIFModifyDNChangeRecord);
  }



  /**
   * Tests the ability to create a changelog entry for a modify DN operation
   * with additional changes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNChangeLogEntryWithAdditionalChanges()
         throws Exception
  {
    StringBuilder changes = new StringBuilder();
    changes.append("replace: modifiersName\n");
    changes.append("modifiersName: uid=admin,dc=example,dc=com\n");
    changes.append("-\n");
    changes.append("replace: modifyTimestamp\n");
    changes.append("modifyTimestamp: 20080101000000Z\n");

    ChangeLogEntry e = new ChangeLogEntry(new Entry(
       "dn: changeNumber=3,cn=changelog",
       "objectClass: top",
       "objectClass: changeLogEntry",
       "changeNumber: 3",
       "targetDN: ou=People,dc=example,dc=com",
       "changeType: modrdn",
       "newRDN: ou=Users",
       "deleteOldRDN: FALSE",
       "newSuperior: o=example.com",
       "changes:: " + Base64.encode(changes.toString())));

    assertNotNull(e);

    assertEquals(e.getChangeNumber(), 3L);

    assertEquals(new DN(e.getTargetDN()),
                 new DN("ou=People,dc=example,dc=com"));

    assertEquals(e.getChangeType(), ChangeType.MODIFY_DN);

    assertNull(e.getAddAttributes());

    assertNull(e.getDeletedEntryAttributes());

    assertNotNull(e.getModifications());
    assertEquals(e.getModifications().size(), 2);

    assertEquals(new RDN(e.getNewRDN()),
                 new RDN("ou=Users"));

    assertFalse(e.deleteOldRDN());

    assertEquals(new DN(e.getNewSuperior()),
         new DN("o=example.com"));

    assertTrue(e.toLDIFChangeRecord() instanceof LDIFModifyDNChangeRecord);
  }



  /**
   * Tests the ability to construct a changelog entry for a modify DN operation
   * without a new superior.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructModifyDNChangeLogEntryNoNewSuperior()
         throws Exception
  {
    final ChangeLogEntry e = ChangeLogEntry.constructChangeLogEntry(3L,
         new LDIFModifyDNChangeRecord("ou=People,dc=example,dc=com",
              "ou=Users", true, null));

    assertNotNull(e);

    assertEquals(e.getChangeNumber(), 3L);

    assertEquals(new DN(e.getTargetDN()),
                 new DN("ou=People,dc=example,dc=com"));

    assertEquals(e.getChangeType(), ChangeType.MODIFY_DN);

    assertNull(e.getAddAttributes());

    assertNull(e.getDeletedEntryAttributes());

    assertNull(e.getModifications());

    assertEquals(new RDN(e.getNewRDN()),
                 new RDN("ou=Users"));

    assertTrue(e.deleteOldRDN());

    assertNull(e.getNewSuperior());

    assertTrue(e.toLDIFChangeRecord() instanceof LDIFModifyDNChangeRecord);
  }



  /**
   * Tests the ability to construct a changelog entry for a modify DN operation
   * with a new superior.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructModifyDNChangeLogEntryWithNewSuperior()
         throws Exception
  {
    final ChangeLogEntry e = ChangeLogEntry.constructChangeLogEntry(3L,
         new LDIFModifyDNChangeRecord("ou=People,dc=example,dc=com",
              "ou=Users", true, "o=example.com"));

    assertNotNull(e);

    assertEquals(e.getChangeNumber(), 3L);

    assertEquals(new DN(e.getTargetDN()),
         new DN("ou=People,dc=example,dc=com"));

    assertEquals(e.getChangeType(), ChangeType.MODIFY_DN);

    assertNull(e.getAddAttributes());

    assertNull(e.getDeletedEntryAttributes());

    assertNull(e.getModifications());

    assertEquals(new RDN(e.getNewRDN()),
                 new RDN("ou=Users"));

    assertTrue(e.deleteOldRDN());

    assertEquals(new DN(e.getNewSuperior()),
                 new DN("o=example.com"));

    assertTrue(e.toLDIFChangeRecord() instanceof LDIFModifyDNChangeRecord);
  }



  /**
   * Tests to ensure that a number of types of invalid entries cannot be
   * parsed as changelog entries.
   *
   * @param  e  The entry to use to try to create the changelog entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "invalidEntries",
        expectedExceptions = { LDAPException.class })
  public void testInvalidEntries(final Entry e)
         throws Exception
  {
    new ChangeLogEntry(e);
  }



  /**
   * Creates a set of invalid entries that cannot be used to create changelog
   * entries.
   *
   * @return  A set of invalid entries that cannot be used to create changelog
   *          entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name = "invalidEntries")
  public Object[][] getInvalidEntries()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        // No change number.
        new Entry(
             "dn: cn=No Change Number,cn=changelog",
             "objectClass: top",
             "objectClass: changeLogEntry",
             "targetDN: dc=example,dc=com",
             "changeType: delete")
      },

      new Object[]
      {
        // Malformed change number.
        new Entry(
             "dn: changeNumber=invalid,cn=changelog",
             "objectClass: top",
             "objectClass: changeLogEntry",
             "changeNumber: invalid",
             "targetDN: dc=example,dc=com",
             "changeType: delete")
      },

      new Object[]
      {
        // No target DN
        new Entry(
             "dn: changeNumber=1,cn=changelog",
             "objectClass: top",
             "objectClass: changeLogEntry",
             "changeNumber: 1",
             "changeType: delete")
      },

      new Object[]
      {
        // No change type
        new Entry(
             "dn: changeNumber=1,cn=changelog",
             "objectClass: top",
             "objectClass: changeLogEntry",
             "changeNumber: 1",
             "targetDN: dc=example,dc=com")
      },

      new Object[]
      {
        // Invalid change type
        new Entry(
             "dn: changeNumber=1,cn=changelog",
             "objectClass: top",
             "objectClass: changeLogEntry",
             "changeNumber: 1",
             "targetDN: dc=example,dc=com",
             "changeType: invalid")
      },

      new Object[]
      {
        // No changes for an add
        new Entry(
             "dn: changeNumber=1,cn=changelog",
             "objectClass: top",
             "objectClass: changeLogEntry",
             "changeNumber: 1",
             "targetDN: dc=example,dc=com",
             "changeType: add")
      },

      new Object[]
      {
        // Malformed changes for an add
        new Entry(
             "dn: changeNumber=1,cn=changelog",
             "objectClass: top",
             "objectClass: changeLogEntry",
             "changeNumber: 1",
             "targetDN: dc=example,dc=com",
             "changeType: add",
             "changes: malformed")
      },

      new Object[]
      {
        // Malformed changes for a modify
        new Entry(
             "dn: changeNumber=1,cn=changelog",
             "objectClass: top",
             "objectClass: changeLogEntry",
             "changeNumber: 1",
             "targetDN: dc=example,dc=com",
             "changeType: modify",
             "changes: malformed")
      },

      new Object[]
      {
        // No newRDN for a modify DN.
        new Entry(
             "dn: changeNumber=1,cn=changelog",
             "objectClass: top",
             "objectClass: changeLogEntry",
             "changeNumber: 1",
             "targetDN: ou=People,dc=example,dc=com",
             "changeType: modrdn",
             "deleteOldRDN: TRUE")
      },

      new Object[]
      {
        // No deleteOldRDN for a modify DN.
        new Entry(
             "dn: changeNumber=1,cn=changelog",
             "objectClass: top",
             "objectClass: changeLogEntry",
             "changeNumber: 1",
             "targetDN: ou=People,dc=example,dc=com",
             "changeType: modrdn",
             "newRDN: ou=Users")
      },

      new Object[]
      {
        // Malformed deleteOldRDN for a modify DN.
        new Entry(
             "dn: changeNumber=1,cn=changelog",
             "objectClass: top",
             "objectClass: changeLogEntry",
             "changeNumber: 1",
             "targetDN: ou=People,dc=example,dc=com",
             "changeType: modrdn",
             "newRDN: ou=Users",
             "deleteOldRDN: invalid")
      },
    };
  }



  /**
   * Tests the {@code processChange} method for each of the change types.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcessChange()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());


    // Test an add operation.
    StringBuilder changes = new StringBuilder();
    changes.append("objectClass: top\n");
    changes.append("objectClass: organizationalUnit\n");
    changes.append("ou: People\n");

    ChangeLogEntry e = new ChangeLogEntry(new Entry(
       "dn: changeNumber=1,cn=changelog",
       "objectClass: top",
       "objectClass: changeLogEntry",
       "changeNumber: 1",
       "targetDN: ou=People," + getTestBaseDN(),
       "changeType: add",
       "changes:: " + Base64.encode(changes.toString())));

    assertEquals(e.processChange(conn).getResultCode(),
                 ResultCode.SUCCESS);


    // Test a modify operation.
    changes = new StringBuilder();
    changes.append("replace: description\n");
    changes.append("description: foo\n");

    e = new ChangeLogEntry(new Entry(
       "dn: changeNumber=2,cn=changelog",
       "objectClass: top",
       "objectClass: changeLogEntry",
       "changeNumber: 2",
       "targetDN: ou=People," + getTestBaseDN(),
       "changeType: modify",
       "changes:: " + Base64.encode(changes.toString())));

    assertEquals(e.processChange(conn).getResultCode(),
                 ResultCode.SUCCESS);


    // Test a modify DN operation.
    e = new ChangeLogEntry(new Entry(
       "dn: changeNumber=3,cn=changelog",
       "objectClass: top",
       "objectClass: changeLogEntry",
       "changeNumber: 3",
       "targetDN: ou=People," + getTestBaseDN(),
       "changeType: modrdn",
       "newRDN: ou=Users",
       "deleteOldRDN: TRUE"));

    assertEquals(e.processChange(conn).getResultCode(),
                 ResultCode.SUCCESS);


    // Test a delete operation.
    e = new ChangeLogEntry(new Entry(
       "dn: changeNumber=4,cn=changelog",
       "objectClass: top",
       "objectClass: changeLogEntry",
       "changeNumber: 4",
       "targetDN: ou=Users," + getTestBaseDN(),
       "changeType: delete"));

    assertEquals(e.processChange(conn).getResultCode(),
                 ResultCode.SUCCESS);


    conn.delete(getTestBaseDN());
    conn.close();
  }



  /**
   * Provides test coverage for the {@code getNewDN} method with various types
   * of changes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetNewDN()
         throws Exception
  {
    // For add and modify operations, the new DN should always be the same as
    // the target DN.
    ChangeLogEntry e = ChangeLogEntry.constructChangeLogEntry(1L,
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example")));
    assertEquals(new DN(e.getNewDN()), new DN("dc=example,dc=com"));

    e = ChangeLogEntry.constructChangeLogEntry(2L,
         new LDIFModifyChangeRecord("dc=example,dc=com",
              new Modification(ModificationType.REPLACE, "description",
                   "foo")));
    assertEquals(new DN(e.getNewDN()), new DN("dc=example,dc=com"));


    // For delete operations, the new DN should always be null.
    e = ChangeLogEntry.constructChangeLogEntry(3L,
         new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertNull(e.getNewDN());


    // For modify DN operations, then the new DN will depend on whether or not
    // there's a new superior DN.
    e = ChangeLogEntry.constructChangeLogEntry(4L,
         new LDIFModifyDNChangeRecord("ou=People,dc=example,dc=com", "ou=Users",
              true, null));
    assertEquals(new DN(e.getNewDN()), new DN("ou=Users,dc=example,dc=com"));

    e = ChangeLogEntry.constructChangeLogEntry(5L,
         new LDIFModifyDNChangeRecord("ou=People,dc=example,dc=com", "ou=Users",
              true, "o=example.com"));
    assertEquals(new DN(e.getNewDN()), new DN("ou=Users,o=example.com"));

    e = ChangeLogEntry.constructChangeLogEntry(6L,
         new LDIFModifyDNChangeRecord("o=example.com", "o=example.net",
              true, null));
    assertEquals(new DN(e.getNewDN()), new DN("o=example.net"));
  }
}
