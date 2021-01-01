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
package com.unboundid.ldap.sdk.unboundidds;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.ChangeLogEntry;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFModifyDNChangeRecord;
import com.unboundid.util.StaticUtils;



/**
 * This class provides test coverage for the UnboundID-specific changelog entry
 * content.
 */
public final class UnboundIDChangeLogEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides coverage for cases in which an UnboundID changelog entry is
   * created for an add operation without any UnboundID-specific content.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicAddChangeLogEntry()
         throws Exception
  {
    final ChangeLogEntry e = ChangeLogEntry.constructChangeLogEntry(1L,
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example")));
    assertNotNull(e);

    final UnboundIDChangeLogEntry ue = new UnboundIDChangeLogEntry(e);
    assertNotNull(ue);

    assertEquals(ue.getChangeNumber(), 1L);

    assertNotNull(ue.getTargetDN());
    assertEquals(new DN(ue.getTargetDN()), new DN("dc=example,dc=com"));

    assertNotNull(ue.getChangeType());
    assertEquals(ue.getChangeType(), ChangeType.ADD);

    assertNotNull(ue.getAddAttributes());
    assertEquals(ue.getAddAttributes().size(), 2);
    assertTrue(ue.getAddAttributes().contains(
         new Attribute("objectClass", "top", "domain")));
    assertTrue(ue.getAddAttributes().contains(new Attribute("dc", "example")));

    assertNotNull(ue.getAddAttributes(true));
    assertEquals(ue.getAddAttributes(true).size(), 2);
    assertTrue(ue.getAddAttributes(true).contains(
         new Attribute("objectClass", "top", "domain")));
    assertTrue(ue.getAddAttributes(true).contains(
         new Attribute("dc", "example")));

    assertNotNull(ue.getAddVirtualAttributes());
    assertTrue(ue.getAddVirtualAttributes().isEmpty());

    assertNull(ue.getDeletedEntryAttributes());

    assertNull(ue.getDeletedEntryAttributes(true));

    assertNull(ue.getDeletedEntryVirtualAttributes());

    assertNull(ue.getModifications());

    assertNull(ue.getNewRDN());

    assertFalse(ue.deleteOldRDN());

    assertNull(ue.getNewSuperior());

    assertNull(ue.getSoftDeleteToDN());

    assertNull(ue.getUndeleteFromDN());

    assertNull(ue.getChangeToSoftDeletedEntry());

    assertNotNull(ue.getNewDN());
    assertEquals(new DN(ue.getNewDN()), new DN("dc=example,dc=com"));

    assertNotNull(ue.getUpdatedAttributesBeforeChange());
    assertTrue(ue.getUpdatedAttributesBeforeChange().isEmpty());

    assertNotNull(ue.getUpdatedAttributesBeforeChange(true));
    assertTrue(ue.getUpdatedAttributesBeforeChange(true).isEmpty());

    assertNotNull(ue.getUpdatedVirtualAttributesBeforeChange());
    assertTrue(ue.getUpdatedVirtualAttributesBeforeChange().isEmpty());

    assertNotNull(ue.getUpdatedAttributesAfterChange());
    assertTrue(ue.getUpdatedAttributesAfterChange().isEmpty());

    assertNotNull(ue.getUpdatedAttributesAfterChange(true));
    assertTrue(ue.getUpdatedAttributesAfterChange(true).isEmpty());

    assertNotNull(ue.getUpdatedVirtualAttributesAfterChange());
    assertTrue(ue.getUpdatedVirtualAttributesAfterChange().isEmpty());

    assertNotNull(ue.getAttributesThatExceededMaxValuesCount());
    assertTrue(ue.getAttributesThatExceededMaxValuesCount().isEmpty());

    assertNotNull(ue.getVirtualAttributesThatExceededMaxValuesCount());
    assertTrue(ue.getVirtualAttributesThatExceededMaxValuesCount().isEmpty());

    assertNotNull(ue.getKeyEntryAttributes());
    assertTrue(ue.getKeyEntryAttributes().isEmpty());

    assertNotNull(ue.getKeyEntryAttributes(true));
    assertTrue(ue.getKeyEntryAttributes(true).isEmpty());

    assertNotNull(ue.getKeyEntryVirtualAttributes());
    assertTrue(ue.getKeyEntryVirtualAttributes().isEmpty());

    assertEquals(ue.getNumExcludedUserAttributes(), -1);

    assertEquals(ue.getNumExcludedOperationalAttributes(), -1);

    assertNotNull(ue.getExcludedUserAttributeNames());
    assertTrue(ue.getExcludedUserAttributeNames().isEmpty());

    assertNotNull(ue.getExcludedOperationalAttributeNames());
    assertTrue(ue.getExcludedOperationalAttributeNames().isEmpty());

    assertNull(ue.getAttributeBeforeChange("dc"));

    assertNull(ue.getAttributeBeforeChange("dc", true));

    assertNotNull(ue.getAttributeAfterChange("dc"));
    assertEquals(ue.getAttributeAfterChange("dc"),
         new Attribute("dc", "example"));

    assertNotNull(ue.getAttributeAfterChange("dc", true));
    assertEquals(ue.getAttributeAfterChange("dc", true),
         new Attribute("dc", "example"));

    assertNull(ue.getAttributeAfterChange("missing"));

    assertNull(ue.getAttributeAfterChange("missing", true));

    assertNull(ue.constructPartialEntryBeforeChange());

    assertNull(ue.constructPartialEntryBeforeChange(true));

    assertNotNull(ue.constructPartialEntryAfterChange());
    assertEquals(ue.constructPartialEntryAfterChange(), new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    assertNotNull(ue.constructPartialEntryAfterChange(true));
    assertEquals(ue.constructPartialEntryAfterChange(true), new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    assertNull(ue.getTargetUniqueID());

    assertNull(ue.getLocalCSN());

    assertNull(ue.getChangeTime());

    assertNotNull(ue.getTargetAttributeNames());
    assertTrue(ue.getTargetAttributeNames().isEmpty());

    assertNotNull(ue.getNotificationDestinationEntryUUIDs());
    assertTrue(ue.getNotificationDestinationEntryUUIDs().isEmpty());

    assertNotNull(ue.getNotificationProperties());
    assertTrue(ue.getNotificationProperties().isEmpty());
  }



  /**
   * Provides coverage for cases in which an UnboundID changelog entry is
   * created for an add operation with an extended set of content.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedAddChangeLogEntry()
         throws Exception
  {
    // Create the basic entry.
    final ChangeLogEntry e = ChangeLogEntry.constructChangeLogEntry(3L,
         new LDIFAddChangeRecord(new Entry(
              "dn: uid=test.user,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: test.user",
              "givenName: Test",
              "sn: User",
              "cn: Test User")));
    assertNotNull(e);

    // Construct virtual attributes for the entry.
    final StringBuilder virtualAttrBuffer = new StringBuilder();
    virtualAttrBuffer.append("cn: Virtual cn");
    virtualAttrBuffer.append(StaticUtils.EOL);
    virtualAttrBuffer.append("description: Virtual description");
    virtualAttrBuffer.append(StaticUtils.EOL);

    // Construct a key attribute value for the "cn" attribute.
    final StringBuilder keyAttrBuffer = new StringBuilder();
    keyAttrBuffer.append("cn: Test User");
    keyAttrBuffer.append(StaticUtils.EOL);

    // Construct a key virtual attribute value for the "cn" attribute.
    final StringBuilder keyVirtualAttrBuffer = new StringBuilder();
    keyVirtualAttrBuffer.append("cn: Virtual cn");
    keyVirtualAttrBuffer.append(StaticUtils.EOL);

    final Entry extendedEntry = e.duplicate();
    extendedEntry.addAttribute("ds-changelog-virtual-attributes",
         virtualAttrBuffer.toString());
    extendedEntry.addAttribute("ds-changelog-entry-key-attr-values",
         keyAttrBuffer.toString());
    extendedEntry.addAttribute("ds-changelog-entry-key-virtual-values",
         keyVirtualAttrBuffer.toString());
    extendedEntry.addAttribute(
         "ds-changelog-num-excluded-user-attributes", "2");
    extendedEntry.addAttribute(
         "ds-changelog-num-excluded-operational-attributes", "3");
    extendedEntry.addAttribute(
         "ds-changelog-excluded-user-attribute", "description", "userPassword");
    extendedEntry.addAttribute(
         "ds-changelog-excluded-operational-attribute", "creatorsName",
         "createTimestamp", "entryUUID");
    extendedEntry.addAttribute("targetUniqueID",
         "468c6887-4fcc-38ea-9425-abcaa3c88be6");
    extendedEntry.addAttribute("localCSN", "00000131EDEDD535000000000006");
    extendedEntry.addAttribute("changeTime", "20110821200012Z");
    extendedEntry.addAttribute("ds-undelete-from-dn",
         "entryUUID=468c6887-4fcc-38ea-9425-abcaa3c88be6+uid=test.user," +
              "ou=People,dc=example,dc=com");
    extendedEntry.addAttribute("ds-changelog-target-attribute", "objectClass",
         "uid", "givenName", "sn", "cn");
    extendedEntry.addAttribute("ds-notification-destination-entry-uuid",
         "12345678-90ab-cdef-1234-567890abcdef",
         "23456789-0abC-def1-2345-67890abcdef1");
    extendedEntry.addAttribute("ds-changelog-notification-properties",
         "notification-property-1", "notification-property-2",
         "notification-property-3");

    final UnboundIDChangeLogEntry ue =
         new UnboundIDChangeLogEntry(extendedEntry);
    assertNotNull(ue);

    assertEquals(ue.getChangeNumber(), 3L);

    assertNotNull(ue.getTargetDN());
    assertEquals(new DN(ue.getTargetDN()),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));

    assertNotNull(ue.getChangeType());
    assertEquals(ue.getChangeType(), ChangeType.ADD);

    assertNotNull(ue.getAddAttributes());
    assertEquals(ue.getAddAttributes().size(), 5);
    assertTrue(ue.getAddAttributes().contains(new Attribute("objectClass",
         "top", "person", "organizationalPerson", "inetOrgPerson")));
    assertTrue(ue.getAddAttributes().contains(
         new Attribute("uid", "test.user")));
    assertTrue(ue.getAddAttributes().contains(
         new Attribute("givenName", "Test")));
    assertTrue(ue.getAddAttributes().contains(
         new Attribute("sn", "User")));
    assertTrue(ue.getAddAttributes().contains(
         new Attribute("cn", "Test User")));
    assertFalse(ue.getAddAttributes().contains(
         new Attribute("cn", "Virtual cn")));
    assertFalse(ue.getAddAttributes().contains(
         new Attribute("description", "Virtual description")));

    assertNotNull(ue.getAddAttributes(true));
    assertEquals(ue.getAddAttributes(true).size(), 6);
    assertTrue(ue.getAddAttributes(true).contains(new Attribute("objectClass",
         "top", "person", "organizationalPerson", "inetOrgPerson")));
    assertTrue(ue.getAddAttributes(true).contains(
         new Attribute("uid", "test.user")));
    assertTrue(ue.getAddAttributes(true).contains(
         new Attribute("givenName", "Test")));
    assertTrue(ue.getAddAttributes(true).contains(
         new Attribute("sn", "User")));
    assertTrue(ue.getAddAttributes(true).contains(
         new Attribute("cn", "Test User", "Virtual cn")));
    assertTrue(ue.getAddAttributes(true).contains(
         new Attribute("description", "Virtual description")));

    assertNull(ue.getDeletedEntryAttributes());

    assertNull(ue.getDeletedEntryAttributes(true));

    assertNull(ue.getDeletedEntryVirtualAttributes());

    assertNull(ue.getModifications());

    assertNull(ue.getNewRDN());

    assertFalse(ue.deleteOldRDN());

    assertNull(ue.getNewSuperior());

    assertNotNull(ue.getNewDN());
    assertEquals(new DN(ue.getNewDN()),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));

    assertNull(ue.getSoftDeleteToDN());

    assertNotNull(ue.getUndeleteFromDN());

    assertNull(ue.getChangeToSoftDeletedEntry());

    assertNotNull(ue.getUpdatedAttributesBeforeChange());
    assertTrue(ue.getUpdatedAttributesBeforeChange().isEmpty());

    assertNotNull(ue.getUpdatedAttributesBeforeChange(true));
    assertTrue(ue.getUpdatedAttributesBeforeChange(true).isEmpty());

    assertNotNull(ue.getUpdatedVirtualAttributesBeforeChange());
    assertTrue(ue.getUpdatedVirtualAttributesBeforeChange().isEmpty());

    assertNotNull(ue.getUpdatedAttributesAfterChange());
    assertTrue(ue.getUpdatedAttributesAfterChange().isEmpty());

    assertNotNull(ue.getUpdatedAttributesAfterChange(true));
    assertTrue(ue.getUpdatedAttributesAfterChange(true).isEmpty());

    assertNotNull(ue.getUpdatedVirtualAttributesAfterChange());
    assertTrue(ue.getUpdatedVirtualAttributesAfterChange().isEmpty());

    assertNotNull(ue.getAttributesThatExceededMaxValuesCount());
    assertTrue(ue.getAttributesThatExceededMaxValuesCount().isEmpty());

    assertNotNull(ue.getVirtualAttributesThatExceededMaxValuesCount());
    assertTrue(ue.getVirtualAttributesThatExceededMaxValuesCount().isEmpty());

    assertNotNull(ue.getKeyEntryAttributes());
    assertEquals(ue.getKeyEntryAttributes().size(), 1);
    assertTrue(ue.getKeyEntryAttributes().contains(
         new Attribute("cn", "Test User")));
    assertFalse(ue.getKeyEntryAttributes().contains(
         new Attribute("cn", "Virtual cn")));

    assertNotNull(ue.getKeyEntryAttributes(true));
    assertEquals(ue.getKeyEntryAttributes(true).size(), 1);
    assertTrue(ue.getKeyEntryAttributes(true).contains(
         new Attribute("cn", "Test User", "Virtual cn")));

    assertNotNull(ue.getKeyEntryVirtualAttributes());
    assertEquals(ue.getKeyEntryVirtualAttributes().size(), 1);
    assertTrue(ue.getKeyEntryVirtualAttributes().contains(
         new Attribute("cn", "Virtual cn")));
    assertFalse(ue.getKeyEntryVirtualAttributes().contains(
         new Attribute("cn", "Test User")));

    assertEquals(ue.getNumExcludedUserAttributes(), 2);

    assertEquals(ue.getNumExcludedOperationalAttributes(), 3);

    assertNotNull(ue.getExcludedUserAttributeNames());
    assertFalse(ue.getExcludedUserAttributeNames().isEmpty());
    assertTrue(ue.getExcludedUserAttributeNames().contains("description"));
    assertTrue(ue.getExcludedUserAttributeNames().contains("userPassword"));

    assertNotNull(ue.getExcludedOperationalAttributeNames());
    assertFalse(ue.getExcludedOperationalAttributeNames().isEmpty());
    assertTrue(ue.getExcludedOperationalAttributeNames().contains(
         "creatorsName"));
    assertTrue(ue.getExcludedOperationalAttributeNames().contains(
         "createTimestamp"));
    assertTrue(ue.getExcludedOperationalAttributeNames().contains(
         "entryUUID"));

    assertNull(ue.getAttributeBeforeChange("uid"));

    assertNull(ue.getAttributeBeforeChange("uid", true));

    assertNotNull(ue.getAttributeAfterChange("uid"));
    assertEquals(ue.getAttributeAfterChange("uid"),
         new Attribute("uid", "test.user"));

    assertNotNull(ue.getAttributeAfterChange("uid", true));
    assertEquals(ue.getAttributeAfterChange("uid", true),
         new Attribute("uid", "test.user"));

    assertNotNull(ue.getAttributeAfterChange("cn"));
    assertEquals(ue.getAttributeAfterChange("cn"),
         new Attribute("cn", "Test User"));

    assertNotNull(ue.getAttributeAfterChange("cn", true));
    assertEquals(ue.getAttributeAfterChange("cn", true),
         new Attribute("cn", "Test User", "Virtual cn"));

    assertNull(ue.getAttributeAfterChange("missing"));

    assertNull(ue.getAttributeAfterChange("missing", true));

    assertNull(ue.getAttributeAfterChange("description"));

    assertNotNull(ue.getAttributeAfterChange("description", true));
    assertEquals(ue.getAttributeAfterChange("description", true),
         new Attribute("description", "Virtual description"));

    assertNull(ue.constructPartialEntryBeforeChange());

    assertNull(ue.constructPartialEntryBeforeChange(true));

    assertNotNull(ue.constructPartialEntryAfterChange());
    assertEquals(ue.constructPartialEntryAfterChange(), new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User"));

    assertNotNull(ue.constructPartialEntryAfterChange(true));
    assertEquals(ue.constructPartialEntryAfterChange(true), new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "cn: Virtual cn",
         "description: Virtual description"));

    assertNotNull(ue.getTargetUniqueID());
    assertEquals(ue.getTargetUniqueID(),
         "468c6887-4fcc-38ea-9425-abcaa3c88be6");

    assertNotNull(ue.getLocalCSN());
    assertEquals(ue.getLocalCSN(), "00000131EDEDD535000000000006");

    assertNotNull(ue.getChangeTime());
    assertEquals(ue.getChangeTime().getTime(),
         StaticUtils.decodeGeneralizedTime("20110821200012Z").getTime());

    assertNotNull(ue.getTargetAttributeNames());
    assertFalse(ue.getTargetAttributeNames().isEmpty());
    assertEquals(ue.getTargetAttributeNames().size(), 5);

    assertNotNull(ue.getNotificationDestinationEntryUUIDs());
    assertFalse(ue.getNotificationDestinationEntryUUIDs().isEmpty());
    assertEquals(ue.getNotificationDestinationEntryUUIDs().size(), 2);

    assertNotNull(ue.getNotificationProperties());
    assertFalse(ue.getNotificationProperties().isEmpty());
    assertEquals(ue.getNotificationProperties().size(), 3);
  }



  /**
   * Provides coverage for cases in which an UnboundID changelog entry is
   * created for a delete operation without any UnboundID-specific content.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicDeleteChangeLogEntry()
         throws Exception
  {
    final ChangeLogEntry e = ChangeLogEntry.constructChangeLogEntry(2L,
         new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertNotNull(e);

    final UnboundIDChangeLogEntry ue = new UnboundIDChangeLogEntry(e);
    assertNotNull(ue);

    assertEquals(ue.getChangeNumber(), 2L);

    assertNotNull(ue.getTargetDN());
    assertEquals(new DN(ue.getTargetDN()), new DN("dc=example,dc=com"));

    assertNotNull(ue.getChangeType());
    assertEquals(ue.getChangeType(), ChangeType.DELETE);

    assertNull(ue.getAddAttributes());

    assertNull(ue.getAddAttributes(true));

    assertNull(ue.getAddVirtualAttributes());

    assertNull(ue.getDeletedEntryAttributes());

    assertNull(ue.getDeletedEntryAttributes(true));

    assertNotNull(ue.getDeletedEntryVirtualAttributes());
    assertTrue(ue.getDeletedEntryVirtualAttributes().isEmpty());

    assertNull(ue.getModifications());

    assertNull(ue.getNewRDN());

    assertFalse(ue.deleteOldRDN());

    assertNull(ue.getNewSuperior());

    assertNull(ue.getSoftDeleteToDN());

    assertNull(ue.getUndeleteFromDN());

    assertNull(ue.getChangeToSoftDeletedEntry());

    assertNull(ue.getNewDN());

    assertNotNull(ue.getUpdatedAttributesBeforeChange());
    assertTrue(ue.getUpdatedAttributesBeforeChange().isEmpty());

    assertNotNull(ue.getUpdatedAttributesBeforeChange(true));
    assertTrue(ue.getUpdatedAttributesBeforeChange(true).isEmpty());

    assertNotNull(ue.getUpdatedVirtualAttributesBeforeChange());
    assertTrue(ue.getUpdatedVirtualAttributesBeforeChange().isEmpty());

    assertNotNull(ue.getUpdatedAttributesAfterChange());
    assertTrue(ue.getUpdatedAttributesAfterChange().isEmpty());

    assertNotNull(ue.getUpdatedAttributesAfterChange(true));
    assertTrue(ue.getUpdatedAttributesAfterChange(true).isEmpty());

    assertNotNull(ue.getUpdatedVirtualAttributesAfterChange());
    assertTrue(ue.getUpdatedVirtualAttributesAfterChange().isEmpty());

    assertNotNull(ue.getAttributesThatExceededMaxValuesCount());
    assertTrue(ue.getAttributesThatExceededMaxValuesCount().isEmpty());

    assertNotNull(ue.getVirtualAttributesThatExceededMaxValuesCount());
    assertTrue(ue.getVirtualAttributesThatExceededMaxValuesCount().isEmpty());

    assertNotNull(ue.getKeyEntryAttributes());
    assertTrue(ue.getKeyEntryAttributes().isEmpty());

    assertNotNull(ue.getKeyEntryAttributes(true));
    assertTrue(ue.getKeyEntryAttributes(true).isEmpty());

    assertNotNull(ue.getKeyEntryVirtualAttributes());
    assertTrue(ue.getKeyEntryVirtualAttributes().isEmpty());

    assertEquals(ue.getNumExcludedUserAttributes(), -1);

    assertEquals(ue.getNumExcludedOperationalAttributes(), -1);

    assertNotNull(ue.getExcludedUserAttributeNames());
    assertTrue(ue.getExcludedUserAttributeNames().isEmpty());

    assertNotNull(ue.getExcludedOperationalAttributeNames());
    assertTrue(ue.getExcludedOperationalAttributeNames().isEmpty());

    assertNull(ue.getAttributeBeforeChange("dc"));

    assertNull(ue.getAttributeBeforeChange("dc", true));

    assertNull(ue.getAttributeAfterChange("dc"));

    assertNull(ue.getAttributeAfterChange("dc", true));

    assertNotNull(ue.constructPartialEntryBeforeChange());
    assertEquals(ue.constructPartialEntryBeforeChange(),
         new Entry("dc=example,dc=com"));

    assertNotNull(ue.constructPartialEntryBeforeChange(true));
    assertEquals(ue.constructPartialEntryBeforeChange(true),
         new Entry("dc=example,dc=com"));

    assertNull(ue.constructPartialEntryAfterChange());

    assertNull(ue.constructPartialEntryAfterChange(true));

    assertNull(ue.getTargetUniqueID());

    assertNull(ue.getLocalCSN());

    assertNull(ue.getChangeTime());

    assertNotNull(ue.getTargetAttributeNames());
    assertTrue(ue.getTargetAttributeNames().isEmpty());

    assertNotNull(ue.getNotificationDestinationEntryUUIDs());
    assertTrue(ue.getNotificationDestinationEntryUUIDs().isEmpty());

    assertNotNull(ue.getNotificationProperties());
    assertTrue(ue.getNotificationProperties().isEmpty());
  }



  /**
   * Provides coverage for cases in which an UnboundID changelog entry is
   * created for a delete operation without an extended set of content.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedDeleteChangeLogEntry()
         throws Exception
  {
    final ChangeLogEntry e = ChangeLogEntry.constructChangeLogEntry(4L,
         new LDIFDeleteChangeRecord(
              "uid=test.user,ou=People,dc=example,dc=com"));
    assertNotNull(e);

    // Construct a set of deleted entry attributes.
    final StringBuilder deletedAttrsBuffer = new StringBuilder();
    deletedAttrsBuffer.append("objectClass: top");
    deletedAttrsBuffer.append(StaticUtils.EOL);
    deletedAttrsBuffer.append("objectClass: person");
    deletedAttrsBuffer.append(StaticUtils.EOL);
    deletedAttrsBuffer.append("objectClass: organizationalPerson");
    deletedAttrsBuffer.append(StaticUtils.EOL);
    deletedAttrsBuffer.append("objectClass: inetOrgPerson");
    deletedAttrsBuffer.append(StaticUtils.EOL);
    deletedAttrsBuffer.append("uid: test.user");
    deletedAttrsBuffer.append(StaticUtils.EOL);
    deletedAttrsBuffer.append("givenName: Test");
    deletedAttrsBuffer.append(StaticUtils.EOL);
    deletedAttrsBuffer.append("sn: User");
    deletedAttrsBuffer.append(StaticUtils.EOL);
    deletedAttrsBuffer.append("cn: Test User");
    deletedAttrsBuffer.append(StaticUtils.EOL);
    deletedAttrsBuffer.append("cn: User, Test");
    deletedAttrsBuffer.append(StaticUtils.EOL);

    // Construct virtual attributes for the entry.
    final StringBuilder virtualAttrBuffer = new StringBuilder();
    virtualAttrBuffer.append("cn: Virtual cn");
    virtualAttrBuffer.append(StaticUtils.EOL);
    virtualAttrBuffer.append("description: Virtual description");
    virtualAttrBuffer.append(StaticUtils.EOL);

    // Construct a key attribute value for the "cn" attribute.
    final StringBuilder keyAttrBuffer = new StringBuilder();
    keyAttrBuffer.append("cn: Test User");
    keyAttrBuffer.append(StaticUtils.EOL);
    keyAttrBuffer.append("cn: User, Test");
    keyAttrBuffer.append(StaticUtils.EOL);

    // Construct a key virtual attribute value for the "cn" attribute.
    final StringBuilder keyVirtualAttrBuffer = new StringBuilder();
    keyVirtualAttrBuffer.append("cn: Virtual cn");
    keyVirtualAttrBuffer.append(StaticUtils.EOL);

    final Entry extendedEntry = e.duplicate();
    extendedEntry.addAttribute("deletedEntryAttrs",
         deletedAttrsBuffer.toString());
    extendedEntry.addAttribute("ds-changelog-virtual-attributes",
         virtualAttrBuffer.toString());
    extendedEntry.addAttribute("ds-changelog-entry-key-attr-values",
         keyAttrBuffer.toString());
    extendedEntry.addAttribute("ds-changelog-entry-key-virtual-values",
         keyVirtualAttrBuffer.toString());
    extendedEntry.addAttribute(
         "ds-changelog-num-excluded-user-attributes", "2");
    extendedEntry.addAttribute(
         "ds-changelog-num-excluded-operational-attributes", "5");
    extendedEntry.addAttribute(
         "ds-changelog-excluded-user-attribute", "description", "userPassword");
    extendedEntry.addAttribute(
         "ds-changelog-excluded-operational-attribute", "creatorsName",
         "createTimestamp", "modifiersName", "modifyTimestamp", "entryUUID");
    extendedEntry.addAttribute("targetUniqueID",
         "468c6887-4fcc-38ea-9425-abcaa3c88be6");
    extendedEntry.addAttribute("localCSN", "00000131EDEDD535000000000006");
    extendedEntry.addAttribute("changeTime", "20110821200012Z");
    extendedEntry.addAttribute("ds-soft-delete-entry-dn",
         "uid=test.user,ou=People,dc=example,dc=com");
    extendedEntry.addAttribute("ds-change-to-soft-deleted-entry", "false");
    extendedEntry.addAttribute("ds-changelog-target-attribute", "objectClass",
         "uid", "givenName", "sn", "cn");
    extendedEntry.addAttribute("ds-notification-destination-entry-uuid",
         "12345678-90ab-cdef-1234-567890abcdef",
         "23456789-0abC-def1-2345-67890abcdef1");
    extendedEntry.addAttribute("ds-changelog-notification-properties",
         "notification-property-1", "notification-property-2",
         "notification-property-3");


    final UnboundIDChangeLogEntry ue =
         new UnboundIDChangeLogEntry(extendedEntry);
    assertNotNull(ue);

    assertEquals(ue.getChangeNumber(), 4L);

    assertNotNull(ue.getTargetDN());
    assertEquals(new DN(ue.getTargetDN()),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));

    assertNotNull(ue.getChangeType());
    assertEquals(ue.getChangeType(), ChangeType.DELETE);

    assertNull(ue.getAddAttributes());

    assertNull(ue.getAddAttributes(true));

    assertNull(ue.getAddVirtualAttributes());

    assertNotNull(ue.getDeletedEntryAttributes());
    assertEquals(ue.getDeletedEntryAttributes().size(), 5);
    assertTrue(ue.getDeletedEntryAttributes().contains(
         new Attribute("objectClass", "top", "person", "organizationalPerson",
              "inetOrgPerson")));
    assertTrue(ue.getDeletedEntryAttributes().contains(
         new Attribute("uid", "test.user")));
    assertTrue(ue.getDeletedEntryAttributes().contains(
         new Attribute("givenName", "Test")));
    assertTrue(ue.getDeletedEntryAttributes().contains(
         new Attribute("sn", "User")));
    assertTrue(ue.getDeletedEntryAttributes().contains(
         new Attribute("cn", "Test User", "User, Test")));

    assertNotNull(ue.getDeletedEntryAttributes(true));
    assertEquals(ue.getDeletedEntryAttributes(true).size(), 6);
    assertTrue(ue.getDeletedEntryAttributes(true).contains(
         new Attribute("objectClass", "top", "person", "organizationalPerson",
              "inetOrgPerson")));
    assertTrue(ue.getDeletedEntryAttributes(true).contains(
         new Attribute("uid", "test.user")));
    assertTrue(ue.getDeletedEntryAttributes(true).contains(
         new Attribute("givenName", "Test")));
    assertTrue(ue.getDeletedEntryAttributes(true).contains(
         new Attribute("sn", "User")));
    assertTrue(ue.getDeletedEntryAttributes(true).contains(
         new Attribute("cn", "Test User", "User, Test", "Virtual cn")));
    assertTrue(ue.getDeletedEntryAttributes(true).contains(
         new Attribute("description", "Virtual description")));

    assertNotNull(ue.getDeletedEntryVirtualAttributes());
    assertEquals(ue.getDeletedEntryVirtualAttributes().size(), 2);
    assertTrue(ue.getDeletedEntryVirtualAttributes().contains(
         new Attribute("cn", "Virtual cn")));
    assertTrue(ue.getDeletedEntryVirtualAttributes().contains(
         new Attribute("description", "Virtual description")));

    assertNull(ue.getModifications());

    assertNull(ue.getNewRDN());

    assertFalse(ue.deleteOldRDN());

    assertNull(ue.getNewSuperior());

    assertNotNull(ue.getSoftDeleteToDN());

    assertNull(ue.getUndeleteFromDN());

    assertNotNull(ue.getChangeToSoftDeletedEntry());
    assertFalse(ue.getChangeToSoftDeletedEntry());

    assertNull(ue.getNewDN());

    assertNotNull(ue.getUpdatedAttributesBeforeChange());
    assertTrue(ue.getUpdatedAttributesBeforeChange().isEmpty());

    assertNotNull(ue.getUpdatedAttributesBeforeChange(true));
    assertTrue(ue.getUpdatedAttributesBeforeChange(true).isEmpty());

    assertNotNull(ue.getUpdatedVirtualAttributesBeforeChange());
    assertTrue(ue.getUpdatedVirtualAttributesBeforeChange().isEmpty());

    assertNotNull(ue.getUpdatedAttributesAfterChange());
    assertTrue(ue.getUpdatedAttributesAfterChange().isEmpty());

    assertNotNull(ue.getUpdatedAttributesAfterChange(true));
    assertTrue(ue.getUpdatedAttributesAfterChange(true).isEmpty());

    assertNotNull(ue.getUpdatedVirtualAttributesAfterChange());
    assertTrue(ue.getUpdatedVirtualAttributesAfterChange().isEmpty());

    assertNotNull(ue.getAttributesThatExceededMaxValuesCount());
    assertTrue(ue.getAttributesThatExceededMaxValuesCount().isEmpty());

    assertNotNull(ue.getVirtualAttributesThatExceededMaxValuesCount());
    assertTrue(ue.getVirtualAttributesThatExceededMaxValuesCount().isEmpty());

    assertNotNull(ue.getKeyEntryAttributes());
    assertEquals(ue.getKeyEntryAttributes().size(), 1);
    assertTrue(ue.getKeyEntryAttributes().contains(new Attribute("cn",
         "Test User", "User, Test")));

    assertNotNull(ue.getKeyEntryAttributes(true));
    assertEquals(ue.getKeyEntryAttributes(true).size(), 1);
    assertTrue(ue.getKeyEntryAttributes(true).contains(new Attribute("cn",
         "Test User", "User, Test", "Virtual cn")));

    assertNotNull(ue.getKeyEntryVirtualAttributes());
    assertEquals(ue.getKeyEntryVirtualAttributes().size(), 1);
    assertTrue(ue.getKeyEntryVirtualAttributes().contains(new Attribute("cn",
         "Virtual cn")));

    assertEquals(ue.getNumExcludedUserAttributes(), 2);

    assertEquals(ue.getNumExcludedOperationalAttributes(), 5);

    assertNotNull(ue.getExcludedUserAttributeNames());
    assertFalse(ue.getExcludedUserAttributeNames().isEmpty());
    assertTrue(ue.getExcludedUserAttributeNames().contains("description"));
    assertTrue(ue.getExcludedUserAttributeNames().contains("userPassword"));

    assertNotNull(ue.getExcludedOperationalAttributeNames());
    assertFalse(ue.getExcludedOperationalAttributeNames().isEmpty());
    assertTrue(ue.getExcludedOperationalAttributeNames().contains(
         "creatorsName"));
    assertTrue(ue.getExcludedOperationalAttributeNames().contains(
         "createTimestamp"));
    assertTrue(ue.getExcludedOperationalAttributeNames().contains(
         "modifiersName"));
    assertTrue(ue.getExcludedOperationalAttributeNames().contains(
         "modifyTimestamp"));
    assertTrue(ue.getExcludedOperationalAttributeNames().contains(
         "entryUUID"));

    assertNotNull(ue.getAttributeBeforeChange("uid"));
    assertEquals(ue.getAttributeBeforeChange("uid"),
         new Attribute("uid", "test.user"));

    assertNotNull(ue.getAttributeBeforeChange("uid", true));
    assertEquals(ue.getAttributeBeforeChange("uid", true),
         new Attribute("uid", "test.user"));

    assertNotNull(ue.getAttributeBeforeChange("cn"));
    assertEquals(ue.getAttributeBeforeChange("cn"),
         new Attribute("cn", "Test User", "User, Test"));

    assertNotNull(ue.getAttributeBeforeChange("cn", true));
    assertEquals(ue.getAttributeBeforeChange("cn", true),
         new Attribute("cn", "Test User", "User, Test", "Virtual cn"));

    assertNull(ue.getAttributeBeforeChange("missing"));

    assertNull(ue.getAttributeBeforeChange("missing", true));

    assertNull(ue.getAttributeBeforeChange("description"));

    assertNotNull(ue.getAttributeBeforeChange("description", true));
    assertEquals(ue.getAttributeBeforeChange("description", true),
         new Attribute("description", "Virtual description"));

    assertNull(ue.getAttributeAfterChange("uid"));

    assertNull(ue.getAttributeAfterChange("uid", true));

    assertNotNull(ue.constructPartialEntryBeforeChange());
    assertEquals(ue.constructPartialEntryBeforeChange(), new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "cn: User, Test"));

    assertNotNull(ue.constructPartialEntryBeforeChange(true));
    assertEquals(ue.constructPartialEntryBeforeChange(true), new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "cn: User, Test",
         "cn: Virtual cn",
         "description: Virtual description"));

    assertNull(ue.constructPartialEntryAfterChange());

    assertNull(ue.constructPartialEntryAfterChange(true));

    assertNotNull(ue.getTargetUniqueID());
    assertEquals(ue.getTargetUniqueID(),
         "468c6887-4fcc-38ea-9425-abcaa3c88be6");

    assertNotNull(ue.getLocalCSN());
    assertEquals(ue.getLocalCSN(), "00000131EDEDD535000000000006");

    assertNotNull(ue.getChangeTime());
    assertEquals(ue.getChangeTime().getTime(),
         StaticUtils.decodeGeneralizedTime("20110821200012Z").getTime());

    assertNotNull(ue.getTargetAttributeNames());
    assertFalse(ue.getTargetAttributeNames().isEmpty());
    assertEquals(ue.getTargetAttributeNames().size(), 5);

    assertNotNull(ue.getNotificationDestinationEntryUUIDs());
    assertFalse(ue.getNotificationDestinationEntryUUIDs().isEmpty());
    assertEquals(ue.getNotificationDestinationEntryUUIDs().size(), 2);

    assertNotNull(ue.getNotificationProperties());
    assertFalse(ue.getNotificationProperties().isEmpty());
    assertEquals(ue.getNotificationProperties().size(), 3);
  }



  /**
   * Provides coverage for cases in which an UnboundID changelog entry is
   * created for a modify operation without any UnboundID-specific content.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicModifyChangeLogEntry()
         throws Exception
  {
    final ChangeLogEntry e = ChangeLogEntry.constructChangeLogEntry(4L,
         new LDIFModifyChangeRecord("uid=test.user,ou=People,dc=example,dc=com",
              new Modification(ModificationType.REPLACE, "description",
                   "foo")));
    assertNotNull(e);

    final UnboundIDChangeLogEntry ue = new UnboundIDChangeLogEntry(e);
    assertNotNull(ue);

    assertEquals(ue.getChangeNumber(), 4L);

    assertNotNull(ue.getTargetDN());
    assertEquals(new DN(ue.getTargetDN()),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));

    assertNotNull(ue.getChangeType());
    assertEquals(ue.getChangeType(), ChangeType.MODIFY);

    assertNull(ue.getAddAttributes());

    assertNull(ue.getAddAttributes(true));

    assertNull(ue.getAddVirtualAttributes());

    assertNull(ue.getDeletedEntryAttributes());

    assertNull(ue.getDeletedEntryAttributes(true));

    assertNull(ue.getDeletedEntryVirtualAttributes());

    assertNotNull(ue.getModifications());
    assertEquals(ue.getModifications().size(), 1);
    assertTrue(ue.getModifications().contains(new Modification(
         ModificationType.REPLACE, "description", "foo")));

    assertNull(ue.getNewRDN());

    assertFalse(ue.deleteOldRDN());

    assertNull(ue.getNewSuperior());

    assertNull(ue.getSoftDeleteToDN());

    assertNull(ue.getUndeleteFromDN());

    assertNull(ue.getChangeToSoftDeletedEntry());

    assertNotNull(ue.getNewDN());
    assertEquals(new DN(ue.getNewDN()),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));

    assertNotNull(ue.getUpdatedAttributesBeforeChange());
    assertTrue(ue.getUpdatedAttributesBeforeChange().isEmpty());

    assertNotNull(ue.getUpdatedAttributesBeforeChange(true));
    assertTrue(ue.getUpdatedAttributesBeforeChange(true).isEmpty());

    assertNotNull(ue.getUpdatedVirtualAttributesBeforeChange());
    assertTrue(ue.getUpdatedVirtualAttributesBeforeChange().isEmpty());

    assertNotNull(ue.getUpdatedAttributesAfterChange());
    assertTrue(ue.getUpdatedAttributesAfterChange().isEmpty());

    assertNotNull(ue.getUpdatedAttributesAfterChange(true));
    assertTrue(ue.getUpdatedAttributesAfterChange(true).isEmpty());

    assertNotNull(ue.getUpdatedVirtualAttributesAfterChange());
    assertTrue(ue.getUpdatedVirtualAttributesAfterChange().isEmpty());

    assertNotNull(ue.getAttributesThatExceededMaxValuesCount());
    assertTrue(ue.getAttributesThatExceededMaxValuesCount().isEmpty());

    assertNotNull(ue.getVirtualAttributesThatExceededMaxValuesCount());
    assertTrue(ue.getVirtualAttributesThatExceededMaxValuesCount().isEmpty());

    assertNotNull(ue.getKeyEntryAttributes());
    assertTrue(ue.getKeyEntryAttributes().isEmpty());

    assertNotNull(ue.getKeyEntryAttributes(true));
    assertTrue(ue.getKeyEntryAttributes(true).isEmpty());

    assertNotNull(ue.getKeyEntryVirtualAttributes());
    assertTrue(ue.getKeyEntryVirtualAttributes().isEmpty());

    assertEquals(ue.getNumExcludedUserAttributes(), -1);

    assertEquals(ue.getNumExcludedOperationalAttributes(), -1);

    assertNotNull(ue.getExcludedUserAttributeNames());
    assertTrue(ue.getExcludedUserAttributeNames().isEmpty());

    assertNotNull(ue.getExcludedOperationalAttributeNames());
    assertTrue(ue.getExcludedOperationalAttributeNames().isEmpty());

    assertNull(ue.getAttributeBeforeChange("uid"));

    assertNull(ue.getAttributeBeforeChange("uid", true));

    assertNull(ue.getAttributeBeforeChange("description"));

    assertNull(ue.getAttributeBeforeChange("description", true));

    assertNull(ue.getAttributeAfterChange("uid"));

    assertNull(ue.getAttributeAfterChange("uid", true));

    assertNotNull(ue.getAttributeAfterChange("description"));
    assertEquals(ue.getAttributeAfterChange("description"),
         new Attribute("description", "foo"));

    assertNotNull(ue.getAttributeAfterChange("description", true));
    assertEquals(ue.getAttributeAfterChange("description", true),
         new Attribute("description", "foo"));

    assertNotNull(ue.constructPartialEntryBeforeChange());
    assertEquals(ue.constructPartialEntryBeforeChange(),
         new Entry("uid=test.user,ou=People,dc=example,dc=com"));

    assertNotNull(ue.constructPartialEntryBeforeChange(true));
    assertEquals(ue.constructPartialEntryBeforeChange(true),
         new Entry("uid=test.user,ou=People,dc=example,dc=com"));

    assertNotNull(ue.constructPartialEntryAfterChange());
    assertEquals(ue.constructPartialEntryAfterChange(), new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "description: foo"));

    assertNotNull(ue.constructPartialEntryAfterChange(true));
    assertEquals(ue.constructPartialEntryAfterChange(true), new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "description: foo"));

    assertNull(ue.getTargetUniqueID());

    assertNull(ue.getLocalCSN());

    assertNull(ue.getChangeTime());

    assertNotNull(ue.getTargetAttributeNames());
    assertTrue(ue.getTargetAttributeNames().isEmpty());

    assertNotNull(ue.getNotificationDestinationEntryUUIDs());
    assertTrue(ue.getNotificationDestinationEntryUUIDs().isEmpty());

    assertNotNull(ue.getNotificationProperties());
    assertTrue(ue.getNotificationProperties().isEmpty());
  }



  /**
   * Provides coverage for cases in which an UnboundID changelog entry is
   * created for a modify operation without an extended set of content that
   * does not have any attributes with an exceeded value count.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedModifyChangeLogEntryNoExceededValues()
         throws Exception
  {
    final ChangeLogEntry e = ChangeLogEntry.constructChangeLogEntry(4L,
         new LDIFModifyChangeRecord("uid=test.user,ou=People,dc=example,dc=com",
              new Modification(ModificationType.REPLACE, "description",
                   "bar"),
              new Modification(ModificationType.ADD, "cn", "User, Test"),
              new Modification(ModificationType.DELETE, "mail")));
    assertNotNull(e);

    // Construct before values for the description, cn and mail attributes.
    final StringBuilder beforeBuffer = new StringBuilder();
    beforeBuffer.append("description: foo");
    beforeBuffer.append(StaticUtils.EOL);
    beforeBuffer.append("cn: Test User");
    beforeBuffer.append(StaticUtils.EOL);
    beforeBuffer.append("mail: test.user@example.com");
    beforeBuffer.append(StaticUtils.EOL);

    // Construct virtual before values for the description and cn attributes.
    final StringBuilder virtualBeforeBuffer = new StringBuilder();
    virtualBeforeBuffer.append("description: Virtual description");
    virtualBeforeBuffer.append(StaticUtils.EOL);
    virtualBeforeBuffer.append("cn: Virtual cn");
    virtualBeforeBuffer.append(StaticUtils.EOL);

    // Construct after values for the description and cn attributes.
    final StringBuilder afterBuffer = new StringBuilder();
    afterBuffer.append("description: bar");
    afterBuffer.append(StaticUtils.EOL);
    afterBuffer.append("cn: Test User");
    afterBuffer.append(StaticUtils.EOL);
    afterBuffer.append("cn: User, Test");
    afterBuffer.append(StaticUtils.EOL);

    // Construct virtual after values for the description and cn attributes.
    final StringBuilder virtualAfterBuffer = new StringBuilder();
    virtualAfterBuffer.append("description: Virtual description");
    virtualAfterBuffer.append(StaticUtils.EOL);
    virtualAfterBuffer.append("cn: Virtual cn");
    virtualAfterBuffer.append(StaticUtils.EOL);

    // Construct a key attribute value for the "cn" attribute.
    final StringBuilder keyAttrBuffer = new StringBuilder();
    keyAttrBuffer.append("cn: Test User");
    keyAttrBuffer.append(StaticUtils.EOL);
    keyAttrBuffer.append("cn: User, Test");
    keyAttrBuffer.append(StaticUtils.EOL);

    // Construct a key virtual attribute value for the "cn" attribute.
    final StringBuilder keyVirtualAttrBuffer = new StringBuilder();
    keyVirtualAttrBuffer.append("cn: Virtual cn");
    keyVirtualAttrBuffer.append(StaticUtils.EOL);

    final Entry extendedEntry = e.duplicate();
    extendedEntry.addAttribute("ds-changelog-before-values",
         beforeBuffer.toString());
    extendedEntry.addAttribute("ds-changelog-before-virtual-values",
         virtualBeforeBuffer.toString());
    extendedEntry.addAttribute("ds-changelog-after-values",
         afterBuffer.toString());
    extendedEntry.addAttribute("ds-changelog-after-virtual-values",
         virtualAfterBuffer.toString());
    extendedEntry.addAttribute("ds-changelog-entry-key-attr-values",
         keyAttrBuffer.toString());
    extendedEntry.addAttribute("ds-changelog-entry-key-virtual-values",
         keyVirtualAttrBuffer.toString());
    extendedEntry.addAttribute(
         "ds-changelog-num-excluded-user-attributes", "1");
    extendedEntry.addAttribute(
         "ds-changelog-num-excluded-operational-attributes", "2");
    extendedEntry.addAttribute(
         "ds-changelog-excluded-user-attribute", "userPassword");
    extendedEntry.addAttribute(
         "ds-changelog-excluded-operational-attribute", "modifiersName",
         "modifyTimestamp");
    extendedEntry.addAttribute("targetUniqueID",
         "468c6887-4fcc-38ea-9425-abcaa3c88be6");
    extendedEntry.addAttribute("localCSN", "00000131EDEDD535000000000006");
    extendedEntry.addAttribute("changeTime", "20110821200012Z");
    extendedEntry.addAttribute("ds-change-to-soft-deleted-entry", "false");
    extendedEntry.addAttribute("ds-changelog-target-attribute", "description",
         "cn", "mail");
    extendedEntry.addAttribute("ds-notification-destination-entry-uuid",
         "12345678-90ab-cdef-1234-567890abcdef",
         "23456789-0abC-def1-2345-67890abcdef1");
    extendedEntry.addAttribute("ds-changelog-notification-properties",
         "notification-property-1", "notification-property-2",
         "notification-property-3");


    final UnboundIDChangeLogEntry ue =
         new UnboundIDChangeLogEntry(extendedEntry);
    assertNotNull(ue);

    assertEquals(ue.getChangeNumber(), 4L);

    assertNotNull(ue.getTargetDN());
    assertEquals(new DN(ue.getTargetDN()),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));

    assertNotNull(ue.getChangeType());
    assertEquals(ue.getChangeType(), ChangeType.MODIFY);

    assertNull(ue.getAddAttributes());

    assertNull(ue.getAddAttributes(true));

    assertNull(ue.getAddVirtualAttributes());

    assertNull(ue.getDeletedEntryAttributes());

    assertNull(ue.getDeletedEntryAttributes(true));

    assertNull(ue.getDeletedEntryVirtualAttributes());

    assertNotNull(ue.getModifications());
    assertEquals(ue.getModifications().size(), 3);
    assertTrue(ue.getModifications().contains(new Modification(
         ModificationType.REPLACE, "description", "bar")));
    assertTrue(ue.getModifications().contains(new Modification(
         ModificationType.ADD, "cn", "User, Test")));
    assertTrue(ue.getModifications().contains(new Modification(
         ModificationType.DELETE, "mail")));

    assertNull(ue.getNewRDN());

    assertFalse(ue.deleteOldRDN());

    assertNull(ue.getNewSuperior());

    assertNull(ue.getSoftDeleteToDN());

    assertNull(ue.getUndeleteFromDN());

    assertNotNull(ue.getChangeToSoftDeletedEntry());
    assertFalse(ue.getChangeToSoftDeletedEntry());

    assertNotNull(ue.getNewDN());
    assertEquals(new DN(ue.getNewDN()),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));

    assertNotNull(ue.getUpdatedAttributesBeforeChange());
    assertEquals(ue.getUpdatedAttributesBeforeChange().size(), 3);
    assertTrue(ue.getUpdatedAttributesBeforeChange().contains(
         new Attribute("description", "foo")));
    assertTrue(ue.getUpdatedAttributesBeforeChange().contains(
         new Attribute("cn", "Test User")));
    assertTrue(ue.getUpdatedAttributesBeforeChange().contains(
         new Attribute("mail", "test.user@example.com")));

    assertNotNull(ue.getUpdatedAttributesBeforeChange(true));
    assertEquals(ue.getUpdatedAttributesBeforeChange(true).size(), 3);
    assertTrue(ue.getUpdatedAttributesBeforeChange(true).contains(
         new Attribute("description", "foo", "Virtual description")));
    assertTrue(ue.getUpdatedAttributesBeforeChange(true).contains(
         new Attribute("cn", "Test User", "Virtual cn")));
    assertTrue(ue.getUpdatedAttributesBeforeChange(true).contains(
         new Attribute("mail", "test.user@example.com")));

    assertNotNull(ue.getUpdatedVirtualAttributesBeforeChange());
    assertEquals(ue.getUpdatedVirtualAttributesBeforeChange().size(), 2);
    assertTrue(ue.getUpdatedVirtualAttributesBeforeChange().contains(
         new Attribute("description", "Virtual description")));
    assertTrue(ue.getUpdatedVirtualAttributesBeforeChange().contains(
         new Attribute("cn", "Virtual cn")));

    assertNotNull(ue.getUpdatedAttributesAfterChange());
    assertEquals(ue.getUpdatedAttributesAfterChange().size(), 2);
    assertTrue(ue.getUpdatedAttributesAfterChange().contains(
         new Attribute("description", "bar")));
    assertTrue(ue.getUpdatedAttributesAfterChange().contains(
         new Attribute("cn", "Test User", "User, Test")));

    assertNotNull(ue.getUpdatedAttributesAfterChange(true));
    assertEquals(ue.getUpdatedAttributesAfterChange(true).size(), 2);
    assertTrue(ue.getUpdatedAttributesAfterChange(true).contains(
         new Attribute("description", "bar", "Virtual description")));
    assertTrue(ue.getUpdatedAttributesAfterChange(true).contains(
         new Attribute("cn", "Test User", "User, Test", "Virtual cn")));

    assertNotNull(ue.getUpdatedVirtualAttributesAfterChange());
    assertEquals(ue.getUpdatedVirtualAttributesAfterChange().size(), 2);
    assertTrue(ue.getUpdatedVirtualAttributesAfterChange().contains(
         new Attribute("description", "Virtual description")));
    assertTrue(ue.getUpdatedVirtualAttributesAfterChange().contains(
         new Attribute("cn", "Virtual cn")));

    assertNotNull(ue.getAttributesThatExceededMaxValuesCount());
    assertTrue(ue.getAttributesThatExceededMaxValuesCount().isEmpty());

    assertNotNull(ue.getVirtualAttributesThatExceededMaxValuesCount());
    assertTrue(ue.getVirtualAttributesThatExceededMaxValuesCount().isEmpty());

    assertNotNull(ue.getKeyEntryAttributes());
    assertEquals(ue.getKeyEntryAttributes().size(), 1);
    assertTrue(ue.getKeyEntryAttributes().contains(
         new Attribute("cn", "Test User", "User, Test")));

    assertNotNull(ue.getKeyEntryAttributes(true));
    assertEquals(ue.getKeyEntryAttributes(true).size(), 1);
    assertTrue(ue.getKeyEntryAttributes(true).contains(
         new Attribute("cn", "Test User", "User, Test", "Virtual cn")));

    assertNotNull(ue.getKeyEntryVirtualAttributes());
    assertEquals(ue.getKeyEntryVirtualAttributes().size(), 1);
    assertTrue(ue.getKeyEntryVirtualAttributes().contains(
         new Attribute("cn", "Virtual cn")));

    assertEquals(ue.getNumExcludedUserAttributes(), 1);

    assertEquals(ue.getNumExcludedOperationalAttributes(), 2);

    assertNotNull(ue.getExcludedUserAttributeNames());
    assertFalse(ue.getExcludedUserAttributeNames().isEmpty());
    assertTrue(ue.getExcludedUserAttributeNames().contains("userPassword"));

    assertNotNull(ue.getExcludedOperationalAttributeNames());
    assertFalse(ue.getExcludedOperationalAttributeNames().isEmpty());
    assertTrue(ue.getExcludedOperationalAttributeNames().contains(
         "modifiersName"));
    assertTrue(ue.getExcludedOperationalAttributeNames().contains(
         "modifyTimestamp"));

    assertNull(ue.getAttributeBeforeChange("uid"));

    assertNull(ue.getAttributeBeforeChange("uid", true));

    assertNotNull(ue.getAttributeBeforeChange("description"));
    assertEquals(ue.getAttributeBeforeChange("description"),
         new Attribute("description", "foo"));

    assertNotNull(ue.getAttributeBeforeChange("description", true));
    assertEquals(ue.getAttributeBeforeChange("description", true),
         new Attribute("description", "foo", "Virtual description"));

    assertNotNull(ue.getAttributeBeforeChange("cn"));
    assertEquals(ue.getAttributeBeforeChange("cn"),
         new Attribute("cn", "Test User"));

    assertNotNull(ue.getAttributeBeforeChange("cn", true));
    assertEquals(ue.getAttributeBeforeChange("cn", true),
         new Attribute("cn", "Test User", "Virtual cn"));

    assertNotNull(ue.getAttributeBeforeChange("mail"));
    assertEquals(ue.getAttributeBeforeChange("mail"),
         new Attribute("mail", "test.user@example.com"));

    assertNotNull(ue.getAttributeBeforeChange("mail", true));
    assertEquals(ue.getAttributeBeforeChange("mail", true),
         new Attribute("mail", "test.user@example.com"));

    assertNull(ue.getAttributeAfterChange("uid"));

    assertNull(ue.getAttributeAfterChange("uid", true));

    assertNull(ue.getAttributeAfterChange("mail"));

    assertNull(ue.getAttributeAfterChange("mail", true));

    assertNotNull(ue.getAttributeAfterChange("description"));
    assertEquals(ue.getAttributeAfterChange("description"),
         new Attribute("description", "bar"));

    assertNotNull(ue.getAttributeAfterChange("description", true));
    assertEquals(ue.getAttributeAfterChange("description", true),
         new Attribute("description", "bar", "Virtual description"));

    assertNotNull(ue.getAttributeAfterChange("cn"));
    assertEquals(ue.getAttributeAfterChange("cn"),
         new Attribute("cn", "Test User", "User, Test"));

    assertNotNull(ue.getAttributeAfterChange("cn", true));
    assertEquals(ue.getAttributeAfterChange("cn", true),
         new Attribute("cn", "Test User", "User, Test", "Virtual cn"));

    assertNotNull(ue.constructPartialEntryBeforeChange());
    assertEquals(ue.constructPartialEntryBeforeChange(), new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "description: foo",
         "cn: Test User",
         "mail: test.user@example.com"));

    assertNotNull(ue.constructPartialEntryBeforeChange(true));
    assertEquals(ue.constructPartialEntryBeforeChange(true), new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "description: foo",
         "description: Virtual description",
         "cn: Test User",
         "cn: Virtual cn",
         "mail: test.user@example.com"));

    assertNotNull(ue.constructPartialEntryAfterChange());
    assertEquals(ue.constructPartialEntryAfterChange(), new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "description: bar",
         "cn: Test User",
         "cn: User, Test"));

    assertNotNull(ue.constructPartialEntryAfterChange(true));
    assertEquals(ue.constructPartialEntryAfterChange(true), new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "description: bar",
         "description: Virtual description",
         "cn: Test User",
         "cn: User, Test",
         "cn: Virtual cn"));

    assertNotNull(ue.getTargetUniqueID());
    assertEquals(ue.getTargetUniqueID(),
         "468c6887-4fcc-38ea-9425-abcaa3c88be6");

    assertNotNull(ue.getLocalCSN());
    assertEquals(ue.getLocalCSN(), "00000131EDEDD535000000000006");

    assertNotNull(ue.getChangeTime());
    assertEquals(ue.getChangeTime().getTime(),
         StaticUtils.decodeGeneralizedTime("20110821200012Z").getTime());

    assertNotNull(ue.getTargetAttributeNames());
    assertFalse(ue.getTargetAttributeNames().isEmpty());
    assertEquals(ue.getTargetAttributeNames().size(), 3);

    assertNotNull(ue.getNotificationDestinationEntryUUIDs());
    assertFalse(ue.getNotificationDestinationEntryUUIDs().isEmpty());
    assertEquals(ue.getNotificationDestinationEntryUUIDs().size(), 2);

    assertNotNull(ue.getNotificationProperties());
    assertFalse(ue.getNotificationProperties().isEmpty());
    assertEquals(ue.getNotificationProperties().size(), 3);
  }



  /**
   * Provides coverage for cases in which an UnboundID changelog entry is
   * created for a modify operation without an extended set of content that
   * includes attributes with exceeded before and after value counts.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedModifyChangeLogEntryWithBothExceededValues()
         throws Exception
  {
    final ChangeLogEntry e = ChangeLogEntry.constructChangeLogEntry(4L,
         new LDIFModifyChangeRecord("cn=Test,ou=Groups,dc=example,dc=com",
              new Modification(ModificationType.ADD, "member",
                   "uid=test.user,ou=People,dc=example,dc=com")));
    assertNotNull(e);

    // Construct a key attribute value for the "cn" attribute.
    final StringBuilder keyAttrBuffer = new StringBuilder();
    keyAttrBuffer.append("cn: Test");
    keyAttrBuffer.append(StaticUtils.EOL);

    // Construct a key virtual attribute value for the "cn" attribute.
    final StringBuilder keyVirtualAttrBuffer = new StringBuilder();
    keyVirtualAttrBuffer.append("cn: Virtual cn");
    keyVirtualAttrBuffer.append(StaticUtils.EOL);

    final Entry extendedEntry = e.duplicate();
    extendedEntry.addAttribute("ds-changelog-attr-exceeded-max-values-count",
         "attr=member,beforeCount=5,afterCount=6");
    extendedEntry.addAttribute(
         "ds-changelog-virtual-attr-exceeded-max-values-count",
         "attr=description,beforeCount=7,afterCount=7");
    extendedEntry.addAttribute("ds-changelog-entry-key-attr-values",
         keyAttrBuffer.toString());
    extendedEntry.addAttribute("ds-changelog-entry-key-virtual-values",
         keyVirtualAttrBuffer.toString());
    extendedEntry.addAttribute("targetUniqueID",
         "468c6887-4fcc-38ea-9425-abcaa3c88be6");
    extendedEntry.addAttribute("localCSN", "00000131EDEDD535000000000006");
    extendedEntry.addAttribute("changeTime", "20110821200012Z");
    extendedEntry.addAttribute("ds-changelog-target-attribute", "member");
    extendedEntry.addAttribute("ds-notification-destination-entry-uuid",
         "12345678-90ab-cdef-1234-567890abcdef",
         "23456789-0abC-def1-2345-67890abcdef1");
    extendedEntry.addAttribute("ds-changelog-notification-properties",
         "notification-property-1", "notification-property-2",
         "notification-property-3");


    final UnboundIDChangeLogEntry ue =
         new UnboundIDChangeLogEntry(extendedEntry);
    assertNotNull(ue);

    assertEquals(ue.getChangeNumber(), 4L);

    assertNotNull(ue.getTargetDN());
    assertEquals(new DN(ue.getTargetDN()),
         new DN("cn=Test,ou=Groups,dc=example,dc=com"));

    assertNotNull(ue.getChangeType());
    assertEquals(ue.getChangeType(), ChangeType.MODIFY);

    assertNull(ue.getAddAttributes());

    assertNull(ue.getAddAttributes(true));

    assertNull(ue.getAddVirtualAttributes());

    assertNull(ue.getDeletedEntryAttributes());

    assertNull(ue.getDeletedEntryAttributes(true));

    assertNull(ue.getDeletedEntryVirtualAttributes());

    assertNotNull(ue.getModifications());
    assertEquals(ue.getModifications().size(), 1);
    assertTrue(ue.getModifications().contains(new Modification(
         ModificationType.ADD, "member",
         "uid=test.user,ou=People,dc=example,dc=com")));

    assertNull(ue.getNewRDN());

    assertFalse(ue.deleteOldRDN());

    assertNull(ue.getNewSuperior());

    assertNull(ue.getSoftDeleteToDN());

    assertNull(ue.getUndeleteFromDN());

    assertNull(ue.getChangeToSoftDeletedEntry());

    assertNotNull(ue.getNewDN());
    assertEquals(new DN(ue.getNewDN()),
         new DN("cn=Test,ou=Groups,dc=example,dc=com"));

    assertNotNull(ue.getUpdatedAttributesBeforeChange());
    assertTrue(ue.getUpdatedAttributesBeforeChange().isEmpty());

    assertNotNull(ue.getUpdatedAttributesBeforeChange(true));
    assertTrue(ue.getUpdatedAttributesBeforeChange(true).isEmpty());

    assertNotNull(ue.getUpdatedVirtualAttributesBeforeChange());
    assertTrue(ue.getUpdatedVirtualAttributesBeforeChange().isEmpty());

    assertNotNull(ue.getUpdatedAttributesAfterChange());
    assertTrue(ue.getUpdatedAttributesAfterChange().isEmpty());

    assertNotNull(ue.getUpdatedAttributesAfterChange(true));
    assertTrue(ue.getUpdatedAttributesAfterChange(true).isEmpty());

    assertNotNull(ue.getUpdatedVirtualAttributesAfterChange());
    assertTrue(ue.getUpdatedVirtualAttributesAfterChange().isEmpty());

    assertNotNull(ue.getAttributesThatExceededMaxValuesCount());
    assertEquals(ue.getAttributesThatExceededMaxValuesCount().size(), 1);
    assertTrue(ue.getAttributesThatExceededMaxValuesCount().contains(
         new ChangeLogEntryAttributeExceededMaxValuesCount(
              "attr=member,beforeCount=5,afterCount=6")));

    assertNotNull(ue.getVirtualAttributesThatExceededMaxValuesCount());
    assertEquals(ue.getVirtualAttributesThatExceededMaxValuesCount().size(), 1);
    assertTrue(ue.getVirtualAttributesThatExceededMaxValuesCount().contains(
         new ChangeLogEntryAttributeExceededMaxValuesCount(
              "attr=description,beforeCount=7,afterCount=7")));

    assertNotNull(ue.getKeyEntryAttributes());
    assertEquals(ue.getKeyEntryAttributes().size(), 1);
    assertTrue(ue.getKeyEntryAttributes().contains(
         new Attribute("cn", "Test")));

    assertNotNull(ue.getKeyEntryAttributes(true));
    assertEquals(ue.getKeyEntryAttributes(true).size(), 1);
    assertTrue(ue.getKeyEntryAttributes(true).contains(
         new Attribute("cn", "Test", "Virtual cn")));

    assertNotNull(ue.getKeyEntryVirtualAttributes());
    assertEquals(ue.getKeyEntryVirtualAttributes().size(), 1);
    assertTrue(ue.getKeyEntryVirtualAttributes().contains(
         new Attribute("cn", "Virtual cn")));

    assertNull(ue.getAttributeBeforeChange("uid"));

    assertNull(ue.getAttributeBeforeChange("uid", true));

    assertNotNull(ue.getAttributeBeforeChange("cn"));
    assertEquals(ue.getAttributeAfterChange("cn"),
         new Attribute("cn", "Test"));

    assertNotNull(ue.getAttributeBeforeChange("cn", true));
    assertEquals(ue.getAttributeAfterChange("cn", true),
         new Attribute("cn", "Test", "Virtual cn"));

    try
    {
      ue.getAttributeBeforeChange("member");
      fail("Expected an exception when trying to member before values");
    }
    catch (final ChangeLogEntryAttributeExceededMaxValuesException ex)
    {
      // This was expected.
      assertNotNull(ex.getAttributeInfo());
      assertTrue(ex.getAttributeInfo().getAttributeName().equalsIgnoreCase(
           "member"));
      assertEquals(ex.getAttributeInfo().getBeforeCount(), 5);
      assertEquals(ex.getAttributeInfo().getAfterCount(), 6);
    }

    try
    {
      ue.getAttributeBeforeChange("member", true);
      fail("Expected an exception when trying to member before values");
    }
    catch (final ChangeLogEntryAttributeExceededMaxValuesException ex)
    {
      // This was expected.
      assertNotNull(ex.getAttributeInfo());
      assertTrue(ex.getAttributeInfo().getAttributeName().equalsIgnoreCase(
           "member"));
      assertEquals(ex.getAttributeInfo().getBeforeCount(), 5);
      assertEquals(ex.getAttributeInfo().getAfterCount(), 6);
    }

    assertNull(ue.getAttributeAfterChange("uid"));

    assertNull(ue.getAttributeAfterChange("uid", true));

    assertNotNull(ue.getAttributeAfterChange("cn"));
    assertEquals(ue.getAttributeAfterChange("cn"),
         new Attribute("cn", "Test"));

    assertNotNull(ue.getAttributeAfterChange("cn", true));
    assertEquals(ue.getAttributeAfterChange("cn", true),
         new Attribute("cn", "Test", "Virtual cn"));

    try
    {
      ue.getAttributeBeforeChange("member");
      fail("Expected an exception when trying to member after values");
    }
    catch (final ChangeLogEntryAttributeExceededMaxValuesException ex)
    {
      // This was expected.
      assertNotNull(ex.getAttributeInfo());
      assertTrue(ex.getAttributeInfo().getAttributeName().equalsIgnoreCase(
           "member"));
      assertEquals(ex.getAttributeInfo().getBeforeCount(), 5);
      assertEquals(ex.getAttributeInfo().getAfterCount(), 6);
    }

    assertNull(ue.getAttributeAfterChange("description"));

    try
    {
      ue.getAttributeBeforeChange("description", true);
      fail("Expected an exception when trying to description after values");
    }
    catch (final ChangeLogEntryAttributeExceededMaxValuesException ex)
    {
      // This was expected.
      assertNotNull(ex.getAttributeInfo());
      assertTrue(ex.getAttributeInfo().getAttributeName().equalsIgnoreCase(
           "description"));
      assertEquals(ex.getAttributeInfo().getBeforeCount(), 7);
      assertEquals(ex.getAttributeInfo().getAfterCount(), 7);
    }

    try
    {
      ue.getAttributeAfterChange("member", true);
      fail("Expected an exception when trying to member after values");
    }
    catch (final ChangeLogEntryAttributeExceededMaxValuesException ex)
    {
      // This was expected.
      assertNotNull(ex.getAttributeInfo());
      assertTrue(ex.getAttributeInfo().getAttributeName().equalsIgnoreCase(
           "member"));
      assertEquals(ex.getAttributeInfo().getBeforeCount(), 5);
      assertEquals(ex.getAttributeInfo().getAfterCount(), 6);
    }

    assertNull(ue.getAttributeAfterChange("description"));

    try
    {
      ue.getAttributeAfterChange("description", true);
      fail("Expected an exception when trying to description after values");
    }
    catch (final ChangeLogEntryAttributeExceededMaxValuesException ex)
    {
      // This was expected.
      assertNotNull(ex.getAttributeInfo());
      assertTrue(ex.getAttributeInfo().getAttributeName().equalsIgnoreCase(
           "description"));
      assertEquals(ex.getAttributeInfo().getBeforeCount(), 7);
      assertEquals(ex.getAttributeInfo().getAfterCount(), 7);
    }

    assertNotNull(ue.constructPartialEntryBeforeChange());
    assertEquals(ue.constructPartialEntryBeforeChange(), new Entry(
         "dn: cn=Test,ou=Groups,dc=example,dc=com",
         "cn: Test"));

    assertNotNull(ue.constructPartialEntryBeforeChange(true));
    assertEquals(ue.constructPartialEntryBeforeChange(true), new Entry(
         "dn: cn=Test,ou=Groups,dc=example,dc=com",
         "cn: Test",
         "cn: Virtual cn"));

    assertNotNull(ue.constructPartialEntryAfterChange());
    assertEquals(ue.constructPartialEntryAfterChange(), new Entry(
         "dn: cn=Test,ou=Groups,dc=example,dc=com",
         "cn: Test"));

    assertNotNull(ue.constructPartialEntryAfterChange(true));
    assertEquals(ue.constructPartialEntryAfterChange(true), new Entry(
         "dn: cn=Test,ou=Groups,dc=example,dc=com",
         "cn: Test",
         "cn: Virtual cn"));

    assertNotNull(ue.getTargetUniqueID());
    assertEquals(ue.getTargetUniqueID(),
         "468c6887-4fcc-38ea-9425-abcaa3c88be6");

    assertNotNull(ue.getLocalCSN());
    assertEquals(ue.getLocalCSN(), "00000131EDEDD535000000000006");

    assertNotNull(ue.getChangeTime());
    assertEquals(ue.getChangeTime().getTime(),
         StaticUtils.decodeGeneralizedTime("20110821200012Z").getTime());

    assertNotNull(ue.getTargetAttributeNames());
    assertFalse(ue.getTargetAttributeNames().isEmpty());
    assertEquals(ue.getTargetAttributeNames().size(), 1);

    assertNotNull(ue.getNotificationDestinationEntryUUIDs());
    assertFalse(ue.getNotificationDestinationEntryUUIDs().isEmpty());
    assertEquals(ue.getNotificationDestinationEntryUUIDs().size(), 2);

    assertNotNull(ue.getNotificationProperties());
    assertFalse(ue.getNotificationProperties().isEmpty());
    assertEquals(ue.getNotificationProperties().size(), 3);
  }



  /**
   * Provides coverage for cases in which an UnboundID changelog entry is
   * created for a modify operation without an extended set of content that
   * includes attributes with non-exceeded before but exceeded after value
   * counts.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedModifyChangeLogEntryWithExceededAfterValues()
         throws Exception
  {
    final ChangeLogEntry e = ChangeLogEntry.constructChangeLogEntry(4L,
         new LDIFModifyChangeRecord("cn=Test,ou=Groups,dc=example,dc=com",
              new Modification(ModificationType.ADD, "member",
                   "uid=user.4,ou=People,dc=example,dc=com")));
    assertNotNull(e);

    // Construct before values for the member attribute.
    final StringBuilder beforeBuffer = new StringBuilder();
    beforeBuffer.append("member: uid=user.1,ou=People,dc=example,dc=com");
    beforeBuffer.append(StaticUtils.EOL);
    beforeBuffer.append("member: uid=user.2,ou=People,dc=example,dc=com");
    beforeBuffer.append(StaticUtils.EOL);
    beforeBuffer.append("member: uid=user.3,ou=People,dc=example,dc=com");
    beforeBuffer.append(StaticUtils.EOL);

    // Construct a key attribute value for the "cn" attribute.
    final StringBuilder keyAttrBuffer = new StringBuilder();
    keyAttrBuffer.append("cn: Test");
    keyAttrBuffer.append(StaticUtils.EOL);

    final Entry extendedEntry = e.duplicate();
    extendedEntry.addAttribute("ds-changelog-before-values",
         beforeBuffer.toString());
    extendedEntry.addAttribute("ds-changelog-attr-exceeded-max-values-count",
         "attr=member,beforeCount=3,afterCount=4");
    extendedEntry.addAttribute("ds-changelog-entry-key-attr-values",
         keyAttrBuffer.toString());
    extendedEntry.addAttribute("targetUniqueID",
         "468c6887-4fcc-38ea-9425-abcaa3c88be6");
    extendedEntry.addAttribute("localCSN", "00000131EDEDD535000000000006");
    extendedEntry.addAttribute("changeTime", "20110821200012Z");
    extendedEntry.addAttribute("ds-changelog-target-attribute", "member");
    extendedEntry.addAttribute("ds-notification-destination-entry-uuid",
         "12345678-90ab-cdef-1234-567890abcdef",
         "23456789-0abC-def1-2345-67890abcdef1");
    extendedEntry.addAttribute("ds-changelog-notification-properties",
         "notification-property-1", "notification-property-2",
         "notification-property-3");


    final UnboundIDChangeLogEntry ue =
         new UnboundIDChangeLogEntry(extendedEntry);
    assertNotNull(ue);

    assertEquals(ue.getChangeNumber(), 4L);

    assertNotNull(ue.getTargetDN());
    assertEquals(new DN(ue.getTargetDN()),
         new DN("cn=Test,ou=Groups,dc=example,dc=com"));

    assertNotNull(ue.getChangeType());
    assertEquals(ue.getChangeType(), ChangeType.MODIFY);

    assertNull(ue.getAddAttributes());

    assertNull(ue.getDeletedEntryAttributes());

    assertNotNull(ue.getModifications());
    assertEquals(ue.getModifications().size(), 1);
    assertTrue(ue.getModifications().contains(new Modification(
         ModificationType.ADD, "member",
         "uid=user.4,ou=People,dc=example,dc=com")));

    assertNull(ue.getNewRDN());

    assertFalse(ue.deleteOldRDN());

    assertNull(ue.getNewSuperior());

    assertNull(ue.getSoftDeleteToDN());

    assertNull(ue.getUndeleteFromDN());

    assertNull(ue.getChangeToSoftDeletedEntry());

    assertNotNull(ue.getNewDN());
    assertEquals(new DN(ue.getNewDN()),
         new DN("cn=Test,ou=Groups,dc=example,dc=com"));

    assertNotNull(ue.getUpdatedAttributesBeforeChange());
    assertEquals(ue.getUpdatedAttributesBeforeChange().size(), 1);
    assertTrue(ue.getUpdatedAttributesBeforeChange().contains(
         new Attribute("member",
              "uid=user.1,ou=People,dc=example,dc=com",
              "uid=user.2,ou=People,dc=example,dc=com",
              "uid=user.3,ou=People,dc=example,dc=com")));

    assertNotNull(ue.getUpdatedAttributesAfterChange());
    assertTrue(ue.getUpdatedAttributesAfterChange().isEmpty());

    assertNotNull(ue.getAttributesThatExceededMaxValuesCount());
    assertEquals(ue.getAttributesThatExceededMaxValuesCount().size(), 1);
    assertTrue(ue.getAttributesThatExceededMaxValuesCount().contains(
         new ChangeLogEntryAttributeExceededMaxValuesCount(
              "attr=member,beforeCount=3,afterCount=4")));

    assertNotNull(ue.getKeyEntryAttributes());
    assertEquals(ue.getKeyEntryAttributes().size(), 1);
    assertTrue(ue.getKeyEntryAttributes().contains(
         new Attribute("cn", "Test")));

    assertNull(ue.getAttributeBeforeChange("uid"));

    assertNotNull(ue.getAttributeBeforeChange("cn"));
    assertEquals(ue.getAttributeAfterChange("cn"),
         new Attribute("cn", "Test"));

    assertNotNull(ue.getAttributeBeforeChange("member"));
    assertEquals(ue.getAttributeBeforeChange("member"), new Attribute("member",
         "uid=user.1,ou=People,dc=example,dc=com",
         "uid=user.2,ou=People,dc=example,dc=com",
         "uid=user.3,ou=People,dc=example,dc=com"));

    assertNull(ue.getAttributeAfterChange("uid"));

    assertNotNull(ue.getAttributeAfterChange("cn"));
    assertEquals(ue.getAttributeAfterChange("cn"),
         new Attribute("cn", "Test"));

    try
    {
      ue.getAttributeAfterChange("member");
      fail("Expected an exception when trying to get member after values");
    }
    catch (final ChangeLogEntryAttributeExceededMaxValuesException ex)
    {
      // This was expected.
      assertNotNull(ex.getAttributeInfo());
      assertTrue(ex.getAttributeInfo().getAttributeName().equalsIgnoreCase(
           "member"));
      assertEquals(ex.getAttributeInfo().getBeforeCount(), 3);
      assertEquals(ex.getAttributeInfo().getAfterCount(), 4);
    }

    assertNotNull(ue.constructPartialEntryBeforeChange());
    assertEquals(ue.constructPartialEntryBeforeChange(), new Entry(
         "dn: cn=Test,ou=Groups,dc=example,dc=com",
         "cn: Test",
         "member: uid=user.1,ou=People,dc=example,dc=com",
         "member: uid=user.2,ou=People,dc=example,dc=com",
         "member: uid=user.3,ou=People,dc=example,dc=com"));

    assertNotNull(ue.constructPartialEntryAfterChange());
    assertEquals(ue.constructPartialEntryAfterChange(), new Entry(
         "dn: cn=Test,ou=Groups,dc=example,dc=com",
         "cn: Test"));

    assertNotNull(ue.getTargetUniqueID());
    assertEquals(ue.getTargetUniqueID(),
         "468c6887-4fcc-38ea-9425-abcaa3c88be6");

    assertNotNull(ue.getLocalCSN());
    assertEquals(ue.getLocalCSN(), "00000131EDEDD535000000000006");

    assertNotNull(ue.getChangeTime());
    assertEquals(ue.getChangeTime().getTime(),
         StaticUtils.decodeGeneralizedTime("20110821200012Z").getTime());

    assertNotNull(ue.getTargetAttributeNames());
    assertFalse(ue.getTargetAttributeNames().isEmpty());
    assertEquals(ue.getTargetAttributeNames().size(), 1);

    assertNotNull(ue.getNotificationDestinationEntryUUIDs());
    assertFalse(ue.getNotificationDestinationEntryUUIDs().isEmpty());
    assertEquals(ue.getNotificationDestinationEntryUUIDs().size(), 2);

    assertNotNull(ue.getNotificationProperties());
    assertFalse(ue.getNotificationProperties().isEmpty());
    assertEquals(ue.getNotificationProperties().size(), 3);
  }



  /**
   * Provides coverage for cases in which an UnboundID changelog entry is
   * created for a modify operation without an extended set of content that
   * includes attributes with exceeded before but non-exceeded after value
   * counts.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedModifyChangeLogEntryWithExceededBeforeValues()
         throws Exception
  {
    final ChangeLogEntry e = ChangeLogEntry.constructChangeLogEntry(4L,
         new LDIFModifyChangeRecord("cn=Test,ou=Groups,dc=example,dc=com",
              new Modification(ModificationType.DELETE, "member",
                   "uid=user.4,ou=People,dc=example,dc=com")));
    assertNotNull(e);

    // Construct after values for the member attribute.
    final StringBuilder afterBuffer = new StringBuilder();
    afterBuffer.append("member: uid=user.1,ou=People,dc=example,dc=com");
    afterBuffer.append(StaticUtils.EOL);
    afterBuffer.append("member: uid=user.2,ou=People,dc=example,dc=com");
    afterBuffer.append(StaticUtils.EOL);
    afterBuffer.append("member: uid=user.3,ou=People,dc=example,dc=com");
    afterBuffer.append(StaticUtils.EOL);

    // Construct a key attribute value for the "cn" attribute.
    final StringBuilder keyAttrBuffer = new StringBuilder();
    keyAttrBuffer.append("cn: Test");
    keyAttrBuffer.append(StaticUtils.EOL);

    final Entry extendedEntry = e.duplicate();
    extendedEntry.addAttribute("ds-changelog-after-values",
         afterBuffer.toString());
    extendedEntry.addAttribute("ds-changelog-attr-exceeded-max-values-count",
         "attr=member,beforeCount=4,afterCount=3");
    extendedEntry.addAttribute("ds-changelog-entry-key-attr-values",
         keyAttrBuffer.toString());
    extendedEntry.addAttribute("targetUniqueID",
         "468c6887-4fcc-38ea-9425-abcaa3c88be6");
    extendedEntry.addAttribute("localCSN", "00000131EDEDD535000000000006");
    extendedEntry.addAttribute("changeTime", "20110821200012Z");
    extendedEntry.addAttribute("ds-changelog-target-attribute", "member");
    extendedEntry.addAttribute("ds-notification-destination-entry-uuid",
         "12345678-90ab-cdef-1234-567890abcdef",
         "23456789-0abC-def1-2345-67890abcdef1");
    extendedEntry.addAttribute("ds-changelog-notification-properties",
         "notification-property-1", "notification-property-2",
         "notification-property-3");


    final UnboundIDChangeLogEntry ue =
         new UnboundIDChangeLogEntry(extendedEntry);
    assertNotNull(ue);

    assertEquals(ue.getChangeNumber(), 4L);

    assertNotNull(ue.getTargetDN());
    assertEquals(new DN(ue.getTargetDN()),
         new DN("cn=Test,ou=Groups,dc=example,dc=com"));

    assertNotNull(ue.getChangeType());
    assertEquals(ue.getChangeType(), ChangeType.MODIFY);

    assertNull(ue.getAddAttributes());

    assertNull(ue.getDeletedEntryAttributes());

    assertNotNull(ue.getModifications());
    assertEquals(ue.getModifications().size(), 1);
    assertTrue(ue.getModifications().contains(new Modification(
         ModificationType.DELETE, "member",
         "uid=user.4,ou=People,dc=example,dc=com")));

    assertNull(ue.getNewRDN());

    assertFalse(ue.deleteOldRDN());

    assertNull(ue.getNewSuperior());

    assertNull(ue.getSoftDeleteToDN());

    assertNull(ue.getUndeleteFromDN());

    assertNull(ue.getChangeToSoftDeletedEntry());

    assertNotNull(ue.getNewDN());
    assertEquals(new DN(ue.getNewDN()),
         new DN("cn=Test,ou=Groups,dc=example,dc=com"));

    assertNotNull(ue.getUpdatedAttributesBeforeChange());
    assertTrue(ue.getUpdatedAttributesBeforeChange().isEmpty());

    assertNotNull(ue.getUpdatedAttributesAfterChange());
    assertEquals(ue.getUpdatedAttributesAfterChange().size(), 1);
    assertTrue(ue.getUpdatedAttributesAfterChange().contains(
         new Attribute("member",
              "uid=user.1,ou=People,dc=example,dc=com",
              "uid=user.2,ou=People,dc=example,dc=com",
              "uid=user.3,ou=People,dc=example,dc=com")));

    assertNotNull(ue.getAttributesThatExceededMaxValuesCount());
    assertEquals(ue.getAttributesThatExceededMaxValuesCount().size(), 1);
    assertTrue(ue.getAttributesThatExceededMaxValuesCount().contains(
         new ChangeLogEntryAttributeExceededMaxValuesCount(
              "attr=member,beforeCount=4,afterCount=3")));

    assertNotNull(ue.getKeyEntryAttributes());
    assertEquals(ue.getKeyEntryAttributes().size(), 1);
    assertTrue(ue.getKeyEntryAttributes().contains(
         new Attribute("cn", "Test")));

    assertNull(ue.getAttributeBeforeChange("uid"));

    assertNotNull(ue.getAttributeBeforeChange("cn"));
    assertEquals(ue.getAttributeAfterChange("cn"),
         new Attribute("cn", "Test"));

    try
    {
      ue.getAttributeBeforeChange("member");
      fail("Expected an exception when trying to get member before values");
    }
    catch (final ChangeLogEntryAttributeExceededMaxValuesException ex)
    {
      // This was expected.
      assertNotNull(ex.getAttributeInfo());
      assertTrue(ex.getAttributeInfo().getAttributeName().equalsIgnoreCase(
           "member"));
      assertEquals(ex.getAttributeInfo().getBeforeCount(), 4);
      assertEquals(ex.getAttributeInfo().getAfterCount(), 3);
    }

    assertNull(ue.getAttributeAfterChange("uid"));

    assertNotNull(ue.getAttributeAfterChange("cn"));
    assertEquals(ue.getAttributeAfterChange("cn"),
         new Attribute("cn", "Test"));

    assertNotNull(ue.getAttributeAfterChange("member"));
    assertEquals(ue.getAttributeAfterChange("member"), new Attribute("member",
         "uid=user.1,ou=People,dc=example,dc=com",
         "uid=user.2,ou=People,dc=example,dc=com",
         "uid=user.3,ou=People,dc=example,dc=com"));

    assertNotNull(ue.constructPartialEntryBeforeChange());
    assertEquals(ue.constructPartialEntryBeforeChange(), new Entry(
         "dn: cn=Test,ou=Groups,dc=example,dc=com",
         "cn: Test"));

    assertNotNull(ue.constructPartialEntryAfterChange());
    assertEquals(ue.constructPartialEntryAfterChange(), new Entry(
         "dn: cn=Test,ou=Groups,dc=example,dc=com",
         "cn: Test",
         "member: uid=user.1,ou=People,dc=example,dc=com",
         "member: uid=user.2,ou=People,dc=example,dc=com",
         "member: uid=user.3,ou=People,dc=example,dc=com"));

    assertNotNull(ue.getTargetUniqueID());
    assertEquals(ue.getTargetUniqueID(),
         "468c6887-4fcc-38ea-9425-abcaa3c88be6");

    assertNotNull(ue.getLocalCSN());
    assertEquals(ue.getLocalCSN(), "00000131EDEDD535000000000006");

    assertNotNull(ue.getChangeTime());
    assertEquals(ue.getChangeTime().getTime(),
         StaticUtils.decodeGeneralizedTime("20110821200012Z").getTime());

    assertNotNull(ue.getTargetAttributeNames());
    assertFalse(ue.getTargetAttributeNames().isEmpty());
    assertEquals(ue.getTargetAttributeNames().size(), 1);

    assertNotNull(ue.getNotificationDestinationEntryUUIDs());
    assertFalse(ue.getNotificationDestinationEntryUUIDs().isEmpty());
    assertEquals(ue.getNotificationDestinationEntryUUIDs().size(), 2);

    assertNotNull(ue.getNotificationProperties());
    assertFalse(ue.getNotificationProperties().isEmpty());
    assertEquals(ue.getNotificationProperties().size(), 3);
  }



  /**
   * Provides coverage for cases in which an UnboundID changelog entry is
   * created for a modify DN operation without any UnboundID-specific content.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicModifyDNChangeLogEntry()
         throws Exception
  {
    final ChangeLogEntry e = ChangeLogEntry.constructChangeLogEntry(4L,
         new LDIFModifyDNChangeRecord(
              "uid=test.user,ou=People,dc=example,dc=com",
              "cn=Test User", false, null));
    assertNotNull(e);

    final UnboundIDChangeLogEntry ue = new UnboundIDChangeLogEntry(e);
    assertNotNull(ue);

    assertEquals(ue.getChangeNumber(), 4L);

    assertNotNull(ue.getTargetDN());
    assertEquals(new DN(ue.getTargetDN()),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));

    assertNotNull(ue.getChangeType());
    assertEquals(ue.getChangeType(), ChangeType.MODIFY_DN);

    assertNull(ue.getAddAttributes());

    assertNull(ue.getDeletedEntryAttributes());

    assertNull(ue.getModifications());

    assertNotNull(ue.getNewRDN());
    assertEquals(new RDN(ue.getNewRDN()), new RDN("cn=Test User"));

    assertFalse(ue.deleteOldRDN());

    assertNull(ue.getNewSuperior());

    assertNull(ue.getSoftDeleteToDN());

    assertNull(ue.getUndeleteFromDN());

    assertNull(ue.getChangeToSoftDeletedEntry());

    assertNotNull(ue.getNewDN());
    assertEquals(new DN(ue.getNewDN()),
         new DN("cn=Test User,ou=People,dc=example,dc=com"));

    assertNotNull(ue.getUpdatedAttributesBeforeChange());
    assertTrue(ue.getUpdatedAttributesBeforeChange().isEmpty());

    assertNotNull(ue.getUpdatedAttributesAfterChange());
    assertTrue(ue.getUpdatedAttributesAfterChange().isEmpty());

    assertNotNull(ue.getAttributesThatExceededMaxValuesCount());
    assertTrue(ue.getAttributesThatExceededMaxValuesCount().isEmpty());

    assertNotNull(ue.getKeyEntryAttributes());
    assertTrue(ue.getKeyEntryAttributes().isEmpty());

    assertEquals(ue.getNumExcludedUserAttributes(), -1);

    assertEquals(ue.getNumExcludedOperationalAttributes(), -1);

    assertNotNull(ue.getExcludedUserAttributeNames());
    assertTrue(ue.getExcludedUserAttributeNames().isEmpty());

    assertNotNull(ue.getExcludedOperationalAttributeNames());
    assertTrue(ue.getExcludedOperationalAttributeNames().isEmpty());

    assertNull(ue.getAttributeBeforeChange("uid"));

    assertNull(ue.getAttributeBeforeChange("cn"));

    assertNull(ue.getAttributeBeforeChange("description"));

    assertNull(ue.getAttributeAfterChange("uid"));

    assertNull(ue.getAttributeAfterChange("cn"));

    assertNull(ue.getAttributeAfterChange("description"));

    assertNotNull(ue.constructPartialEntryBeforeChange());
    assertEquals(ue.constructPartialEntryBeforeChange(),
         new Entry("uid=test.user,ou=People,dc=example,dc=com"));

    assertNotNull(ue.constructPartialEntryAfterChange());
    assertEquals(ue.constructPartialEntryAfterChange(),
         new Entry("cn=Test User,ou=People,dc=example,dc=com"));

    assertNull(ue.getTargetUniqueID());

    assertNull(ue.getLocalCSN());

    assertNull(ue.getChangeTime());

    assertNotNull(ue.getTargetAttributeNames());
    assertTrue(ue.getTargetAttributeNames().isEmpty());

    assertNotNull(ue.getNotificationDestinationEntryUUIDs());
    assertTrue(ue.getNotificationDestinationEntryUUIDs().isEmpty());

    assertNotNull(ue.getNotificationProperties());
    assertTrue(ue.getNotificationProperties().isEmpty());
  }



  /**
   * Provides coverage for cases in which an UnboundID changelog entry is
   * created for a modify DN operation an extended set of content.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedModifyDNChangeLogEntry()
         throws Exception
  {
    final ChangeLogEntry e = ChangeLogEntry.constructChangeLogEntry(4L,
         new LDIFModifyDNChangeRecord(
              "uid=test.1,ou=People,dc=example,dc=com",
              "uid=test.2", true, "ou=Users,o=example.com"));
    assertNotNull(e);

    // Construct before values for the uid attribute.
    final StringBuilder beforeBuffer = new StringBuilder();
    beforeBuffer.append("uid: test.1");
    beforeBuffer.append(StaticUtils.EOL);

    // Construct after values for the uid attribute.
    final StringBuilder afterBuffer = new StringBuilder();
    afterBuffer.append("uid: test.2");
    afterBuffer.append(StaticUtils.EOL);

    // Construct a key attribute value for the "cn" attribute.
    final StringBuilder keyAttrBuffer = new StringBuilder();
    keyAttrBuffer.append("cn: Test User");
    keyAttrBuffer.append(StaticUtils.EOL);

    final Entry extendedEntry = e.duplicate();
    extendedEntry.addAttribute("ds-changelog-before-values",
         beforeBuffer.toString());
    extendedEntry.addAttribute("ds-changelog-after-values",
         afterBuffer.toString());
    extendedEntry.addAttribute("ds-changelog-entry-key-attr-values",
         keyAttrBuffer.toString());
    extendedEntry.addAttribute(
         "ds-changelog-num-excluded-operational-attributes", "2");
    extendedEntry.addAttribute(
         "ds-changelog-excluded-operational-attribute", "modifiersName",
         "modifyTimestamp");
    extendedEntry.addAttribute("targetUniqueID",
         "468c6887-4fcc-38ea-9425-abcaa3c88be6");
    extendedEntry.addAttribute("localCSN", "00000131EDEDD535000000000006");
    extendedEntry.addAttribute("changeTime", "20110821200012Z");
    extendedEntry.addAttribute("ds-changelog-target-attribute", "uid");
    extendedEntry.addAttribute("ds-notification-destination-entry-uuid",
         "12345678-90ab-cdef-1234-567890abcdef",
         "23456789-0abC-def1-2345-67890abcdef1");
    extendedEntry.addAttribute("ds-changelog-notification-properties",
         "notification-property-1", "notification-property-2",
         "notification-property-3");


    final UnboundIDChangeLogEntry ue =
         new UnboundIDChangeLogEntry(extendedEntry);
    assertNotNull(ue);

    assertEquals(ue.getChangeNumber(), 4L);

    assertNotNull(ue.getTargetDN());
    assertEquals(new DN(ue.getTargetDN()),
         new DN("uid=test.1,ou=People,dc=example,dc=com"));

    assertNotNull(ue.getChangeType());
    assertEquals(ue.getChangeType(), ChangeType.MODIFY_DN);

    assertNull(ue.getAddAttributes());

    assertNull(ue.getDeletedEntryAttributes());

    assertNull(ue.getModifications());

    assertNotNull(ue.getNewRDN());
    assertEquals(new RDN(ue.getNewRDN()), new RDN("uid=test.2"));

    assertTrue(ue.deleteOldRDN());

    assertNotNull(ue.getNewSuperior());
    assertEquals(new DN(ue.getNewSuperior()),
         new DN("ou=Users,o=example.com"));

    assertNull(ue.getSoftDeleteToDN());

    assertNull(ue.getUndeleteFromDN());

    assertNull(ue.getChangeToSoftDeletedEntry());

    assertNotNull(ue.getNewDN());
    assertEquals(new DN(ue.getNewDN()),
         new DN("uid=test.2,ou=Users,o=example.com"));

    assertNotNull(ue.getUpdatedAttributesBeforeChange());
    assertEquals(ue.getUpdatedAttributesBeforeChange().size(), 1);
    assertTrue(ue.getUpdatedAttributesBeforeChange().contains(
         new Attribute("uid", "test.1")));

    assertNotNull(ue.getUpdatedAttributesAfterChange());
    assertEquals(ue.getUpdatedAttributesAfterChange().size(), 1);
    assertTrue(ue.getUpdatedAttributesAfterChange().contains(
         new Attribute("uid", "test.2")));

    assertNotNull(ue.getAttributesThatExceededMaxValuesCount());
    assertTrue(ue.getAttributesThatExceededMaxValuesCount().isEmpty());

    assertNotNull(ue.getKeyEntryAttributes());
    assertEquals(ue.getKeyEntryAttributes().size(), 1);
    assertTrue(ue.getKeyEntryAttributes().contains(
         new Attribute("cn", "Test User")));

    assertEquals(ue.getNumExcludedUserAttributes(), -1);

    assertEquals(ue.getNumExcludedOperationalAttributes(), 2);

    assertNotNull(ue.getExcludedUserAttributeNames());
    assertTrue(ue.getExcludedUserAttributeNames().isEmpty());

    assertNotNull(ue.getExcludedOperationalAttributeNames());
    assertFalse(ue.getExcludedOperationalAttributeNames().isEmpty());
    assertTrue(ue.getExcludedOperationalAttributeNames().contains(
         "modifiersName"));
    assertTrue(ue.getExcludedOperationalAttributeNames().contains(
         "modifyTimestamp"));

    assertNotNull(ue.getAttributeBeforeChange("uid"));
    assertEquals(ue.getAttributeBeforeChange("uid"),
         new Attribute("uid", "test.1"));

    assertNotNull(ue.getAttributeBeforeChange("cn"));
    assertEquals(ue.getAttributeBeforeChange("cn"),
         new Attribute("cn", "Test User"));

    assertNull(ue.getAttributeBeforeChange("description"));

    assertNotNull(ue.getAttributeAfterChange("uid"));
    assertEquals(ue.getAttributeAfterChange("uid"),
         new Attribute("uid", "test.2"));

    assertNotNull(ue.getAttributeAfterChange("cn"));
    assertEquals(ue.getAttributeAfterChange("cn"),
         new Attribute("cn", "Test User"));

    assertNull(ue.getAttributeAfterChange("description"));

    assertNotNull(ue.constructPartialEntryBeforeChange());
    assertEquals(ue.constructPartialEntryBeforeChange(), new Entry(
         "dn: uid=test.1,ou=People,dc=example,dc=com",
         "uid: test.1",
         "cn: Test User"));

    assertNotNull(ue.constructPartialEntryAfterChange());
    assertEquals(ue.constructPartialEntryAfterChange(), new Entry(
         "dn: uid=test.2,ou=Users,o=example.com",
         "uid: test.2",
         "cn: Test User"));

    assertNotNull(ue.getTargetUniqueID());
    assertEquals(ue.getTargetUniqueID(),
         "468c6887-4fcc-38ea-9425-abcaa3c88be6");

    assertNotNull(ue.getLocalCSN());
    assertEquals(ue.getLocalCSN(), "00000131EDEDD535000000000006");

    assertNotNull(ue.getChangeTime());
    assertEquals(ue.getChangeTime().getTime(),
         StaticUtils.decodeGeneralizedTime("20110821200012Z").getTime());

    assertNotNull(ue.getTargetAttributeNames());
    assertFalse(ue.getTargetAttributeNames().isEmpty());
    assertEquals(ue.getTargetAttributeNames().size(), 1);

    assertNotNull(ue.getNotificationDestinationEntryUUIDs());
    assertFalse(ue.getNotificationDestinationEntryUUIDs().isEmpty());
    assertEquals(ue.getNotificationDestinationEntryUUIDs().size(), 2);

    assertNotNull(ue.getNotificationProperties());
    assertFalse(ue.getNotificationProperties().isEmpty());
    assertEquals(ue.getNotificationProperties().size(), 3);
  }
}
