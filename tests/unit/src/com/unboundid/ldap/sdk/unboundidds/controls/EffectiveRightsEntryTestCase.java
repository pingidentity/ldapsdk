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
package com.unboundid.ldap.sdk.unboundidds.controls;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code EffectiveRightsEntry}
 * class.
 */
public class EffectiveRightsEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the case in which an entry does not have any
   * aclRights information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoAclRights()
         throws Exception
  {
    Entry entry = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    EffectiveRightsEntry e = new EffectiveRightsEntry(entry);

    assertFalse(e.rightsInformationAvailable());

    assertNull(e.getEntryRights());

    assertFalse(e.hasEntryRight(EntryRight.READ));

    assertNull(e.getAttributeRights());

    assertNull(e.getAttributeRights("dc"));

    assertFalse(e.hasAttributeRight(AttributeRight.READ, "dc"));

    assertNull(e.getAttributeRights("undefined"));

    assertFalse(e.hasAttributeRight(AttributeRight.READ, "undefined"));
  }



  /**
   * Provides test coverage for the case for a case in which the entry has
   * entry rights information but not attribute rights.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyEntryRights()
         throws Exception
  {
    Entry entry = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "aclRights;entryLevel: add:1,delete:1,read:1,write:1,proxy:1");

    EffectiveRightsEntry e = new EffectiveRightsEntry(entry);

    assertTrue(e.rightsInformationAvailable());

    assertNotNull(e.getEntryRights());
    assertFalse(e.getEntryRights().isEmpty());

    assertTrue(e.hasEntryRight(EntryRight.READ));

    assertNull(e.getAttributeRights());

    assertNull(e.getAttributeRights("dc"));

    assertFalse(e.hasAttributeRight(AttributeRight.READ, "dc"));

    assertNull(e.getAttributeRights("undefined"));

    assertFalse(e.hasAttributeRight(AttributeRight.READ, "undefined"));
  }



  /**
   * Provides test coverage for the case for a case in which the entry has
   * attribute rights information but not entry rights.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyAttributeRights()
         throws Exception
  {
    Entry entry = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "aclRights;attributeLevel;dc: search:1,read:1,compare:1,write:1," +
              "selfwrite_add:1,selfwrite_delete:1,proxy:1",
         "aclRights;attributeLevel;objectClass: search:1,read:1,compare:1," +
              "write:1,selfwrite_add:1,selfwrite_delete:1,proxy:1");

    EffectiveRightsEntry e = new EffectiveRightsEntry(entry);

    assertTrue(e.rightsInformationAvailable());

    assertNull(e.getEntryRights());

    assertFalse(e.hasEntryRight(EntryRight.READ));

    assertNotNull(e.getAttributeRights());

    assertNotNull(e.getAttributeRights("dc"));
    assertFalse(e.getAttributeRights("dc").isEmpty());

    assertTrue(e.hasAttributeRight(AttributeRight.READ, "dc"));

    assertNull(e.getAttributeRights("undefined"));

    assertFalse(e.hasAttributeRight(AttributeRight.READ, "undefined"));
  }



  /**
   * Provides test coverage for the case for a case in which the set of rights
   * information includes unrecognized entry and attribute rights.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnrecognizedRights()
         throws Exception
  {
    Entry entry = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "aclRights;entryLevel: add:1,delete:1,read:1,write:1,proxy:1;" +
              "unrecognized:1",
         "aclRights;attributeLevel;dc: search:1,read:1,compare:1,write:1," +
              "selfwrite_add:1,selfwrite_delete:1,proxy:1;unrecognized:1",
         "aclRights;attributeLevel;objectClass: search:1,read:1,compare:1," +
              "write:1,selfwrite_add:1,selfwrite_delete:1,proxy:1," +
              "unrecognized:1");

    EffectiveRightsEntry e = new EffectiveRightsEntry(entry);

    assertTrue(e.rightsInformationAvailable());

    assertNotNull(e.getEntryRights());
    assertFalse(e.getEntryRights().isEmpty());

    assertTrue(e.hasEntryRight(EntryRight.READ));

    assertNotNull(e.getAttributeRights());

    assertNotNull(e.getAttributeRights("dc"));
    assertFalse(e.getAttributeRights("dc").isEmpty());

    assertTrue(e.hasAttributeRight(AttributeRight.READ, "dc"));

    assertNull(e.getAttributeRights("undefined"));

    assertFalse(e.hasAttributeRight(AttributeRight.READ, "undefined"));
  }



  /**
   * Provides test coverage for the case for a case in which a user has all
   * rights.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllRights()
         throws Exception
  {
    Entry entry = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "aclRights;entryLevel: add:1,delete:1,read:1,write:1,proxy:1",
         "aclRights;attributeLevel;dc: search:1,read:1,compare:1,write:1," +
              "selfwrite_add:1,selfwrite_delete:1,proxy:1",
         "aclRights;attributeLevel;objectClass: search:1,read:1,compare:1," +
              "write:1,selfwrite_add:1,selfwrite_delete:1,proxy:1");

    EffectiveRightsEntry e = new EffectiveRightsEntry(entry);

    assertTrue(e.rightsInformationAvailable());

    assertNotNull(e.getEntryRights());
    assertFalse(e.getEntryRights().isEmpty());

    assertTrue(e.hasEntryRight(EntryRight.READ));

    assertNotNull(e.getAttributeRights());

    assertNotNull(e.getAttributeRights("dc"));
    assertFalse(e.getAttributeRights("dc").isEmpty());

    assertTrue(e.hasAttributeRight(AttributeRight.READ, "dc"));

    assertNull(e.getAttributeRights("undefined"));

    assertFalse(e.hasAttributeRight(AttributeRight.READ, "undefined"));
  }



  /**
   * Provides test coverage for the case for a case in which a user has no
   * rights.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoRights()
         throws Exception
  {
    Entry entry = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "aclRights;entryLevel: add:0,delete:0,read:0,write:0,proxy:0",
         "aclRights;attributeLevel;dc: search:0,read:0,compare:0,write:0," +
              "selfwrite_add:0,selfwrite_delete:0,proxy:0",
         "aclRights;attributeLevel;objectClass: search:0,read:0,compare:0," +
              "write:0,selfwrite_add:0,selfwrite_delete:0,proxy:0");

    EffectiveRightsEntry e = new EffectiveRightsEntry(entry);

    assertTrue(e.rightsInformationAvailable());

    assertNotNull(e.getEntryRights());
    assertTrue(e.getEntryRights().isEmpty());

    assertFalse(e.hasEntryRight(EntryRight.READ));

    assertNotNull(e.getAttributeRights());

    assertNotNull(e.getAttributeRights("dc"));
    assertTrue(e.getAttributeRights("dc").isEmpty());

    assertFalse(e.hasAttributeRight(AttributeRight.READ, "dc"));

    assertNull(e.getAttributeRights("undefined"));

    assertFalse(e.hasAttributeRight(AttributeRight.READ, "undefined"));
  }
}
