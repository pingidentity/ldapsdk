/*
 * Copyright 2021-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021-2024 Ping Identity Corporation
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
 * Copyright (C) 2021-2024 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.util.Collections;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ReadOnlyEntry;



/**
 * This class provides a set of test cases for the ldap-diff processor result.
 */
public final class LDAPDiffProcessorResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a result that indicates that there are no changes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEntryMissingResult()
         throws Exception
  {
    final LDAPDiffProcessorResult result =
         LDAPDiffProcessorResult.createEntryMissingResult("dc=example,dc=com");
    assertNotNull(result);

    assertNotNull(result.getDN());
    assertEquals(result.getDN(), "dc=example,dc=com");

    assertTrue(result.isEntryMissing());

    assertNull(result.getChangeType());

    assertNull(result.getEntry());

    assertNull(result.getModifications());

    assertNotNull(result.toString());
  }



  /**
   * Tests the behavior for a result that indicates that there are no changes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoChangesResult()
         throws Exception
  {
    final LDAPDiffProcessorResult result =
         LDAPDiffProcessorResult.createNoChangesResult("dc=example,dc=com");
    assertNotNull(result);

    assertNotNull(result.getDN());
    assertEquals(result.getDN(), "dc=example,dc=com");

    assertFalse(result.isEntryMissing());

    assertNull(result.getChangeType());

    assertNull(result.getEntry());

    assertNull(result.getModifications());

    assertNotNull(result.toString());
  }



  /**
   * Tests the behavior for a result that indicates that an entry needs to be
   * added to the source server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddResult()
         throws Exception
  {
    final LDAPDiffProcessorResult result =
         LDAPDiffProcessorResult.createAddResult(new ReadOnlyEntry(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example")));
    assertNotNull(result);

    assertNotNull(result.getDN());
    assertEquals(result.getDN(), "dc=example,dc=com");

    assertFalse(result.isEntryMissing());

    assertNotNull(result.getChangeType());
    assertEquals(result.getChangeType(), ChangeType.ADD);

    assertNotNull(result.getEntry());
    assertEquals(result.getEntry(),
         new ReadOnlyEntry(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example")));

    assertNull(result.getModifications());

    assertNotNull(result.toString());
  }



  /**
   * Tests the behavior for a result that indicates that an entry needs to be
   * deleted from the source server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteResult()
         throws Exception
  {
    final LDAPDiffProcessorResult result =
         LDAPDiffProcessorResult.createDeleteResult(new ReadOnlyEntry(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example")));
    assertNotNull(result);

    assertNotNull(result.getDN());
    assertEquals(result.getDN(), "dc=example,dc=com");

    assertFalse(result.isEntryMissing());

    assertNotNull(result.getChangeType());
    assertEquals(result.getChangeType(), ChangeType.DELETE);

    assertNotNull(result.getEntry());
    assertEquals(result.getEntry(),
         new ReadOnlyEntry(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example")));

    assertNull(result.getModifications());

    assertNotNull(result.toString());
  }



  /**
   * Tests the behavior for a result that indicates that an entry needs to be
   * modified in the source server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyResult()
         throws Exception
  {
    final List<Modification> mods = Collections.singletonList(
         new Modification(ModificationType.REPLACE, "description", "foo"));

    final LDAPDiffProcessorResult result =
         LDAPDiffProcessorResult.createModifyResult("dc=example,dc=com", mods);
    assertNotNull(result);

    assertNotNull(result.getDN());
    assertEquals(result.getDN(), "dc=example,dc=com");

    assertFalse(result.isEntryMissing());

    assertNotNull(result.getChangeType());
    assertEquals(result.getChangeType(), ChangeType.MODIFY);

    assertNull(result.getEntry());

    assertNotNull(result.getModifications());
    assertEquals(result.getModifications(), mods);

    assertNotNull(result.toString());
  }
}
