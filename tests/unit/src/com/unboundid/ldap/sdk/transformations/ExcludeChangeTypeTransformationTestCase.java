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
package com.unboundid.ldap.sdk.transformations;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFModifyDNChangeRecord;



/**
 * This class provides a set of test cases for the exclude change type
 * transformation.
 */
public final class ExcludeChangeTypeTransformationTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when the set of change types to exclude is empty.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeEmptySet()
         throws Exception
  {
    final ExcludeChangeTypeTransformation t =
         new ExcludeChangeTypeTransformation();


    final LDIFAddChangeRecord addChangeRecord =
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));

    assertNotNull(t.transformChangeRecord(addChangeRecord));
    assertEquals(t.transformChangeRecord(addChangeRecord), addChangeRecord);

    assertNotNull(t.translate(addChangeRecord, 0));
    assertEquals(t.translate(addChangeRecord, 0), addChangeRecord);

    assertNotNull(t.translateChangeRecordToWrite(addChangeRecord));
    assertEquals(t.translateChangeRecordToWrite(addChangeRecord),
         addChangeRecord);


    final LDIFDeleteChangeRecord deleteChangeRecord =
         new LDIFDeleteChangeRecord("dc=example,dc=com");

    assertNotNull(t.transformChangeRecord(deleteChangeRecord));
    assertEquals(t.transformChangeRecord(deleteChangeRecord),
         deleteChangeRecord);

    assertNotNull(t.translate(deleteChangeRecord, 0));
    assertEquals(t.translate(deleteChangeRecord, 0), deleteChangeRecord);

    assertNotNull(t.translateChangeRecordToWrite(deleteChangeRecord));
    assertEquals(t.translateChangeRecordToWrite(deleteChangeRecord),
         deleteChangeRecord);


    final LDIFModifyChangeRecord modifyChangeRecord =
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=example,dc=com",
              "changetype: modify",
              "replace: description",
              "description: foo"));

    assertNotNull(t.transformChangeRecord(modifyChangeRecord));
    assertEquals(t.transformChangeRecord(modifyChangeRecord),
         modifyChangeRecord);

    assertNotNull(t.translate(modifyChangeRecord, 0));
    assertEquals(t.translate(modifyChangeRecord, 0), modifyChangeRecord);

    assertNotNull(t.translateChangeRecordToWrite(modifyChangeRecord));
    assertEquals(t.translateChangeRecordToWrite(modifyChangeRecord),
         modifyChangeRecord);


    final LDIFModifyDNChangeRecord modifyDNChangeRecord =
         new LDIFModifyDNChangeRecord("ou=People,dc=example,dc=com",
              "ou=Users", true, null);

    assertNotNull(t.transformChangeRecord(modifyDNChangeRecord));
    assertEquals(t.transformChangeRecord(modifyDNChangeRecord),
         modifyDNChangeRecord);

    assertNotNull(t.translate(modifyDNChangeRecord, 0));
    assertEquals(t.translate(modifyDNChangeRecord, 0), modifyDNChangeRecord);

    assertNotNull(t.translateChangeRecordToWrite(modifyDNChangeRecord));
    assertEquals(t.translateChangeRecordToWrite(modifyDNChangeRecord),
         modifyDNChangeRecord);
  }



  /**
   * Tests the behavior when the set of change types to exclude is
   * {@code null}}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeNullSet()
         throws Exception
  {
    final ExcludeChangeTypeTransformation t =
         new ExcludeChangeTypeTransformation((ChangeType[]) null);


    final LDIFAddChangeRecord addChangeRecord =
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));

    assertNotNull(t.transformChangeRecord(addChangeRecord));
    assertEquals(t.transformChangeRecord(addChangeRecord), addChangeRecord);

    assertNotNull(t.translate(addChangeRecord, 0));
    assertEquals(t.translate(addChangeRecord, 0), addChangeRecord);

    assertNotNull(t.translateChangeRecordToWrite(addChangeRecord));
    assertEquals(t.translateChangeRecordToWrite(addChangeRecord),
         addChangeRecord);


    final LDIFDeleteChangeRecord deleteChangeRecord =
         new LDIFDeleteChangeRecord("dc=example,dc=com");

    assertNotNull(t.transformChangeRecord(deleteChangeRecord));
    assertEquals(t.transformChangeRecord(deleteChangeRecord),
         deleteChangeRecord);

    assertNotNull(t.translate(deleteChangeRecord, 0));
    assertEquals(t.translate(deleteChangeRecord, 0), deleteChangeRecord);

    assertNotNull(t.translateChangeRecordToWrite(deleteChangeRecord));
    assertEquals(t.translateChangeRecordToWrite(deleteChangeRecord),
         deleteChangeRecord);


    final LDIFModifyChangeRecord modifyChangeRecord =
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=example,dc=com",
              "changetype: modify",
              "replace: description",
              "description: foo"));

    assertNotNull(t.transformChangeRecord(modifyChangeRecord));
    assertEquals(t.transformChangeRecord(modifyChangeRecord),
         modifyChangeRecord);

    assertNotNull(t.translate(modifyChangeRecord, 0));
    assertEquals(t.translate(modifyChangeRecord, 0), modifyChangeRecord);

    assertNotNull(t.translateChangeRecordToWrite(modifyChangeRecord));
    assertEquals(t.translateChangeRecordToWrite(modifyChangeRecord),
         modifyChangeRecord);


    final LDIFModifyDNChangeRecord modifyDNChangeRecord =
         new LDIFModifyDNChangeRecord("ou=People,dc=example,dc=com",
              "ou=Users", true, null);

    assertNotNull(t.transformChangeRecord(modifyDNChangeRecord));
    assertEquals(t.transformChangeRecord(modifyDNChangeRecord),
         modifyDNChangeRecord);

    assertNotNull(t.translate(modifyDNChangeRecord, 0));
    assertEquals(t.translate(modifyDNChangeRecord, 0), modifyDNChangeRecord);

    assertNotNull(t.translateChangeRecordToWrite(modifyDNChangeRecord));
    assertEquals(t.translateChangeRecordToWrite(modifyDNChangeRecord),
         modifyDNChangeRecord);
  }



  /**
   * Tests the behavior when the set of change types to exclude contains only
   * the add change type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeAddChangeType()
         throws Exception
  {
    final ExcludeChangeTypeTransformation t =
         new ExcludeChangeTypeTransformation(ChangeType.ADD);


    final LDIFAddChangeRecord addChangeRecord =
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));

    assertNull(t.transformChangeRecord(addChangeRecord));

    assertNull(t.translate(addChangeRecord, 0));

    assertNull(t.translateChangeRecordToWrite(addChangeRecord));


    final LDIFDeleteChangeRecord deleteChangeRecord =
         new LDIFDeleteChangeRecord("dc=example,dc=com");

    assertNotNull(t.transformChangeRecord(deleteChangeRecord));
    assertEquals(t.transformChangeRecord(deleteChangeRecord),
         deleteChangeRecord);

    assertNotNull(t.translate(deleteChangeRecord, 0));
    assertEquals(t.translate(deleteChangeRecord, 0), deleteChangeRecord);

    assertNotNull(t.translateChangeRecordToWrite(deleteChangeRecord));
    assertEquals(t.translateChangeRecordToWrite(deleteChangeRecord),
         deleteChangeRecord);


    final LDIFModifyChangeRecord modifyChangeRecord =
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=example,dc=com",
              "changetype: modify",
              "replace: description",
              "description: foo"));

    assertNotNull(t.transformChangeRecord(modifyChangeRecord));
    assertEquals(t.transformChangeRecord(modifyChangeRecord),
         modifyChangeRecord);

    assertNotNull(t.translate(modifyChangeRecord, 0));
    assertEquals(t.translate(modifyChangeRecord, 0), modifyChangeRecord);

    assertNotNull(t.translateChangeRecordToWrite(modifyChangeRecord));
    assertEquals(t.translateChangeRecordToWrite(modifyChangeRecord),
         modifyChangeRecord);


    final LDIFModifyDNChangeRecord modifyDNChangeRecord =
         new LDIFModifyDNChangeRecord("ou=People,dc=example,dc=com",
              "ou=Users", true, null);

    assertNotNull(t.transformChangeRecord(modifyDNChangeRecord));
    assertEquals(t.transformChangeRecord(modifyDNChangeRecord),
         modifyDNChangeRecord);

    assertNotNull(t.translate(modifyDNChangeRecord, 0));
    assertEquals(t.translate(modifyDNChangeRecord, 0), modifyDNChangeRecord);

    assertNotNull(t.translateChangeRecordToWrite(modifyDNChangeRecord));
    assertEquals(t.translateChangeRecordToWrite(modifyDNChangeRecord),
         modifyDNChangeRecord);
  }



  /**
   * Tests the behavior when the set of change types to exclude contains only
   * the delete change type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeDeleteChangeType()
         throws Exception
  {
    final ExcludeChangeTypeTransformation t =
         new ExcludeChangeTypeTransformation(ChangeType.DELETE);


    final LDIFAddChangeRecord addChangeRecord =
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));

    assertNotNull(t.transformChangeRecord(addChangeRecord));
    assertEquals(t.transformChangeRecord(addChangeRecord), addChangeRecord);

    assertNotNull(t.translate(addChangeRecord, 0));
    assertEquals(t.translate(addChangeRecord, 0), addChangeRecord);

    assertNotNull(t.translateChangeRecordToWrite(addChangeRecord));
    assertEquals(t.translateChangeRecordToWrite(addChangeRecord),
         addChangeRecord);


    final LDIFDeleteChangeRecord deleteChangeRecord =
         new LDIFDeleteChangeRecord("dc=example,dc=com");

    assertNull(t.transformChangeRecord(deleteChangeRecord));

    assertNull(t.translate(deleteChangeRecord, 0));

    assertNull(t.translateChangeRecordToWrite(deleteChangeRecord));


    final LDIFModifyChangeRecord modifyChangeRecord =
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=example,dc=com",
              "changetype: modify",
              "replace: description",
              "description: foo"));

    assertNotNull(t.transformChangeRecord(modifyChangeRecord));
    assertEquals(t.transformChangeRecord(modifyChangeRecord),
         modifyChangeRecord);

    assertNotNull(t.translate(modifyChangeRecord, 0));
    assertEquals(t.translate(modifyChangeRecord, 0), modifyChangeRecord);

    assertNotNull(t.translateChangeRecordToWrite(modifyChangeRecord));
    assertEquals(t.translateChangeRecordToWrite(modifyChangeRecord),
         modifyChangeRecord);


    final LDIFModifyDNChangeRecord modifyDNChangeRecord =
         new LDIFModifyDNChangeRecord("ou=People,dc=example,dc=com",
              "ou=Users", true, null);

    assertNotNull(t.transformChangeRecord(modifyDNChangeRecord));
    assertEquals(t.transformChangeRecord(modifyDNChangeRecord),
         modifyDNChangeRecord);

    assertNotNull(t.translate(modifyDNChangeRecord, 0));
    assertEquals(t.translate(modifyDNChangeRecord, 0), modifyDNChangeRecord);

    assertNotNull(t.translateChangeRecordToWrite(modifyDNChangeRecord));
    assertEquals(t.translateChangeRecordToWrite(modifyDNChangeRecord),
         modifyDNChangeRecord);
  }



  /**
   * Tests the behavior when the set of change types to exclude contains only
   * the modify change type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeModifyChangeType()
         throws Exception
  {
    final ExcludeChangeTypeTransformation t =
         new ExcludeChangeTypeTransformation(ChangeType.MODIFY);


    final LDIFAddChangeRecord addChangeRecord =
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));

    assertNotNull(t.transformChangeRecord(addChangeRecord));
    assertEquals(t.transformChangeRecord(addChangeRecord), addChangeRecord);

    assertNotNull(t.translate(addChangeRecord, 0));
    assertEquals(t.translate(addChangeRecord, 0), addChangeRecord);

    assertNotNull(t.translateChangeRecordToWrite(addChangeRecord));
    assertEquals(t.translateChangeRecordToWrite(addChangeRecord),
         addChangeRecord);


    final LDIFDeleteChangeRecord deleteChangeRecord =
         new LDIFDeleteChangeRecord("dc=example,dc=com");

    assertNotNull(t.transformChangeRecord(deleteChangeRecord));
    assertEquals(t.transformChangeRecord(deleteChangeRecord),
         deleteChangeRecord);

    assertNotNull(t.translate(deleteChangeRecord, 0));
    assertEquals(t.translate(deleteChangeRecord, 0), deleteChangeRecord);

    assertNotNull(t.translateChangeRecordToWrite(deleteChangeRecord));
    assertEquals(t.translateChangeRecordToWrite(deleteChangeRecord),
         deleteChangeRecord);


    final LDIFModifyChangeRecord modifyChangeRecord =
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=example,dc=com",
              "changetype: modify",
              "replace: description",
              "description: foo"));

    assertNull(t.transformChangeRecord(modifyChangeRecord));

    assertNull(t.translate(modifyChangeRecord, 0));

    assertNull(t.translateChangeRecordToWrite(modifyChangeRecord));


    final LDIFModifyDNChangeRecord modifyDNChangeRecord =
         new LDIFModifyDNChangeRecord("ou=People,dc=example,dc=com",
              "ou=Users", true, null);

    assertNotNull(t.transformChangeRecord(modifyDNChangeRecord));
    assertEquals(t.transformChangeRecord(modifyDNChangeRecord),
         modifyDNChangeRecord);

    assertNotNull(t.translate(modifyDNChangeRecord, 0));
    assertEquals(t.translate(modifyDNChangeRecord, 0), modifyDNChangeRecord);

    assertNotNull(t.translateChangeRecordToWrite(modifyDNChangeRecord));
    assertEquals(t.translateChangeRecordToWrite(modifyDNChangeRecord),
         modifyDNChangeRecord);
  }



  /**
   * Tests the behavior when the set of change types to exclude contains only
   * the modify DN change type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeModifyDNChangeType()
         throws Exception
  {
    final ExcludeChangeTypeTransformation t =
         new ExcludeChangeTypeTransformation(ChangeType.MODIFY_DN);


    final LDIFAddChangeRecord addChangeRecord =
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));

    assertNotNull(t.transformChangeRecord(addChangeRecord));
    assertEquals(t.transformChangeRecord(addChangeRecord), addChangeRecord);

    assertNotNull(t.translate(addChangeRecord, 0));
    assertEquals(t.translate(addChangeRecord, 0), addChangeRecord);

    assertNotNull(t.translateChangeRecordToWrite(addChangeRecord));
    assertEquals(t.translateChangeRecordToWrite(addChangeRecord),
         addChangeRecord);


    final LDIFDeleteChangeRecord deleteChangeRecord =
         new LDIFDeleteChangeRecord("dc=example,dc=com");

    assertNotNull(t.transformChangeRecord(deleteChangeRecord));
    assertEquals(t.transformChangeRecord(deleteChangeRecord),
         deleteChangeRecord);

    assertNotNull(t.translate(deleteChangeRecord, 0));
    assertEquals(t.translate(deleteChangeRecord, 0), deleteChangeRecord);

    assertNotNull(t.translateChangeRecordToWrite(deleteChangeRecord));
    assertEquals(t.translateChangeRecordToWrite(deleteChangeRecord),
         deleteChangeRecord);


    final LDIFModifyChangeRecord modifyChangeRecord =
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=example,dc=com",
              "changetype: modify",
              "replace: description",
              "description: foo"));

    assertNotNull(t.transformChangeRecord(modifyChangeRecord));
    assertEquals(t.transformChangeRecord(modifyChangeRecord),
         modifyChangeRecord);

    assertNotNull(t.translate(modifyChangeRecord, 0));
    assertEquals(t.translate(modifyChangeRecord, 0), modifyChangeRecord);

    assertNotNull(t.translateChangeRecordToWrite(modifyChangeRecord));
    assertEquals(t.translateChangeRecordToWrite(modifyChangeRecord),
         modifyChangeRecord);


    final LDIFModifyDNChangeRecord modifyDNChangeRecord =
         new LDIFModifyDNChangeRecord("ou=People,dc=example,dc=com",
              "ou=Users", true, null);

    assertNull(t.transformChangeRecord(modifyDNChangeRecord));

    assertNull(t.translate(modifyDNChangeRecord, 0));

    assertNull(t.translateChangeRecordToWrite(modifyDNChangeRecord));
  }



  /**
   * Tests the behavior when the set of change types to exclude contains all of
   * the change types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeAllChangeTypes()
         throws Exception
  {
    final ExcludeChangeTypeTransformation t =
         new ExcludeChangeTypeTransformation(ChangeType.ADD, ChangeType.DELETE,
              ChangeType.MODIFY, ChangeType.MODIFY_DN);


    final LDIFAddChangeRecord addChangeRecord =
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));

    assertNull(t.transformChangeRecord(addChangeRecord));

    assertNull(t.translate(addChangeRecord, 0));

    assertNull(t.translateChangeRecordToWrite(addChangeRecord));


    final LDIFDeleteChangeRecord deleteChangeRecord =
         new LDIFDeleteChangeRecord("dc=example,dc=com");

    assertNull(t.transformChangeRecord(deleteChangeRecord));

    assertNull(t.translate(deleteChangeRecord, 0));

    assertNull(t.translateChangeRecordToWrite(deleteChangeRecord));


    final LDIFModifyChangeRecord modifyChangeRecord =
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=example,dc=com",
              "changetype: modify",
              "replace: description",
              "description: foo"));

    assertNull(t.transformChangeRecord(modifyChangeRecord));

    assertNull(t.translate(modifyChangeRecord, 0));

    assertNull(t.translateChangeRecordToWrite(modifyChangeRecord));


    final LDIFModifyDNChangeRecord modifyDNChangeRecord =
         new LDIFModifyDNChangeRecord("ou=People,dc=example,dc=com",
              "ou=Users", true, null);

    assertNull(t.transformChangeRecord(modifyDNChangeRecord));

    assertNull(t.translate(modifyDNChangeRecord, 0));

    assertNull(t.translateChangeRecordToWrite(modifyDNChangeRecord));
  }
}
