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
package com.unboundid.ldif;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.util.ByteStringBuffer;



/**
 * This class provides basic coverage for the methods in the LDIFChangeRecord
 * class.
 */
public class LDIFChangeRecordTestCase
       extends LDIFTestCase
{
  /**
   * Performs a set of general tests for an add change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddChangeRecord()
         throws Exception
  {
    LDIFAddChangeRecord r = new LDIFAddChangeRecord(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    assertNotNull(r.getDN());
    assertEquals(new DN(r.getDN()), new DN("dc=example,dc=com"));

    assertNotNull(r.getParsedDN());
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    assertEquals(r.getChangeType(), ChangeType.ADD);

    assertNotNull(r.toEntry());

    assertNotNull(r.toLDIF());
    assertFalse(r.toLDIF().length == 0);
    assertEquals(LDIFReader.decodeChangeRecord(r.toLDIF()), r);

    ByteStringBuffer byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer);
    assertFalse(byteBuffer.length() == 0);

    byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer, 10);
    assertFalse(byteBuffer.length() == 0);

    assertNotNull(r.toLDIF(10));
    assertFalse(r.toLDIF(10).length == 0);
    assertEquals(LDIFReader.decodeChangeRecord(r.toLDIF(10)), r);

    assertNotNull(r.toLDIFString());

    assertNotNull(r.toLDIFString(10));

    StringBuilder stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer);
    assertFalse(stringBuffer.length() == 0);

    stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer, 10);
    assertFalse(stringBuffer.length() == 0);

    assertNotNull(r.toString());
  }



  /**
   * Performs a set of general tests for a delete change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteChangeRecord()
         throws Exception
  {
    LDIFDeleteChangeRecord r = new LDIFDeleteChangeRecord("dc=example,dc=com");

    assertNotNull(r.getDN());
    assertEquals(new DN(r.getDN()), new DN("dc=example,dc=com"));

    assertNotNull(r.getParsedDN());
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    assertEquals(r.getChangeType(), ChangeType.DELETE);

    assertNotNull(r.toEntry());

    assertNotNull(r.toLDIF());
    assertFalse(r.toLDIF().length == 0);
    assertEquals(LDIFReader.decodeChangeRecord(r.toLDIF()), r);

    assertNotNull(r.toLDIF(10));
    assertFalse(r.toLDIF(10).length == 0);
    assertEquals(LDIFReader.decodeChangeRecord(r.toLDIF(10)), r);

    ByteStringBuffer byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer);
    assertFalse(byteBuffer.length() == 0);

    byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer, 10);
    assertFalse(byteBuffer.length() == 0);

    assertNotNull(r.toLDIFString());

    assertNotNull(r.toLDIFString(10));

    StringBuilder stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer);
    assertFalse(stringBuffer.length() == 0);

    stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer, 10);
    assertFalse(stringBuffer.length() == 0);

    assertNotNull(r.toString());
  }



  /**
   * Performs a set of general tests for a modify change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyChangeRecord()
         throws Exception
  {
    LDIFModifyChangeRecord r = new LDIFModifyChangeRecord("dc=example,dc=com",
         new Modification(ModificationType.REPLACE, "description", "foo"));

    assertNotNull(r.getDN());
    assertEquals(new DN(r.getDN()), new DN("dc=example,dc=com"));

    assertNotNull(r.getParsedDN());
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    assertEquals(r.getChangeType(), ChangeType.MODIFY);

    assertNotNull(r.toLDIF());
    assertFalse(r.toLDIF().length == 0);
    assertEquals(LDIFReader.decodeChangeRecord(r.toLDIF()), r);

    assertNotNull(r.toLDIF(10));
    assertFalse(r.toLDIF(10).length == 0);
    assertEquals(LDIFReader.decodeChangeRecord(r.toLDIF(10)), r);

    ByteStringBuffer byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer);
    assertFalse(byteBuffer.length() == 0);

    byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer, 10);
    assertFalse(byteBuffer.length() == 0);

    assertNotNull(r.toLDIFString());

    assertNotNull(r.toLDIFString(10));

    StringBuilder stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer);
    assertFalse(stringBuffer.length() == 0);

    stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer, 10);
    assertFalse(stringBuffer.length() == 0);

    assertNotNull(r.toString());
  }



  /**
   * Performs a set of general tests for a modify change record with multiple
   * changes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyChangeRecordWithMultipleChanges()
         throws Exception
  {
    LDIFModifyChangeRecord r = new LDIFModifyChangeRecord("dc=example,dc=com",
         new Modification(ModificationType.REPLACE, "description", "foo"),
         new Modification(ModificationType.REPLACE, "o", "example.com"));

    assertNotNull(r.getDN());
    assertEquals(new DN(r.getDN()), new DN("dc=example,dc=com"));

    assertNotNull(r.getParsedDN());
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    assertEquals(r.getChangeType(), ChangeType.MODIFY);

    try
    {
      assertNotNull(r.toEntry());
      fail("Expected an exception when trying to convert a modify change " +
           "record with multiple changes to an entry.");
    }
    catch (LDIFException le)
    {
      // This was expected.
    }

    assertNotNull(r.toLDIF());
    assertFalse(r.toLDIF().length == 0);
    assertEquals(LDIFReader.decodeChangeRecord(r.toLDIF()), r);

    assertNotNull(r.toLDIF(10));
    assertFalse(r.toLDIF(10).length == 0);
    assertEquals(LDIFReader.decodeChangeRecord(r.toLDIF(10)), r);

    ByteStringBuffer byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer);
    assertFalse(byteBuffer.length() == 0);

    byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer, 10);
    assertFalse(byteBuffer.length() == 0);

    assertNotNull(r.toLDIFString());

    assertNotNull(r.toLDIFString(10));

    StringBuilder stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer);
    assertFalse(stringBuffer.length() == 0);

    stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer, 10);
    assertFalse(stringBuffer.length() == 0);

    assertNotNull(r.toString());
  }



  /**
   * Performs a set of general tests for a modify DN change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNChangeRecord()
         throws Exception
  {
    LDIFModifyDNChangeRecord r = new LDIFModifyDNChangeRecord(
         "ou=People,dc=example,dc=com", "ou=Users", true, null);


    assertNotNull(r.getDN());
    assertEquals(new DN(r.getDN()), new DN("ou=People,dc=example,dc=com"));

    assertNotNull(r.getParsedDN());
    assertEquals(r.getParsedDN(), new DN("ou=People,dc=example,dc=com"));

    assertEquals(r.getChangeType(), ChangeType.MODIFY_DN);

    assertNotNull(r.toEntry());

    assertNotNull(r.toLDIF());
    assertFalse(r.toLDIF().length == 0);
    assertEquals(LDIFReader.decodeChangeRecord(r.toLDIF()), r);

    assertNotNull(r.toLDIF(10));
    assertFalse(r.toLDIF(10).length == 0);
    assertEquals(LDIFReader.decodeChangeRecord(r.toLDIF(10)), r);

    ByteStringBuffer byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer);
    assertFalse(byteBuffer.length() == 0);

    byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer, 10);
    assertFalse(byteBuffer.length() == 0);

    assertNotNull(r.toLDIFString());

    assertNotNull(r.toLDIFString(10));

    StringBuilder stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer);
    assertFalse(stringBuffer.length() == 0);

    stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer, 10);
    assertFalse(stringBuffer.length() == 0);

    assertNotNull(r.toString());
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

    LDIFAddChangeRecord addRecord =
         new LDIFAddChangeRecord(getTestBaseDN(), getBaseEntryAttributes());
    addRecord.processChange(conn);

    addRecord = new LDIFAddChangeRecord("ou=People," + getTestBaseDN(),
         new Attribute("objectClass", "top", "organizationalUnit"),
         new Attribute("ou", "People"));
    addRecord.processChange(conn);

    LDIFModifyChangeRecord modifyRecord = new LDIFModifyChangeRecord(
         "ou=People," + getTestBaseDN(),
         new Modification(ModificationType.REPLACE, "description", "foo"));
    modifyRecord.processChange(conn);

    LDIFModifyDNChangeRecord modifyDNRecord = new LDIFModifyDNChangeRecord(
         "ou=People," + getTestBaseDN(), "ou=Users", true, null);
    modifyDNRecord.processChange(conn);

    LDIFDeleteChangeRecord deleteRecord = new LDIFDeleteChangeRecord(
         "ou=Users," + getTestBaseDN());
    deleteRecord.processChange(conn);

    deleteRecord = new LDIFDeleteChangeRecord(getTestBaseDN());
    deleteRecord.processChange(conn);

    conn.close();
  }
}
