/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFModifyDNChangeRecord;



/**
 * This class provides a set of test cases for exclude attribute
 * transformations.
 */
public final class MoveSubtreeTransformationTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the behavior when provided with a null entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullEntry()
         throws Exception
  {
    final MoveSubtreeTransformation t = new MoveSubtreeTransformation(
         new DN("o=example.com"), new DN("dc=example,dc=com"));

    assertNull(t.transformEntry(null));
  }



  /**
   * Provides test coverage for the behavior when provided with a null change
   * record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullChangeRecord()
         throws Exception
  {
    final MoveSubtreeTransformation t = new MoveSubtreeTransformation(
         new DN("o=example.com"), new DN("dc=example,dc=com"));

    assertNull(t.transformChangeRecord(null));
  }



  /**
   * Provides test coverage for the behavior when provided with a null change
   * record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullString()
         throws Exception
  {
    final MoveSubtreeTransformation t = new MoveSubtreeTransformation(
         new DN("o=example.com"), new DN("dc=example,dc=com"));

    assertNull(t.processString(null));
  }



  /**
   * Provides general test coverage for the transformEntry method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformEntry()
         throws Exception
  {
    final MoveSubtreeTransformation t = new MoveSubtreeTransformation(
         new DN("o=example.com"), new DN("dc=example,dc=com"));

    Entry e = t.transformEntry(new Entry(
         "dn: o=example.com",
         "objectClass: top",
         "objectClass: organization",
         "objectClass: dcObject",
         "o: example.com",
         "dc: example",
         "entryDN: o=example.com",
         "seeAlso: ou=test,o=example.com"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: organization",
              "objectClass: dcObject",
              "o: example.com",
              "dc: example",
              "entryDN: dc=example,dc=com",
              "seeAlso: ou=test,dc=example,dc=com"));

    e = t.transformEntry(new Entry(
         "dn: cn=Test,ou=Groups,o=example.com",
         "objectClass: top",
         "objectClass: groupOfNames",
         "cn: Test",
         "member: uid=user.1,ou=People,o=example.com",
         "member: uid=user.2,ou=People,dc=example,dc=com",
         "member: malformed3,o=example.com",
         "member: uid=user.4,o=example.org",
         "entryDN: cn=Test,ou=Groups,o=example.com"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: cn=Test,ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: groupOfNames",
              "cn: Test",
              "member: uid=user.1,ou=People,dc=example,dc=com",
              "member: uid=user.2,ou=People,dc=example,dc=com",
              "member: malformed3,o=example.com",
              "member: uid=user.4,o=example.org",
              "entryDN: cn=Test,ou=Groups,dc=example,dc=com"));

    e = t.transformEntry(new Entry(
         "dn: malformed,o=example.com",
         "objectClass: top",
         "objectClass: untypedObject",
         "cn: malformed"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: malformed,o=example.com",
              "objectClass: top",
              "objectClass: untypedObject",
              "cn: malformed"));
  }



  /**
   * Provides general test coverage for the transformChangeRecord method for
   * add change records.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformAddChangeRecord()
         throws Exception
  {
    final MoveSubtreeTransformation t = new MoveSubtreeTransformation(
         new DN("o=example.com"), new DN("dc=example,dc=com"));

    LDIFChangeRecord r =
         t.transformChangeRecord(new LDIFAddChangeRecord(new Entry(
              "dn: o=example.com",
              "objectClass: top",
              "objectClass: organization",
              "objectClass: dcObject",
              "o: example.com",
              "dc: example",
              "entryDN: o=example.com",
              "seeAlso: ou=test,o=example.com")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: organization",
              "objectClass: dcObject",
              "o: example.com",
              "dc: example",
              "entryDN: dc=example,dc=com",
              "seeAlso: ou=test,dc=example,dc=com")));

    r = t.transformChangeRecord(new LDIFAddChangeRecord(new Entry(
         "dn: cn=Test,ou=Groups,o=example.com",
         "objectClass: top",
         "objectClass: groupOfNames",
         "cn: Test",
         "member: uid=user.1,ou=People,o=example.com",
         "member: uid=user.2,ou=People,dc=example,dc=com",
         "member: malformed3,o=example.com",
         "member: uid=user.4,o=example.org",
         "entryDN: cn=Test,ou=Groups,o=example.com")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFAddChangeRecord(new Entry(
              "dn: cn=Test,ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: groupOfNames",
              "cn: Test",
              "member: uid=user.1,ou=People,dc=example,dc=com",
              "member: uid=user.2,ou=People,dc=example,dc=com",
              "member: malformed3,o=example.com",
              "member: uid=user.4,o=example.org",
              "entryDN: cn=Test,ou=Groups,dc=example,dc=com")));

    r = t.transformChangeRecord(new LDIFAddChangeRecord(new Entry(
         "dn: malformed,o=example.com",
         "objectClass: top",
         "objectClass: untypedObject",
         "cn: malformed")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFAddChangeRecord(new Entry(
              "dn: malformed,o=example.com",
              "objectClass: top",
              "objectClass: untypedObject",
              "cn: malformed")));
  }



  /**
   * Provides general test coverage for the transformChangeRecord method for
   * delete change records.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformDeleteChangeRecord()
         throws Exception
  {
    final MoveSubtreeTransformation t = new MoveSubtreeTransformation(
         new DN("o=example.com"), new DN("dc=example,dc=com"));

    LDIFChangeRecord r =
         t.transformChangeRecord(new LDIFDeleteChangeRecord("o=example.com"));
    assertNotNull(r);
    assertEquals(r,
         new LDIFDeleteChangeRecord("dc=example,dc=com"));

    r = t.transformChangeRecord(
         new LDIFDeleteChangeRecord("ou=People,o=example.com"));
    assertNotNull(r);
    assertEquals(r,
         new LDIFDeleteChangeRecord("ou=People,dc=example,dc=com"));

    r = t.transformChangeRecord(
         new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertNotNull(r);
    assertEquals(r,
         new LDIFDeleteChangeRecord("dc=example,dc=com"));

    r = t.transformChangeRecord(
         new LDIFDeleteChangeRecord("o=example.org"));
    assertNotNull(r);
    assertEquals(r,
         new LDIFDeleteChangeRecord("o=example.org"));
  }



  /**
   * Provides general test coverage for the transformChangeRecord method for
   * modify change records.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformModifyChangeRecord()
         throws Exception
  {
    final MoveSubtreeTransformation t = new MoveSubtreeTransformation(
         new DN("o=example.com"), new DN("dc=example,dc=com"));

    LDIFChangeRecord r =
         t.transformChangeRecord(new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: o=example.com",
              "changetype: modify",
              "replace: seeAlso",
              "seeAlso: ou=test,o=example.com",
              "-",
              "delete: description")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: dc=example,dc=com",
              "changetype: modify",
              "replace: seeAlso",
              "seeAlso: ou=test,dc=example,dc=com",
              "-",
              "delete: description")));

    r = t.transformChangeRecord(new LDIFModifyChangeRecord(new ModifyRequest(
         "dn: cn=Test,ou=Groups,dc=example,dc=com",
         "changetype: modify",
         "add: member",
         "member: uid=user.1,ou=People,o=example.com",
         "member: uid=user.2,ou=People,dc=example,dc=com",
         "member: malformed,ou=People,o=example.com")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: cn=Test,ou=Groups,dc=example,dc=com",
              "changetype: modify",
              "add: member",
              "member: uid=user.1,ou=People,dc=example,dc=com",
              "member: uid=user.2,ou=People,dc=example,dc=com",
              "member: malformed,ou=People,o=example.com")));
  }



  /**
   * Provides general test coverage for the transformChangeRecord method for
   * modify DN change records.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformModifyDNChangeRecord()
         throws Exception
  {
    final MoveSubtreeTransformation t = new MoveSubtreeTransformation(
         new DN("o=example.com"), new DN("dc=example,dc=com"));

    final LDIFChangeRecord r =
         t.transformChangeRecord(new LDIFModifyDNChangeRecord(
              "uid=test.user,ou=Users,o=example.com", "cn=Test User", false,
              "ou=People,o=example.com"));
    assertNotNull(r);
    assertEquals(r,
         new LDIFModifyDNChangeRecord(
              "uid=test.user,ou=Users,dc=example,dc=com", "cn=Test User", false,
              "ou=People,dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the translate method for entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTranslateEntry()
         throws Exception
  {
    final MoveSubtreeTransformation t = new MoveSubtreeTransformation(
         new DN("o=example.com"), new DN("dc=example,dc=com"));

    final Entry e = t.translate(
         new Entry(
              "dn: o=example.com",
              "objectClass: top",
              "objectClass: organization",
              "objectClass: dcObject",
              "o: example.com",
              "dc: example",
              "entryDN: o=example.com",
              "seeAlso: ou=test,o=example.com"),
         0);
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: organization",
              "objectClass: dcObject",
              "o: example.com",
              "dc: example",
              "entryDN: dc=example,dc=com",
              "seeAlso: ou=test,dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the translateEntryToWrite method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTranslateEntryToWrite()
         throws Exception
  {
    final MoveSubtreeTransformation t = new MoveSubtreeTransformation(
         new DN("o=example.com"), new DN("dc=example,dc=com"));

    final Entry e = t.translateEntryToWrite(
         new Entry(
              "dn: o=example.com",
              "objectClass: top",
              "objectClass: organization",
              "objectClass: dcObject",
              "o: example.com",
              "dc: example",
              "entryDN: o=example.com",
              "seeAlso: ou=test,o=example.com"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: organization",
              "objectClass: dcObject",
              "o: example.com",
              "dc: example",
              "entryDN: dc=example,dc=com",
              "seeAlso: ou=test,dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the translate method for change records.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTranslateChangeRecord()
         throws Exception
  {
    final MoveSubtreeTransformation t = new MoveSubtreeTransformation(
         new DN("o=example.com"), new DN("dc=example,dc=com"));

    final LDIFChangeRecord r =
         t.translate(new LDIFAddChangeRecord(
              new Entry(
                   "dn: o=example.com",
                   "objectClass: top",
                   "objectClass: organization",
                   "objectClass: dcObject",
                   "o: example.com",
                   "dc: example",
                   "entryDN: o=example.com",
                   "seeAlso: ou=test,o=example.com")),
              0);
    assertNotNull(r);
    assertEquals(r,
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: organization",
              "objectClass: dcObject",
              "o: example.com",
              "dc: example",
              "entryDN: dc=example,dc=com",
              "seeAlso: ou=test,dc=example,dc=com")));
  }



  /**
   * Provides test coverage for the translateChangeRecordToWrite method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTranslateChangeRecordToWrite()
         throws Exception
  {
    final MoveSubtreeTransformation t = new MoveSubtreeTransformation(
         new DN("o=example.com"), new DN("dc=example,dc=com"));

    final LDIFChangeRecord r =
         t.translateChangeRecordToWrite(new LDIFAddChangeRecord(
              new Entry(
                   "dn: o=example.com",
                   "objectClass: top",
                   "objectClass: organization",
                   "objectClass: dcObject",
                   "o: example.com",
                   "dc: example",
                   "entryDN: o=example.com",
                   "seeAlso: ou=test,o=example.com")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: organization",
              "objectClass: dcObject",
              "o: example.com",
              "dc: example",
              "entryDN: dc=example,dc=com",
              "seeAlso: ou=test,dc=example,dc=com")));
  }
}
