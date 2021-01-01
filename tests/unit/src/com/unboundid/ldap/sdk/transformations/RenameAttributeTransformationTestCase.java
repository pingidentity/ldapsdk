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

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFModifyDNChangeRecord;



/**
 * This class provides a set of test cases for rename attribute transformations.
 */
public final class RenameAttributeTransformationTestCase
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
    final RenameAttributeTransformation t = new RenameAttributeTransformation(
         null, "cn", "fullName", true);

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
    final RenameAttributeTransformation t = new RenameAttributeTransformation(
         null, "cn", "fullName", true);

    assertNull(t.transformChangeRecord(null));
  }



  /**
   * Provides test coverage for the transformEntry method in which renames
   * should be applied in DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformEntryIncludeDNs()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final RenameAttributeTransformation t = new RenameAttributeTransformation(
         schema, "cn", "fullName", true);

    final Entry e = t.transformEntry(new Entry(
         "dn: cn=Test User,cn=Something,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "cn;lang-en-US: Test User",
         "description: Test description 1",
         "description: Test description 2",
         "userPassword: password",
         "seeAlso: cn=Another User,cn=Something Else,dc=example,dc=com",
         "seeAlso: malformed,cn=Something Else,dc=example,dc=com"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: fullName=Test User,fullName=Something,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "fullName: Test User",
              "fullName;lang-en-US: Test User",
              "description: Test description 1",
              "description: Test description 2",
              "userPassword: password",
              "seeAlso: fullName=Another User," +
                   "fullName=Something Else,dc=example,dc=com",
              "seeAlso: malformed,cn=Something Else,dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the transformEntry method in which renames
   * should not be applied in DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformEntryExcludeDNs()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final RenameAttributeTransformation t = new RenameAttributeTransformation(
         schema, "cn", "fullName", false);

    final Entry e = t.transformEntry(new Entry(
         "dn: cn=Test User,cn=Something,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "cn;lang-en-US: Test User",
         "description: Test description 1",
         "description: Test description 2",
         "userPassword: password",
         "seeAlso: cn=Another User,cn=Something Else,dc=example,dc=com",
         "seeAlso: malformed,cn=Something Else,dc=example,dc=com"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: cn=Test User,cn=Something,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "fullName: Test User",
              "fullName;lang-en-US: Test User",
              "description: Test description 1",
              "description: Test description 2",
              "userPassword: password",
              "seeAlso: cn=Another User," +
                   "cn=Something Else,dc=example,dc=com",
              "seeAlso: malformed,cn=Something Else,dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the transformChangeRecord method for an add
   * change record in which renames should be applied in DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformAddChangeRecordIncludeDNs()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final RenameAttributeTransformation t = new RenameAttributeTransformation(
         schema, "cn", "fullName", true);

    final LDIFChangeRecord r = t.transformChangeRecord(
         new LDIFAddChangeRecord(new Entry(
              "dn: cn=Test User,cn=Something,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "cn: Test User",
              "cn;lang-en-US: Test User",
              "description: Test description 1",
              "description: Test description 2",
              "userPassword: password",
              "seeAlso: cn=Another User,cn=Something Else,dc=example,dc=com",
              "seeAlso: malformed,cn=Something Else,dc=example,dc=com")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFAddChangeRecord(new Entry(
              "dn: fullName=Test User,fullName=Something,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "fullName: Test User",
              "fullName;lang-en-US: Test User",
              "description: Test description 1",
              "description: Test description 2",
              "userPassword: password",
              "seeAlso: fullName=Another User," +
                   "fullName=Something Else,dc=example,dc=com",
              "seeAlso: malformed,cn=Something Else,dc=example,dc=com")));
  }



  /**
   * Provides test coverage for the transformChangeRecord method for an add
   * change record in which renames should not be applied in DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformAddChangeRecordExcludeDNs()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final RenameAttributeTransformation t = new RenameAttributeTransformation(
         schema, "cn", "fullName", false);

    final LDIFChangeRecord r = t.transformChangeRecord(
         new LDIFAddChangeRecord(new Entry(
              "dn: cn=Test User,cn=Something,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "cn: Test User",
              "cn;lang-en-US: Test User",
              "description: Test description 1",
              "description: Test description 2",
              "userPassword: password",
              "seeAlso: cn=Another User,cn=Something Else,dc=example,dc=com",
              "seeAlso: malformed,cn=Something Else,dc=example,dc=com")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFAddChangeRecord(new Entry(
              "dn: cn=Test User,cn=Something,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "fullName: Test User",
              "fullName;lang-en-US: Test User",
              "description: Test description 1",
              "description: Test description 2",
              "userPassword: password",
              "seeAlso: cn=Another User," +
                   "cn=Something Else,dc=example,dc=com",
              "seeAlso: malformed,cn=Something Else,dc=example,dc=com")));
  }



  /**
   * Provides test coverage for the transformChangeRecord method for a delete
   * change record in which renames should be applied in DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformDeleteChangeRecordIncludeDNs()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final RenameAttributeTransformation t = new RenameAttributeTransformation(
         schema, "cn", "fullName", true);

    final LDIFChangeRecord r = t.transformChangeRecord(
         new LDIFDeleteChangeRecord("cn=A,2.5.4.3=B,dc=example,dc=com"));
    assertNotNull(r);
    assertEquals(r,
         new LDIFDeleteChangeRecord("fullName=A,fullName=B,dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the transformChangeRecord method for a delete
   * change record in which renames should not be applied in DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformDeleteChangeRecordExcludeDNs()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final RenameAttributeTransformation t = new RenameAttributeTransformation(
         schema, "cn", "fullName", false);

    final LDIFChangeRecord r = t.transformChangeRecord(
         new LDIFDeleteChangeRecord("cn=A,2.5.4.3=B,dc=example,dc=com"));
    assertNotNull(r);
    assertEquals(r,
         new LDIFDeleteChangeRecord("cn=A,2.5.4.3=B,dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the transformChangeRecord method for a modify
   * change record in which renames should be applied in DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformModifyChangeRecordIncludeDNs()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final RenameAttributeTransformation t = new RenameAttributeTransformation(
         schema, "cn", "fullName", true);

    final LDIFChangeRecord r = t.transformChangeRecord(
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: cn=A,cn=B,dc=example,dc=com",
              "changetype: modify",
              "replace: cn",
              "-",
              "add: cn",
              "cn: foo",
              "cn: bar",
              "-",
              "add: cn;lang-en-US",
              "cn;lang-en-US: baz",
              "-",
              "replace: seeAlso",
              "seeAlso: cn=X,cn=Y,cn=Z,dc=example,dc=com")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: fullName=A,fullName=B,dc=example,dc=com",
              "changetype: modify",
              "replace: fullName",
              "-",
              "add: fullName",
              "fullName: foo",
              "fullName: bar",
              "-",
              "add: fullName;lang-en-US",
              "fullName;lang-en-US: baz",
              "-",
              "replace: seeAlso",
              "seeAlso: fullName=X,fullName=Y,fullName=Z,dc=example,dc=com")));
  }



  /**
   * Provides test coverage for the transformChangeRecord method for a modify
   * change record in which renames should not be applied in DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformModifyChangeRecordExcludeDNs()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final RenameAttributeTransformation t = new RenameAttributeTransformation(
         schema, "cn", "fullName", false);

    final LDIFChangeRecord r = t.transformChangeRecord(
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: cn=A,cn=B,dc=example,dc=com",
              "changetype: modify",
              "replace: cn",
              "-",
              "add: cn",
              "cn: foo",
              "cn: bar",
              "-",
              "add: cn;lang-en-US",
              "cn;lang-en-US: baz",
              "-",
              "replace: seeAlso",
              "seeAlso: cn=X,cn=Y,cn=Z,dc=example,dc=com")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: cn=A,cn=B,dc=example,dc=com",
              "changetype: modify",
              "replace: fullName",
              "-",
              "add: fullName",
              "fullName: foo",
              "fullName: bar",
              "-",
              "add: fullName;lang-en-US",
              "fullName;lang-en-US: baz",
              "-",
              "replace: seeAlso",
              "seeAlso: cn=X,cn=Y,cn=Z,dc=example,dc=com")));
  }



  /**
   * Provides test coverage for the transformChangeRecord method for a modify DN
   * change record in which renames should be applied in DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformModifyDNChangeRecordIncludeDNs()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final RenameAttributeTransformation t = new RenameAttributeTransformation(
         schema, "cn", "fullName", true);

    final LDIFChangeRecord r = t.transformChangeRecord(
         new LDIFModifyDNChangeRecord("cn=A,cn=B,dc=example,dc=com", "cn=C",
              true, "cn=D,dc=example,dc=com"));
    assertNotNull(r);
    assertEquals(r,
         new LDIFModifyDNChangeRecord("fullName=A,fullName=B,dc=example,dc=com",
              "fullName=C", true, "fullName=D,dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the transformChangeRecord method for a modify DN
   * change record in which renames should not be applied in DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformModifyDNChangeRecordExcludeDNs()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final RenameAttributeTransformation t = new RenameAttributeTransformation(
         schema, "cn", "fullName", false);

    final LDIFChangeRecord r = t.transformChangeRecord(
         new LDIFModifyDNChangeRecord("cn=A,cn=B,dc=example,dc=com", "cn=C",
              true, "cn=D,dc=example,dc=com"));
    assertNotNull(r);
    assertEquals(r,
         new LDIFModifyDNChangeRecord("cn=A,cn=B,dc=example,dc=com", "cn=C",
              true, "cn=D,dc=example,dc=com"));
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
    final Schema schema = Schema.getDefaultStandardSchema();
    final RenameAttributeTransformation t = new RenameAttributeTransformation(
         schema, "cn", "fullName", true);

    final Entry e = t.translate(
         new Entry(
              "dn: cn=Test User,cn=Something,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "cn: Test User",
              "description: Test description 1",
              "description: Test description 2",
              "userPassword: password",
              "seeAlso: cn=Another User,cn=Something Else,dc=example,dc=com",
              "seeAlso: malformed,cn=Something Else,dc=example,dc=com"),
         0);
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: fullName=Test User,fullName=Something,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "fullName: Test User",
              "description: Test description 1",
              "description: Test description 2",
              "userPassword: password",
              "seeAlso: fullName=Another User," +
                   "fullName=Something Else,dc=example,dc=com",
              "seeAlso: malformed,cn=Something Else,dc=example,dc=com"));
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
    final Schema schema = Schema.getDefaultStandardSchema();
    final RenameAttributeTransformation t = new RenameAttributeTransformation(
         schema, "cn", "fullName", true);

    final Entry e = t.translateEntryToWrite(
         new Entry(
              "dn: cn=Test User,cn=Something,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "cn: Test User",
              "description: Test description 1",
              "description: Test description 2",
              "userPassword: password",
              "seeAlso: cn=Another User,cn=Something Else,dc=example,dc=com",
              "seeAlso: malformed,cn=Something Else,dc=example,dc=com"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: fullName=Test User,fullName=Something,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "fullName: Test User",
              "description: Test description 1",
              "description: Test description 2",
              "userPassword: password",
              "seeAlso: fullName=Another User," +
                   "fullName=Something Else,dc=example,dc=com",
              "seeAlso: malformed,cn=Something Else,dc=example,dc=com"));
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
    final Schema schema = Schema.getDefaultStandardSchema();
    final RenameAttributeTransformation t = new RenameAttributeTransformation(
         schema, "cn", "fullName", true);

    final LDIFChangeRecord r = t.translate(
         new LDIFAddChangeRecord(new Entry(
              "dn: cn=Test User,cn=Something,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "cn: Test User",
              "description: Test description 1",
              "description: Test description 2",
              "userPassword: password",
              "seeAlso: cn=Another User,cn=Something Else,dc=example,dc=com",
              "seeAlso: malformed,cn=Something Else,dc=example,dc=com")),
         0);
    assertNotNull(r);
    assertEquals(r,
         new LDIFAddChangeRecord(new Entry(
              "dn: fullName=Test User,fullName=Something,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "fullName: Test User",
              "description: Test description 1",
              "description: Test description 2",
              "userPassword: password",
              "seeAlso: fullName=Another User," +
                   "fullName=Something Else,dc=example,dc=com",
              "seeAlso: malformed,cn=Something Else,dc=example,dc=com")));
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
    final Schema schema = Schema.getDefaultStandardSchema();
    final RenameAttributeTransformation t = new RenameAttributeTransformation(
         schema, "cn", "fullName", true);

    final LDIFChangeRecord r = t.translateChangeRecordToWrite(
         new LDIFAddChangeRecord(new Entry(
              "dn: cn=Test User,cn=Something,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "cn: Test User",
              "description: Test description 1",
              "description: Test description 2",
              "userPassword: password",
              "seeAlso: cn=Another User,cn=Something Else,dc=example,dc=com",
              "seeAlso: malformed,cn=Something Else,dc=example,dc=com")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFAddChangeRecord(new Entry(
              "dn: fullName=Test User,fullName=Something,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "fullName: Test User",
              "description: Test description 1",
              "description: Test description 2",
              "userPassword: password",
              "seeAlso: fullName=Another User," +
                   "fullName=Something Else,dc=example,dc=com",
              "seeAlso: malformed,cn=Something Else,dc=example,dc=com")));
  }
}
