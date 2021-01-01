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
 * This class provides a set of test cases for redact attribute transformations.
 */
public final class RedactAttributeTransformationTestCase
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
    final RedactAttributeTransformation t = new RedactAttributeTransformation(
         null, true, true, "description");

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
    final RedactAttributeTransformation t = new RedactAttributeTransformation(
         null, true, true, "description");

    assertNull(t.transformChangeRecord(null));
  }



  /**
   * Provides test coverage for the transformEntry method with both processDNs
   * and preserveValueCount arguments set to true.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformEntryProcessDNsTruePreserveCountTrue()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final RedactAttributeTransformation t = new RedactAttributeTransformation(
         schema, true, true, "description", "displayName", "cn", "ou");

    final Entry e = t.transformEntry(new Entry(
         "dn: cn=Test User,ou=People,dc=example,dc=com",
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
         "seeAlso: uid=test.user,ou=People,dc=example,dc=com",
         "seeAlso: malformed,ou=People,dc=example,dc=com"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: cn=***REDACTED***,ou=***REDACTED***,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "cn: ***REDACTED***",
              "description: ***REDACTED1***",
              "description: ***REDACTED2***",
              "userPassword: password",
              "seeAlso: uid=test.user,ou=***REDACTED***,dc=example,dc=com",
              "seeAlso: malformed,ou=People,dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the transformEntry method with both processDNs
   * and preserveValueCount arguments set to false.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformEntryProcessDNsFalsePreserveCountFalse()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final RedactAttributeTransformation t = new RedactAttributeTransformation(
         schema, false, false, "description", "displayName", "cn", "ou");

    final Entry e = t.transformEntry(new Entry(
         "dn: cn=Test User,ou=People,dc=example,dc=com",
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
         "seeAlso: uid=test.user,ou=People,dc=example,dc=com"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: cn=Test User,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "cn: ***REDACTED***",
              "description: ***REDACTED***",
              "userPassword: password",
              "seeAlso: uid=test.user,ou=People,dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the transformChangeRecord method for an add
   * record with both processDNs and preserveValueCount arguments set to true.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformAddChangeRecordProcessDNsTruePreserveCountTrue()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final RedactAttributeTransformation t = new RedactAttributeTransformation(
         schema, true, true, "description", "displayName", "cn", "ou");

    final LDIFChangeRecord r =
         t.transformChangeRecord(new LDIFAddChangeRecord(new Entry(
              "dn: cn=Test User,ou=People,dc=example,dc=com",
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
              "seeAlso: uid=test.user,ou=People,dc=example,dc=com",
              "seeAlso: malformed,ou=People,dc=example,dc=com")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFAddChangeRecord(new Entry(
              "dn: cn=***REDACTED***,ou=***REDACTED***,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "cn: ***REDACTED***",
              "description: ***REDACTED1***",
              "description: ***REDACTED2***",
              "userPassword: password",
              "seeAlso: uid=test.user,ou=***REDACTED***,dc=example,dc=com",
              "seeAlso: malformed,ou=People,dc=example,dc=com")));
  }



  /**
   * Provides test coverage for the transformChangeRecord method for an add
   * record with both processDNs and preserveValueCount arguments set to false.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformAddChangeRecordProcessDNsFalsePreserveCountFalse()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final RedactAttributeTransformation t = new RedactAttributeTransformation(
         schema, false, false, "description", "displayName", "cn", "ou");

    final LDIFChangeRecord r =
         t.transformChangeRecord(new LDIFAddChangeRecord(new Entry(
              "dn: cn=Test User,ou=People,dc=example,dc=com",
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
              "seeAlso: uid=test.user,ou=People,dc=example,dc=com",
              "seeAlso: malformed,ou=People,dc=example,dc=com")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFAddChangeRecord(new Entry(
              "dn: cn=Test User,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "cn: ***REDACTED***",
              "description: ***REDACTED***",
              "userPassword: password",
              "seeAlso: uid=test.user,ou=People,dc=example,dc=com",
              "seeAlso: malformed,ou=People,dc=example,dc=com")));
  }



  /**
   * Provides test coverage for the transformChangeRecord method for a delete
   * record with both processDNs and preserveValueCount arguments set to true.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformDeleteChangeRecordProcessDNsTruePreserveCountTrue()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final RedactAttributeTransformation t = new RedactAttributeTransformation(
         schema, true, true, "description", "displayName", "cn", "ou");

    final LDIFChangeRecord r = t.transformChangeRecord(
         new LDIFDeleteChangeRecord("cn=Test,ou=People,dc=example,dc=com"));
    assertNotNull(r);
    assertEquals(r,
         new LDIFDeleteChangeRecord(
              "cn=***REDACTED***,ou=***REDACTED***,dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the transformChangeRecord method for an add
   * record with both processDNs and preserveValueCount arguments set to false.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformDeleteChangeRecordProcessDNsFalsePreserveCountFalse()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final RedactAttributeTransformation t = new RedactAttributeTransformation(
         schema, false, false, "description", "displayName", "cn", "ou");

    final LDIFChangeRecord r = t.transformChangeRecord(
         new LDIFDeleteChangeRecord("cn=Test,ou=People,dc=example,dc=com"));
    assertNotNull(r);
    assertEquals(r,
         new LDIFDeleteChangeRecord("cn=Test,ou=People,dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the transformChangeRecord method for a modify
   * record with both processDNs and preserveValueCount arguments set to true.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformModifyChangeRecordProcessDNsTruePreserveCountTrue()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final RedactAttributeTransformation t = new RedactAttributeTransformation(
         schema, true, true, "description", "displayName", "cn", "ou");

    final LDIFChangeRecord r = t.transformChangeRecord(
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: cn=Test,ou=People,dc=example,dc=com",
              "changetype: modify",
              "add: description",
              "description: First value",
              "description: Second value",
              "-",
              "replace: seeAlso",
              "seeAlso: uid=test,ou=People,dc=example,dc=com")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: cn=***REDACTED***,ou=***REDACTED***,dc=example,dc=com",
              "changetype: modify",
              "add: description",
              "description: ***REDACTED1***",
              "description: ***REDACTED2***",
              "-",
              "replace: seeAlso",
              "seeAlso: uid=test,ou=***REDACTED***,dc=example,dc=com")));
  }



  /**
   * Provides test coverage for the transformChangeRecord method for a modify
   * record with both processDNs and preserveValueCount arguments set to false.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformModifyChangeRecordProcessDNsFalsePreserveCountFalse()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final RedactAttributeTransformation t = new RedactAttributeTransformation(
         schema, false, false, "description", "displayName", "cn", "ou");

    final LDIFChangeRecord r = t.transformChangeRecord(
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: cn=Test,ou=People,dc=example,dc=com",
              "changetype: modify",
              "add: description",
              "description: First value",
              "description: Second value",
              "-",
              "replace: seeAlso",
              "seeAlso: uid=test,ou=People,dc=example,dc=com")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: cn=Test,ou=People,dc=example,dc=com",
              "changetype: modify",
              "add: description",
              "description: ***REDACTED***",
              "-",
              "replace: seeAlso",
              "seeAlso: uid=test,ou=People,dc=example,dc=com")));
  }



  /**
   * Provides test coverage for the transformChangeRecord method for a modify DN
   * record with both processDNs and preserveValueCount arguments set to true.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformModDNChangeRecordProcessDNsTruePreserveCountTrue()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final RedactAttributeTransformation t = new RedactAttributeTransformation(
         schema, true, true, "description", "displayName", "cn", "ou");

    LDIFChangeRecord r = t.transformChangeRecord(
         new LDIFModifyDNChangeRecord(
              "cn=Test 1,ou=People,dc=example,dc=com", "cn=Test 2", true,
              null));
    assertNotNull(r);
    assertEquals(r,
         new LDIFModifyDNChangeRecord(
              "cn=***REDACTED***,ou=***REDACTED***,dc=example,dc=com",
              "cn=***REDACTED***", true, null));

    r = t.transformChangeRecord(
         new LDIFModifyDNChangeRecord(
              "cn=Test 1,ou=People,dc=example,dc=com", "cn=Test 2", true,
              "ou=Users,dc=example,dc=com"));
    assertNotNull(r);
    assertEquals(r,
         new LDIFModifyDNChangeRecord(
              "cn=***REDACTED***,ou=***REDACTED***,dc=example,dc=com",
              "cn=***REDACTED***", true,
              "ou=***REDACTED***,dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the transformChangeRecord method for a modify DN
   * record with both processDNs and preserveValueCount arguments set to false.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformModDNChangeRecordProcessDNsFalsePreserveCountFalse()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final RedactAttributeTransformation t = new RedactAttributeTransformation(
         schema, false, false, "description", "displayName", "cn", "ou");

    LDIFChangeRecord r = t.transformChangeRecord(
         new LDIFModifyDNChangeRecord(
              "cn=Test 1,ou=People,dc=example,dc=com", "cn=Test 2", true,
              null));
    assertNotNull(r);
    assertEquals(r,
         new LDIFModifyDNChangeRecord(
              "cn=Test 1,ou=People,dc=example,dc=com", "cn=Test 2", true,
              null));

    r = t.transformChangeRecord(
         new LDIFModifyDNChangeRecord(
              "cn=Test 1,ou=People,dc=example,dc=com", "cn=Test 2", true,
              "ou=Users,dc=example,dc=com"));
    assertNotNull(r);
    assertEquals(r,
         new LDIFModifyDNChangeRecord(
              "cn=Test 1,ou=People,dc=example,dc=com", "cn=Test 2", true,
              "ou=Users,dc=example,dc=com"));
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
    final RedactAttributeTransformation t = new RedactAttributeTransformation(
         Schema.getDefaultStandardSchema(), true, true, "description",
         "displayName", "cn", "ou");

    final Entry e = t.translate(
         new Entry(
              "dn: cn=Test User,ou=People,dc=example,dc=com",
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
              "seeAlso: uid=test.user,ou=People,dc=example,dc=com"),
         0);
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: cn=***REDACTED***,ou=***REDACTED***,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "cn: ***REDACTED***",
              "description: ***REDACTED1***",
              "description: ***REDACTED2***",
              "userPassword: password",
              "seeAlso: uid=test.user,ou=***REDACTED***,dc=example,dc=com"));
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
    final RedactAttributeTransformation t = new RedactAttributeTransformation(
         Schema.getDefaultStandardSchema(), true, true, "description",
         "displayName", "cn", "ou");

    final Entry e = t.translateEntryToWrite(
         new Entry(
              "dn: cn=Test User,ou=People,dc=example,dc=com",
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
              "seeAlso: uid=test.user,ou=People,dc=example,dc=com"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: cn=***REDACTED***,ou=***REDACTED***,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "cn: ***REDACTED***",
              "description: ***REDACTED1***",
              "description: ***REDACTED2***",
              "userPassword: password",
              "seeAlso: uid=test.user,ou=***REDACTED***,dc=example,dc=com"));
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
    final RedactAttributeTransformation t = new RedactAttributeTransformation(
         schema, true, true, "description", "displayName", "cn", "ou");

    final LDIFChangeRecord r = t.translate(
         new LDIFAddChangeRecord(new Entry(
              "dn: cn=Test User,ou=People,dc=example,dc=com",
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
              "seeAlso: uid=test.user,ou=People,dc=example,dc=com",
              "seeAlso: malformed,ou=People,dc=example,dc=com")),
         0);
    assertNotNull(r);
    assertEquals(r,
         new LDIFAddChangeRecord(new Entry(
              "dn: cn=***REDACTED***,ou=***REDACTED***,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "cn: ***REDACTED***",
              "description: ***REDACTED1***",
              "description: ***REDACTED2***",
              "userPassword: password",
              "seeAlso: uid=test.user,ou=***REDACTED***,dc=example,dc=com",
              "seeAlso: malformed,ou=People,dc=example,dc=com")));
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
    final RedactAttributeTransformation t = new RedactAttributeTransformation(
         schema, true, true, "description", "displayName", "cn", "ou");

    final LDIFChangeRecord r = t.translateChangeRecordToWrite(
         new LDIFAddChangeRecord(new Entry(
              "dn: cn=Test User,ou=People,dc=example,dc=com",
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
              "seeAlso: uid=test.user,ou=People,dc=example,dc=com",
              "seeAlso: malformed,ou=People,dc=example,dc=com")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFAddChangeRecord(new Entry(
              "dn: cn=***REDACTED***,ou=***REDACTED***,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "givenName: Test",
              "sn: User",
              "cn: ***REDACTED***",
              "description: ***REDACTED1***",
              "description: ***REDACTED2***",
              "userPassword: password",
              "seeAlso: uid=test.user,ou=***REDACTED***,dc=example,dc=com",
              "seeAlso: malformed,ou=People,dc=example,dc=com")));
  }
}
