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
 * This class provides a set of test cases for exclude attribute
 * transformations.
 */
public final class ExcludeAttributeTransformationTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for entries when invoked with a {@code null} schema so
   * that the default schema will be used.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeForEntryNullSchema()
         throws Exception
  {
    final ExcludeAttributeTransformation t = new ExcludeAttributeTransformation(
         null, "description");


    // Test when trying to exclude an attribute with a name that exactly matches
    // the configured value.
    Entry e = t.transformEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));


    // Test when trying to exclude an attribute with a name that differs from
    // the configured name only in capitalization.
    e = t.transformEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "DeScRiPtIoN: foo"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));


    // Test when trying to exclude an attribute provided by OID when the
    // same attribute was configured by name.
    e = t.transformEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "2.5.4.13: foo"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));


    // Test when trying to exclude an attribute that is not present in the
    // provided entry.
    e = t.transformEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));


    // Test when trying to exclude an attribute that is present in the entry
    // with multiple sets of options.
    e = t.transformEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo",
         "description;lang-en-US: bar",
         "2.5.4.13;binary;lang-en-US: baz"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
  }



  /**
   * Tests the behavior for entries when invoked with a non-{@code null} schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeForEntryNonNullSchema()
         throws Exception
  {
    final ExcludeAttributeTransformation t = new ExcludeAttributeTransformation(
         Schema.getDefaultStandardSchema(), "description");


    // Test when trying to exclude an attribute with a name that exactly matches
    // the configured value.
    Entry e = t.transformEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));


    // Test when trying to exclude an attribute with a name that differs from
    // the configured name only in capitalization.
    e = t.transformEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "DeScRiPtIoN: foo"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));


    // Test when trying to exclude an attribute provided by OID when the
    // same attribute was configured by name.
    e = t.transformEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "2.5.4.13: foo"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));


    // Test when trying to exclude an attribute that is not present in the
    // provided entry.
    e = t.transformEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));


    // Test when trying to exclude an attribute that is present in the entry
    // with multiple sets of options.
    e = t.transformEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo",
         "description;lang-en-US: bar",
         "2.5.4.13;binary;lang-en-US: baz"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
  }



  /**
   * Tests the behavior for LDIF add change records.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeForAddChangeRecord()
         throws Exception
  {
    final ExcludeAttributeTransformation t = new ExcludeAttributeTransformation(
         Schema.getDefaultStandardSchema(), "description");


    // Test when trying to exclude an attribute with a name that exactly matches
    // the configured value.
    LDIFChangeRecord r =
         t.transformChangeRecord(new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: foo")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example")));


    // Test when trying to exclude an attribute with a name that differs from
    // the configured name only in capitalization.
    r = t.transformChangeRecord(new LDIFAddChangeRecord(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "DeScRiPtIoN: foo")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example")));


    // Test when trying to exclude an attribute provided by OID when the
    // same attribute was configured by name.
    r = t.transformChangeRecord(new LDIFAddChangeRecord(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "2.5.4.13: foo")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example")));


    // Test when trying to exclude an attribute that is not present in the
    // provided entry.
    r = t.transformChangeRecord(new LDIFAddChangeRecord(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example")));
  }



  /**
   * Tests the behavior for LDIF modify change records.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeForModifyChangeRecord()
         throws Exception
  {
    final ExcludeAttributeTransformation t = new ExcludeAttributeTransformation(
         Schema.getDefaultStandardSchema(), "description", "displayName");


    // Test when trying to modify a single attribute that is not one of the
    // target attributes.
    LDIFChangeRecord r =
         t.transformChangeRecord(new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: uid=test.user,ou=People,dc=example,dc=com",
              "changetype: modify",
              "replace: title",
              "title: foo")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: uid=test.user,ou=People,dc=example,dc=com",
              "changetype: modify",
              "replace: title",
              "title: foo")));


    // Test when trying to modify a single attribute that is one of the target
    // attributes.
    r = t.transformChangeRecord(new LDIFModifyChangeRecord(new ModifyRequest(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo")));
    assertNull(r);


    // Test when trying with multiple modifications that all target the same
    // attribute type.
    r = t.transformChangeRecord(new LDIFModifyChangeRecord(new ModifyRequest(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: modify",
         "add: description",
         "description: foo",
         "-",
         "add: DeScRiPtIoN",
         "DeScRiPtIoN: bar",
         "-",
         "add: 2.5.4.13",
         "2.5.4.13: baz")));
    assertNull(r);


    // Test when trying with multiple modifications that target different
    // attribute types when only two of them are types to exclude.
    r = t.transformChangeRecord(new LDIFModifyChangeRecord(new ModifyRequest(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: modify",
         "add: description",
         "description: foo",
         "-",
         "add: title",
         "title: bar",
         "-",
         "add: displayName;lang-en-US",
         "displayName;lang-en-US: baz")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: uid=test.user,ou=People,dc=example,dc=com",
              "changetype: modify",
              "add: title",
              "title: bar")));
  }



  /**
   * Tests the behavior for LDIF delete change records.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeForDeleteChangeRecord()
         throws Exception
  {
    final ExcludeAttributeTransformation t = new ExcludeAttributeTransformation(
         Schema.getDefaultStandardSchema(), "description", "displayName");

    final LDIFChangeRecord r = t.transformChangeRecord(
         new LDIFDeleteChangeRecord("dc=example,dc=com"));
    assertNotNull(r);
    assertEquals(r,
         new LDIFDeleteChangeRecord("dc=example,dc=com"));
  }



  /**
   * Tests the behavior for LDIF modify DN change records.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeForModifyDNChangeRecord()
         throws Exception
  {
    final ExcludeAttributeTransformation t = new ExcludeAttributeTransformation(
         Schema.getDefaultStandardSchema(), "description", "displayName");

    final LDIFChangeRecord r = t.transformChangeRecord(
         new LDIFModifyDNChangeRecord("ou=People,dc=example,dc=com", "ou=users",
              true, "o=example.com"));
    assertNotNull(r);
    assertEquals(r,
         new LDIFModifyDNChangeRecord("ou=People,dc=example,dc=com", "ou=users",
              true, "o=example.com"));
  }



  /**
   * Tests the behavior when trying to exclude a null entry and change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeForNullRecords()
         throws Exception
  {
    final ExcludeAttributeTransformation t = new ExcludeAttributeTransformation(
         Schema.getDefaultStandardSchema(), "objectClass", "dc", "description");

    assertNull(t.transformEntry(null));

    assertNull(t.transformChangeRecord(null));
  }



  /**
   * Tests the behavior when trying to exclude a null entry and change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeAllAddAttributes()
         throws Exception
  {
    final ExcludeAttributeTransformation t = new ExcludeAttributeTransformation(
         Schema.getDefaultStandardSchema(), "objectClass", "dc", "description");

    final Entry e = t.transformEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo"));
    assertNotNull(e);
    assertEquals(e,
         new Entry("dc=example,dc=com"));

    final LDIFChangeRecord r =
         t.transformChangeRecord(new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: foo")));
    assertNull(r);
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
    final ExcludeAttributeTransformation t = new ExcludeAttributeTransformation(
         null, "description");

    final Entry e = t.translate(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: foo"),
         0);
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
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
    final ExcludeAttributeTransformation t = new ExcludeAttributeTransformation(
         null, "description");

    final Entry e = t.translateEntryToWrite(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
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
    final ExcludeAttributeTransformation t = new ExcludeAttributeTransformation(
         Schema.getDefaultStandardSchema(), "description");

    final LDIFChangeRecord r = t.translate(
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: foo")),
         0);
    assertNotNull(r);
    assertEquals(r,
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example")));
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
    final ExcludeAttributeTransformation t = new ExcludeAttributeTransformation(
         Schema.getDefaultStandardSchema(), "description");

    final LDIFChangeRecord r = t.translateChangeRecordToWrite(
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: foo")));
    assertNotNull(r);
    assertEquals(r,
         new LDIFAddChangeRecord(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example")));
  }
}
