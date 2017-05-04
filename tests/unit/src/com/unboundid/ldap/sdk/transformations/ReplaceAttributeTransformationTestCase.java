/*
 * Copyright 2016-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2016-2017 Ping Identity Corporation
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



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.schema.Schema;



/**
 * This class provides a set of test cases for replace attribute
 * transformations.
 */
public final class ReplaceAttributeTransformationTestCase
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
    final ReplaceAttributeTransformation t = new ReplaceAttributeTransformation(
         null, "description", "bar", "baz");

    assertNull(t.transformEntry(null));
  }



  /**
   * Provides test coverage for the transformEntry method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformEntry()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    final ReplaceAttributeTransformation t = new ReplaceAttributeTransformation(
         schema, "description", "foo", "bar");


    // Test with an entry that has a single value for the target attribute.
    Entry e = t.transformEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: a"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: foo",
              "description: bar"));


    // Test with an entry that has multiple values for the target attribute.
    e = t.transformEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: a",
         "description: b"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: foo",
              "description: bar"));


    // Test with an entry that does not include the target attribute.
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


    // Test with an entry that includes the target attribute with options.
    e = t.transformEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description;lang-en-US: a"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description;lang-en-US: foo",
              "description;lang-en-US: bar"));


    // Test with an entry that includes the target attribute with and without
    // options.
    e = t.transformEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: a",
         "description;lang-en-US: b"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: foo",
              "description: bar",
              "description;lang-en-US: foo",
              "description;lang-en-US: bar"));
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
    final ReplaceAttributeTransformation t = new ReplaceAttributeTransformation(
         schema, "description", Arrays.asList("foo", "bar"));

    final Entry e = t.translate(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: a"),
         0);
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: foo",
              "description: bar"));
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
    final ReplaceAttributeTransformation t = new ReplaceAttributeTransformation(
         schema, "description", "foo", "bar");

    final Entry e = t.translateEntryToWrite(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: a"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: foo",
              "description: bar"));
  }
}
