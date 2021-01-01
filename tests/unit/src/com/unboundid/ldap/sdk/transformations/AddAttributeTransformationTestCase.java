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

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.schema.Schema;



/**
 * This class provides a set of test cases for add attribute transformations.
 */
public final class AddAttributeTransformationTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when trying to add an attribute to an entry only if it
   * is missing that attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddValueOnlyIfMissing()
         throws Exception
  {
    final AddAttributeTransformation t = new AddAttributeTransformation(null,
         null, null, null, new Attribute("description", "foo"), true);

    Entry e = t.transformEntry(
         new Entry(
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
              "dc: example",
              "description: foo"));

    e = t.transformEntry(
         new Entry(
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
              "dc: example",
              "description: foo"));

    e = t.transformEntry(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "2.5.4.13: bar"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "2.5.4.13: bar"));
  }



  /**
   * Tests the behavior when trying to add an attribute to an entry, merging
   * with the existing set of values if the entry already has that attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddValueMergeWithExisting()
         throws Exception
  {
    final AddAttributeTransformation t = new AddAttributeTransformation(
         Schema.getDefaultStandardSchema(), null, null, null,
         new Attribute("description", "foo"), false);

    Entry e = t.transformEntry(
         new Entry(
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
              "dc: example",
              "description: foo"));

    e = t.transformEntry(
         new Entry(
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
              "dc: example",
              "description: foo"));

    e = t.transformEntry(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "2.5.4.13: bar"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "2.5.4.13: bar",
              "2.5.4.13: foo"));
  }



  /**
   * Tests the behavior when trying to add an entry that may or may not match
   * the base, scope, and filter criteria.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddWithCriteria()
         throws Exception
  {
    final AddAttributeTransformation t = new AddAttributeTransformation(
         Schema.getDefaultStandardSchema(),
         new DN("ou=People,dc=example,dc=com"), SearchScope.SUBORDINATE_SUBTREE,
         Filter.createEqualityFilter("a", "b"),
         new Attribute("description", "foo"), true);


    // Test with an entry that is outside the base and scope.
    Entry e = t.transformEntry(
         new Entry(
              "dn: ou=test,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test",
              "a: b"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=test,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test",
              "a: b"));


    // Test with an entry that is within the base but outside the scope.
    e = t.transformEntry(
         new Entry(
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People",
              "a: b"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People",
              "a: b"));


    // Test with an entry that is within the base and scope but does not match
    // the filter.
    e = t.transformEntry(
         new Entry(
              "dn: ou=test,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test",
              "a: c"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=test,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test",
              "a: c"));


    // Test with an entry that is within the base and scope and matches the
    // filter.
    e = t.transformEntry(
         new Entry(
              "dn: ou=test,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test",
              "a: b"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=test,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test",
              "a: b",
              "description: foo"));
  }



  /**
   * Tests the behavior when trying to transform a null entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformNull()
         throws Exception
  {
    final AddAttributeTransformation t = new AddAttributeTransformation(null,
         null, null, Filter.createANDFilter(),
         new Attribute("description", "foo"), true);

    assertNull(t.transformEntry(null));
  }



  /**
   * Tests the behavior when trying to transform an entry with a malformed DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedEntryDN()
         throws Exception
  {
    final AddAttributeTransformation t = new AddAttributeTransformation(null,
         new DN("dc=example,dc=com"), SearchScope.SUB,
         Filter.createANDFilter(),
         new Attribute("description", "foo"), true);

    final Entry e = t.transformEntry(
         new Entry(
              "dn: malformed,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test",
              "a: b"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: malformed,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test",
              "a: b"));
  }



  /**
   * Tests the behavior when trying to evaluate a filter that we can't handle.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCannotEvaluateFilter()
         throws Exception
  {
    final AddAttributeTransformation t = new AddAttributeTransformation(null,
         new DN("dc=example,dc=com"), SearchScope.SUB,
         Filter.createApproximateMatchFilter("a", "b"),
         new Attribute("description", "foo"), true);

    final Entry e = t.transformEntry(
         new Entry(
              "dn: ou=test,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test",
              "a: b"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=test,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test",
              "a: b"));
  }



  /**
   * Provides test coverage for the translate method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTranslate()
         throws Exception
  {
    final AddAttributeTransformation t = new AddAttributeTransformation(null,
         null, null, null, new Attribute("description", "foo"), true);

    final Entry e = t.translate(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"),
         0);
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: foo"));
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
    final AddAttributeTransformation t = new AddAttributeTransformation(null,
         null, null, null, new Attribute("description", "foo"), true);

    final Entry e = t.translateEntryToWrite(
         new Entry(
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
              "dc: example",
              "description: foo"));
  }
}
