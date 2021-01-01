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



import java.util.concurrent.atomic.AtomicLong;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.schema.Schema;



/**
 * This class provides a set of test cases for exclude entry transformations.
 */
public final class ExcludeEntryTransformationTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the exclude behavior when provided with a null
   * input.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeNull()
         throws Exception
  {
    final AtomicLong excludeCount = new AtomicLong(0L);

    final ExcludeEntryTransformation t = new ExcludeEntryTransformation(null,
         null, null, null, true, excludeCount);

    assertNull(t.transformEntry(null));
    assertEquals(excludeCount.get(), 0L);
  }



  /**
   * Provides test coverage for the exclude behavior when no exclude criteria
   * is given and entries matching the criteria should be excluded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeNoCriteriaExcludeMatching()
         throws Exception
  {
    final AtomicLong excludeCount = new AtomicLong(0L);

    final ExcludeEntryTransformation t = new ExcludeEntryTransformation(null,
         null, null, null, true, excludeCount);

    final Entry e = t.transformEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));
    assertNull(e);
    assertEquals(excludeCount.get(), 1L);
  }



  /**
   * Provides test coverage for the exclude behavior when no exclude criteria
   * is given and entries not matching the criteria should be excluded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeNoCriteriaExcludeNonMatching()
         throws Exception
  {
    final AtomicLong excludeCount = new AtomicLong(0L);

    final ExcludeEntryTransformation t = new ExcludeEntryTransformation(null,
         null, null, null, false, excludeCount);

    final Entry e = t.transformEntry(new Entry(
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
    assertEquals(excludeCount.get(), 0L);
  }



  /**
   * Provides test coverage for the exclude behavior when exclude criteria is
   * given, the entry matches the scope criteria, the entry matches the filter
   * criteria, and matching entries should be excluded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeWithCriteriaEntryMatchesAllExcludeMatching()
         throws Exception
  {
    final AtomicLong excludeCount = new AtomicLong(0L);

    final ExcludeEntryTransformation t = new ExcludeEntryTransformation(
         Schema.getDefaultStandardSchema(), new DN("dc=example,dc=com"),
         SearchScope.SUB, Filter.createANDFilter(), true,
         excludeCount);

    final Entry e = t.transformEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));
    assertNull(e);
    assertEquals(excludeCount.get(), 1L);
  }



  /**
   * Provides test coverage for the exclude behavior when exclude criteria is
   * given, the entry matches the scope criteria, the entry matches the filter
   * criteria, and non-matching entries should be excluded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeWithCriteriaEntryMatchesAllExcludeNonMatching()
         throws Exception
  {
    final AtomicLong excludeCount = new AtomicLong(0L);

    final ExcludeEntryTransformation t = new ExcludeEntryTransformation(
         Schema.getDefaultStandardSchema(), new DN("dc=example,dc=com"),
         SearchScope.SUB, Filter.createPresenceFilter("objectClass"), false,
         excludeCount);

    final Entry e = t.transformEntry(new Entry(
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
    assertEquals(excludeCount.get(), 0L);
  }



  /**
   * Provides test coverage for the exclude behavior when exclude criteria is
   * given, the entry does not match the scope criteria, the entry matches the
   * filter criteria, and matching entries should be excluded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeWithCriteriaEntryDoesNotMatchScopeExcludeMatching()
         throws Exception
  {
    final AtomicLong excludeCount = new AtomicLong(0L);

    final ExcludeEntryTransformation t = new ExcludeEntryTransformation(
         Schema.getDefaultStandardSchema(), new DN("o=example.com"),
         SearchScope.ONE, Filter.createPresenceFilter("objectClass"), true,
         excludeCount);

    final Entry e = t.transformEntry(new Entry(
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
    assertEquals(excludeCount.get(), 0L);
  }



  /**
   * Provides test coverage for the exclude behavior when exclude criteria is
   * given, the entry does not match the scope criteria, the entry matches the
   * filter criteria, and non-matching entries should be excluded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeWithCriteriaEntryDoesNotMatchScopeExcludeNonMatching()
         throws Exception
  {
    final AtomicLong excludeCount = new AtomicLong(0L);

    final ExcludeEntryTransformation t = new ExcludeEntryTransformation(
         Schema.getDefaultStandardSchema(), new DN("o=example.com"),
         SearchScope.ONE, Filter.createPresenceFilter("objectClass"), false,
         excludeCount);

    final Entry e = t.transformEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));
    assertNull(e);
    assertEquals(excludeCount.get(), 1L);
  }



  /**
   * Provides test coverage for the exclude behavior when exclude criteria is
   * given, the entry matches the scope criteria, the entry does not match the
   * filter criteria, and matching entries should be excluded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeWithCriteriaEntryDoesNotMatchFilterExcludeMatching()
         throws Exception
  {
    final AtomicLong excludeCount = new AtomicLong(0L);

    final ExcludeEntryTransformation t = new ExcludeEntryTransformation(
         Schema.getDefaultStandardSchema(), new DN("dc=example,dc=com"),
         SearchScope.BASE, Filter.createPresenceFilter("description"), true,
         excludeCount);

    final Entry e = t.transformEntry(new Entry(
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
    assertEquals(excludeCount.get(), 0L);
  }



  /**
   * Provides test coverage for the exclude behavior when exclude criteria is
   * given, the entry matches the scope criteria, the entry does not match the
   * filter criteria, and non-matching entries should be excluded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeWithCriteriaEntryDoesNotMatchFilterExcludeNonMatching()
         throws Exception
  {
    final AtomicLong excludeCount = new AtomicLong(0L);

    final ExcludeEntryTransformation t = new ExcludeEntryTransformation(
         Schema.getDefaultStandardSchema(), new DN("dc=example,dc=com"),
         SearchScope.BASE, Filter.createPresenceFilter("description"), false,
         excludeCount);

    final Entry e = t.transformEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));
    assertNull(e);
    assertEquals(excludeCount.get(), 1L);
  }



  /**
   * Provides test coverage for the exclude behavior when exclude criteria is
   * given, the entry has a malformed DN so the DN criteria cannot match, and
   * matching entries should be excluded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeWithCriteriaMalformedDNExcludeMatching()
         throws Exception
  {
    final AtomicLong excludeCount = new AtomicLong(0L);

    final ExcludeEntryTransformation t = new ExcludeEntryTransformation(
         Schema.getDefaultStandardSchema(), new DN("dc=example,dc=com"),
         SearchScope.BASE, Filter.createPresenceFilter("description"), true,
         excludeCount);

    final Entry e = t.transformEntry(new Entry(
         "dn: malformed,dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: malformed,dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
    assertEquals(excludeCount.get(), 0L);
  }



  /**
   * Provides test coverage for the exclude behavior when exclude criteria is
   * given, the entry has a malformed DN so the DN criteria cannot match, and
   * non-matching entries should be excluded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeWithCriteriaMalformedDNExcludeNonMatching()
         throws Exception
  {
    final AtomicLong excludeCount = new AtomicLong(0L);

    final ExcludeEntryTransformation t = new ExcludeEntryTransformation(
         Schema.getDefaultStandardSchema(), new DN("dc=example,dc=com"),
         SearchScope.BASE, Filter.createPresenceFilter("description"), false,
         excludeCount);

    final Entry e = t.transformEntry(new Entry(
         "dn: malformed,dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));
    assertNull(e);
    assertEquals(excludeCount.get(), 1L);
  }



  /**
   * Provides test coverage for the exclude behavior when exclude criteria is
   * given, the filter cannot be processed against the entry, and matching
   * entries should be excluded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeWithCriteriaUnsupportedFilterExcludeMatching()
         throws Exception
  {
    final AtomicLong excludeCount = new AtomicLong(0L);

    final ExcludeEntryTransformation t = new ExcludeEntryTransformation(
         Schema.getDefaultStandardSchema(), new DN("dc=example,dc=com"),
         SearchScope.BASE,
         Filter.createApproximateMatchFilter("description", "foo"), true,
         excludeCount);

    final Entry e = t.transformEntry(new Entry(
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
    assertEquals(excludeCount.get(), 0L);
  }



  /**
   * Provides test coverage for the exclude behavior when exclude criteria is
   * given, the filter cannot be processed against the entry, and non-matching
   * entries should be excluded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeWithCriteriaUnsupportedFilterExcludeNonMatching()
         throws Exception
  {
    final AtomicLong excludeCount = new AtomicLong(0L);

    final ExcludeEntryTransformation t = new ExcludeEntryTransformation(
         Schema.getDefaultStandardSchema(), new DN("dc=example,dc=com"),
         SearchScope.BASE,
         Filter.createApproximateMatchFilter("description", "foo"), false,
         excludeCount);

    final Entry e = t.transformEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));
    assertNull(e);
    assertEquals(excludeCount.get(), 1L);
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
    final AtomicLong excludeCount = new AtomicLong(0L);

    final ExcludeEntryTransformation t = new ExcludeEntryTransformation(null,
         null, null, null, true, excludeCount);

    final Entry e = t.translate(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"),
         0);
    assertNull(e);
    assertEquals(excludeCount.get(), 1L);
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
    final AtomicLong excludeCount = new AtomicLong(0L);

    final ExcludeEntryTransformation t = new ExcludeEntryTransformation(null,
         null, null, null, true, excludeCount);

    final Entry e = t.translateEntryToWrite(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
    assertNull(e);
    assertEquals(excludeCount.get(), 1L);
  }
}
