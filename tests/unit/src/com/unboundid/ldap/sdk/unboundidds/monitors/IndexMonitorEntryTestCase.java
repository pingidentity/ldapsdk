/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.monitors;



import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the IndexMonitorEntry class.
 */
public class IndexMonitorEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the constructor with a valid entry with all
   * values present.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorAllValues()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Index dc_example_dc_com_cn.equality,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-index-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Index dc_example_dc_com_cn.equality",
         "ds-index-name: dc_example_dc_com_cn.equality",
         "ds-index-backend-id: userRoot",
         "ds-index-backend-base-dn: dc=example,dc=com",
         "ds-index-attribute-type: cn",
         "ds-index-type: equality",
         "ds-index-filter: (objectClass=person)",
         "ds-index-trusted: true",
         "ds-index-entry-limit: 1",
         "ds-index-exceeded-entry-limit-count-since-db-open: 2",
         "ds-index-maintain-count: false",
         "ds-index-fully-primed-at-backend-open: false",
         "ds-index-prime-incomplete-reason: An exception was caught",
         "ds-index-prime-exception: exception goes here",
         "ds-index-num-primed-keys-at-backend-open: 3",
         "ds-index-write-count-since-db-open: 4",
         "ds-index-remove-count-since-db-open: 5",
         "ds-index-read-count-since-db-open: 6",
         "ds-index-read-for-search-count-since-db-open: 7",
         "ds-index-open-cursor-count-since-db-open: 8",
         "ds-index-unique-keys-near-entry-limit-accessed-by-search-since-db-" +
              "open: 9",
         "ds-index-unique-keys-exceeding-entry-limit-accessed-by-search-" +
              "since-db-open: 10",
         "ds-index-unique-keys-near-entry-limit-accessed-by-write-since-db-" +
              "open: 11",
         "ds-index-unique-keys-exceeding-entry-limit-accessed-by-write-since-" +
              "db-open: 12");

    IndexMonitorEntry me = new IndexMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-index-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
         IndexMonitorEntry.class.getName());

    assertNotNull(me.getIndexName());
    assertEquals(me.getIndexName(),
         "dc_example_dc_com_cn.equality");

    assertNotNull(me.getBackendID());
    assertEquals(me.getBackendID(),
         "userRoot");

    assertNotNull(me.getBaseDN());
    assertEquals(new DN(me.getBaseDN()),
         new DN("dc=example,dc=com"));

    assertNotNull(me.getAttributeType());
    assertEquals(me.getAttributeType(),
         "cn");

    assertNotNull(me.getAttributeIndexType());
    assertEquals(me.getAttributeIndexType(),
         "equality");

    assertNotNull(me.getIndexFilter());
    assertEquals(Filter.create(me.getIndexFilter()),
         Filter.create("(objectClass=person)"));

    assertNotNull(me.isIndexTrusted());
    assertTrue(me.isIndexTrusted());

    assertNotNull(me.getIndexEntryLimit());
    assertEquals(me.getIndexEntryLimit(),
         Long.valueOf(1));

    assertNotNull(me.getEntryLimitExceededCountSinceComingOnline());
    assertEquals(me.getEntryLimitExceededCountSinceComingOnline(),
         Long.valueOf(2));

    assertNotNull(me.maintainCountForExceededKeys());
    assertFalse(me.maintainCountForExceededKeys());

    assertNotNull(me.fullyPrimedWhenBroughtOnline());
    assertFalse(me.fullyPrimedWhenBroughtOnline());

    assertNotNull(me.getPrimeIncompleteReason());
    assertEquals(me.getPrimeIncompleteReason(),
         "An exception was caught");

    assertNotNull(me.getPrimeException());
    assertEquals(me.getPrimeException(),
         "exception goes here");

    assertNotNull(me.getKeysPrimedWhenBroughtOnline());
    assertEquals(me.getKeysPrimedWhenBroughtOnline(),
         Long.valueOf(3));

    assertNotNull(me.getKeysWrittenSinceComingOnline());
    assertEquals(me.getKeysWrittenSinceComingOnline(),
         Long.valueOf(4));

    assertNotNull(me.getKeysDeletedSinceComingOnline());
    assertEquals(me.getKeysDeletedSinceComingOnline(),
         Long.valueOf(5));

    assertNotNull(me.getKeysReadSinceComingOnline());
    assertEquals(me.getKeysReadSinceComingOnline(),
         Long.valueOf(6));

    assertNotNull(me.getFilterInitiatedReadsSinceComingOnline());
    assertEquals(me.getFilterInitiatedReadsSinceComingOnline(),
         Long.valueOf(7));

    assertNotNull(me.getCursorsCreatedSinceComingOnline());
    assertEquals(me.getCursorsCreatedSinceComingOnline(),
         Long.valueOf(8));

    assertNotNull(
         me.getUniqueKeysNearEntryLimitAccessedBySearchSinceComingOnline());
    assertEquals(
         me.getUniqueKeysNearEntryLimitAccessedBySearchSinceComingOnline(),
         Long.valueOf(9));

    assertNotNull(
         me.getUniqueKeysOverEntryLimitAccessedBySearchSinceComingOnline());
    assertEquals(
         me.getUniqueKeysOverEntryLimitAccessedBySearchSinceComingOnline(),
         Long.valueOf(10));

    assertNotNull(
         me.getUniqueKeysNearEntryLimitAccessedByWriteSinceComingOnline());
    assertEquals(
         me.getUniqueKeysNearEntryLimitAccessedByWriteSinceComingOnline(),
         Long.valueOf(11));

    assertNotNull(
         me.getUniqueKeysOverEntryLimitAccessedByWriteSinceComingOnline());
    assertEquals(
         me.getUniqueKeysOverEntryLimitAccessedByWriteSinceComingOnline(),
         Long.valueOf(12));



    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("ds-index-name"));
    assertEquals(attrs.get("ds-index-name").getStringValue(),
         "dc_example_dc_com_cn.equality");

    assertNotNull(attrs.get("ds-index-backend-id"));
    assertEquals(attrs.get("ds-index-backend-id").getStringValue(),
         "userRoot");

    assertNotNull(attrs.get("ds-index-backend-base-dn"));
    assertEquals(new DN(attrs.get("ds-index-backend-base-dn").getStringValue()),
         new DN("dc=example,dc=com"));

    assertNotNull(attrs.get("ds-index-attribute-type"));
    assertEquals(attrs.get("ds-index-attribute-type").getStringValue(),
         "cn");

    assertNotNull(attrs.get("ds-index-type"));
    assertEquals(attrs.get("ds-index-type").getStringValue(),
         "equality");

    assertNotNull(attrs.get("ds-index-filter"));
    assertEquals(Filter.create(attrs.get("ds-index-filter").getStringValue()),
         Filter.create("(objectClass=person)"));

    assertNotNull(attrs.get("ds-index-trusted"));
    assertEquals(attrs.get("ds-index-trusted").getBooleanValue(),
         Boolean.TRUE);

    assertNotNull(attrs.get("ds-index-entry-limit"));
    assertEquals(attrs.get("ds-index-entry-limit").getLongValue(),
         Long.valueOf(1L));

    assertNotNull(attrs.get(
         "ds-index-exceeded-entry-limit-count-since-db-open"));
    assertEquals(attrs.get(
         "ds-index-exceeded-entry-limit-count-since-db-open").getLongValue(),
         Long.valueOf(2L));

    assertNotNull(attrs.get("ds-index-maintain-count"));
    assertEquals(attrs.get("ds-index-maintain-count").getBooleanValue(),
         Boolean.FALSE);

    assertNotNull(attrs.get("ds-index-fully-primed-at-backend-open"));
    assertEquals(attrs.get(
         "ds-index-fully-primed-at-backend-open").getBooleanValue(),
         Boolean.FALSE);

    assertNotNull(attrs.get("ds-index-prime-incomplete-reason"));
    assertEquals(attrs.get("ds-index-prime-incomplete-reason").getStringValue(),
         "An exception was caught");

    assertNotNull(attrs.get("ds-index-prime-exception"));
    assertEquals(attrs.get("ds-index-prime-exception").getStringValue(),
         "exception goes here");

    assertNotNull(attrs.get("ds-index-num-primed-keys-at-backend-open"));
    assertEquals(attrs.get(
         "ds-index-num-primed-keys-at-backend-open").getLongValue(),
         Long.valueOf(3L));

    assertNotNull(attrs.get("ds-index-write-count-since-db-open"));
    assertEquals(attrs.get("ds-index-write-count-since-db-open").getLongValue(),
         Long.valueOf(4L));

    assertNotNull(attrs.get("ds-index-remove-count-since-db-open"));
    assertEquals(attrs.get(
         "ds-index-remove-count-since-db-open").getLongValue(),
         Long.valueOf(5L));

    assertNotNull(attrs.get("ds-index-read-count-since-db-open"));
    assertEquals(attrs.get("ds-index-read-count-since-db-open").getLongValue(),
         Long.valueOf(6L));

    assertNotNull(attrs.get("ds-index-read-for-search-count-since-db-open"));
    assertEquals(attrs.get(
         "ds-index-read-for-search-count-since-db-open").getLongValue(),
         Long.valueOf(7L));

    assertNotNull(attrs.get("ds-index-open-cursor-count-since-db-open"));
    assertEquals(attrs.get(
         "ds-index-open-cursor-count-since-db-open").getLongValue(),
         Long.valueOf(8L));

    assertNotNull(attrs.get("ds-index-unique-keys-near-entry-limit-accessed-" +
         "by-search-since-db-open"));
    assertEquals(
         attrs.get("ds-index-unique-keys-near-entry-limit-accessed-by-search-" +
              "since-db-open").getLongValue(),
         Long.valueOf(9L));

    assertNotNull(attrs.get("ds-index-unique-keys-exceeding-entry-limit-" +
         "accessed-by-search-since-db-open"));
    assertEquals(
         attrs.get("ds-index-unique-keys-exceeding-entry-limit-accessed-by-" +
              "search-since-db-open").getLongValue(),
         Long.valueOf(10L));

    assertNotNull(attrs.get("ds-index-unique-keys-near-entry-limit-accessed-" +
         "by-write-since-db-open"));
    assertEquals(
         attrs.get("ds-index-unique-keys-near-entry-limit-accessed-by-write-" +
              "since-db-open").getLongValue(),
         Long.valueOf(11L));

    assertNotNull(attrs.get("ds-index-unique-keys-exceeding-entry-limit-" +
         "accessed-by-write-since-db-open"));
    assertEquals(
         attrs.get("ds-index-unique-keys-exceeding-entry-limit-accessed-by-" +
              "write-since-db-open").getLongValue(),
         Long.valueOf(12L));
  }



  /**
   * Provides test coverage for the constructor with a valid entry with no
   * values present.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorNoValues()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Index dc_example_dc_com_cn.equality,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-index-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Index dc_example_dc_com_cn.equality");

    IndexMonitorEntry me = new IndexMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-index-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
         IndexMonitorEntry.class.getName());

    assertNull(me.getIndexName());

    assertNull(me.getBackendID());

    assertNull(me.getBaseDN());

    assertNull(me.getAttributeType());

    assertNull(me.getAttributeIndexType());

    assertNull(me.getIndexFilter());

    assertNull(me.isIndexTrusted());

    assertNull(me.getIndexEntryLimit());

    assertNull(me.getEntryLimitExceededCountSinceComingOnline());

    assertNull(me.maintainCountForExceededKeys());

    assertNull(me.fullyPrimedWhenBroughtOnline());

    assertNull(me.getPrimeIncompleteReason());

    assertNull(me.getPrimeException());

    assertNull(me.getKeysPrimedWhenBroughtOnline());

    assertNull(me.getKeysWrittenSinceComingOnline());

    assertNull(me.getKeysDeletedSinceComingOnline());

    assertNull(me.getKeysReadSinceComingOnline());

    assertNull(me.getFilterInitiatedReadsSinceComingOnline());

    assertNull(me.getCursorsCreatedSinceComingOnline());

    assertNull(
         me.getUniqueKeysNearEntryLimitAccessedBySearchSinceComingOnline());

    assertNull(
         me.getUniqueKeysOverEntryLimitAccessedBySearchSinceComingOnline());

    assertNull(
         me.getUniqueKeysNearEntryLimitAccessedByWriteSinceComingOnline());

    assertNull(
         me.getUniqueKeysOverEntryLimitAccessedByWriteSinceComingOnline());
  }
}
