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
package com.unboundid.ldap.sdk.unboundidds.monitors;



import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the EntryCacheMonitorEntry class.
 */
public class EntryCacheMonitorEntryTestCase
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
         "dn: cn=Entry Caches,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-entry-cache-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Entry Caches",
         "currentEntryCacheCount: 1234",
         "maxEntryCacheCount: 1000000",
         "currentEntryCacheSize: 12345678",
         "maxEntryCacheSize: 50000000",
         "entryCacheTries: 500",
         "entryCacheHits: 400",
         "entryCacheHitRatio: 0.8");

    EntryCacheMonitorEntry me = new EntryCacheMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-entry-cache-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 EntryCacheMonitorEntry.class.getName());

    assertNotNull(me.getCacheTries());
    assertEquals(me.getCacheTries().longValue(), 500L);

    assertNotNull(me.getCacheHits());
    assertEquals(me.getCacheHits().longValue(), 400L);

    assertNotNull(me.getCacheMisses());
    assertEquals(me.getCacheMisses().longValue(), 100L);

    assertNotNull(me.getCacheHitRatio());
    assertEquals(me.getCacheHitRatio(), Double.valueOf(0.8d));

    assertNotNull(me.getCurrentCount());
    assertEquals(me.getCurrentCount().longValue(), 1234L);

    assertNotNull(me.getMaxCount());
    assertEquals(me.getMaxCount().longValue(), 1000000L);

    assertNotNull(me.getCurrentCacheSize());
    assertEquals(me.getCurrentCacheSize().longValue(), 12345678L);

    assertNotNull(me.getMaxCacheSize());
    assertEquals(me.getMaxCacheSize().longValue(), 50000000L);

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("currententrycachecount"));
    assertEquals(attrs.get("currententrycachecount").getLongValue(),
                 Long.valueOf(1234L));

    assertNotNull(attrs.get("maxentrycachecount"));
    assertEquals(attrs.get("maxentrycachecount").getLongValue(),
                 Long.valueOf(1000000L));

    assertNotNull(attrs.get("currententrycachesize"));
    assertEquals(attrs.get("currententrycachesize").getLongValue(),
                 Long.valueOf(12345678L));

    assertNotNull(attrs.get("maxentrycachesize"));
    assertEquals(attrs.get("maxentrycachesize").getLongValue(),
                 Long.valueOf(50000000L));

    assertNotNull(attrs.get("entrycachetries"));
    assertEquals(attrs.get("entrycachetries").getLongValue(),
                 Long.valueOf(500L));

    assertNotNull(attrs.get("entrycachehits"));
    assertEquals(attrs.get("entrycachehits").getLongValue(),
                 Long.valueOf(400L));

    assertNotNull(attrs.get("entrycachemisses"));
    assertEquals(attrs.get("entrycachemisses").getLongValue(),
                 Long.valueOf(100L));

    assertNotNull(attrs.get("entrycachehitratio"));
    assertEquals(attrs.get("entrycachehitratio").getDoubleValue(),
                 Double.valueOf(0.8D));
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
         "dn: cn=Entry Caches,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-entry-cache-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Entry Caches");

    EntryCacheMonitorEntry me = new EntryCacheMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-entry-cache-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 EntryCacheMonitorEntry.class.getName());

    assertNull(me.getCacheTries());

    assertNull(me.getCacheHits());

    assertNull(me.getCacheMisses());

    assertNull(me.getCacheHitRatio());

    assertNull(me.getCurrentCount());

    assertNull(me.getMaxCount());

    assertNull(me.getCurrentCacheSize());

    assertNull(me.getMaxCacheSize());
  }
}
