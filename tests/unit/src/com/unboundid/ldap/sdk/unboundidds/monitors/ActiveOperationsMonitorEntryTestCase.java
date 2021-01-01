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
 * This class provides test coverage for the ActiveOperationsMonitorEntry class.
 */
public class ActiveOperationsMonitorEntryTestCase
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
         "dn: cn=Active Operations,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-active-operations-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Active Operations",
         "num-operations-in-progress: 1",
         "operation-in-progress: [14/Aug/2008:13:44:53 -0500] SEARCH conn=0 " +
              "op=1 msgID=2 clientIP=\"127.0.0.1\" " +
              "authDN=\"cn=Directory Manager,cn=Root DNs,cn=config\" " +
              "base=\"cn=monitor\" scope=wholeSubtree " +
              "filter=\"(objectClass=*)\" attrs=\"ALL\"",
         "num-persistent-searches-in-progress: 2",
         "persistent-search-in-progress: [14/Aug/2008:13:44:53 -0500] SEARCH " +
              "conn=0 op=0 msgID=1 clientIP=\"127.0.0.1\" " +
              "authDN=\"cn=Directory Manager,cn=Root DNs,cn=config\" " +
              "base=\"cn=alerts\" scope=wholeSubtree " +
              "filter=\"(objectClass=*)\" attrs=\"ALL\"");

    ActiveOperationsMonitorEntry me = new ActiveOperationsMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-active-operations-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 ActiveOperationsMonitorEntry.class.getName());

    assertNotNull(me.getNumOperationsInProgress());
    assertEquals(me.getNumOperationsInProgress(), Long.valueOf(1L));

    assertNotNull(me.getActiveOperations());
    assertEquals(me.getActiveOperations().size(), 1);

    assertNotNull(me.getNumPersistentSearchesInProgress());
    assertEquals(me.getNumPersistentSearchesInProgress(), Long.valueOf(2L));

    assertNotNull(me.getActivePersistentSearches());
    assertEquals(me.getActivePersistentSearches().size(), 1);

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("num-operations-in-progress"));
    assertFalse(attrs.get("num-operations-in-progress").hasMultipleValues());
    assertNotNull(attrs.get("num-operations-in-progress").getLongValue());

    assertNotNull(attrs.get("operation-in-progress"));
    assertFalse(attrs.get("operation-in-progress").hasMultipleValues());
    assertNotNull(attrs.get("operation-in-progress").getStringValue());

    assertNotNull(attrs.get("num-persistent-searches-in-progress"));
    assertFalse(attrs.get(
         "num-persistent-searches-in-progress").hasMultipleValues());
    assertNotNull(attrs.get(
         "num-persistent-searches-in-progress").getLongValue());

    assertNotNull(attrs.get("persistent-search-in-progress"));
    assertFalse(attrs.get("persistent-search-in-progress").hasMultipleValues());
    assertNotNull(attrs.get("persistent-search-in-progress").getStringValue());
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
         "dn: cn=Active Operations,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-active-operations-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Active Operations");

    ActiveOperationsMonitorEntry me = new ActiveOperationsMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-active-operations-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 ActiveOperationsMonitorEntry.class.getName());

    assertNull(me.getNumOperationsInProgress());

    assertNotNull(me.getActiveOperations());
    assertEquals(me.getActiveOperations().size(), 0);

    assertNull(me.getNumPersistentSearchesInProgress());

    assertNotNull(me.getActivePersistentSearches());
    assertEquals(me.getActivePersistentSearches().size(), 0);
  }
}
