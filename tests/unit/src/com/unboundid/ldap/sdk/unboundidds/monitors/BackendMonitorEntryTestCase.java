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

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the BackendMonitorEntry class.
 */
public class BackendMonitorEntryTestCase
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
         "dn: cn=userRoot Backend,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-backend-monitor-entry",
         "objectClass: extensibleObject",
         "cn: userRoot Backend",
         "ds-backend-id: userRoot",
         "ds-backend-base-dn: dc=example,dc=com",
         "ds-backend-base-dn: o=example.com",
         "ds-backend-entry-count: 300",
         "ds-base-dn-entry-count: 200 dc=example,dc=com",
         "ds-base-dn-entry-count: 100 o=example.com",
         "ds-backend-is-private: false",
         "ds-backend-writability-mode: enabled",
         "ds-soft-delete-operations-count: 123",
         "ds-undelete-operations-count: 456");

    BackendMonitorEntry me = new BackendMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-backend-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 BackendMonitorEntry.class.getName());

    assertNotNull(me.getBackendID());
    assertEquals(me.getBackendID(), "userRoot");

    assertNotNull(me.getBaseDNs());
    assertEquals(me.getBaseDNs().size(), 2);
    assertEquals(new DN(me.getBaseDNs().get(0)),
                 new DN("dc=example,dc=com"));
    assertEquals(new DN(me.getBaseDNs().get(1)),
                 new DN("o=example.com"));

    assertNotNull(me.isPrivate());
    assertFalse(me.isPrivate());

    assertNotNull(me.getWritabilityMode());
    assertEquals(me.getWritabilityMode(), "enabled");

    assertNotNull(me.getTotalEntries());
    assertEquals(me.getTotalEntries().longValue(), 300L);

    assertNotNull(me.getEntriesPerBaseDN());
    assertEquals(me.getEntriesPerBaseDN().size(), 2);
    assertEquals(me.getEntriesPerBaseDN().get("dc=example,dc=com").longValue(),
                 200L);
    assertEquals(me.getEntriesPerBaseDN().get("o=example.com").longValue(),
                 100L);

    assertEquals(me.getSoftDeleteCount(), Long.valueOf(123L));

    assertEquals(me.getUndeleteCount(), Long.valueOf(456L));

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("ds-backend-id"));
    assertEquals(attrs.get("ds-backend-id").getStringValue(), "userRoot");

    assertNotNull(attrs.get("ds-backend-base-dn"));
    assertEquals(attrs.get("ds-backend-base-dn").getStringValues().size(), 2);
    assertEquals(attrs.get("ds-backend-base-dn").getStringValue(),
                 "dc=example,dc=com");

    assertNotNull(attrs.get("ds-backend-entry-count"));
    assertEquals(attrs.get("ds-backend-entry-count").getLongValue(),
                 Long.valueOf(300L));

    assertNotNull(attrs.get("ds-base-dn-entry-count-dc=example,dc=com"));
    assertEquals(
         attrs.get("ds-base-dn-entry-count-dc=example,dc=com").getLongValue(),
         Long.valueOf(200L));

    assertNotNull(attrs.get("ds-base-dn-entry-count-o=example.com"));
    assertEquals(
         attrs.get("ds-base-dn-entry-count-o=example.com").getLongValue(),
         Long.valueOf(100L));

    assertNotNull(attrs.get("ds-backend-is-private"));
    assertEquals(attrs.get("ds-backend-is-private").getBooleanValue(),
                 Boolean.FALSE);

    assertNotNull(attrs.get("ds-backend-writability-mode"));
    assertEquals(attrs.get("ds-backend-writability-mode").getStringValue(),
                 "enabled");

    assertNotNull(attrs.get("ds-soft-delete-operations-count"));
    assertEquals(attrs.get("ds-soft-delete-operations-count").getLongValue(),
         Long.valueOf(123L));

    assertNotNull(attrs.get("ds-undelete-operations-count"));
    assertEquals(attrs.get("ds-undelete-operations-count").getLongValue(),
         Long.valueOf(456L));
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
         "dn: cn=userRoot Backend,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-backend-monitor-entry",
         "objectClass: extensibleObject",
         "cn: userRoot Backend");

    BackendMonitorEntry me = new BackendMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-backend-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 BackendMonitorEntry.class.getName());

    assertNull(me.getBackendID());

    assertNotNull(me.getBaseDNs());
    assertEquals(me.getBaseDNs().size(), 0);

    assertNull(me.isPrivate());

    assertNull(me.getWritabilityMode());

    assertNull(me.getTotalEntries());

    assertNotNull(me.getEntriesPerBaseDN());
    assertEquals(me.getEntriesPerBaseDN().size(), 0);

    assertNull(me.getSoftDeleteCount());

    assertNull(me.getUndeleteCount());
  }



  /**
   * Provides test coverage for the constructor with an entry containing an
   * invalid value for the entries per base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorInvalidEntriesPerBaseDN()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=userRoot Backend,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-backend-monitor-entry",
         "objectClass: extensibleObject",
         "cn: userRoot Backend",
         "ds-backend-id: userRoot",
         "ds-backend-base-dn: dc=example,dc=com",
         "ds-backend-base-dn: o=example.com",
         "ds-backend-entry-count: 300",
         "ds-base-dn-entry-count: invalid",
         "ds-backend-is-private: false",
         "ds-backend-writability-mode: enabled");

    BackendMonitorEntry me = new BackendMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-backend-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 BackendMonitorEntry.class.getName());

    assertNotNull(me.getBackendID());
    assertEquals(me.getBackendID(), "userRoot");

    assertNotNull(me.getBaseDNs());
    assertEquals(me.getBaseDNs().size(), 2);
    assertEquals(new DN(me.getBaseDNs().get(0)),
                 new DN("dc=example,dc=com"));
    assertEquals(new DN(me.getBaseDNs().get(1)),
                 new DN("o=example.com"));

    assertNotNull(me.isPrivate());
    assertFalse(me.isPrivate());

    assertNotNull(me.getWritabilityMode());
    assertEquals(me.getWritabilityMode(), "enabled");

    assertNotNull(me.getTotalEntries());
    assertEquals(me.getTotalEntries().longValue(), 300L);

    assertNotNull(me.getEntriesPerBaseDN());
    assertEquals(me.getEntriesPerBaseDN().size(), 0);

    assertNull(me.getSoftDeleteCount());

    assertNull(me.getUndeleteCount());
  }
}
