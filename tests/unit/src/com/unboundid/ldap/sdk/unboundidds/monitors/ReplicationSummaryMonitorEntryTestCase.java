/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
 * This class provides test coverage for the ReplicationSummaryMonitorEntry
 * class.
 */
public class ReplicationSummaryMonitorEntryTestCase
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
         "dn: cn=Replication Summary dc_example_dc_com,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-replication-server-summary-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Replication Summary dc_example_dc_com",
         "base-dn: dc=example,dc=com",
         "replication-server: server-id=\"12345\" " +
              "server=\"directory.example.com:8989\" generation-id=\"1234567\"",
         "replica: replica-id=\"12345\" " +
              "ldap-server=\"directory.example.com:389\" " +
              "connected-to=\"54321\" generation-id=\"1234567\" " +
              "replication-backlog=\"12\" recent-update-rate=\"123/sec\" " +
              "peak-update-rate=\"321/sec\" age-of-oldest-backlog-change=\"" +
              "20090101000000.000Z (behind by 10 seconds)\"");

    ReplicationSummaryMonitorEntry me = new ReplicationSummaryMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
                 "ds-replication-server-summary-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 ReplicationSummaryMonitorEntry.class.getName());

    assertNotNull(me.getBaseDN());
    assertEquals(new DN(me.getBaseDN()), new DN("dc=example,dc=com"));

    assertNotNull(me.getReplicas());
    assertEquals(me.getReplicas().size(), 1);

    assertNotNull(me.getReplicationServers());
    assertEquals(me.getReplicationServers().size(), 1);

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("base-dn"));
    assertEquals(new DN(attrs.get("base-dn").getStringValue()),
                 new DN("dc=example,dc=com"));

    assertNotNull(attrs.get("replica"));
    assertNotNull(attrs.get("replica").getStringValues());
    assertFalse(attrs.get("replica").getStringValues().isEmpty());

    assertNotNull(attrs.get("replication-server"));
    assertNotNull(attrs.get("replication-server").getStringValues());
    assertFalse(attrs.get("replication-server").getStringValues().isEmpty());
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
         "dn: cn=Replication Summary dc_example_dc_com,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-replication-server-summary-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Replication Summary dc_example_dc_com");

    ReplicationSummaryMonitorEntry me = new ReplicationSummaryMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
                 "ds-replication-server-summary-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 ReplicationSummaryMonitorEntry.class.getName());

    assertNull(me.getBaseDN());

    assertNotNull(me.getReplicas());
    assertEquals(me.getReplicas().size(), 0);

    assertNotNull(me.getReplicationServers());
    assertEquals(me.getReplicationServers().size(), 0);

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertTrue(me.getMonitorAttributes().isEmpty());

    assertNull(attrs.get("base-dn"));

    assertNull(attrs.get("replica"));

    assertNull(attrs.get("replication-server"));
  }
}
