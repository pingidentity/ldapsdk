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
 * This class provides test coverage for the ReplicaMonitorEntry class.
 */
public class ReplicaMonitorEntryTestCase
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
         "dn: cn=Replica dc_example_dc_com,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-replica-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Replica dc_example_dc_com",
         "base-dn: dc=example,dc=com",
         "connected-to: directory.example.com:8989",
         "lost-connections: 1",
         "received-updates: 2",
         "sent-updates: 3",
         "pending-updates: 4",
         "replayed-updates: 5",
         "replayed-updates-ok: 6",
         "resolved-modify-conflicts: 7",
         "resolved-naming-conflicts: 8",
         "unresolved-naming-conflicts: 9",
         "replica-id: 10",
         "max-rcv-window: 11",
         "current-rcv-window: 12",
         "max-send-window: 13",
         "current-send-window: 14",
         "ssl-encryption: false",
         "generation-id: 15");

    ReplicaMonitorEntry me = new ReplicaMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
                 "ds-replica-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 ReplicaMonitorEntry.class.getName());

    assertNotNull(me.getBaseDN());
    assertEquals(new DN(me.getBaseDN()), new DN("dc=example,dc=com"));

    assertNotNull(me.getReplicationServerAddress());
    assertEquals(me.getReplicationServerAddress(), "directory.example.com");

    assertNotNull(me.getReplicationServerPort());
    assertEquals(me.getReplicationServerPort(), Long.valueOf(8989L));

    assertNotNull(me.getLostConnections());
    assertEquals(me.getLostConnections(), Long.valueOf(1L));

    assertNotNull(me.getReceivedUpdates());
    assertEquals(me.getReceivedUpdates(), Long.valueOf(2L));

    assertNotNull(me.getSentUpdates());
    assertEquals(me.getSentUpdates(), Long.valueOf(3L));

    assertNotNull(me.getPendingUpdates());
    assertEquals(me.getPendingUpdates(), Long.valueOf(4L));

    assertNotNull(me.getTotalUpdatesReplayed());
    assertEquals(me.getTotalUpdatesReplayed(), Long.valueOf(5L));

    assertNotNull(me.getUpdatesSuccessfullyReplayed());
    assertEquals(me.getUpdatesSuccessfullyReplayed(), Long.valueOf(6L));

    assertNotNull(me.getUpdatesReplayedAfterModifyConflict());
    assertEquals(me.getUpdatesReplayedAfterModifyConflict(), Long.valueOf(7L));

    assertNotNull(me.getUpdatesReplayedAfterNamingConflict());
    assertEquals(me.getUpdatesReplayedAfterNamingConflict(), Long.valueOf(8L));

    assertNotNull(me.getUnresolvedNamingConflicts());
    assertEquals(me.getUnresolvedNamingConflicts(), Long.valueOf(9L));

    assertNotNull(me.getReplicaID());
    assertEquals(me.getReplicaID(), "10");

    assertNotNull(me.getMaximumReceiveWindowSize());
    assertEquals(me.getMaximumReceiveWindowSize(), Long.valueOf(11L));

    assertNotNull(me.getCurrentReceiveWindowSize());
    assertEquals(me.getCurrentReceiveWindowSize(), Long.valueOf(12L));

    assertNotNull(me.getMaximumSendWindowSize());
    assertEquals(me.getMaximumSendWindowSize(), Long.valueOf(13L));

    assertNotNull(me.getCurrentSendWindowSize());
    assertEquals(me.getCurrentSendWindowSize(), Long.valueOf(14L));

    assertNotNull(me.useSSL());
    assertEquals(me.useSSL(), Boolean.FALSE);

    assertNotNull(me.getGenerationID());
    assertEquals(me.getGenerationID(), "15");

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("base-dn"));
    assertEquals(new DN(attrs.get("base-dn").getStringValue()),
                 new DN("dc=example,dc=com"));

    assertNotNull(attrs.get("connected-to"));
    assertEquals(attrs.get("connected-to").getStringValue(),
                 "directory.example.com:8989");

    assertNotNull(attrs.get("lost-connections"));
    assertEquals(attrs.get("lost-connections").getLongValue(),
                 Long.valueOf(1L));

    assertNotNull(attrs.get("received-updates"));
    assertEquals(attrs.get("received-updates").getLongValue(),
                 Long.valueOf(2L));

    assertNotNull(attrs.get("sent-updates"));
    assertEquals(attrs.get("sent-updates").getLongValue(),
                 Long.valueOf(3L));

    assertNotNull(attrs.get("pending-updates"));
    assertEquals(attrs.get("pending-updates").getLongValue(),
                 Long.valueOf(4L));

    assertNotNull(attrs.get("replayed-updates"));
    assertEquals(attrs.get("replayed-updates").getLongValue(),
                 Long.valueOf(5L));

    assertNotNull(attrs.get("replayed-updates-ok"));
    assertEquals(attrs.get("replayed-updates-ok").getLongValue(),
                 Long.valueOf(6L));

    assertNotNull(attrs.get("resolved-modify-conflicts"));
    assertEquals(attrs.get("resolved-modify-conflicts").getLongValue(),
                 Long.valueOf(7L));

    assertNotNull(attrs.get("resolved-naming-conflicts"));
    assertEquals(attrs.get("resolved-naming-conflicts").getLongValue(),
                 Long.valueOf(8L));

    assertNotNull(attrs.get("unresolved-naming-conflicts"));
    assertEquals(attrs.get("unresolved-naming-conflicts").getLongValue(),
                 Long.valueOf(9L));

    assertNotNull(attrs.get("replica-id"));
    assertEquals(attrs.get("replica-id").getStringValue(), "10");

    assertNotNull(attrs.get("max-rcv-window"));
    assertEquals(attrs.get("max-rcv-window").getLongValue(), Long.valueOf(11L));

    assertNotNull(attrs.get("current-rcv-window"));
    assertEquals(attrs.get("current-rcv-window").getLongValue(),
                 Long.valueOf(12L));

    assertNotNull(attrs.get("max-send-window"));
    assertEquals(attrs.get("max-send-window").getLongValue(),
                 Long.valueOf(13L));

    assertNotNull(attrs.get("current-send-window"));
    assertEquals(attrs.get("current-send-window").getLongValue(),
                 Long.valueOf(14L));

    assertNotNull(attrs.get("ssl-encryption"));
    assertEquals(attrs.get("ssl-encryption").getBooleanValue(), Boolean.FALSE);

    assertNotNull(attrs.get("generation-id"));
    assertEquals(attrs.get("generation-id").getStringValue(), "15");
  }



  /**
   * Provides test coverage for the constructor with an entry with an invalid
   * replication server address:port combination.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorInvalidHostPort()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Replica dc_example_dc_com,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-replica-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Replica dc_example_dc_com",
         "connected-to: invalid");

    ReplicaMonitorEntry me = new ReplicaMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
                 "ds-replica-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 ReplicaMonitorEntry.class.getName());

    assertNull(me.getBaseDN());

    assertNull(me.getReplicationServerAddress());

    assertNull(me.getReplicationServerPort());

    assertNull(me.getLostConnections());

    assertNull(me.getReceivedUpdates());

    assertNull(me.getSentUpdates());

    assertNull(me.getPendingUpdates());

    assertNull(me.getTotalUpdatesReplayed());

    assertNull(me.getUpdatesSuccessfullyReplayed());

    assertNull(me.getUpdatesReplayedAfterModifyConflict());

    assertNull(me.getUpdatesReplayedAfterNamingConflict());

    assertNull(me.getUnresolvedNamingConflicts());

    assertNull(me.getReplicaID());

    assertNull(me.getMaximumReceiveWindowSize());

    assertNull(me.getCurrentReceiveWindowSize());

    assertNull(me.getMaximumSendWindowSize());

    assertNull(me.getCurrentSendWindowSize());

    assertNull(me.useSSL());

    assertNull(me.getGenerationID());

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertTrue(me.getMonitorAttributes().isEmpty());
  }



  /**
   * Provides test coverage for the constructor with an entry with an invalid
   * port number for the replication server address:port combination.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorInvalidPort()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Replica dc_example_dc_com,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-replica-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Replica dc_example_dc_com",
         "connected-to: invalid:invalid");

    ReplicaMonitorEntry me = new ReplicaMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
                 "ds-replica-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 ReplicaMonitorEntry.class.getName());

    assertNull(me.getBaseDN());

    assertNull(me.getReplicationServerAddress());

    assertNull(me.getReplicationServerPort());

    assertNull(me.getLostConnections());

    assertNull(me.getReceivedUpdates());

    assertNull(me.getSentUpdates());

    assertNull(me.getPendingUpdates());

    assertNull(me.getTotalUpdatesReplayed());

    assertNull(me.getUpdatesSuccessfullyReplayed());

    assertNull(me.getUpdatesReplayedAfterModifyConflict());

    assertNull(me.getUpdatesReplayedAfterNamingConflict());

    assertNull(me.getUnresolvedNamingConflicts());

    assertNull(me.getReplicaID());

    assertNull(me.getMaximumReceiveWindowSize());

    assertNull(me.getCurrentReceiveWindowSize());

    assertNull(me.getMaximumSendWindowSize());

    assertNull(me.getCurrentSendWindowSize());

    assertNull(me.useSSL());

    assertNull(me.getGenerationID());

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertTrue(me.getMonitorAttributes().isEmpty());
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
         "dn: cn=Replica dc_example_dc_com,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-replica-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Replica dc_example_dc_com");

    ReplicaMonitorEntry me = new ReplicaMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
                 "ds-replica-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 ReplicaMonitorEntry.class.getName());

    assertNull(me.getBaseDN());

    assertNull(me.getReplicationServerAddress());

    assertNull(me.getReplicationServerPort());

    assertNull(me.getLostConnections());

    assertNull(me.getReceivedUpdates());

    assertNull(me.getSentUpdates());

    assertNull(me.getPendingUpdates());

    assertNull(me.getTotalUpdatesReplayed());

    assertNull(me.getUpdatesSuccessfullyReplayed());

    assertNull(me.getUpdatesReplayedAfterModifyConflict());

    assertNull(me.getUpdatesReplayedAfterNamingConflict());

    assertNull(me.getUnresolvedNamingConflicts());

    assertNull(me.getReplicaID());

    assertNull(me.getMaximumReceiveWindowSize());

    assertNull(me.getCurrentReceiveWindowSize());

    assertNull(me.getMaximumSendWindowSize());

    assertNull(me.getCurrentSendWindowSize());

    assertNull(me.useSSL());

    assertNull(me.getGenerationID());

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertTrue(me.getMonitorAttributes().isEmpty());
  }
}
