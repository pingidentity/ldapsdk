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
 * This class provides test coverage for the ReplicationServerMonitorEntry
 * class.
 */
public class ReplicationServerMonitorEntryTestCase
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
         "dn: cn=Replication Server 12345 54321,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-replication-server-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Replication Server 12345 54321",
         "replication-server-id: 54321",
         "replication-server-port: 12345",
         "ssl-encryption-available: true",
         "base-dn: dc=example,dc=com",
         "base-dn: cn=schema",
         "base-dn: cn=admin data",
         "base-dn-generation-id: dc=example,dc=com 1234567",
         "base-dn-generation-id: cn=schema 1234568",
         "base-dn-generation-id: cn=admin data 1234569",
         "base-dn-generation-id: invalid dn 1234570");

    ReplicationServerMonitorEntry me = new ReplicationServerMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
                 "ds-replication-server-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 ReplicationServerMonitorEntry.class.getName());

    assertNotNull(me.getReplicationServerID());
    assertEquals(me.getReplicationServerID(), "54321");

    assertNotNull(me.getReplicationServerPort());
    assertEquals(me.getReplicationServerPort(), Long.valueOf(12345L));

    assertNotNull(me.sslEncryptionAvailable());
    assertEquals(me.sslEncryptionAvailable(), Boolean.TRUE);

    assertNotNull(me.getBaseDNs());
    assertFalse(me.getBaseDNs().isEmpty());
    assertEquals(me.getBaseDNs().size(), 3);

    assertNotNull(me.getGenerationIDs());
    assertFalse(me.getGenerationIDs().isEmpty());
    assertEquals(me.getGenerationIDs().size(), 3);

    assertNotNull(me.getGenerationID("dc=example,dc=com"));
    assertEquals(me.getGenerationID("dc=example,dc=com"), "1234567");

    assertNotNull(me.getGenerationID("cn=schema"));
    assertEquals(me.getGenerationID("cn=schema"), "1234568");

    assertNotNull(me.getGenerationID("cn=admin data"));
    assertEquals(me.getGenerationID("cn=admin data"), "1234569");

    assertNull(me.getGenerationID("o=example.com"));

    assertNull(me.getGenerationID("invalid DN"));

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("replication-server-id"));
    assertEquals(attrs.get("replication-server-id").getStringValue(), "54321");

    assertNotNull(attrs.get("replication-server-port"));
    assertEquals(attrs.get("replication-server-port").getLongValue(),
                 Long.valueOf(12345L));

    assertNotNull(attrs.get("ssl-encryption-available"));
    assertEquals(attrs.get("ssl-encryption-available").getBooleanValue(),
                 Boolean.TRUE);

    assertNotNull(attrs.get("base-dn"));
    assertEquals(attrs.get("base-dn").getStringValues().size(), 3);
    assertEquals(new DN(attrs.get("base-dn").getStringValue()),
                 new DN("dc=example,dc=com"));

    assertNotNull(attrs.get("base-dn-generation-id"));
    assertEquals(attrs.get("base-dn-generation-id").getStringValues().size(),
                 3);
    assertEquals(new DN(attrs.get("base-dn-generation-id").getStringValue()),
                 new DN("dc=example,dc=com 1234567"));
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
         "dn: cn=Replication Server 12345 54321,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-replication-server-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Replication Server 12345 54321");

    ReplicationServerMonitorEntry me = new ReplicationServerMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
                 "ds-replication-server-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 ReplicationServerMonitorEntry.class.getName());

    assertNull(me.getReplicationServerID());

    assertNull(me.getReplicationServerPort());

    assertNull(me.sslEncryptionAvailable());

    assertNotNull(me.getBaseDNs());
    assertTrue(me.getBaseDNs().isEmpty());

    assertNotNull(me.getGenerationIDs());
    assertTrue(me.getGenerationIDs().isEmpty());

    assertNull(me.getGenerationID("dc=example,dc=com"));

    assertNull(me.getGenerationID("invalid DN"));

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertTrue(me.getMonitorAttributes().isEmpty());

    assertNull(attrs.get("replication-server-id"));

    assertNull(attrs.get("replication-server-port"));

    assertNull(attrs.get("base-dn"));

    assertNull(attrs.get("base-dn-generation-id"));
  }
}
