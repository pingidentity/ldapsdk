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
 * This class provides test coverage for the ClientConnectionMonitorEntry class.
 */
public class ClientConnectionMonitorEntryTestCase
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
    String connStr1 = "connID=\"0\" connectTime=\"20080101010101Z\" " +
         "source=\"127.0.0.1:1234\" destination=\"127.0.0.1:389\" " +
         "ldapVersion=\"3\" authDN=\"\" security=\"none\" opsInProgress=\"1\"";
    String connStr2 = "connID=\"1\" connectTime=\"20080101020202Z\" " +
         "source=\"127.0.0.1:5678\" destination=\"127.0.0.1:389\" " +
         "ldapVersion=\"3\" authDN=\"cn=Directory Manager\" " +
         "security=\"SSL\" opsInProgress=\"0\"";

    Entry e = new Entry(
         "dn: cn=Client Connections,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-client-connection-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Client Connections",
         "connection: " + connStr1,
         "connection: " + connStr2);

    ClientConnectionMonitorEntry me = new ClientConnectionMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-client-connection-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 ClientConnectionMonitorEntry.class.getName());

    assertNotNull(me.getConnections());
    assertEquals(me.getConnections().size(), 2);
    assertEquals(me.getConnections().get(0), connStr1);
    assertEquals(me.getConnections().get(1), connStr2);

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("connection"));
    assertTrue(attrs.get("connection").hasMultipleValues());
    assertEquals(attrs.get("connection").getStringValue(), connStr1);
    assertEquals(attrs.get("connection").getStringValues().size(), 2);
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
         "dn: cn=Client Connections,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-client-connection-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Client Connections");

    ClientConnectionMonitorEntry me = new ClientConnectionMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-client-connection-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 ClientConnectionMonitorEntry.class.getName());

    assertNotNull(me.getConnections());
    assertEquals(me.getConnections().size(), 0);
  }
}
