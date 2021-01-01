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
 * This class provides test coverage for the ConnectionHandlerMonitorEntry
 * class.
 */
public class ConnectionHandlerMonitorEntryTestCase
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
         "dn: cn=LDAP Connection Handler 0.0.0.0 port 389,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-connectionhandler-monitor-entry",
         "objectClass: extensibleObject",
         "cn: LDAP Connection Handler 0.0.0.0 port 389",
         "ds-connectionhandler-protocol: LDAP",
         "ds-connectionhandler-listener: 0.0.0.0:389",
         "ds-connectionhandler-connection: " + connStr1,
         "ds-connectionhandler-connection: " + connStr2,
         "ds-connectionhandler-num-connections: 2");

    ConnectionHandlerMonitorEntry me = new ConnectionHandlerMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-connectionhandler-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 ConnectionHandlerMonitorEntry.class.getName());

    assertNotNull(me.getConnections());
    assertEquals(me.getConnections().size(), 2);
    assertEquals(me.getConnections().get(0), connStr1);
    assertEquals(me.getConnections().get(1), connStr2);

    assertNotNull(me.getListeners());
    assertEquals(me.getListeners().size(), 1);
    assertEquals(me.getListeners().get(0), "0.0.0.0:389");

    assertNotNull(me.getNumConnections());
    assertEquals(me.getNumConnections().longValue(), 2L);

    assertNotNull(me.getProtocol());
    assertEquals(me.getProtocol(), "LDAP");

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("ds-connectionhandler-protocol"));
    assertEquals(attrs.get("ds-connectionhandler-protocol").getStringValue(),
                 "LDAP");

    assertNotNull(attrs.get("ds-connectionhandler-listener"));
    assertEquals(attrs.get("ds-connectionhandler-listener").getStringValue(),
                 "0.0.0.0:389");

    assertNotNull(attrs.get("ds-connectionhandler-connection"));

    assertNotNull(attrs.get("ds-connectionhandler-num-connections"));
    assertEquals(
         attrs.get("ds-connectionhandler-num-connections").getLongValue(),
         Long.valueOf(2));
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
         "dn: cn=LDAP Connection Handler 0.0.0.0 port 389,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-connectionhandler-monitor-entry",
         "objectClass: extensibleObject",
         "cn: LDAP Connection Handler 0.0.0.0 port 389");

    ConnectionHandlerMonitorEntry me = new ConnectionHandlerMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-connectionhandler-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 ConnectionHandlerMonitorEntry.class.getName());

    assertNotNull(me.getConnections());
    assertEquals(me.getConnections().size(), 0);

    assertNotNull(me.getListeners());
    assertEquals(me.getListeners().size(), 0);

    assertNull(me.getNumConnections());

    assertNull(me.getProtocol());
  }
}
