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
 * This class provides test coverage for the GeneralMonitorEntry class.
 */
public class GeneralMonitorEntryTestCase
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
         "dn: cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-general-monitor-entry",
         "objectClass: extensibleObject",
         "cn: monitor",
         "productName: UnboundID Directory Server",
         "clusterName: Test Cluster",
         "instanceName: server.example.com:389",
         "locationName: Test Location",
         "locationDN: cn=Test Location,cn=Locations,cn=config",
         "startTime: 20080101010101Z",
         "serverUUID: 11111111-2222-3333-4444-555555555555",
         "startupID: abcdefg",
         "startupUUID: 12345678-1234-1234-1234-1234567890ab",
         "currentTime: 20080102020202Z",
         "upTime: 1 day 1 hour 1 minute 1 second",
         "currentConnections: 123",
         "maxConnections: 456",
         "totalConnections: 789",
         "productVendor: Ping Identity Corporation",
         "productVersion: UnboundID Directory Server 1.0.0",
         "degraded-alert-type: low-disk-space-warning",
         "unavailable-alert-type: deadlock-detected",
         "thirdPartyExtensionDN: cn=Third-Party Plugin,cn=Plugins,cn=config");

    GeneralMonitorEntry me = new GeneralMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-general-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 GeneralMonitorEntry.class.getName());

    assertNotNull(me.getCurrentConnections());
    assertEquals(me.getCurrentConnections().longValue(), 123L);

    assertNotNull(me.getMaxConnections());
    assertEquals(me.getMaxConnections().longValue(), 456L);

    assertNotNull(me.getTotalConnections());
    assertEquals(me.getTotalConnections().longValue(), 789L);

    assertNotNull(me.getClusterName());
    assertEquals(me.getClusterName(), "Test Cluster");

    assertNotNull(me.getInstanceName());
    assertEquals(me.getInstanceName(), "server.example.com:389");

    assertNotNull(me.getLocationName());
    assertEquals(me.getLocationName(), "Test Location");

    assertNotNull(me.getLocationDN());
    assertDNsEqual(me.getLocationDN(),
         "cn=Test Location,cn=Locations,cn=config");

    assertNotNull(me.getStartTime());

    assertNotNull(me.getServerUUID());
    assertEquals(me.getServerUUID(), "11111111-2222-3333-4444-555555555555");

    assertNotNull(me.getStartupID());
    assertEquals(me.getStartupID(), "abcdefg");

    assertNotNull(me.getStartupUUID());
    assertEquals(me.getStartupUUID(), "12345678-1234-1234-1234-1234567890ab");

    assertNotNull(me.getCurrentTime());

    assertNotNull(me.getUptimeMillis());
    assertEquals(me.getUptimeMillis().longValue(), 90061000L);

    assertNotNull(me.getUptimeString());
    assertEquals(me.getUptimeString(), "1 day 1 hour 1 minute 1 second");

    assertNotNull(me.getProductName());
    assertEquals(me.getProductName(), "UnboundID Directory Server");

    assertNotNull(me.getVendorName());
    assertEquals(me.getVendorName(), "Ping Identity Corporation");

    assertNotNull(me.getVersionString());
    assertEquals(me.getVersionString(), "UnboundID Directory Server 1.0.0");

    assertNotNull(me.getDegradedAlertTypes());
    assertFalse(me.getDegradedAlertTypes().isEmpty());
    assertTrue(me.getDegradedAlertTypes().contains("low-disk-space-warning"));

    assertNotNull(me.getUnavailableAlertTypes());
    assertFalse(me.getUnavailableAlertTypes().isEmpty());
    assertTrue(me.getUnavailableAlertTypes().contains("deadlock-detected"));

    assertNotNull(me.getThirdPartyExtensionDNs());
    assertFalse(me.getThirdPartyExtensionDNs().isEmpty());
    assertEquals(new DN(me.getThirdPartyExtensionDNs().get(0)),
         new DN("cn=Third-Party Plugin,cn=Plugins,cn=config"));

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("productname"));
    assertEquals(attrs.get("productname").getStringValue(),
                 "UnboundID Directory Server");

    assertNotNull(attrs.get("instancename"));
    assertEquals(attrs.get("instancename").getStringValue(),
                 "server.example.com:389");

    assertNotNull(attrs.get("starttime"));

    assertNotNull(attrs.get("currenttime"));

    assertNotNull(attrs.get("startupid"));
    assertEquals(attrs.get("startupid").getStringValue(), "abcdefg");

    assertNotNull(attrs.get("startupuuid"));
    assertEquals(attrs.get("startupuuid").getStringValue(),
                 "12345678-1234-1234-1234-1234567890ab");

    assertNotNull(attrs.get("uptime"));
    assertEquals(attrs.get("uptime").getStringValue(),
                 "1 day 1 hour 1 minute 1 second");

    assertNotNull(attrs.get("uptimemillis"));
    assertEquals(attrs.get("uptimemillis").getLongValue(),
                 Long.valueOf(90061000L));

    assertNotNull(attrs.get("currentconnections"));
    assertEquals(attrs.get("currentconnections").getLongValue(),
                 Long.valueOf(123));

    assertNotNull(attrs.get("maxconnections"));
    assertEquals(attrs.get("maxconnections").getLongValue(),
                 Long.valueOf(456));

    assertNotNull(attrs.get("totalconnections"));
    assertEquals(attrs.get("totalconnections").getLongValue(),
                 Long.valueOf(789));

    assertNotNull(attrs.get("productvendor"));
    assertEquals(attrs.get("productvendor").getStringValue(),
                 "Ping Identity Corporation");

    assertNotNull(attrs.get("productversion"));
    assertEquals(attrs.get("productversion").getStringValue(),
                 "UnboundID Directory Server 1.0.0");

    assertNotNull(attrs.get("degraded-alert-type"));
    assertEquals(attrs.get("degraded-alert-type").getStringValue(),
                 "low-disk-space-warning");

    assertNotNull(attrs.get("unavailable-alert-type"));
    assertEquals(attrs.get("unavailable-alert-type").getStringValue(),
                 "deadlock-detected");

    assertNotNull(attrs.get("thirdpartyextensiondn"));
    assertEquals(new DN(attrs.get("thirdpartyextensiondn").getStringValue()),
         new DN("cn=Third-Party Plugin,cn=Plugins,cn=config"));
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
         "dn: cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-general-monitor-entry",
         "objectClass: extensibleObject",
         "cn: monitor");

    GeneralMonitorEntry me = new GeneralMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-general-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 GeneralMonitorEntry.class.getName());

    assertNull(me.getCurrentConnections());

    assertNull(me.getMaxConnections());

    assertNull(me.getTotalConnections());

    assertNull(me.getClusterName());

    assertNull(me.getInstanceName());

    assertNull(me.getLocationName());

    assertNull(me.getLocationDN());

    assertNull(me.getStartTime());

    assertNull(me.getServerUUID());

    assertNull(me.getStartupID());

    assertNull(me.getStartupUUID());

    assertNull(me.getCurrentTime());

    assertNull(me.getUptimeMillis());

    assertNull(me.getUptimeString());

    assertNull(me.getProductName());

    assertNull(me.getVendorName());

    assertNull(me.getVersionString());

    assertNotNull(me.getDegradedAlertTypes());
    assertTrue(me.getDegradedAlertTypes().isEmpty());

    assertNotNull(me.getUnavailableAlertTypes());
    assertTrue(me.getUnavailableAlertTypes().isEmpty());

    assertNotNull(me.getThirdPartyExtensionDNs());
    assertTrue(me.getThirdPartyExtensionDNs().isEmpty());
  }
}
