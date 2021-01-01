/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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



import java.util.Arrays;
import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the LoadBalancingAlgorithmMonitorEntry
 * class.
 */
public class LoadBalancingAlgorithmMonitorEntryTestCase
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
    final Entry e = new Entry(
         "dn: cn=load-balancing algorithm " +
              "dc_example_dc_com-fewest-operations,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-load-balancing-algorithm-monitor-entry",
         "objectClass: extensibleObject",
         "cn: load-balancing algorithm dc_example_dc_com-fewest-operations",
         "algorithm-name: dc_example_dc_com-fewest-operations",
         "config-entry-dn: cn=dc_example_dc_com-fewest-operations," +
              "cn=Load-Balancing Algorithms,cn=config",
         "health-check-state: AVAILABLE",
         "local-servers-health-check-state: DEGRADED",
         "non-local-servers-health-check-state: UNAVAILABLE",
         "ldap-external-server: ds1.example.com:389:AVAILABLE",
         "ldap-external-server: ds2.example.com:389:DEGRADED",
         "ldap-external-server: ds3.example.com:389:DEGRADED",
         "ldap-external-server: ds4.example.com:389:UNAVAILABLE",
         "ldap-external-server: ds5.example.com:389:UNAVAILABLE",
         "ldap-external-server: ds6.example.com:389:UNAVAILABLE",
         "ldap-external-server: malformed-value-will-not-be-used",
         "num-available-servers: 1",
         "num-degraded-servers: 2",
         "num-unavailable-servers: 3");


    final LoadBalancingAlgorithmMonitorEntry me =
         new LoadBalancingAlgorithmMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
         "ds-load-balancing-algorithm-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
         LoadBalancingAlgorithmMonitorEntry.class.getName());

    assertNotNull(me.getAlgorithmName());
    assertEquals(me.getAlgorithmName(), "dc_example_dc_com-fewest-operations");

    assertNotNull(me.getConfigEntryDN());
    assertDNsEqual(
         me.getConfigEntryDN(),
         "cn=dc_example_dc_com-fewest-operations," +
              "cn=Load-Balancing Algorithms,cn=config");

    assertNotNull(me.getHealthCheckState());
    assertEquals(me.getHealthCheckState(), HealthCheckState.AVAILABLE);

    assertNotNull(me.getLocalServersHealthCheckState());
    assertEquals(me.getLocalServersHealthCheckState(),
         HealthCheckState.DEGRADED);

    assertNotNull(me.getNonLocalServersHealthCheckState());
    assertEquals(me.getNonLocalServersHealthCheckState(),
         HealthCheckState.UNAVAILABLE);

    assertNotNull(me.getServerAvailabilityData());
    assertEquals(me.getServerAvailabilityData().size(), 6);

    final LoadBalancingAlgorithmServerAvailabilityData d =
         me.getServerAvailabilityData().get(0);
    assertNotNull(d);
    assertEquals(d.getServerAddress(), "ds1.example.com");
    assertEquals(d.getServerPort(), 389);
    assertEquals(d.getHealthCheckState(), HealthCheckState.AVAILABLE);
    assertNotNull(d.toString());
    assertEquals(d.toCompactString(), "ds1.example.com:389:AVAILABLE");

    assertNotNull(me.getNumAvailableServers());
    assertEquals(me.getNumAvailableServers().intValue(), 1);

    assertNotNull(me.getNumDegradedServers());
    assertEquals(me.getNumDegradedServers().intValue(), 2);

    assertNotNull(me.getNumUnavailableServers());
    assertEquals(me.getNumUnavailableServers().intValue(), 3);

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    final Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("algorithm-name"));
    assertEquals(attrs.get("algorithm-name").getStringValue(),
         "dc_example_dc_com-fewest-operations");

    assertNotNull(attrs.get("config-entry-dn"));
    assertDNsEqual(
         attrs.get("config-entry-dn").getStringValue(),
         "cn=dc_example_dc_com-fewest-operations," +
              "cn=Load-Balancing Algorithms,cn=config");

    assertNotNull(attrs.get("health-check-state"));
    assertEquals(attrs.get("health-check-state").getStringValue(),
         "AVAILABLE");

    assertNotNull(attrs.get("local-servers-health-check-state"));
    assertEquals(attrs.get("local-servers-health-check-state").getStringValue(),
         "DEGRADED");

    assertNotNull(attrs.get("non-local-servers-health-check-state"));
    assertEquals(
         attrs.get("non-local-servers-health-check-state").getStringValue(),
         "UNAVAILABLE");

    assertNotNull(attrs.get("ldap-external-server"));
    assertEquals(attrs.get("ldap-external-server").getStringValues(),
         Arrays.asList(
              "ds1.example.com:389:AVAILABLE",
              "ds2.example.com:389:DEGRADED",
              "ds3.example.com:389:DEGRADED",
              "ds4.example.com:389:UNAVAILABLE",
              "ds5.example.com:389:UNAVAILABLE",
              "ds6.example.com:389:UNAVAILABLE"));

    assertNotNull(attrs.get("num-available-servers"));
    assertEquals(attrs.get("num-available-servers").getLongValue(),
         Long.valueOf(1L));

    assertNotNull(attrs.get("num-degraded-servers"));
    assertEquals(attrs.get("num-degraded-servers").getLongValue(),
         Long.valueOf(2L));

    assertNotNull(attrs.get("num-unavailable-servers"));
    assertEquals(attrs.get("num-unavailable-servers").getLongValue(),
         Long.valueOf(3L));
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
    final Entry e = new Entry(
         "dn: cn=load-balancing algorithm " +
              "dc_example_dc_com-fewest-operations,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-load-balancing-algorithm-monitor-entry",
         "objectClass: extensibleObject",
         "cn: load-balancing algorithm dc_example_dc_com-fewest-operations");


    final LoadBalancingAlgorithmMonitorEntry me =
         new LoadBalancingAlgorithmMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(),
         "ds-load-balancing-algorithm-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
         LoadBalancingAlgorithmMonitorEntry.class.getName());

    assertNull(me.getAlgorithmName());

    assertNull(me.getConfigEntryDN());

    assertNull(me.getHealthCheckState());

    assertNull(me.getLocalServersHealthCheckState());

    assertNull(me.getNonLocalServersHealthCheckState());

    assertNotNull(me.getServerAvailabilityData());
    assertTrue(me.getServerAvailabilityData().isEmpty());

    assertNull(me.getNumAvailableServers());

    assertNull(me.getNumDegradedServers());

    assertNull(me.getNumUnavailableServers());

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    final Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertTrue(me.getMonitorAttributes().isEmpty());

    assertNull(attrs.get("algorithm-name"));

    assertNull(attrs.get("config-entry-dn"));

    assertNull(attrs.get("health-check-state"));

    assertNull(attrs.get("local-servers-health-check-state"));

    assertNull(attrs.get("non-local-servers-health-check-state"));

    assertNull(attrs.get("ldap-external-server"));

    assertNull(attrs.get("num-available-servers"));

    assertNull(attrs.get("num-degraded-servers"));

    assertNull(attrs.get("num-unavailable-servers"));
  }
}
