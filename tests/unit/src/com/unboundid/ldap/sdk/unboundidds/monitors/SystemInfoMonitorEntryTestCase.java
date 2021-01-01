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



import java.util.Arrays;
import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the SystemInfoMonitorEntry class.
 */
public class SystemInfoMonitorEntryTestCase
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
         "dn: cn=System Information,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-system-info-monitor-entry",
         "objectClass: extensibleObject",
         "cn: System Information",
         "javaVersion: 1.6.0_05",
         "javaVendor: Sun Microsystems Inc.",
         "jvmPID: 1234",
         "jvmVersion: 10.0-b19",
         "jvmVendor: Sun Microsystems Inc.",
         "javaHome: /usr/java",
         "classPath: classes:lib/UnboundID-DS.jar",
         "workingDirectory: /opt/UnboundID-DS/bin",
         "instanceRoot: /opt/UnboundID-DS",
         "operatingSystem: SunOS 5.11 x86",
         "jvmArchitecture: 32-bit",
         "systemName: server.example.com",
         "sslContextProtocol: TLSv1.2",
         "availableCPUs: 4",
         "maxMemory: 1234567890",
         "usedMemory: 123456789",
         "freeUsedMemory: 12345678",
         "jvmArguments: -server",
         "userName: ds",
         "environmentVariable: VAR1='oof'",
         "environmentVariable: VAR2='rab'",
         "environmentVariable: VAR3=''",
         "environmentVariable: VAR4='",
         "systemProperty: prop.1='foo'",
         "systemProperty: prop.2='bar'",
         "systemProperty: prop.3=''",
         "systemProperty: prop.4='");

    SystemInfoMonitorEntry me = new SystemInfoMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-system-info-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 SystemInfoMonitorEntry.class.getName());

    assertNotNull(me.getAvailableCPUs());
    assertEquals(me.getAvailableCPUs().longValue(), 4L);

    assertNotNull(me.getClassPath());
    assertEquals(me.getClassPath(), "classes:lib/UnboundID-DS.jar");

    assertNotNull(me.getFreeMemory());
    assertEquals(me.getFreeMemory().longValue(), 12345678L);

    assertNotNull(me.getHostname());
    assertEquals(me.getHostname(), "server.example.com");

    assertNotNull(me.getInstanceRoot());
    assertEquals(me.getInstanceRoot(), "/opt/UnboundID-DS");

    assertNotNull(me.getJavaHome());
    assertEquals(me.getJavaHome(), "/usr/java");

    assertNotNull(me.getJavaVendor());
    assertEquals(me.getJavaVendor(), "Sun Microsystems Inc.");

    assertNotNull(me.getJavaVersion());
    assertEquals(me.getJavaVersion(), "1.6.0_05");

    assertNotNull(me.getJVMArchitectureDataModel());
    assertEquals(me.getJVMArchitectureDataModel(), "32-bit");

    assertNotNull(me.getJVMArguments());
    assertEquals(me.getJVMArguments(), "-server");

    assertNotNull(me.getJVMPID());
    assertEquals(me.getJVMPID().longValue(), 1234L);

    assertNotNull(me.getJVMVendor());
    assertEquals(me.getJVMVendor(), "Sun Microsystems Inc.");

    assertNotNull(me.getJVMVersion());
    assertEquals(me.getJVMVersion(), "10.0-b19");

    assertNotNull(me.getSSLContextProtocol());
    assertEquals(me.getSSLContextProtocol(), "TLSv1.2");

    assertNotNull(me.getMaxMemory());
    assertEquals(me.getMaxMemory().longValue(), 1234567890L);

    assertNotNull(me.getOperatingSystem());
    assertEquals(me.getOperatingSystem(), "SunOS 5.11 x86");

    assertNotNull(me.getUsedMemory());
    assertEquals(me.getUsedMemory().longValue(), 123456789L);

    assertNotNull(me.getWorkingDirectory());
    assertEquals(me.getWorkingDirectory(), "/opt/UnboundID-DS/bin");

    assertNotNull(me.getUserName());
    assertEquals(me.getUserName(), "ds");

    assertNotNull(me.getEnvironmentVariables());
    assertFalse(me.getEnvironmentVariables().isEmpty());
    assertEquals(me.getEnvironmentVariables().size(), 3);
    assertEquals(me.getEnvironmentVariables().get("VAR1"), "oof");
    assertEquals(me.getEnvironmentVariables().get("VAR2"), "rab");
    assertEquals(me.getEnvironmentVariables().get("VAR3"), "");
    assertNull(me.getEnvironmentVariables().get("VAR4"));
    assertNull(me.getEnvironmentVariables().get("undefined"));

    assertNotNull(me.getSystemProperties());
    assertFalse(me.getSystemProperties().isEmpty());
    assertEquals(me.getSystemProperties().size(), 3);
    assertEquals(me.getSystemProperties().get("prop.1"), "foo");
    assertEquals(me.getSystemProperties().get("prop.2"), "bar");
    assertEquals(me.getSystemProperties().get("prop.3"), "");
    assertNull(me.getSystemProperties().get("prop.4"));
    assertNull(me.getSystemProperties().get("undefined"));

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("javaversion"));
    assertEquals(attrs.get("javaversion").getStringValue(),
                 "1.6.0_05");

    assertNotNull(attrs.get("javavendor"));
    assertEquals(attrs.get("javavendor").getStringValue(),
                 "Sun Microsystems Inc.");

    assertNotNull(attrs.get("jvmversion"));
    assertEquals(attrs.get("jvmversion").getStringValue(),
                 "10.0-b19");

    assertNotNull(attrs.get("jvmvendor"));
    assertEquals(attrs.get("jvmvendor").getStringValue(),
                 "Sun Microsystems Inc.");

    assertNotNull(attrs.get("javahome"));
    assertEquals(attrs.get("javahome").getStringValue(),
                 "/usr/java");

    assertNotNull(attrs.get("classpath"));
    assertEquals(attrs.get("classpath").getStringValue(),
                 "classes:lib/UnboundID-DS.jar");

    assertNotNull(attrs.get("workingdirectory"));
    assertEquals(attrs.get("workingdirectory").getStringValue(),
                 "/opt/UnboundID-DS/bin");

    assertNotNull(attrs.get("instanceroot"));
    assertEquals(attrs.get("instanceroot").getStringValue(),
                 "/opt/UnboundID-DS");

    assertNotNull(attrs.get("operatingsystem"));
    assertEquals(attrs.get("operatingsystem").getStringValue(),
                 "SunOS 5.11 x86");

    assertNotNull(attrs.get("jvmarchitecture"));
    assertEquals(attrs.get("jvmarchitecture").getStringValue(),
                 "32-bit");

    assertNotNull(attrs.get("jvmpid"));
    assertEquals(attrs.get("jvmpid").getLongValue(), Long.valueOf(1234L));

    assertNotNull(attrs.get("systemname"));
    assertEquals(attrs.get("systemname").getStringValue(),
                 "server.example.com");

    assertNotNull(attrs.get("sslcontextprotocol"));
    assertEquals(attrs.get("sslcontextprotocol").getStringValue(),
                 "TLSv1.2");

    assertNotNull(attrs.get("availablecpus"));
    assertEquals(attrs.get("availablecpus").getLongValue(),
                 Long.valueOf(4));

    assertNotNull(attrs.get("maxmemory"));
    assertEquals(attrs.get("maxmemory").getLongValue(),
                 Long.valueOf(1234567890));

    assertNotNull(attrs.get("usedmemory"));
    assertEquals(attrs.get("usedmemory").getLongValue(),
                 Long.valueOf(123456789));

    assertNotNull(attrs.get("freeusedmemory"));
    assertEquals(attrs.get("freeusedmemory").getLongValue(),
                 Long.valueOf(12345678));

    assertNotNull(attrs.get("jvmarguments"));
    assertEquals(attrs.get("jvmarguments").getStringValue(),
                 "-server");

    assertNotNull(attrs.get("username"));
    assertEquals(attrs.get("username").getStringValue(),
                 "ds");

    assertNotNull(attrs.get("environmentvariable"));
    assertEquals(attrs.get("environmentvariable").getStringValues(),
         Arrays.asList("VAR1='oof'", "VAR2='rab'", "VAR3=''"));

    assertNotNull(attrs.get("systemproperty"));
    assertEquals(attrs.get("systemproperty").getStringValues(),
         Arrays.asList("prop.1='foo'", "prop.2='bar'", "prop.3=''"));
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
         "dn: cn=System Information,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-system-info-monitor-entry",
         "objectClass: extensibleObject",
         "cn: System Information");

    SystemInfoMonitorEntry me = new SystemInfoMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-system-info-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 SystemInfoMonitorEntry.class.getName());

    assertNull(me.getAvailableCPUs());

    assertNull(me.getClassPath());

    assertNull(me.getFreeMemory());

    assertNull(me.getHostname());

    assertNull(me.getInstanceRoot());

    assertNull(me.getJavaHome());

    assertNull(me.getJavaVendor());

    assertNull(me.getJavaVersion());

    assertNull(me.getJVMArchitectureDataModel());

    assertNull(me.getJVMArguments());

    assertNull(me.getJVMPID());

    assertNull(me.getJVMVendor());

    assertNull(me.getJVMVersion());

    assertNull(me.getSSLContextProtocol());

    assertNull(me.getMaxMemory());

    assertNull(me.getOperatingSystem());

    assertNull(me.getUsedMemory());

    assertNull(me.getWorkingDirectory());

    assertNull(me.getUserName());

    assertNotNull(me.getEnvironmentVariables());
    assertTrue(me.getEnvironmentVariables().isEmpty());

    assertNotNull(me.getSystemProperties());
    assertTrue(me.getSystemProperties().isEmpty());
  }
}
