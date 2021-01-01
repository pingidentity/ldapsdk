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
 * This class provides test coverage for the VersionMonitorEntry class.
 */
public class VersionMonitorEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the constructor with a valid entry with all
   * values present.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testConstructorAllValues()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Version,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-version-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Version",
         "buildID: 20080101010101Z",
         "buildNumber: 1",
         "compactVersion: UnboundID-DS-1.2-beta1-build1",
         "fixIDs: 1234,5678",
         "fullVersion: UnboundID Directory Server 1.2-beta1-build1",
         "majorVersion: 1",
         "minorVersion: 2",
         "pointVersion: 3",
         "productName: UnboundID Directory Server",
         "revisionNumber: 123",
         "revisionID: 123",
         "shortName: UnboundID-DS",
         "versionQualifier: -beta1",
         "groovyVersion: groovy-1.2.3.4",
         "jeVersion: je-1.2.3.4",
         "jzlibVersion: jzlib-1.2.3.4",
         "ldapSDKVersion: ldap-sdk-1.2.3.4",
         "serverSDKVersion: server-sdk-1.2.3.4",
         "snmp4jVersion: snmp4j-1.2.3.4",
         "snmp4jAgentVersion: snmp4j-agent-1.2.3.4",
         "snmp4jAgentXVersion: snmp4j-agentx-1.2.3.4");

    VersionMonitorEntry me = new VersionMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-version-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 VersionMonitorEntry.class.getName());

    assertNotNull(me.getBuildID());
    assertEquals(me.getBuildID(), "20080101010101Z");

    assertNotNull(me.getBuildNumber());
    assertEquals(me.getBuildNumber().longValue(), 1L);

    assertNotNull(me.getCompactVersion());
    assertEquals(me.getCompactVersion(), "UnboundID-DS-1.2-beta1-build1");

    assertNotNull(me.getFixIDs());
    assertEquals(me.getFixIDs(), "1234,5678");

    assertNotNull(me.getFullVersion());
    assertEquals(me.getFullVersion(),
                 "UnboundID Directory Server 1.2-beta1-build1");

    assertNotNull(me.getMajorVersion());
    assertEquals(me.getMajorVersion().longValue(), 1L);

    assertNotNull(me.getMinorVersion());
    assertEquals(me.getMinorVersion().longValue(), 2L);

    assertNotNull(me.getPointVersion());
    assertEquals(me.getPointVersion().longValue(), 3L);

    assertNotNull(me.getProductName());
    assertEquals(me.getProductName(), "UnboundID Directory Server");

    assertNotNull(me.getRevisionNumber());
    assertEquals(me.getRevisionNumber().longValue(), 123L);

    assertNotNull(me.getRevisionID());
    assertEquals(me.getRevisionID(), "123");

    assertNotNull(me.getShortProductName());
    assertEquals(me.getShortProductName(), "UnboundID-DS");

    assertNotNull(me.getVersionQualifier());
    assertEquals(me.getVersionQualifier(), "-beta1");

    assertNotNull(me.getGroovyVersion());
    assertEquals(me.getGroovyVersion(),
         "groovy-1.2.3.4");

    assertNotNull(me.getBerkeleyDBJEVersion());
    assertEquals(me.getBerkeleyDBJEVersion(),
         "je-1.2.3.4");

    assertNotNull(me.getJZLibVersion());
    assertEquals(me.getJZLibVersion(),
         "jzlib-1.2.3.4");

    assertNotNull(me.getLDAPSDKVersion());
    assertEquals(me.getLDAPSDKVersion(),
         "ldap-sdk-1.2.3.4");

    assertNotNull(me.getServerSDKVersion());
    assertEquals(me.getServerSDKVersion(),
         "server-sdk-1.2.3.4");

    assertNotNull(me.getSNMP4JVersion());
    assertEquals(me.getSNMP4JVersion(),
         "snmp4j-1.2.3.4");

    assertNotNull(me.getSNMP4JAgentVersion());
    assertEquals(me.getSNMP4JAgentVersion(),
         "snmp4j-agent-1.2.3.4");

    assertNotNull(me.getSNMP4JAgentXVersion());
    assertEquals(me.getSNMP4JAgentXVersion(),
         "snmp4j-agentx-1.2.3.4");

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("buildid"));
    assertEquals(attrs.get("buildid").getStringValue(),
                 "20080101010101Z");

    assertNotNull(attrs.get("buildnumber"));
    assertEquals(attrs.get("buildnumber").getLongValue(),
                 Long.valueOf(1L));

    assertNotNull(attrs.get("compactversion"));
    assertEquals(attrs.get("compactversion").getStringValue(),
                 "UnboundID-DS-1.2-beta1-build1");

    assertNotNull(attrs.get("fixids"));
    assertEquals(attrs.get("fixids").getStringValue(),
                 "1234,5678");

    assertNotNull(attrs.get("fullversion"));
    assertEquals(attrs.get("fullversion").getStringValue(),
                 "UnboundID Directory Server 1.2-beta1-build1");

    assertNotNull(attrs.get("majorversion"));
    assertEquals(attrs.get("majorversion").getLongValue(),
                 Long.valueOf(1L));

    assertNotNull(attrs.get("minorversion"));
    assertEquals(attrs.get("minorversion").getLongValue(),
                 Long.valueOf(2L));

    assertNotNull(attrs.get("pointversion"));
    assertEquals(attrs.get("pointversion").getLongValue(),
                 Long.valueOf(3L));

    assertNotNull(attrs.get("productname"));
    assertEquals(attrs.get("productname").getStringValue(),
                 "UnboundID Directory Server");

    assertNotNull(attrs.get("revisionnumber"));
    assertEquals(attrs.get("revisionnumber").getLongValue(),
                 Long.valueOf(123L));

    assertNotNull(attrs.get("shortname"));
    assertEquals(attrs.get("shortname").getStringValue(),
                 "UnboundID-DS");

    assertNotNull(attrs.get("versionqualifier"));
    assertEquals(attrs.get("versionqualifier").getStringValue(),
                 "-beta1");

    assertNotNull(attrs.get("groovyversion"));
    assertEquals(attrs.get("groovyversion").getStringValue(),
                 "groovy-1.2.3.4");

    assertNotNull(attrs.get("jeversion"));
    assertEquals(attrs.get("jeversion").getStringValue(),
                 "je-1.2.3.4");

    assertNotNull(attrs.get("jzlibversion"));
    assertEquals(attrs.get("jzlibversion").getStringValue(),
                 "jzlib-1.2.3.4");

    assertNotNull(attrs.get("ldapsdkversion"));
    assertEquals(attrs.get("ldapsdkversion").getStringValue(),
                 "ldap-sdk-1.2.3.4");

    assertNotNull(attrs.get("serversdkversion"));
    assertEquals(attrs.get("serversdkversion").getStringValue(),
                 "server-sdk-1.2.3.4");

    assertNotNull(attrs.get("snmp4jversion"));
    assertEquals(attrs.get("snmp4jversion").getStringValue(),
                 "snmp4j-1.2.3.4");

    assertNotNull(attrs.get("snmp4jagentversion"));
    assertEquals(attrs.get("snmp4jagentversion").getStringValue(),
                 "snmp4j-agent-1.2.3.4");

    assertNotNull(attrs.get("snmp4jagentxversion"));
    assertEquals(attrs.get("snmp4jagentxversion").getStringValue(),
                 "snmp4j-agentx-1.2.3.4");
  }



  /**
   * Provides test coverage for the constructor with a valid entry with no
   * values present.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testConstructorNoValues()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Version,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-version-monitor-entry",
         "objectClass: extensibleObject",
         "cn: Version");

    VersionMonitorEntry me = new VersionMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-version-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 VersionMonitorEntry.class.getName());

    assertNull(me.getBuildID());

    assertNull(me.getBuildNumber());

    assertNull(me.getCompactVersion());

    assertNull(me.getFixIDs());

    assertNull(me.getFullVersion());

    assertNull(me.getMajorVersion());

    assertNull(me.getMinorVersion());

    assertNull(me.getPointVersion());

    assertNull(me.getProductName());

    assertNull(me.getRevisionNumber());

    assertNull(me.getRevisionID());

    assertNull(me.getShortProductName());

    assertNull(me.getVersionQualifier());

    assertNull(me.getGroovyVersion());

    assertNull(me.getBerkeleyDBJEVersion());

    assertNull(me.getJZLibVersion());

    assertNull(me.getLDAPSDKVersion());

    assertNull(me.getServerSDKVersion());

    assertNull(me.getSNMP4JVersion());

    assertNull(me.getSNMP4JAgentVersion());

    assertNull(me.getSNMP4JAgentXVersion());
  }
}
