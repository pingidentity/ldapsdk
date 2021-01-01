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
 * This class provides test coverage for the LDAPExternalServerMonitorEntry
 * class.
 */
public class LDAPExternalServerMonitorEntryTestCase
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
         "dn: cn=LDAP external server test:389 for test-lba,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-ldap-external-server-monitor-entry",
         "objectClass: extensibleObject",
         "cn: cn=LDAP external server test:389 for test-lba",
         "server-address: test.example.com",
         "server-port: 389",
         "communication-security: none",
         "load-balancing-algorithm: cn=test-lba,cn=Load-Balancing Algorithms," +
              "cn=config",
         "health-check-state: AVAILABLE",
         "health-check-score: 10",
         "health-check-message: Everything is A-OK",
         "health-check-update-time: 20090101000000Z",
         "add-attempts: 1",
         "add-failures: 2",
         "add-successes: 3",
         "bind-attempts: 4",
         "bind-failures: 5",
         "bind-successes: 6",
         "compare-attempts: 7",
         "compare-failures: 8",
         "compare-successes: 9",
         "delete-attempts: 10",
         "delete-failures: 11",
         "delete-successes: 12",
         "modify-attempts: 13",
         "modify-failures: 14",
         "modify-successes: 15",
         "modify-dn-attempts: 16",
         "modify-dn-failures: 17",
         "modify-dn-successes: 18",
         "search-attempts: 19",
         "search-failures: 20",
         "search-successes: 21",
         "common-pool-available-connections: 22",
         "common-pool-max-available-connections: 23",
         "common-pool-num-successful-connection-attempts: 24",
         "common-pool-num-failed-connection-attempts: 25",
         "common-pool-num-closed-defunct: 26",
         "common-pool-num-closed-expired: 27",
         "common-pool-num-closed-unneeded: 28",
         "common-pool-num-successful-checkouts: 29",
         "common-pool-num-successful-checkouts-without-waiting: 30",
         "common-pool-num-successful-checkouts-after-waiting: 31",
         "common-pool-num-successful-checkouts-new-connection: 32",
         "common-pool-num-failed-checkouts: 33",
         "common-pool-num-released-valid: 34",
         "bind-pool-available-connections: 35",
         "bind-pool-max-available-connections: 36",
         "bind-pool-num-successful-connection-attempts: 37",
         "bind-pool-num-failed-connection-attempts: 38",
         "bind-pool-num-closed-defunct: 39",
         "bind-pool-num-closed-expired: 40",
         "bind-pool-num-closed-unneeded: 41",
         "bind-pool-num-successful-checkouts: 42",
         "bind-pool-num-successful-checkouts-without-waiting: 43",
         "bind-pool-num-successful-checkouts-after-waiting: 44",
         "bind-pool-num-successful-checkouts-new-connection: 45",
         "bind-pool-num-failed-checkouts: 46",
         "bind-pool-num-released-valid: 47",
         "non-bind-pool-available-connections: 48",
         "non-bind-pool-max-available-connections: 49",
         "non-bind-pool-num-successful-connection-attempts: 50",
         "non-bind-pool-num-failed-connection-attempts: 51",
         "non-bind-pool-num-closed-defunct: 52",
         "non-bind-pool-num-closed-expired: 53",
         "non-bind-pool-num-closed-unneeded: 54",
         "non-bind-pool-num-successful-checkouts: 55",
         "non-bind-pool-num-successful-checkouts-without-waiting: 56",
         "non-bind-pool-num-successful-checkouts-after-waiting: 57",
         "non-bind-pool-num-successful-checkouts-new-connection: 58",
         "non-bind-pool-num-failed-checkouts: 59",
         "non-bind-pool-num-released-valid: 60");


    LDAPExternalServerMonitorEntry me = new LDAPExternalServerMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-ldap-external-server-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 LDAPExternalServerMonitorEntry.class.getName());

    assertEquals(me.getServerAddress(), "test.example.com");
    assertEquals(me.getServerPort(), Long.valueOf(389));
    assertEquals(me.getCommunicationSecurity(), "none");

    assertEquals(new DN(me.getLoadBalancingAlgorithmDN()),
                 new DN("cn=test-lba,cn=Load-Balancing Algorithms,cn=config"));

    assertEquals(me.getHealthCheckState(),
                 HealthCheckState.AVAILABLE);

    assertEquals(me.getHealthCheckScore(), Long.valueOf(10));

    assertNotNull(me.getHealthCheckMessages());
    assertEquals(me.getHealthCheckMessages().size(), 1);

    assertNotNull(me.getHealthCheckUpdateTime());

    assertEquals(me.getAddAttempts(), Long.valueOf(1));
    assertEquals(me.getAddFailures(), Long.valueOf(2));
    assertEquals(me.getAddSuccesses(), Long.valueOf(3));

    assertEquals(me.getBindAttempts(), Long.valueOf(4));
    assertEquals(me.getBindFailures(), Long.valueOf(5));
    assertEquals(me.getBindSuccesses(), Long.valueOf(6));

    assertEquals(me.getCompareAttempts(), Long.valueOf(7));
    assertEquals(me.getCompareFailures(), Long.valueOf(8));
    assertEquals(me.getCompareSuccesses(), Long.valueOf(9));

    assertEquals(me.getDeleteAttempts(), Long.valueOf(10));
    assertEquals(me.getDeleteFailures(), Long.valueOf(11));
    assertEquals(me.getDeleteSuccesses(), Long.valueOf(12));

    assertEquals(me.getModifyAttempts(), Long.valueOf(13));
    assertEquals(me.getModifyFailures(), Long.valueOf(14));
    assertEquals(me.getModifySuccesses(), Long.valueOf(15));

    assertEquals(me.getModifyDNAttempts(), Long.valueOf(16));
    assertEquals(me.getModifyDNFailures(), Long.valueOf(17));
    assertEquals(me.getModifyDNSuccesses(), Long.valueOf(18));

    assertEquals(me.getSearchAttempts(), Long.valueOf(19));
    assertEquals(me.getSearchFailures(), Long.valueOf(20));
    assertEquals(me.getSearchSuccesses(), Long.valueOf(21));

    assertEquals(me.getCommonPoolAvailableConnections(), Long.valueOf(22));
    assertEquals(me.getCommonPoolMaxAvailableConnections(), Long.valueOf(23));
    assertEquals(me.getCommonPoolNumSuccessfulConnectionAttempts(),
                 Long.valueOf(24));
    assertEquals(me.getCommonPoolNumFailedConnectionAttempts(),
                 Long.valueOf(25));
    assertEquals(me.getCommonPoolNumClosedDefunct(), Long.valueOf(26));
    assertEquals(me.getCommonPoolNumClosedExpired(), Long.valueOf(27));
    assertEquals(me.getCommonPoolNumClosedUnneeded(), Long.valueOf(28));
    assertEquals(me.getCommonPoolTotalSuccessfulCheckouts(), Long.valueOf(29));
    assertEquals(me.getCommonPoolNumSuccessfulCheckoutsWithoutWaiting(),
                 Long.valueOf(30));
    assertEquals(me.getCommonPoolNumSuccessfulCheckoutsAfterWaiting(),
                 Long.valueOf(31));
    assertEquals(me.getCommonPoolNumSuccessfulCheckoutsNewConnection(),
                 Long.valueOf(32));
    assertEquals(me.getCommonPoolNumFailedCheckouts(), Long.valueOf(33));
    assertEquals(me.getCommonPoolNumReleasedValid(), Long.valueOf(34));

    assertEquals(me.getBindPoolAvailableConnections(), Long.valueOf(35));
    assertEquals(me.getBindPoolMaxAvailableConnections(), Long.valueOf(36));
    assertEquals(me.getBindPoolNumSuccessfulConnectionAttempts(),
                 Long.valueOf(37));
    assertEquals(me.getBindPoolNumFailedConnectionAttempts(),
                 Long.valueOf(38));
    assertEquals(me.getBindPoolNumClosedDefunct(), Long.valueOf(39));
    assertEquals(me.getBindPoolNumClosedExpired(), Long.valueOf(40));
    assertEquals(me.getBindPoolNumClosedUnneeded(), Long.valueOf(41));
    assertEquals(me.getBindPoolTotalSuccessfulCheckouts(), Long.valueOf(42));
    assertEquals(me.getBindPoolNumSuccessfulCheckoutsWithoutWaiting(),
                 Long.valueOf(43));
    assertEquals(me.getBindPoolNumSuccessfulCheckoutsAfterWaiting(),
                 Long.valueOf(44));
    assertEquals(me.getBindPoolNumSuccessfulCheckoutsNewConnection(),
                 Long.valueOf(45));
    assertEquals(me.getBindPoolNumFailedCheckouts(), Long.valueOf(46));
    assertEquals(me.getBindPoolNumReleasedValid(), Long.valueOf(47));

    assertEquals(me.getNonBindPoolAvailableConnections(), Long.valueOf(48));
    assertEquals(me.getNonBindPoolMaxAvailableConnections(), Long.valueOf(49));
    assertEquals(me.getNonBindPoolNumSuccessfulConnectionAttempts(),
                 Long.valueOf(50));
    assertEquals(me.getNonBindPoolNumFailedConnectionAttempts(),
                 Long.valueOf(51));
    assertEquals(me.getNonBindPoolNumClosedDefunct(), Long.valueOf(52));
    assertEquals(me.getNonBindPoolNumClosedExpired(), Long.valueOf(53));
    assertEquals(me.getNonBindPoolNumClosedUnneeded(), Long.valueOf(54));
    assertEquals(me.getNonBindPoolTotalSuccessfulCheckouts(), Long.valueOf(55));
    assertEquals(me.getNonBindPoolNumSuccessfulCheckoutsWithoutWaiting(),
                 Long.valueOf(56));
    assertEquals(me.getNonBindPoolNumSuccessfulCheckoutsAfterWaiting(),
                 Long.valueOf(57));
    assertEquals(me.getNonBindPoolNumSuccessfulCheckoutsNewConnection(),
                 Long.valueOf(58));
    assertEquals(me.getNonBindPoolNumFailedCheckouts(), Long.valueOf(59));
    assertEquals(me.getNonBindPoolNumReleasedValid(), Long.valueOf(60));

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("server-address"));
    assertEquals(attrs.get("server-address").getStringValue(),
                 "test.example.com");

    assertNotNull(attrs.get("server-port"));
    assertEquals(attrs.get("server-port").getLongValue(), Long.valueOf(389));

    assertNotNull(attrs.get("communication-security"));
    assertEquals(attrs.get("communication-security").getStringValue(),
                 "none");

    assertNotNull(attrs.get("load-balancing-algorithm"));
    assertEquals(new DN(attrs.get("load-balancing-algorithm").getStringValue()),
                 new DN("cn=test-lba,cn=Load-Balancing Algorithms,cn=config"));

    assertNotNull(attrs.get("health-check-state"));
    assertEquals(attrs.get("health-check-state").getStringValue(), "available");

    assertNotNull(attrs.get("health-check-score"));
    assertEquals(attrs.get("health-check-score").getLongValue(),
                 Long.valueOf(10));

    assertNotNull(attrs.get("health-check-message"));
    assertEquals(attrs.get("health-check-message").getStringValue(),
                 "Everything is A-OK");

    assertNotNull(attrs.get("health-check-update-time"));

    assertNotNull(attrs.get("add-attempts"));
    assertEquals(attrs.get("add-attempts").getLongValue(),
                 Long.valueOf(1));

    assertNotNull(attrs.get("add-failures"));
    assertEquals(attrs.get("add-failures").getLongValue(),
                 Long.valueOf(2));

    assertNotNull(attrs.get("add-successes"));
    assertEquals(attrs.get("add-successes").getLongValue(),
                 Long.valueOf(3));

    assertNotNull(attrs.get("bind-attempts"));
    assertEquals(attrs.get("bind-attempts").getLongValue(),
                 Long.valueOf(4));

    assertNotNull(attrs.get("bind-failures"));
    assertEquals(attrs.get("bind-failures").getLongValue(),
                 Long.valueOf(5));

    assertNotNull(attrs.get("bind-successes"));
    assertEquals(attrs.get("bind-successes").getLongValue(),
                 Long.valueOf(6));

    assertNotNull(attrs.get("compare-attempts"));
    assertEquals(attrs.get("compare-attempts").getLongValue(),
                 Long.valueOf(7));

    assertNotNull(attrs.get("compare-failures"));
    assertEquals(attrs.get("compare-failures").getLongValue(),
                 Long.valueOf(8));

    assertNotNull(attrs.get("compare-successes"));
    assertEquals(attrs.get("compare-successes").getLongValue(),
                 Long.valueOf(9));

    assertNotNull(attrs.get("delete-attempts"));
    assertEquals(attrs.get("delete-attempts").getLongValue(),
                 Long.valueOf(10));

    assertNotNull(attrs.get("delete-failures"));
    assertEquals(attrs.get("delete-failures").getLongValue(),
                 Long.valueOf(11));

    assertNotNull(attrs.get("delete-successes"));
    assertEquals(attrs.get("delete-successes").getLongValue(),
                 Long.valueOf(12));

    assertNotNull(attrs.get("modify-attempts"));
    assertEquals(attrs.get("modify-attempts").getLongValue(),
                 Long.valueOf(13));

    assertNotNull(attrs.get("modify-failures"));
    assertEquals(attrs.get("modify-failures").getLongValue(),
                 Long.valueOf(14));

    assertNotNull(attrs.get("modify-successes"));
    assertEquals(attrs.get("modify-successes").getLongValue(),
                 Long.valueOf(15));

    assertNotNull(attrs.get("modify-dn-attempts"));
    assertEquals(attrs.get("modify-dn-attempts").getLongValue(),
                 Long.valueOf(16));

    assertNotNull(attrs.get("modify-dn-failures"));
    assertEquals(attrs.get("modify-dn-failures").getLongValue(),
                 Long.valueOf(17));

    assertNotNull(attrs.get("modify-dn-successes"));
    assertEquals(attrs.get("modify-dn-successes").getLongValue(),
                 Long.valueOf(18));

    assertNotNull(attrs.get("search-attempts"));
    assertEquals(attrs.get("search-attempts").getLongValue(),
                 Long.valueOf(19));

    assertNotNull(attrs.get("search-failures"));
    assertEquals(attrs.get("search-failures").getLongValue(),
                 Long.valueOf(20));

    assertNotNull(attrs.get("search-successes"));
    assertEquals(attrs.get("search-successes").getLongValue(),
                 Long.valueOf(21));
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
         "dn: cn=LDAP external server test:389 for test-lba,cn=monitor," +
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-ldap-external-server-monitor-entry",
         "objectClass: extensibleObject",
         "cn: cn=LDAP external server test:389 for test-lba");

    LDAPExternalServerMonitorEntry me = new LDAPExternalServerMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-ldap-external-server-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 LDAPExternalServerMonitorEntry.class.getName());

    assertNull(me.getServerAddress());
    assertNull(me.getServerPort());
    assertNull(me.getCommunicationSecurity());

    assertNull(me.getLoadBalancingAlgorithmDN());

    assertNull(me.getHealthCheckState());
    assertNull(me.getHealthCheckScore());
    assertNull(me.getHealthCheckUpdateTime());

    assertNotNull(me.getHealthCheckMessages());
    assertTrue(me.getHealthCheckMessages().isEmpty());

    assertNull(me.getAddAttempts());
    assertNull(me.getAddFailures());
    assertNull(me.getAddSuccesses());

    assertNull(me.getBindAttempts());
    assertNull(me.getBindFailures());
    assertNull(me.getBindSuccesses());

    assertNull(me.getCompareAttempts());
    assertNull(me.getCompareFailures());
    assertNull(me.getCompareSuccesses());

    assertNull(me.getDeleteAttempts());
    assertNull(me.getDeleteFailures());
    assertNull(me.getDeleteSuccesses());

    assertNull(me.getModifyAttempts());
    assertNull(me.getModifyFailures());
    assertNull(me.getModifySuccesses());

    assertNull(me.getModifyDNAttempts());
    assertNull(me.getModifyDNFailures());
    assertNull(me.getModifyDNSuccesses());

    assertNull(me.getSearchAttempts());
    assertNull(me.getSearchFailures());
    assertNull(me.getSearchSuccesses());

    assertNull(me.getCommonPoolAvailableConnections());
    assertNull(me.getCommonPoolMaxAvailableConnections());
    assertNull(me.getCommonPoolNumSuccessfulConnectionAttempts());
    assertNull(me.getCommonPoolNumFailedConnectionAttempts());
    assertNull(me.getCommonPoolNumClosedDefunct());
    assertNull(me.getCommonPoolNumClosedExpired());
    assertNull(me.getCommonPoolNumClosedUnneeded());
    assertNull(me.getCommonPoolTotalSuccessfulCheckouts());
    assertNull(me.getCommonPoolNumSuccessfulCheckoutsWithoutWaiting());
    assertNull(me.getCommonPoolNumSuccessfulCheckoutsAfterWaiting());
    assertNull(me.getCommonPoolNumSuccessfulCheckoutsNewConnection());
    assertNull(me.getCommonPoolNumFailedCheckouts());
    assertNull(me.getCommonPoolNumReleasedValid());

    assertNull(me.getBindPoolAvailableConnections());
    assertNull(me.getBindPoolMaxAvailableConnections());
    assertNull(me.getBindPoolNumSuccessfulConnectionAttempts());
    assertNull(me.getBindPoolNumFailedConnectionAttempts());
    assertNull(me.getBindPoolNumClosedDefunct());
    assertNull(me.getBindPoolNumClosedExpired());
    assertNull(me.getBindPoolNumClosedUnneeded());
    assertNull(me.getBindPoolTotalSuccessfulCheckouts());
    assertNull(me.getBindPoolNumSuccessfulCheckoutsWithoutWaiting());
    assertNull(me.getBindPoolNumSuccessfulCheckoutsAfterWaiting());
    assertNull(me.getBindPoolNumSuccessfulCheckoutsNewConnection());
    assertNull(me.getBindPoolNumFailedCheckouts());
    assertNull(me.getBindPoolNumReleasedValid());

    assertNull(me.getNonBindPoolAvailableConnections());
    assertNull(me.getNonBindPoolMaxAvailableConnections());
    assertNull(me.getNonBindPoolNumSuccessfulConnectionAttempts());
    assertNull(me.getNonBindPoolNumFailedConnectionAttempts());
    assertNull(me.getNonBindPoolNumClosedDefunct());
    assertNull(me.getNonBindPoolNumClosedExpired());
    assertNull(me.getNonBindPoolNumClosedUnneeded());
    assertNull(me.getNonBindPoolTotalSuccessfulCheckouts());
    assertNull(me.getNonBindPoolNumSuccessfulCheckoutsWithoutWaiting());
    assertNull(me.getNonBindPoolNumSuccessfulCheckoutsAfterWaiting());
    assertNull(me.getNonBindPoolNumSuccessfulCheckoutsNewConnection());
    assertNull(me.getNonBindPoolNumFailedCheckouts());
    assertNull(me.getNonBindPoolNumReleasedValid());

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertTrue(me.getMonitorAttributes().isEmpty());
  }
}
