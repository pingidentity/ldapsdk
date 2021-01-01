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



import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the extended operation result
 * code info object.
 */
public final class ExtendedOperationResultCodeInfoTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with a monitor entry with all of the attributes relevant
   * to extended operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllAttributes()
         throws Exception
  {
    final MonitorEntry e = new MonitorEntry(new Entry(
         "dn: cn=LDAP Result Codes,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-ldap-result-codes-monitor-entry",
         "objectClass: extensibleObject",
         "cn: LDAP Result Codes",
         "extended-op-total-count: 75",
         "extended-op-failed-count: 7",
         "extended-op-failed-percent: 9.333",
         "extended-op-1-3-6-1-1-8-name: Cancel",
         "extended-op-1-3-6-1-1-8-total-count: 2",
         "extended-op-1-3-6-1-1-8-failed-count: 2",
         "extended-op-1-3-6-1-1-8-failed-percent: 100.000",
         "extended-op-1-3-6-1-1-8-result-119-name: No Such Operation",
         "extended-op-1-3-6-1-1-8-result-119-count: 2",
         "extended-op-1-3-6-1-1-8-result-119-percent: 100.000",
         "extended-op-1-3-6-1-1-8-result-119-average-response-time-millis: " +
              "11.793",
         "extended-op-1-3-6-1-1-8-result-119-total-response-time-millis: " +
              "23.586",
         "extended-op-1-3-6-1-4-1-1466-20037-name: StartTLS",
         "extended-op-1-3-6-1-4-1-1466-20037-total-count: 19",
         "extended-op-1-3-6-1-4-1-1466-20037-failed-count: 0",
         "extended-op-1-3-6-1-4-1-1466-20037-failed-percent: 0.000",
         "extended-op-1-3-6-1-4-1-1466-20037-result-0-name: Success",
         "extended-op-1-3-6-1-4-1-1466-20037-result-0-count: 19",
         "extended-op-1-3-6-1-4-1-1466-20037-result-0-percent: 100.000",
         "extended-op-1-3-6-1-4-1-1466-20037-result-0-average-response-time-" +
              "millis: 2.868",
         "extended-op-1-3-6-1-4-1-1466-20037-result-0-total-response-time-" +
              "millis: 54.502"));

    final ExtendedOperationResultCodeInfo rcInfo =
         new ExtendedOperationResultCodeInfo(e);

    assertNotNull(rcInfo.getTotalCount());
    assertEquals(rcInfo.getTotalCount().longValue(), 75L);

    assertNotNull(rcInfo.getTotalCountsByOID());
    assertEquals(rcInfo.getTotalCountsByOID().size(), 2);
    assertEquals(rcInfo.getTotalCountsByOID().get("1.3.6.1.1.8").longValue(),
         2L);

    assertNotNull(rcInfo.getFailedCount());
    assertEquals(rcInfo.getFailedCount().longValue(), 7L);

    assertNotNull(rcInfo.getFailedCountsByOID());
    assertEquals(rcInfo.getFailedCountsByOID().size(), 2);
    assertEquals(rcInfo.getFailedCountsByOID().get(
              "1.3.6.1.4.1.1466.20037").longValue(),
         0L);

    assertNotNull(rcInfo.getFailedPercent());
    assertEquals(rcInfo.getFailedPercent(), Double.valueOf("9.333"));

    assertNotNull(rcInfo.getFailedPercentsByOID());
    assertEquals(rcInfo.getFailedPercentsByOID().size(), 2);
    assertEquals(
         rcInfo.getFailedPercentsByOID().get("1.3.6.1.1.8").doubleValue(),
         Double.parseDouble("100.000"));

    assertNotNull(rcInfo.getResultCodeInfoMap());
    assertFalse(rcInfo.getResultCodeInfoMap().isEmpty());
    assertEquals(rcInfo.getResultCodeInfoMap().size(), 2);

    final Map<Integer,ResultCodeInfo> cancelMap =
         rcInfo.getResultCodeInfoMap().get("1.3.6.1.1.8");
    assertNotNull(cancelMap);
    assertFalse(cancelMap.isEmpty());
    assertTrue(cancelMap.containsKey(119));
    assertEquals(cancelMap.get(119).getName(), "No Such Operation");
    assertEquals(cancelMap.get(119).getCount(), 2L);
    assertEquals(cancelMap.get(119).getPercent(), 100.0d);
    assertEquals(cancelMap.get(119).getAverageResponseTimeMillis(),
         Double.parseDouble("11.793"));
    assertEquals(cancelMap.get(119).getTotalResponseTimeMillis(),
         Double.parseDouble("23.586"));

    assertNotNull(rcInfo.getExtendedRequestNamesByOID());
    assertEquals(rcInfo.getExtendedRequestNamesByOID().size(), 2);
    assertEquals(rcInfo.getExtendedRequestNamesByOID().get("1.3.6.1.1.8"),
         "Cancel");
  }



  /**
   * Tests the behavior with a monitor entry with no attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoAttributes()
         throws Exception
  {
    final MonitorEntry e = new MonitorEntry(new Entry(
         "dn: cn=LDAP Result Codes,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-ldap-result-codes-monitor-entry",
         "objectClass: extensibleObject",
         "cn: LDAP Result Codes"));

    final ExtendedOperationResultCodeInfo rcInfo =
         new ExtendedOperationResultCodeInfo(e);

    assertNull(rcInfo.getTotalCount());

    assertNotNull(rcInfo.getTotalCountsByOID());
    assertTrue(rcInfo.getTotalCountsByOID().isEmpty());

    assertNull(rcInfo.getFailedCount());

    assertNotNull(rcInfo.getFailedCountsByOID());
    assertTrue(rcInfo.getFailedCountsByOID().isEmpty());

    assertNull(rcInfo.getFailedPercent());

    assertNotNull(rcInfo.getFailedPercentsByOID());
    assertTrue(rcInfo.getFailedPercentsByOID().isEmpty());

    assertNotNull(rcInfo.getResultCodeInfoMap());
    assertTrue(rcInfo.getResultCodeInfoMap().isEmpty());
  }



  /**
   * Tests the behavior with a monitor entry with a malformed value for the
   * extended operation count that will cause an exception to be thrown.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBadExtOpCountValue()
         throws Exception
  {
    final MonitorEntry e = new MonitorEntry(new Entry(
         "dn: cn=LDAP Result Codes,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-ldap-result-codes-monitor-entry",
         "objectClass: extensibleObject",
         "cn: LDAP Result Codes",
         "extended-op-total-count: 75",
         "extended-op-failed-count: 7",
         "extended-op-failed-percent: 9.333",
         "extended-op-1-3-6-1-1-8-name: Cancel",
         "extended-op-1-3-6-1-1-8-total-count: malformed",
         "extended-op-1-3-6-1-1-8-failed-count: 2",
         "extended-op-1-3-6-1-1-8-failed-percent: 100.000",
         "extended-op-1-3-6-1-1-8-result-119-name: No Such Operation",
         "extended-op-1-3-6-1-1-8-result-119-count: 2",
         "extended-op-1-3-6-1-1-8-result-119-percent: 100.000",
         "extended-op-1-3-6-1-1-8-result-119-average-response-time-millis: " +
              "11.793",
         "extended-op-1-3-6-1-1-8-result-119-total-response-time-millis: " +
              "23.586",
         "extended-op-1-3-6-1-4-1-1466-20037-name: StartTLS",
         "extended-op-1-3-6-1-4-1-1466-20037-total-count: malformed",
         "extended-op-1-3-6-1-4-1-1466-20037-failed-count: 0",
         "extended-op-1-3-6-1-4-1-1466-20037-failed-percent: 0.000",
         "extended-op-1-3-6-1-4-1-1466-20037-result-0-name: Success",
         "extended-op-1-3-6-1-4-1-1466-20037-result-0-count: 19",
         "extended-op-1-3-6-1-4-1-1466-20037-result-0-percent: 100.000",
         "extended-op-1-3-6-1-4-1-1466-20037-result-0-average-response-time-" +
              "millis: 2.868",
         "extended-op-1-3-6-1-4-1-1466-20037-result-0-total-response-time-" +
              "millis: 54.502"));

    final ExtendedOperationResultCodeInfo rcInfo =
         new ExtendedOperationResultCodeInfo(e);

    assertNotNull(rcInfo.getTotalCount());
    assertEquals(rcInfo.getTotalCount().longValue(), 75L);

    assertNotNull(rcInfo.getTotalCountsByOID());
    assertEquals(rcInfo.getTotalCountsByOID().size(), 0);

    assertNotNull(rcInfo.getFailedCount());
    assertEquals(rcInfo.getFailedCount().longValue(), 7L);

    assertNotNull(rcInfo.getFailedCountsByOID());
    assertEquals(rcInfo.getFailedCountsByOID().size(), 0);

    assertNotNull(rcInfo.getFailedPercent());
    assertEquals(rcInfo.getFailedPercent(), Double.valueOf("9.333"));

    assertNotNull(rcInfo.getFailedPercentsByOID());
    assertEquals(rcInfo.getFailedPercentsByOID().size(), 0);

    assertNotNull(rcInfo.getResultCodeInfoMap());
    assertTrue(rcInfo.getResultCodeInfoMap().isEmpty());
  }



  /**
   * Tests the behavior with a monitor entry with all of the attributes relevant
   * to extended operations except one needed to create a result code info
   * object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMissingRCInfoField()
         throws Exception
  {
    final MonitorEntry e = new MonitorEntry(new Entry(
         "dn: cn=LDAP Result Codes,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-ldap-result-codes-monitor-entry",
         "objectClass: extensibleObject",
         "cn: LDAP Result Codes",
         "extended-op-total-count: 75",
         "extended-op-failed-count: 7",
         "extended-op-failed-percent: 9.333",
         "extended-op-1-3-6-1-1-8-name: Cancel",
         "extended-op-1-3-6-1-1-8-total-count: 2",
         "extended-op-1-3-6-1-1-8-failed-count: 2",
         "extended-op-1-3-6-1-1-8-failed-percent: 100.000",
         "extended-op-1-3-6-1-1-8-result-119-name: No Such Operation",
         "extended-op-1-3-6-1-1-8-result-119-percent: 100.000",
         "extended-op-1-3-6-1-1-8-result-119-average-response-time-millis: " +
              "11.793",
         "extended-op-1-3-6-1-1-8-result-119-total-response-time-millis: " +
              "23.586",
         "extended-op-1-3-6-1-4-1-1466-20037-name: StartTLS",
         "extended-op-1-3-6-1-4-1-1466-20037-total-count: 19",
         "extended-op-1-3-6-1-4-1-1466-20037-failed-count: 0",
         "extended-op-1-3-6-1-4-1-1466-20037-failed-percent: 0.000",
         "extended-op-1-3-6-1-4-1-1466-20037-result-0-name: Success",
         "extended-op-1-3-6-1-4-1-1466-20037-result-0-percent: 100.000",
         "extended-op-1-3-6-1-4-1-1466-20037-result-0-average-response-time-" +
              "millis: 2.868",
         "extended-op-1-3-6-1-4-1-1466-20037-result-0-total-response-time-" +
              "millis: 54.502"));

    final ExtendedOperationResultCodeInfo rcInfo =
         new ExtendedOperationResultCodeInfo(e);

    assertNotNull(rcInfo.getTotalCount());
    assertEquals(rcInfo.getTotalCount().longValue(), 75L);

    assertNotNull(rcInfo.getTotalCountsByOID());
    assertEquals(rcInfo.getTotalCountsByOID().size(), 2);
    assertEquals(rcInfo.getTotalCountsByOID().get("1.3.6.1.1.8").longValue(),
         2L);

    assertNotNull(rcInfo.getFailedCount());
    assertEquals(rcInfo.getFailedCount().longValue(), 7L);

    assertNotNull(rcInfo.getFailedCountsByOID());
    assertEquals(rcInfo.getFailedCountsByOID().size(), 2);
    assertEquals(rcInfo.getFailedCountsByOID().get(
              "1.3.6.1.4.1.1466.20037").longValue(),
         0L);

    assertNotNull(rcInfo.getFailedPercent());
    assertEquals(rcInfo.getFailedPercent(), Double.valueOf("9.333"));

    assertNotNull(rcInfo.getFailedPercentsByOID());
    assertEquals(rcInfo.getFailedPercentsByOID().size(), 2);
    assertEquals(
         rcInfo.getFailedPercentsByOID().get("1.3.6.1.1.8").doubleValue(),
         Double.parseDouble("100.000"));

    assertNotNull(rcInfo.getResultCodeInfoMap());
    assertFalse(rcInfo.getResultCodeInfoMap().isEmpty());
    for (final Map<Integer,ResultCodeInfo> m :
         rcInfo.getResultCodeInfoMap().values())
    {
      assertTrue(m.isEmpty());
    }
  }
}
