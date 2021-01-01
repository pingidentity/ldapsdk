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



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.OperationType;



/**
 * This class provides a set of test cases for the operation result code info
 * object.
 */
public final class OperationResultCodeInfoTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with no operation type and a monitor entry with all of
   * the attributes relevant to all operation types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullOperationTypeAllAttributes()
         throws Exception
  {
    final MonitorEntry e = new MonitorEntry(new Entry(
         "dn: cn=LDAP Result Codes,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-ldap-result-codes-monitor-entry",
         "objectClass: extensibleObject",
         "cn: LDAP Result Codes",
         "all-ops-total-count: 1234",
         "all-ops-failed-count: 567",
         "all-ops-failed-percent: 45.948",
         "all-ops-result-0-name: Success",
         "all-ops-result-0-count: 667",
         "all-ops-result-0-percent: 54.052",
         "all-ops-result-0-average-response-time-millis: 12.345",
         "all-ops-result-0-total-response-time-millis: 8234.115",
         "all-ops-result-32-name: No Such Object",
         "all-ops-result-32-count: 123",
         "all-ops-result-32-percent: 9.968",
         "all-ops-result-32-average-response-time-millis: 2.345",
         "all-ops-result-32-total-response-time-millis: 288.435",
         "all-ops-result-80-name: Other",
         "all-ops-result-80-count: 544",
         "all-ops-result-80-percent: 44.084",
         "all-ops-result-80-average-response-time-millis: 5.678",
         "all-ops-result-80-total-response-time-millis: 3088.832"));

    final OperationResultCodeInfo rcInfo =
         new OperationResultCodeInfo(e, null, "all-ops-");

    assertNull(rcInfo.getOperationType());

    assertNotNull(rcInfo.getTotalCount());
    assertEquals(rcInfo.getTotalCount().longValue(), 1234L);

    assertNotNull(rcInfo.getFailedCount());
    assertEquals(rcInfo.getFailedCount().longValue(), 567L);

    assertNotNull(rcInfo.getFailedPercent());
    assertEquals(rcInfo.getFailedPercent(), Double.valueOf("45.948"));

    assertNotNull(rcInfo.getResultCodeInfoMap());
    assertFalse(rcInfo.getResultCodeInfoMap().isEmpty());
    assertEquals(rcInfo.getResultCodeInfoMap().size(), 3);

    final ResultCodeInfo successInfo = rcInfo.getResultCodeInfoMap().get(0);
    assertNotNull(successInfo);
    assertEquals(successInfo.getName(), "Success");
    assertEquals(successInfo.getCount(), 667L);
    assertEquals(successInfo.getPercent(), Double.parseDouble("54.052"));
    assertEquals(successInfo.getAverageResponseTimeMillis(),
         Double.parseDouble("12.345"));
    assertEquals(successInfo.getTotalResponseTimeMillis(),
         Double.parseDouble("8234.115"));
  }



  /**
   * Tests the behavior with no operation type and a monitor entry with no
   * attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullOperationTypeNoAttributes()
         throws Exception
  {
    final MonitorEntry e = new MonitorEntry(new Entry(
         "dn: cn=LDAP Result Codes,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-ldap-result-codes-monitor-entry",
         "objectClass: extensibleObject",
         "cn: LDAP Result Codes"));

    final OperationResultCodeInfo rcInfo =
         new OperationResultCodeInfo(e, null, "all-ops-");

    assertNull(rcInfo.getOperationType());

    assertNull(rcInfo.getTotalCount());

    assertNull(rcInfo.getFailedCount());

    assertNull(rcInfo.getFailedPercent());

    assertNotNull(rcInfo.getResultCodeInfoMap());
    assertTrue(rcInfo.getResultCodeInfoMap().isEmpty());
  }



  /**
   * Tests the behavior with a bind operation type and a monitor entry with all
   * of the attributes relevant to bind operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindOperationTypeAllAttributes()
         throws Exception
  {
    final MonitorEntry e = new MonitorEntry(new Entry(
         "dn: cn=LDAP Result Codes,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-ldap-result-codes-monitor-entry",
         "objectClass: extensibleObject",
         "cn: LDAP Result Codes",
         "bind-op-total-count: 1234",
         "bind-op-failed-count: 567",
         "bind-op-failed-percent: 45.948",
         "bind-op-result-0-name: Success",
         "bind-op-result-0-count: 667",
         "bind-op-result-0-percent: 54.052",
         "bind-op-result-0-average-response-time-millis: 12.345",
         "bind-op-result-0-total-response-time-millis: 8234.115",
         "bind-op-result-32-name: No Such Object",
         "bind-op-result-32-count: 123",
         "bind-op-result-32-percent: 9.968",
         "bind-op-result-32-average-response-time-millis: 2.345",
         "bind-op-result-32-total-response-time-millis: 288.435",
         "bind-op-result-80-name: Other",
         "bind-op-result-80-count: 544",
         "bind-op-result-80-percent: 44.084",
         "bind-op-result-80-average-response-time-millis: 5.678",
         "bind-op-result-80-total-response-time-millis: 3088.832"));

    final OperationResultCodeInfo rcInfo =
         new OperationResultCodeInfo(e, OperationType.BIND, "bind-op-");

    assertNotNull(rcInfo.getOperationType());
    assertEquals(rcInfo.getOperationType(), OperationType.BIND);

    assertNotNull(rcInfo.getTotalCount());
    assertEquals(rcInfo.getTotalCount().longValue(), 1234L);

    assertNotNull(rcInfo.getFailedCount());
    assertEquals(rcInfo.getFailedCount().longValue(), 567L);

    assertNotNull(rcInfo.getFailedPercent());
    assertEquals(rcInfo.getFailedPercent(), Double.valueOf("45.948"));

    assertNotNull(rcInfo.getResultCodeInfoMap());
    assertFalse(rcInfo.getResultCodeInfoMap().isEmpty());
    assertEquals(rcInfo.getResultCodeInfoMap().size(), 3);

    final ResultCodeInfo successInfo = rcInfo.getResultCodeInfoMap().get(0);
    assertNotNull(successInfo);
    assertEquals(successInfo.getName(), "Success");
    assertEquals(successInfo.getCount(), 667L);
    assertEquals(successInfo.getPercent(), Double.parseDouble("54.052"));
    assertEquals(successInfo.getAverageResponseTimeMillis(),
         Double.parseDouble("12.345"));
    assertEquals(successInfo.getTotalResponseTimeMillis(),
         Double.parseDouble("8234.115"));
  }



  /**
   * Tests the behavior with the compare type and a monitor entry with no
   * attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareOperationTypeNoAttributes()
         throws Exception
  {
    final MonitorEntry e = new MonitorEntry(new Entry(
         "dn: cn=LDAP Result Codes,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-ldap-result-codes-monitor-entry",
         "objectClass: extensibleObject",
         "cn: LDAP Result Codes"));

    final OperationResultCodeInfo rcInfo =
         new OperationResultCodeInfo(e, OperationType.COMPARE, "compare-op-");

    assertNotNull(rcInfo.getOperationType());
    assertEquals(rcInfo.getOperationType(), OperationType.COMPARE);

    assertNull(rcInfo.getTotalCount());

    assertNull(rcInfo.getFailedCount());

    assertNull(rcInfo.getFailedPercent());

    assertNotNull(rcInfo.getResultCodeInfoMap());
    assertTrue(rcInfo.getResultCodeInfoMap().isEmpty());
  }



  /**
   * Tests the behavior with a delete operation type and an entry that is
   * missing one of the attributes needed to construct a {@code ResultCodeInfo}
   * object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMissingRCInfoAttribute()
         throws Exception
  {
    final MonitorEntry e = new MonitorEntry(new Entry(
         "dn: cn=LDAP Result Codes,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-ldap-result-codes-monitor-entry",
         "objectClass: extensibleObject",
         "cn: LDAP Result Codes",
         "delete-op-total-count: 1234",
         "delete-op-failed-count: 567",
         "delete-op-failed-percent: 45.948",
         "delete-op-result-0-name: Success",
         "delete-op-result-0-percent: 54.052",
         "delete-op-result-0-average-response-time-millis: 12.345",
         "delete-op-result-0-total-response-time-millis: 8234.115",
         "delete-op-result-32-name: No Such Object",
         "delete-op-result-32-percent: 9.968",
         "delete-op-result-32-average-response-time-millis: 2.345",
         "delete-op-result-32-total-response-time-millis: 288.435",
         "delete-op-result-80-name: Other",
         "delete-op-result-80-percent: 44.084",
         "delete-op-result-80-average-response-time-millis: 5.678",
         "delete-op-result-80-total-response-time-millis: 3088.832"));

    final OperationResultCodeInfo rcInfo =
         new OperationResultCodeInfo(e, OperationType.DELETE, "delete-op-");

    assertNotNull(rcInfo.getOperationType());
    assertEquals(rcInfo.getOperationType(), OperationType.DELETE);

    assertNotNull(rcInfo.getTotalCount());
    assertEquals(rcInfo.getTotalCount().longValue(), 1234L);

    assertNotNull(rcInfo.getFailedCount());
    assertEquals(rcInfo.getFailedCount().longValue(), 567L);

    assertNotNull(rcInfo.getFailedPercent());
    assertEquals(rcInfo.getFailedPercent(), Double.valueOf("45.948"));

    assertNotNull(rcInfo.getResultCodeInfoMap());
    assertTrue(rcInfo.getResultCodeInfoMap().isEmpty());
  }
}
