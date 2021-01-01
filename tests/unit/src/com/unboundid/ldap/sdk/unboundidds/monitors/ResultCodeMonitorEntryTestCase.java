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
 * This class provides a set of test cases for the result code monitor entry
 * class.
 */
public final class ResultCodeMonitorEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for an entry with all relevant attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllAttributes()
         throws Exception
  {
    final Entry e = new Entry(
         "dn: cn=LDAP Result Codes,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-ldap-result-codes-monitor-entry",
         "objectClass: extensibleObject",
         "cn: LDAP Result Codes",
         "all-ops-total-count: 603376",
         "all-ops-failed-count: 215131",
         "all-ops-failed-percent: 35.655",
         "all-ops-result-0-name: Success",
         "all-ops-result-0-count: 369442",
         "all-ops-result-0-percent: 61.229",
         "all-ops-result-0-average-response-time-millis: 0.526",
         "all-ops-result-0-total-response-time-millis: 194575.102",
         "all-ops-result-4-name: Size Limit Exceeded",
         "all-ops-result-4-count: 2",
         "all-ops-result-4-percent: 0.000",
         "all-ops-result-4-average-response-time-millis: 0.668",
         "all-ops-result-4-total-response-time-millis: 1.336",
         "all-ops-result-5-name: Compare False",
         "all-ops-result-5-count: 9",
         "all-ops-result-5-percent: 0.001",
         "all-ops-result-5-average-response-time-millis: 0.273",
         "all-ops-result-5-total-response-time-millis: 2.463",
         "all-ops-result-6-name: Compare True",
         "all-ops-result-6-count: 37",
         "all-ops-result-6-percent: 0.006",
         "all-ops-result-6-average-response-time-millis: 0.394",
         "all-ops-result-6-total-response-time-millis: 14.579",
         "all-ops-result-10-name: Referral",
         "all-ops-result-10-count: 91",
         "all-ops-result-10-percent: 0.015",
         "all-ops-result-10-average-response-time-millis: 0.735",
         "all-ops-result-10-total-response-time-millis: 66.953",
         "all-ops-result-14-name: SASL Bind in Progress",
         "all-ops-result-14-count: 18664",
         "all-ops-result-14-percent: 3.093",
         "all-ops-result-14-average-response-time-millis: 0.047",
         "all-ops-result-14-total-response-time-millis: 884.570",
         "all-ops-result-32-name: No Such Entry",
         "all-ops-result-32-count: 150332",
         "all-ops-result-32-percent: 24.915",
         "all-ops-result-32-average-response-time-millis: 0.245",
         "all-ops-result-32-total-response-time-millis: 36900.186",
         "all-ops-result-34-name: Invalid DN Syntax",
         "all-ops-result-34-count: 44349",
         "all-ops-result-34-percent: 7.350",
         "all-ops-result-34-average-response-time-millis: 0.026",
         "all-ops-result-34-total-response-time-millis: 1158.114",
         "all-ops-result-49-name: Invalid Credentials",
         "all-ops-result-49-count: 18696",
         "all-ops-result-49-percent: 3.099",
         "all-ops-result-49-average-response-time-millis: 0.179",
         "all-ops-result-49-total-response-time-millis: 3354.933",
         "all-ops-result-50-name: Insufficient Access Rights",
         "all-ops-result-50-count: 3",
         "all-ops-result-50-percent: 0.000",
         "all-ops-result-50-average-response-time-millis: 0.351",
         "all-ops-result-50-total-response-time-millis: 1.053",
         "all-ops-result-53-name: Unwilling to Perform",
         "all-ops-result-53-count: 3",
         "all-ops-result-53-percent: 0.000",
         "all-ops-result-53-average-response-time-millis: 0.341",
         "all-ops-result-53-total-response-time-millis: 1.025",
         "all-ops-result-65-name: Object Class Violation",
         "all-ops-result-65-count: 11",
         "all-ops-result-65-percent: 0.002",
         "all-ops-result-65-average-response-time-millis: 0.458",
         "all-ops-result-65-total-response-time-millis: 5.039",
         "all-ops-result-66-name: Not Allowed on Non-Leaf",
         "all-ops-result-66-count: 1",
         "all-ops-result-66-percent: 0.000",
         "all-ops-result-66-average-response-time-millis: 0.924",
         "all-ops-result-66-total-response-time-millis: 0.924",
         "all-ops-result-80-name: Other",
         "all-ops-result-80-count: 5",
         "all-ops-result-80-percent: 0.001",
         "all-ops-result-80-average-response-time-millis: 5402.056",
         "all-ops-result-80-total-response-time-millis: 27010.283",
         "all-ops-result-119-name: No Such Operation",
         "all-ops-result-119-count: 2",
         "all-ops-result-119-percent: 0.000",
         "all-ops-result-119-average-response-time-millis: 11.793",
         "all-ops-result-119-total-response-time-millis: 23.586",
         "all-ops-result-122-name: Assertion Failed",
         "all-ops-result-122-count: 1",
         "all-ops-result-122-percent: 0.000",
         "all-ops-result-122-average-response-time-millis: 1.799",
         "all-ops-result-122-total-response-time-millis: 1.799",
         "all-ops-result-123-name: Authorization Denied",
         "all-ops-result-123-count: 1726",
         "all-ops-result-123-percent: 0.286",
         "all-ops-result-123-average-response-time-millis: 17.574",
         "all-ops-result-123-total-response-time-millis: 30333.887",
         "all-ops-result-16654-name: No Operation",
         "all-ops-result-16654-count: 2",
         "all-ops-result-16654-percent: 0.000",
         "all-ops-result-16654-average-response-time-millis: 0.593",
         "all-ops-result-16654-total-response-time-millis: 1.187",
         "add-op-total-count: 636",
         "add-op-failed-count: 8",
         "add-op-failed-percent: 1.258",
         "add-op-result-0-name: Success",
         "add-op-result-0-count: 614",
         "add-op-result-0-percent: 96.541",
         "add-op-result-0-average-response-time-millis: 4.811",
         "add-op-result-0-total-response-time-millis: 2954.025",
         "add-op-result-10-name: Referral",
         "add-op-result-10-count: 12",
         "add-op-result-10-percent: 1.887",
         "add-op-result-10-average-response-time-millis: 0.662",
         "add-op-result-10-total-response-time-millis: 7.944",
         "add-op-result-32-name: No Such Entry",
         "add-op-result-32-count: 2",
         "add-op-result-32-percent: 0.314",
         "add-op-result-32-average-response-time-millis: 0.395",
         "add-op-result-32-total-response-time-millis: 0.790",
         "add-op-result-65-name: Object Class Violation",
         "add-op-result-65-count: 6",
         "add-op-result-65-percent: 0.943",
         "add-op-result-65-average-response-time-millis: 0.428",
         "add-op-result-65-total-response-time-millis: 2.572",
         "add-op-result-16654-name: No Operation",
         "add-op-result-16654-count: 2",
         "add-op-result-16654-percent: 0.314",
         "add-op-result-16654-average-response-time-millis: 0.593",
         "add-op-result-16654-total-response-time-millis: 1.187",
         "bind-op-total-count: 92421",
         "bind-op-failed-count: 18697",
         "bind-op-failed-percent: 20.230",
         "bind-op-result-0-name: Success",
         "bind-op-result-0-count: 55060",
         "bind-op-result-0-percent: 59.575",
         "bind-op-result-0-average-response-time-millis: 0.253",
         "bind-op-result-0-total-response-time-millis: 13978.787",
         "bind-op-result-14-name: SASL Bind in Progress",
         "bind-op-result-14-count: 18664",
         "bind-op-result-14-percent: 20.195",
         "bind-op-result-14-average-response-time-millis: 0.047",
         "bind-op-result-14-total-response-time-millis: 884.570",
         "bind-op-result-49-name: Invalid Credentials",
         "bind-op-result-49-count: 18696",
         "bind-op-result-49-percent: 20.229",
         "bind-op-result-49-average-response-time-millis: 0.179",
         "bind-op-result-49-total-response-time-millis: 3354.933",
         "bind-op-result-53-name: Unwilling to Perform",
         "bind-op-result-53-count: 1",
         "bind-op-result-53-percent: 0.001",
         "bind-op-result-53-average-response-time-millis: 0.447",
         "bind-op-result-53-total-response-time-millis: 0.447",
         "compare-op-total-count: 62",
         "compare-op-failed-count: 7",
         "compare-op-failed-percent: 11.290",
         "compare-op-result-5-name: Compare False",
         "compare-op-result-5-count: 9",
         "compare-op-result-5-percent: 14.516",
         "compare-op-result-5-average-response-time-millis: 0.273",
         "compare-op-result-5-total-response-time-millis: 2.463",
         "compare-op-result-6-name: Compare True",
         "compare-op-result-6-count: 37",
         "compare-op-result-6-percent: 59.677",
         "compare-op-result-6-average-response-time-millis: 0.394",
         "compare-op-result-6-total-response-time-millis: 14.579",
         "compare-op-result-10-name: Referral",
         "compare-op-result-10-count: 9",
         "compare-op-result-10-percent: 14.516",
         "compare-op-result-10-average-response-time-millis: 0.680",
         "compare-op-result-10-total-response-time-millis: 6.127",
         "compare-op-result-32-name: No Such Entry",
         "compare-op-result-32-count: 6",
         "compare-op-result-32-percent: 9.677",
         "compare-op-result-32-average-response-time-millis: 0.263",
         "compare-op-result-32-total-response-time-millis: 1.581",
         "compare-op-result-50-name: Insufficient Access Rights",
         "compare-op-result-50-count: 1",
         "compare-op-result-50-percent: 1.613",
         "compare-op-result-50-average-response-time-millis: 0.486",
         "compare-op-result-50-total-response-time-millis: 0.486",
         "delete-op-total-count: 313",
         "delete-op-failed-count: 11",
         "delete-op-failed-percent: 3.514",
         "delete-op-result-0-name: Success",
         "delete-op-result-0-count: 284",
         "delete-op-result-0-percent: 90.735",
         "delete-op-result-0-average-response-time-millis: 5.733",
         "delete-op-result-0-total-response-time-millis: 1628.376",
         "delete-op-result-10-name: Referral",
         "delete-op-result-10-count: 18",
         "delete-op-result-10-percent: 5.751",
         "delete-op-result-10-average-response-time-millis: 0.796",
         "delete-op-result-10-total-response-time-millis: 14.343",
         "delete-op-result-32-name: No Such Entry",
         "delete-op-result-32-count: 10",
         "delete-op-result-32-percent: 3.195",
         "delete-op-result-32-average-response-time-millis: 0.297",
         "delete-op-result-32-total-response-time-millis: 2.979",
         "delete-op-result-66-name: Not Allowed on Non-Leaf",
         "delete-op-result-66-count: 1",
         "delete-op-result-66-percent: 0.319",
         "delete-op-result-66-average-response-time-millis: 0.924",
         "delete-op-result-66-total-response-time-millis: 0.924",
         "extended-op-total-count: 75",
         "extended-op-failed-count: 7",
         "extended-op-failed-percent: 9.333",
         "extended-op-1-3-6-1-1-21-1-name: Start LDAP Transaction",
         "extended-op-1-3-6-1-1-21-1-total-count: 2",
         "extended-op-1-3-6-1-1-21-1-failed-count: 0",
         "extended-op-1-3-6-1-1-21-1-failed-percent: 0.000",
         "extended-op-1-3-6-1-1-21-1-result-0-name: Success",
         "extended-op-1-3-6-1-1-21-1-result-0-count: 2",
         "extended-op-1-3-6-1-1-21-1-result-0-percent: 100.000",
         "extended-op-1-3-6-1-1-21-1-result-0-average-response-time-millis: " +
              "1.031",
         "extended-op-1-3-6-1-1-21-1-result-0-total-response-time-millis: " +
              "2.062",
         "extended-op-1-3-6-1-1-21-3-name: End LDAP Transaction",
         "extended-op-1-3-6-1-1-21-3-total-count: 2",
         "extended-op-1-3-6-1-1-21-3-failed-count: 0",
         "extended-op-1-3-6-1-1-21-3-failed-percent: 0.000",
         "extended-op-1-3-6-1-1-21-3-result-0-name: Success",
         "extended-op-1-3-6-1-1-21-3-result-0-count: 2",
         "extended-op-1-3-6-1-1-21-3-result-0-percent: 100.000",
         "extended-op-1-3-6-1-1-21-3-result-0-average-response-time-millis: " +
              "3.390",
         "extended-op-1-3-6-1-1-21-3-result-0-total-response-time-millis: " +
              "6.781",
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
              "millis: 54.502",
         "extended-op-1-3-6-1-4-1-30221-1-6-1-name: Password Policy State",
         "extended-op-1-3-6-1-4-1-30221-1-6-1-total-count: 3",
         "extended-op-1-3-6-1-4-1-30221-1-6-1-failed-count: 0",
         "extended-op-1-3-6-1-4-1-30221-1-6-1-failed-percent: 0.000",
         "extended-op-1-3-6-1-4-1-30221-1-6-1-result-0-name: Success",
         "extended-op-1-3-6-1-4-1-30221-1-6-1-result-0-count: 3",
         "extended-op-1-3-6-1-4-1-30221-1-6-1-result-0-percent: 100.000",
         "extended-op-1-3-6-1-4-1-30221-1-6-1-result-0-average-response-time-" +
              "millis: 0.957",
         "extended-op-1-3-6-1-4-1-30221-1-6-1-result-0-total-response-time-" +
              "millis: 2.871",
         "extended-op-1-3-6-1-4-1-30221-1-6-2-name: Get Connection ID",
         "extended-op-1-3-6-1-4-1-30221-1-6-2-total-count: 1",
         "extended-op-1-3-6-1-4-1-30221-1-6-2-failed-count: 0",
         "extended-op-1-3-6-1-4-1-30221-1-6-2-failed-percent: 0.000",
         "extended-op-1-3-6-1-4-1-30221-1-6-2-result-0-name: Success",
         "extended-op-1-3-6-1-4-1-30221-1-6-2-result-0-count: 1",
         "extended-op-1-3-6-1-4-1-30221-1-6-2-result-0-percent: 100.000",
         "extended-op-1-3-6-1-4-1-30221-1-6-2-result-0-average-response-time-" +
              "millis: 2.528",
         "extended-op-1-3-6-1-4-1-30221-1-6-2-result-0-total-response-time-" +
              "millis: 2.528",
         "extended-op-1-3-6-1-4-1-30221-1-6-20-name: Get Subtree " +
              "Accessibility Extended Request",
         "extended-op-1-3-6-1-4-1-30221-1-6-20-total-count: 10",
         "extended-op-1-3-6-1-4-1-30221-1-6-20-failed-count: 1",
         "extended-op-1-3-6-1-4-1-30221-1-6-20-failed-percent: 10.000",
         "extended-op-1-3-6-1-4-1-30221-1-6-20-result-0-name: Success",
         "extended-op-1-3-6-1-4-1-30221-1-6-20-result-0-count: 9",
         "extended-op-1-3-6-1-4-1-30221-1-6-20-result-0-percent: 90.000",
         "extended-op-1-3-6-1-4-1-30221-1-6-20-result-0-average-response-" +
              "time-millis: 4.094",
         "extended-op-1-3-6-1-4-1-30221-1-6-20-result-0-total-response-time-" +
              "millis: 36.854",
         "extended-op-1-3-6-1-4-1-30221-1-6-20-result-50-name: Insufficient " +
              "Access Rights",
         "extended-op-1-3-6-1-4-1-30221-1-6-20-result-50-count: 1",
         "extended-op-1-3-6-1-4-1-30221-1-6-20-result-50-percent: 10.000",
         "extended-op-1-3-6-1-4-1-30221-1-6-20-result-50-average-response-" +
              "time-millis: 0.418",
         "extended-op-1-3-6-1-4-1-30221-1-6-20-result-50-total-response-" +
              "time-millis: 0.418",
         "extended-op-1-3-6-1-4-1-30221-2-6-1-name: Start Batched Transaction",
         "extended-op-1-3-6-1-4-1-30221-2-6-1-total-count: 2",
         "extended-op-1-3-6-1-4-1-30221-2-6-1-failed-count: 0",
         "extended-op-1-3-6-1-4-1-30221-2-6-1-failed-percent: 0.000",
         "extended-op-1-3-6-1-4-1-30221-2-6-1-result-0-name: Success",
         "extended-op-1-3-6-1-4-1-30221-2-6-1-result-0-count: 2",
         "extended-op-1-3-6-1-4-1-30221-2-6-1-result-0-percent: 100.000",
         "extended-op-1-3-6-1-4-1-30221-2-6-1-result-0-average-response-time-" +
              "millis: 0.060",
         "extended-op-1-3-6-1-4-1-30221-2-6-1-result-0-total-response-time-" +
              "millis: 0.121",
         "extended-op-1-3-6-1-4-1-30221-2-6-10-name: Get Changelog Batch",
         "extended-op-1-3-6-1-4-1-30221-2-6-10-total-count: 2",
         "extended-op-1-3-6-1-4-1-30221-2-6-10-failed-count: 2",
         "extended-op-1-3-6-1-4-1-30221-2-6-10-failed-percent: 100.000",
         "extended-op-1-3-6-1-4-1-30221-2-6-10-result-80-name: Other",
         "extended-op-1-3-6-1-4-1-30221-2-6-10-result-80-count: 2",
         "extended-op-1-3-6-1-4-1-30221-2-6-10-result-80-percent: 100.000",
         "extended-op-1-3-6-1-4-1-30221-2-6-10-result-80-average-response-" +
              "time-millis: 4.094",
         "extended-op-1-3-6-1-4-1-30221-2-6-10-result-80-total-response-time-" +
              "millis: 8.189",
         "extended-op-1-3-6-1-4-1-30221-2-6-19-name: Set Subtree " +
              "Accessibility Extended Request",
         "extended-op-1-3-6-1-4-1-30221-2-6-19-total-count: 7",
         "extended-op-1-3-6-1-4-1-30221-2-6-19-failed-count: 2",
         "extended-op-1-3-6-1-4-1-30221-2-6-19-failed-percent: 28.571",
         "extended-op-1-3-6-1-4-1-30221-2-6-19-result-0-name: Success",
         "extended-op-1-3-6-1-4-1-30221-2-6-19-result-0-count: 5",
         "extended-op-1-3-6-1-4-1-30221-2-6-19-result-0-percent: 71.429",
         "extended-op-1-3-6-1-4-1-30221-2-6-19-result-0-average-response-" +
              "time-millis: 6.249",
         "extended-op-1-3-6-1-4-1-30221-2-6-19-result-0-total-response-time-" +
              "millis: 31.246",
         "extended-op-1-3-6-1-4-1-30221-2-6-19-result-50-name: " +
              "Insufficient Access Rights",
         "extended-op-1-3-6-1-4-1-30221-2-6-19-result-50-count: 1",
         "extended-op-1-3-6-1-4-1-30221-2-6-19-result-50-percent: 14.286",
         "extended-op-1-3-6-1-4-1-30221-2-6-19-result-50-average-response-" +
              "time-millis: 0.149",
         "extended-op-1-3-6-1-4-1-30221-2-6-19-result-50-total-response-time-" +
              "millis: 0.149",
         "extended-op-1-3-6-1-4-1-30221-2-6-19-result-53-name: Unwilling to " +
              "Perform",
         "extended-op-1-3-6-1-4-1-30221-2-6-19-result-53-count: 1",
         "extended-op-1-3-6-1-4-1-30221-2-6-19-result-53-percent: 14.286",
         "extended-op-1-3-6-1-4-1-30221-2-6-19-result-53-average-response-" +
              "time-millis: 0.321",
         "extended-op-1-3-6-1-4-1-30221-2-6-19-result-53-total-response-time-" +
              "millis: 0.321",
         "extended-op-1-3-6-1-4-1-30221-2-6-2-name: End Batched Transaction",
         "extended-op-1-3-6-1-4-1-30221-2-6-2-total-count: 2",
         "extended-op-1-3-6-1-4-1-30221-2-6-2-failed-count: 0",
         "extended-op-1-3-6-1-4-1-30221-2-6-2-failed-percent: 0.000",
         "extended-op-1-3-6-1-4-1-30221-2-6-2-result-0-name: Success",
         "extended-op-1-3-6-1-4-1-30221-2-6-2-result-0-count: 2",
         "extended-op-1-3-6-1-4-1-30221-2-6-2-result-0-percent: 100.000",
         "extended-op-1-3-6-1-4-1-30221-2-6-2-result-0-average-response-" +
              "time-millis: 1.658",
         "extended-op-1-3-6-1-4-1-30221-2-6-2-result-0-total-response-time-" +
              "millis: 3.316",
         "extended-op-1-3-6-1-4-1-30221-2-6-6-name: Stream Directory Values",
         "extended-op-1-3-6-1-4-1-30221-2-6-6-total-count: 2",
         "extended-op-1-3-6-1-4-1-30221-2-6-6-failed-count: 0",
         "extended-op-1-3-6-1-4-1-30221-2-6-6-failed-percent: 0.000",
         "extended-op-1-3-6-1-4-1-30221-2-6-6-result-0-name: Success",
         "extended-op-1-3-6-1-4-1-30221-2-6-6-result-0-count: 2",
         "extended-op-1-3-6-1-4-1-30221-2-6-6-result-0-percent: 100.000",
         "extended-op-1-3-6-1-4-1-30221-2-6-6-result-0-average-response-time-" +
              "millis: 5.830",
         "extended-op-1-3-6-1-4-1-30221-2-6-6-result-0-total-response-time-" +
              "millis: 11.660",
         "extended-op-1-3-6-1-4-1-4203-1-11-1-name: Password Modify",
         "extended-op-1-3-6-1-4-1-4203-1-11-1-total-count: 4",
         "extended-op-1-3-6-1-4-1-4203-1-11-1-failed-count: 0",
         "extended-op-1-3-6-1-4-1-4203-1-11-1-failed-percent: 0.000",
         "extended-op-1-3-6-1-4-1-4203-1-11-1-result-0-name: Success",
         "extended-op-1-3-6-1-4-1-4203-1-11-1-result-0-count: 4",
         "extended-op-1-3-6-1-4-1-4203-1-11-1-result-0-percent: 100.000",
         "extended-op-1-3-6-1-4-1-4203-1-11-1-result-0-average-response-time-" +
              "millis: 3.045",
         "extended-op-1-3-6-1-4-1-4203-1-11-1-result-0-total-response-time-" +
              "millis: 12.180",
         "extended-op-1-3-6-1-4-1-4203-1-11-3-name: Who Am I?",
         "extended-op-1-3-6-1-4-1-4203-1-11-3-total-count: 17",
         "extended-op-1-3-6-1-4-1-4203-1-11-3-failed-count: 0",
         "extended-op-1-3-6-1-4-1-4203-1-11-3-failed-percent: 0.000",
         "extended-op-1-3-6-1-4-1-4203-1-11-3-result-0-name: Success",
         "extended-op-1-3-6-1-4-1-4203-1-11-3-result-0-count: 17",
         "extended-op-1-3-6-1-4-1-4203-1-11-3-result-0-percent: 100.000",
         "extended-op-1-3-6-1-4-1-4203-1-11-3-result-0-average-response-time-" +
              "millis: 0.056",
         "extended-op-1-3-6-1-4-1-4203-1-11-3-result-0-total-response-time-" +
              "millis: 0.963",
         "modify-op-total-count: 76115",
         "modify-op-failed-count: 46075",
         "modify-op-failed-percent: 60.533",
         "modify-op-result-0-name: Success",
         "modify-op-result-0-count: 30028",
         "modify-op-result-0-percent: 39.451",
         "modify-op-result-0-average-response-time-millis: 2.332",
         "modify-op-result-0-total-response-time-millis: 70046.701",
         "modify-op-result-10-name: Referral",
         "modify-op-result-10-count: 12",
         "modify-op-result-10-percent: 0.016",
         "modify-op-result-10-average-response-time-millis: 0.641",
         "modify-op-result-10-total-response-time-millis: 7.696",
         "modify-op-result-32-name: No Such Entry",
         "modify-op-result-32-count: 7",
         "modify-op-result-32-percent: 0.009",
         "modify-op-result-32-average-response-time-millis: 0.338",
         "modify-op-result-32-total-response-time-millis: 2.371",
         "modify-op-result-34-name: Invalid DN Syntax",
         "modify-op-result-34-count: 44336",
         "modify-op-result-34-percent: 58.249",
         "modify-op-result-34-average-response-time-millis: 0.025",
         "modify-op-result-34-total-response-time-millis: 1113.184",
         "modify-op-result-65-name: Object Class Violation",
         "modify-op-result-65-count: 5",
         "modify-op-result-65-percent: 0.007",
         "modify-op-result-65-average-response-time-millis: 0.493",
         "modify-op-result-65-total-response-time-millis: 2.467",
         "modify-op-result-80-name: Other",
         "modify-op-result-80-count: 3",
         "modify-op-result-80-percent: 0.004",
         "modify-op-result-80-average-response-time-millis: 9000.698",
         "modify-op-result-80-total-response-time-millis: 27002.094",
         "modify-op-result-123-name: Authorization Denied",
         "modify-op-result-123-count: 1724",
         "modify-op-result-123-percent: 2.265",
         "modify-op-result-123-average-response-time-millis: 17.594",
         "modify-op-result-123-total-response-time-millis: 30333.120",
         "modifydn-op-total-count: 52",
         "modifydn-op-failed-count: 5",
         "modifydn-op-failed-percent: 9.615",
         "modifydn-op-result-0-name: Success",
         "modifydn-op-result-0-count: 35",
         "modifydn-op-result-0-percent: 67.308",
         "modifydn-op-result-0-average-response-time-millis: 1.867",
         "modifydn-op-result-0-total-response-time-millis: 65.351",
         "modifydn-op-result-10-name: Referral",
         "modifydn-op-result-10-count: 12",
         "modifydn-op-result-10-percent: 23.077",
         "modifydn-op-result-10-average-response-time-millis: 0.763",
         "modifydn-op-result-10-total-response-time-millis: 9.166",
         "modifydn-op-result-32-name: No Such Entry",
         "modifydn-op-result-32-count: 4",
         "modifydn-op-result-32-percent: 7.692",
         "modifydn-op-result-32-average-response-time-millis: 0.300",
         "modifydn-op-result-32-total-response-time-millis: 1.200",
         "modifydn-op-result-53-name: Unwilling to Perform",
         "modifydn-op-result-53-count: 1",
         "modifydn-op-result-53-percent: 1.923",
         "modifydn-op-result-53-average-response-time-millis: 0.257",
         "modifydn-op-result-53-total-response-time-millis: 0.257",
         "search-op-total-count: 433702",
         "search-op-failed-count: 150321",
         "search-op-failed-percent: 34.660",
         "search-op-result-0-name: Success",
         "search-op-result-0-count: 283353",
         "search-op-result-0-percent: 65.334",
         "search-op-result-0-average-response-time-millis: 0.373",
         "search-op-result-0-total-response-time-millis: 105736.778",
         "search-op-result-4-name: Size Limit Exceeded",
         "search-op-result-4-count: 2",
         "search-op-result-4-percent: 0.000",
         "search-op-result-4-average-response-time-millis: 0.668",
         "search-op-result-4-total-response-time-millis: 1.336",
         "search-op-result-10-name: Referral",
         "search-op-result-10-count: 28",
         "search-op-result-10-percent: 0.006",
         "search-op-result-10-average-response-time-millis: 0.774",
         "search-op-result-10-total-response-time-millis: 21.677",
         "search-op-result-32-name: No Such Entry",
         "search-op-result-32-count: 150303",
         "search-op-result-32-percent: 34.656",
         "search-op-result-32-average-response-time-millis: 0.245",
         "search-op-result-32-total-response-time-millis: 36891.265",
         "search-op-result-34-name: Invalid DN Syntax",
         "search-op-result-34-count: 13",
         "search-op-result-34-percent: 0.003",
         "search-op-result-34-average-response-time-millis: 3.456",
         "search-op-result-34-total-response-time-millis: 44.930",
         "search-op-result-122-name: Assertion Failed",
         "search-op-result-122-count: 1",
         "search-op-result-122-percent: 0.000",
         "search-op-result-122-average-response-time-millis: 1.799",
         "search-op-result-122-total-response-time-millis: 1.799",
         "search-op-result-123-name: Authorization Denied",
         "search-op-result-123-count: 2",
         "search-op-result-123-percent: 0.000",
         "search-op-result-123-average-response-time-millis: 0.383",
         "search-op-result-123-total-response-time-millis: 0.767");

    final ResultCodeMonitorEntry me = new ResultCodeMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-ldap-result-codes-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
         ResultCodeMonitorEntry.class.getName());

    assertNotNull(me.getAllOperationsResultCodeInfo());
    assertEquals(me.getAllOperationsResultCodeInfo().getTotalCount(),
         Long.valueOf(603376L));
    assertEquals(me.getAllOperationsResultCodeInfo().getFailedCount(),
         Long.valueOf(215131L));
    assertEquals(me.getAllOperationsResultCodeInfo().getFailedPercent(),
         Double.valueOf("35.655"));
    assertFalse(me.getAllOperationsResultCodeInfo().getResultCodeInfoMap().
         isEmpty());
    assertEquals(
         me.getAllOperationsResultCodeInfo().getResultCodeInfoMap().size(), 18);

    assertNotNull(me.getAddOperationResultCodeInfo());
    assertFalse(me.getAddOperationResultCodeInfo().getResultCodeInfoMap().
         isEmpty());

    assertNotNull(me.getBindOperationResultCodeInfo());
    assertFalse(me.getBindOperationResultCodeInfo().getResultCodeInfoMap().
         isEmpty());

    assertNotNull(me.getCompareOperationResultCodeInfo());
    assertFalse(me.getCompareOperationResultCodeInfo().getResultCodeInfoMap().
         isEmpty());

    assertNotNull(me.getDeleteOperationResultCodeInfo());
    assertFalse(me.getDeleteOperationResultCodeInfo().getResultCodeInfoMap().
         isEmpty());

    assertNotNull(me.getExtendedOperationResultCodeInfo());
    assertFalse(me.getExtendedOperationResultCodeInfo().getResultCodeInfoMap().
         isEmpty());

    assertNotNull(me.getModifyOperationResultCodeInfo());
    assertFalse(me.getModifyOperationResultCodeInfo().getResultCodeInfoMap().
         isEmpty());

    assertNotNull(me.getModifyDNOperationResultCodeInfo());
    assertFalse(me.getModifyDNOperationResultCodeInfo().getResultCodeInfoMap().
         isEmpty());

    assertNotNull(me.getSearchOperationResultCodeInfo());
    assertFalse(me.getSearchOperationResultCodeInfo().getResultCodeInfoMap().
         isEmpty());

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());


    final Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(attrs);
    assertFalse(attrs.isEmpty());
  }



  /**
   * Tests the behavior for an entry without any attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoAttributes()
         throws Exception
  {
    final Entry e = new Entry(
         "dn: cn=LDAP Result Codes,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-ldap-result-codes-monitor-entry",
         "objectClass: extensibleObject",
         "cn: LDAP Result Codes");

    final ResultCodeMonitorEntry me = new ResultCodeMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-ldap-result-codes-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
         ResultCodeMonitorEntry.class.getName());

    assertNotNull(me.getAllOperationsResultCodeInfo());
    assertTrue(me.getAllOperationsResultCodeInfo().getResultCodeInfoMap().
         isEmpty());

    assertNotNull(me.getAddOperationResultCodeInfo());
    assertTrue(me.getAddOperationResultCodeInfo().getResultCodeInfoMap().
         isEmpty());

    assertNotNull(me.getBindOperationResultCodeInfo());
    assertTrue(me.getBindOperationResultCodeInfo().getResultCodeInfoMap().
         isEmpty());

    assertNotNull(me.getCompareOperationResultCodeInfo());
    assertTrue(me.getCompareOperationResultCodeInfo().getResultCodeInfoMap().
         isEmpty());

    assertNotNull(me.getDeleteOperationResultCodeInfo());
    assertTrue(me.getDeleteOperationResultCodeInfo().getResultCodeInfoMap().
         isEmpty());

    assertNotNull(me.getExtendedOperationResultCodeInfo());
    assertTrue(me.getExtendedOperationResultCodeInfo().getResultCodeInfoMap().
         isEmpty());

    assertNotNull(me.getModifyOperationResultCodeInfo());
    assertTrue(me.getModifyOperationResultCodeInfo().getResultCodeInfoMap().
         isEmpty());

    assertNotNull(me.getModifyDNOperationResultCodeInfo());
    assertTrue(me.getModifyDNOperationResultCodeInfo().getResultCodeInfoMap().
         isEmpty());

    assertNotNull(me.getSearchOperationResultCodeInfo());
    assertTrue(me.getSearchOperationResultCodeInfo().getResultCodeInfoMap().
         isEmpty());

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());


    final Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(attrs);
    assertTrue(attrs.isEmpty());
  }
}
