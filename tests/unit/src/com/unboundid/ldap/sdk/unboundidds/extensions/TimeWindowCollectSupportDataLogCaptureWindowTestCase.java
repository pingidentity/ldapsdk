/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.Date;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the time window log capture
 * window.
 */
public final class TimeWindowCollectSupportDataLogCaptureWindowTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a log capture window that has both start and
   * end times when using dates.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStartAndEndDates()
         throws Exception
  {
    final Date endDate = new Date();
    final Date startDate = new Date(endDate.getTime() - 600_000L);

    TimeWindowCollectSupportDataLogCaptureWindow lcw =
         new TimeWindowCollectSupportDataLogCaptureWindow(startDate, endDate);

    lcw = TimeWindowCollectSupportDataLogCaptureWindow.decodeInternal(
         lcw.encode());

    assertNotNull(lcw.getStartTime());
    assertEquals(lcw.getStartTime(), startDate);

    assertEquals(lcw.getStartTimeMillis(), startDate.getTime());

    assertNotNull(lcw.getEndTime());
    assertEquals(lcw.getEndTime(), endDate);

    assertNotNull(lcw.getEndTimeMillis());
    assertEquals(lcw.getEndTimeMillis().longValue(), endDate.getTime());

    assertNotNull(lcw.toString());
  }



  /**
   * Tests the behavior for a log capture window that has a start time but no
   * end time when using dates.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyStartDate()
         throws Exception
  {
    final Date startDate = new Date(System.currentTimeMillis() - 600_000L);

    TimeWindowCollectSupportDataLogCaptureWindow lcw =
         new TimeWindowCollectSupportDataLogCaptureWindow(startDate, null);

    lcw = TimeWindowCollectSupportDataLogCaptureWindow.decodeInternal(
         lcw.encode());

    assertNotNull(lcw.getStartTime());
    assertEquals(lcw.getStartTime(), startDate);

    assertEquals(lcw.getStartTimeMillis(), startDate.getTime());

    assertNull(lcw.getEndTime());

    assertNull(lcw.getEndTimeMillis());

    assertNotNull(lcw.toString());
  }



  /**
   * Tests the behavior for a log capture window that has both start and
   * end times when using longs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStartAndEndTimes()
         throws Exception
  {
    final long endTime = System.currentTimeMillis();
    final long startTime = endTime - 600_000L;

    TimeWindowCollectSupportDataLogCaptureWindow lcw =
         new TimeWindowCollectSupportDataLogCaptureWindow(startTime, endTime);

    lcw = TimeWindowCollectSupportDataLogCaptureWindow.decodeInternal(
         lcw.encode());

    assertNotNull(lcw.getStartTime());
    assertEquals(lcw.getStartTime(), new Date(startTime));

    assertEquals(lcw.getStartTimeMillis(), startTime);

    assertNotNull(lcw.getEndTime());
    assertEquals(lcw.getEndTime(), new Date(endTime));

    assertNotNull(lcw.getEndTimeMillis());
    assertEquals(lcw.getEndTimeMillis().longValue(), endTime);

    assertNotNull(lcw.toString());
  }



  /**
   * Tests the behavior for a log capture window that has a start time but no
   * end time when using longs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyStartTime()
         throws Exception
  {
    final long startTime = System.currentTimeMillis() - 600_000L;

    TimeWindowCollectSupportDataLogCaptureWindow lcw =
         new TimeWindowCollectSupportDataLogCaptureWindow(startTime, null);

    lcw = TimeWindowCollectSupportDataLogCaptureWindow.decodeInternal(
         lcw.encode());

    assertNotNull(lcw.getStartTime());
    assertEquals(lcw.getStartTime(), new Date(startTime));

    assertEquals(lcw.getStartTimeMillis(), startTime);

    assertNull(lcw.getEndTime());

    assertNull(lcw.getEndTimeMillis());

    assertNotNull(lcw.toString());
  }



  /**
   * Tests the behavior when requesting a negative start time.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNegativeStartTime()
          throws Exception
  {
    new TimeWindowCollectSupportDataLogCaptureWindow(-1L, null);
  }



  /**
   * Tests the behavior when requesting a start time that is after the end time.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testStartDateAfterEndDate()
          throws Exception
  {
    final long startTime = System.currentTimeMillis();
    final long endTime = startTime - 1L;

    new TimeWindowCollectSupportDataLogCaptureWindow(startTime, endTime);
  }



  /**
   * Tests the behavior when trying to decode a malformed element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedElement()
          throws Exception
  {
    TimeWindowCollectSupportDataLogCaptureWindow.decodeInternal(
         new ASN1OctetString("malformed"));
  }



  /**
   * Tests the behavior when trying to decode an element that is a sequence
   * with too many elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSequenceWithTooManyElements()
          throws Exception
  {
    final long endTime = System.currentTimeMillis();
    final long startTime = endTime - 600_000L;
    final long beforeStartTime = startTime - 600_000L;

    final ASN1Sequence elementSequence = new ASN1Sequence(
         new ASN1OctetString(
              StaticUtils.encodeGeneralizedTime(beforeStartTime)),
         new ASN1OctetString(StaticUtils.encodeGeneralizedTime(startTime)),
         new ASN1OctetString(StaticUtils.encodeGeneralizedTime(endTime)));

    TimeWindowCollectSupportDataLogCaptureWindow.decodeInternal(
         elementSequence);
  }



  /**
   * Tests the behavior when trying to decode an element that has a malformed
   * timestamp.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSequenceWithMalformedTimestamp()
          throws Exception
  {
    final long endTime = System.currentTimeMillis();

    final ASN1Sequence elementSequence = new ASN1Sequence(
         new ASN1OctetString("malformed"),
         new ASN1OctetString(StaticUtils.encodeGeneralizedTime(endTime)));

    TimeWindowCollectSupportDataLogCaptureWindow.decodeInternal(
         elementSequence);
  }
}
