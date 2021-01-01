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
package com.unboundid.ldap.sdk.unboundidds.controls;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for recent login history attempts.
 */
public final class RecentLoginHistoryAttemptTestCase
     extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when creating with a successful attempt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessfulAttempt()
         throws Exception
  {
    final long currentTime = System.currentTimeMillis();

    RecentLoginHistoryAttempt a = new RecentLoginHistoryAttempt(true,
         currentTime, "simple", "1.2.3.4", null, 0L);

    a = new RecentLoginHistoryAttempt(a.asJSONObject());

    assertTrue(a.isSuccessful());

    assertNotNull(a.getTimestamp());
    assertEquals(a.getTimestamp().getTime(), currentTime);

    assertNotNull(a.getAuthenticationMethod());
    assertEquals(a.getAuthenticationMethod(), "simple");

    assertNotNull(a.getClientIPAddress());
    assertEquals(a.getClientIPAddress(), "1.2.3.4");

    assertNull(a.getFailureReason());

    assertNotNull(a.getAdditionalAttemptCount());
    assertEquals(a.getAdditionalAttemptCount().longValue(), 0L);

    assertNotNull(a.toString());
  }



  /**
   * Tests the behavior when creating with a failed attempt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailedAttempt()
         throws Exception
  {
    final long currentTime = System.currentTimeMillis();

    RecentLoginHistoryAttempt a = new RecentLoginHistoryAttempt(false,
         currentTime, "SASL PLAIN", "1.2.3.4",
         AuthenticationFailureReason.FAILURE_NAME_INVALID_CREDENTIALS, 1L);

    a = new RecentLoginHistoryAttempt(a.asJSONObject());

    assertFalse(a.isSuccessful());

    assertNotNull(a.getTimestamp());
    assertEquals(a.getTimestamp().getTime(), currentTime);

    assertNotNull(a.getAuthenticationMethod());
    assertEquals(a.getAuthenticationMethod(), "SASL PLAIN");

    assertNotNull(a.getClientIPAddress());
    assertEquals(a.getClientIPAddress(), "1.2.3.4");

    assertNotNull(a.getFailureReason());
    assertEquals(a.getFailureReason(),
         AuthenticationFailureReason.FAILURE_NAME_INVALID_CREDENTIALS);

    assertNotNull(a.getAdditionalAttemptCount());
    assertEquals(a.getAdditionalAttemptCount().longValue(), 1L);

    assertNotNull(a.toString());
  }



  /**
   * Tests the behavior when creating an attempt with a minimal set of
   * content.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalAttempt()
         throws Exception
  {
    final long currentTime = System.currentTimeMillis();

    RecentLoginHistoryAttempt a = new RecentLoginHistoryAttempt(true,
         currentTime, "internal", null, null, null);

    a = new RecentLoginHistoryAttempt(a.asJSONObject());

    assertTrue(a.isSuccessful());

    assertNotNull(a.getTimestamp());
    assertEquals(a.getTimestamp().getTime(), currentTime);

    assertNotNull(a.getAuthenticationMethod());
    assertEquals(a.getAuthenticationMethod(), "internal");

    assertNull(a.getClientIPAddress());

    assertNull(a.getFailureReason());

    assertNull(a.getAdditionalAttemptCount());

    assertNotNull(a.toString());
  }



  /**
   * Tests the behavior when trying to create an attempt without an
   * authentication method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testAttemptWithoutAuthenticationMethod()
         throws Exception
  {
    new RecentLoginHistoryAttempt(true, System.currentTimeMillis(), null, null,
         null, null);
  }



  /**
   * Tests the behavior when trying to create a successful attempt with a
   * failure reason.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testSuccessfulAttemptWithFailureReason()
         throws Exception
  {
    new RecentLoginHistoryAttempt(true, System.currentTimeMillis(), "simple",
         null, AuthenticationFailureReason.FAILURE_NAME_OTHER, null);
  }



  /**
   * Tests the behavior when trying to create a failed attempt without a
   * failure reason.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testFailedAttemptWithoutFailureReason()
         throws Exception
  {
    new RecentLoginHistoryAttempt(false, System.currentTimeMillis(), "simple",
         null, null, null);
  }



  /**
   * Tests the behavior when trying to decode a JSON object that does not
   * contain the required successful field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeObjectWithoutSuccessfulField()
         throws Exception
  {
    new RecentLoginHistoryAttempt(new JSONObject(
         new JSONField("timestamp",
              StaticUtils.encodeRFC3339Time(System.currentTimeMillis())),
         new JSONField("authentication-method", "simple")));
  }



  /**
   * Tests the behavior when trying to decode a JSON object that does not
   * contain the required timestamp field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeObjectWithoutTimestampField()
         throws Exception
  {
    new RecentLoginHistoryAttempt(new JSONObject(
         new JSONField("successful", true),
         new JSONField("authentication-method", "simple")));
  }



  /**
   * Tests the behavior when trying to decode a JSON object with a malformed
   * timestamp field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeObjectWithMalformedTimestampField()
         throws Exception
  {
    new RecentLoginHistoryAttempt(new JSONObject(
         new JSONField("successful", true),
         new JSONField("timestamp", "malformed"),
         new JSONField("authentication-method", "simple")));
  }



  /**
   * Tests the behavior when trying to decode a JSON object that does not
   * contain the required authentication method field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeObjectWithoutAuthenticationMethodField()
         throws Exception
  {
    new RecentLoginHistoryAttempt(new JSONObject(
         new JSONField("successful", true),
         new JSONField("timestamp",
              StaticUtils.encodeRFC3339Time(System.currentTimeMillis()))));
  }



  /**
   * Tests the behavior when trying to decode a JSON object for a successful
   * attempt that has a failure reason.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeObjectWithFailureReasonForSuccess()
         throws Exception
  {
    new RecentLoginHistoryAttempt(new JSONObject(
         new JSONField("successful", true),
         new JSONField("timestamp",
              StaticUtils.encodeRFC3339Time(System.currentTimeMillis())),
         new JSONField("authentication-method", "simple"),
         new JSONField("failure-reason", "invalid-credentials")));
  }



  /**
   * Tests the behavior when trying to decode a JSON object for a failed
   * attempt that does not have a failure reason.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeObjectWithoutFailureReasonForFailure()
         throws Exception
  {
    new RecentLoginHistoryAttempt(new JSONObject(
         new JSONField("successful", false),
         new JSONField("timestamp",
              StaticUtils.encodeRFC3339Time(System.currentTimeMillis())),
         new JSONField("authentication-method", "simple")));
  }



  /**
   * Tests the behavior of the equals method.  This method also provides
   * coverage for the hashCode method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsAndHashCode()
         throws Exception
  {
    final long currentTime = System.currentTimeMillis();

    // Identity.
    final RecentLoginHistoryAttempt a1 = new RecentLoginHistoryAttempt(true,
         currentTime, "simple", "1.2.3.4", null, 0L);
    assertTrue(a1.equals(a1));
    a1.hashCode();

    // Null.
    assertFalse(a1.equals(null));

    // Not attempt.
    assertFalse(a1.equals("not an attempt"));

    // Equivalent.
    final RecentLoginHistoryAttempt a2 = new RecentLoginHistoryAttempt(true,
         currentTime, "simple", "1.2.3.4", null, 0L);
    assertTrue(a1.equals(a2));
    a2.hashCode();

    // Different successful.
    final RecentLoginHistoryAttempt a3 = new RecentLoginHistoryAttempt(false,
         currentTime, "simple", "1.2.3.4", "invalid-credentials", 0L);
    assertFalse(a1.equals(a3));
    a3.hashCode();

    // Different timestamp.
    final RecentLoginHistoryAttempt a4 = new RecentLoginHistoryAttempt(true,
         (currentTime + 1L), "simple", "1.2.3.4", null, 0L);
    assertFalse(a1.equals(a4));
    a4.hashCode();

    // Different authentication method.
    final RecentLoginHistoryAttempt a5 = new RecentLoginHistoryAttempt(true,
         currentTime, "SASL PLAIN", "1.2.3.4", null, 0L);
    assertFalse(a1.equals(a5));
    a5.hashCode();

    // Different IP address.
    final RecentLoginHistoryAttempt a6 = new RecentLoginHistoryAttempt(true,
         currentTime, "simple", "1.2.3.5", null, 0L);
    assertFalse(a1.equals(a6));
    a6.hashCode();

    // Different failure reason.
    final RecentLoginHistoryAttempt a7 = new RecentLoginHistoryAttempt(false,
         currentTime, "simple", "1.2.3.4", "other", 0L);
    assertFalse(a3.equals(a7));
    a7.hashCode();

    // Different attempt count.
    final RecentLoginHistoryAttempt a8 = new RecentLoginHistoryAttempt(true,
         currentTime, "simple", "1.2.3.4", null, 1L);
    assertFalse(a1.equals(a8));
    a8.hashCode();
  }



  /**
   * Tests the behavior of the compareTo method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareTo()
         throws Exception
  {
    // Equivalent.
    final long currentTime = System.currentTimeMillis();
    final RecentLoginHistoryAttempt a1 = new RecentLoginHistoryAttempt(true,
         currentTime, "simple", "1.2.3.4", null, 0L);
    final RecentLoginHistoryAttempt a2 = new RecentLoginHistoryAttempt(true,
         currentTime, "simple", "1.2.3.4", null, 0L);
    assertEquals(a1.compareTo(a2), 0);


    // Different timestamp.
    final RecentLoginHistoryAttempt a3 = new RecentLoginHistoryAttempt(true,
         (currentTime + 1), "simple", "1.2.3.4", null, 0L);
    assertTrue(a1.compareTo(a3) > 0);
    assertTrue(a3.compareTo(a1) < 0);


    // Different successful.
    final RecentLoginHistoryAttempt a4 = new RecentLoginHistoryAttempt(false,
         currentTime, "simple", "1.2.3.4", "other", 0L);
    assertTrue(a1.compareTo(a4) < 0);
    assertTrue(a4.compareTo(a1) > 0);


    // Different authentication method.
    final RecentLoginHistoryAttempt a5 = new RecentLoginHistoryAttempt(true,
         currentTime, "SASL PLAIN", "1.2.3.4", null, 0L);
    assertFalse(a1.compareTo(a5) == 0);


    // Different attempt count.
    final RecentLoginHistoryAttempt a6 = new RecentLoginHistoryAttempt(true,
         currentTime, "simple", "1.2.3.4", null, 1L);
    assertTrue(a1.compareTo(a6) > 0);
    assertTrue(a6.compareTo(a1) < 0);


    // Null attempt count.
    final RecentLoginHistoryAttempt a7 = new RecentLoginHistoryAttempt(true,
         currentTime, "simple", "1.2.3.4", null, null);
    assertTrue(a1.compareTo(a7) < 0);
    assertTrue(a7.compareTo(a1) > 0);


    // Different client IP address.
    final RecentLoginHistoryAttempt a8 = new RecentLoginHistoryAttempt(true,
         currentTime, "simple", "1.2.3.5", null, 0L);
    assertFalse(a1.compareTo(a8) == 0);


    // Null client IP address.
    final RecentLoginHistoryAttempt a9 = new RecentLoginHistoryAttempt(true,
         currentTime, "simple", null, null, 0L);
    assertTrue(a1.compareTo(a9) < 0);
    assertTrue(a9.compareTo(a1) > 0);


    // Different failure reason.
    final RecentLoginHistoryAttempt a10 = new RecentLoginHistoryAttempt(false,
         currentTime, "simple", "1.2.3.4", "invalid-credentials", 0L);
    assertFalse(a4.compareTo(a10) == 0);
  }
}
