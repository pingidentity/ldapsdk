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



import java.util.TreeSet;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides a set of test cases for recent login history objects.
 */
public final class RecentLoginHistoryTestCase
     extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a history created with both successes and failures.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessesAndFailures()
         throws Exception
  {
    final TreeSet<RecentLoginHistoryAttempt> successes = new TreeSet<>();
    successes.add(new RecentLoginHistoryAttempt(true,
         System.currentTimeMillis(), "simple", "1.2.3.4", null, null));
    successes.add(new RecentLoginHistoryAttempt(true,
         (System.currentTimeMillis() + 1), "simple", "1.2.3.4", null, null));

    final TreeSet<RecentLoginHistoryAttempt> failures = new TreeSet<>();
    failures.add(new RecentLoginHistoryAttempt(false,
         (System.currentTimeMillis() + 2), "simple", "1.2.3.4",
         "invalid-credentials", null));
    failures.add(new RecentLoginHistoryAttempt(false,
         (System.currentTimeMillis() + 3), "simple", "1.2.3.4",
         "invalid-credentials", null));
    failures.add(new RecentLoginHistoryAttempt(false,
         (System.currentTimeMillis() + 4), "simple", "1.2.3.4",
         "invalid-credentials", null));


    RecentLoginHistory h = new RecentLoginHistory(successes, failures);

    h = new RecentLoginHistory(h.asJSONObject());

    assertNotNull(h.getSuccessfulAttempts());
    assertFalse(h.getSuccessfulAttempts().isEmpty());
    assertEquals(h.getSuccessfulAttempts().size(), 2);
    assertEquals(h.getSuccessfulAttempts(), successes);

    assertNotNull(h.getFailedAttempts());
    assertFalse(h.getFailedAttempts().isEmpty());
    assertEquals(h.getFailedAttempts().size(), 3);
    assertEquals(h.getFailedAttempts(), failures);

    assertNotNull(h.toString());
  }



  /**
   * Tests the behavior for a history created with {@code null} values for both
   * the successful and failed attempts.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullSuccessesAndFailures()
         throws Exception
  {
    RecentLoginHistory h = new RecentLoginHistory(null, null);

    h = new RecentLoginHistory(h.asJSONObject());

    assertNotNull(h.getSuccessfulAttempts());
    assertTrue(h.getSuccessfulAttempts().isEmpty());

    assertNotNull(h.getFailedAttempts());
    assertTrue(h.getFailedAttempts().isEmpty());

    assertNotNull(h.toString());
  }



  /**
   * Tests the behavior when trying to decode an empty JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEmptyObject()
         throws Exception
  {
    final RecentLoginHistory h =
         new RecentLoginHistory(JSONObject.EMPTY_OBJECT);

    assertNotNull(h.getSuccessfulAttempts());
    assertTrue(h.getSuccessfulAttempts().isEmpty());

    assertNotNull(h.getFailedAttempts());
    assertTrue(h.getFailedAttempts().isEmpty());

    assertNotNull(h.toString());
  }



  /**
   * Tests the behavior when trying to decode a JSON object with a malformed
   * set of successful attempts when the malformed attempt is an object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedSuccessObject()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("successful-attempts",
              new JSONArray(new JSONObject(
                   new JSONField("malformed", true)))));

    new RecentLoginHistory(o);
  }



  /**
   * Tests the behavior when trying to decode a JSON object with a malformed
   * set of successful attempts when the malformed attempt is not an object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedSuccessNotObject()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("successful-attempts",
              new JSONArray(new JSONString("malformed"))));

    new RecentLoginHistory(o);
  }



  /**
   * Tests the behavior when trying to decode a JSON object with a malformed
   * set of failed attempts when the malformed attempt is an object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedFailureObject()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("failed-attempts",
              new JSONArray(new JSONObject(
                   new JSONField("malformed", true)))));

    new RecentLoginHistory(o);
  }



  /**
   * Tests the behavior when trying to decode a JSON object with a malformed
   * set of failed attempts when the malformed attempt is not an object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedFailureNotObject()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("failed-attempts",
              new JSONArray(new JSONString("malformed"))));

    new RecentLoginHistory(o);
  }
}
