/*
 * Copyright 2020-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2025 Ping Identity Corporation
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
 * Copyright (C) 2020-2025 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides a set of test cases for the get recent login history
 * response control.
 */
public final class GetRecentLoginHistoryResponseControlTestCase
     extends LDAPSDKTestCase
{
  /**
   * Tests a valid response control.
   *
   * @throws  Exception   If an unexpected problem occurs.
   */
  @Test()
  public void testValidControl()
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

    final RecentLoginHistory h = new RecentLoginHistory(successes, failures);

    GetRecentLoginHistoryResponseControl c =
         new GetRecentLoginHistoryResponseControl(h);

    c = new GetRecentLoginHistoryResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.62");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getRecentLoginHistory());

    assertNotNull(c.getControlName());
    assertFalse(c.getControlName().isEmpty());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to decode a control that does not have a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithoutValue()
         throws Exception
  {
    new GetRecentLoginHistoryResponseControl("1.3.6.1.4.1.30221.2.5.62", false,
         null);
  }



  /**
   * Tests the behavior when trying to decode a control whose value is not a
   * valid JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithValueNotJSONObject()
         throws Exception
  {
    new GetRecentLoginHistoryResponseControl("1.3.6.1.4.1.30221.2.5.62", false,
         new ASN1OctetString("not a JSON object"));
  }



  /**
   * Tests the behavior when trying to decode a control whose value is a JSON
   * object that can't be parsed as a valid recent login history.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueNotValidLoginHistory()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("successful-attempts",
              new JSONArray(new JSONObject(
                   new JSONField("malformed", true)))));

    new GetRecentLoginHistoryResponseControl("1.3.6.1.4.1.30221.2.5.62", false,
         new ASN1OctetString(o.toSingleLineString()));
  }



  /**
   * Tests the behavior fo the get method for a bind result that does not
   * include a get recent login history response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithoutControl()
         throws Exception
  {
    final BindResult bindResult = new BindResult(-1, ResultCode.SUCCESS,
         null, null, null, StaticUtils.NO_CONTROLS);
    assertNull(GetRecentLoginHistoryResponseControl.get(bindResult));
  }



  /**
   * Tests the behavior fo the get method for a bind result that includes an
   * already-decoded version of the control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithAlreadyDecodedControl()
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

    final RecentLoginHistory h = new RecentLoginHistory(successes, failures);

    final Control[] controls =
    {
      new GetRecentLoginHistoryResponseControl(h)
    };

    final BindResult bindResult = new BindResult(-1, ResultCode.SUCCESS,
         null, null, null, controls);
    assertNotNull(GetRecentLoginHistoryResponseControl.get(bindResult));
  }



  /**
   * Tests the behavior fo the get method for a bind result that includes a
   * valid control that has not been decoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithValidNonDecodedControl()
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

    final RecentLoginHistory h = new RecentLoginHistory(successes, failures);

    final Control[] controls =
    {
      new Control("1.3.6.1.4.1.30221.2.5.62", false,
           new GetRecentLoginHistoryResponseControl(h).getValue())
    };

    final BindResult bindResult = new BindResult(-1, ResultCode.SUCCESS,
         null, null, null, controls);
    assertNotNull(GetRecentLoginHistoryResponseControl.get(bindResult));
  }



  /**
   * Tests the behavior fo the get method for a bind result that includes a
   * malformed control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetWithInvalidNonDecodedControl()
         throws Exception
  {
    final Control[] controls =
    {
      new Control("1.3.6.1.4.1.30221.2.5.62", false, null)
    };

    final BindResult bindResult = new BindResult(-1, ResultCode.SUCCESS,
         null, null, null, controls);
    GetRecentLoginHistoryResponseControl.get(bindResult);
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when there are no attempts.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlNoAttempts()
          throws Exception
  {
    final GetRecentLoginHistoryResponseControl c =
         new GetRecentLoginHistoryResponseControl(
              new RecentLoginHistory(null, null));

    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.FALSE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         JSONObject.EMPTY_OBJECT);


    GetRecentLoginHistoryResponseControl decodedControl =
         GetRecentLoginHistoryResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    RecentLoginHistory history = decodedControl.getRecentLoginHistory();
    assertTrue(history.getSuccessfulAttempts().isEmpty());
    assertTrue(history.getFailedAttempts().isEmpty());


    decodedControl =
         (GetRecentLoginHistoryResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    history = decodedControl.getRecentLoginHistory();
    assertTrue(history.getSuccessfulAttempts().isEmpty());
    assertTrue(history.getFailedAttempts().isEmpty());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when there are both successful and failed attempts.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlWithAttempts()
          throws Exception
  {
    final long successfulAttempt1Timestamp = System.currentTimeMillis();
    final long successfulAttempt2Timestamp = successfulAttempt1Timestamp - 1;
    final long failedAttempt1Timestamp = successfulAttempt1Timestamp - 2;
    final long failedAttempt2Timestamp = successfulAttempt1Timestamp - 3;
    final long failedAttempt3Timestamp = successfulAttempt1Timestamp - 4;


    final TreeSet<RecentLoginHistoryAttempt> successes = new TreeSet<>();
    successes.add(new RecentLoginHistoryAttempt(true,
         successfulAttempt1Timestamp, "simple", "1.2.3.4", null, null));
    successes.add(new RecentLoginHistoryAttempt(true,
         successfulAttempt2Timestamp, "simple", "1.2.3.4", null, 1L));

    final TreeSet<RecentLoginHistoryAttempt> failures = new TreeSet<>();
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt1Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", null));
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt2Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", 2L));
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt3Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", 3L));

    final RecentLoginHistory h = new RecentLoginHistory(successes, failures);

    final GetRecentLoginHistoryResponseControl c =
         new GetRecentLoginHistoryResponseControl(h);

    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.FALSE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("successful-attempts", new JSONArray(
                   new JSONObject(
                        new JSONField("successful", true),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  successfulAttempt1Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4")),
                   new JSONObject(
                        new JSONField("successful", true),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  successfulAttempt2Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("additional-attempt-count", 1L)))),
              new JSONField("failed-attempts", new JSONArray(
                   new JSONObject(
                        new JSONField("successful", false),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  failedAttempt1Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("failure-reason", "invalid-credentials")),
                   new JSONObject(
                        new JSONField("successful", false),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  failedAttempt2Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("failure-reason", "invalid-credentials"),
                        new JSONField("additional-attempt-count", 2L)),
                   new JSONObject(
                        new JSONField("successful", false),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  failedAttempt3Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("failure-reason", "invalid-credentials"),
                        new JSONField("additional-attempt-count", 3L))))));


    GetRecentLoginHistoryResponseControl decodedControl =
         GetRecentLoginHistoryResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    RecentLoginHistory history = decodedControl.getRecentLoginHistory();
    assertEquals(history.getSuccessfulAttempts().size(), 2);
    assertEquals(history.getFailedAttempts().size(), 3);


    decodedControl =
         (GetRecentLoginHistoryResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    history = decodedControl.getRecentLoginHistory();
    assertEquals(history.getSuccessfulAttempts().size(), 2);
    assertEquals(history.getFailedAttempts().size(), 3);
  }



  /**
   * Tests the behavior when trying to decode the control from a JSON object
   * when the value is base64-encoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueBase64()
          throws Exception
  {
    final long successfulAttempt1Timestamp = System.currentTimeMillis();
    final long successfulAttempt2Timestamp = successfulAttempt1Timestamp - 1;
    final long failedAttempt1Timestamp = successfulAttempt1Timestamp - 2;
    final long failedAttempt2Timestamp = successfulAttempt1Timestamp - 3;
    final long failedAttempt3Timestamp = successfulAttempt1Timestamp - 4;


    final TreeSet<RecentLoginHistoryAttempt> successes = new TreeSet<>();
    successes.add(new RecentLoginHistoryAttempt(true,
         successfulAttempt1Timestamp, "simple", "1.2.3.4", null, null));
    successes.add(new RecentLoginHistoryAttempt(true,
         successfulAttempt2Timestamp, "simple", "1.2.3.4", null, 1L));

    final TreeSet<RecentLoginHistoryAttempt> failures = new TreeSet<>();
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt1Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", null));
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt2Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", 2L));
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt3Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", 3L));

    final RecentLoginHistory h = new RecentLoginHistory(successes, failures);

    final GetRecentLoginHistoryResponseControl c =
         new GetRecentLoginHistoryResponseControl(h);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    GetRecentLoginHistoryResponseControl decodedControl =
         GetRecentLoginHistoryResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    RecentLoginHistory history = decodedControl.getRecentLoginHistory();
    assertEquals(history.getSuccessfulAttempts().size(), 2);
    assertEquals(history.getFailedAttempts().size(), 3);


    decodedControl =
         (GetRecentLoginHistoryResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    history = decodedControl.getRecentLoginHistory();
    assertEquals(history.getSuccessfulAttempts().size(), 2);
    assertEquals(history.getFailedAttempts().size(), 3);
  }



  /**
   * Tests the behavior when trying to decode the control from a JSON object
   * when the value has a malformed success object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueHasMalformedSuccess()
          throws Exception
  {
    final long successfulAttempt1Timestamp = System.currentTimeMillis();
    final long successfulAttempt2Timestamp = successfulAttempt1Timestamp - 1;
    final long failedAttempt1Timestamp = successfulAttempt1Timestamp - 2;
    final long failedAttempt2Timestamp = successfulAttempt1Timestamp - 3;
    final long failedAttempt3Timestamp = successfulAttempt1Timestamp - 4;


    final TreeSet<RecentLoginHistoryAttempt> successes = new TreeSet<>();
    successes.add(new RecentLoginHistoryAttempt(true,
         successfulAttempt1Timestamp, "simple", "1.2.3.4", null, null));
    successes.add(new RecentLoginHistoryAttempt(true,
         successfulAttempt2Timestamp, "simple", "1.2.3.4", null, 1L));

    final TreeSet<RecentLoginHistoryAttempt> failures = new TreeSet<>();
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt1Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", null));
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt2Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", 2L));
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt3Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", 3L));

    final RecentLoginHistory h = new RecentLoginHistory(successes, failures);

    final GetRecentLoginHistoryResponseControl c =
         new GetRecentLoginHistoryResponseControl(h);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("successful-attempts", new JSONArray(
                   new JSONObject(
                        new JSONField("malformed", true)))),
              new JSONField("failed-attempts", new JSONArray(
                   new JSONObject(
                        new JSONField("successful", false),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  failedAttempt1Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("failure-reason", "invalid-credentials")),
                   new JSONObject(
                        new JSONField("successful", false),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  failedAttempt2Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("failure-reason", "invalid-credentials"),
                        new JSONField("additional-attempt-count", 2L)),
                   new JSONObject(
                        new JSONField("successful", false),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  failedAttempt3Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("failure-reason", "invalid-credentials"),
                        new JSONField("additional-attempt-count", 3L)))))));

    GetRecentLoginHistoryResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode the control from a JSON object
   * when the value has a success object that is not a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueSuccessNotObject()
          throws Exception
  {
    final long successfulAttempt1Timestamp = System.currentTimeMillis();
    final long successfulAttempt2Timestamp = successfulAttempt1Timestamp - 1;
    final long failedAttempt1Timestamp = successfulAttempt1Timestamp - 2;
    final long failedAttempt2Timestamp = successfulAttempt1Timestamp - 3;
    final long failedAttempt3Timestamp = successfulAttempt1Timestamp - 4;


    final TreeSet<RecentLoginHistoryAttempt> successes = new TreeSet<>();
    successes.add(new RecentLoginHistoryAttempt(true,
         successfulAttempt1Timestamp, "simple", "1.2.3.4", null, null));
    successes.add(new RecentLoginHistoryAttempt(true,
         successfulAttempt2Timestamp, "simple", "1.2.3.4", null, 1L));

    final TreeSet<RecentLoginHistoryAttempt> failures = new TreeSet<>();
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt1Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", null));
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt2Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", 2L));
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt3Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", 3L));

    final RecentLoginHistory h = new RecentLoginHistory(successes, failures);

    final GetRecentLoginHistoryResponseControl c =
         new GetRecentLoginHistoryResponseControl(h);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("successful-attempts", new JSONArray(
                   new JSONObject(
                        new JSONField("successful", true),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  successfulAttempt1Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4")),
                   new JSONString("not-an-object"))),
              new JSONField("failed-attempts", new JSONArray(
                   new JSONObject(
                        new JSONField("successful", false),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  failedAttempt1Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("failure-reason", "invalid-credentials")),
                   new JSONObject(
                        new JSONField("successful", false),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  failedAttempt2Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("failure-reason", "invalid-credentials"),
                        new JSONField("additional-attempt-count", 2L)),
                   new JSONObject(
                        new JSONField("successful", false),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  failedAttempt3Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("failure-reason", "invalid-credentials"),
                        new JSONField("additional-attempt-count", 3L)))))));

    GetRecentLoginHistoryResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode the control from a JSON object
   * when the value has a failure object that is not a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueHasMalformedFailure()
          throws Exception
  {
    final long successfulAttempt1Timestamp = System.currentTimeMillis();
    final long successfulAttempt2Timestamp = successfulAttempt1Timestamp - 1;
    final long failedAttempt1Timestamp = successfulAttempt1Timestamp - 2;
    final long failedAttempt2Timestamp = successfulAttempt1Timestamp - 3;
    final long failedAttempt3Timestamp = successfulAttempt1Timestamp - 4;


    final TreeSet<RecentLoginHistoryAttempt> successes = new TreeSet<>();
    successes.add(new RecentLoginHistoryAttempt(true,
         successfulAttempt1Timestamp, "simple", "1.2.3.4", null, null));
    successes.add(new RecentLoginHistoryAttempt(true,
         successfulAttempt2Timestamp, "simple", "1.2.3.4", null, 1L));

    final TreeSet<RecentLoginHistoryAttempt> failures = new TreeSet<>();
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt1Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", null));
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt2Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", 2L));
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt3Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", 3L));

    final RecentLoginHistory h = new RecentLoginHistory(successes, failures);

    final GetRecentLoginHistoryResponseControl c =
         new GetRecentLoginHistoryResponseControl(h);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("successful-attempts", new JSONArray(
                   new JSONObject(
                        new JSONField("successful", true),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  successfulAttempt1Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4")),
                   new JSONObject(
                        new JSONField("successful", true),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  successfulAttempt2Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("additional-attempt-count", 1L)))),
              new JSONField("failed-attempts", new JSONArray(
                   new JSONObject(
                        new JSONField("malformed", true)),
                   new JSONObject(
                        new JSONField("successful", false),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  failedAttempt2Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("failure-reason", "invalid-credentials"),
                        new JSONField("additional-attempt-count", 2L)),
                   new JSONObject(
                        new JSONField("successful", false),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  failedAttempt3Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("failure-reason", "invalid-credentials"),
                        new JSONField("additional-attempt-count", 3L)))))));

    GetRecentLoginHistoryResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode the control from a JSON object
   * when the value has a failure object that is not a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueFailureNotObject()
          throws Exception
  {
    final long successfulAttempt1Timestamp = System.currentTimeMillis();
    final long successfulAttempt2Timestamp = successfulAttempt1Timestamp - 1;
    final long failedAttempt1Timestamp = successfulAttempt1Timestamp - 2;
    final long failedAttempt2Timestamp = successfulAttempt1Timestamp - 3;
    final long failedAttempt3Timestamp = successfulAttempt1Timestamp - 4;


    final TreeSet<RecentLoginHistoryAttempt> successes = new TreeSet<>();
    successes.add(new RecentLoginHistoryAttempt(true,
         successfulAttempt1Timestamp, "simple", "1.2.3.4", null, null));
    successes.add(new RecentLoginHistoryAttempt(true,
         successfulAttempt2Timestamp, "simple", "1.2.3.4", null, 1L));

    final TreeSet<RecentLoginHistoryAttempt> failures = new TreeSet<>();
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt1Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", null));
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt2Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", 2L));
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt3Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", 3L));

    final RecentLoginHistory h = new RecentLoginHistory(successes, failures);

    final GetRecentLoginHistoryResponseControl c =
         new GetRecentLoginHistoryResponseControl(h);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("successful-attempts", new JSONArray(
                   new JSONObject(
                        new JSONField("successful", true),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  successfulAttempt1Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4")),
                   new JSONObject(
                        new JSONField("successful", true),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  successfulAttempt2Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("additional-attempt-count", 1L)))),
              new JSONField("failed-attempts", new JSONArray(
                   new JSONObject(
                        new JSONField("successful", false),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  failedAttempt1Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("failure-reason", "invalid-credentials")),
                   new JSONString("not-an-object"),
                   new JSONObject(
                        new JSONField("successful", false),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  failedAttempt3Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("failure-reason", "invalid-credentials"),
                        new JSONField("additional-attempt-count", 3L)))))));

    GetRecentLoginHistoryResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode the control from a JSON object
   * when the value has an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueUnrecognizedFieldStrict()
          throws Exception
  {
    final long successfulAttempt1Timestamp = System.currentTimeMillis();
    final long successfulAttempt2Timestamp = successfulAttempt1Timestamp - 1;
    final long failedAttempt1Timestamp = successfulAttempt1Timestamp - 2;
    final long failedAttempt2Timestamp = successfulAttempt1Timestamp - 3;
    final long failedAttempt3Timestamp = successfulAttempt1Timestamp - 4;


    final TreeSet<RecentLoginHistoryAttempt> successes = new TreeSet<>();
    successes.add(new RecentLoginHistoryAttempt(true,
         successfulAttempt1Timestamp, "simple", "1.2.3.4", null, null));
    successes.add(new RecentLoginHistoryAttempt(true,
         successfulAttempt2Timestamp, "simple", "1.2.3.4", null, 1L));

    final TreeSet<RecentLoginHistoryAttempt> failures = new TreeSet<>();
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt1Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", null));
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt2Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", 2L));
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt3Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", 3L));

    final RecentLoginHistory h = new RecentLoginHistory(successes, failures);

    final GetRecentLoginHistoryResponseControl c =
         new GetRecentLoginHistoryResponseControl(h);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("successful-attempts", new JSONArray(
                   new JSONObject(
                        new JSONField("successful", true),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  successfulAttempt1Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4")),
                   new JSONObject(
                        new JSONField("successful", true),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  successfulAttempt2Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("additional-attempt-count", 1L)))),
              new JSONField("failed-attempts", new JSONArray(
                   new JSONObject(
                        new JSONField("successful", false),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  failedAttempt1Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("failure-reason", "invalid-credentials")),
                   new JSONObject(
                        new JSONField("successful", false),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  failedAttempt2Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("failure-reason", "invalid-credentials"),
                        new JSONField("additional-attempt-count", 2L)),
                   new JSONObject(
                        new JSONField("successful", false),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  failedAttempt3Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("failure-reason", "invalid-credentials"),
                        new JSONField("additional-attempt-count", 3L)))),
              new JSONField("unrecognized", "foo"))));

    GetRecentLoginHistoryResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode the control from a JSON object
   * when the value has an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueUnrecognizedFieldNonStrict()
          throws Exception
  {
    final long successfulAttempt1Timestamp = System.currentTimeMillis();
    final long successfulAttempt2Timestamp = successfulAttempt1Timestamp - 1;
    final long failedAttempt1Timestamp = successfulAttempt1Timestamp - 2;
    final long failedAttempt2Timestamp = successfulAttempt1Timestamp - 3;
    final long failedAttempt3Timestamp = successfulAttempt1Timestamp - 4;


    final TreeSet<RecentLoginHistoryAttempt> successes = new TreeSet<>();
    successes.add(new RecentLoginHistoryAttempt(true,
         successfulAttempt1Timestamp, "simple", "1.2.3.4", null, null));
    successes.add(new RecentLoginHistoryAttempt(true,
         successfulAttempt2Timestamp, "simple", "1.2.3.4", null, 1L));

    final TreeSet<RecentLoginHistoryAttempt> failures = new TreeSet<>();
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt1Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", null));
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt2Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", 2L));
    failures.add(new RecentLoginHistoryAttempt(false, failedAttempt3Timestamp,
         "simple", "1.2.3.4", "invalid-credentials", 3L));

    final RecentLoginHistory h = new RecentLoginHistory(successes, failures);

    final GetRecentLoginHistoryResponseControl c =
         new GetRecentLoginHistoryResponseControl(h);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("successful-attempts", new JSONArray(
                   new JSONObject(
                        new JSONField("successful", true),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  successfulAttempt1Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4")),
                   new JSONObject(
                        new JSONField("successful", true),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  successfulAttempt2Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("additional-attempt-count", 1L)))),
              new JSONField("failed-attempts", new JSONArray(
                   new JSONObject(
                        new JSONField("successful", false),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  failedAttempt1Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("failure-reason", "invalid-credentials")),
                   new JSONObject(
                        new JSONField("successful", false),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  failedAttempt2Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("failure-reason", "invalid-credentials"),
                        new JSONField("additional-attempt-count", 2L)),
                   new JSONObject(
                        new JSONField("successful", false),
                        new JSONField("timestamp",
                             StaticUtils.encodeRFC3339Time(
                                  failedAttempt3Timestamp)),
                        new JSONField("authentication-method", "simple"),
                        new JSONField("client-ip-address", "1.2.3.4"),
                        new JSONField("failure-reason", "invalid-credentials"),
                        new JSONField("additional-attempt-count", 3L)))),
              new JSONField("unrecognized", "foo"))));


    GetRecentLoginHistoryResponseControl decodedControl =
         GetRecentLoginHistoryResponseControl.decodeJSONControl(controlObject,
              false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    RecentLoginHistory history = decodedControl.getRecentLoginHistory();
    assertEquals(history.getSuccessfulAttempts().size(), 2);
    assertEquals(history.getFailedAttempts().size(), 3);


    decodedControl =
         (GetRecentLoginHistoryResponseControl)
         Control.decodeJSONControl(controlObject, false, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    history = decodedControl.getRecentLoginHistory();
    assertEquals(history.getSuccessfulAttempts().size(), 2);
    assertEquals(history.getFailedAttempts().size(), 3);
  }
}
