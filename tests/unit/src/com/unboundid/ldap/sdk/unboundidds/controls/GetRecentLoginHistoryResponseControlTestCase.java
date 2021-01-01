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

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



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
}
