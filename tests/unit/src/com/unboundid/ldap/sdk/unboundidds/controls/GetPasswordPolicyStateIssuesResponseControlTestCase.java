/*
 * Copyright 2015-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2022 Ping Identity Corporation
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
 * Copyright (C) 2015-2022 Ping Identity Corporation
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



import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityError;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityNotice;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityWarning;
import com.unboundid.util.Base64;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;

import static com.unboundid.ldap.sdk.unboundidds.controls.
                   AuthenticationFailureReason.*;
import static com.unboundid.ldap.sdk.unboundidds.extensions.
                   PasswordPolicyStateAccountUsabilityError.*;
import static com.unboundid.ldap.sdk.unboundidds.extensions.
                   PasswordPolicyStateAccountUsabilityNotice.*;
import static com.unboundid.ldap.sdk.unboundidds.extensions.
                   PasswordPolicyStateAccountUsabilityWarning.*;



/**
 * This class provides test coverage for the get password policy state issues
 * response control.
 */
public final class GetPasswordPolicyStateIssuesResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a control without any notices, warnings, or errors.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoContents()
         throws Exception
  {
    GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(null, null, null);

    c = new GetPasswordPolicyStateIssuesResponseControl().decodeControl(
         c.getOID(), c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.47");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getNotices());
    assertTrue(c.getNotices().isEmpty());

    assertNotNull(c.getWarnings());
    assertTrue(c.getWarnings().isEmpty());

    assertNotNull(c.getErrors());
    assertTrue(c.getErrors().isEmpty());

    assertNull(c.getAuthenticationFailureReason());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior for a control with only a single notice and no warnings
   * or errors.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleNotice()
         throws Exception
  {
    final List<PasswordPolicyStateAccountUsabilityNotice> notices =
         Collections.singletonList(
              new PasswordPolicyStateAccountUsabilityNotice(
                   NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
                   NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
                   "The user has a retired password"));
    final List<PasswordPolicyStateAccountUsabilityWarning> warnings =
         Collections.emptyList();
    final List<PasswordPolicyStateAccountUsabilityError> errors =
         Collections.emptyList();


    GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(notices, warnings,
              errors);

    c = new GetPasswordPolicyStateIssuesResponseControl().decodeControl(
         c.getOID(), c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.47");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getNotices());
    assertFalse(c.getNotices().isEmpty());
    assertEquals(c.getNotices().size(), 1);
    assertEquals(c.getNotices().get(0).getIntValue(),
         NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD);
    assertEquals(c.getNotices().get(0).getName(),
         NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD);
    assertEquals(c.getNotices().get(0).getMessage(),
         "The user has a retired password");

    assertNotNull(c.getWarnings());
    assertTrue(c.getWarnings().isEmpty());

    assertNotNull(c.getErrors());
    assertTrue(c.getErrors().isEmpty());

    assertNull(c.getAuthenticationFailureReason());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior for a control with only a single warning and no notices
   * or errors.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleWarning()
         throws Exception
  {
    final List<PasswordPolicyStateAccountUsabilityNotice> notices =
         Collections.emptyList();
    final List<PasswordPolicyStateAccountUsabilityWarning> warnings =
         Collections.singletonList(
              new PasswordPolicyStateAccountUsabilityWarning(
                   WARNING_TYPE_ACCOUNT_EXPIRING,
                   WARNING_NAME_ACCOUNT_EXPIRING,
                   "The account is expiring"));
    final List<PasswordPolicyStateAccountUsabilityError> errors =
         Collections.emptyList();


    GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(notices, warnings,
              errors);

    c = new GetPasswordPolicyStateIssuesResponseControl().decodeControl(
         c.getOID(), c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.47");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getNotices());
    assertTrue(c.getNotices().isEmpty());

    assertNotNull(c.getWarnings());
    assertFalse(c.getWarnings().isEmpty());
    assertEquals(c.getWarnings().size(), 1);
    assertEquals(c.getWarnings().get(0).getIntValue(),
         WARNING_TYPE_ACCOUNT_EXPIRING);
    assertEquals(c.getWarnings().get(0).getName(),
         WARNING_NAME_ACCOUNT_EXPIRING);
    assertEquals(c.getWarnings().get(0).getMessage(),
         "The account is expiring");

    assertNotNull(c.getErrors());
    assertTrue(c.getErrors().isEmpty());

    assertNull(c.getAuthenticationFailureReason());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior for a control with only a single error and no notices
   * or warnings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleError()
         throws Exception
  {
    final List<PasswordPolicyStateAccountUsabilityNotice> notices =
         Collections.emptyList();
    final List<PasswordPolicyStateAccountUsabilityWarning> warnings =
         Collections.emptyList();
    final List<PasswordPolicyStateAccountUsabilityError> errors =
         Collections.singletonList(
              new PasswordPolicyStateAccountUsabilityError(
                   ERROR_TYPE_ACCOUNT_DISABLED,
                   ERROR_NAME_ACCOUNT_DISABLED,
                   "The account is disabled"));
    final AuthenticationFailureReason authFailureReason =
         new AuthenticationFailureReason(FAILURE_TYPE_ACCOUNT_NOT_USABLE,
              FAILURE_NAME_ACCOUNT_NOT_USABLE,
              "The account is not usable because it is disabled");


    GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(notices, warnings,
              errors, authFailureReason);

    c = new GetPasswordPolicyStateIssuesResponseControl().decodeControl(
         c.getOID(), c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.47");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getNotices());
    assertTrue(c.getNotices().isEmpty());

    assertNotNull(c.getWarnings());
    assertTrue(c.getWarnings().isEmpty());

    assertNotNull(c.getErrors());
    assertFalse(c.getErrors().isEmpty());
    assertEquals(c.getErrors().size(), 1);
    assertEquals(c.getErrors().get(0).getIntValue(),
         ERROR_TYPE_ACCOUNT_DISABLED);
    assertEquals(c.getErrors().get(0).getName(),
         ERROR_NAME_ACCOUNT_DISABLED);
    assertEquals(c.getErrors().get(0).getMessage(),
         "The account is disabled");

    assertNotNull(c.getAuthenticationFailureReason());
    assertEquals(c.getAuthenticationFailureReason().getIntValue(),
         FAILURE_TYPE_ACCOUNT_NOT_USABLE);
    assertEquals(c.getAuthenticationFailureReason().getName(),
         FAILURE_NAME_ACCOUNT_NOT_USABLE);
    assertEquals(c.getAuthenticationFailureReason().getMessage(),
         "The account is not usable because it is disabled");

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior for a control with multiple notices, warnings, and
   * errors.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllTypes()
         throws Exception
  {
    final List<PasswordPolicyStateAccountUsabilityNotice> notices =
         Arrays.asList(
              new PasswordPolicyStateAccountUsabilityNotice(
                   NOTICE_TYPE_OUTSTANDING_ONE_TIME_PASSWORD,
                   NOTICE_NAME_OUTSTANDING_ONE_TIME_PASSWORD,
                   "The user has an outstanding one-time password"),
              new PasswordPolicyStateAccountUsabilityNotice(
                   NOTICE_TYPE_IN_MINIMUM_PASSWORD_AGE,
                   NOTICE_NAME_IN_MINIMUM_PASSWORD_AGE,
                   null));

    final List<PasswordPolicyStateAccountUsabilityWarning> warnings =
         Arrays.asList(
              new PasswordPolicyStateAccountUsabilityWarning(
                   WARNING_TYPE_PASSWORD_EXPIRING,
                   WARNING_NAME_PASSWORD_EXPIRING,
                   "The password is about to expire"),
              new PasswordPolicyStateAccountUsabilityWarning(
                   WARNING_TYPE_ACCOUNT_IDLE,
                   WARNING_NAME_ACCOUNT_IDLE,
                   null));

    final List<PasswordPolicyStateAccountUsabilityError> errors =
         Arrays.asList(
              new PasswordPolicyStateAccountUsabilityError(
                   ERROR_TYPE_ACCOUNT_NOT_YET_ACTIVE,
                   ERROR_NAME_ACCOUNT_NOT_YET_ACTIVE,
                   "The account is not yet active"),
              new PasswordPolicyStateAccountUsabilityError(
                   ERROR_TYPE_ACCOUNT_DISABLED,
                   ERROR_NAME_ACCOUNT_DISABLED,
                   null));

    final AuthenticationFailureReason authFailureReason =
         new AuthenticationFailureReason(FAILURE_TYPE_LOCKDOWN_MODE,
              FAILURE_NAME_LOCKDOWN_MODE, null);


    GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(notices, warnings,
              errors, authFailureReason);

    c = new GetPasswordPolicyStateIssuesResponseControl().decodeControl(
         c.getOID(), c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.47");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getNotices());
    assertFalse(c.getNotices().isEmpty());
    assertEquals(c.getNotices().size(), 2);

    assertNotNull(c.getWarnings());
    assertFalse(c.getWarnings().isEmpty());
    assertEquals(c.getWarnings().size(), 2);

    assertNotNull(c.getErrors());
    assertFalse(c.getErrors().isEmpty());
    assertEquals(c.getErrors().size(), 2);

    assertNotNull(c.getAuthenticationFailureReason());
    assertEquals(c.getAuthenticationFailureReason().getIntValue(),
         FAILURE_TYPE_LOCKDOWN_MODE);
    assertEquals(c.getAuthenticationFailureReason().getName(),
         FAILURE_NAME_LOCKDOWN_MODE);
    assertNull(c.getAuthenticationFailureReason().getMessage());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to decode a control that does not have a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoValue()
         throws Exception
  {
    new GetPasswordPolicyStateIssuesResponseControl().decodeControl(
         "1.3.6.1.4.1.30221.2.5.47", false, null);
  }



  /**
   * Tests the behavior when trying to decode a control that has a malformed
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedValue()
         throws Exception
  {
    new GetPasswordPolicyStateIssuesResponseControl().decodeControl(
         "1.3.6.1.4.1.30221.2.5.47", false, new ASN1OctetString("malformed"));
  }



  /**
   * Tests the behavior when trying to decode a control that has a value
   * sequence that contains an element with an unexpected BER type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceUnexpectedElementType()
         throws Exception
  {
    new GetPasswordPolicyStateIssuesResponseControl().decodeControl(
         "1.3.6.1.4.1.30221.2.5.47", false,
         new ASN1OctetString(
              new ASN1Sequence(
                   new ASN1OctetString("foo")).encode()));
  }



  /**
   * Tests the behavior of the get method for a bind result that doesn't contain
   * any controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetBindResultNoControl()
         throws Exception
  {
    final BindResult bindResult = new BindResult(1, ResultCode.SUCCESS, null,
         null, null, null);
    assertNull(GetPasswordPolicyStateIssuesResponseControl.get(bindResult));
  }



  /**
   * Tests the behavior of the get method for a bind result that contains a
   * control that is already the correct type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetBindResultPreDecodedControl()
         throws Exception
  {
    final List<PasswordPolicyStateAccountUsabilityNotice> notices =
         Collections.singletonList(
              new PasswordPolicyStateAccountUsabilityNotice(
                   NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
                   NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
                   "The user has a retired password"));
    final List<PasswordPolicyStateAccountUsabilityWarning> warnings =
         Collections.emptyList();
    final List<PasswordPolicyStateAccountUsabilityError> errors =
         Collections.emptyList();

    final GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(notices, warnings,
              errors);

    final Control[] controls =
    {
      c
    };

    final BindResult bindResult = new BindResult(1, ResultCode.SUCCESS, null,
         null, null, controls);
    assertNotNull(GetPasswordPolicyStateIssuesResponseControl.get(bindResult));
    assertEquals(GetPasswordPolicyStateIssuesResponseControl.get(bindResult),
         c);
  }



  /**
   * Tests the behavior of the get method for a bind result that contains a
   * generic control that can be decoded as a get password policy state issues
   * response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetBindResultValidGenericControl()
         throws Exception
  {
    final List<PasswordPolicyStateAccountUsabilityNotice> notices =
         Collections.singletonList(
              new PasswordPolicyStateAccountUsabilityNotice(
                   NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
                   NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
                   "The user has a retired password"));
    final List<PasswordPolicyStateAccountUsabilityWarning> warnings =
         Collections.emptyList();
    final List<PasswordPolicyStateAccountUsabilityError> errors =
         Collections.emptyList();

    final GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(notices, warnings,
              errors);

    final Control[] controls =
    {
      new Control(c.getOID(), c.isCritical(), c.getValue())
    };

    final BindResult bindResult = new BindResult(1, ResultCode.SUCCESS, null,
         null, null, controls);
    assertNotNull(GetPasswordPolicyStateIssuesResponseControl.get(bindResult));
    assertEquals(GetPasswordPolicyStateIssuesResponseControl.get(bindResult),
         c);
  }



  /**
   * Tests the behavior of the get method for a bind result that contains a
   * generic control that cannot be decoded as a get password policy state
   * issues response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetBindResultInvalidGenericControl()
         throws Exception
  {
    final Control[] controls =
    {
      new Control("1.3.6.1.4.1.30221.2.5.47", false, null)
    };

    final BindResult bindResult = new BindResult(1, ResultCode.SUCCESS, null,
         null, null, controls);
    GetPasswordPolicyStateIssuesResponseControl.get(bindResult);
  }



  /**
   * Tests the behavior of the get method for an LDAP exception that doesn't
   * contain any controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetLDAPExceptionNoControl()
         throws Exception
  {
    final LDAPException ldapException = new LDAPException(
         ResultCode.INVALID_CREDENTIALS, null, null, null, null, null);
    assertNull(GetPasswordPolicyStateIssuesResponseControl.get(ldapException));
  }



  /**
   * Tests the behavior of the get method for an LDAP exception that contains a
   * control that is already the correct type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetLDAPExceptionPreDecodedControl()
         throws Exception
  {
    final List<PasswordPolicyStateAccountUsabilityNotice> notices =
         Collections.singletonList(
              new PasswordPolicyStateAccountUsabilityNotice(
                   NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
                   NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
                   "The user has a retired password"));
    final List<PasswordPolicyStateAccountUsabilityWarning> warnings =
         Collections.emptyList();
    final List<PasswordPolicyStateAccountUsabilityError> errors =
         Collections.emptyList();

    final GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(notices, warnings,
              errors);

    final Control[] controls =
    {
      c
    };

    final LDAPException ldapException = new LDAPException(
         ResultCode.INVALID_CREDENTIALS, null, null, null, controls, null);
    assertNotNull(
         GetPasswordPolicyStateIssuesResponseControl.get(ldapException));
    assertEquals(
         GetPasswordPolicyStateIssuesResponseControl.get(ldapException), c);
  }



  /**
   * Tests the behavior of the get method for an LDAP exception that contains a
   * generic control that can be decoded as a get password policy state issues
   * response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetLDAPExceptionValidGenericControl()
         throws Exception
  {
    final List<PasswordPolicyStateAccountUsabilityNotice> notices =
         Collections.singletonList(
              new PasswordPolicyStateAccountUsabilityNotice(
                   NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
                   NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
                   "The user has a retired password"));
    final List<PasswordPolicyStateAccountUsabilityWarning> warnings =
         Collections.emptyList();
    final List<PasswordPolicyStateAccountUsabilityError> errors =
         Collections.emptyList();

    final GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(notices, warnings,
              errors);

    final Control[] controls =
    {
      new Control(c.getOID(), c.isCritical(), c.getValue())
    };

    final LDAPException ldapException = new LDAPException(
         ResultCode.INVALID_CREDENTIALS, null, null, null, controls, null);
    assertNotNull(
         GetPasswordPolicyStateIssuesResponseControl.get(ldapException));
    assertEquals(
         GetPasswordPolicyStateIssuesResponseControl.get(ldapException), c);
  }



  /**
   * Tests the behavior of the get method for an LDAP exception that contains a
   * generic control that cannot be decoded as a get password policy state
   * issues response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetLDAPExceptionInvalidGenericControl()
         throws Exception
  {
    final Control[] controls =
    {
      new Control("1.3.6.1.4.1.30221.2.5.47", false, null)
    };

    final LDAPException ldapException = new LDAPException(
         ResultCode.INVALID_CREDENTIALS, null, null, null, controls, null);
    GetPasswordPolicyStateIssuesResponseControl.get(ldapException);
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when there are no issues and no authentication failure
   * reason.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlEmpty()
          throws Exception
  {
    final GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(null, null, null,
              null);

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


    GetPasswordPolicyStateIssuesResponseControl decodedControl =
         GetPasswordPolicyStateIssuesResponseControl.decodeJSONControl(
              controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getNotices(), Collections.emptyList());

    assertEquals(decodedControl.getWarnings(), Collections.emptyList());

    assertEquals(decodedControl.getErrors(), Collections.emptyList());

    assertNull(decodedControl.getAuthenticationFailureReason());


    decodedControl =
         (GetPasswordPolicyStateIssuesResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getNotices(), Collections.emptyList());

    assertEquals(decodedControl.getWarnings(), Collections.emptyList());

    assertEquals(decodedControl.getErrors(), Collections.emptyList());

    assertNull(decodedControl.getAuthenticationFailureReason());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when all items are populated.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlAllItems()
          throws Exception
  {
    final GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityNotice(
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
                        "The user has a valid retired password")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityWarning(
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_TYPE_ACCOUNT_EXPIRING,
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_NAME_ACCOUNT_EXPIRING,
                        "The account will expire soon")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityError(
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_TYPE_MUST_CHANGE_PASSWORD,
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_NAME_MUST_CHANGE_PASSWORD,
                        "The user must change their password")),
              new AuthenticationFailureReason(
                   AuthenticationFailureReason.FAILURE_TYPE_INVALID_CREDENTIALS,
                   AuthenticationFailureReason.FAILURE_NAME_INVALID_CREDENTIALS,
                   "Wrong password"));

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
              new JSONField("notices", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "outstanding-retired-password"),
                        new JSONField("message",
                             "The user has a valid retired password")))),
              new JSONField("warnings", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "account-expiring"),
                        new JSONField("message",
                             "The account will expire soon")))),
              new JSONField("errors", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 11),
                        new JSONField("name", "must-change-password"),
                        new JSONField("message",
                             "The user must change their password")))),
              new JSONField("authentication-failure-reason", new JSONObject(
                   new JSONField("id", 9),
                   new JSONField("name", "invalid-credentials"),
                   new JSONField("message", "Wrong password")))));


    GetPasswordPolicyStateIssuesResponseControl decodedControl =
         GetPasswordPolicyStateIssuesResponseControl.decodeJSONControl(
              controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getNotices().size(), 1);
    assertEquals(decodedControl.getNotices().get(0).getIntValue(), 1);
    assertEquals(decodedControl.getNotices().get(0).getName(),
         "outstanding-retired-password");
    assertEquals(decodedControl.getNotices().get(0).getMessage(),
         "The user has a valid retired password");

    assertEquals(decodedControl.getWarnings().size(), 1);
    assertEquals(decodedControl.getWarnings().get(0).getIntValue(), 1);
    assertEquals(decodedControl.getWarnings().get(0).getName(),
         "account-expiring");
    assertEquals(decodedControl.getWarnings().get(0).getMessage(),
         "The account will expire soon");

    assertEquals(decodedControl.getErrors().size(), 1);
    assertEquals(decodedControl.getErrors().get(0).getIntValue(), 11);
    assertEquals(decodedControl.getErrors().get(0).getName(),
         "must-change-password");
    assertEquals(decodedControl.getErrors().get(0).getMessage(),
         "The user must change their password");

    assertNotNull(decodedControl.getAuthenticationFailureReason());
    assertEquals(decodedControl.getAuthenticationFailureReason().getIntValue(),
         9);
    assertEquals(decodedControl.getAuthenticationFailureReason().getName(),
         "invalid-credentials");
    assertEquals(decodedControl.getAuthenticationFailureReason().getMessage(),
         "Wrong password");


    decodedControl =
         (GetPasswordPolicyStateIssuesResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getNotices().size(), 1);
    assertEquals(decodedControl.getNotices().get(0).getIntValue(), 1);
    assertEquals(decodedControl.getNotices().get(0).getName(),
         "outstanding-retired-password");
    assertEquals(decodedControl.getNotices().get(0).getMessage(),
         "The user has a valid retired password");

    assertEquals(decodedControl.getWarnings().size(), 1);
    assertEquals(decodedControl.getWarnings().get(0).getIntValue(), 1);
    assertEquals(decodedControl.getWarnings().get(0).getName(),
         "account-expiring");
    assertEquals(decodedControl.getWarnings().get(0).getMessage(),
         "The account will expire soon");

    assertEquals(decodedControl.getErrors().size(), 1);
    assertEquals(decodedControl.getErrors().get(0).getIntValue(), 11);
    assertEquals(decodedControl.getErrors().get(0).getName(),
         "must-change-password");
    assertEquals(decodedControl.getErrors().get(0).getMessage(),
         "The user must change their password");

    assertNotNull(decodedControl.getAuthenticationFailureReason());
    assertEquals(decodedControl.getAuthenticationFailureReason().getIntValue(),
         9);
    assertEquals(decodedControl.getAuthenticationFailureReason().getName(),
         "invalid-credentials");
    assertEquals(decodedControl.getAuthenticationFailureReason().getMessage(),
         "Wrong password");
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is base64-encoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueBase64()
          throws Exception
  {
    final GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityNotice(
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
                        "The user has a valid retired password")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityWarning(
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_TYPE_ACCOUNT_EXPIRING,
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_NAME_ACCOUNT_EXPIRING,
                        "The account will expire soon")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityError(
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_TYPE_MUST_CHANGE_PASSWORD,
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_NAME_MUST_CHANGE_PASSWORD,
                        "The user must change their password")),
              new AuthenticationFailureReason(
                   AuthenticationFailureReason.FAILURE_TYPE_INVALID_CREDENTIALS,
                   AuthenticationFailureReason.FAILURE_NAME_INVALID_CREDENTIALS,
                   "Wrong password"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    GetPasswordPolicyStateIssuesResponseControl decodedControl =
         GetPasswordPolicyStateIssuesResponseControl.decodeJSONControl(
              controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getNotices().size(), 1);
    assertEquals(decodedControl.getNotices().get(0).getIntValue(), 1);
    assertEquals(decodedControl.getNotices().get(0).getName(),
         "outstanding-retired-password");
    assertEquals(decodedControl.getNotices().get(0).getMessage(),
         "The user has a valid retired password");

    assertEquals(decodedControl.getWarnings().size(), 1);
    assertEquals(decodedControl.getWarnings().get(0).getIntValue(), 1);
    assertEquals(decodedControl.getWarnings().get(0).getName(),
         "account-expiring");
    assertEquals(decodedControl.getWarnings().get(0).getMessage(),
         "The account will expire soon");

    assertEquals(decodedControl.getErrors().size(), 1);
    assertEquals(decodedControl.getErrors().get(0).getIntValue(), 11);
    assertEquals(decodedControl.getErrors().get(0).getName(),
         "must-change-password");
    assertEquals(decodedControl.getErrors().get(0).getMessage(),
         "The user must change their password");

    assertNotNull(decodedControl.getAuthenticationFailureReason());
    assertEquals(decodedControl.getAuthenticationFailureReason().getIntValue(),
         9);
    assertEquals(decodedControl.getAuthenticationFailureReason().getName(),
         "invalid-credentials");
    assertEquals(decodedControl.getAuthenticationFailureReason().getMessage(),
         "Wrong password");


    decodedControl =
         (GetPasswordPolicyStateIssuesResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getNotices().size(), 1);
    assertEquals(decodedControl.getNotices().get(0).getIntValue(), 1);
    assertEquals(decodedControl.getNotices().get(0).getName(),
         "outstanding-retired-password");
    assertEquals(decodedControl.getNotices().get(0).getMessage(),
         "The user has a valid retired password");

    assertEquals(decodedControl.getWarnings().size(), 1);
    assertEquals(decodedControl.getWarnings().get(0).getIntValue(), 1);
    assertEquals(decodedControl.getWarnings().get(0).getName(),
         "account-expiring");
    assertEquals(decodedControl.getWarnings().get(0).getMessage(),
         "The account will expire soon");

    assertEquals(decodedControl.getErrors().size(), 1);
    assertEquals(decodedControl.getErrors().get(0).getIntValue(), 11);
    assertEquals(decodedControl.getErrors().get(0).getName(),
         "must-change-password");
    assertEquals(decodedControl.getErrors().get(0).getMessage(),
         "The user must change their password");

    assertNotNull(decodedControl.getAuthenticationFailureReason());
    assertEquals(decodedControl.getAuthenticationFailureReason().getIntValue(),
         9);
    assertEquals(decodedControl.getAuthenticationFailureReason().getName(),
         "invalid-credentials");
    assertEquals(decodedControl.getAuthenticationFailureReason().getMessage(),
         "Wrong password");
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when an
   * account usability notice is missing the required ID field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlNoticeMissingID()
          throws Exception
  {
    final GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityNotice(
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
                        "The user has a valid retired password")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityWarning(
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_TYPE_ACCOUNT_EXPIRING,
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_NAME_ACCOUNT_EXPIRING,
                        "The account will expire soon")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityError(
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_TYPE_MUST_CHANGE_PASSWORD,
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_NAME_MUST_CHANGE_PASSWORD,
                        "The user must change their password")),
              new AuthenticationFailureReason(
                   AuthenticationFailureReason.FAILURE_TYPE_INVALID_CREDENTIALS,
                   AuthenticationFailureReason.FAILURE_NAME_INVALID_CREDENTIALS,
                   "Wrong password"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("notices", new JSONArray(
                   new JSONObject(
                        new JSONField("name", "outstanding-retired-password"),
                        new JSONField("message",
                             "The user has a valid retired password")))),
              new JSONField("warnings", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "account-expiring"),
                        new JSONField("message",
                             "The account will expire soon")))),
              new JSONField("errors", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 11),
                        new JSONField("name", "must-change-password"),
                        new JSONField("message",
                             "The user must change their password")))),
              new JSONField("authentication-failure-reason", new JSONObject(
                   new JSONField("id", 9),
                   new JSONField("name", "invalid-credentials"),
                   new JSONField("message", "Wrong password"))))));

    GetPasswordPolicyStateIssuesResponseControl.decodeJSONControl(controlObject,
         true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when an
   * account usability notice is missing the required name field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlNoticeMissingName()
          throws Exception
  {
    final GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityNotice(
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
                        "The user has a valid retired password")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityWarning(
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_TYPE_ACCOUNT_EXPIRING,
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_NAME_ACCOUNT_EXPIRING,
                        "The account will expire soon")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityError(
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_TYPE_MUST_CHANGE_PASSWORD,
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_NAME_MUST_CHANGE_PASSWORD,
                        "The user must change their password")),
              new AuthenticationFailureReason(
                   AuthenticationFailureReason.FAILURE_TYPE_INVALID_CREDENTIALS,
                   AuthenticationFailureReason.FAILURE_NAME_INVALID_CREDENTIALS,
                   "Wrong password"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("notices", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("message",
                             "The user has a valid retired password")))),
              new JSONField("warnings", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "account-expiring"),
                        new JSONField("message",
                             "The account will expire soon")))),
              new JSONField("errors", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 11),
                        new JSONField("name", "must-change-password"),
                        new JSONField("message",
                             "The user must change their password")))),
              new JSONField("authentication-failure-reason", new JSONObject(
                   new JSONField("id", 9),
                   new JSONField("name", "invalid-credentials"),
                   new JSONField("message", "Wrong password"))))));

    GetPasswordPolicyStateIssuesResponseControl.decodeJSONControl(controlObject,
         true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the set of account usability notices has a value that is not an object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlNoticeNotObject()
          throws Exception
  {
    final GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityNotice(
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
                        "The user has a valid retired password")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityWarning(
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_TYPE_ACCOUNT_EXPIRING,
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_NAME_ACCOUNT_EXPIRING,
                        "The account will expire soon")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityError(
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_TYPE_MUST_CHANGE_PASSWORD,
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_NAME_MUST_CHANGE_PASSWORD,
                        "The user must change their password")),
              new AuthenticationFailureReason(
                   AuthenticationFailureReason.FAILURE_TYPE_INVALID_CREDENTIALS,
                   AuthenticationFailureReason.FAILURE_NAME_INVALID_CREDENTIALS,
                   "Wrong password"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("notices", new JSONArray(
                   new JSONString("foo"))),
              new JSONField("warnings", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "account-expiring"),
                        new JSONField("message",
                             "The account will expire soon")))),
              new JSONField("errors", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 11),
                        new JSONField("name", "must-change-password"),
                        new JSONField("message",
                             "The user must change their password")))),
              new JSONField("authentication-failure-reason", new JSONObject(
                   new JSONField("id", 9),
                   new JSONField("name", "invalid-credentials"),
                   new JSONField("message", "Wrong password"))))));

    GetPasswordPolicyStateIssuesResponseControl.decodeJSONControl(controlObject,
         true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when an
   * account usability warning is missing the required ID field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlWarningMissingID()
          throws Exception
  {
    final GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityNotice(
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
                        "The user has a valid retired password")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityWarning(
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_TYPE_ACCOUNT_EXPIRING,
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_NAME_ACCOUNT_EXPIRING,
                        "The account will expire soon")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityError(
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_TYPE_MUST_CHANGE_PASSWORD,
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_NAME_MUST_CHANGE_PASSWORD,
                        "The user must change their password")),
              new AuthenticationFailureReason(
                   AuthenticationFailureReason.FAILURE_TYPE_INVALID_CREDENTIALS,
                   AuthenticationFailureReason.FAILURE_NAME_INVALID_CREDENTIALS,
                   "Wrong password"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("notices", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "outstanding-retired-password"),
                        new JSONField("message",
                             "The user has a valid retired password")))),
              new JSONField("warnings", new JSONArray(
                   new JSONObject(
                        new JSONField("name", "account-expiring"),
                        new JSONField("message",
                             "The account will expire soon")))),
              new JSONField("errors", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 11),
                        new JSONField("name", "must-change-password"),
                        new JSONField("message",
                             "The user must change their password")))),
              new JSONField("authentication-failure-reason", new JSONObject(
                   new JSONField("id", 9),
                   new JSONField("name", "invalid-credentials"),
                   new JSONField("message", "Wrong password"))))));

    GetPasswordPolicyStateIssuesResponseControl.decodeJSONControl(controlObject,
         true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when an
   * account usability warning is missing the required name field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlWarningMissingName()
          throws Exception
  {
    final GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityNotice(
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
                        "The user has a valid retired password")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityWarning(
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_TYPE_ACCOUNT_EXPIRING,
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_NAME_ACCOUNT_EXPIRING,
                        "The account will expire soon")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityError(
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_TYPE_MUST_CHANGE_PASSWORD,
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_NAME_MUST_CHANGE_PASSWORD,
                        "The user must change their password")),
              new AuthenticationFailureReason(
                   AuthenticationFailureReason.FAILURE_TYPE_INVALID_CREDENTIALS,
                   AuthenticationFailureReason.FAILURE_NAME_INVALID_CREDENTIALS,
                   "Wrong password"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("notices", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "outstanding-retired-password"),
                        new JSONField("message",
                             "The user has a valid retired password")))),
              new JSONField("warnings", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("message",
                             "The account will expire soon")))),
              new JSONField("errors", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 11),
                        new JSONField("name", "must-change-password"),
                        new JSONField("message",
                             "The user must change their password")))),
              new JSONField("authentication-failure-reason", new JSONObject(
                   new JSONField("id", 9),
                   new JSONField("name", "invalid-credentials"),
                   new JSONField("message", "Wrong password"))))));

    GetPasswordPolicyStateIssuesResponseControl.decodeJSONControl(controlObject,
         true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the set of account usability warnings has a value that is not an object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlWarningNotObject()
          throws Exception
  {
    final GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityNotice(
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
                        "The user has a valid retired password")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityWarning(
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_TYPE_ACCOUNT_EXPIRING,
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_NAME_ACCOUNT_EXPIRING,
                        "The account will expire soon")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityError(
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_TYPE_MUST_CHANGE_PASSWORD,
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_NAME_MUST_CHANGE_PASSWORD,
                        "The user must change their password")),
              new AuthenticationFailureReason(
                   AuthenticationFailureReason.FAILURE_TYPE_INVALID_CREDENTIALS,
                   AuthenticationFailureReason.FAILURE_NAME_INVALID_CREDENTIALS,
                   "Wrong password"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("notices", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "outstanding-retired-password"),
                        new JSONField("message",
                             "The user has a valid retired password")))),
              new JSONField("warnings", new JSONArray(
                   new JSONString("foo"))),
              new JSONField("errors", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 11),
                        new JSONField("name", "must-change-password"),
                        new JSONField("message",
                             "The user must change their password")))),
              new JSONField("authentication-failure-reason", new JSONObject(
                   new JSONField("id", 9),
                   new JSONField("name", "invalid-credentials"),
                   new JSONField("message", "Wrong password"))))));

    GetPasswordPolicyStateIssuesResponseControl.decodeJSONControl(controlObject,
         true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when an
   * account usability error is missing the required ID field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlErrorMissingID()
          throws Exception
  {
    final GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityNotice(
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
                        "The user has a valid retired password")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityWarning(
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_TYPE_ACCOUNT_EXPIRING,
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_NAME_ACCOUNT_EXPIRING,
                        "The account will expire soon")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityError(
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_TYPE_MUST_CHANGE_PASSWORD,
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_NAME_MUST_CHANGE_PASSWORD,
                        "The user must change their password")),
              new AuthenticationFailureReason(
                   AuthenticationFailureReason.FAILURE_TYPE_INVALID_CREDENTIALS,
                   AuthenticationFailureReason.FAILURE_NAME_INVALID_CREDENTIALS,
                   "Wrong password"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("notices", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "outstanding-retired-password"),
                        new JSONField("message",
                             "The user has a valid retired password")))),
              new JSONField("warnings", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "account-expiring"),
                        new JSONField("message",
                             "The account will expire soon")))),
              new JSONField("errors", new JSONArray(
                   new JSONObject(
                        new JSONField("name", "must-change-password"),
                        new JSONField("message",
                             "The user must change their password")))),
              new JSONField("authentication-failure-reason", new JSONObject(
                   new JSONField("id", 9),
                   new JSONField("name", "invalid-credentials"),
                   new JSONField("message", "Wrong password"))))));

    GetPasswordPolicyStateIssuesResponseControl.decodeJSONControl(controlObject,
         true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when an
   * account usability error is missing the required name field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlErrorMissingName()
          throws Exception
  {
    final GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityNotice(
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
                        "The user has a valid retired password")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityWarning(
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_TYPE_ACCOUNT_EXPIRING,
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_NAME_ACCOUNT_EXPIRING,
                        "The account will expire soon")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityError(
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_TYPE_MUST_CHANGE_PASSWORD,
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_NAME_MUST_CHANGE_PASSWORD,
                        "The user must change their password")),
              new AuthenticationFailureReason(
                   AuthenticationFailureReason.FAILURE_TYPE_INVALID_CREDENTIALS,
                   AuthenticationFailureReason.FAILURE_NAME_INVALID_CREDENTIALS,
                   "Wrong password"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("notices", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "outstanding-retired-password"),
                        new JSONField("message",
                             "The user has a valid retired password")))),
              new JSONField("warnings", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "account-expiring"),
                        new JSONField("message",
                             "The account will expire soon")))),
              new JSONField("errors", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 11),
                        new JSONField("message",
                             "The user must change their password")))),
              new JSONField("authentication-failure-reason", new JSONObject(
                   new JSONField("id", 9),
                   new JSONField("name", "invalid-credentials"),
                   new JSONField("message", "Wrong password"))))));

    GetPasswordPolicyStateIssuesResponseControl.decodeJSONControl(controlObject,
         true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the set of account usability errors has a value that is not an object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlErrorNotObject()
          throws Exception
  {
    final GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityNotice(
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
                        "The user has a valid retired password")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityWarning(
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_TYPE_ACCOUNT_EXPIRING,
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_NAME_ACCOUNT_EXPIRING,
                        "The account will expire soon")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityError(
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_TYPE_MUST_CHANGE_PASSWORD,
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_NAME_MUST_CHANGE_PASSWORD,
                        "The user must change their password")),
              new AuthenticationFailureReason(
                   AuthenticationFailureReason.FAILURE_TYPE_INVALID_CREDENTIALS,
                   AuthenticationFailureReason.FAILURE_NAME_INVALID_CREDENTIALS,
                   "Wrong password"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("notices", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "outstanding-retired-password"),
                        new JSONField("message",
                             "The user has a valid retired password")))),
              new JSONField("warnings", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "account-expiring"),
                        new JSONField("message",
                             "The account will expire soon")))),
              new JSONField("errors", new JSONArray(
                   new JSONString("foo"))),
              new JSONField("authentication-failure-reason", new JSONObject(
                   new JSONField("id", 9),
                   new JSONField("name", "invalid-credentials"),
                   new JSONField("message", "Wrong password"))))));

    GetPasswordPolicyStateIssuesResponseControl.decodeJSONControl(controlObject,
         true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the authentication failure reason is missing the required ID field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlAuthFailureReasonMissingID()
          throws Exception
  {
    final GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityNotice(
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
                        "The user has a valid retired password")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityWarning(
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_TYPE_ACCOUNT_EXPIRING,
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_NAME_ACCOUNT_EXPIRING,
                        "The account will expire soon")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityError(
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_TYPE_MUST_CHANGE_PASSWORD,
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_NAME_MUST_CHANGE_PASSWORD,
                        "The user must change their password")),
              new AuthenticationFailureReason(
                   AuthenticationFailureReason.FAILURE_TYPE_INVALID_CREDENTIALS,
                   AuthenticationFailureReason.FAILURE_NAME_INVALID_CREDENTIALS,
                   "Wrong password"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("notices", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "outstanding-retired-password"),
                        new JSONField("message",
                             "The user has a valid retired password")))),
              new JSONField("warnings", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "account-expiring"),
                        new JSONField("message",
                             "The account will expire soon")))),
              new JSONField("errors", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 11),
                        new JSONField("name", "must-change-password"),
                        new JSONField("message",
                             "The user must change their password")))),
              new JSONField("authentication-failure-reason", new JSONObject(
                   new JSONField("name", "invalid-credentials"),
                   new JSONField("message", "Wrong password"))))));

    GetPasswordPolicyStateIssuesResponseControl.decodeJSONControl(controlObject,
         true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the authentication failure reason is missing the required name field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlAuthFailureReasonMissingName()
          throws Exception
  {
    final GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityNotice(
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
                        "The user has a valid retired password")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityWarning(
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_TYPE_ACCOUNT_EXPIRING,
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_NAME_ACCOUNT_EXPIRING,
                        "The account will expire soon")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityError(
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_TYPE_MUST_CHANGE_PASSWORD,
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_NAME_MUST_CHANGE_PASSWORD,
                        "The user must change their password")),
              new AuthenticationFailureReason(
                   AuthenticationFailureReason.FAILURE_TYPE_INVALID_CREDENTIALS,
                   AuthenticationFailureReason.FAILURE_NAME_INVALID_CREDENTIALS,
                   "Wrong password"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("notices", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "outstanding-retired-password"),
                        new JSONField("message",
                             "The user has a valid retired password")))),
              new JSONField("warnings", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "account-expiring"),
                        new JSONField("message",
                             "The account will expire soon")))),
              new JSONField("errors", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 11),
                        new JSONField("name", "must-change-password"),
                        new JSONField("message",
                             "The user must change their password")))),
              new JSONField("authentication-failure-reason", new JSONObject(
                   new JSONField("id", 9),
                   new JSONField("message", "Wrong password"))))));

    GetPasswordPolicyStateIssuesResponseControl.decodeJSONControl(controlObject,
         true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlUnrecognizedFieldStrict()
          throws Exception
  {
    final GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityNotice(
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
                        "The user has a valid retired password")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityWarning(
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_TYPE_ACCOUNT_EXPIRING,
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_NAME_ACCOUNT_EXPIRING,
                        "The account will expire soon")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityError(
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_TYPE_MUST_CHANGE_PASSWORD,
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_NAME_MUST_CHANGE_PASSWORD,
                        "The user must change their password")),
              new AuthenticationFailureReason(
                   AuthenticationFailureReason.FAILURE_TYPE_INVALID_CREDENTIALS,
                   AuthenticationFailureReason.FAILURE_NAME_INVALID_CREDENTIALS,
                   "Wrong password"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("notices", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "outstanding-retired-password"),
                        new JSONField("message",
                             "The user has a valid retired password")))),
              new JSONField("warnings", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "account-expiring"),
                        new JSONField("message",
                             "The account will expire soon")))),
              new JSONField("errors", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 11),
                        new JSONField("name", "must-change-password"),
                        new JSONField("message",
                             "The user must change their password")))),
              new JSONField("authentication-failure-reason", new JSONObject(
                   new JSONField("id", 9),
                   new JSONField("name", "invalid-credentials"),
                   new JSONField("message", "Wrong password"))),
              new JSONField("unrecognized", "foo"))));

    GetPasswordPolicyStateIssuesResponseControl.decodeJSONControl(controlObject,
         true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlUnrecognizedFieldNonStrict()
          throws Exception
  {
    final GetPasswordPolicyStateIssuesResponseControl c =
         new GetPasswordPolicyStateIssuesResponseControl(
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityNotice(
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD,
                        PasswordPolicyStateAccountUsabilityNotice.
                             NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD,
                        "The user has a valid retired password")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityWarning(
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_TYPE_ACCOUNT_EXPIRING,
                        PasswordPolicyStateAccountUsabilityWarning.
                             WARNING_NAME_ACCOUNT_EXPIRING,
                        "The account will expire soon")),
              Collections.singletonList(
                   new PasswordPolicyStateAccountUsabilityError(
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_TYPE_MUST_CHANGE_PASSWORD,
                        PasswordPolicyStateAccountUsabilityError.
                             ERROR_NAME_MUST_CHANGE_PASSWORD,
                        "The user must change their password")),
              new AuthenticationFailureReason(
                   AuthenticationFailureReason.FAILURE_TYPE_INVALID_CREDENTIALS,
                   AuthenticationFailureReason.FAILURE_NAME_INVALID_CREDENTIALS,
                   "Wrong password"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("notices", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "outstanding-retired-password"),
                        new JSONField("message",
                             "The user has a valid retired password")))),
              new JSONField("warnings", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 1),
                        new JSONField("name", "account-expiring"),
                        new JSONField("message",
                             "The account will expire soon")))),
              new JSONField("errors", new JSONArray(
                   new JSONObject(
                        new JSONField("id", 11),
                        new JSONField("name", "must-change-password"),
                        new JSONField("message",
                             "The user must change their password")))),
              new JSONField("authentication-failure-reason", new JSONObject(
                   new JSONField("id", 9),
                   new JSONField("name", "invalid-credentials"),
                   new JSONField("message", "Wrong password"))),
              new JSONField("unrecognized", "foo"))));


    GetPasswordPolicyStateIssuesResponseControl decodedControl =
         GetPasswordPolicyStateIssuesResponseControl.decodeJSONControl(
              controlObject, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getNotices().size(), 1);
    assertEquals(decodedControl.getNotices().get(0).getIntValue(), 1);
    assertEquals(decodedControl.getNotices().get(0).getName(),
         "outstanding-retired-password");
    assertEquals(decodedControl.getNotices().get(0).getMessage(),
         "The user has a valid retired password");

    assertEquals(decodedControl.getWarnings().size(), 1);
    assertEquals(decodedControl.getWarnings().get(0).getIntValue(), 1);
    assertEquals(decodedControl.getWarnings().get(0).getName(),
         "account-expiring");
    assertEquals(decodedControl.getWarnings().get(0).getMessage(),
         "The account will expire soon");

    assertEquals(decodedControl.getErrors().size(), 1);
    assertEquals(decodedControl.getErrors().get(0).getIntValue(), 11);
    assertEquals(decodedControl.getErrors().get(0).getName(),
         "must-change-password");
    assertEquals(decodedControl.getErrors().get(0).getMessage(),
         "The user must change their password");

    assertNotNull(decodedControl.getAuthenticationFailureReason());
    assertEquals(decodedControl.getAuthenticationFailureReason().getIntValue(),
         9);
    assertEquals(decodedControl.getAuthenticationFailureReason().getName(),
         "invalid-credentials");
    assertEquals(decodedControl.getAuthenticationFailureReason().getMessage(),
         "Wrong password");


    decodedControl =
         (GetPasswordPolicyStateIssuesResponseControl)
         Control.decodeJSONControl(controlObject, false, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getNotices().size(), 1);
    assertEquals(decodedControl.getNotices().get(0).getIntValue(), 1);
    assertEquals(decodedControl.getNotices().get(0).getName(),
         "outstanding-retired-password");
    assertEquals(decodedControl.getNotices().get(0).getMessage(),
         "The user has a valid retired password");

    assertEquals(decodedControl.getWarnings().size(), 1);
    assertEquals(decodedControl.getWarnings().get(0).getIntValue(), 1);
    assertEquals(decodedControl.getWarnings().get(0).getName(),
         "account-expiring");
    assertEquals(decodedControl.getWarnings().get(0).getMessage(),
         "The account will expire soon");

    assertEquals(decodedControl.getErrors().size(), 1);
    assertEquals(decodedControl.getErrors().get(0).getIntValue(), 11);
    assertEquals(decodedControl.getErrors().get(0).getName(),
         "must-change-password");
    assertEquals(decodedControl.getErrors().get(0).getMessage(),
         "The user must change their password");

    assertNotNull(decodedControl.getAuthenticationFailureReason());
    assertEquals(decodedControl.getAuthenticationFailureReason().getIntValue(),
         9);
    assertEquals(decodedControl.getAuthenticationFailureReason().getName(),
         "invalid-credentials");
    assertEquals(decodedControl.getAuthenticationFailureReason().getMessage(),
         "Wrong password");
  }
}
