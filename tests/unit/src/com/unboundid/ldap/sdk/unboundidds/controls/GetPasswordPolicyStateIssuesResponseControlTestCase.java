/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
}
