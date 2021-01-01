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
package com.unboundid.ldap.sdk.unboundidds;



import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.controls.RecentLoginHistory;
import com.unboundid.ldap.sdk.unboundidds.controls.RecentLoginHistoryAttempt;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityError;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityNotice;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityWarning;
import com.unboundid.ldap.sdk.unboundidds.extensions.PasswordQualityRequirement;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.PasswordPolicyStateJSONField.*;



/**
 * This class provides a set of test cases for the
 * {@code PasswordPolicyStateJSON} enum.
 */
public final class PasswordPolicyStateJSONTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when trying to retrieve the password policy state JSON
   * object for a user that does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetNoSuchUser()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    try (LDAPConnection connection = ds.getConnection())
    {
      try
      {
        PasswordPolicyStateJSON.get(connection,
             "uid=missing,ou=People,dc=example,dc=com");
        fail("Expected an exception when trying to retrieve password policy " +
             "state information for a user that does not exist.");
      }
      catch (final LDAPException e)
      {
        assertEquals(e.getResultCode(), ResultCode.NO_SUCH_OBJECT);
        assertNotNull(e.getMessage());
        assertFalse(e.getMessage().isEmpty());
      }
    }
  }



  /**
   * Tests the behavior when trying to retrieve the password policy state JSON
   * object for a user that exists but whose entry does not include the
   * ds-pwp-state-json attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetNoSuchAttribute()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    try (LDAPConnection connection = ds.getConnection())
    {
      assertNull(PasswordPolicyStateJSON.get(connection,
           "uid=test.user,ou=People,dc=example,dc=com"));
    }
  }



  /**
   * Tests the behavior when trying to retrieve the password policy state JSON
   * object for a user that exists and whose entry contains the
   * ds-pwp-state-json attribute with a value that is not a valid JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValueNotJSON()
         throws Exception
  {
    final Entry entry = new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "ds-pwp-state-json: this-is-not-a-valid-json-object");


    try
    {
      PasswordPolicyStateJSON.get(entry);
      fail("Expected an exception when trying to retrieve password policy " +
           "state information for a user with a malformed value.");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
      assertNotNull(e.getMessage());
      assertFalse(e.getMessage().isEmpty());
    }
  }



  /**
   * Tests the behavior when trying to retrieve the password policy state JSON
   * object for a user that exists and whose entry contains the
   * ds-pwp-state-json attribute with a value that is an empty JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValueEmptyJSONObject()
         throws Exception
  {
    final Entry entry = new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "ds-pwp-state-json: {}");


    final PasswordPolicyStateJSON state = PasswordPolicyStateJSON.get(entry);
    assertNotNull(state);

    assertNotNull(state.getPasswordPolicyStateJSONObject());
    assertTrue(state.getPasswordPolicyStateJSONObject().getFields().isEmpty());

    assertNull(state.getPasswordPolicyDN());

    assertNull(state.getAccountIsUsable());

    assertNotNull(state.getAccountUsabilityErrors());
    assertTrue(state.getAccountUsabilityErrors().isEmpty());

    assertNotNull(state.getAccountUsabilityWarnings());
    assertTrue(state.getAccountUsabilityWarnings().isEmpty());

    assertNotNull(state.getAccountUsabilityNotices());
    assertTrue(state.getAccountUsabilityNotices().isEmpty());

    assertNull(state.getHasStaticPassword());

    assertNull(state.getPasswordChangedTime());

    assertNull(state.getSecondsSincePasswordChange());

    assertNull(state.getAccountIsDisabled());

    assertNull(state.getAccountIsNotYetActive());

    assertNull(state.getAccountActivationTime());

    assertNull(state.getSecondsUntilAccountActivation());

    assertNull(state.getSecondsSinceAccountActivation());

    assertNull(state.getAccountIsExpired());

    assertNull(state.getAccountExpirationTime());

    assertNull(state.getSecondsUntilAccountExpiration());

    assertNull(state.getSecondsSinceAccountExpiration());

    assertNull(state.getPasswordIsExpired());

    assertNull(state.getMaximumPasswordAgeSeconds());

    assertNull(state.getPasswordExpirationTime());

    assertNull(state.getSecondsUntilPasswordExpiration());

    assertNull(state.getSecondsSincePasswordExpiration());

    assertNull(state.getPasswordExpirationWarningIntervalSeconds());

    assertNull(state.getExpirePasswordsWithoutWarning());

    assertNull(state.getPasswordExpirationWarningIssued());

    assertNull(state.getPasswordExpirationWarningTime());

    assertNull(state.getSecondsUntilPasswordExpirationWarning());

    assertNull(state.getSecondsSincePasswordExpirationWarning());

    assertNull(state.getAccountIsFailureLocked());

    assertNull(state.getFailureLockoutCount());

    assertNull(state.getCurrentAuthenticationFailureCount());

    assertNull(state.getRemainingAuthenticationFailureCount());

    assertNotNull(state.getAuthenticationFailureTimes());
    assertTrue(state.getAuthenticationFailureTimes().isEmpty());

    assertNull(state.getFailureLockoutTime());

    assertNull(state.getFailureLockoutDurationSeconds());

    assertNull(state.getFailureLockoutExpirationTime());

    assertNull(state.getSecondsRemainingInFailureLockout());

    assertNull(state.getLastLoginTime());

    assertNull(state.getSecondsSinceLastLogin());

    assertNull(state.getLastLoginIPAddress());

    assertNull(state.getAccountIsIdleLocked());

    assertNull(state.getIdleLockoutIntervalSeconds());

    assertNull(state.getIdleLockoutTime());

    assertNull(state.getSecondsUntilIdleLockout());

    assertNull(state.getSecondsSinceIdleLockout());

    assertNull(state.getMustChangePassword());

    assertNull(state.getAccountIsResetLocked());

    assertNull(state.getForceChangeOnAdd());

    assertNull(state.getForceChangeOnReset());

    assertNull(state.getMaximumPasswordResetAgeSeconds());

    assertNull(state.getResetLockoutTime());

    assertNull(state.getSecondsUntilResetLockout());

    assertNull(state.getMaximumPasswordHistoryCount());

    assertNull(state.getMaximumPasswordHistoryDurationSeconds());

    assertNull(state.getCurrentPasswordHistoryCount());

    assertNull(state.getIsWithinMinimumPasswordAge());

    assertNull(state.getMinimumPasswordAgeSeconds());

    assertNull(state.getMinimumPasswordAgeExpirationTime());

    assertNull(state.getSecondsRemainingInMinimumPasswordAge());

    assertNull(state.getMaximumGraceLoginCount());

    assertNull(state.getUsedGraceLoginCount());

    assertNull(state.getRemainingGraceLoginCount());

    assertNotNull(state.getGraceLoginUseTimes());
    assertTrue(state.getGraceLoginUseTimes().isEmpty());

    assertNull(state.getHasRetiredPassword());

    assertNull(state.getRetiredPasswordExpirationTime());

    assertNull(state.getSecondsUntilRetiredPasswordExpiration());

    assertNull(state.getRequireSecureAuthentication());

    assertNull(state.getRequireSecurePasswordChanges());

    assertNotNull(state.getAvailableSASLMechanisms());
    assertTrue(state.getAvailableSASLMechanisms().isEmpty());

    assertNotNull(state.getAvailableOTPDeliveryMechanisms());
    assertTrue(state.getAvailableOTPDeliveryMechanisms().isEmpty());

    assertNull(state.getHasTOTPSharedSecret());

    assertNull(state.getHasRegisteredYubiKeyOTPDevice());

    assertNull(state.getAccountIsValidationLocked());

    assertNull(state.getLastBindPasswordValidationTime());

    assertNull(state.getSecondsSinceLastBindPasswordValidation());

    assertNull(state.getMinimumBindPasswordValidationFrequencySeconds());

    assertNull(state.getBindPasswordValidationFailureAction());

    assertNull(state.getRecentLoginHistory());

    assertNull(
         state.getMaximumRecentLoginHistorySuccessfulAuthenticationCount());

    assertNull(state.
         getMaximumRecentLoginHistorySuccessfulAuthenticationDurationSeconds());

    assertNull(state.getMaximumRecentLoginHistoryFailedAuthenticationCount());

    assertNull(state.
         getMaximumRecentLoginHistoryFailedAuthenticationDurationSeconds());

    assertNotNull(state.getAddPasswordQualityRequirements());
    assertTrue(state.getAddPasswordQualityRequirements().isEmpty());

    assertNotNull(state.getSelfChangePasswordQualityRequirements());
    assertTrue(state.getSelfChangePasswordQualityRequirements().isEmpty());

    assertNotNull(state.getAdministrativeResetPasswordQualityRequirements());
    assertTrue(state.getAdministrativeResetPasswordQualityRequirements().
         isEmpty());

    assertNotNull(state.getBindPasswordQualityRequirements());
    assertTrue(state.getBindPasswordQualityRequirements().isEmpty());

    assertNotNull(state.toString());
    assertFalse(state.toString().isEmpty());
  }



  /**
   * Tests the behavior for the property used to hold the DN of the user's
   * password policy.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordPolicyDN()
         throws Exception
  {
    final String policyDN =
         "cn=Default Password Policy,cn=Password Policies,cn=config";

    final PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         PASSWORD_POLICY_DN, policyDN));

    assertNotNull(state.getPasswordPolicyDN());
    assertDNsEqual(state.getPasswordPolicyDN(), policyDN);
  }



  /**
   * Tests the behavior for the properties related to account usability when the
   * account is usable and there are no usability errors, warnings, or notices.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAccountUsabilityIsUsable()
         throws Exception
  {
    final List<PasswordPolicyStateAccountUsabilityError> errors =
         Collections.emptyList();
    final List<PasswordPolicyStateAccountUsabilityWarning> warnings =
         Collections.emptyList();
    final List<PasswordPolicyStateAccountUsabilityNotice> notices =
         Collections.emptyList();

    final PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         ACCOUNT_IS_USABLE, true,
         ACCOUNT_USABILITY_ERRORS, errors,
         ACCOUNT_USABILITY_WARNINGS, warnings,
         ACCOUNT_USABILITY_NOTICES, notices));

    assertNotNull(state.getAccountIsUsable());
    assertEquals(state.getAccountIsUsable(), Boolean.TRUE);

    assertNotNull(state.getAccountUsabilityErrors());
    assertTrue(state.getAccountUsabilityErrors().isEmpty());

    assertNotNull(state.getAccountUsabilityWarnings());
    assertTrue(state.getAccountUsabilityWarnings().isEmpty());

    assertNotNull(state.getAccountUsabilityNotices());
    assertTrue(state.getAccountUsabilityNotices().isEmpty());
  }



  /**
   * Tests the behavior for the properties related to account usability when the
   * account is not and there are multiple usability errors, warnings, and
   * notices.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAccountUsabilityIsNotUsable()
         throws Exception
  {
    final List<PasswordPolicyStateAccountUsabilityError> errors =
         Arrays.asList(
              new PasswordPolicyStateAccountUsabilityError(
                   PasswordPolicyStateAccountUsabilityError.
                        ERROR_TYPE_ACCOUNT_DISABLED,
                   PasswordPolicyStateAccountUsabilityError.
                        ERROR_NAME_ACCOUNT_DISABLED,
                   null),
              new PasswordPolicyStateAccountUsabilityError(
                   PasswordPolicyStateAccountUsabilityError.
                        ERROR_TYPE_ACCOUNT_EXPIRED,
                   PasswordPolicyStateAccountUsabilityError.
                        ERROR_NAME_ACCOUNT_EXPIRED,
                   "The account expired a while ago."));

    final List<PasswordPolicyStateAccountUsabilityWarning> warnings =
         Arrays.asList(
              new PasswordPolicyStateAccountUsabilityWarning(
                   PasswordPolicyStateAccountUsabilityWarning.
                        WARNING_TYPE_ACCOUNT_IDLE,
                   PasswordPolicyStateAccountUsabilityWarning.
                        WARNING_NAME_ACCOUNT_IDLE,
                   null),
              new PasswordPolicyStateAccountUsabilityWarning(
                   PasswordPolicyStateAccountUsabilityWarning.
                        WARNING_TYPE_OUTSTANDING_BIND_FAILURES,
                   PasswordPolicyStateAccountUsabilityWarning.
                        WARNING_NAME_OUTSTANDING_BIND_FAILURES,
                   "The account has outstanding bind failures."));

    final List<PasswordPolicyStateAccountUsabilityNotice> notices =
         Arrays.asList(
              new PasswordPolicyStateAccountUsabilityNotice(
                   PasswordPolicyStateAccountUsabilityNotice.
                        NOTICE_TYPE_NO_STATIC_PASSWORD,
                   PasswordPolicyStateAccountUsabilityNotice.
                        NOTICE_NAME_NO_STATIC_PASSWORD,
                   null),
              new PasswordPolicyStateAccountUsabilityNotice(
                   PasswordPolicyStateAccountUsabilityNotice.
                        NOTICE_TYPE_IN_MINIMUM_PASSWORD_AGE,
                   PasswordPolicyStateAccountUsabilityNotice.
                        NOTICE_NAME_IN_MINIMUM_PASSWORD_AGE,
                   "You can't change your password again for a while."));

    final PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         ACCOUNT_IS_USABLE, false,
         ACCOUNT_USABILITY_ERRORS, errors,
         ACCOUNT_USABILITY_WARNINGS, warnings,
         ACCOUNT_USABILITY_NOTICES, notices));

    assertNotNull(state.getAccountIsUsable());
    assertEquals(state.getAccountIsUsable(), Boolean.FALSE);


    assertNotNull(state.getAccountUsabilityErrors());
    assertFalse(state.getAccountUsabilityErrors().isEmpty());
    assertEquals(state.getAccountUsabilityErrors().size(), 2);

    final PasswordPolicyStateAccountUsabilityError e1 =
         state.getAccountUsabilityErrors().get(0);
    assertEquals(e1.getIntValue(),
         PasswordPolicyStateAccountUsabilityError.ERROR_TYPE_ACCOUNT_DISABLED);
    assertEquals(e1.getName(),
         PasswordPolicyStateAccountUsabilityError.ERROR_NAME_ACCOUNT_DISABLED);
    assertNull(e1.getMessage());

    final PasswordPolicyStateAccountUsabilityError e2 =
         state.getAccountUsabilityErrors().get(1);
    assertEquals(e2.getIntValue(),
         PasswordPolicyStateAccountUsabilityError.ERROR_TYPE_ACCOUNT_EXPIRED);
    assertEquals(e2.getName(),
         PasswordPolicyStateAccountUsabilityError.ERROR_NAME_ACCOUNT_EXPIRED);
    assertNotNull(e2.getMessage());
    assertEquals(e2.getMessage(), "The account expired a while ago.");


    assertNotNull(state.getAccountUsabilityWarnings());
    assertFalse(state.getAccountUsabilityWarnings().isEmpty());
    assertEquals(state.getAccountUsabilityWarnings().size(), 2);

    final PasswordPolicyStateAccountUsabilityWarning w1 =
         state.getAccountUsabilityWarnings().get(0);
    assertEquals(w1.getIntValue(),
         PasswordPolicyStateAccountUsabilityWarning.WARNING_TYPE_ACCOUNT_IDLE);
    assertEquals(w1.getName(),
         PasswordPolicyStateAccountUsabilityWarning.WARNING_NAME_ACCOUNT_IDLE);
    assertNull(w1.getMessage());

    final PasswordPolicyStateAccountUsabilityWarning w2 =
         state.getAccountUsabilityWarnings().get(1);
    assertEquals(w2.getIntValue(),
         PasswordPolicyStateAccountUsabilityWarning.
              WARNING_TYPE_OUTSTANDING_BIND_FAILURES);
    assertEquals(w2.getName(),
         PasswordPolicyStateAccountUsabilityWarning.
              WARNING_NAME_OUTSTANDING_BIND_FAILURES);
    assertNotNull(w2.getMessage());
    assertEquals(w2.getMessage(), "The account has outstanding bind failures.");


    assertNotNull(state.getAccountUsabilityNotices());
    assertFalse(state.getAccountUsabilityNotices().isEmpty());
    assertEquals(state.getAccountUsabilityNotices().size(), 2);

    final PasswordPolicyStateAccountUsabilityNotice n1 =
         state.getAccountUsabilityNotices().get(0);
    assertEquals(n1.getIntValue(),
         PasswordPolicyStateAccountUsabilityNotice.
              NOTICE_TYPE_NO_STATIC_PASSWORD);
    assertEquals(n1.getName(),
         PasswordPolicyStateAccountUsabilityNotice.
              NOTICE_NAME_NO_STATIC_PASSWORD);
    assertNull(n1.getMessage());

    final PasswordPolicyStateAccountUsabilityNotice n2 =
         state.getAccountUsabilityNotices().get(1);
    assertEquals(n2.getIntValue(),
         PasswordPolicyStateAccountUsabilityNotice.
              NOTICE_TYPE_IN_MINIMUM_PASSWORD_AGE);
    assertEquals(n2.getName(),
         PasswordPolicyStateAccountUsabilityNotice.
              NOTICE_NAME_IN_MINIMUM_PASSWORD_AGE);
    assertNotNull(n2.getMessage());
    assertEquals(n2.getMessage(),
         "You can't change your password again for a while.");
  }



  /**
   * Tests the behavior for the properties related to account usability when the
   * errors, warnings, and notices are all empty objects.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyAccountUsabilityObjects()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField(ACCOUNT_USABILITY_ERRORS.getFieldName(),
              new JSONArray(JSONObject.EMPTY_OBJECT)),
         new JSONField(ACCOUNT_USABILITY_WARNINGS.getFieldName(),
              new JSONArray(JSONObject.EMPTY_OBJECT)),
         new JSONField(ACCOUNT_USABILITY_NOTICES.getFieldName(),
              new JSONArray(JSONObject.EMPTY_OBJECT)));

    final Entry entry = new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User");
    entry.addAttribute("ds-pwp-state-json", o.toSingleLineString());

    final PasswordPolicyStateJSON state = PasswordPolicyStateJSON.get(entry);
    assertNotNull(state);

    assertNotNull(state.getAccountUsabilityErrors());
    assertTrue(state.getAccountUsabilityErrors().isEmpty());

    assertNotNull(state.getAccountUsabilityWarnings());
    assertTrue(state.getAccountUsabilityWarnings().isEmpty());

    assertNotNull(state.getAccountUsabilityNotices());
    assertTrue(state.getAccountUsabilityNotices().isEmpty());
  }



  /**
   * Tests the behavior for the properties related to the presence of a password
   * and when it was changed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordPresenceAndChangeFields()
         throws Exception
  {
    final Date currentDate = new Date();
    final Date tenMinutesAgo = new Date(currentDate.getTime() - 600_000L);

    final PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         HAS_STATIC_PASSWORD, true,
         PASSWORD_CHANGED_TIME, tenMinutesAgo,
         SECONDS_SINCE_PASSWORD_CHANGE, 600));

    assertNotNull(state.getHasStaticPassword());
    assertTrue(state.getHasStaticPassword().booleanValue());

    assertNotNull(state.getPasswordChangedTime());
    assertEquals(state.getPasswordChangedTime(), tenMinutesAgo);

    assertNotNull(state.getSecondsSincePasswordChange());
    assertEquals(state.getSecondsSincePasswordChange().intValue(), 600);
  }



  /**
   * Tests the behavior for the properties related to an account's
   * enabled/disabled state.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAccountIsDisabled()
         throws Exception
  {
    PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         ACCOUNT_IS_DISABLED, true));

    assertNotNull(state.getAccountIsDisabled());
    assertTrue(state.getAccountIsDisabled().booleanValue());


    state = createState(StaticUtils.mapOf(
         ACCOUNT_IS_DISABLED, false));

    assertNotNull(state.getAccountIsDisabled());
    assertFalse(state.getAccountIsDisabled().booleanValue());
  }



  /**
   * Tests the behavior for the properties related to account activation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAccountActivation()
         throws Exception
  {
    final Date currentDate = new Date();
    final Date tenMinutesFromNow = new Date(currentDate.getTime() + 600_000L);

    PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         ACCOUNT_IS_NOT_YET_ACTIVE, true,
         ACCOUNT_ACTIVATION_TIME, tenMinutesFromNow,
         SECONDS_UNTIL_ACCOUNT_ACTIVATION, 600));

    assertNotNull(state.getAccountIsNotYetActive());
    assertTrue(state.getAccountIsNotYetActive().booleanValue());

    assertNotNull(state.getAccountActivationTime());
    assertEquals(state.getAccountActivationTime(), tenMinutesFromNow);

    assertNotNull(state.getSecondsUntilAccountActivation());
    assertEquals(state.getSecondsUntilAccountActivation().intValue(), 600);

    assertNull(state.getSecondsSinceAccountActivation());


    final Date fiveMinutesAgo = new Date(currentDate.getTime() - 300_000L);

    state = createState(StaticUtils.mapOf(
         ACCOUNT_IS_NOT_YET_ACTIVE, false,
         ACCOUNT_ACTIVATION_TIME, fiveMinutesAgo,
         SECONDS_SINCE_ACCOUNT_ACTIVATION, 300));

    assertNotNull(state.getAccountIsNotYetActive());
    assertFalse(state.getAccountIsNotYetActive().booleanValue());

    assertNotNull(state.getAccountActivationTime());
    assertEquals(state.getAccountActivationTime(), fiveMinutesAgo);

    assertNull(state.getSecondsUntilAccountActivation());

    assertNotNull(state.getSecondsSinceAccountActivation());
    assertEquals(state.getSecondsSinceAccountActivation().intValue(), 300);
  }



  /**
   * Tests the behavior for the properties related to account expiration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAccountExpiration()
         throws Exception
  {
    final Date currentDate = new Date();
    final Date tenMinutesFromNow = new Date(currentDate.getTime() + 600_000L);

    PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         ACCOUNT_IS_EXPIRED, false,
         ACCOUNT_EXPIRATION_TIME, tenMinutesFromNow,
         SECONDS_UNTIL_ACCOUNT_EXPIRATION, 600));

    assertNotNull(state.getAccountIsExpired());
    assertFalse(state.getAccountIsExpired().booleanValue());

    assertNotNull(state.getAccountExpirationTime());
    assertEquals(state.getAccountExpirationTime(), tenMinutesFromNow);

    assertNotNull(state.getSecondsUntilAccountExpiration());
    assertEquals(state.getSecondsUntilAccountExpiration().intValue(), 600);

    assertNull(state.getSecondsSinceAccountExpiration());


    final Date fiveMinutesAgo = new Date(currentDate.getTime() - 300_000L);

    state = createState(StaticUtils.mapOf(
         ACCOUNT_IS_EXPIRED, true,
         ACCOUNT_EXPIRATION_TIME, fiveMinutesAgo,
         SECONDS_SINCE_ACCOUNT_EXPIRATION, 300));

    assertNotNull(state.getAccountIsExpired());
    assertTrue(state.getAccountIsExpired().booleanValue());

    assertNotNull(state.getAccountExpirationTime());
    assertEquals(state.getAccountExpirationTime(), fiveMinutesAgo);

    assertNull(state.getSecondsUntilAccountExpiration());

    assertNotNull(state.getSecondsSinceAccountExpiration());
    assertEquals(state.getSecondsSinceAccountExpiration().intValue(), 300);
  }



  /**
   * Tests the behavior for the properties related to password expiration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordExpiration()
         throws Exception
  {
    final Date currentDate = new Date();
    final Date twentyFiveDaysFromNow = new Date(currentDate.getTime() +
         TimeUnit.DAYS.toMillis(25L));
    final Date thirtyDaysFromNow = new Date(currentDate.getTime() +
         TimeUnit.DAYS.toMillis(30L));

    final int fiveDaysInSeconds = (int) TimeUnit.DAYS.toSeconds(5L);
    final int twentyFiveDaysInSeconds = (int) TimeUnit.DAYS.toSeconds(25L);
    final int thirtyDaysInSeconds = (int) TimeUnit.DAYS.toSeconds(30L);
    final int ninetyDaysInSeconds = (int) TimeUnit.DAYS.toSeconds(90L);

    PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         PASSWORD_IS_EXPIRED, false,
         MAXIMUM_PASSWORD_AGE_SECONDS, ninetyDaysInSeconds,
         PASSWORD_EXPIRATION_TIME, thirtyDaysFromNow,
         SECONDS_UNTIL_PASSWORD_EXPIRATION, thirtyDaysInSeconds,
         PASSWORD_EXPIRATION_WARNING_INTERVAL_SECONDS, fiveDaysInSeconds,
         EXPIRE_PASSWORDS_WITHOUT_WARNING, true,
         PASSWORD_EXPIRATION_WARNING_ISSUED, false,
         PASSWORD_EXPIRATION_WARNING_TIME, twentyFiveDaysFromNow,
         SECONDS_UNTIL_PASSWORD_EXPIRATION_WARNING, twentyFiveDaysInSeconds));

    assertNotNull(state.getPasswordIsExpired());
    assertFalse(state.getPasswordIsExpired().booleanValue());

    assertNotNull(state.getMaximumPasswordAgeSeconds());
    assertEquals(state.getMaximumPasswordAgeSeconds().intValue(),
         ninetyDaysInSeconds);

    assertNotNull(state.getPasswordExpirationTime());
    assertEquals(state.getPasswordExpirationTime(), thirtyDaysFromNow);

    assertNotNull(state.getSecondsUntilPasswordExpiration());
    assertEquals(state.getSecondsUntilPasswordExpiration().intValue(),
         thirtyDaysInSeconds);

    assertNull(state.getSecondsSincePasswordExpiration());

    assertNotNull(state.getPasswordExpirationWarningIntervalSeconds());
    assertEquals(state.getPasswordExpirationWarningIntervalSeconds().intValue(),
         fiveDaysInSeconds);

    assertNotNull(state.getExpirePasswordsWithoutWarning());
    assertTrue(state.getExpirePasswordsWithoutWarning().booleanValue());

    assertNotNull(state.getPasswordExpirationWarningIssued());
    assertFalse(state.getPasswordExpirationWarningIssued().booleanValue());

    assertNotNull(state.getPasswordExpirationWarningTime());
    assertEquals(state.getPasswordExpirationWarningTime(),
         twentyFiveDaysFromNow);

    assertNotNull(state.getSecondsUntilPasswordExpirationWarning());
    assertEquals(state.getSecondsUntilPasswordExpirationWarning().intValue(),
         twentyFiveDaysInSeconds);

    assertNull(state.getSecondsSincePasswordExpirationWarning());


    final Date threeDaysAgo = new Date(currentDate.getTime() -
         TimeUnit.DAYS.toMillis(3L));
    final Date twoDaysFromNow = new Date(currentDate.getTime() +
         TimeUnit.DAYS.toMillis(2L));

    final int twoDaysInSeconds = (int) TimeUnit.DAYS.toSeconds(2L);
    final int threeDaysInSeconds = (int) TimeUnit.DAYS.toSeconds(3L);

    state = createState(StaticUtils.mapOf(
         PASSWORD_IS_EXPIRED, false,
         MAXIMUM_PASSWORD_AGE_SECONDS, ninetyDaysInSeconds,
         PASSWORD_EXPIRATION_TIME, twoDaysFromNow,
         SECONDS_UNTIL_PASSWORD_EXPIRATION, twoDaysInSeconds,
         PASSWORD_EXPIRATION_WARNING_INTERVAL_SECONDS, fiveDaysInSeconds,
         EXPIRE_PASSWORDS_WITHOUT_WARNING, false,
         PASSWORD_EXPIRATION_WARNING_ISSUED, true,
         PASSWORD_EXPIRATION_WARNING_TIME, threeDaysAgo,
         SECONDS_SINCE_PASSWORD_EXPIRATION_WARNING, threeDaysInSeconds));

    assertNotNull(state.getPasswordIsExpired());
    assertFalse(state.getPasswordIsExpired().booleanValue());

    assertNotNull(state.getMaximumPasswordAgeSeconds());
    assertEquals(state.getMaximumPasswordAgeSeconds().intValue(),
         ninetyDaysInSeconds);

    assertNotNull(state.getPasswordExpirationTime());
    assertEquals(state.getPasswordExpirationTime(), twoDaysFromNow);

    assertNotNull(state.getSecondsUntilPasswordExpiration());
    assertEquals(state.getSecondsUntilPasswordExpiration().intValue(),
         twoDaysInSeconds);

    assertNull(state.getSecondsSincePasswordExpiration());

    assertNotNull(state.getPasswordExpirationWarningIntervalSeconds());
    assertEquals(state.getPasswordExpirationWarningIntervalSeconds().intValue(),
         fiveDaysInSeconds);

    assertNotNull(state.getExpirePasswordsWithoutWarning());
    assertFalse(state.getExpirePasswordsWithoutWarning().booleanValue());

    assertNotNull(state.getPasswordExpirationWarningIssued());
    assertTrue(state.getPasswordExpirationWarningIssued().booleanValue());

    assertNotNull(state.getPasswordExpirationWarningTime());
    assertEquals(state.getPasswordExpirationWarningTime(), threeDaysAgo);

    assertNull(state.getSecondsUntilPasswordExpirationWarning());

    assertNotNull(state.getSecondsSincePasswordExpirationWarning());
    assertEquals(state.getSecondsSincePasswordExpirationWarning().intValue(),
         threeDaysInSeconds);


    final Date fiveDaysAgo = new Date(currentDate.getTime() -
         TimeUnit.DAYS.toMillis(5L));
    final Date tenDaysAgo = new Date(currentDate.getTime() -
         TimeUnit.DAYS.toMillis(10L));

    final int tenDaysInSeconds = (int) TimeUnit.DAYS.toSeconds(10L);

    state = createState(StaticUtils.mapOf(
         PASSWORD_IS_EXPIRED, true,
         MAXIMUM_PASSWORD_AGE_SECONDS, ninetyDaysInSeconds,
         PASSWORD_EXPIRATION_TIME, fiveDaysAgo,
         SECONDS_SINCE_PASSWORD_EXPIRATION, fiveDaysInSeconds,
         PASSWORD_EXPIRATION_WARNING_INTERVAL_SECONDS, fiveDaysInSeconds,
         EXPIRE_PASSWORDS_WITHOUT_WARNING, false,
         PASSWORD_EXPIRATION_WARNING_ISSUED, true,
         PASSWORD_EXPIRATION_WARNING_TIME, tenDaysAgo,
         SECONDS_SINCE_PASSWORD_EXPIRATION_WARNING, tenDaysInSeconds));

    assertNotNull(state.getPasswordIsExpired());
    assertTrue(state.getPasswordIsExpired().booleanValue());

    assertNotNull(state.getMaximumPasswordAgeSeconds());
    assertEquals(state.getMaximumPasswordAgeSeconds().intValue(),
         ninetyDaysInSeconds);

    assertNotNull(state.getPasswordExpirationTime());
    assertEquals(state.getPasswordExpirationTime(), fiveDaysAgo);

    assertNull(state.getSecondsUntilPasswordExpiration());

    assertNotNull(state.getSecondsSincePasswordExpiration());
    assertEquals(state.getSecondsSincePasswordExpiration().intValue(),
         fiveDaysInSeconds);

    assertNotNull(state.getPasswordExpirationWarningIntervalSeconds());
    assertEquals(state.getPasswordExpirationWarningIntervalSeconds().intValue(),
         fiveDaysInSeconds);

    assertNotNull(state.getExpirePasswordsWithoutWarning());
    assertFalse(state.getExpirePasswordsWithoutWarning().booleanValue());

    assertNotNull(state.getPasswordExpirationWarningIssued());
    assertTrue(state.getPasswordExpirationWarningIssued().booleanValue());

    assertNotNull(state.getPasswordExpirationWarningTime());
    assertEquals(state.getPasswordExpirationWarningTime(), tenDaysAgo);

    assertNull(state.getSecondsUntilPasswordExpirationWarning());

    assertNotNull(state.getSecondsSincePasswordExpirationWarning());
    assertEquals(state.getSecondsSincePasswordExpirationWarning().intValue(),
         tenDaysInSeconds);
  }



  /**
   * Tests the behavior for the properties related to failure lockout.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailureLockout()
         throws Exception
  {
    final Date currentDate = new Date();
    final Date tenSecondsAgo = new Date(currentDate.getTime() - 10_000L);
    final Date fiveSecondsAgo = new Date(currentDate.getTime() - 5_000);

    List<Date> failureTimes = Arrays.asList(tenSecondsAgo, fiveSecondsAgo);

    final int tenMinutesInSeconds = (int) TimeUnit.MINUTES.toSeconds(10L);

    PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         ACCOUNT_IS_FAILURE_LOCKED, false,
         FAILURE_LOCKOUT_COUNT, 5,
         CURRENT_AUTHENTICATION_FAILURE_COUNT, 2,
         REMAINING_AUTHENTICATION_FAILURE_COUNT, 3,
         AUTHENTICATION_FAILURE_TIMES, failureTimes,
         FAILURE_LOCKOUT_DURATION_SECONDS, tenMinutesInSeconds));

    assertNotNull(state.getAccountIsFailureLocked());
    assertEquals(state.getAccountIsFailureLocked().booleanValue(), false);

    assertNotNull(state.getFailureLockoutCount());
    assertEquals(state.getFailureLockoutCount().intValue(), 5);

    assertNotNull(state.getCurrentAuthenticationFailureCount());
    assertEquals(state.getCurrentAuthenticationFailureCount().intValue(), 2);

    assertNotNull(state.getRemainingAuthenticationFailureCount());
    assertEquals(state.getRemainingAuthenticationFailureCount().intValue(), 3);

    assertNotNull(state.getAuthenticationFailureTimes());
    assertEquals(state.getAuthenticationFailureTimes(), failureTimes);

    assertNull(state.getFailureLockoutTime());

    assertNotNull(state.getFailureLockoutDurationSeconds());
    assertEquals(state.getFailureLockoutDurationSeconds().intValue(),
         tenMinutesInSeconds);

    assertNull(state.getFailureLockoutExpirationTime());

    assertNull(state.getSecondsRemainingInFailureLockout());


    final Date twentyFiveSecondsAgo = new Date(currentDate.getTime() - 25_000L);
    final Date twentySecondsAgo = new Date(currentDate.getTime() - 20_000L);
    final Date fifteenSecondsAgo = new Date(currentDate.getTime() - 15_000L);

    final int tenMinutesMinusFiveSecondsInSeconds = tenMinutesInSeconds - 5;
    final Date tenMinutesFromNowMinusFiveSeconds = new Date(
         currentDate.getTime() + (tenMinutesMinusFiveSecondsInSeconds * 1000L));

    failureTimes = Arrays.asList(twentyFiveSecondsAgo, twentySecondsAgo,
         fifteenSecondsAgo, tenSecondsAgo, fiveSecondsAgo);

    state = createState(StaticUtils.mapOf(
         ACCOUNT_IS_FAILURE_LOCKED, true,
         FAILURE_LOCKOUT_COUNT, 5,
         CURRENT_AUTHENTICATION_FAILURE_COUNT, 5,
         REMAINING_AUTHENTICATION_FAILURE_COUNT, 0,
         AUTHENTICATION_FAILURE_TIMES, failureTimes,
         FAILURE_LOCKOUT_TIME, fiveSecondsAgo,
         FAILURE_LOCKOUT_DURATION_SECONDS, tenMinutesInSeconds,
         FAILURE_LOCKOUT_EXPIRATION_TIME, tenMinutesFromNowMinusFiveSeconds,
         SECONDS_REMAINING_IN_FAILURE_LOCKOUT,
              tenMinutesMinusFiveSecondsInSeconds));

    assertNotNull(state.getAccountIsFailureLocked());
    assertEquals(state.getAccountIsFailureLocked().booleanValue(), true);

    assertNotNull(state.getFailureLockoutCount());
    assertEquals(state.getFailureLockoutCount().intValue(), 5);

    assertNotNull(state.getCurrentAuthenticationFailureCount());
    assertEquals(state.getCurrentAuthenticationFailureCount().intValue(), 5);

    assertNotNull(state.getRemainingAuthenticationFailureCount());
    assertEquals(state.getRemainingAuthenticationFailureCount().intValue(), 0);

    assertNotNull(state.getAuthenticationFailureTimes());
    assertEquals(state.getAuthenticationFailureTimes(), failureTimes);

    assertNotNull(state.getFailureLockoutTime());
    assertEquals(state.getFailureLockoutTime(), fiveSecondsAgo);

    assertNotNull(state.getFailureLockoutDurationSeconds());
    assertEquals(state.getFailureLockoutDurationSeconds().intValue(),
         tenMinutesInSeconds);

    assertNotNull(state.getFailureLockoutExpirationTime());
    assertEquals(state.getFailureLockoutExpirationTime(),
         tenMinutesFromNowMinusFiveSeconds);

    assertNotNull(state.getSecondsRemainingInFailureLockout());
    assertEquals(state.getSecondsRemainingInFailureLockout().intValue(),
         tenMinutesMinusFiveSecondsInSeconds);


    final JSONObject o = new JSONObject(
         new JSONField(AUTHENTICATION_FAILURE_TIMES.getFieldName(),
              new JSONArray(
                   new JSONString("malformed-timestamp"))));

    final Entry entry = new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User");
    entry.addAttribute("ds-pwp-state-json", o.toSingleLineString());

    state = PasswordPolicyStateJSON.get(entry);
    assertNotNull(state);

    assertNotNull(state.getAuthenticationFailureTimes());
    assertTrue(state.getAuthenticationFailureTimes().isEmpty());
  }



  /**
   * Tests the behavior for the properties related to last login tracking and
   * idle account lockout.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLastLoginAndIdleLockout()
         throws Exception
  {
    final Date currentDate = new Date();
    final Date fiveSecondsAgo = new Date(currentDate.getTime() - 5_000L);

    final int oneYearInSeconds = (int) TimeUnit.DAYS.toSeconds(365L);
    final int oneYearMinusFiveSecondsInSeconds = oneYearInSeconds - 5;

    final Date oneYearFromNowMinusFiveSeconds = new Date(
         currentDate.getTime() + (oneYearMinusFiveSecondsInSeconds * 1000L));

    PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         LAST_LOGIN_TIME, fiveSecondsAgo,
         SECONDS_SINCE_LAST_LOGIN, 5,
         LAST_LOGIN_IP_ADDRESS, "1.2.3.4",
         ACCOUNT_IS_IDLE_LOCKED, false,
         IDLE_LOCKOUT_INTERVAL_SECONDS, oneYearInSeconds,
         IDLE_LOCKOUT_TIME, oneYearFromNowMinusFiveSeconds,
         SECONDS_UNTIL_IDLE_LOCKOUT, oneYearMinusFiveSecondsInSeconds));

    assertNotNull(state.getLastLoginTime());
    assertEquals(state.getLastLoginTime(), fiveSecondsAgo);

    assertNotNull(state.getSecondsSinceLastLogin());
    assertEquals(state.getSecondsSinceLastLogin().intValue(), 5);

    assertNotNull(state.getLastLoginIPAddress());
    assertEquals(state.getLastLoginIPAddress(), "1.2.3.4");

    assertNotNull(state.getAccountIsIdleLocked());
    assertFalse(state.getAccountIsIdleLocked().booleanValue());

    assertNotNull(state.getIdleLockoutIntervalSeconds());
    assertEquals(state.getIdleLockoutIntervalSeconds().intValue(),
         oneYearInSeconds);

    assertNotNull(state.getIdleLockoutTime());
    assertEquals(state.getIdleLockoutTime(), oneYearFromNowMinusFiveSeconds);

    assertNotNull(state.getSecondsUntilIdleLockout());
    assertEquals(state.getSecondsUntilIdleLockout().intValue(),
         oneYearMinusFiveSecondsInSeconds);

    assertNull(state.getSecondsSinceIdleLockout());


    final int twoYearsInSeconds = (int) TimeUnit.DAYS.toSeconds(365L * 2L);
    final Date twoYearsAgo =
         new Date(currentDate.getTime() - (twoYearsInSeconds * 1000L));
    final Date oneYearAgo =
         new Date(currentDate.getTime() - (oneYearInSeconds * 1000L));

    state = createState(StaticUtils.mapOf(
         LAST_LOGIN_TIME, twoYearsAgo,
         SECONDS_SINCE_LAST_LOGIN, twoYearsInSeconds,
         LAST_LOGIN_IP_ADDRESS, "1.2.3.4",
         ACCOUNT_IS_IDLE_LOCKED, true,
         IDLE_LOCKOUT_INTERVAL_SECONDS, oneYearInSeconds,
         IDLE_LOCKOUT_TIME, oneYearAgo,
         SECONDS_SINCE_IDLE_LOCKOUT, oneYearInSeconds));

    assertNotNull(state.getLastLoginTime());
    assertEquals(state.getLastLoginTime(), twoYearsAgo);

    assertNotNull(state.getSecondsSinceLastLogin());
    assertEquals(state.getSecondsSinceLastLogin().intValue(),
         twoYearsInSeconds);

    assertNotNull(state.getLastLoginIPAddress());
    assertEquals(state.getLastLoginIPAddress(), "1.2.3.4");

    assertNotNull(state.getAccountIsIdleLocked());
    assertTrue(state.getAccountIsIdleLocked().booleanValue());

    assertNotNull(state.getIdleLockoutIntervalSeconds());
    assertEquals(state.getIdleLockoutIntervalSeconds().intValue(),
         oneYearInSeconds);

    assertNotNull(state.getIdleLockoutTime());
    assertEquals(state.getIdleLockoutTime(), oneYearAgo);

    assertNull(state.getSecondsUntilIdleLockout());

    assertNotNull(state.getSecondsSinceIdleLockout());
    assertEquals(state.getSecondsSinceIdleLockout().intValue(),
         oneYearInSeconds);
  }



  /**
   * Tests the behavior for the properties related to password reset.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordReset()
         throws Exception
  {
    PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         MUST_CHANGE_PASSWORD, false,
         ACCOUNT_IS_RESET_LOCKED, false,
         FORCE_CHANGE_ON_ADD, false,
         FORCE_CHANGE_ON_RESET, true,
         MAXIMUM_PASSWORD_RESET_AGE_SECONDS, 3_600));

    assertNotNull(state.getMustChangePassword());
    assertFalse(state.getMustChangePassword().booleanValue());

    assertNotNull(state.getAccountIsResetLocked());
    assertFalse(state.getAccountIsResetLocked().booleanValue());

    assertNotNull(state.getForceChangeOnAdd());
    assertFalse(state.getForceChangeOnAdd());

    assertNotNull(state.getForceChangeOnReset());
    assertTrue(state.getForceChangeOnReset());

    assertNotNull(state.getMaximumPasswordResetAgeSeconds());
    assertEquals(state.getMaximumPasswordResetAgeSeconds().intValue(), 3_600);

    assertNull(state.getResetLockoutTime());

    assertNull(state.getSecondsUntilResetLockout());


    final Date currentDate = new Date();
    final Date tenMinutesFromNow = new Date(currentDate.getTime() + 600_000L);

    state = createState(StaticUtils.mapOf(
         MUST_CHANGE_PASSWORD, true,
         ACCOUNT_IS_RESET_LOCKED, false,
         FORCE_CHANGE_ON_ADD, true,
         FORCE_CHANGE_ON_RESET, true,
         MAXIMUM_PASSWORD_RESET_AGE_SECONDS, 3_600,
         RESET_LOCKOUT_TIME, tenMinutesFromNow,
         SECONDS_UNTIL_RESET_LOCKOUT, 600));

    assertNotNull(state.getMustChangePassword());
    assertTrue(state.getMustChangePassword().booleanValue());

    assertNotNull(state.getAccountIsResetLocked());
    assertFalse(state.getAccountIsResetLocked().booleanValue());

    assertNotNull(state.getForceChangeOnAdd());
    assertTrue(state.getForceChangeOnAdd());

    assertNotNull(state.getForceChangeOnReset());
    assertTrue(state.getForceChangeOnReset());

    assertNotNull(state.getMaximumPasswordResetAgeSeconds());
    assertEquals(state.getMaximumPasswordResetAgeSeconds().intValue(), 3_600);

    assertNotNull(state.getResetLockoutTime());
    assertEquals(state.getResetLockoutTime(), tenMinutesFromNow);

    assertNotNull(state.getSecondsUntilResetLockout());
    assertEquals(state.getSecondsUntilResetLockout().intValue(), 600);


    final Date fiveMinutesAgo = new Date(currentDate.getTime() - 300_000L);

    state = createState(StaticUtils.mapOf(
         MUST_CHANGE_PASSWORD, true,
         ACCOUNT_IS_RESET_LOCKED, true,
         FORCE_CHANGE_ON_ADD, true,
         FORCE_CHANGE_ON_RESET, true,
         MAXIMUM_PASSWORD_RESET_AGE_SECONDS, 3_600,
         RESET_LOCKOUT_TIME, fiveMinutesAgo));

    assertNotNull(state.getMustChangePassword());
    assertTrue(state.getMustChangePassword().booleanValue());

    assertNotNull(state.getAccountIsResetLocked());
    assertTrue(state.getAccountIsResetLocked().booleanValue());

    assertNotNull(state.getForceChangeOnAdd());
    assertTrue(state.getForceChangeOnAdd());

    assertNotNull(state.getForceChangeOnReset());
    assertTrue(state.getForceChangeOnReset());

    assertNotNull(state.getMaximumPasswordResetAgeSeconds());
    assertEquals(state.getMaximumPasswordResetAgeSeconds().intValue(), 3_600);

    assertNotNull(state.getResetLockoutTime());
    assertEquals(state.getResetLockoutTime(), fiveMinutesAgo);

    assertNull(state.getSecondsUntilResetLockout());
  }



  /**
   * Tests the behavior for the properties related to password history and
   * minimum password age.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordHistoryAndMinimumPasswordAge()
         throws Exception
  {
    PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         MAXIMUM_PASSWORD_HISTORY_COUNT, 12,
         CURRENT_PASSWORD_HISTORY_COUNT, 5,
         IS_WITHIN_MINIMUM_PASSWORD_AGE, false,
         MINIMUM_PASSWORD_AGE_SECONDS, 3_600));

    assertNotNull(state.getMaximumPasswordHistoryCount());
    assertEquals(state.getMaximumPasswordHistoryCount().intValue(), 12);

    assertNull(state.getMaximumPasswordHistoryDurationSeconds());

    assertNotNull(state.getIsWithinMinimumPasswordAge());
    assertFalse(state.getIsWithinMinimumPasswordAge().booleanValue());

    assertNotNull(state.getMinimumPasswordAgeSeconds());
    assertEquals(state.getMinimumPasswordAgeSeconds().intValue(), 3_600);

    assertNull(state.getMinimumPasswordAgeExpirationTime());

    assertNull(state.getSecondsRemainingInMinimumPasswordAge());


    final Date currentDate = new Date();
    final Date fiveMinutesFromNow = new Date(currentDate.getTime() + 300_000L);

    final int oneYearInSeconds = (int) TimeUnit.DAYS.toSeconds(365L);

    state = createState(StaticUtils.mapOf(
         MAXIMUM_PASSWORD_HISTORY_DURATION_SECONDS, oneYearInSeconds,
         CURRENT_PASSWORD_HISTORY_COUNT, 3,
         IS_WITHIN_MINIMUM_PASSWORD_AGE, true,
         MINIMUM_PASSWORD_AGE_SECONDS, 3_600,
         MINIMUM_PASSWORD_AGE_EXPIRATION_TIME, fiveMinutesFromNow,
         SECONDS_REMAINING_IN_MINIMUM_PASSWORD_AGE, 300));

    assertNull(state.getMaximumPasswordHistoryCount());

    assertNotNull(state.getMaximumPasswordHistoryDurationSeconds());
    assertEquals(state.getMaximumPasswordHistoryDurationSeconds().intValue(),
         oneYearInSeconds);

    assertNotNull(state.getIsWithinMinimumPasswordAge());
    assertTrue(state.getIsWithinMinimumPasswordAge().booleanValue());

    assertNotNull(state.getMinimumPasswordAgeSeconds());
    assertEquals(state.getMinimumPasswordAgeSeconds().intValue(), 3_600);

    assertNotNull(state.getMinimumPasswordAgeExpirationTime());
    assertEquals(state.getMinimumPasswordAgeExpirationTime(),
         fiveMinutesFromNow);

    assertNotNull(state.getSecondsRemainingInMinimumPasswordAge());
    assertEquals(state.getSecondsRemainingInMinimumPasswordAge().intValue(),
         300);
  }



  /**
   * Tests the behavior for the properties related to grace logins.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGraceLogins()
         throws Exception
  {
    PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         MAXIMUM_GRACE_LOGIN_COUNT, 5,
         USED_GRACE_LOGIN_COUNT, 0,
         REMAINING_GRACE_LOGIN_COUNT, 5,
         GRACE_LOGIN_USE_TIMES, Collections.emptyList()));

    assertNotNull(state.getMaximumGraceLoginCount());
    assertEquals(state.getMaximumGraceLoginCount().intValue(), 5);

    assertNotNull(state.getUsedGraceLoginCount());
    assertEquals(state.getUsedGraceLoginCount().intValue(), 0);

    assertNotNull(state.getRemainingGraceLoginCount());
    assertEquals(state.getRemainingGraceLoginCount().intValue(), 5);

    assertNotNull(state.getGraceLoginUseTimes());
    assertTrue(state.getGraceLoginUseTimes().isEmpty());


    final Date currentDate = new Date();
    final Date threeMinutesAgo = new Date(currentDate.getTime() - 3_000L);
    final Date twoMinutesAgo = new Date(currentDate.getTime() - 2_000L);
    final Date oneMinuteAgo = new Date(currentDate.getTime() - 1_000L);

    final List<Date> graceLoginUseTimes =
         Arrays.asList(threeMinutesAgo, twoMinutesAgo, oneMinuteAgo);

    state = createState(StaticUtils.mapOf(
         MAXIMUM_GRACE_LOGIN_COUNT, 5,
         USED_GRACE_LOGIN_COUNT, 3,
         REMAINING_GRACE_LOGIN_COUNT, 2,
         GRACE_LOGIN_USE_TIMES, graceLoginUseTimes));

    assertNotNull(state.getMaximumGraceLoginCount());
    assertEquals(state.getMaximumGraceLoginCount().intValue(), 5);

    assertNotNull(state.getUsedGraceLoginCount());
    assertEquals(state.getUsedGraceLoginCount().intValue(), 3);

    assertNotNull(state.getRemainingGraceLoginCount());
    assertEquals(state.getRemainingGraceLoginCount().intValue(), 2);

    assertNotNull(state.getGraceLoginUseTimes());
    assertFalse(state.getGraceLoginUseTimes().isEmpty());
    assertEquals(state.getGraceLoginUseTimes(), graceLoginUseTimes);


    final JSONObject o = new JSONObject(
         new JSONField(GRACE_LOGIN_USE_TIMES.getFieldName(),
              new JSONArray(
                   new JSONString("malformed-timestamp"))));

    final Entry entry = new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User");
    entry.addAttribute("ds-pwp-state-json", o.toSingleLineString());

    state = PasswordPolicyStateJSON.get(entry);
    assertNotNull(state);

    assertNotNull(state.getGraceLoginUseTimes());
    assertTrue(state.getGraceLoginUseTimes().isEmpty());
  }



  /**
   * Tests the behavior for the properties related to retired passwords.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRetiredPasswords()
         throws Exception
  {
    PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         HAS_RETIRED_PASSWORD, false));

    assertNotNull(state.getHasRetiredPassword());
    assertFalse(state.getHasRetiredPassword().booleanValue());

    assertNull(state.getRetiredPasswordExpirationTime());

    assertNull(state.getSecondsUntilRetiredPasswordExpiration());


    final Date currentDate = new Date();
    final Date tenMinutesFromNow = new Date(currentDate.getTime() + 600_000L);

    state = createState(StaticUtils.mapOf(
         HAS_RETIRED_PASSWORD, true,
         RETIRED_PASSWORD_EXPIRATION_TIME, tenMinutesFromNow,
         SECONDS_UNTIL_RETIRED_PASSWORD_EXPIRATION, 600));

    assertNotNull(state.getHasRetiredPassword());
    assertTrue(state.getHasRetiredPassword().booleanValue());

    assertNotNull(state.getRetiredPasswordExpirationTime());
    assertEquals(state.getRetiredPasswordExpirationTime(), tenMinutesFromNow);

    assertNotNull(state.getSecondsUntilRetiredPasswordExpiration());
    assertEquals(state.getSecondsUntilRetiredPasswordExpiration().intValue(),
         600);
  }



  /**
   * Tests the behavior for the properties related to account security.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAccountSecurity()
         throws Exception
  {
    PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         REQUIRE_SECURE_AUTHENTICATION, false,
         REQUIRE_SECURE_PASSWORD_CHANGES, true));

    assertNotNull(state.getRequireSecureAuthentication());
    assertFalse(state.getRequireSecureAuthentication().booleanValue());

    assertNotNull(state.getRequireSecurePasswordChanges());
    assertTrue(state.getRequireSecurePasswordChanges().booleanValue());


    state = createState(StaticUtils.mapOf(
         REQUIRE_SECURE_AUTHENTICATION, true,
         REQUIRE_SECURE_PASSWORD_CHANGES, false));

    assertNotNull(state.getRequireSecureAuthentication());
    assertTrue(state.getRequireSecureAuthentication().booleanValue());

    assertNotNull(state.getRequireSecurePasswordChanges());
    assertFalse(state.getRequireSecurePasswordChanges().booleanValue());
  }



  /**
   * Tests the behavior for the properties related to SASL authentication.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSASLAuthentication()
         throws Exception
  {
    List<String> availableSASLMechanisms =
         Arrays.asList("PLAIN", "UNBOUNDID-TOTP");

    PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         AVAILABLE_SASL_MECHANISMS, availableSASLMechanisms,
         HAS_TOTP_SHARED_SECRET, true,
         HAS_REGISTERED_YUBIKEY_OTP_DEVICE, false));

    assertNotNull(state.getAvailableSASLMechanisms());
    assertFalse(state.getAvailableSASLMechanisms().isEmpty());
    assertEquals(state.getAvailableSASLMechanisms(), availableSASLMechanisms);

    assertNotNull(state.getAvailableOTPDeliveryMechanisms());
    assertTrue(state.getAvailableOTPDeliveryMechanisms().isEmpty());

    assertNotNull(state.getHasTOTPSharedSecret());
    assertTrue(state.getHasTOTPSharedSecret().booleanValue());

    assertNotNull(state.getHasRegisteredYubiKeyOTPDevice());
    assertFalse(state.getHasRegisteredYubiKeyOTPDevice());


    availableSASLMechanisms = Arrays.asList("PLAIN", "UNBOUNDID-DELIVERED-OTP");
    final List<String> availableOTPDeliveryMechanisms =
         Arrays.asList("SMS", "E-Mail");

    state = createState(StaticUtils.mapOf(
         AVAILABLE_SASL_MECHANISMS, availableSASLMechanisms,
         AVAILABLE_OTP_DELIVERY_MECHANISMS, availableOTPDeliveryMechanisms,
         HAS_TOTP_SHARED_SECRET, false,
         HAS_REGISTERED_YUBIKEY_OTP_DEVICE, false));

    assertNotNull(state.getAvailableSASLMechanisms());
    assertFalse(state.getAvailableSASLMechanisms().isEmpty());
    assertEquals(state.getAvailableSASLMechanisms(), availableSASLMechanisms);

    assertNotNull(state.getAvailableOTPDeliveryMechanisms());
    assertFalse(state.getAvailableOTPDeliveryMechanisms().isEmpty());
    assertEquals(state.getAvailableOTPDeliveryMechanisms(),
         availableOTPDeliveryMechanisms);

    assertNotNull(state.getHasTOTPSharedSecret());
    assertFalse(state.getHasTOTPSharedSecret().booleanValue());

    assertNotNull(state.getHasRegisteredYubiKeyOTPDevice());
    assertFalse(state.getHasRegisteredYubiKeyOTPDevice());


    availableSASLMechanisms = Arrays.asList("PLAIN", "UNBOUNDID-YUBIKEY-OTP");

    state = createState(StaticUtils.mapOf(
         AVAILABLE_SASL_MECHANISMS, availableSASLMechanisms,
         HAS_TOTP_SHARED_SECRET, false,
         HAS_REGISTERED_YUBIKEY_OTP_DEVICE, true));

    assertNotNull(state.getAvailableSASLMechanisms());
    assertFalse(state.getAvailableSASLMechanisms().isEmpty());
    assertEquals(state.getAvailableSASLMechanisms(), availableSASLMechanisms);

    assertNotNull(state.getAvailableOTPDeliveryMechanisms());
    assertTrue(state.getAvailableOTPDeliveryMechanisms().isEmpty());

    assertNotNull(state.getHasTOTPSharedSecret());
    assertFalse(state.getHasTOTPSharedSecret().booleanValue());

    assertNotNull(state.getHasRegisteredYubiKeyOTPDevice());
    assertTrue(state.getHasRegisteredYubiKeyOTPDevice());


    final JSONObject o = new JSONObject(
         new JSONField(AVAILABLE_SASL_MECHANISMS.getFieldName(),
              new JSONArray(
                   new JSONNumber(1234))),
         new JSONField(AVAILABLE_OTP_DELIVERY_MECHANISMS.getFieldName(),
              new JSONArray(
                   new JSONNumber(5678))));

    final Entry entry = new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User");
    entry.addAttribute("ds-pwp-state-json", o.toSingleLineString());

    state = PasswordPolicyStateJSON.get(entry);
    assertNotNull(state);

    assertNotNull(state.getAvailableSASLMechanisms());
    assertTrue(state.getAvailableSASLMechanisms().isEmpty());

    assertNotNull(state.getAvailableOTPDeliveryMechanisms());
    assertTrue(state.getAvailableOTPDeliveryMechanisms().isEmpty());

    assertNull(state.getHasTOTPSharedSecret());

    assertNull(state.getHasRegisteredYubiKeyOTPDevice());
  }



  /**
   * Tests the behavior for the properties related to password validation during
   * bind processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindPasswordValidation()
         throws Exception
  {
    final Date lastValidationTime = new Date();

    final PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         ACCOUNT_IS_VALIDATION_LOCKED, false,
         LAST_BIND_PASSWORD_VALIDATION_TIME, lastValidationTime,
         SECONDS_SINCE_LAST_BIND_PASSWORD_VALIDATION, 0,
         MINIMUM_BIND_PASSWORD_VALIDATION_FREQUENCY_SECONDS,
              (int) TimeUnit.DAYS.toSeconds(30L),
         BIND_PASSWORD_VALIDATION_FAILURE_ACTION, "force-password-change"));

    assertNotNull(state.getAccountIsValidationLocked());
    assertFalse(state.getAccountIsValidationLocked().booleanValue());

    assertNotNull(state.getLastBindPasswordValidationTime());
    assertEquals(state.getLastBindPasswordValidationTime(), lastValidationTime);

    assertNotNull(state.getSecondsSinceLastBindPasswordValidation());
    assertEquals(state.getSecondsSinceLastBindPasswordValidation().intValue(),
         0);

    assertNotNull(state.getMinimumBindPasswordValidationFrequencySeconds());
    assertEquals(
         state.getMinimumBindPasswordValidationFrequencySeconds().intValue(),
         TimeUnit.DAYS.toSeconds(30L));

    assertNotNull(state.getBindPasswordValidationFailureAction());
    assertEquals(state.getBindPasswordValidationFailureAction(),
         "force-password-change");
  }



  /**
   * Tests the behavior for the properties related to maintaining a recent login
   * history.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRecentLoginHistory()
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

    final PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         RECENT_LOGIN_HISTORY, h.asJSONObject(),
         MAXIMUM_RECENT_LOGIN_HISTORY_SUCCESSFUL_AUTHENTICATION_COUNT, 50,
         MAXIMUM_RECENT_LOGIN_HISTORY_SUCCESSFUL_AUTHENTICATION_DURATION_SECONDS
              , (int) TimeUnit.DAYS.toSeconds(30L),
         MAXIMUM_RECENT_LOGIN_HISTORY_FAILED_AUTHENTICATION_COUNT, 20,
         MAXIMUM_RECENT_LOGIN_HISTORY_FAILED_AUTHENTICATION_DURATION_SECONDS,
              (int) TimeUnit.DAYS.toSeconds(10L)));

    assertNotNull(state.getRecentLoginHistory());

    assertNotNull(
         state.getMaximumRecentLoginHistorySuccessfulAuthenticationCount());
    assertEquals(
         state.getMaximumRecentLoginHistorySuccessfulAuthenticationCount().
              intValue(),
         50);

    assertNotNull(state.
         getMaximumRecentLoginHistorySuccessfulAuthenticationDurationSeconds());
    assertEquals(state.
         getMaximumRecentLoginHistorySuccessfulAuthenticationDurationSeconds().
              intValue(),
         TimeUnit.DAYS.toSeconds(30L));

    assertNotNull(
         state.getMaximumRecentLoginHistoryFailedAuthenticationCount());
    assertEquals(
         state.getMaximumRecentLoginHistoryFailedAuthenticationCount().
              intValue(),
         20);

    assertNotNull(state.
         getMaximumRecentLoginHistoryFailedAuthenticationDurationSeconds());
    assertEquals(state.
         getMaximumRecentLoginHistoryFailedAuthenticationDurationSeconds()
              .intValue(),
         TimeUnit.DAYS.toSeconds(10L));
  }



  /**
   * Tests the behavior when trying to retrieve a malformed recent login
   * history.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testMalformedRecentLoginHistory()
         throws Exception
  {
    final PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         RECENT_LOGIN_HISTORY, new JSONObject(
              new JSONField("successful-attempts",
                   new JSONArray(new JSONObject(
                        new JSONField("malformed", true))))),
         MAXIMUM_RECENT_LOGIN_HISTORY_SUCCESSFUL_AUTHENTICATION_COUNT, 50,
         MAXIMUM_RECENT_LOGIN_HISTORY_SUCCESSFUL_AUTHENTICATION_DURATION_SECONDS
              , (int) TimeUnit.DAYS.toSeconds(30L),
         MAXIMUM_RECENT_LOGIN_HISTORY_FAILED_AUTHENTICATION_COUNT, 20,
         MAXIMUM_RECENT_LOGIN_HISTORY_FAILED_AUTHENTICATION_DURATION_SECONDS,
              (int) TimeUnit.DAYS.toSeconds(10L)));

    state.getRecentLoginHistory();
  }



  /**
   * Tests the behavior when encountering fields whose values are of an
   * unexpected type or format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedValues()
         throws Exception
  {
    final PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         PASSWORD_POLICY_DN, 1234,
         ACCOUNT_IS_USABLE, "false",
         ACCOUNT_USABILITY_ERRORS, Arrays.asList(new Date()),
         ACCOUNT_USABILITY_WARNINGS, "not an array",
         PASSWORD_CHANGED_TIME, "malformed-string",
         SECONDS_SINCE_PASSWORD_CHANGE, true,
         ACCOUNT_ACTIVATION_TIME, 5678));

    assertNull(state.getPasswordPolicyDN());

    assertNull(state.getAccountIsUsable());

    assertNotNull(state.getAccountUsabilityErrors());
    assertTrue(state.getAccountUsabilityErrors().isEmpty());

    assertNotNull(state.getAccountUsabilityWarnings());
    assertTrue(state.getAccountUsabilityWarnings().isEmpty());

    assertNull(state.getPasswordChangedTime());

    assertNull(state.getSecondsSincePasswordChange());

    assertNull(state.getAccountActivationTime());
  }



  /**
   * Tests the behavior for the properties related to password quality
   * requirements for add operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAddPasswordQualityRequirements()
         throws Exception
  {
    final PasswordQualityRequirement allRequirement =
         new PasswordQualityRequirement("all-requirement-description",
              "all-requirement-type", Collections.<String,String>emptyMap());
    final PasswordQualityRequirement noneRequirement =
         new PasswordQualityRequirement("none-requirement-description",
              "none-requirement-type", Collections.<String,String>emptyMap());
    final PasswordQualityRequirement addRequirement =
         new PasswordQualityRequirement("add-requirement-description",
              "add-requirement-type",
              Collections.singletonMap("property-1", "value-1"));
    final PasswordQualityRequirement selfChangeRequirement =
         new PasswordQualityRequirement("self-change-requirement-description",
              "self-change-requirement-type",
              StaticUtils.mapOf("property-1", "value-1",
                   "property-2", "value-2"));
    final PasswordQualityRequirement adminResetRequirement =
         new PasswordQualityRequirement("admin-reset-requirement-description",
              "admin-reset-requirement-type",
              StaticUtils.mapOf("property-1", "value-1",
                   "property-2", "value-2",
                   "property-3", "value-3"));
    final PasswordQualityRequirement bindRequirement =
         new PasswordQualityRequirement("bind-requirement-description", null,
              null);

    final JSONArray requirementsArray = new JSONArray(
         encodeRequirement(allRequirement, true, true, true, true),
         encodeRequirement(noneRequirement, false, false, false, false),
         encodeRequirement(addRequirement, true, false, false, false),
         encodeRequirement(selfChangeRequirement, false, true, false, false),
         encodeRequirement(adminResetRequirement, false, false, true, false),
         encodeRequirement(bindRequirement, false, false, false, true));

    final PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         PASSWORD_QUALITY_REQUIREMENTS, requirementsArray));

    assertNotNull(state.getAddPasswordQualityRequirements());
    assertFalse(state.getAddPasswordQualityRequirements().isEmpty());
    assertEquals(state.getAddPasswordQualityRequirements().size(), 2);

    final PasswordQualityRequirement requirement0 =
         state.getAddPasswordQualityRequirements().get(0);
    assertEquals(requirement0.getDescription(),
         allRequirement.getDescription());
    assertEquals(requirement0.getClientSideValidationType(),
         allRequirement.getClientSideValidationType());
    assertEquals(requirement0.getClientSideValidationProperties(),
         allRequirement.getClientSideValidationProperties());

    final PasswordQualityRequirement requirement1 =
         state.getAddPasswordQualityRequirements().get(1);
    assertEquals(requirement1.getDescription(),
         addRequirement.getDescription());
    assertEquals(requirement1.getClientSideValidationType(),
         addRequirement.getClientSideValidationType());
    assertEquals(requirement1.getClientSideValidationProperties(),
         addRequirement.getClientSideValidationProperties());
  }



  /**
   * Tests the behavior for the properties related to password quality
   * requirements for self password changes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSelfChangePasswordQualityRequirements()
         throws Exception
  {
    final PasswordQualityRequirement allRequirement =
         new PasswordQualityRequirement("all-requirement-description",
              "all-requirement-type", Collections.<String,String>emptyMap());
    final PasswordQualityRequirement noneRequirement =
         new PasswordQualityRequirement("none-requirement-description",
              "none-requirement-type", Collections.<String,String>emptyMap());
    final PasswordQualityRequirement addRequirement =
         new PasswordQualityRequirement("add-requirement-description",
              "add-requirement-type",
              Collections.singletonMap("property-1", "value-1"));
    final PasswordQualityRequirement selfChangeRequirement =
         new PasswordQualityRequirement("self-change-requirement-description",
              "self-change-requirement-type",
              StaticUtils.mapOf("property-1", "value-1",
                   "property-2", "value-2"));
    final PasswordQualityRequirement adminResetRequirement =
         new PasswordQualityRequirement("admin-reset-requirement-description",
              "admin-reset-requirement-type",
              StaticUtils.mapOf("property-1", "value-1",
                   "property-2", "value-2",
                   "property-3", "value-3"));
    final PasswordQualityRequirement bindRequirement =
         new PasswordQualityRequirement("bind-requirement-description", null,
              null);

    final JSONArray requirementsArray = new JSONArray(
         encodeRequirement(allRequirement, true, true, true, true),
         encodeRequirement(noneRequirement, false, false, false, false),
         encodeRequirement(addRequirement, true, false, false, false),
         encodeRequirement(selfChangeRequirement, false, true, false, false),
         encodeRequirement(adminResetRequirement, false, false, true, false),
         encodeRequirement(bindRequirement, false, false, false, true));

    final PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         PASSWORD_QUALITY_REQUIREMENTS, requirementsArray));

    assertNotNull(state.getSelfChangePasswordQualityRequirements());
    assertFalse(state.getSelfChangePasswordQualityRequirements().isEmpty());
    assertEquals(state.getSelfChangePasswordQualityRequirements().size(), 2);

    final PasswordQualityRequirement requirement0 =
         state.getSelfChangePasswordQualityRequirements().get(0);
    assertEquals(requirement0.getDescription(),
         allRequirement.getDescription());
    assertEquals(requirement0.getClientSideValidationType(),
         allRequirement.getClientSideValidationType());
    assertEquals(requirement0.getClientSideValidationProperties(),
         allRequirement.getClientSideValidationProperties());

    final PasswordQualityRequirement requirement1 =
         state.getSelfChangePasswordQualityRequirements().get(1);
    assertEquals(requirement1.getDescription(),
         selfChangeRequirement.getDescription());
    assertEquals(requirement1.getClientSideValidationType(),
         selfChangeRequirement.getClientSideValidationType());
    assertEquals(requirement1.getClientSideValidationProperties(),
         selfChangeRequirement.getClientSideValidationProperties());
  }



  /**
   * Tests the behavior for the properties related to password quality
   * requirements for administrative password resets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAdministrativeResetPasswordQualityRequirements()
         throws Exception
  {
    final PasswordQualityRequirement allRequirement =
         new PasswordQualityRequirement("all-requirement-description",
              "all-requirement-type", Collections.<String,String>emptyMap());
    final PasswordQualityRequirement noneRequirement =
         new PasswordQualityRequirement("none-requirement-description",
              "none-requirement-type", Collections.<String,String>emptyMap());
    final PasswordQualityRequirement addRequirement =
         new PasswordQualityRequirement("add-requirement-description",
              "add-requirement-type",
              Collections.singletonMap("property-1", "value-1"));
    final PasswordQualityRequirement selfChangeRequirement =
         new PasswordQualityRequirement("self-change-requirement-description",
              "self-change-requirement-type",
              StaticUtils.mapOf("property-1", "value-1",
                   "property-2", "value-2"));
    final PasswordQualityRequirement adminResetRequirement =
         new PasswordQualityRequirement("admin-reset-requirement-description",
              "admin-reset-requirement-type",
              StaticUtils.mapOf("property-1", "value-1",
                   "property-2", "value-2",
                   "property-3", "value-3"));
    final PasswordQualityRequirement bindRequirement =
         new PasswordQualityRequirement("bind-requirement-description", null,
              null);

    final JSONArray requirementsArray = new JSONArray(
         encodeRequirement(allRequirement, true, true, true, true),
         encodeRequirement(noneRequirement, false, false, false, false),
         encodeRequirement(addRequirement, true, false, false, false),
         encodeRequirement(selfChangeRequirement, false, true, false, false),
         encodeRequirement(adminResetRequirement, false, false, true, false),
         encodeRequirement(bindRequirement, false, false, false, true));

    final PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         PASSWORD_QUALITY_REQUIREMENTS, requirementsArray));

    assertNotNull(state.getAdministrativeResetPasswordQualityRequirements());
    assertFalse(
         state.getAdministrativeResetPasswordQualityRequirements().isEmpty());
    assertEquals(
         state.getAdministrativeResetPasswordQualityRequirements().size(), 2);

    final PasswordQualityRequirement requirement0 =
         state.getAdministrativeResetPasswordQualityRequirements().get(0);
    assertEquals(requirement0.getDescription(),
         allRequirement.getDescription());
    assertEquals(requirement0.getClientSideValidationType(),
         allRequirement.getClientSideValidationType());
    assertEquals(requirement0.getClientSideValidationProperties(),
         allRequirement.getClientSideValidationProperties());

    final PasswordQualityRequirement requirement1 =
         state.getAdministrativeResetPasswordQualityRequirements().get(1);
    assertEquals(requirement1.getDescription(),
         adminResetRequirement.getDescription());
    assertEquals(requirement1.getClientSideValidationType(),
         adminResetRequirement.getClientSideValidationType());
    assertEquals(requirement1.getClientSideValidationProperties(),
         adminResetRequirement.getClientSideValidationProperties());
  }



  /**
   * Tests the behavior for the properties related to password quality
   * requirements for bind operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetBindPasswordQualityRequirements()
         throws Exception
  {
    final PasswordQualityRequirement allRequirement =
         new PasswordQualityRequirement("all-requirement-description",
              "all-requirement-type", Collections.<String,String>emptyMap());
    final PasswordQualityRequirement noneRequirement =
         new PasswordQualityRequirement("none-requirement-description",
              "none-requirement-type", Collections.<String,String>emptyMap());
    final PasswordQualityRequirement addRequirement =
         new PasswordQualityRequirement("add-requirement-description",
              "add-requirement-type",
              Collections.singletonMap("property-1", "value-1"));
    final PasswordQualityRequirement selfChangeRequirement =
         new PasswordQualityRequirement("self-change-requirement-description",
              "self-change-requirement-type",
              StaticUtils.mapOf("property-1", "value-1",
                   "property-2", "value-2"));
    final PasswordQualityRequirement adminResetRequirement =
         new PasswordQualityRequirement("admin-reset-requirement-description",
              "admin-reset-requirement-type",
              StaticUtils.mapOf("property-1", "value-1",
                   "property-2", "value-2",
                   "property-3", "value-3"));
    final PasswordQualityRequirement bindRequirement =
         new PasswordQualityRequirement("bind-requirement-description", null,
              null);

    final JSONArray requirementsArray = new JSONArray(
         encodeRequirement(allRequirement, true, true, true, true),
         encodeRequirement(noneRequirement, false, false, false, false),
         encodeRequirement(addRequirement, true, false, false, false),
         encodeRequirement(selfChangeRequirement, false, true, false, false),
         encodeRequirement(adminResetRequirement, false, false, true, false),
         encodeRequirement(bindRequirement, false, false, false, true));

    final PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         PASSWORD_QUALITY_REQUIREMENTS, requirementsArray));

    assertNotNull(state.getBindPasswordQualityRequirements());
    assertFalse(state.getBindPasswordQualityRequirements().isEmpty());
    assertEquals(state.getBindPasswordQualityRequirements().size(), 2);

    final PasswordQualityRequirement requirement0 =
         state.getBindPasswordQualityRequirements().get(0);
    assertEquals(requirement0.getDescription(),
         allRequirement.getDescription());
    assertEquals(requirement0.getClientSideValidationType(),
         allRequirement.getClientSideValidationType());
    assertEquals(requirement0.getClientSideValidationProperties(),
         allRequirement.getClientSideValidationProperties());

    final PasswordQualityRequirement requirement1 =
         state.getBindPasswordQualityRequirements().get(1);
    assertEquals(requirement1.getDescription(),
         bindRequirement.getDescription());
    assertNull(requirement1.getClientSideValidationType());
    assertNotNull(requirement1.getClientSideValidationProperties());
    assertTrue(requirement1.getClientSideValidationProperties().isEmpty());
  }



  /**
   * Encodes the provided password quality requirement to a JSON object suitable
   * for inclusion in the password policy state properties object.
   *
   * @param  requirement          The requirement to be encoded.
   * @param  appliesToAdd         Indicates whether the requirement applies to
   *                              add operations.
   * @param  appliesToSelfChange  Indicates whether the requirement applies to
   *                              self password changes.
   * @param  appliesToAdminReset  Indicates whether the requirement applies to
   *                              administrative password resets.
   * @param  appliesToBind        Indicates whether the requirement applies to
   *                              bind operations.
   *
   * @return  The encoded JSON object.
   */
  private static JSONObject encodeRequirement(
       final PasswordQualityRequirement requirement,
       final boolean appliesToAdd,
       final boolean appliesToSelfChange,
       final boolean appliesToAdminReset,
       final boolean appliesToBind)
  {
    final Map<String,JSONValue> objectFields = new LinkedHashMap<>();
    objectFields.put("description",
         new JSONString(requirement.getDescription()));

    final String validationType = requirement.getClientSideValidationType();
    if (validationType != null)
    {
      objectFields.put("client-side-validation-type",
           new JSONString(validationType));

      final List<JSONValue> propertyObjects = new ArrayList<>();
      for (Map.Entry<String,String> e :
           requirement.getClientSideValidationProperties().entrySet())
      {
        propertyObjects.add(new JSONObject(
             new JSONField("name", e.getKey()),
             new JSONField("value", e.getValue())));
      }
      objectFields.put("client-side-validation-properties",
           new JSONArray(propertyObjects));
    }

    objectFields.put("applies-to-add", new JSONBoolean(appliesToAdd));
    objectFields.put("applies-to-self-change",
         new JSONBoolean(appliesToSelfChange));
    objectFields.put("applies-to-administrative-reset",
         new JSONBoolean(appliesToAdminReset));
    objectFields.put("applies-to-bind", new JSONBoolean(appliesToBind));

    return new JSONObject(objectFields);
  }



  /**
   * Tests the behavior when trying to retrieve password quality requirements
   * when the field exists and is an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetPasswordQualityRequirementsFieldEmptyArray()
         throws Exception
  {
    final PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         PASSWORD_QUALITY_REQUIREMENTS, JSONArray.EMPTY_ARRAY));

    assertNotNull(state.getAddPasswordQualityRequirements());
    assertTrue(state.getAddPasswordQualityRequirements().isEmpty());
  }



  /**
   * Tests the behavior when trying to retrieve password quality requirements
   * when the field exists but its value is not an array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetPasswordQualityRequirementsFieldValueNotArray()
         throws Exception
  {
    final PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         PASSWORD_QUALITY_REQUIREMENTS, new JSONString("foo")));

    assertNotNull(state.getAddPasswordQualityRequirements());
    assertTrue(state.getAddPasswordQualityRequirements().isEmpty());
  }



  /**
   * Tests the behavior when trying to retrieve password quality requirements
   * when the array contains a non-object element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetPasswordQualityRequirementsArrayValueNotObject()
         throws Exception
  {
    final PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         PASSWORD_QUALITY_REQUIREMENTS,
         new JSONArray(new JSONString("foo"))));

    assertNotNull(state.getAddPasswordQualityRequirements());
    assertTrue(state.getAddPasswordQualityRequirements().isEmpty());
  }



  /**
   * Tests the behavior when trying to retrieve password quality requirements
   * when the array contains an object that is missing the required description
   * field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetPasswordQualityRequirementsObjectMissingDescription()
         throws Exception
  {
    final PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         PASSWORD_QUALITY_REQUIREMENTS,
         new JSONArray(
              new JSONObject(
                   new JSONField("client-side-validation-type", "type"),
                   new JSONField("applies-to-add", true)))));

    assertNotNull(state.getAddPasswordQualityRequirements());
    assertTrue(state.getAddPasswordQualityRequirements().isEmpty());
  }



  /**
   * Tests the behavior when trying to retrieve password quality requirements
   * when the properties array has a non-object element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetPasswordQualityRequirementsPropertyNotObject()
         throws Exception
  {
    final PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         PASSWORD_QUALITY_REQUIREMENTS,
         new JSONArray(
              new JSONObject(
                   new JSONField("description", "description"),
                   new JSONField("client-side-validation-type", "type"),
                   new JSONField("client-side-validation-properties",
                        new JSONArray(new JSONString("foo"))),
                   new JSONField("applies-to-add", true)))));

    assertNotNull(state.getAddPasswordQualityRequirements());
    assertFalse(state.getAddPasswordQualityRequirements().isEmpty());
    assertEquals(state.getAddPasswordQualityRequirements().size(), 1);

    final PasswordQualityRequirement r =
         state.getAddPasswordQualityRequirements().get(0);
    assertEquals(r.getDescription(), "description");
    assertEquals(r.getClientSideValidationType(), "type");
    assertNotNull(r.getClientSideValidationProperties());
    assertTrue(r.getClientSideValidationProperties().isEmpty());
  }



  /**
   * Tests the behavior when trying to retrieve password quality requirements
   * when the properties array has an object without a name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetPasswordQualityRequirementsPropertyMissingName()
         throws Exception
  {
    final PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         PASSWORD_QUALITY_REQUIREMENTS,
         new JSONArray(
              new JSONObject(
                   new JSONField("description", "description"),
                   new JSONField("client-side-validation-type", "type"),
                   new JSONField("client-side-validation-properties",
                        new JSONArray(new JSONObject(
                             new JSONField("value", "foo")))),
                   new JSONField("applies-to-add", true)))));

    assertNotNull(state.getAddPasswordQualityRequirements());
    assertFalse(state.getAddPasswordQualityRequirements().isEmpty());
    assertEquals(state.getAddPasswordQualityRequirements().size(), 1);

    final PasswordQualityRequirement r =
         state.getAddPasswordQualityRequirements().get(0);
    assertEquals(r.getDescription(), "description");
    assertEquals(r.getClientSideValidationType(), "type");
    assertNotNull(r.getClientSideValidationProperties());
    assertTrue(r.getClientSideValidationProperties().isEmpty());
  }



  /**
   * Tests the behavior when trying to retrieve password quality requirements
   * when the properties array has an object without a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetPasswordQualityRequirementsPropertyMissingValue()
         throws Exception
  {
    final PasswordPolicyStateJSON state = createState(StaticUtils.mapOf(
         PASSWORD_QUALITY_REQUIREMENTS,
         new JSONArray(
              new JSONObject(
                   new JSONField("description", "description"),
                   new JSONField("client-side-validation-type", "type"),
                   new JSONField("client-side-validation-properties",
                        new JSONArray(new JSONObject(
                             new JSONField("name", "foo")))),
                   new JSONField("applies-to-add", true)))));

    assertNotNull(state.getAddPasswordQualityRequirements());
    assertFalse(state.getAddPasswordQualityRequirements().isEmpty());
    assertEquals(state.getAddPasswordQualityRequirements().size(), 1);

    final PasswordQualityRequirement r =
         state.getAddPasswordQualityRequirements().get(0);
    assertEquals(r.getDescription(), "description");
    assertEquals(r.getClientSideValidationType(), "type");
    assertNotNull(r.getClientSideValidationProperties());
    assertTrue(r.getClientSideValidationProperties().isEmpty());
  }



  /**
   * Creates a password policy state JSON object with the provided fields.
   *
   * @param  fields  The fields to include in the JSON object.
   *
   * @return  The password policy state JSON object that was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private PasswordPolicyStateJSON createState(
               final Map<PasswordPolicyStateJSONField,?> fields)
          throws Exception
  {
    final Map<String,JSONValue> jsonFields = new LinkedHashMap<>();
    for (final PasswordPolicyStateJSONField field : fields.keySet())
    {
      final String name = field.getFieldName();
      final Object value = fields.get(field);
      if (value instanceof Boolean)
      {
        final Boolean b = (Boolean) value;
        jsonFields.put(name, new JSONBoolean(b));
      }
      else if (value instanceof Integer)
      {
        final Integer i = (Integer) value;
        jsonFields.put(name, new JSONNumber(i));
      }
      else if (value instanceof String)
      {
        final String s = (String) value;
        jsonFields.put(name, new JSONString(s));
      }
      else if (value instanceof Date)
      {
        final Date d = (Date) value;
        jsonFields.put(name, new JSONString(StaticUtils.encodeRFC3339Time(d)));
      }
      else if (value instanceof List)
      {
        final List<?> l = (List<?>) value;
        final List<JSONValue> arrayValues = new ArrayList<>();
        for (final Object o : l)
        {
          if (o instanceof Date)
          {
            final Date d = (Date) o;
            arrayValues.add(new JSONString(StaticUtils.encodeRFC3339Time(d)));
          }
          else if (o instanceof String)
          {
            final String s = (String) o;
            arrayValues.add(new JSONString(s));
          }
          else if (o instanceof PasswordPolicyStateAccountUsabilityError)
          {
            final PasswordPolicyStateAccountUsabilityError e =
                 (PasswordPolicyStateAccountUsabilityError) o;
            if (e.getMessage() == null)
            {
              arrayValues.add(new JSONObject(
                   new JSONField("type-name", e.getName()),
                   new JSONField("type-id", e.getIntValue())));
            }
            else
            {
              arrayValues.add(new JSONObject(
                   new JSONField("type-name", e.getName()),
                   new JSONField("type-id", e.getIntValue()),
                   new JSONField("message", e.getMessage())));
            }
          }
          else if (o instanceof PasswordPolicyStateAccountUsabilityWarning)
          {
            final PasswordPolicyStateAccountUsabilityWarning w =
                 (PasswordPolicyStateAccountUsabilityWarning) o;
            if (w.getMessage() == null)
            {
              arrayValues.add(new JSONObject(
                   new JSONField("type-name", w.getName()),
                   new JSONField("type-id", w.getIntValue())));
            }
            else
            {
              arrayValues.add(new JSONObject(
                   new JSONField("type-name", w.getName()),
                   new JSONField("type-id", w.getIntValue()),
                   new JSONField("message", w.getMessage())));
            }
          }
          else if (o instanceof PasswordPolicyStateAccountUsabilityNotice)
          {
            final PasswordPolicyStateAccountUsabilityNotice n =
                 (PasswordPolicyStateAccountUsabilityNotice) o;
            if (n.getMessage() == null)
            {
              arrayValues.add(new JSONObject(
                   new JSONField("type-name", n.getName()),
                   new JSONField("type-id", n.getIntValue())));
            }
            else
            {
              arrayValues.add(new JSONObject(
                   new JSONField("type-name", n.getName()),
                   new JSONField("type-id", n.getIntValue()),
                   new JSONField("message", n.getMessage())));
            }
          }
          else
          {
            fail("Unexpected list element " + o + " of type " +
                 o.getClass().getName());
          }
        }

        jsonFields.put(name, new JSONArray(arrayValues));
      }
      else if ( value instanceof JSONValue)
      {
        jsonFields.put(name, (JSONValue) value);
      }
      else
      {
        fail("Unexpected field value " + value + " of type " +
             value.getClass().getName());
      }
    }

    final JSONObject o = new JSONObject(jsonFields);

    final Entry entry = new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User");
    entry.addAttribute("ds-pwp-state-json", o.toSingleLineString());

    final PasswordPolicyStateJSON state = PasswordPolicyStateJSON.get(entry);
    assertNotNull(state);

    assertNotNull(state.getPasswordPolicyStateJSONObject());
    assertFalse(state.getPasswordPolicyStateJSONObject().getFields().isEmpty());
    assertEquals(state.getPasswordPolicyStateJSONObject().getFields().size(),
         jsonFields.size());

    assertNotNull(state.toString());
    assertFalse(state.toString().isEmpty());

    return state;
  }
}
