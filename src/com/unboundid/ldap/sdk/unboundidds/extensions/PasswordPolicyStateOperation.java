/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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



import java.io.Serializable;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class defines an operation that may be used in conjunction with the
 * password policy state extended operation.  A password policy state operation
 * can be used to get or set various properties of the password policy state for
 * a user.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * Operations that are available for use with the password policy state
 * operation include:
 * <UL>
 *   <LI>Get the DN of the password policy configuration entry for the target
 *       user.</LI>
 *   <LI>Determine whether an account is usable (may authenticate or be used as
 *       an alternate authorization identity.</LI>
 *   <LI>Retrieve the set of account usability notice, warning, and error
 *       messages for a user.</LI>
 *   <LI>Get, set, and clear the account disabled flag for the target user.</LI>
 *   <LI>Get, set, and clear the account activation time for the target
 *       user.</LI>
 *   <LI>Get, set, and clear the account expiration time for the target
 *       user.</LI>
 *   <LI>Get the length of time in seconds until the target user account
 *       expires.</LI>
 *   <LI>Get the time that the target user's password was last changed.</LI>
 *   <LI>Get and clear the time that the first password expiration warning was
 *       sent to the user.</LI>
 *   <LI>Get the length of time in seconds until the target user's password
 *       expires and the password expiration time for the account.</LI>
 *   <LI>Get the length of time in seconds until the user should receive the
 *       first warning about an upcoming password expiration.</LI>
 *   <LI>Determine whether the user's password is expired.</LI>
 *   <LI>Determine whether the account is locked because of failed
 *       authentication attempts, an idle lockout, or a password reset
 *       lockout.</LI>
 *   <LI>Get, update, set, and clear the list of times that the target user has
 *       unsuccessfully tried to authenticate since the last successful
 *       authentication.</LI>
 *   <LI>Get the number of remaining failed authentication attempts for the
 *       target user before the account is locked.</LI>
 *   <LI>Get the length of time in seconds until the target user's account is
 *       automatically unlocked after it was locked due to failed authentication
 *       attempts.</LI>
 *   <LI>Get, set, and clear the time that the user last authenticated to the
 *       server.</LI>
 *   <LI>Get, set, and clear the IP address of the client from which the user
 *       last authenticated to the server.</LI>
 *   <LI>Get the length of time in seconds until the user account may be locked
 *       after remaining idle.</LI>
 *   <LI>Get, set, and clear the flag that controls whether the target user must
 *       change his/her password before being allowed to perform any other
 *       operations.</LI>
 *   <LI>Get the length of time in seconds until the user's account is locked
 *       after failing to change the password after an administrative
 *       reset.</LI>
 *   <LI>Get, update, set, and clear the times that the target user has
 *       authenticated using a grace login after the password had expired.</LI>
 *   <LI>Retrieve the number of remaining grace logins for the user.</LI>
 *   <LI>Get, set, and clear the required password change time for the target
 *       user.</LI>
 *   <LI>Retrieve the length of time in seconds until the target user's account
 *       will be locked as a result of failing to comply with a password change
 *       by required time.</LI>
 *   <LI>Get the password history count for the target user.</LI>
 *   <LI>Clear the password history for the target user.</LI>
 *   <LI>Get information about or purge a user's retired password.</LI>
 *   <LI>Get information about which SASL mechanisms are available for a
 *       user.</LI>
 *   <LI>Get information about which OTP delivery mechanisms are available for a
 *       user.</LI>
 *   <LI>Determine whether a user has any TOTP shared secrets and manipulate the
 *       registered secrets.</LI>
 *   <LI>Get, set, and clear the public IDs of any YubiKey OTP devices
 *       registered for a user.</LI>
 *   <LI>Determine whether the user has a static password.</LI>
 *   <LI>Get, set, and clear the time that the server last performed validation
 *       on a password provided in a bind request.</LI>
 *   <LI>Get and set whether the user's account is locked because it contains a
 *       password that does not satisfy all of the configured password
 *       validators.</LI>
 *   <LI>Get and clear a user's recent login history.</LI>
 * </UL>
 * Note that many of these methods are dependent upon the password policy
 * configuration for the target user and therefore some of them may not be
 * applicable for some users.  For example, if password expiration is not
 * enabled in the password policy associated with the target user, then
 * operations that involve password expiration will have no effect and/or will
 * have a return value that indicates that password expiration is not in effect.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PasswordPolicyStateOperation
       implements Serializable
{
  /**
   * The operation type that may be used to retrieve the DN of the password
   * policy to which the user is subject.
   */
  public static final int OP_TYPE_GET_PW_POLICY_DN = 0;



  /**
   * The operation type that may be used to determine whether the user account
   * is disabled.
   */
  public static final int OP_TYPE_GET_ACCOUNT_DISABLED_STATE = 1;



  /**
   * The operation type that may be used to specify whether the user account is
   * disabled.
   */
  public static final int OP_TYPE_SET_ACCOUNT_DISABLED_STATE = 2;



  /**
   * The operation type that may be used to clear the account disabled flag in
   * the user's entry.
   */
  public static final int OP_TYPE_CLEAR_ACCOUNT_DISABLED_STATE = 3;



  /**
   * The operation type that may be used to get the time that the user's account
   * will expire.
   */
  public static final int OP_TYPE_GET_ACCOUNT_EXPIRATION_TIME = 4;



  /**
   * The operation type that may be used to set the time that the user's account
   * will expire.
   */
  public static final int OP_TYPE_SET_ACCOUNT_EXPIRATION_TIME = 5;



  /**
   * The operation type that may be used to clear the user's account expiration
   * time.
   */
  public static final int OP_TYPE_CLEAR_ACCOUNT_EXPIRATION_TIME = 6;



  /**
   * The operation type that may be used to retrieve the length of time in
   * seconds until the user's account expires.
   */
  public static final int OP_TYPE_GET_SECONDS_UNTIL_ACCOUNT_EXPIRATION = 7;



  /**
   * The operation type that may be used to get the time that the user's
   * password was last changed.
   */
  public static final int OP_TYPE_GET_PW_CHANGED_TIME = 8;



  /**
   * The operation type that may be used to set the time that the user's
   * password was last changed.
   */
  public static final int OP_TYPE_SET_PW_CHANGED_TIME = 9;



  /**
   * The operation type that may be used to clear the password changed time in
   * the user's account.
   */
  public static final int OP_TYPE_CLEAR_PW_CHANGED_TIME = 10;



  /**
   * The operation type that may be used to get the time that the user was
   * first sent a password expiration warning.
   */
  public static final int OP_TYPE_GET_PW_EXPIRATION_WARNED_TIME = 11;



  /**
   * The operation type that may be used to set the time that the user was
   * first sent a password expiration warning.
   */
  public static final int OP_TYPE_SET_PW_EXPIRATION_WARNED_TIME = 12;



  /**
   * The operation type that may be used to clear the password expiration warned
   * time from the user's entry.
   */
  public static final int OP_TYPE_CLEAR_PW_EXPIRATION_WARNED_TIME = 13;



  /**
   * The operation type that may be used to get the length of time in seconds
   * until the user's password expires.
   */
  public static final int OP_TYPE_GET_SECONDS_UNTIL_PW_EXPIRATION = 14;



  /**
   * The operation type that may be used to get the length of time in seconds
   * until the user will be eligible to receive a password expiration warning.
   */
  public static final int OP_TYPE_GET_SECONDS_UNTIL_PW_EXPIRATION_WARNING = 15;



  /**
   * The operation type that may be used to get the set of times that the user
   * has unsuccessfully tried to authenticate since the last successful attempt.
   */
  public static final int OP_TYPE_GET_AUTH_FAILURE_TIMES = 16;



  /**
   * The operation type that may be used to add a new authentication failure
   * time to the user's account.
   */
  public static final int OP_TYPE_ADD_AUTH_FAILURE_TIME = 17;



  /**
   * The operation type that may be used to set the set of times that the user
   * has unsuccessfully tried to authenticate since the last successful attempt.
   */
  public static final int OP_TYPE_SET_AUTH_FAILURE_TIMES = 18;



  /**
   * The operation type that may be used to clear the authentication failure
   * times in the user account.
   */
  public static final int OP_TYPE_CLEAR_AUTH_FAILURE_TIMES = 19;



  /**
   * The operation type that may be used to retrieve the length of time in
   * seconds until the user's account is unlocked.
   */
  public static final int OP_TYPE_GET_SECONDS_UNTIL_AUTH_FAILURE_UNLOCK = 20;



  /**
   * The operation type that may be used to retrieve the number of failed
   * authentication attempts that the user has before the account is locked.
   */
  public static final int OP_TYPE_GET_REMAINING_AUTH_FAILURE_COUNT = 21;



  /**
   * The operation type that may be used to retrieve the time that the user last
   * authenticated to the server.
   */
  public static final int OP_TYPE_GET_LAST_LOGIN_TIME = 22;



  /**
   * The operation type that may be used to set the time that the user last
   * authenticated to the server.
   */
  public static final int OP_TYPE_SET_LAST_LOGIN_TIME = 23;



  /**
   * The operation type that may be used to clear the last login time in the
   * user's entry.
   */
  public static final int OP_TYPE_CLEAR_LAST_LOGIN_TIME = 24;



  /**
   * The operation type that may be used to get the length of time in seconds
   * until the user account is locked due to inactivity.
   */
  public static final int OP_TYPE_GET_SECONDS_UNTIL_IDLE_LOCKOUT = 25;



  /**
   * The operation type that may be used to determine whether a user's password
   * has been reset by an administrator and must be changed.
   */
  public static final int OP_TYPE_GET_PW_RESET_STATE = 26;



  /**
   * The operation type that may be used to set the flag to indicate whether a
   * user's password has been reset by an administrator and must be changed.
   */
  public static final int OP_TYPE_SET_PW_RESET_STATE = 27;



  /**
   * The operation type that may be used to clear the password reset flag in the
   * user's entry.
   */
  public static final int OP_TYPE_CLEAR_PW_RESET_STATE = 28;



  /**
   * The operation type that may be used to get the length of time in seconds
   * until the user's account is locked due to failure to change the password
   * after an administrative reset.
   */
  public static final int OP_TYPE_GET_SECONDS_UNTIL_PW_RESET_LOCKOUT = 29;



  /**
   * The operation type that may be used to retrieve the times that the user has
   * authenticated using a grace login after his/her password has expired.
   */
  public static final int OP_TYPE_GET_GRACE_LOGIN_USE_TIMES = 30;



  /**
   * The operation type that may be used add a value to the set of times that
   * the user has authenticated using a grace login after his/her password has
   * expired.
   */
  public static final int OP_TYPE_ADD_GRACE_LOGIN_USE_TIME = 31;



  /**
   * The operation type that may be used to set the times that the user has
   * authenticated using a grace login after his/her password has expired.
   */
  public static final int OP_TYPE_SET_GRACE_LOGIN_USE_TIMES = 32;



  /**
   * The operation type that may be used to clear the set of times that the user
   * has authenticated using a grace login after his/her password has expired.
   */
  public static final int OP_TYPE_CLEAR_GRACE_LOGIN_USE_TIMES = 33;



  /**
   * The operation type that may be used to retrieve the number of grace logins
   * available for the user.
   */
  public static final int OP_TYPE_GET_REMAINING_GRACE_LOGIN_COUNT = 34;



  /**
   * The operation type that may be used to retrieve the last time that the
   * user's password was changed during a required change period.
   */
  public static final int OP_TYPE_GET_PW_CHANGED_BY_REQUIRED_TIME = 35;



  /**
   * The operation type that may be used to set the last time that the
   * user's password was changed during a required change period.
   */
  public static final int OP_TYPE_SET_PW_CHANGED_BY_REQUIRED_TIME = 36;



  /**
   * The operation type that may be used to clear the last time that the
   * user's password was changed during a required change period.
   */
  public static final int OP_TYPE_CLEAR_PW_CHANGED_BY_REQUIRED_TIME = 37;



  /**
   * The operation type that may be used to get the length of time in seconds
   * until the user's account will be locked due to a failure to change the
   * password by a required time.
   */
  public static final int OP_TYPE_GET_SECONDS_UNTIL_REQUIRED_CHANGE_TIME = 38;



  /**
   * The operation type that may be used to retrieve the stored password history
   * values for a user.
   *
   * @deprecated  This operation type has been deprecated in favor of the
   *              {@link #OP_TYPE_GET_PW_HISTORY_COUNT} operation type.
   */
  @Deprecated()
  public static final int OP_TYPE_GET_PW_HISTORY = 39;



  /**
   * The operation type that may be used to clear the stored password history
   * values for a user.
   */
  public static final int OP_TYPE_CLEAR_PW_HISTORY = 40;



  /**
   * The operation type that may be used to determine whether a user has a valid
   * retired password.
   */
  public static final int OP_TYPE_HAS_RETIRED_PASSWORD = 41;



  /**
   * The operation type that may be used to retrieve the time that the user's
   * former password was retired.
   */
  public static final int OP_TYPE_GET_PASSWORD_RETIRED_TIME = 42;



  /**
   * The operation type that may be used to retrieve the time that the user's
   * retired password will expire.
   */
  public static final int OP_TYPE_GET_RETIRED_PASSWORD_EXPIRATION_TIME = 43;



  /**
   * The operation type that may be used to purge any retired password from the
   * user's entry.
   */
  public static final int OP_TYPE_PURGE_RETIRED_PASSWORD = 44;



  /**
   * The operation type that may be used to get the time that the user's account
   * will become active.
   */
  public static final int OP_TYPE_GET_ACCOUNT_ACTIVATION_TIME = 45;



  /**
   * The operation type that may be used to set the time that the user's account
   * will become active.
   */
  public static final int OP_TYPE_SET_ACCOUNT_ACTIVATION_TIME = 46;



  /**
   * The operation type that may be used to clear the user's account activation
   * time.
   */
  public static final int OP_TYPE_CLEAR_ACCOUNT_ACTIVATION_TIME = 47;



  /**
   * The operation type that may be used to retrieve the length of time in
   * seconds until the user's account will become active.
   */
  public static final int OP_TYPE_GET_SECONDS_UNTIL_ACCOUNT_ACTIVATION = 48;



  /**
   * The operation type that may be used to retrieve the IP address from which
   * the user last authenticated to the server.
   */
  public static final int OP_TYPE_GET_LAST_LOGIN_IP_ADDRESS = 49;



  /**
   * The operation type that may be used to set the IP address from which the
   * user last authenticated to the server.
   */
  public static final int OP_TYPE_SET_LAST_LOGIN_IP_ADDRESS = 50;



  /**
   * The operation type that may be used to clear the last login IP address in
   * the user's entry.
   */
  public static final int OP_TYPE_CLEAR_LAST_LOGIN_IP_ADDRESS = 51;



  /**
   * The operation type that may be used to retrieve a list of structured
   * strings that provide information about notices pertaining to account
   * usability.
   */
  public static final int OP_TYPE_GET_ACCOUNT_USABILITY_NOTICES = 52;



  /**
   * The operation type that may be used to retrieve a list of structured
   * strings that provide information about warnings that may affect the account
   * usability.
   */
  public static final int OP_TYPE_GET_ACCOUNT_USABILITY_WARNINGS = 53;



  /**
   * The operation type that may be used to retrieve a list of structured
   * strings that provide information about errors that may affect the account
   * usability.
   */
  public static final int OP_TYPE_GET_ACCOUNT_USABILITY_ERRORS = 54;



  /**
   * The operation type that may be used to determine whether an account is
   * usable (i.e., the account may authenticate or be used as an alternate
   * authorization identity).
   */
  public static final int OP_TYPE_GET_ACCOUNT_IS_USABLE = 55;



  /**
   * The operation type that may be used to determine whether an account is
   * not yet active (because the account activation time is in the future).
   */
  public static final int OP_TYPE_GET_ACCOUNT_IS_NOT_YET_ACTIVE = 56;



  /**
   * The operation type that may be used to determine whether an account is
   * expired (because the account expiration time is in the past).
   */
  public static final int OP_TYPE_GET_ACCOUNT_IS_EXPIRED = 57;



  /**
   * The operation type that may be used to determine when a user's password
   * will expire.
   */
  public static final int OP_TYPE_GET_PW_EXPIRATION_TIME = 58;



  /**
   * The operation type that may be used to determine whether a user's account
   * is locked because of too many authentication failures.
   */
  public static final int OP_TYPE_GET_ACCOUNT_IS_FAILURE_LOCKED = 59;



  /**
   * The operation type that may be used to specify whether a user's account
   * is locked because of too many authentication failures.
   */
  public static final int OP_TYPE_SET_ACCOUNT_IS_FAILURE_LOCKED = 60;



  /**
   * The operation type that may be used to determine the failure lockout time
   * for a user account.
   */
  public static final int OP_TYPE_GET_FAILURE_LOCKOUT_TIME = 61;



  /**
   * The operation type that may be used to determine whether a user's account
   * is locked because it has been idle for too long.
   */
  public static final int OP_TYPE_GET_ACCOUNT_IS_IDLE_LOCKED = 62;



  /**
   * The operation type that may be used to determine the idle lockout time for
   * a user account.
   */
  public static final int OP_TYPE_GET_IDLE_LOCKOUT_TIME = 63;



  /**
   * The operation type that may be used to determine whether a user's account
   * is locked because the user did not change their password in a timely manner
   * after an administrative reset.
   */
  public static final int OP_TYPE_GET_ACCOUNT_IS_RESET_LOCKED = 64;



  /**
   * The operation type that may be used to determine the reset lockout time for
   * a user account.
   */
  public static final int OP_TYPE_GET_RESET_LOCKOUT_TIME = 65;



  /**
   * The operation type that may be used to retrieve the password history count
   * for a user.
   */
  public static final int OP_TYPE_GET_PW_HISTORY_COUNT = 66;



  /**
   * The operation type that may be used to determine whether a user's password
   * is expired.
   */
  public static final int OP_TYPE_GET_PW_IS_EXPIRED = 67;



  /**
   * The operation type that may be used to retrieve a list of the SASL
   * mechanisms that are available for a user.
   */
  public static final int OP_TYPE_GET_AVAILABLE_SASL_MECHANISMS = 68;



  /**
   * The operation type that may be used to retrieve a list of the one-time
   * password delivery mechanisms that are available for a user.
   */
  public static final int OP_TYPE_GET_AVAILABLE_OTP_DELIVERY_MECHANISMS = 69;



  /**
   * The operation type that may be used to determine whether a user has one or
   * more TOTP shared secrets.
   */
  public static final int OP_TYPE_HAS_TOTP_SHARED_SECRET = 70;



  /**
   * The operation type that may be used to retrieve get the set of public IDs
   * for the registered YubiKey OTP devices for a user.
   */
  public static final int OP_TYPE_GET_REGISTERED_YUBIKEY_PUBLIC_IDS = 71;



  /**
   * The operation type that may be used to add a value to the set of registered
   * YubiKey OTP device public IDs for a user.
   */
  public static final int OP_TYPE_ADD_REGISTERED_YUBIKEY_PUBLIC_ID = 72;



  /**
   * The operation type that may be used to remove a value from the set of
   * registered YubiKey OTP device public IDs for a user.
   */
  public static final int OP_TYPE_REMOVE_REGISTERED_YUBIKEY_PUBLIC_ID = 73;



  /**
   * The operation type that may be used to replace the set of public IDs for
   * the registered YubiKey OTP devices for a user.
   */
  public static final int OP_TYPE_SET_REGISTERED_YUBIKEY_PUBLIC_IDS = 74;



  /**
   * The operation type that may be used to clear the set of public IDs for
   * the registered YubiKey OTP devices for a user.
   */
  public static final int OP_TYPE_CLEAR_REGISTERED_YUBIKEY_PUBLIC_IDS = 75;



  /**
   * The operation type that may be used to add a value to the set of registered
   * TOTP shared secrets for a user.
   */
  public static final int OP_TYPE_ADD_TOTP_SHARED_SECRET = 76;



  /**
   * The operation type that may be used to remove a value from the set of
   * registered TOTP shared secrets for a user.
   */
  public static final int OP_TYPE_REMOVE_TOTP_SHARED_SECRET = 77;



  /**
   * The operation type that may be used to replace the set of registered TOTP
   * shared secrets for a user.
   */
  public static final int OP_TYPE_SET_TOTP_SHARED_SECRETS = 78;



  /**
   * The operation type that may be used to clear the set of TOTP shared secrets
   * for a user.
   */
  public static final int OP_TYPE_CLEAR_TOTP_SHARED_SECRETS = 79;



  /**
   * The operation type that may be used to determine whether a user has one
   * or more registered YubiKey OTP devices.
   * shared secret.
   */
  public static final int OP_TYPE_HAS_REGISTERED_YUBIKEY_PUBLIC_ID = 80;



  /**
   * The operation type that may be used to determine whether a user has a
   * static password.
   */
  public static final int OP_TYPE_HAS_STATIC_PASSWORD = 81;



  /**
   * The operation type that may be used to retrieve the time that the server
   * last invoked password validation during a bind operation for a user.
   */
  public static final int OP_TYPE_GET_LAST_BIND_PASSWORD_VALIDATION_TIME = 82;



  /**
   * The operation type that may be used to retrieve the length of time in
   * seconds since the server last invoked password validation during a bind
   * operation.
   */
  public static final int
       OP_TYPE_GET_SECONDS_SINCE_LAST_BIND_PASSWORD_VALIDATION = 83;



  /**
   * The operation type that may be used to set the time that the server last
   * invoked password validation during a bind operation for a user.
   */
  public static final int OP_TYPE_SET_LAST_BIND_PASSWORD_VALIDATION_TIME = 84;



  /**
   * The operation type that may be used to clear the time that the server last
   * invoked password validation during a bind operation for a user.
   */
  public static final int OP_TYPE_CLEAR_LAST_BIND_PASSWORD_VALIDATION_TIME = 85;



  /**
   * The operation type that may be used to determine whether a user's account
   * is locked because it contains a password that does not satisfy all of the
   * configured password validators.
   */
  public static final int OP_TYPE_GET_ACCOUNT_IS_VALIDATION_LOCKED = 86;



  /**
   * The operation type that may be used to specify whether a user's account
   * is locked because it contains a password that does not satisfy all of the
   * configured password validators.
   */
  public static final int OP_TYPE_SET_ACCOUNT_IS_VALIDATION_LOCKED = 87;



  /**
   * The operation type that may be used to retrieve a user's recent login
   * history.
   */
  public static final int OP_TYPE_GET_RECENT_LOGIN_HISTORY = 88;



  /**
   * The operation type that may be used to clear a user's recent login history.
   */
  public static final int OP_TYPE_CLEAR_RECENT_LOGIN_HISTORY = 89;



  /**
   * The set of values that will be used if there are no values.
   */
  @NotNull private static final ASN1OctetString[] NO_VALUES =
       new ASN1OctetString[0];



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7711496660183073026L;



  // The set of values for this operation.
  @NotNull private final ASN1OctetString[] values;

  // The operation type for this operation.
  private final int opType;



  /**
   * Creates a new password policy state operation with the specified operation
   * type and no values.
   *
   * @param  opType  The operation type for this password policy state
   *                 operation.
   */
  public PasswordPolicyStateOperation(final int opType)
  {
    this(opType, NO_VALUES);
  }



  /**
   * Creates a new password policy state operation with the specified operation
   * type and set of values.
   *
   * @param  opType  The operation type for this password policy state
   *                 operation.
   * @param  values  The set of values for this password policy state operation.
   */
  public PasswordPolicyStateOperation(final int opType,
                                      @Nullable final ASN1OctetString[] values)
  {
    this.opType = opType;

    if (values == null)
    {
      this.values = NO_VALUES;
    }
    else
    {
      this.values = values;
    }
  }



  /**
   * Creates a new password policy state operation that may be used to request
   * the DN of the password policy configuration entry for the user.  The result
   * returned should include an operation of type
   * {@link #OP_TYPE_GET_PW_POLICY_DN} with a single string value that is the
   * DN of the password policy configuration entry.
   *
   * @return The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetPasswordPolicyDNOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_PW_POLICY_DN);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * whether the user account is disabled.  The result returned should include
   * an operation of type {@link #OP_TYPE_GET_ACCOUNT_DISABLED_STATE} with a
   * single boolean value of {@code true} if the account is disabled, or
   * {@code false} if the account is not disabled.
   *
   * @return The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetAccountDisabledStateOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_ACCOUNT_DISABLED_STATE);
  }



  /**
   * Creates a new password policy state operation that may be used to specify
   * whether the user account is disabled.  The result returned should include
   * an operation of type {@link #OP_TYPE_GET_ACCOUNT_DISABLED_STATE} with a
   * single boolean value of {@code true} if the account has been disabled, or
   * {@code false} if the account is not disabled.
   *
   * @param  isDisabled  Indicates whether the user account should be disabled.
   *
   * @return The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createSetAccountDisabledStateOperation(
                          final boolean isDisabled)
  {
    final ASN1OctetString[] values =
    {
      new ASN1OctetString(String.valueOf(isDisabled))
    };

    return new PasswordPolicyStateOperation(OP_TYPE_SET_ACCOUNT_DISABLED_STATE,
         values);
  }



  /**
   * Creates a new password policy state operation that may be used to clear
   * the user account disabled state in the user's entry.  The result returned
   * should include an operation of type
   * {@link #OP_TYPE_GET_ACCOUNT_DISABLED_STATE} with a single boolean value of
   * {@code true} if the account is disabled, or {@code false} if the account is
   * not disabled.
   *
   * @return The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createClearAccountDisabledStateOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_CLEAR_ACCOUNT_DISABLED_STATE);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * the time that the user's account will become active.  The result returned
   * should include an operation of type
   * {@link #OP_TYPE_GET_ACCOUNT_ACTIVATION_TIME} with a single string value
   * that is the generalized time representation of the account activation time,
   * or a {@code null} value if the account does not have an activation time.
   *
   * @return The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetAccountActivationTimeOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_ACCOUNT_ACTIVATION_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to set the
   * time that the user's account expires.  The result returned should include
   * an operation of type {@link #OP_TYPE_GET_ACCOUNT_ACTIVATION_TIME} with a
   * single string value that is the generalized time representation of the
   * account activation time, or a {@code null} value if the account does not
   * have an activation time.
   *
   * @param  expirationTime  The time that the user's account should expire.  It
   *                         may be {@code null} if the server should use the
   *                         current time.
   *
   * @return The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createSetAccountActivationTimeOperation(
                          @Nullable final Date expirationTime)
  {
    return new PasswordPolicyStateOperation(OP_TYPE_SET_ACCOUNT_ACTIVATION_TIME,
         createValues(expirationTime));
  }



  /**
   * Creates a new password policy state operation that may be used to clear
   * the account expiration time in the user's entry.  The result returned
   * should include an operation of type
   * {@link #OP_TYPE_GET_ACCOUNT_ACTIVATION_TIME} with a single string value
   * that is the generalized time representation of the account activation time,
   * or a {@code null} value if the account does not have an activation time.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createClearAccountActivationTimeOperation()
  {
    return new PasswordPolicyStateOperation(
                    OP_TYPE_CLEAR_ACCOUNT_ACTIVATION_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the length of time in seconds until the user's account becomes active.  The
   * result returned should include an operation of type
   * {@link #OP_TYPE_GET_SECONDS_UNTIL_ACCOUNT_ACTIVATION} with a single integer
   * value representing the number of seconds until the account becomes active,
   * or a {@code null} value if the account does not have an activation time.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetSecondsUntilAccountActivationOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_SECONDS_UNTIL_ACCOUNT_ACTIVATION);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * the time that the user's account expires.  The result returned should
   * include an operation of type {@link #OP_TYPE_GET_ACCOUNT_EXPIRATION_TIME}
   * with a single string value that is the generalized time representation of
   * the account expiration time, or a {@code null} value if the account does
   * not have an expiration time.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetAccountExpirationTimeOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_ACCOUNT_EXPIRATION_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to set the
   * time that the user's account expires.  The result returned should include
   * an operation of type {@link #OP_TYPE_GET_ACCOUNT_EXPIRATION_TIME} with a
   * single string value that is the generalized time representation of the
   * account expiration time, or a {@code null} value if the account does not
   * have an expiration time.
   *
   * @param  expirationTime  The time that the user's account should expire.  It
   *                         may be {@code null} if the server should use the
   *                         current time.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createSetAccountExpirationTimeOperation(
                          @Nullable final Date expirationTime)
  {
    return new PasswordPolicyStateOperation(OP_TYPE_SET_ACCOUNT_EXPIRATION_TIME,
         createValues(expirationTime));
  }



  /**
   * Creates a new password policy state operation that may be used to clear
   * the account expiration time in the user's entry.  The result returned
   * should include an operation of type
   * {@link #OP_TYPE_GET_ACCOUNT_EXPIRATION_TIME} with a single string value
   * that is the generalized time representation of the account expiration time,
   * or a {@code null} value if the account does not have an expiration time.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createClearAccountExpirationTimeOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_CLEAR_ACCOUNT_EXPIRATION_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the length of time in seconds until the user's account is expired.  The
   * result returned should include an operation of type
   * {@link #OP_TYPE_GET_SECONDS_UNTIL_ACCOUNT_EXPIRATION} with a single integer
   * value representing the number of seconds until the account will expire, or
   * a {@code null} value if the account does not have an expiration time.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetSecondsUntilAccountExpirationOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_SECONDS_UNTIL_ACCOUNT_EXPIRATION);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * when the user's password was last changed.  The result returned should
   * include an operation of type {@link #OP_TYPE_GET_PW_CHANGED_TIME} with a
   * single string value that is the generalized time representation of the
   * time the password was last changed.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetPasswordChangedTimeOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_PW_CHANGED_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to specify
   * when the user's password was last changed.  The result returned should
   * include an operation of type {@link #OP_TYPE_GET_PW_CHANGED_TIME} with a
   * single string value that is the generalized time representation of the
   * time the password was last changed.
   *
   * @param  passwordChangedTime  The time the user's password was last changed.
   *                              It may be {@code null} if the server should
   *                              use the current time.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createSetPasswordChangedTimeOperation(
                          @Nullable final Date passwordChangedTime)
  {
    return new PasswordPolicyStateOperation(OP_TYPE_SET_PW_CHANGED_TIME,
         createValues(passwordChangedTime));
  }



  /**
   * Creates a new password policy state operation that may be used to clear
   * the password changed time from a user's entry.  The result returned should
   * include an operation of type {@link #OP_TYPE_GET_PW_CHANGED_TIME} with a
   * single string value that is the generalized time representation of the
   * time the password was last changed, or {@code null} if it can no longer be
   * determined.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createClearPasswordChangedTimeOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_CLEAR_PW_CHANGED_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * when the user first received a password expiration warning.  The result
   * returned should include an operation of type
   * {@link #OP_TYPE_GET_PW_EXPIRATION_WARNED_TIME} with a single string value
   * that is the generalized time representation of the time the user received
   * the first expiration warning.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetPasswordExpirationWarnedTimeOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_PW_EXPIRATION_WARNED_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to specify
   * when the user first received a password expiration warning.  The result
   * returned should include an operation of type
   * {@link #OP_TYPE_GET_PW_EXPIRATION_WARNED_TIME} with a single string value
   * that is the generalized time representation of the time the user received
   * the first expiration warning.
   *
   * @param  passwordExpirationWarnedTime  The password expiration warned time
   *                                       for the user.  It may be {@code null}
   *                                       if the server should use the current
   *                                       time.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createSetPasswordExpirationWarnedTimeOperation(
                          @Nullable final Date passwordExpirationWarnedTime)
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_SET_PW_EXPIRATION_WARNED_TIME,
         createValues(passwordExpirationWarnedTime));
  }



  /**
   * Creates a new password policy state operation that may be used to clear the
   * password expiration warned time from the user's entry.  The result returned
   * should include an operation of type
   * {@link #OP_TYPE_GET_PW_EXPIRATION_WARNED_TIME} with a single string value
   * that is the generalized time representation of the time the user received
   * the first expiration warning.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createClearPasswordExpirationWarnedTimeOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_CLEAR_PW_EXPIRATION_WARNED_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the length of time in seconds until the user's password expires.  The
   * result returned should include an operation of type
   * {@link #OP_TYPE_GET_SECONDS_UNTIL_PW_EXPIRATION} with a single integer
   * value that is the number of seconds until the user's password expires, or
   * a {@code null} value if the user's password will not expire.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetSecondsUntilPasswordExpirationOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_SECONDS_UNTIL_PW_EXPIRATION);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the length of time in seconds until the user is eligible to start receiving
   * password expiration warnings.  The result returned should include an
   * operation of type {@link #OP_TYPE_GET_SECONDS_UNTIL_PW_EXPIRATION_WARNING}
   * with a single integer value that is the number of seconds until the user is
   * eligible to receive the first expiration warning, or a {@code null} value
   * if the user's password will not expire.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetSecondsUntilPasswordExpirationWarningOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_SECONDS_UNTIL_PW_EXPIRATION_WARNING);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * the times that the user has unsuccessfully tried to authenticate since the
   * last successful authentication.  The result returned should include an
   * operation of type {@link #OP_TYPE_GET_AUTH_FAILURE_TIMES} with an array of
   * string values representing the timestamps (in generalized time format) of
   * the authentication failures.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetAuthenticationFailureTimesOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_AUTH_FAILURE_TIMES);
  }



  /**
   * Creates a new password policy state operation that may be used to add the
   * current time to the set of times that the user has unsuccessfully tried to
   * authenticate since the last successful authentication.  The result returned
   * should include an operation of type {@link #OP_TYPE_GET_AUTH_FAILURE_TIMES}
   * with an array of string values representing the timestamps (in generalized
   * time format) of the authentication failures.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createAddAuthenticationFailureTimeOperation()
  {
    return createAddAuthenticationFailureTimeOperation(null);
  }



  /**
   * Creates a new password policy state operation that may be used to add the
   * specified values to the set of times that the user has unsuccessfully tried
   * to authenticate since the last successful authentication.  The result
   * returned should include an operation of type
   * {@link #OP_TYPE_GET_AUTH_FAILURE_TIMES} with an array of string values
   * representing the timestamps (in generalized time format) of the
   * authentication failures.
   *
   * @param  authFailureTimes  The set of authentication failure time values to
   *                           add.  It may be {@code null} or empty if the
   *                           server should add the current time.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createAddAuthenticationFailureTimeOperation(
                          @Nullable final Date[] authFailureTimes)
  {
    return new PasswordPolicyStateOperation(OP_TYPE_ADD_AUTH_FAILURE_TIME,
         createValues(authFailureTimes));
  }



  /**
   * Creates a new password policy state operation that may be used to specify
   * the set of times that the user has unsuccessfully tried to authenticate
   * since the last successful authentication.  The result returned should
   * include an operation of type {@link #OP_TYPE_GET_AUTH_FAILURE_TIMES} with
   * an array of string values representing the timestamps (in generalized time
   * format) of the authentication failures.
   *
   * @param  authFailureTimes  The set of times that the user has unsuccessfully
   *                           tried to authenticate since the last successful
   *                           authentication.  It may be {@code null} or empty
   *                           if the server should use the current time as the
   *                           only failure time.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createSetAuthenticationFailureTimesOperation(
                          @Nullable final Date[] authFailureTimes)
  {
    return new PasswordPolicyStateOperation(OP_TYPE_SET_AUTH_FAILURE_TIMES,
         createValues(authFailureTimes));
  }



  /**
   * Creates a new password policy state operation that may be used to clear the
   * set of times that the user has unsuccessfully tried to authenticate since
   * the last successful authentication.  The result returned should include an
   * operation of type {@link #OP_TYPE_GET_AUTH_FAILURE_TIMES} with an array of
   * string values representing the timestamps (in generalized time format) of
   * the authentication failures.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createClearAuthenticationFailureTimesOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_CLEAR_AUTH_FAILURE_TIMES);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the length of time in seconds until the user's account is automatically
   * unlocked after too many failed authentication attempts.  The result
   * returned should include an operation of type
   * {@link #OP_TYPE_GET_SECONDS_UNTIL_AUTH_FAILURE_UNLOCK} with a single
   * integer value that represents the number of seconds until the account
   * becomes unlocked, or a {@code null} value if the account is not temporarily
   * locked as a result of authentication failures.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetSecondsUntilAuthenticationFailureUnlockOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_SECONDS_UNTIL_AUTH_FAILURE_UNLOCK);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the number of authentication failures required to lock the user's account.
   * The result returned should include an operation of type
   * {@link #OP_TYPE_GET_REMAINING_AUTH_FAILURE_COUNT} with a single integer
   * value that represents the number of authentication failures that a user
   * will be permitted before the account is locked, or a {@code null} value if
   * the password policy is not configured to lock accounts as a result of too
   * many failed authentication attempts.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetRemainingAuthenticationFailureCountOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_REMAINING_AUTH_FAILURE_COUNT);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the time that the user last successfully authenticated to the server.  The
   * result returned should include an operation of type
   * {@link #OP_TYPE_GET_LAST_LOGIN_TIME} with a single string value that is
   * the generalized time representation of the user's last login time, or a
   * {@code null} value if no last login time is available.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation createGetLastLoginTimeOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_LAST_LOGIN_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to set
   * the time that the user last successfully authenticated to the server.  The
   * result returned should include an operation of type
   * {@link #OP_TYPE_GET_LAST_LOGIN_TIME} with a single string value that is
   * the generalized time representation of the user's last login time, or a
   * {@code null} value if no last login time is available.
   *
   * @param  lastLoginTime  The last login time to set in the user's entry.  It
   *                        may be {@code null} if the server should use the
   *                        current time.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createSetLastLoginTimeOperation(
                          @Nullable final Date lastLoginTime)
  {
    return new PasswordPolicyStateOperation(OP_TYPE_SET_LAST_LOGIN_TIME,
         createValues(lastLoginTime));
  }



  /**
   * Creates a new password policy state operation that may be used to clear
   * the last login time from the user's entry.  The result returned should
   * include an operation of type {@link #OP_TYPE_GET_LAST_LOGIN_TIME} with a
   * single string value that is the generalized time representation of the
   * user's last login time, or a {@code null} value if no last login time is
   * available.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation createClearLastLoginTimeOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_CLEAR_LAST_LOGIN_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the IP address from which the user last successfully authenticated to the
   * server.  The result returned should include an operation of type
   * {@link #OP_TYPE_GET_LAST_LOGIN_IP_ADDRESS} with a single string value that
   * is the user's last login IP address, or a {@code null} value if no last
   * login IP address is available.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetLastLoginIPAddressOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_LAST_LOGIN_IP_ADDRESS);
  }



  /**
   * Creates a new password policy state operation that may be used to set
   * the IP address from which the user last successfully authenticated to the
   * server.  The result returned should include an operation of type
   * {@link #OP_TYPE_GET_LAST_LOGIN_IP_ADDRESS} with a single string value that
   * is the user's last login IP address, or a {@code null} value if no last
   * login IP address is available.
   *
   * @param  lastLoginIPAddress  The last login IP address to set in the user's
   *                             entry.  It must not be {@code null}.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createSetLastLoginIPAddressOperation(
                          @NotNull final String lastLoginIPAddress)
  {
    final ASN1OctetString[] values =
    {
      new ASN1OctetString(lastLoginIPAddress)
    };

    return new PasswordPolicyStateOperation(OP_TYPE_SET_LAST_LOGIN_IP_ADDRESS,
         values);
  }



  /**
   * Creates a new password policy state operation that may be used to clear
   * the last login IP address from the user's entry.  The result returned
   * should include an operation of type
   * {@link #OP_TYPE_GET_LAST_LOGIN_IP_ADDRESS} with a single string value that
   * is the user's last login IP address, or a {@code null} value if no last
   * login IP address is available.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createClearLastLoginIPAddressOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_CLEAR_LAST_LOGIN_IP_ADDRESS);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the length of time in seconds until the user's account is locked due to
   * inactivity.  The result returned should include an operation of type
   * {@link #OP_TYPE_GET_SECONDS_UNTIL_IDLE_LOCKOUT} with a single integer value
   * that represents the number of seconds until the user's account is locked as
   * a result of being idle for too long, or a {@code null} value if no idle
   * account lockout is configured.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetSecondsUntilIdleLockoutOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_SECONDS_UNTIL_IDLE_LOCKOUT);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * whether the user's password has been reset by an administrator and must be
   * changed before performing any other operations.  The result returned should
   * include an operation of type {@link #OP_TYPE_GET_PW_RESET_STATE} with a
   * single boolean value of {@code true} if the user's password must be changed
   * before the account can be used, or {@code false} if not.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetPasswordResetStateOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_PW_RESET_STATE);
  }



  /**
   * Creates a new password policy state operation that may be used to specify
   * whether the user's password has been reset by an administrator and must be
   * changed before performing any other operations.  The result returned should
   * include an operation of type {@link #OP_TYPE_GET_PW_RESET_STATE} with a
   * single boolean value of {@code true} if the user's password must be changed
   * before the account can be used, or {@code false} if not.
   *
   * @param  isReset  Specifies whether the user's password must be changed
   *                  before performing any other operations.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createSetPasswordResetStateOperation(final boolean isReset)
  {
    final ASN1OctetString[] values =
    {
      new ASN1OctetString(String.valueOf(isReset))
    };

    return new PasswordPolicyStateOperation(OP_TYPE_SET_PW_RESET_STATE, values);
  }



  /**
   * Creates a new password policy state operation that may be used to clear the
   * password reset state information in the user's entry.  The result returned
   * should include an operation of type {@link #OP_TYPE_GET_PW_RESET_STATE}
   * with a single boolean value of {@code true} if the user's password must be
   * changed before the account can be used, or {@code false} if not.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createClearPasswordResetStateOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_CLEAR_PW_RESET_STATE);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the length of time in seconds that the user has left to change his/her
   * password after an administrative reset before the account is locked.  The
   * result returned should include an operation of type
   * {@link #OP_TYPE_GET_SECONDS_UNTIL_PW_RESET_LOCKOUT} with a single integer
   * value that represents the number of seconds until the user's account will
   * be locked unless the password is reset, or a {@code null} value if the
   * user's password is not in a "must change" state.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetSecondsUntilPasswordResetLockoutOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_SECONDS_UNTIL_PW_RESET_LOCKOUT);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * the set of times that the user has authenticated using grace logins since
   * his/her password expired.  The result returned should include an operation
   * of type {@link #OP_TYPE_GET_GRACE_LOGIN_USE_TIMES} with an array of string
   * values in generalized time format.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetGraceLoginUseTimesOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_GRACE_LOGIN_USE_TIMES);
  }



  /**
   * Creates a new password policy state operation that may be used to add the
   * current time to the set of times that the user has authenticated using
   * grace logins since his/her password expired.  The result returned should
   * include an operation of type {@link #OP_TYPE_GET_GRACE_LOGIN_USE_TIMES}
   * with an array of string values in generalized time format.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createAddGraceLoginUseTimeOperation()
  {
    return createAddGraceLoginUseTimeOperation(null);
  }



  /**
   * Creates a new password policy state operation that may be used to add the
   * current time to the set of times that the user has authenticated using
   * grace logins since his/her password expired.  The result returned should
   * include an operation of type {@link #OP_TYPE_GET_GRACE_LOGIN_USE_TIMES}
   * with an array of string values in generalized time format.
   *
   * @param  graceLoginUseTimes  The set of grace login use times to add.  It
   *                             may be {@code null} or empty if the server
   *                             should add the current time to the set of grace
   *                             login times.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createAddGraceLoginUseTimeOperation(
                          @Nullable final Date[] graceLoginUseTimes)
  {
    return new PasswordPolicyStateOperation(OP_TYPE_ADD_GRACE_LOGIN_USE_TIME,
         createValues(graceLoginUseTimes));
  }



  /**
   * Creates a new password policy state operation that may be used to specify
   * the set of times that the user has authenticated using grace logins since
   * his/her password expired.  The result returned should include an operation
   * of type {@link #OP_TYPE_GET_GRACE_LOGIN_USE_TIMES} with an array of string
   * values in generalized time format.
   *
   * @param  graceLoginUseTimes  The set of times that the user has
   *                             authenticated using grace logins since his/her
   *                             password expired.  It amy be {@code null} or
   *                             empty if the server should use the current time
   *                             as the only grace login use time.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createSetGraceLoginUseTimesOperation(
                          @Nullable final Date[] graceLoginUseTimes)
  {
    return new PasswordPolicyStateOperation(OP_TYPE_SET_GRACE_LOGIN_USE_TIMES,
         createValues(graceLoginUseTimes));
  }



  /**
   * Creates a new password policy state operation that may be used to clear
   * the set of times that the user has authenticated using grace logins since
   * his/her password expired.  The result returned should include an operation
   * of type {@link #OP_TYPE_GET_GRACE_LOGIN_USE_TIMES} with an array of string
   * values in generalized time format.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createClearGraceLoginUseTimesOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_CLEAR_GRACE_LOGIN_USE_TIMES);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * the number of remaining grace logins available to the user.  The result
   * returned should include an operation of type
   * {@link #OP_TYPE_GET_REMAINING_GRACE_LOGIN_COUNT} with a single integer
   * value that represents the number of remaining grace logins, or a
   * {@code null} value if grace login functionality is not enabled for the
   * user.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetRemainingGraceLoginCountOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_REMAINING_GRACE_LOGIN_COUNT);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * the last required password change time that with which the user has
   * complied.  The result returned should include an operation of type
   * {@link #OP_TYPE_GET_PW_CHANGED_BY_REQUIRED_TIME} with a single string
   * value that is the generalized time representation of the most recent
   * required password change time with which the user complied, or a
   * {@code null} value if this is not available for the user.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetPasswordChangedByRequiredTimeOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_PW_CHANGED_BY_REQUIRED_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to update
   * the user's entry to indicate that he/she has complied with the required
   * password change time.  The result returned should include an operation of
   * type {@link #OP_TYPE_GET_PW_CHANGED_BY_REQUIRED_TIME} with a single string
   * value that is the generalized time representation of the most recent
   * required password change time with which the user complied, or a
   * {@code null} value if this is not available for the user.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createSetPasswordChangedByRequiredTimeOperation()
  {
    return createSetPasswordChangedByRequiredTimeOperation(null);
  }



  /**
   * Creates a new password policy state operation that may be used to update
   * the user's entry to indicate that he/she has complied with the required
   * password change time.  The result returned should include an operation of
   * type {@link #OP_TYPE_GET_PW_CHANGED_BY_REQUIRED_TIME} with a single string
   * value that is the generalized time representation of the most recent
   * required password change time with which the user complied, or a
   * {@code null} value if this is not available for the user.
   *
   * @param  requiredTime  The required password changed time with which the
   *                       user has complied.  It may be {@code null} if the
   *                       server should use the most recent required change
   *                       time.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createSetPasswordChangedByRequiredTimeOperation(
                          @Nullable final Date requiredTime)
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_SET_PW_CHANGED_BY_REQUIRED_TIME, createValues(requiredTime));
  }



  /**
   * Creates a new password policy state operation that may be used to clear
   * the last required password change time from the user's entry.  The result
   * returned should include an operation of type
   * {@link #OP_TYPE_GET_PW_CHANGED_BY_REQUIRED_TIME} with a single string value
   * that is the generalized time representation of the most recent required
   * password change time with which the user complied, or a {@code null} value
   * if this is not available for the user.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createClearPasswordChangedByRequiredTimeOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_CLEAR_PW_CHANGED_BY_REQUIRED_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * the length of time in seconds until the required password change time
   * arrives.  The result returned should include an operation of type
   * {@link #OP_TYPE_GET_SECONDS_UNTIL_REQUIRED_CHANGE_TIME} with a single
   * integer value that represents the number of seconds before the user will
   * be required to change his/her password as a result of the
   * require-change-by-time property, or a {@code null} value if the user is
   * not required to change their password for this reason.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetSecondsUntilRequiredChangeTimeOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_SECONDS_UNTIL_REQUIRED_CHANGE_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * the password history values stored in the user's entry.  The result
   * returned should include an operation of type
   * {@link #OP_TYPE_GET_PW_HISTORY} with an array of strings representing the
   * user's password history content.
   *
   * @return  The created password policy state operation.
   *
   * @deprecated  This method has been deprecated in favor of the
   *              {@link #createGetPasswordHistoryCountOperation} method.
   */
  @Deprecated()
  @SuppressWarnings("deprecation")
  @NotNull()
  public static PasswordPolicyStateOperation createGetPasswordHistoryOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_PW_HISTORY);
  }



  /**
   * Creates a new password policy state operation that may be used to clear the
   * password history values stored in the user's entry.  The result returned
   * should include an operation of type {@link #OP_TYPE_GET_PW_HISTORY} with an
   * array of strings representing the user's password history content.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createClearPasswordHistoryOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_CLEAR_PW_HISTORY);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * whether the user has a valid retired password.  The result returned should
   * include an operation of type {@link #OP_TYPE_HAS_RETIRED_PASSWORD} with a
   * single boolean value of {@code true} if the user has a valid retired
   * password, or {@code false} if not.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation createHasRetiredPasswordOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_HAS_RETIRED_PASSWORD);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the time that the user's former password was retired.  The result returned
   * should include an operation of type
   * {@link #OP_TYPE_GET_PASSWORD_RETIRED_TIME} with a single string value that
   * is the generalized time representation of the time the user's former
   * password was retired, or a {@code null} value if the user does not have a
   * valid retired password.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetPasswordRetiredTimeOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_PASSWORD_RETIRED_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the length of time until the user's retired password expires.  The result
   * returned should include an operation of type
   * {@link #OP_TYPE_GET_RETIRED_PASSWORD_EXPIRATION_TIME} with a single string
   * value that is the generalized time representation of the time the user's
   * retired password will cease to be valid, or a {@code null} value if the
   * user does not have a valid retired password.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetRetiredPasswordExpirationTimeOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_RETIRED_PASSWORD_EXPIRATION_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to purge
   * any retired password from the user's entry.  The result returned should
   * include an operation of type {@link #OP_TYPE_HAS_RETIRED_PASSWORD} with a
   * single boolean value of {@code true} if the user has a valid retired
   * password, or {@code false} if not.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createPurgeRetiredPasswordOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_PURGE_RETIRED_PASSWORD);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * information about any password policy state notices pertaining to the
   * usability of the user's account.  The result returned should include an
   * operation of type {@link #OP_TYPE_GET_ACCOUNT_USABILITY_NOTICES} with an
   * array of strings that represent
   * {@link PasswordPolicyStateAccountUsabilityWarning} values.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetAccountUsabilityNoticesOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_ACCOUNT_USABILITY_NOTICES);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * information about any password policy state warnings that may impact the
   * usability of the user's account.  The result returned should include an
   * operation of type {@link #OP_TYPE_GET_ACCOUNT_USABILITY_WARNINGS} with an
   * array of strings that represent
   * {@link PasswordPolicyStateAccountUsabilityWarning} values.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetAccountUsabilityWarningsOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_ACCOUNT_USABILITY_WARNINGS);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * information about any password policy state errors that may impact the
   * usability of the user's account.  The result returned should include an
   * operation of type {@link #OP_TYPE_GET_ACCOUNT_USABILITY_ERRORS} with an
   * array of strings that represent
   * {@link PasswordPolicyStateAccountUsabilityError} values.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetAccountUsabilityErrorsOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_ACCOUNT_USABILITY_ERRORS);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * whether an account is usable (i.e., the account will be allowed to
   * authenticate and/or be used as an alternate authorization identity.  The
   * result returned should include an operation of type
   * {@link #OP_TYPE_GET_ACCOUNT_IS_USABLE} with a single boolean value that
   * indicates whether the account is usable.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetAccountIsUsableOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_ACCOUNT_IS_USABLE);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * whether an account has an activation time that is in the future.  The
   * result returned should include an operation of type
   * {@link #OP_TYPE_GET_ACCOUNT_IS_NOT_YET_ACTIVE} with a single boolean value
   * that indicates whether the account is not yet active.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetAccountIsNotYetActiveOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_ACCOUNT_IS_NOT_YET_ACTIVE);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * whether an account has an expiration time that is in the past.  The result
   * returned should include an operation of type
   * {@link #OP_TYPE_GET_ACCOUNT_IS_EXPIRED} with a single boolean value that
   * indicates whether the account is expired.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetAccountIsExpiredOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_ACCOUNT_IS_EXPIRED);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * when a user's password is expected to expire.  The result returned should
   * include an operation of type {@link #OP_TYPE_GET_PW_EXPIRATION_TIME} with a
   * single string value that is the generalized time representation of the
   * password expiration time.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetPasswordExpirationTimeOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_PW_EXPIRATION_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * whether an account has been locked because of too many failed
   * authentication attempts.  The result returned should include an operation
   * of type {@link #OP_TYPE_GET_ACCOUNT_IS_FAILURE_LOCKED} with a single
   * boolean value that indicates whether the account is failure locked.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetAccountIsFailureLockedOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_ACCOUNT_IS_FAILURE_LOCKED);
  }



  /**
   * Creates a new password policy state operation that may be used to specify
   * whether an account should be locked because of too many failed
   * authentication attempts.  The result returned should include an operation
   * of type {@link #OP_TYPE_GET_ACCOUNT_IS_FAILURE_LOCKED} with a single
   * boolean value that indicates whether the account is failure locked.
   *
   * @param  isFailureLocked  Indicates whether the account should be locked
   *                          because of too many failed attempts.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createSetAccountIsFailureLockedOperation(
                          final boolean isFailureLocked)
  {
    final ASN1OctetString[] values =
    {
      new ASN1OctetString(String.valueOf(isFailureLocked))
    };

    return new PasswordPolicyStateOperation(
         OP_TYPE_SET_ACCOUNT_IS_FAILURE_LOCKED, values);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * when a user's password is was locked because of too many failed
   * authentication attempts.  The result returned should include an operation
   * of type {@link #OP_TYPE_GET_FAILURE_LOCKOUT_TIME} with a single string
   * value that is the generalized time representation of the failure lockout
   * time.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetFailureLockoutTimeOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_FAILURE_LOCKOUT_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * whether an account has been locked because it has remained idle for too
   * long.  The result returned should include an operation of type
   * {@link #OP_TYPE_GET_ACCOUNT_IS_IDLE_LOCKED} with a single boolean value
   * that indicates whether the account is idle locked.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetAccountIsIdleLockedOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_ACCOUNT_IS_IDLE_LOCKED);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * when a user's password is was locked because of the idle account lockout.
   * The result returned should include an operation of type
   * {@link #OP_TYPE_GET_IDLE_LOCKOUT_TIME} with a single string value that is
   * the generalized time representation of the idle lockout time.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetIdleLockoutTimeOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_IDLE_LOCKOUT_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * whether an account has been locked because the user failed to change their
   * password in a timely manner after an administrative reset.  The result
   * returned should include an operation of type
   * {@link #OP_TYPE_GET_ACCOUNT_IS_RESET_LOCKED} with a single boolean value
   * that indicates whether the account is reset locked.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetAccountIsResetLockedOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_ACCOUNT_IS_RESET_LOCKED);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * when a user's password is was locked because the user failed to change
   * their password in a timely manner after an administrative reset.  The
   * result returned should include an operation of type
   * {@link #OP_TYPE_GET_RESET_LOCKOUT_TIME} with a single string value that is
   * the generalized time representation of the reset lockout time.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetResetLockoutTimeOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_RESET_LOCKOUT_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * the number of passwords currently held in a user's password history.  The
   * result returned should include an operation of type
   * {@link #OP_TYPE_GET_PW_HISTORY_COUNT} with a single integer value that
   * represents the number of passwords in the history, or a {@code null} value
   * if a password history is not enabled for the user.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetPasswordHistoryCountOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_PW_HISTORY_COUNT);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * whether a user's password is expired.  The result returned should include
   * an operation of type {@link #OP_TYPE_GET_PW_IS_EXPIRED} with a single
   * Boolean value that indicates whether the password is expired, or a
   * {@code null} value if password expiration is not enabled for the user.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetPasswordIsExpiredOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_PW_IS_EXPIRED);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * a list of the SASL mechanisms that are available for a user.  This will
   * take into consideration the server's configuration, the types of
   * credentials that a user has, and per-user constraints and preferences.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetAvailableSASLMechanismsOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_AVAILABLE_SASL_MECHANISMS);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * a list of the one-time password delivery mechanisms that are available for
   * a user.  If the user's entry includes information about which OTP delivery
   * mechanisms are preferred, the list will be ordered from most preferred to
   * least preferred.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetAvailableOTPDeliveryMechanismsOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_AVAILABLE_OTP_DELIVERY_MECHANISMS);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * whether the user has at least one TOTP shared secret.  The result returned
   * should include an operation of type {@link #OP_TYPE_HAS_TOTP_SHARED_SECRET}
   * with a single boolean value of {@code true} if the user has one or more
   * TOTP shared secrets, or {@code false} if not.
   *
   * @return  The created password policy state operation.
   *
   * @deprecated  Use {@link #createHasTOTPSharedSecretOperation} instead.
   */
  @Deprecated()
  @NotNull()
  public static PasswordPolicyStateOperation createHasTOTPSharedSecret()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_HAS_TOTP_SHARED_SECRET);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * whether the user has at least one TOTP shared secret.  The result returned
   * should include an operation of type {@link #OP_TYPE_HAS_TOTP_SHARED_SECRET}
   * with a single boolean value of {@code true} if the user has one or more
   * TOTP shared secrets, or {@code false} if not.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createHasTOTPSharedSecretOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_HAS_TOTP_SHARED_SECRET);
  }



  /**
   * Creates a new password policy state operation that may be used to add one
   * or more values to the set of TOTP shared secrets for a user.  The result
   * returned should include an operation of type
   * {@link #OP_TYPE_HAS_TOTP_SHARED_SECRET} with a single boolean value of
   * {@code true} if the user has one or more TOTP shared secrets, or
   * {@code false} if not.
   *
   * @param  totpSharedSecrets  The base32-encoded representations of the TOTP
   *                            shared secrets to add to the user.  It must not
   *                            be {@code null} or empty.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createAddTOTPSharedSecretOperation(
                          @NotNull final String... totpSharedSecrets)
  {
    final ASN1OctetString[] values =
         new ASN1OctetString[totpSharedSecrets.length];
    for (int i=0; i < totpSharedSecrets.length; i++)
    {
      values[i] = new ASN1OctetString(totpSharedSecrets[i]);
    }

    return new PasswordPolicyStateOperation(OP_TYPE_ADD_TOTP_SHARED_SECRET,
         values);
  }



  /**
   * Creates a new password policy state operation that may be used to remove
   * one or more values from the set of TOTP shared secrets for a user.  The
   * result returned should include an operation of type
   * {@link #OP_TYPE_HAS_TOTP_SHARED_SECRET} with a single boolean value of
   * {@code true} if the user has one or more TOTP shared secrets, or
   * {@code false} if not.
   *
   * @param  totpSharedSecrets  The base32-encoded representations of the TOTP
   *                            shared secrets to remove from the user.  It must
   *                            not be {@code null} or empty.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createRemoveTOTPSharedSecretOperation(
                          @NotNull final String... totpSharedSecrets)
  {
    final ASN1OctetString[] values =
         new ASN1OctetString[totpSharedSecrets.length];
    for (int i=0; i < totpSharedSecrets.length; i++)
    {
      values[i] = new ASN1OctetString(totpSharedSecrets[i]);
    }

    return new PasswordPolicyStateOperation(OP_TYPE_REMOVE_TOTP_SHARED_SECRET,
         values);
  }



  /**
   * Creates a new password policy state operation that may be used to replace
   * the set of TOTP shared secrets for a user.  The result returned should
   * include an operation of type {@link #OP_TYPE_HAS_TOTP_SHARED_SECRET} with a
   * single boolean value of {@code true} if the user has one or more TOTP
   * shared secrets, or {@code false} if not.
   *
   * @param  totpSharedSecrets  The base32-encoded representations of the TOTP
   *                            shared secrets for the user.  It must not be
   *                            {@code null} but may be empty.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createSetTOTPSharedSecretsOperation(
                          @NotNull final String... totpSharedSecrets)
  {
    final ASN1OctetString[] values =
         new ASN1OctetString[totpSharedSecrets.length];
    for (int i=0; i < totpSharedSecrets.length; i++)
    {
      values[i] = new ASN1OctetString(totpSharedSecrets[i]);
    }

    return new PasswordPolicyStateOperation(OP_TYPE_SET_TOTP_SHARED_SECRETS,
         values);
  }



  /**
   * Creates a new password policy state operation that may be used to clear
   * the set of TOTP shared secrets for a user.  The result returned should
   * include an operation of type {@link #OP_TYPE_HAS_TOTP_SHARED_SECRET} with a
   * single boolean value of {@code true} if the user has one or more TOTP
   * shared secrets, or {@code false} if not.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createClearTOTPSharedSecretsOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_CLEAR_TOTP_SHARED_SECRETS);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * whether the user has at least one registered YubiKey OTP device.  The
   * result returned should include an operation of type
   * {@link #OP_TYPE_HAS_REGISTERED_YUBIKEY_PUBLIC_ID}
   * with a single boolean value of {@code true} if the user has one or more
   * registered devices, or {@code false} if not.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation createHasYubiKeyPublicIDOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_HAS_REGISTERED_YUBIKEY_PUBLIC_ID);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * the public IDs of the YubiKey OTP devices registered for a user.  The
   * result returned should include an operation of type
   * {@link #OP_TYPE_GET_REGISTERED_YUBIKEY_PUBLIC_IDS} with an array of string
   * values that represent the public IDs of the registered YubiKey OTP devices.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetRegisteredYubiKeyPublicIDsOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_REGISTERED_YUBIKEY_PUBLIC_IDS);
  }



  /**
   * Creates a new password policy state operation that may be used to add one
   * or more values to the set of the public IDs of the YubiKey OTP devices
   * registered for a user.  The result returned should include an operation of
   * type {@link #OP_TYPE_GET_REGISTERED_YUBIKEY_PUBLIC_IDS} with an array of
   * string values that represent the public IDs of the registered YubiKey OTP
   * devices.
   *
   * @param  publicIDs  The set of public IDs to add to the set of YubiKey OTP
   *                    devices registered for the user.  It must not be
   *                    {@code null} or empty.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createAddRegisteredYubiKeyPublicIDOperation(
                          @NotNull final String... publicIDs)
  {
    final ASN1OctetString[] values = new ASN1OctetString[publicIDs.length];
    for (int i=0; i < publicIDs.length; i++)
    {
      values[i] = new ASN1OctetString(publicIDs[i]);
    }

    return new PasswordPolicyStateOperation(
         OP_TYPE_ADD_REGISTERED_YUBIKEY_PUBLIC_ID, values);
  }



  /**
   * Creates a new password policy state operation that may be used to remove
   * one or more values from the set of the public IDs of the YubiKey OTP
   * devices registered for a user.  The result returned should include an
   * operation of type {@link #OP_TYPE_GET_REGISTERED_YUBIKEY_PUBLIC_IDS} with
   * an array of string values that represent the public IDs of the registered
   * YubiKey OTP devices.
   *
   * @param  publicIDs  The set of public IDs to remove from the set of YubiKey
   *                    OTP devices registered for the user.  It must not be
   *                    {@code null} or empty.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createRemoveRegisteredYubiKeyPublicIDOperation(
                          @NotNull final String... publicIDs)
  {
    final ASN1OctetString[] values = new ASN1OctetString[publicIDs.length];
    for (int i=0; i < publicIDs.length; i++)
    {
      values[i] = new ASN1OctetString(publicIDs[i]);
    }

    return new PasswordPolicyStateOperation(
         OP_TYPE_REMOVE_REGISTERED_YUBIKEY_PUBLIC_ID, values);
  }



  /**
   * Creates a new password policy state operation that may be used to replace
   * the set of the public IDs of the YubiKey OTP devices registered for a user.
   * The result returned should include an operation of type
   * {@link #OP_TYPE_GET_REGISTERED_YUBIKEY_PUBLIC_IDS} with an array of string
   * values that represent the public IDs of the registered YubiKey OTP devices.
   *
   * @param  publicIDs  The set of public IDs for the YubiKey OTP devices
   *                    registered for the user.  It must not be {@code null}
   *                    but may be empty.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createSetRegisteredYubiKeyPublicIDsOperation(
                          @NotNull final String... publicIDs)
  {
    final ASN1OctetString[] values = new ASN1OctetString[publicIDs.length];
    for (int i=0; i < publicIDs.length; i++)
    {
      values[i] = new ASN1OctetString(publicIDs[i]);
    }

    return new PasswordPolicyStateOperation(
         OP_TYPE_SET_REGISTERED_YUBIKEY_PUBLIC_IDS, values);
  }



  /**
   * Creates a new password policy state operation that may be used to clear
   * the set of the public IDs of the YubiKey OTP devices registered for a user.
   * The result returned should include an operation of type
   * {@link #OP_TYPE_GET_REGISTERED_YUBIKEY_PUBLIC_IDS} with an array of string
   * values that represent the public IDs of the registered YubiKey OTP devices.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createClearRegisteredYubiKeyPublicIDsOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_CLEAR_REGISTERED_YUBIKEY_PUBLIC_IDS);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * whether the user has a static password.  The result should include an
   * operation of type {@link #OP_TYPE_HAS_STATIC_PASSWORD} with a single
   * boolean value of {@code true} if the user has a static password, or
   * {@code false} if not.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation createHasStaticPasswordOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_HAS_STATIC_PASSWORD);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * the time that the server last invoked password validators during a bind
   * operation for the target user.  The result should include an operation of
   * type {@link #OP_TYPE_GET_LAST_BIND_PASSWORD_VALIDATION_TIME} with a
   * single string value that is the generalized time representation of the last
   * bind password validation time, or a {@code null} value if the account does
   * not have a last bind password validation time.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetLastBindPasswordValidationTimeOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_LAST_BIND_PASSWORD_VALIDATION_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the length of time in seconds since the server last invoked password
   * validators during a bind operation for the target user.  The result should
   * include an operation of type
   * {@link #OP_TYPE_GET_SECONDS_SINCE_LAST_BIND_PASSWORD_VALIDATION} with a
   * single integer value representing the number of seconds since the last
   * bind password validation time, or a {@code null} value if the account does
   * not have a last bind password validation time.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetSecondsSinceLastBindPasswordValidationOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_SECONDS_SINCE_LAST_BIND_PASSWORD_VALIDATION);
  }



  /**
   * Creates a new password policy state operation that may be used to set the
   * time that the server last invoked password validators during a bind
   * operation for the target user.  The result returned should include an
   * operation of type {@link #OP_TYPE_GET_LAST_BIND_PASSWORD_VALIDATION_TIME}
   * with a  single string value that is the generalized time representation of
   * the last bind password validation time, or a {@code null} value if the
   * account does not have a last bind password validation time.
   *
   * @param  validationTime  The time that the server last invoke password
   *                         validators during a bind operation for the target
   *                         user.  It may be {@code null} if the server should
   *                         use the current time.
   *
   * @return The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createSetLastBindPasswordValidationTimeOperation(
                          @Nullable final Date validationTime)
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_SET_LAST_BIND_PASSWORD_VALIDATION_TIME,
         createValues(validationTime));
  }



  /**
   * Creates a new password policy state operation that may be used to clear the
   * last bind password validation time in the user's entry.  The result
   * returned should include an operation of type
   * {@link #OP_TYPE_GET_LAST_BIND_PASSWORD_VALIDATION_TIME} with a single
   * string value that is the generalized time representation of the last bind
   * password validation time, or a {@code null} value if the account does not
   * have a last bind password validation time.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createClearLastBindPasswordValidationTimeOperation()
  {
    return new PasswordPolicyStateOperation(
                    OP_TYPE_CLEAR_LAST_BIND_PASSWORD_VALIDATION_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * whether an account has been locked because it contains a password that does
   * not satisfy all of the configured password validators.  The result returned
   * should include an operation of type
   * {@link #OP_TYPE_GET_ACCOUNT_IS_VALIDATION_LOCKED} with a single boolean
   * value that indicates whether the account is validation locked.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetAccountIsValidationLockedOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_ACCOUNT_IS_VALIDATION_LOCKED);
  }



  /**
   * Creates a new password policy state operation that may be used to specify
   * whether an account should be locked because it contains a password that
   * does not satisfy all of the configured password validators.  The result
   * authentication attempts.  The result returned should include an operation
   * of type {@link #OP_TYPE_SET_ACCOUNT_IS_VALIDATION_LOCKED} with a single
   * boolean value that indicates whether the account is validation locked.
   *
   * @param  isValidationLocked  Indicates whether the account should be locked
   *                             because it contains a password that does not
   *                             satisfy all of the configured password
   *                             validators.
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createSetAccountIsValidationLockedOperation(
                          final boolean isValidationLocked)
  {
    final ASN1OctetString[] values =
    {
      new ASN1OctetString(String.valueOf(isValidationLocked))
    };

    return new PasswordPolicyStateOperation(
         OP_TYPE_SET_ACCOUNT_IS_VALIDATION_LOCKED, values);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * the recent login history for a user.  The result returned should include an
   * operation of type {@link #OP_TYPE_GET_RECENT_LOGIN_HISTORY} with a single
   * string value that is a JSON object that represents the user's recent login
   * history/
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createGetRecentLoginHistoryOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_RECENT_LOGIN_HISTORY);
  }



  /**
   * Creates a new password policy state operation that may be used to clear
   * the recent login history for a user.  The result returned should include an
   * operation of type {@link #OP_TYPE_GET_RECENT_LOGIN_HISTORY} with a single
   * string value that is a JSON object that represents the user's recent login
   * history/
   *
   * @return  The created password policy state operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation
                     createClearRecentLoginHistoryOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_CLEAR_RECENT_LOGIN_HISTORY);
  }



  /**
   * Retrieves the operation type for this password policy state operation.
   *
   * @return  The operation type for this password policy state operation.
   */
  public int getOperationType()
  {
    return opType;
  }



  /**
   * Retrieves the set of raw values for this password policy state operation.
   *
   * @return  The set of raw values for this password policy state operation.
   */
  @NotNull()
  public ASN1OctetString[] getRawValues()
  {
    return values;
  }



  /**
   * Retrieves the string representation of the value for this password policy
   * state operation.  If there are multiple values, then the first will be
   * returned.
   *
   * @return  The string representation of the value for this password policy
   *          state operation, or {@code null} if there are no values.
   */
  @Nullable()
  public String getStringValue()
  {
    if (values.length == 0)
    {
      return null;
    }
    else
    {
      return values[0].stringValue();
    }
  }



  /**
   * Retrieves the string representations of the values for this password policy
   * state operation.
   *
   * @return  The string representations of the values for this password policy
   *          state operation.
   */
  @NotNull()
  public String[] getStringValues()
  {
    final String[] stringValues = new String[values.length];
    for (int i=0; i < values.length; i++)
    {
      stringValues[i] = values[i].stringValue();
    }

    return stringValues;
  }



  /**
   * Retrieves the boolean representation of the value for this password policy
   * state operation.
   *
   * @return  The boolean representation of the value for this password policy
   *          state operation.
   *
   * @throws  IllegalStateException  If this operation does not have exactly one
   *                                 value, or if the value cannot be decoded as
   *                                 a boolean value.
   */
  public boolean getBooleanValue()
         throws IllegalStateException
  {
    if (values.length != 1)
    {
      throw new IllegalStateException(
           ERR_PWP_STATE_INVALID_BOOLEAN_VALUE_COUNT.get(values.length));
    }

    final String valueString = StaticUtils.toLowerCase(values[0].stringValue());
    if (valueString.equals("true"))
    {
      return true;
    }
    else if (valueString.equals("false"))
    {
      return false;
    }
    else
    {
      throw new IllegalStateException(
           ERR_PWP_STATE_VALUE_NOT_BOOLEAN.get(values[0].stringValue()));
    }
  }



  /**
   * Retrieves the integer representation of the value for this password policy
   * state operation.  If there are multiple values, then the first will be
   * returned.
   *
   * @return  The integer representation of the value for this password policy
   *          operation.
   *
   * @throws  IllegalStateException  If this operation does not have any values.
   *
   * @throws  NumberFormatException  If the value cannot be parsed as an
   *                                 integer.
   */
  public int getIntValue()
         throws IllegalStateException, NumberFormatException
  {
    if (values.length == 0)
    {
      throw new IllegalStateException(ERR_PWP_STATE_NO_VALUES.get());
    }

    return Integer.parseInt(values[0].stringValue());
  }



  /**
   * Retrieves the {@code Date} object represented by the value for this
   * password policy state operation treated as a timestamp in generalized time
   * form.  If there are multiple values, then the first will be returned.
   *
   * @return  The {@code Date} object represented by the value for this password
   *          policy state operation treated as a timestamp in generalized time
   *          form, or {@code null} if this operation does not have any values.
   *
   * @throws  ParseException  If the value cannot be decoded as a timestamp in
   *                          generalized time form.
   */
  @Nullable()
  public Date getGeneralizedTimeValue()
         throws ParseException
  {
    if (values.length == 0)
    {
      return null;
    }

    return StaticUtils.decodeGeneralizedTime(values[0].stringValue());
  }



  /**
   * Retrieves the {@code Date} objects represented by the values for this
   * password policy state operation treated as timestamps in generalized time
   * form.
   *
   * @return  The {@code Date} objects represented by the values for this
   *          password policy state operation treated as timestamps in
   *          generalized time form.
   *
   * @throws  ParseException  If any of the values cannot be decoded as a
   *                          timestamp in generalized time form.
   */
  @NotNull()
  public Date[] getGeneralizedTimeValues()
         throws ParseException
  {
    final Date[] dateValues = new Date[values.length];
    for (int i=0; i < values.length; i++)
    {
      dateValues[i] =
           StaticUtils.decodeGeneralizedTime(values[i].stringValue());
    }

    return dateValues;
  }



  /**
   * Creates an array of ASN.1 octet strings with the provided set of values.
   *
   * @param  dates  The dates from which to create the values.  It may be
   *                {@code null} or empty if there should be no values.
   *
   * @return  The array of ASN.1 octet strings.
   */
  @NotNull()
  private static ASN1OctetString[] createValues(@Nullable final Date... dates)
  {
    if ((dates == null) || (dates.length == 0))
    {
      return NO_VALUES;
    }

    final ArrayList<ASN1OctetString> valueList =
         new ArrayList<ASN1OctetString>(dates.length);
    for (final Date d : dates)
    {
      if (d != null)
      {
        valueList.add(new ASN1OctetString(
             StaticUtils.encodeGeneralizedTime(d)));
      }
    }

    return valueList.toArray(NO_VALUES);
  }



  /**
   * Encodes this password policy state operation for use in the extended
   * request or response.
   *
   * @return  An ASN.1 element containing an encoded representation of this
   *          password policy state operation.
   */
  @NotNull()
  public ASN1Element encode()
  {
    final ASN1Element[] elements;
    if (values.length > 0)
    {
      elements = new ASN1Element[]
      {
        new ASN1Enumerated(opType),
        new ASN1Sequence(values)
      };
    }
    else
    {
      elements = new ASN1Element[]
      {
        new ASN1Enumerated(opType),
      };
    }

    return new ASN1Sequence(elements);
  }



  /**
   * Decodes the provided ASN.1 element as a password policy state operation.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The decoded password policy state operation.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided ASN.1 element as a password policy state
   *                         operation.
   */
  @NotNull()
  public static PasswordPolicyStateOperation decode(
                     @NotNull final ASN1Element element)
         throws LDAPException
  {
    final ASN1Element[] elements;
    try
    {
      elements = ASN1Sequence.decodeAsSequence(element).elements();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PWP_STATE_ELEMENT_NOT_SEQUENCE.get(e), e);
    }

    if ((elements.length < 1) || (elements.length > 2))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PWP_STATE_INVALID_ELEMENT_COUNT.get(
                                   elements.length));
    }

    final int opType;
    try
    {
      opType = ASN1Enumerated.decodeAsEnumerated(elements[0]).intValue();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PWP_STATE_OP_TYPE_NOT_INTEGER.get(e), e);
    }

    final ASN1OctetString[] values;
    if (elements.length == 2)
    {
      try
      {
        final ASN1Element[] valueElements =
             ASN1Sequence.decodeAsSequence(elements[1]).elements();
        values = new ASN1OctetString[valueElements.length];
        for (int i=0; i < valueElements.length; i++)
        {
          values[i] = ASN1OctetString.decodeAsOctetString(valueElements[i]);
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PWP_STATE_CANNOT_DECODE_VALUES.get(e), e);
      }
    }
    else
    {
      values = NO_VALUES;
    }

    return new PasswordPolicyStateOperation(opType, values);
  }



  /**
   * Retrieves a string representation of this password policy state operation.
   *
   * @return  A string representation of this password policy state operation.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this password policy state operation to
   * the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("PasswordPolicyStateOperation(opType=");
    buffer.append(opType);

    if (values.length > 0)
    {
      buffer.append(", values={");
      for (int i=0; i < values.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append('\'');
        buffer.append(values[i].stringValue());
        buffer.append('\'');
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
