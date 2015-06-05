/*
 * Copyright 2008-2015 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015 UnboundID Corp.
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
import java.util.Date;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;



/**
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class is part of the Commercial Edition of the UnboundID
 *   LDAP SDK for Java.  It is not available for use in applications that
 *   include only the Standard Edition of the LDAP SDK, and is not supported for
 *   use in conjunction with non-UnboundID products.
 * </BLOCKQUOTE>
 * This class defines an operation that may be used in conjunction with the
 * password policy state extended operation.  A password policy state operation
 * can be used to get or set various properties of the password policy state for
 * a user.  Operations that are available for use with the password policy state
 * operation include:
 * <UL>
 *   <LI>Get the DN of the password policy configuration entry for the target
 *       user.</LI>
 *   <LI>Get, set, and clear the account disabled flag for the target user.</LI>
 *   <LI>Get, set, and clear the account expiration time for the target
 *       user.</LI>
 *   <LI>Get the length of time in seconds until the target user account
 *       expires.</LI>
 *   <LI>Get the time that the target user's password was last changed.</LI>
 *   <LI>Get and clear the time that the first password expiration warning was
 *       sent to the user.</LI>
 *   <LI>Get the length of time in seconds until the target user's password
 *       expires.</LI>
 *   <LI>Get the length of time in seconds until the user should receive the
 *       first warning about an upcoming password expiration.</LI>
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
 *   <LI>Get and clear the password history for the target user.</LI>
 *   <LI>Get information about or purge a user's retired password.</LI>
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
   */
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
   * The set of values that will be used if there are no values.
   */
  private static final ASN1OctetString[] NO_VALUES = new ASN1OctetString[0];



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7430165299583556387L;



  // The set of values for this operation.
  private final ASN1OctetString[] values;

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
                                      final ASN1OctetString[] values)
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
   * the DN of the password policy configuration entry for the user.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createGetPasswordPolicyDNOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_PW_POLICY_DN);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * whether the user account is disabled.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createGetAccountDisabledStateOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_ACCOUNT_DISABLED_STATE);
  }



  /**
   * Creates a new password policy state operation that may be used to specify
   * whether the user account is disabled.
   *
   * @param  isDisabled  Indicates whether the user account should be disabled.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createSetAccountDisabledStateOperation(final boolean isDisabled)
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
   * the user account disabled state in the user's entry.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createClearAccountDisabledStateOperation()
  {
    return new PasswordPolicyStateOperation(
                    OP_TYPE_CLEAR_ACCOUNT_DISABLED_STATE);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * the time that the user's account expires.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createGetAccountExpirationTimeOperation()
  {
    return new PasswordPolicyStateOperation(
                    OP_TYPE_GET_ACCOUNT_EXPIRATION_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to set the
   * time that the user's account expires.
   *
   * @param  expirationTime  The time that the user's account should expire.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createSetAccountExpirationTimeOperation(final Date expirationTime)
  {
    final ASN1OctetString[] values =
    {
      new ASN1OctetString(encodeGeneralizedTime(expirationTime))
    };

    return new PasswordPolicyStateOperation(OP_TYPE_SET_ACCOUNT_EXPIRATION_TIME,
                                            values);
  }



  /**
   * Creates a new password policy state operation that may be used to clear
   * the account expiration time in the user's entry.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createClearAccountExpirationTimeOperation()
  {
    return new PasswordPolicyStateOperation(
                    OP_TYPE_CLEAR_ACCOUNT_EXPIRATION_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the length of time in seconds until the user's account is expired.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createGetSecondsUntilAccountExpirationOperation()
  {
    return new PasswordPolicyStateOperation(
                    OP_TYPE_GET_SECONDS_UNTIL_ACCOUNT_EXPIRATION);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * when the user's password was last changed.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createGetPasswordChangedTimeOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_PW_CHANGED_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * when the user first received a password expiration warning.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createGetPasswordExpirationWarnedTimeOperation()
  {
    return new PasswordPolicyStateOperation(
                    OP_TYPE_GET_PW_EXPIRATION_WARNED_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to clear the
   * password expiration warned time from the user's entry.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createClearPasswordExpirationWarnedTimeOperation()
  {
    return new PasswordPolicyStateOperation(
                    OP_TYPE_CLEAR_PW_EXPIRATION_WARNED_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the length of time in seconds until the user's password expires.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createGetSecondsUntilPasswordExpirationOperation()
  {
    return new PasswordPolicyStateOperation(
                    OP_TYPE_GET_SECONDS_UNTIL_PW_EXPIRATION);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the length of time in seconds until the user is eligible to start receiving
   * password expiration warnings.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createGetSecondsUntilPasswordExpirationWarningOperation()
  {
    return new PasswordPolicyStateOperation(
                    OP_TYPE_GET_SECONDS_UNTIL_PW_EXPIRATION_WARNING);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * the times that the user has unsuccessfully tried to authenticate since the
   * last successful authentication.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createGetAuthenticationFailureTimesOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_AUTH_FAILURE_TIMES);
  }



  /**
   * Creates a new password policy state operation that may be used to add the
   * current time to the set of times that the user has unsuccessfully tried to
   * authenticate since the last successful authentication.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createAddAuthenticationFailureTimeOperation()
  {
    final ASN1OctetString[] values =
    {
      new ASN1OctetString(encodeGeneralizedTime(new Date()))
    };

    return new PasswordPolicyStateOperation(OP_TYPE_ADD_AUTH_FAILURE_TIME,
                                            values);
  }



  /**
   * Creates a new password policy state operation that may be used to specify
   * the set of times that the user has unsuccessfully tried to authenticate
   * since the last successful authentication.
   *
   * @param  authFailureTimes  The set of times that the user has unsuccessfully
   *                           tried to authenticate since the last successful
   *                           authentication.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createSetAuthenticationFailureTimesOperation(
            final Date[] authFailureTimes)
  {
    final ASN1OctetString[] values;
    if ((authFailureTimes == null) || (authFailureTimes.length == 0))
    {
      values = NO_VALUES;
    }
    else
    {
      values = new ASN1OctetString[authFailureTimes.length];
      for (int i=0; i < authFailureTimes.length; i++)
      {
        values[i] =
             new ASN1OctetString(encodeGeneralizedTime(authFailureTimes[i]));
      }
    }

    return new PasswordPolicyStateOperation(OP_TYPE_SET_AUTH_FAILURE_TIMES,
                                            values);
  }



  /**
   * Creates a new password policy state operation that may be used to clear the
   * set of times that the user has unsuccessfully tried to authenticate since
   * the last successful authentication.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createClearAuthenticationFailureTimesOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_CLEAR_AUTH_FAILURE_TIMES);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the length of time in seconds until the user's account is automatically
   * unlocked after too many failed authentication attempts.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createGetSecondsUntilAuthenticationFailureUnlockOperation()
  {
    return new PasswordPolicyStateOperation(
                    OP_TYPE_GET_SECONDS_UNTIL_AUTH_FAILURE_UNLOCK);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the number of authentication failures required to lock the user's account.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createGetRemainingAuthenticationFailureCountOperation()
  {
    return new PasswordPolicyStateOperation(
                    OP_TYPE_GET_REMAINING_AUTH_FAILURE_COUNT);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the time that the user last successfully authenticated to the server.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation createGetLastLoginTimeOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_LAST_LOGIN_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to set
   * the time that the user last successfully authenticated to the server.
   *
   * @param  lastLoginTime  The last login time to set in the user's entry.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createSetLastLoginTimeOperation(final Date lastLoginTime)
  {
    final ASN1OctetString[] values =
    {
      new ASN1OctetString(encodeGeneralizedTime(lastLoginTime))
    };

    return new PasswordPolicyStateOperation(OP_TYPE_SET_LAST_LOGIN_TIME,
                                            values);
  }



  /**
   * Creates a new password policy state operation that may be used to clear
   * the last login time time from the user's entry.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation createClearLastLoginTimeOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_CLEAR_LAST_LOGIN_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the length of time in seconds until the user's account is locked due to
   * inactivity.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createGetSecondsUntilIdleLockoutOperation()
  {
    return new PasswordPolicyStateOperation(
                    OP_TYPE_GET_SECONDS_UNTIL_IDLE_LOCKOUT);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * whether the user's password has been reset by an administrator and must be
   * changed before performing any other operations.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createGetPasswordResetStateOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_PW_RESET_STATE);
  }



  /**
   * Creates a new password policy state operation that may be used to specify
   * whether the user's password has been reset by an administrator and must be
   * changed before performing any other operations.
   *
   * @param  isReset  Specifies whether the user's password must be changed
   *                  before performing any other operations.
   *
   * @return  The created password policy state operation.
   */
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
   * password reset state information in the user's entry.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createClearPasswordResetStateOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_CLEAR_PW_RESET_STATE);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the length of time in seconds that the user has left to change his/her
   * password after an administrative reset before the account is locked.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createGetSecondsUntilPasswordResetLockoutOperation()
  {
    return new PasswordPolicyStateOperation(
                    OP_TYPE_GET_SECONDS_UNTIL_PW_RESET_LOCKOUT);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * the set of times that the user has authenticated using grace logins since
   * his/her password expired.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createGetGraceLoginUseTimesOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_GRACE_LOGIN_USE_TIMES);
  }



  /**
   * Creates a new password policy state operation that may be used to add the
   * current time to the set of times that the user has authenticated using
   * grace logins since his/her password expired.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createAddGraceLoginUseTimeOperation()
  {
    final ASN1OctetString[] values =
    {
      new ASN1OctetString(encodeGeneralizedTime(new Date()))
    };

    return new PasswordPolicyStateOperation(OP_TYPE_ADD_GRACE_LOGIN_USE_TIME,
                                            values);
  }



  /**
   * Creates a new password policy state operation that may be used to specify
   * the set of times that the user has authenticated using grace logins since
   * his/her password expired.
   *
   * @param  graceLoginUseTimes  The set of times that the user has
   *                             authenticated using grace logins since his/her
   *                             password expired.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createSetGraceLoginUseTimesOperation(final Date[] graceLoginUseTimes)
  {
    final ASN1OctetString[] values;
    if ((graceLoginUseTimes == null) || (graceLoginUseTimes.length == 0))
    {
      values = NO_VALUES;
    }
    else
    {
      values = new ASN1OctetString[graceLoginUseTimes.length];
      for (int i=0; i < graceLoginUseTimes.length; i++)
      {
        values[i] =
             new ASN1OctetString(encodeGeneralizedTime(graceLoginUseTimes[i]));
      }
    }

    return new PasswordPolicyStateOperation(OP_TYPE_SET_GRACE_LOGIN_USE_TIMES,
                                            values);
  }



  /**
   * Creates a new password policy state operation that may be used to clear
   * the set of times that the user has authenticated using grace logins since
   * his/her password expired.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createClearGraceLoginUseTimesOperation()
  {
    return new PasswordPolicyStateOperation(
                    OP_TYPE_CLEAR_GRACE_LOGIN_USE_TIMES);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * the number of remaining grace logins available to the user.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createGetRemainingGraceLoginCountOperation()
  {
    return new PasswordPolicyStateOperation(
                    OP_TYPE_GET_REMAINING_GRACE_LOGIN_COUNT);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * the last required password change time that with which the user has
   * complied.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createGetPasswordChangedByRequiredTimeOperation()
  {
    return new PasswordPolicyStateOperation(
                    OP_TYPE_GET_PW_CHANGED_BY_REQUIRED_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to update
   * the user's entry to indicate that he/she has complied with the required
   * password change time.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createSetPasswordChangedByRequiredTimeOperation()
  {
    return new PasswordPolicyStateOperation(
                    OP_TYPE_SET_PW_CHANGED_BY_REQUIRED_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to clear
   * the last required password change time from the user's entry.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createClearPasswordChangedByRequiredTimeOperation()
  {
    return new PasswordPolicyStateOperation(
                    OP_TYPE_CLEAR_PW_CHANGED_BY_REQUIRED_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * the length of time in seconds until the required password change time
   * arrives.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createGetSecondsUntilRequiredChangeTimeOperation()
  {
    return new PasswordPolicyStateOperation(
                    OP_TYPE_GET_SECONDS_UNTIL_REQUIRED_CHANGE_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to retrieve
   * the password history values stored in the user's entry.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation createGetPasswordHistoryOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_PW_HISTORY);
  }



  /**
   * Creates a new password policy state operation that may be used to clear the
   * password history values stored in the user's entry.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
       createClearPasswordHistoryOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_CLEAR_PW_HISTORY);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * whether the user has a valid retired password.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation createHasRetiredPasswordOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_HAS_RETIRED_PASSWORD);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the time that the user's former password was retired.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
                     createGetPasswordRetiredTimeOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_GET_PASSWORD_RETIRED_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to determine
   * the length of time until the user's retired password expires.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
                     createGetRetiredPasswordExpirationTimeOperation()
  {
    return new PasswordPolicyStateOperation(
         OP_TYPE_GET_RETIRED_PASSWORD_EXPIRATION_TIME);
  }



  /**
   * Creates a new password policy state operation that may be used to purge
   * any retired password from the user's entry.
   *
   * @return  The created password policy state operation.
   */
  public static PasswordPolicyStateOperation
                     createPurgeRetiredPasswordOperation()
  {
    return new PasswordPolicyStateOperation(OP_TYPE_PURGE_RETIRED_PASSWORD);
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

    final String valueString = toLowerCase(values[0].stringValue());
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
  public Date getGeneralizedTimeValue()
         throws ParseException
  {
    if (values.length == 0)
    {
      return null;
    }

    return decodeGeneralizedTime(values[0].stringValue());
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
  public Date[] getGeneralizedTimeValues()
         throws ParseException
  {
    final Date[] dateValues = new Date[values.length];
    for (int i=0; i < values.length; i++)
    {
      dateValues[i] = decodeGeneralizedTime(values[i].stringValue());
    }

    return dateValues;
  }



  /**
   * Encodes this password policy state operation for use in the extended
   * request or response.
   *
   * @return  An ASN.1 element containing an encoded representation of this
   *          password policy state operation.
   */
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
  public static PasswordPolicyStateOperation decode(final ASN1Element element)
         throws LDAPException
  {
    final ASN1Element[] elements;
    try
    {
      elements = ASN1Sequence.decodeAsSequence(element).elements();
    }
    catch (Exception e)
    {
      debugException(e);
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
    catch (Exception e)
    {
      debugException(e);
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
      catch (Exception e)
      {
        debugException(e);
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
  public void toString(final StringBuilder buffer)
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
