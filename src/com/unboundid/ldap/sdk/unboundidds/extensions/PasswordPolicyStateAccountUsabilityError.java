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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.io.Serializable;
import java.util.StringTokenizer;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class defines a data structure that will provide information about
 * errors that may affect an account's usability.  It includes a number of
 * predefined error types, but also allows for the possibility of additional
 * error types that have not been defined.
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
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PasswordPolicyStateAccountUsabilityError
       implements Serializable
{
  /**
   * The numeric value for the error type that indicates the user's account is
   * disabled.
   */
  public static final int ERROR_TYPE_ACCOUNT_DISABLED = 1;



  /**
   * The name for the error type that indicates the user's account is disabled.
   */
  @NotNull public static final String ERROR_NAME_ACCOUNT_DISABLED =
       "account-disabled";



  /**
   * The numeric value for the error type that indicates the user's account is
   * not yet active.
   */
  public static final int ERROR_TYPE_ACCOUNT_NOT_YET_ACTIVE = 2;



  /**
   * The name for the error type that indicates the user's account is not yet
   * valid.
   */
  @NotNull public static final String ERROR_NAME_ACCOUNT_NOT_YET_ACTIVE =
       "account-not-yet-active";



  /**
   * The numeric value for the error type that indicates the user's account is
   * expired.
   */
  public static final int ERROR_TYPE_ACCOUNT_EXPIRED = 3;



  /**
   * The name for the error type that indicates the user's account is expired.
   */
  @NotNull public static final String ERROR_NAME_ACCOUNT_EXPIRED =
       "account-expired";



  /**
   * The numeric value for the error type that indicates the user's account is
   * permanently locked (until the password is reset by an administrator) as a
   * result of too many failed authentication attempts.
   */
  public static final int
       ERROR_TYPE_ACCOUNT_PERMANENTLY_LOCKED_DUE_TO_BIND_FAILURES = 4;



  /**
   * The name for the error type that indicates the user's account is
   * permanently locked (until the password is reset by an administrator) as a
   * result of too many failed authentication attempts.
   */
  @NotNull public static final String
       ERROR_NAME_ACCOUNT_PERMANENTLY_LOCKED_DUE_TO_BIND_FAILURES =
       "account-permanently-locked-due-to-bind-failures";



  /**
   * The numeric value for the error type that indicates the user's account is
   * temporarily locked (until the lockout period elapses or the password is
   * reset by an administrator) as a result of too many failed authentication
   * attempts.
   */
  public static final int
       ERROR_TYPE_ACCOUNT_TEMPORARILY_LOCKED_DUE_TO_BIND_FAILURES = 5;



  /**
   * The name for the error type that indicates the user's account is
   * temporarily locked (until the lockout period elapses or the password is
   * reset by an administrator) as a result of too many failed authentication
   * attempts.
   */
  @NotNull public static final String
       ERROR_NAME_ACCOUNT_TEMPORARILY_LOCKED_DUE_TO_BIND_FAILURES =
       "account-temporarily-locked-due-to-bind-failures";



  /**
   * The numeric value for the error type that indicates the user's account is
   * locked (until the password is reset by an administrator) as a result of
   * remaining idle for too long (i.e., it has been too long since the user last
   * authenticated).
   */
  public static final int ERROR_TYPE_ACCOUNT_IDLE_LOCKED = 6;



  /**
   * The name for the error type that indicates the user's account is locked
   * (until the password is reset by an administrator) as a result of remaining
   * idle for too long (i.e., it has been too long since the user last
   * authenticated).
   */
  @NotNull public static final String ERROR_NAME_ACCOUNT_IDLE_LOCKED =
       "account-idle-locked";



  /**
   * The numeric value for the error type that indicates the user's account is
   * locked (until the password is reset by an administrator) as a result of
   * failing to change the password in a timely manner after it was reset by an
   * administrator.
   */
  public static final int ERROR_TYPE_ACCOUNT_RESET_LOCKED = 7;



  /**
   * The name for the error type that indicates the user's account is locked
   * (until the password is reset by an administrator) as a result of failing to
   * change the password in a timely manner after it was reset by an
   * administrator.
   */
  @NotNull public static final String ERROR_NAME_ACCOUNT_RESET_LOCKED =
       "account-reset-locked";



  /**
   * The numeric value for the error type that indicates the user's password
   * is expired.
   */
  public static final int ERROR_TYPE_PASSWORD_EXPIRED = 8;



  /**
   * The name for the error type that indicates the user's password is expired.
   */
  @NotNull public static final String ERROR_NAME_PASSWORD_EXPIRED =
       "password-expired";



  /**
   * The numeric value for the error type that indicates the user's account is
   * locked (until the password is reset by an administrator) as a result of
   * failing to change the password by a required time.
   */
  public static final int ERROR_TYPE_PASSWORD_NOT_CHANGED_BY_REQUIRED_TIME = 9;



  /**
   * The name for the error type that indicates the user's account is locked
   * (until the password is reset by an administrator) as a result of failing to
   * change the password by a required time.
   */
  @NotNull public static final String
       ERROR_NAME_PASSWORD_NOT_CHANGED_BY_REQUIRED_TIME =
            "password-not-changed-by-required-time";



  /**
   * The numeric value for the error type that indicates the user's password
   * has expired, but the user has one or more grace logins remaining.  The
   * user may still authenticate with a grace login, but will not be permitted
   * to submit any other requests until changing the password.
   */
  public static final int ERROR_TYPE_PASSWORD_EXPIRED_WITH_GRACE_LOGINS = 10;



  /**
   * The name for the error type that indicates the user's password has
   * expired, but the user has one or more grace logins remaining.  The user may
   * still authenticate with a grace login, but will not be permitted to submit
   * any other requests until changing the password.
   */
  @NotNull public static final String
       ERROR_NAME_PASSWORD_EXPIRED_WITH_GRACE_LOGINS =
            "password-expired-with-grace-logins";



  /**
   * The numeric value for the error type that indicates the user must change
   * their password after an administrative reset (or for a newly-created
   * account) before they will be submit any requests.  The user's account may
   * be locked if they do not change their password in a timely manner.
   */
  public static final int ERROR_TYPE_MUST_CHANGE_PASSWORD = 11;



  /**
   * The name for the error type that indicates the user must change their
   * password after an administrative reset (or for a newly-created account)
   * before they will be submit any requests.  The user's account may be locked
   * if they do not change their password in a timely manner.
   */
  @NotNull public static final String ERROR_NAME_MUST_CHANGE_PASSWORD =
       "must-change-password";



  /**
   * The numeric value for the error type that indicates the user's account is
   * locked because it contains a password that does not satisfy all of the
   * configured password validators.
   */
  public static final int ERROR_TYPE_ACCOUNT_VALIDATION_LOCKED = 12;



  /**
   * The name for the error type that indicates the user's account is locked
   * because it contains a password that does not satisfy all of the configured
   * password validators.
   */
  @NotNull public static final String ERROR_NAME_ACCOUNT_VALIDATION_LOCKED =
       "account-validation-locked";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8399539239321392737L;



  // The integer value for this account usability error.
  private final int intValue;

  // A human-readable message that provides specific details about this account
  // usability error.
  @Nullable private final String message;

  // The name for this account usability error.
  @NotNull private final String name;

  // The encoded string representation for this account usability error.
  @NotNull private final String stringRepresentation;



  /**
   * Creates a new account usability error with the provided information.
   *
   * @param  intValue  The integer value for this account usability error.
   * @param  name      The name for this account usability error.  It must not
   *                   be {@code null}.
   * @param  message   A human-readable message that provides specific details
   *                   about this account usability error.  It may be
   *                   {@code null} if no message is available.
   */
  public PasswordPolicyStateAccountUsabilityError(final int intValue,
              @NotNull final String name,
              @Nullable final String message)
  {
    Validator.ensureNotNull(name);

    this.intValue = intValue;
    this.name = name;
    this.message = message;

    final StringBuilder buffer = new StringBuilder();
    buffer.append("code=");
    buffer.append(intValue);
    buffer.append("\tname=");
    buffer.append(name);

    if (message != null)
    {
      buffer.append("\tmessage=");
      buffer.append(message);
    }

    stringRepresentation = buffer.toString();
  }



  /**
   * Creates a new account usability error that is decoded from the provided
   * string representation.
   *
   * @param  stringRepresentation  The string representation of the account
   *                               usability error to decode.  It must not be
   *                               {@code null}.
   *
   * @throws  LDAPException  If the provided string cannot be decoded as a valid
   *                         account usability error.
   */
  public PasswordPolicyStateAccountUsabilityError(
              @NotNull final String stringRepresentation)
         throws LDAPException
  {
    this.stringRepresentation = stringRepresentation;

    try
    {
      Integer i = null;
      String  n = null;
      String  m = null;

      final StringTokenizer tokenizer =
           new StringTokenizer(stringRepresentation, "\t");
      while (tokenizer.hasMoreTokens())
      {
        final String token = tokenizer.nextToken();
        final int equalPos = token.indexOf('=');
        final String fieldName = token.substring(0, equalPos);
        final String fieldValue = token.substring(equalPos+1);
        if (fieldName.equals("code"))
        {
          i = Integer.valueOf(fieldValue);
        }
        else if (fieldName.equals("name"))
        {
          n = fieldValue;
        }
        else if (fieldName.equals("message"))
        {
          m = fieldValue;
        }
      }

      if (i == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PWP_STATE_ACCOUNT_USABILITY_ERROR_CANNOT_DECODE.get(
                  stringRepresentation,
                  ERR_PWP_STATE_ACCOUNT_USABILITY_ERROR_NO_CODE.get()));
      }

      if (n == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PWP_STATE_ACCOUNT_USABILITY_ERROR_CANNOT_DECODE.get(
                  stringRepresentation,
                  ERR_PWP_STATE_ACCOUNT_USABILITY_ERROR_NO_NAME.get()));
      }

      intValue = i;
      name     = n;
      message  = m;
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);

      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PWP_STATE_ACCOUNT_USABILITY_ERROR_CANNOT_DECODE.get(
                stringRepresentation, StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the integer value for this account usability error.
   *
   * @return  The integer value for this account usability error.
   */
  public int getIntValue()
  {
    return intValue;
  }



  /**
   * Retrieves the name for this account usability error.
   *
   * @return  The name for this account usability error.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves a human-readable message that provides specific details about
   * this account usability error.
   *
   * @return  A human-readable message that provides specific details about this
   *          account usability error, or {@code null} if no message is
   *          available.
   */
  @Nullable()
  public String getMessage()
  {
    return message;
  }



  /**
   * Retrieves a string representation of this account usability error.
   *
   * @return  A string representation of this account usability error.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return stringRepresentation;
  }
}
