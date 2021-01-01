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
 * notices pertaining to a user's password policy state (items that might be
 * of interest, but do not necessarily represent a current or imminent problem
 * with the account).  It includes a number of predefined notice types, but also
 * allows for the possibility of additional notice types that have not been
 * defined.
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
public final class PasswordPolicyStateAccountUsabilityNotice
       implements Serializable
{
  /**
   * The numeric value for the notice type that indicates the user has a valid
   * outstanding retired password.
   */
  public static final int NOTICE_TYPE_OUTSTANDING_RETIRED_PASSWORD = 1;



  /**
   * The name for the notice type that indicates the user user has a valid
   * outstanding retired password.
   */
  @NotNull public static final String NOTICE_NAME_OUTSTANDING_RETIRED_PASSWORD =
       "outstanding-retired-password";



  /**
   * The numeric value for the notice type that indicates the user has a valid
   * outstanding one-time password.
   */
  public static final int NOTICE_TYPE_OUTSTANDING_ONE_TIME_PASSWORD = 2;



  /**
   * The name for the notice type that indicates the user has a valid
   * outstanding one-time password.
   */
  @NotNull public static final String
       NOTICE_NAME_OUTSTANDING_ONE_TIME_PASSWORD =
            "outstanding-one-time-password";



  /**
   * The numeric value for the notice type that indicates the user has a valid
   * outstanding password reset token.
   */
  public static final int NOTICE_TYPE_OUTSTANDING_PASSWORD_RESET_TOKEN = 3;



  /**
   * The name for the notice type that indicates the user has a valid
   * outstanding password reset token that will expire in the near future.
   */
  @NotNull public static final String
       NOTICE_NAME_OUTSTANDING_PASSWORD_RESET_TOKEN =
            "outstanding-password-reset-token";



  /**
   * The numeric value for the notice type that indicates the user is not
   * currently allowed to change his/her password because they are within the
   * minimum password age.
   */
  public static final int NOTICE_TYPE_IN_MINIMUM_PASSWORD_AGE = 4;



  /**
   * The name for the notice type that indicates the user is not currently
   * allowed to change his/her password because they are within the minimum
   * password age.
   */
  @NotNull public static final String NOTICE_NAME_IN_MINIMUM_PASSWORD_AGE =
       "in-minimum-password-age";



  /**
   * The numeric value for the notice type that indicates that the user does not
   * have a static password.
   */
  public static final int NOTICE_TYPE_NO_STATIC_PASSWORD = 5;



  /**
   * The name for the notice type that indicates that the user does not have a
   * static password.
   */
  @NotNull public static final  String NOTICE_NAME_NO_STATIC_PASSWORD =
       "no-static-password";



  /**
   * The numeric value for the notice type that indicates that although the
   * user's account should be locked as a result of too many outstanding
   * failed authentication attempts, their password policy is configured with a
   * failure lockout action that will not prevent them from authenticating, and
   * should not otherwise have an effect on the usability of their account.
   */
  public static final int NOTICE_TYPE_TOO_MANY_OUTSTANDING_BIND_FAILURES = 6;



  /**
   * The name for the warning type that indicates that although the user's
   * account should be locked as a result of too many outstanding failed
   * authentication attempts, their password policy is configured with a failure
   * lockout action that will not prevent them from authenticating, and should
   * not otherwise have an effect on the usability of their account.
   */
  @NotNull public static final String
       NOTICE_NAME_TOO_MANY_OUTSTANDING_BIND_FAILURES =
            "too-many-outstanding-bind-failures";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6147730018701385799L;



  // The integer value for this account usability notice.
  private final int intValue;

  // A human-readable message that provides specific details about this account
  // usability notice.
  @Nullable private final String message;

  // The name for this account usability notice.
  @NotNull private final String name;

  // The encoded string representation for this account usability notice.
  @NotNull private final String stringRepresentation;



  /**
   * Creates a new account usability notice with the provided information.
   *
   * @param  intValue  The integer value for this account usability notice.
   * @param  name      The name for this account usability notice.  It must not
   *                   be {@code null}.
   * @param  message   A human-readable message that provides specific details
   *                   about this account usability notice.  It may be
   *                   {@code null} if no message is available.
   */
  public PasswordPolicyStateAccountUsabilityNotice(final int intValue,
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
   * Creates a new account usability notice that is decoded from the provided
   * string representation.
   *
   * @param  stringRepresentation  The string representation of the account
   *                               usability notice to decode.  It must not be
   *                               {@code null}.
   *
   * @throws LDAPException  If the provided string cannot be decoded as a valid
   *                         account usability notice.
   */
  public PasswordPolicyStateAccountUsabilityNotice(
              @NotNull final String stringRepresentation)
         throws LDAPException
  {
    this.stringRepresentation = stringRepresentation;

    try
    {
      Integer i = null;
      String n = null;
      String m = null;

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
             ERR_PWP_STATE_ACCOUNT_USABILITY_NOTICE_CANNOT_DECODE.get(
                  stringRepresentation,
                  ERR_PWP_STATE_ACCOUNT_USABILITY_NOTICE_NO_CODE.get()));
      }

      if (n == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PWP_STATE_ACCOUNT_USABILITY_NOTICE_CANNOT_DECODE.get(
                  stringRepresentation,
                  ERR_PWP_STATE_ACCOUNT_USABILITY_NOTICE_NO_NAME.get()));
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
           ERR_PWP_STATE_ACCOUNT_USABILITY_NOTICE_CANNOT_DECODE.get(
                stringRepresentation, StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the integer value for this account usability notice.
   *
   * @return  The integer value for this account usability notice.
   */
  public int getIntValue()
  {
    return intValue;
  }



  /**
   * Retrieves the name for this account usability notice.
   *
   * @return  The name for this account usability notice.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves a human-readable message that provides specific details about
   * this account usability notice.
   *
   * @return  A human-readable message that provides specific details about this
   *          account usability notice, or {@code null} if no message is
   *          available.
   */
  @Nullable()
  public String getMessage()
  {
    return message;
  }



  /**
   * Retrieves a string representation of this account usability notice.
   *
   * @return  A string representation of this account usability notice.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return stringRepresentation;
  }
}
