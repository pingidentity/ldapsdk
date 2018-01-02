/*
 * Copyright 2015-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class defines a data structure that will provide information about
 * warnings that may affect an account's usability.  It includes a number of
 * predefined warning types, but also allows for the possibility of additional
 * warning types that have not been defined.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PasswordPolicyStateAccountUsabilityWarning
       implements Serializable
{
  /**
   * The numeric value for the warning type that indicates the user's account is
   * about to expire.
   */
  public static final int WARNING_TYPE_ACCOUNT_EXPIRING = 1;



  /**
   * The name for the warning type that indicates the user's account is about
   * to expire.
   */
  public static final String WARNING_NAME_ACCOUNT_EXPIRING = "account-expiring";



  /**
   * The numeric value for the warning type that indicates the user's password
   * is about to expire.
   */
  public static final int WARNING_TYPE_PASSWORD_EXPIRING = 2;



  /**
   * The name for the warning type that indicates the user's password is about
   * to expire.
   */
  public static final String WARNING_NAME_PASSWORD_EXPIRING =
       "password-expiring";



  /**
   * The numeric value for the warning type that indicates the user has one or
   * more failed authentication attempts since the last successful bind, and
   * that the account may be locked if there are too many more failures.
   */
  public static final int WARNING_TYPE_OUTSTANDING_BIND_FAILURES = 3;



  /**
   * The name for the warning type that indicates the user has one or more
   * failed authentication attempts since the last successful bind, and that the
   * account may be locked if there are too many more failures.
   */
  public static final String WARNING_NAME_OUTSTANDING_BIND_FAILURES =
       "outstanding-bind-failures";



  /**
   * The numeric value for the warning type that indicates the user has not
   * authenticated in some time, and the account may be locked in the near
   * future if it remains idle.
   */
  public static final int WARNING_TYPE_ACCOUNT_IDLE = 4;



  /**
   * The name for the warning type that indicates the user has not authenticated
   * in some time, and the account may be locked in the near future if it
   * remains idle.
   */
  public static final String WARNING_NAME_ACCOUNT_IDLE = "account-idle";



  /**
   * The numeric value for the warning type that indicates the user will be
   * required to change his/her password by a specific time because the password
   * policy requires all users to change their passwords by that time.
   */
  public static final int WARNING_TYPE_REQUIRE_PASSWORD_CHANGE_BY_TIME = 5;



  /**
   * The name for the warning type that indicates the user user will be required
   * to change his/her password by a specific time because the password policy
   * requires all users to change their passwords by that time.
   */
  public static final String WARNING_NAME_REQUIRE_PASSWORD_CHANGE_BY_TIME =
       "require-password-change-by-time";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4256291819633130578L;



  // The integer value for this account usability warning.
  private final int intValue;

  // A human-readable message that provides specific details about this account
  // usability warning.
  private final String message;

  // The name for this account usability warning.
  private final String name;

  // The encoded string representation for this account usability warning.
  private final String stringRepresentation;



  /**
   * Creates a new account usability warning with the provided information.
   *
   * @param  intValue  The integer value for this account usability warning.
   * @param  name      The name for this account usability warning.  It must not
   *                   be {@code null}.
   * @param  message   A human-readable message that provides specific details
   *                   about this account usability warning.  It may be
   *                   {@code null} if no message is available.
   */
  public PasswordPolicyStateAccountUsabilityWarning(final int intValue,
                                                    final String name,
                                                    final String message)
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
   * Creates a new account usability warning that is decoded from the provided
   * string representation.
   *
   * @param  stringRepresentation  The string representation of the account
   *                               usability warning to decode.  It must not be
   *                               {@code null}.
   *
   * @throws  LDAPException  If the provided string cannot be decoded as a valid
   *                         account usability warning.
   */
  public PasswordPolicyStateAccountUsabilityWarning(
              final String stringRepresentation)
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
             ERR_PWP_STATE_ACCOUNT_USABILITY_WARNING_CANNOT_DECODE.get(
                  stringRepresentation,
                  ERR_PWP_STATE_ACCOUNT_USABILITY_WARNING_NO_CODE.get()));
      }

      if (n == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PWP_STATE_ACCOUNT_USABILITY_WARNING_CANNOT_DECODE.get(
                  stringRepresentation,
                  ERR_PWP_STATE_ACCOUNT_USABILITY_WARNING_NO_NAME.get()));
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
           ERR_PWP_STATE_ACCOUNT_USABILITY_WARNING_CANNOT_DECODE.get(
                stringRepresentation, StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the integer value for this account usability warning.
   *
   * @return  The integer value for this account usability warning.
   */
  public int getIntValue()
  {
    return intValue;
  }



  /**
   * Retrieves the name for this account usability warning.
   *
   * @return  The name for this account usability warning.
   */
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves a human-readable message that provides specific details about
   * this account usability warning.
   *
   * @return  A human-readable message that provides specific details about this
   *          account usability warning, or {@code null} if no message is
   *          available.
   */
  public String getMessage()
  {
    return message;
  }



  /**
   * Retrieves a string representation of this account usability warning.
   *
   * @return  A string representation of this account usability warning.
   */
  @Override()
  public String toString()
  {
    return stringRepresentation;
  }
}
