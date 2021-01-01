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

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class defines a data structure that will provide information about
 * errors that could cause an authentication attempt to fail.  It includes a
 * number of predefined failure types, but but also allows for the possibility
 * of additional failure types that have not been defined.
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
public final class AuthenticationFailureReason
       implements Serializable
{
  /**
   * The numeric value for the failure type that indicates the user's account
   * is not in a usable state.  Examining the set of account usability errors
   * should provide more specific information about the nature of the error.
   */
  public static final int FAILURE_TYPE_ACCOUNT_NOT_USABLE = 1;



  /**
   * The name for the failure type that indicates the user's account is not in a
   * usable state.  Examining the set of account usability errors should provide
   * more specific information about the nature of the error.
   */
  @NotNull public static final String FAILURE_NAME_ACCOUNT_NOT_USABLE =
       "account-not-usable";



  /**
   * The numeric value for the failure type that indicates that the server was
   * unable to assign a client connection policy for the user.
   */
  public static final int FAILURE_TYPE_CANNOT_ASSIGN_CLIENT_CONNECTION_POLICY =
       3;



  /**
   * The name for the failure type that indicates that the server was unable to
   * assign a client connection policy for the user.
   */
  @NotNull public static final String
       FAILURE_NAME_CANNOT_ASSIGN_CLIENT_CONNECTION_POLICY =
       "cannot-assign-client-connection-policy";



  /**
   * The numeric value for the failure type that indicates that the server was
   * unable to identify the user specified as the authentication or
   * authorization identity.
   */
  public static final int FAILURE_TYPE_CANNOT_IDENTIFY_USER = 4;



  /**
   * The numeric value for the failure type that indicates that the server was
   * unable to identify the user specified as the authentication or
   * authorization identity.
   */
  @NotNull public static final String FAILURE_NAME_CANNOT_IDENTIFY_USER =
       "cannot-identify-user";



  /**
   * The numeric value for the failure type that indicates that bind was not
   * permitted by some constraint defined in the server (password policy,
   * client connection policy, operational attributes in the user entry, etc.).
   */
  public static final int FAILURE_TYPE_CONSTRAINT_VIOLATION = 5;



  /**
   * The name for the failure type that indicates that bind was not permitted by
   * some constraint defined in the server (password policy, client connection
   * policy, operational attributes in the user entry, etc.).
   */
  @NotNull public static final String FAILURE_NAME_CONSTRAINT_VIOLATION =
       "constraint-violation";



  /**
   * The numeric value for the failure type that indicates that there was a
   * problem with a control included in the bind request.
   */
  public static final int FAILURE_TYPE_CONTROL_PROBLEM = 6;



  /**
   * The name for the failure type that indicates that there was a problem with
   * a control included in the bind request.
   */
  @NotNull public static final String FAILURE_NAME_CONTROL_PROBLEM =
       "control-problem";



  /**
   * The numeric value for the failure type that indicates that there was a
   * problem with the SASL credentials provided to the server (e.g., they were
   * malformed, out of sequence, or otherwise invalid).
   */
  public static final int FAILURE_TYPE_IMPROPER_SASL_CREDENTIALS = 7;



  /**
   * The name for the failure type that indicates that there was a problem with
   * the SASL credentials provided to the server (e.g., they were malformed, out
   * of sequence, or otherwise invalid).
   */
  @NotNull public static final String FAILURE_NAME_IMPROPER_SASL_CREDENTIALS =
       "improper-sasl-credentials";



  /**
   * The numeric value for the failure type that indicates that the bind was
   * not permitted by the server's access control configuration.
   */
  public static final int FAILURE_TYPE_INSUFFICIENT_ACCESS_RIGHTS = 8;



  /**
   * The name for the failure type that indicates that the bind was not
   * permitted by the server's access control configuration.
   */
  @NotNull public static final String FAILURE_NAME_INSUFFICIENT_ACCESS_RIGHTS =
       "insufficient-access-rights";



  /**
   * The numeric value for the failure type that indicates that the user
   * provided an incorrect password or other form of invalid credentials.
   */
  public static final int FAILURE_TYPE_INVALID_CREDENTIALS = 9;



  /**
   * The name for the failure type that indicates that the user provided an
   * incorrect password or other form of invalid credentials.
   */
  @NotNull public static final String FAILURE_NAME_INVALID_CREDENTIALS =
       "invalid-credentials";



  /**
   * The numeric value for the failure type that indicates that the server is in
   * lockdown mode and will only permit authentication for a limited set of
   * administrators.
   */
  public static final int FAILURE_TYPE_LOCKDOWN_MODE = 10;



  /**
   * The name for the failure type that indicates that the server is in lockdown
   * mode and will only permit authentication for a limited set of
   * administrators.
   */
  @NotNull public static final String FAILURE_NAME_LOCKDOWN_MODE =
       "lockdown-mode";



  /**
   * The numeric value for the failure type that indicates that the user will
   * only be permitted to authenticate in a secure manner.
   */
  public static final int FAILURE_TYPE_SECURE_AUTHENTICATION_REQUIRED = 11;



  /**
   * The name for the failure type that indicates that the user will only be
   * permitted to authenticate in a secure manner.
   */
  @NotNull public static final String
       FAILURE_NAME_SECURE_AUTHENTICATION_REQUIRED =
            "secure-authentication-required";



  /**
   * The numeric value for the failure type that indicates that a server error
   * occurred while processing the bind operation.
   */
  public static final int FAILURE_TYPE_SERVER_ERROR = 12;



  /**
   * The name for the failure type that indicates that a server error occurred
   * while processing the bind operation.
   */
  @NotNull public static final String FAILURE_NAME_SERVER_ERROR =
       "server-error";



  /**
   * The numeric value for the failure type that indicates that a third-party
   * SASL mechanism handler failed to authenticate the user.
   */
  public static final int FAILURE_TYPE_THIRD_PARTY_SASL_AUTHENTICATION_FAILURE =
       13;



  /**
   * The name for the failure type that indicates that a third-party SASL
   * mechanism handler failed to authenticate the user.
   */
  @NotNull public static final String
       FAILURE_NAME_THIRD_PARTY_SASL_AUTHENTICATION_FAILURE =
            "third-party-sasl-authentication-failure";



  /**
   * The numeric value for the failure type that indicates that the attempted
   * authentication type is not available for the target user.
   */
  public static final int FAILURE_TYPE_UNAVAILABLE_AUTHENTICATION_TYPE = 14;



  /**
   * The name for the failure type that indicates that the attempted
   * authentication type is not available for the target user.
   */
  @NotNull public static final  String
       FAILURE_NAME_UNAVAILABLE_AUTHENTICATION_TYPE =
            "unavailable-authentication-type";



  /**
   * The numeric value for a failure type that does not fit into any other of
   * the defined failure types.
   */
  public static final int FAILURE_TYPE_OTHER = 15;



  /**
   * The name for a failure type that does not fit into any other of the defined
   * failure types.
   */
  @NotNull public static final String FAILURE_NAME_OTHER = "other";



  /**
   * The numeric value for the failure type that indicates that the bind request
   * used a password that did not satisfy the configured set of password
   * validators.
   */
  public static final int FAILURE_TYPE_PASSWORD_FAILED_VALIDATION = 16;



  /**
   * The name for the failure type that indicates that the bind request used a
   * password that did not satisfy the configured set of password validators.
   */
  @NotNull public static final String FAILURE_NAME_PASSWORD_FAILED_VALIDATION =
       "password-failed-validation";



  /**
   * The numeric value for the failure type that indicates that a
   * security-related problem was encountered while processing the bind
   * operation.
   */
  public static final int FAILURE_TYPE_SECURITY_PROBLEM = 17;



  /**
   * The name for the failure type that indicates that the bind request used a
   * security-related problem was encountered while processing the bind
   * operation.
   */
  @NotNull public static final String FAILURE_NAME_SECURITY_PROBLEM =
       "security-problem";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4331994950570326032L;



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
   * Creates a new authentication failure reason with the provided information.
   *
   * @param  intValue  The integer value for this authentication failure reason.
   * @param  name      The name for this authentication failure reason.  It must
   *                   not be {@code null}.
   * @param  message   A human-readable message that provides specific details
   *                   about this account usability error.  It may be
   *                   {@code null} if no message is available.
   */
  public AuthenticationFailureReason(final int intValue,
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
   * Creates a new authentication failure reason that is decoded from the
   * provided string representation.
   *
   * @param  stringRepresentation  The string representation of the
   *                               authentication failure reason to decode.  It
   *                               must not be {@code null}.
   *
   * @throws LDAPException  If the provided string cannot be decoded as a valid
   *                         authentication failure reason.
   */
  public AuthenticationFailureReason(@NotNull final String stringRepresentation)
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
             ERR_AUTH_FAILURE_REASON_CANNOT_DECODE.get(stringRepresentation,
                  ERR_AUTH_FAILURE_REASON_NO_CODE.get()));
      }

      if (n == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_AUTH_FAILURE_REASON_CANNOT_DECODE.get(stringRepresentation,
                  ERR_AUTH_FAILURE_REASON_NO_NAME.get()));
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
           ERR_AUTH_FAILURE_REASON_CANNOT_DECODE.get(stringRepresentation,
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the integer value for this authentication failure reason.
   *
   * @return  The integer value for this authentication failure reason.
   */
  public int getIntValue()
  {
    return intValue;
  }



  /**
   * Retrieves the name for this authentication failure reason.
   *
   * @return  The name for this authentication failure reason.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves a human-readable message that provides specific details about
   * this authentication failure reason.
   *
   * @return  A human-readable message that provides specific details about this
   *          authentication failure reason, or {@code null} if no message is
   *          available.
   */
  @Nullable()
  public String getMessage()
  {
    return message;
  }



  /**
   * Retrieves a string representation of this authentication failure reason.
   *
   * @return  A string representation of this authentication failure reason.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return stringRepresentation;
  }
}
