/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import java.util.Locale;

import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an exception that may be thrown if an error occurs during
 * LDAP-related processing.
 * <BR><BR>
 * This class is primarily intended to be used in the process of updating
 * applications which use the Netscape Directory SDK for Java to switch to or
 * coexist with the UnboundID LDAP SDK for Java.  For applications not written
 * using the Netscape Directory SDK for Java, the
 * {@link com.unboundid.ldap.sdk.LDAPException} class should be used instead.
 */
@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPException
       extends Exception
{
  /**
   * The int value for the SUCCESS result code.
   */
  public static final int SUCCESS = ResultCode.SUCCESS_INT_VALUE;



  /**
   * The int value for the OPERATION_ERROR result code.
   */
  public static final int OPERATION_ERROR =
       ResultCode.OPERATIONS_ERROR_INT_VALUE;



  /**
   * The int value for the PROTOCOL_ERROR result code.
   */
  public static final int PROTOCOL_ERROR = ResultCode.PROTOCOL_ERROR_INT_VALUE;



  /**
   * The int value for the TIME_LIMIT_EXCEEDED result code.
   */
  public static final int TIME_LIMIT_EXCEEDED =
       ResultCode.TIME_LIMIT_EXCEEDED_INT_VALUE;



  /**
   * The int value for the SIZE_LIMIT_EXCEEDED result code.
   */
  public static final int SIZE_LIMIT_EXCEEDED =
       ResultCode.SIZE_LIMIT_EXCEEDED_INT_VALUE;



  /**
   * The int value for the COMPARE_FALSE result code.
   */
  public static final int COMPARE_FALSE = ResultCode.COMPARE_FALSE_INT_VALUE;



  /**
   * The int value for the COMPARE_TRUE result code.
   */
  public static final int COMPARE_TRUE = ResultCode.COMPARE_TRUE_INT_VALUE;



  /**
   * The int value for the AUTH_METHOD_NOT_SUPPORTED result code.
   */
  public static final int AUTH_METHOD_NOT_SUPPORTED =
       ResultCode.AUTH_METHOD_NOT_SUPPORTED_INT_VALUE;



  /**
   * The int value for the STRONG_AUTH_REQUIRED result code.
   */
  public static final int STRONG_AUTH_REQUIRED =
       ResultCode.STRONG_AUTH_REQUIRED_INT_VALUE;



  /**
   * The int value for the LDAP_PARTIAL_RESULTS result code.
   */
  public static final int LDAP_PARTIAL_RESULTS = 9;



  /**
   * The int value for the REFERRAL result code.
   */
  public static final int REFERRAL = ResultCode.REFERRAL_INT_VALUE;



  /**
   * The int value for the ADMIN_LIMIT_EXCEEDED result code.
   */
  public static final int ADMIN_LIMIT_EXCEEDED =
       ResultCode.ADMIN_LIMIT_EXCEEDED_INT_VALUE;



  /**
   * The int value for the UNAVAILABLE_CRITICAL_EXTENSION result code.
   */
  public static final int UNAVAILABLE_CRITICAL_EXTENSION =
       ResultCode.UNAVAILABLE_CRITICAL_EXTENSION_INT_VALUE;



  /**
   * The int value for the CONFIDENTIALITY_REQUIRED result code.
   */
  public static final int CONFIDENTIALITY_REQUIRED =
       ResultCode.CONFIDENTIALITY_REQUIRED_INT_VALUE;



  /**
   * The int value for the SASL_BIND_IN_PROGRESS result code.
   */
  public static final int SASL_BIND_IN_PROGRESS =
       ResultCode.SASL_BIND_IN_PROGRESS_INT_VALUE;



  /**
   * The int value for the NO_SUCH_ATTRIBUTE result code.
   */
  public static final int NO_SUCH_ATTRIBUTE =
       ResultCode.NO_SUCH_ATTRIBUTE_INT_VALUE;



  /**
   * The int value for the UNDEFINED_ATTRIBUTE_TYPE result code.
   */
  public static final int UNDEFINED_ATTRIBUTE_TYPE =
       ResultCode.UNDEFINED_ATTRIBUTE_TYPE_INT_VALUE;



  /**
   * The int value for the INAPPROPRIATE_MATCHING result code.
   */
  public static final int INAPPROPRIATE_MATCHING =
       ResultCode.INAPPROPRIATE_MATCHING_INT_VALUE;



  /**
   * The int value for the CONSTRAINT_VIOLATION result code.
   */
  public static final int CONSTRAINT_VIOLATION =
       ResultCode.CONSTRAINT_VIOLATION_INT_VALUE;



  /**
   * The int value for the ATTRIBUTE_OR_VALUE_EXISTS result code.
   */
  public static final int ATTRIBUTE_OR_VALUE_EXISTS =
       ResultCode.ATTRIBUTE_OR_VALUE_EXISTS_INT_VALUE;



  /**
   * The int value for the INVALID_ATTRIBUTE_SYNTAX result code.
   */
  public static final int INVALID_ATTRIBUTE_SYNTAX =
       ResultCode.INVALID_ATTRIBUTE_SYNTAX_INT_VALUE;



  /**
   * The int value for the NO_SUCH_OBJECT result code.
   */
  public static final int NO_SUCH_OBJECT = ResultCode.NO_SUCH_OBJECT_INT_VALUE;



  /**
   * The int value for the ALIAS_PROBLEM result code.
   */
  public static final int ALIAS_PROBLEM = ResultCode.ALIAS_PROBLEM_INT_VALUE;



  /**
   * The int value for the INVALID_DN_SYNTAX result code.
   */
  public static final int INVALID_DN_SYNTAX =
       ResultCode.INVALID_DN_SYNTAX_INT_VALUE;



  /**
   * The int value for the IS_LEAF result code.
   */
  public static final int IS_LEAF = 35;



  /**
   * The int value for the ALIAS_DEREFERENCING_PROBLEM result code.
   */
  public static final int ALIAS_DEREFERENCING_PROBLEM =
       ResultCode.ALIAS_DEREFERENCING_PROBLEM_INT_VALUE;



  /**
   * The int value for the INAPPROPRIATE_AUTHENTICATION result code.
   */
  public static final int INAPPROPRIATE_AUTHENTICATION =
       ResultCode.INAPPROPRIATE_AUTHENTICATION_INT_VALUE;



  /**
   * The int value for the INVALID_CREDENTIALS result code.
   */
  public static final int INVALID_CREDENTIALS =
       ResultCode.INVALID_CREDENTIALS_INT_VALUE;



  /**
   * The int value for the INSUFFICIENT_ACCESS_RIGHTS result code.
   */
  public static final int INSUFFICIENT_ACCESS_RIGHTS =
       ResultCode.INSUFFICIENT_ACCESS_RIGHTS_INT_VALUE;



  /**
   * The int value for the BUSY result code.
   */
  public static final int BUSY = ResultCode.BUSY_INT_VALUE;



  /**
   * The int value for the UNAVAILABLE result code.
   */
  public static final int UNAVAILABLE = ResultCode.UNAVAILABLE_INT_VALUE;



  /**
   * The int value for the UNWILLING_TO_PERFORM result code.
   */
  public static final int UNWILLING_TO_PERFORM =
       ResultCode.UNWILLING_TO_PERFORM_INT_VALUE;



  /**
   * The int value for the LOOP_DETECT result code.
   */
  public static final int LOOP_DETECTED = ResultCode.LOOP_DETECT_INT_VALUE;



  /**
   * The int value for the SORT_CONTROL_MISSING result code.
   */
  public static final int SORT_CONTROL_MISSING =
       ResultCode.SORT_CONTROL_MISSING_INT_VALUE;



  /**
   * The int value for the INDEX_RANGE_ERROR result code.
   */
  public static final int INDEX_RANGE_ERROR =
       ResultCode.OFFSET_RANGE_ERROR_INT_VALUE;



  /**
   * The int value for the NAMING_VIOLATION result code.
   */
  public static final int NAMING_VIOLATION =
       ResultCode.NAMING_VIOLATION_INT_VALUE;



  /**
   * The int value for the OBJECT_CLASS_VIOLATION result code.
   */
  public static final int OBJECT_CLASS_VIOLATION =
       ResultCode.OBJECT_CLASS_VIOLATION_INT_VALUE;



  /**
   * The int value for the NOT_ALLOWED_ON_NONLEAF result code.
   */
  public static final int NOT_ALLOWED_ON_NONLEAF =
       ResultCode.NOT_ALLOWED_ON_NONLEAF_INT_VALUE;



  /**
   * The int value for the NOT_ALLOWED_ON_RDN result code.
   */
  public static final int NOT_ALLOWED_ON_RDN =
       ResultCode.NOT_ALLOWED_ON_RDN_INT_VALUE;



  /**
   * The int value for the ENTRY_ALREADY_EXISTS result code.
   */
  public static final int ENTRY_ALREADY_EXISTS =
       ResultCode.ENTRY_ALREADY_EXISTS_INT_VALUE;



  /**
   * The int value for the OBJECT_CLASS_MODS_PROHIBITED result code.
   */
  public static final int OBJECT_CLASS_MODS_PROHIBITED =
       ResultCode.OBJECT_CLASS_MODS_PROHIBITED_INT_VALUE;



  /**
   * The int value for the AFFECTS_MULTIPLE_DSAS result code.
   */
  public static final int AFFECTS_MULTIPLE_DSAS =
       ResultCode.AFFECTS_MULTIPLE_DSAS_INT_VALUE;



  /**
   * The int value for the OTHER result code.
   */
  public static final int OTHER = ResultCode.OTHER_INT_VALUE;



  /**
   * The int value for the SERVER_DOWN result code.
   */
  public static final int SERVER_DOWN = ResultCode.SERVER_DOWN_INT_VALUE;



  /**
   * The int value for the LDAP_TIMEOUT result code.
   */
  public static final int LDAP_TIMEOUT = ResultCode.TIMEOUT_INT_VALUE;



  /**
   * The int value for the PARAM_ERROR result code.
   */
  public static final int PARAM_ERROR = ResultCode.PARAM_ERROR_INT_VALUE;



  /**
   * The int value for the CONNECT_ERROR result code.
   */
  public static final int CONNECT_ERROR = ResultCode.CONNECT_ERROR_INT_VALUE;



  /**
   * The int value for the LDAP_NOT_SUPPORTED result code.
   */
  public static final int LDAP_NOT_SUPPORTED =
       ResultCode.NOT_SUPPORTED_INT_VALUE;



  /**
   * The int value for the CONTROL_NOT_FOUND result code.
   */
  public static final int CONTROL_NOT_FOUND =
       ResultCode.CONTROL_NOT_FOUND_INT_VALUE;



  /**
   * The int value for the NO_RESULTS_RETURNED result code.
   */
  public static final int NO_RESULTS_RETURNED =
       ResultCode.NO_RESULTS_RETURNED_INT_VALUE;



  /**
   * The int value for the MORE_RESULTS_TO_RETURN result code.
   */
  public static final int MORE_RESULTS_TO_RETURN =
       ResultCode.MORE_RESULTS_TO_RETURN_INT_VALUE;



  /**
   * The int value for the CLIENT_LOOP result code.
   */
  public static final int CLIENT_LOOP =
       ResultCode.CLIENT_LOOP_INT_VALUE;



  /**
   * The int value for the REFERRAL_LIMIT_EXCEEDED result code.
   */
  public static final int REFERRAL_LIMIT_EXCEEDED =
       ResultCode.REFERRAL_LIMIT_EXCEEDED_INT_VALUE;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1942111440459840394L;



  // The result code for this LDAP exception.
  private final int resultCode;

  // The matched DN for this LDAP exception.
  @Nullable private final String matchedDN;

  // The error message for this LDAP exception.
  @Nullable private final String serverErrorMessage;



  /**
   * Creates a new LDAP exception with no information.
   */
  public LDAPException()
  {
    this(null, OTHER, null, null);
  }



  /**
   * Creates a new LDAP exception with the provided information.
   *
   * @param  message  The message for this exception, if available.
   */
  public LDAPException(@Nullable final String message)
  {
    this(message, OTHER, null, null);
  }



  /**
   * Creates a new LDAP exception with the provided information.
   *
   * @param  message     The message for this exception, if available.
   * @param  resultCode  The result code for this exception.
   */
  public LDAPException(@Nullable final String message, final int resultCode)
  {
    this(message, resultCode, null, null);
  }



  /**
   * Creates a new LDAP exception with the provided information.
   *
   * @param  message             The message for this exception, if available.
   * @param  resultCode          The result code for this exception.
   * @param  serverErrorMessage  The error message received from the server, if
   *                             available.
   */
  public LDAPException(@Nullable final String message, final int resultCode,
                       @Nullable final String serverErrorMessage)
  {
    this(message, resultCode, serverErrorMessage, null);
  }



  /**
   * Creates a new LDAP exception with the provided information.
   *
   * @param  message             The message for this exception, if available.
   * @param  resultCode          The result code for this exception.
   * @param  serverErrorMessage  The error message received from the server, if
   *                             available.
   * @param  matchedDN           The matched DN for this exception, if
   *                             available.
   */
  public LDAPException(@Nullable final String message, final int resultCode,
                       @Nullable final String serverErrorMessage,
                       @Nullable final String matchedDN)
  {
    super(getMessage(message, serverErrorMessage, resultCode));

    this.resultCode         = resultCode;
    this.serverErrorMessage = serverErrorMessage;
    this.matchedDN          = matchedDN;
  }



  /**
   * Creates a new LDAP exception from the provided
   * {@link com.unboundid.ldap.sdk.LDAPException} object.
   *
   * @param  ldapException  The {@code LDAPException} object to use to create
   *                        this LDAP exception.
   */
  public LDAPException(
              @NotNull final com.unboundid.ldap.sdk.LDAPException ldapException)
  {
    this(ldapException.getMessage(), ldapException.getResultCode().intValue(),
         ldapException.getMessage(), ldapException.getMatchedDN());
  }



  /**
   * Determines the appropriate message to use for this LDAP exception.
   *
   * @param  message             The message for this exception, if available.
   * @param  serverErrorMessage  The error message received from the server, if
   *                             available.
   * @param  resultCode          The result code for this exception.
   *
   * @return  The appropriate message to use for this LDAP exception.
   */
  @NotNull()
  private static String getMessage(@Nullable final String message,
                                   @Nullable final String serverErrorMessage,
                                   final int resultCode)
  {
    if ((message != null) && (! message.isEmpty()))
    {
      return message;
    }

    if ((serverErrorMessage != null) && (! serverErrorMessage.isEmpty()))
    {
      return serverErrorMessage;
    }

    return ResultCode.valueOf(resultCode).getName();
  }



  /**
   * Retrieves the result code for this LDAP exception.
   *
   * @return  The result code for this LDAP exception.
   */
  public int getLDAPResultCode()
  {
    return resultCode;
  }



  /**
   * Retrieves the error message received from the server, if available.
   *
   * @return  The error message received from the server, or {@code null} if
   *          none is available.
   */
  @Nullable()
  public String getLDAPErrorMessage()
  {
    return serverErrorMessage;
  }



  /**
   * Retrieves the matched DN for this LDAP exception, if available.
   *
   * @return  The matched DN for this LDAP exception, or {@code null} if none is
   *          available.
   */
  @Nullable()
  public String getMatchedDN()
  {
    return matchedDN;
  }



  /**
   * Retrieves an {@link com.unboundid.ldap.sdk.LDAPException} object that is
   * the equivalent of this LDAP exception.
   *
   * @return  The {@code LDAPException} object that is the equivalent of this
   *          LDAP exception.
   */
  @NotNull()
  public final com.unboundid.ldap.sdk.LDAPException toLDAPException()
  {
    return new com.unboundid.ldap.sdk.LDAPException(
         ResultCode.valueOf(resultCode), getMessage(), matchedDN, null);
  }



  /**
   * Retrieves a string representation of the result code for this LDAP
   * exception.
   *
   * @return  A string representation of the result code for this LDAP
   *          exception.
   */
  @NotNull()
  public String errorCodeToString()
  {
    return ResultCode.valueOf(resultCode).getName();
  }



  /**
   * Retrieves a string representation of the result code for this LDAP
   * exception.
   *
   * @param  l  The locale for the string representation.
   *
   * @return  A string representation of the result code for this LDAP
   *          exception.
   */
  @NotNull()
  public String errorCodeToString(@Nullable final Locale l)
  {
    return ResultCode.valueOf(resultCode).getName();
  }



  /**
   * Retrieves a string representation of the result code for this LDAP
   * exception.
   *
   * @param  code  The result code for which to retrieve the corresponding
   *               message.
   *
   * @return  A string representation of the result code for this LDAP
   *          exception.
   */
  @NotNull()
  public static String errorCodeToString(final int code)
  {
    return ResultCode.valueOf(code).getName();
  }



  /**
   * Retrieves a string representation of the result code for this LDAP
   * exception.
   *
   * @param  code    The result code for which to retrieve the corresponding
   *                 message.
   * @param  locale  The locale for the string representation.
   *
   * @return  A string representation of the result code for this LDAP
   *          exception.
   */
  @NotNull()
  public static String errorCodeToString(final int code,
                                         @Nullable final Locale locale)
  {
    return ResultCode.valueOf(code).getName();
  }



  /**
   * Retrieves a string representation of this LDAP exception.
   *
   * @return  A string representation of this LDAP exception.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return toLDAPException().toString();
  }
}
