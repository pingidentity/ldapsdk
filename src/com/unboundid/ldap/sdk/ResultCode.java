/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.io.Serializable;
import java.util.concurrent.ConcurrentHashMap;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class defines a number of constants associated with LDAP result codes.
 * The {@code ResultCode} constant values defined in this class are immutable,
 * and at most one result code object will ever be created for a given int
 * value, so it is acceptable to compare result codes with either the
 * {@link ResultCode#equals} method or the "{@code ==}" operator.
 *<BR><BR>
 * The result codes that are currently defined include:
 * <BR>
 * <TABLE BORDER="1" CELLPADDING="3" CELLSPACING="0" WIDTH="50%"
 *        SUMMARY="Result Code Names and Numeric Values">
 *   <TR>
 *     <TH ALIGN="LEFT">Name</TH>
 *     <TH ALIGN="RIGHT">Integer Value</TH>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">SUCCESS</TD>
 *     <TD ALIGN="RIGHT">0</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">OPERATIONS_ERROR</TD>
 *     <TD ALIGN="RIGHT">1</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">PROTOCOL_ERROR</TD>
 *     <TD ALIGN="RIGHT">2</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">TIME_LIMIT_EXCEEDED</TD>
 *     <TD ALIGN="RIGHT">3</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">SIZE_LIMIT_EXCEEDED</TD>
 *     <TD ALIGN="RIGHT">4</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">COMPARE_FALSE</TD>
 *     <TD ALIGN="RIGHT">5</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">COMPARE_TRUE</TD>
 *     <TD ALIGN="RIGHT">6</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">AUTH_METHOD_NOT_SUPPORTED</TD>
 *     <TD ALIGN="RIGHT">7</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">STRONG_AUTH_REQUIRED</TD>
 *     <TD ALIGN="RIGHT">8</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">REFERRAL</TD>
 *     <TD ALIGN="RIGHT">10</TD>
 *   </TR>
 *   <TR>
 *    <TD ALIGN="LEFT">ADMIN_LIMIT_EXCEEDED</TD>
 *     <TD ALIGN="RIGHT">11</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">UNAVAILABLE_CRITICAL_EXTENSION</TD>
 *     <TD ALIGN="RIGHT">12</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">CONFIDENTIALITY_REQUIRED</TD>
 *     <TD ALIGN="RIGHT">13</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">SASL_BIND_IN_PROGRESS</TD>
 *     <TD ALIGN="RIGHT">14</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">NO_SUCH_ATTRIBUTE</TD>
 *     <TD ALIGN="RIGHT">16</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">UNDEFINED_ATTRIBUTE_TYPE</TD>
 *     <TD ALIGN="RIGHT">17</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">INAPPROPRIATE_MATCHING</TD>
 *     <TD ALIGN="RIGHT">18</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">CONSTRAINT_VIOLATION</TD>
 *     <TD ALIGN="RIGHT">19</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">ATTRIBUTE_OR_VALUE_EXISTS</TD>
 *     <TD ALIGN="RIGHT">20</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">INVALID_ATTRIBUTE_SYNTAX</TD>
 *     <TD ALIGN="RIGHT">21</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">NO_SUCH_OBJECT</TD>
 *     <TD ALIGN="RIGHT">32</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">ALIAS_PROBLEM</TD>
 *     <TD ALIGN="RIGHT">33</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">INVALID_DN_SYNTAX</TD>
 *     <TD ALIGN="RIGHT">34</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">ALIAS_DEREFERENCING_PROBLEM</TD>
 *     <TD ALIGN="RIGHT">36</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">INAPPROPRIATE_AUTHENTICATION</TD>
 *     <TD ALIGN="RIGHT">48</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">INVALID_CREDENTIALS</TD>
 *     <TD ALIGN="RIGHT">49</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">INSUFFICIENT_ACCESS_RIGHTS</TD>
 *     <TD ALIGN="RIGHT">50</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">BUSY</TD>
 *     <TD ALIGN="RIGHT">51</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">UNAVAILABLE</TD>
 *     <TD ALIGN="RIGHT">52</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">UNWILLING_TO_PERFORM</TD>
 *     <TD ALIGN="RIGHT">53</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">LOOP_DETECT</TD>
 *     <TD ALIGN="RIGHT">54</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">SORT_CONTROL_MISSING</TD>
 *     <TD ALIGN="RIGHT">60</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">OFFSET_RANGE_ERROR</TD>
 *     <TD ALIGN="RIGHT">61</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">NAMING_VIOLATION</TD>
 *     <TD ALIGN="RIGHT">64</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">OBJECT_CLASS_VIOLATION</TD>
 *     <TD ALIGN="RIGHT">65</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">NOT_ALLOWED_ON_NONLEAF</TD>
 *     <TD ALIGN="RIGHT">66</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">NOT_ALLOWED_ON_NONLEAF</TD>
 *     <TD ALIGN="RIGHT">66</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">NOT_ALLOWED_ON_RDN</TD>
 *     <TD ALIGN="RIGHT">67</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">ENTRY_ALREADY_EXISTS</TD>
 *     <TD ALIGN="RIGHT">68</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">OBJECT_CLASS_MODS_PROHIBITED</TD>
 *     <TD ALIGN="RIGHT">69</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">AFFECTS_MULTIPLE_DSAS</TD>
 *     <TD ALIGN="RIGHT">71</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">VIRTUAL_LIST_VIEW_ERROR</TD>
 *     <TD ALIGN="RIGHT">76</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">OTHER</TD>
 *     <TD ALIGN="RIGHT">80</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">SERVER_DOWN</TD>
 *     <TD ALIGN="RIGHT">81</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">LOCAL_ERROR</TD>
 *     <TD ALIGN="RIGHT">82</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">ENCODING_ERROR</TD>
 *     <TD ALIGN="RIGHT">83</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">DECODING_ERROR</TD>
 *     <TD ALIGN="RIGHT">84</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">TIMEOUT</TD>
 *     <TD ALIGN="RIGHT">85</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">AUTH_UNKNOWN</TD>
 *     <TD ALIGN="RIGHT">86</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">FILTER_ERROR</TD>
 *      <TD ALIGN="RIGHT">87</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">USER_CANCELED</TD>
 *     <TD ALIGN="RIGHT">88</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">PARAM_ERROR</TD>
 *     <TD ALIGN="RIGHT">89</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">NO_MEMORY</TD>
 *     <TD ALIGN="RIGHT">90</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">CONNECT_ERROR</TD>
 *     <TD ALIGN="RIGHT">91</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">NOT_SUPPORTED</TD>
 *     <TD ALIGN="RIGHT">92</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">CONTROL_NOT_FOUND</TD>
 *     <TD ALIGN="RIGHT">93</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">NO_RESULTS_RETURNED</TD>
 *     <TD ALIGN="RIGHT">94</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">MORE_RESULTS_TO_RETURN</TD>
 *     <TD ALIGN="RIGHT">95</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">CLIENT_LOOP</TD>
 *     <TD ALIGN="RIGHT">96</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">REFERRAL_LIMIT_EXCEEDED</TD>
 *     <TD ALIGN="RIGHT">97</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">CANCELED</TD>
 *     <TD ALIGN="RIGHT">118</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">NO_SUCH_OPERATION</TD>
 *     <TD ALIGN="RIGHT">119</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">TOO_LATE</TD>
 *     <TD ALIGN="RIGHT">120</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">CANNOT_CANCEL</TD>
 *     <TD ALIGN="RIGHT">121</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">ASSERTION_FAILED</TD>
 *     <TD ALIGN="RIGHT">122</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">AUTHORIZATION_DENIED</TD>
 *     <TD ALIGN="RIGHT">123</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">E_SYNC_REFRESH_REQUIRED</TD>
 *     <TD ALIGN="RIGHT">4096</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">NO_OPERATION</TD>
 *     <TD ALIGN="RIGHT">16654</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">INTERACTIVE_TRANSACTION_ABORTED</TD>
 *     <TD ALIGN="RIGHT">30221001</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">DATABASE_LOCK_CONFLICT</TD>
 *     <TD ALIGN="RIGHT">30221002</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">MIRRORED_SUBTREE_DIGEST_MISMATCH</TD>
 *     <TD ALIGN="RIGHT">30221003</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">TOKEN_DELIVERY_MECHANISM_UNAVAILABLE</TD>
 *     <TD ALIGN="RIGHT">30221004</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">TOKEN_DELIVERY_ATTEMPT_FAILED</TD>
 *     <TD ALIGN="RIGHT">30221005</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">TOKEN_DELIVERY_INVALID_RECIPIENT_ID</TD>
 *     <TD ALIGN="RIGHT">30221006</TD>
 *   </TR>
 *   <TR>
 *     <TD ALIGN="LEFT">TOKEN_DELIVERY_INVALID_ACCOUNT_STATE</TD>
 *     <TD ALIGN="RIGHT">30221007</TD>
 *   </TR>
 * </TABLE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ResultCode
       implements Serializable
{
  /**
   * The integer value (0) for the "SUCCESS" result code.
   */
  public static final int SUCCESS_INT_VALUE = 0;



  /**
   * The result code (0) that will be used to indicate a successful operation.
   */
  @NotNull public static final ResultCode SUCCESS =
       new ResultCode(INFO_RC_SUCCESS.get(), SUCCESS_INT_VALUE);



  /**
   * The integer value (1) for the "OPERATIONS_ERROR" result code.
   */
  public static final int OPERATIONS_ERROR_INT_VALUE = 1;



  /**
   * The result code (1) that will be used to indicate that an operation was
   * requested out of sequence.
   */
  @NotNull public static final ResultCode OPERATIONS_ERROR =
       new ResultCode(INFO_RC_OPERATIONS_ERROR.get(),
                      OPERATIONS_ERROR_INT_VALUE);



  /**
   * The integer value (2) for the "PROTOCOL_ERROR" result code.
   */
  public static final int PROTOCOL_ERROR_INT_VALUE = 2;



  /**
   * The result code (2) that will be used to indicate that the client sent a
   * malformed request.
   */
  @NotNull public static final ResultCode PROTOCOL_ERROR =
       new ResultCode(INFO_RC_PROTOCOL_ERROR.get(), PROTOCOL_ERROR_INT_VALUE);



  /**
   * The integer value (3) for the "TIME_LIMIT_EXCEEDED" result code.
   */
  public static final int TIME_LIMIT_EXCEEDED_INT_VALUE = 3;



  /**
   * The result code (3) that will be used to indicate that the server was
   * unable to complete processing on the request in the allotted time limit.
   */
  @NotNull public static final ResultCode TIME_LIMIT_EXCEEDED =
       new ResultCode(INFO_RC_TIME_LIMIT_EXCEEDED.get(),
                      TIME_LIMIT_EXCEEDED_INT_VALUE);



  /**
   * The integer value (4) for the "SIZE_LIMIT_EXCEEDED" result code.
   */
  public static final int SIZE_LIMIT_EXCEEDED_INT_VALUE = 4;



  /**
   * The result code (4) that will be used to indicate that the server found
   * more matching entries than the configured request size limit.
   */
  @NotNull public static final ResultCode SIZE_LIMIT_EXCEEDED =
       new ResultCode(INFO_RC_SIZE_LIMIT_EXCEEDED.get(),
                      SIZE_LIMIT_EXCEEDED_INT_VALUE);



  /**
   * The integer value (5) for the "COMPARE_FALSE" result code.
   */
  public static final int COMPARE_FALSE_INT_VALUE = 5;



  /**
   * The result code (5) that will be used if a requested compare assertion does
   * not match the target entry.
   */
  @NotNull public static final ResultCode COMPARE_FALSE =
       new ResultCode(INFO_RC_COMPARE_FALSE.get(), COMPARE_FALSE_INT_VALUE);



  /**
   * The integer value (6) for the "COMPARE_TRUE" result code.
   */
  public static final int COMPARE_TRUE_INT_VALUE = 6;



  /**
   * The result code (6) that will be used if a requested compare assertion
   * matched the target entry.
   */
  @NotNull public static final ResultCode COMPARE_TRUE =
       new ResultCode(INFO_RC_COMPARE_TRUE.get(), COMPARE_TRUE_INT_VALUE);



  /**
   * The integer value (7) for the "AUTH_METHOD_NOT_SUPPORTED" result code.
   */
  public static final int AUTH_METHOD_NOT_SUPPORTED_INT_VALUE = 7;



  /**
   * The result code (7) that will be used if the client requested a form of
   * authentication that is not supported by the server.
   */
  @NotNull public static final ResultCode AUTH_METHOD_NOT_SUPPORTED =
       new ResultCode(INFO_RC_AUTH_METHOD_NOT_SUPPORTED.get(),
                      AUTH_METHOD_NOT_SUPPORTED_INT_VALUE);



  /**
   * The integer value (8) for the "STRONG_AUTH_REQUIRED" result code.
   */
  public static final int STRONG_AUTH_REQUIRED_INT_VALUE = 8;



  /**
   * The result code (8) that will be used if the client requested an operation
   * that requires a strong authentication mechanism.
   */
  @NotNull public static final ResultCode STRONG_AUTH_REQUIRED =
       new ResultCode(INFO_RC_STRONG_AUTH_REQUIRED.get(),
                      STRONG_AUTH_REQUIRED_INT_VALUE);



  /**
   * The integer value (10) for the "REFERRAL" result code.
   */
  public static final int REFERRAL_INT_VALUE = 10;



  /**
   * The result code (10) that will be used if the server sends a referral to
   * the client to refer to data in another location.
   */
  @NotNull public static final ResultCode REFERRAL =
       new ResultCode(INFO_RC_REFERRAL.get(), REFERRAL_INT_VALUE);



  /**
   * The integer value (11) for the "ADMIN_LIMIT_EXCEEDED" result code.
   */
  public static final int ADMIN_LIMIT_EXCEEDED_INT_VALUE = 11;



  /**
   * The result code (11) that will be used if a server administrative limit has
   * been exceeded.
   */
  @NotNull public static final ResultCode ADMIN_LIMIT_EXCEEDED =
       new ResultCode(INFO_RC_ADMIN_LIMIT_EXCEEDED.get(),
                      ADMIN_LIMIT_EXCEEDED_INT_VALUE);



  /**
   * The integer value (12) for the "UNAVAILABLE_CRITICAL_EXTENSION" result
   * code.
   */
  public static final int UNAVAILABLE_CRITICAL_EXTENSION_INT_VALUE = 12;



  /**
   * The result code (12) that will be used if the client requests a critical
   * control that is not supported by the server.
   */
  @NotNull public static final ResultCode UNAVAILABLE_CRITICAL_EXTENSION =
       new ResultCode(INFO_RC_UNAVAILABLE_CRITICAL_EXTENSION.get(),
                      UNAVAILABLE_CRITICAL_EXTENSION_INT_VALUE);



  /**
   * The integer value (13) for the "CONFIDENTIALITY_REQUIRED" result code.
   */
  public static final int CONFIDENTIALITY_REQUIRED_INT_VALUE = 13;



  /**
   * The result code (13) that will be used if the server requires a secure
   * communication mechanism for the requested operation.
   */
  @NotNull public static final ResultCode CONFIDENTIALITY_REQUIRED =
       new ResultCode(INFO_RC_CONFIDENTIALITY_REQUIRED.get(),
                      CONFIDENTIALITY_REQUIRED_INT_VALUE);



  /**
   * The integer value (14) for the "SASL_BIND_IN_PROGRESS" result code.
   */
  public static final int SASL_BIND_IN_PROGRESS_INT_VALUE = 14;



  /**
   * The result code (14) that will be returned from the server after SASL bind
   * stages in which more processing is required.
   */
  @NotNull public static final ResultCode SASL_BIND_IN_PROGRESS =
       new ResultCode(INFO_RC_SASL_BIND_IN_PROGRESS.get(),
                      SASL_BIND_IN_PROGRESS_INT_VALUE);



  /**
   * The integer value (16) for the "NO_SUCH_ATTRIBUTE" result code.
   */
  public static final int NO_SUCH_ATTRIBUTE_INT_VALUE = 16;



  /**
   * The result code (16) that will be used if the client referenced an
   * attribute that does not exist in the target entry.
   */
  @NotNull public static final ResultCode NO_SUCH_ATTRIBUTE =
       new ResultCode(INFO_RC_NO_SUCH_ATTRIBUTE.get(),
                      NO_SUCH_ATTRIBUTE_INT_VALUE);



  /**
   * The integer value (17) for the "UNDEFINED_ATTRIBUTE_TYPE" result code.
   */
  public static final int UNDEFINED_ATTRIBUTE_TYPE_INT_VALUE = 17;



  /**
   * The result code (17) that will be used if the client referenced an
   * attribute that is not defined in the server schema.
   */
  @NotNull public static final ResultCode UNDEFINED_ATTRIBUTE_TYPE =
       new ResultCode(INFO_RC_UNDEFINED_ATTRIBUTE_TYPE.get(),
                      UNDEFINED_ATTRIBUTE_TYPE_INT_VALUE);



  /**
   * The integer value (18) for the "INAPPROPRIATE_MATCHING" result code.
   */
  public static final int INAPPROPRIATE_MATCHING_INT_VALUE = 18;



  /**
   * The result code (18) that will be used if the client attempted to use an
   * attribute in a search filter in a manner not supported by the matching
   * rules associated with that attribute.
   */
  @NotNull public static final ResultCode INAPPROPRIATE_MATCHING =
       new ResultCode(INFO_RC_INAPPROPRIATE_MATCHING.get(),
                      INAPPROPRIATE_MATCHING_INT_VALUE);



  /**
   * The integer value (19) for the "CONSTRAINT_VIOLATION" result code.
   */
  public static final int CONSTRAINT_VIOLATION_INT_VALUE = 19;



  /**
   * The result code (19) that will be used if the requested operation would
   * violate some constraint defined in the server.
   */
  @NotNull public static final ResultCode CONSTRAINT_VIOLATION =
       new ResultCode(INFO_RC_CONSTRAINT_VIOLATION.get(),
                      CONSTRAINT_VIOLATION_INT_VALUE);



  /**
   * The integer value (20) for the "ATTRIBUTE_OR_VALUE_EXISTS" result code.
   */
  public static final int ATTRIBUTE_OR_VALUE_EXISTS_INT_VALUE = 20;



  /**
   * The result code (20) that will be used if the client attempts to modify an
   * entry in a way that would create a duplicate value, or create multiple
   * values for a single-valued attribute.
   */
  @NotNull public static final ResultCode ATTRIBUTE_OR_VALUE_EXISTS =
       new ResultCode(INFO_RC_ATTRIBUTE_OR_VALUE_EXISTS.get(),
                      ATTRIBUTE_OR_VALUE_EXISTS_INT_VALUE);



  /**
   * The integer value (21) for the "INVALID_ATTRIBUTE_SYNTAX" result code.
   */
  public static final int INVALID_ATTRIBUTE_SYNTAX_INT_VALUE = 21;



  /**
   * The result code (21) that will be used if the client attempts to perform an
   * operation that would create an attribute value that violates the syntax
   * for that attribute.
   */
  @NotNull public static final ResultCode INVALID_ATTRIBUTE_SYNTAX =
       new ResultCode(INFO_RC_INVALID_ATTRIBUTE_SYNTAX.get(),
                      INVALID_ATTRIBUTE_SYNTAX_INT_VALUE);



  /**
   * The integer value (32) for the "NO_SUCH_OBJECT" result code.
   */
  public static final int NO_SUCH_OBJECT_INT_VALUE = 32;



  /**
   * The result code (32) that will be used if the client targeted an entry that
   * does not exist.
   */
  @NotNull public static final ResultCode NO_SUCH_OBJECT =
       new ResultCode(INFO_RC_NO_SUCH_OBJECT.get(), NO_SUCH_OBJECT_INT_VALUE);



  /**
   * The integer value (33) for the "ALIAS_PROBLEM" result code.
   */
  public static final int ALIAS_PROBLEM_INT_VALUE = 33;



  /**
   * The result code (33) that will be used if the client targeted an entry that
   * as an alias.
   */
  @NotNull public static final ResultCode ALIAS_PROBLEM =
       new ResultCode(INFO_RC_ALIAS_PROBLEM.get(), ALIAS_PROBLEM_INT_VALUE);



  /**
   * The integer value (34) for the "INVALID_DN_SYNTAX" result code.
   */
  public static final int INVALID_DN_SYNTAX_INT_VALUE = 34;



  /**
   * The result code (34) that will be used if the client provided an invalid
   * DN.
   */
  @NotNull public static final ResultCode INVALID_DN_SYNTAX =
       new ResultCode(INFO_RC_INVALID_DN_SYNTAX.get(),
                      INVALID_DN_SYNTAX_INT_VALUE);



  /**
   * The integer value (36) for the "ALIAS_DEREFERENCING_PROBLEM" result code.
   */
  public static final int ALIAS_DEREFERENCING_PROBLEM_INT_VALUE = 36;



  /**
   * The result code (36) that will be used if a problem is encountered while
   * the server is attempting to dereference an alias.
   */
  @NotNull public static final ResultCode ALIAS_DEREFERENCING_PROBLEM =
       new ResultCode(INFO_RC_ALIAS_DEREFERENCING_PROBLEM.get(),
                      ALIAS_DEREFERENCING_PROBLEM_INT_VALUE);



  /**
   * The integer value (48) for the "INAPPROPRIATE_AUTHENTICATION" result code.
   */
  public static final int INAPPROPRIATE_AUTHENTICATION_INT_VALUE = 48;



  /**
   * The result code (48) that will be used if the client attempts to perform a
   * type of authentication that is not supported for the target user.
   */
  @NotNull public static final ResultCode INAPPROPRIATE_AUTHENTICATION =
       new ResultCode(INFO_RC_INAPPROPRIATE_AUTHENTICATION.get(),
                      INAPPROPRIATE_AUTHENTICATION_INT_VALUE);



  /**
   * The integer value (49) for the "INVALID_CREDENTIALS" result code.
   */
  public static final int INVALID_CREDENTIALS_INT_VALUE = 49;



  /**
   * The result code (49) that will be used if the client provided invalid
   * credentials while trying to authenticate.
   */
  @NotNull public static final ResultCode INVALID_CREDENTIALS =
       new ResultCode(INFO_RC_INVALID_CREDENTIALS.get(),
                      INVALID_CREDENTIALS_INT_VALUE);



  /**
   * The integer value (50) for the "INSUFFICIENT_ACCESS_RIGHTS" result code.
   */
  public static final int INSUFFICIENT_ACCESS_RIGHTS_INT_VALUE = 50;



  /**
   * The result code (50) that will be used if the client does not have
   * permission to perform the requested operation.
   */
  @NotNull public static final ResultCode INSUFFICIENT_ACCESS_RIGHTS =
       new ResultCode(INFO_RC_INSUFFICIENT_ACCESS_RIGHTS.get(),
                      INSUFFICIENT_ACCESS_RIGHTS_INT_VALUE);



  /**
   * The integer value (51) for the "BUSY" result code.
   */
  public static final int BUSY_INT_VALUE = 51;



  /**
   * The result code (51) that will be used if the server is too busy to process
   * the requested operation.
   */
  @NotNull public static final ResultCode BUSY =
       new ResultCode(INFO_RC_BUSY.get(), BUSY_INT_VALUE);



  /**
   * The integer value (52) for the "UNAVAILABLE" result code.
   */
  public static final int UNAVAILABLE_INT_VALUE = 52;



  /**
   * The result code (52) that will be used if the server is unavailable.
   */
  @NotNull public static final ResultCode UNAVAILABLE =
       new ResultCode(INFO_RC_UNAVAILABLE.get(), UNAVAILABLE_INT_VALUE);



  /**
   * The integer value (53) for the "UNWILLING_TO_PERFORM" result code.
   */
  public static final int UNWILLING_TO_PERFORM_INT_VALUE = 53;



  /**
   * The result code (53) that will be used if the server is not willing to
   * perform the requested operation.
   */
  @NotNull public static final ResultCode UNWILLING_TO_PERFORM =
       new ResultCode(INFO_RC_UNWILLING_TO_PERFORM.get(),
                      UNWILLING_TO_PERFORM_INT_VALUE);



  /**
   * The integer value (54) for the "LOOP_DETECT" result code.
   */
  public static final int LOOP_DETECT_INT_VALUE = 54;



  /**
   * The result code (54) that will be used if the server detects a chaining or
   * alias loop.
   */
  @NotNull public static final ResultCode LOOP_DETECT =
       new ResultCode(INFO_RC_LOOP_DETECT.get(), LOOP_DETECT_INT_VALUE);



  /**
   * The integer value (60) for the "SORT_CONTROL_MISSING" result code.
   */
  public static final int SORT_CONTROL_MISSING_INT_VALUE = 60;



  /**
   * The result code (60) that will be used if the client sends a virtual list
   * view control without a server-side sort control.
   */
  @NotNull public static final ResultCode SORT_CONTROL_MISSING =
       new ResultCode(INFO_RC_SORT_CONTROL_MISSING.get(),
                      SORT_CONTROL_MISSING_INT_VALUE);



  /**
   * The integer value (61) for the "OFFSET_RANGE_ERROR" result code.
   */
  public static final int OFFSET_RANGE_ERROR_INT_VALUE = 61;



  /**
   * The result code (61) that will be used if the client provides a virtual
   * list view control with a target offset that is out of range for the
   * available data set.
   */
  @NotNull public static final ResultCode OFFSET_RANGE_ERROR =
       new ResultCode(INFO_RC_OFFSET_RANGE_ERROR.get(),
                      OFFSET_RANGE_ERROR_INT_VALUE);



  /**
   * The integer value (64) for the "NAMING_VIOLATION" result code.
   */
  public static final int NAMING_VIOLATION_INT_VALUE = 64;



  /**
   * The result code (64) that will be used if the client request violates a
   * naming constraint (e.g., a name form or DIT structure rule) defined in the
   * server.
   */
  @NotNull public static final ResultCode NAMING_VIOLATION =
       new ResultCode(INFO_RC_NAMING_VIOLATION.get(),
                      NAMING_VIOLATION_INT_VALUE);



  /**
   * The integer value (65) for the "OBJECT_CLASS_VIOLATION" result code.
   */
  public static final int OBJECT_CLASS_VIOLATION_INT_VALUE = 65;



  /**
   * The result code (65) that will be used if the client request violates an
   * object class constraint (e.g., an undefined object class, a
   * disallowed attribute, or a missing required attribute) defined in the
   * server.
   */
  @NotNull public static final ResultCode OBJECT_CLASS_VIOLATION =
       new ResultCode(INFO_RC_OBJECT_CLASS_VIOLATION.get(),
                      OBJECT_CLASS_VIOLATION_INT_VALUE);



  /**
   * The integer value (66) for the "NOT_ALLOWED_ON_NONLEAF" result code.
   */
  public static final int NOT_ALLOWED_ON_NONLEAF_INT_VALUE = 66;



  /**
   * The result code (66) that will be used if the requested operation is not
   * allowed to be performed on non-leaf entries.
   */
  @NotNull public static final ResultCode NOT_ALLOWED_ON_NONLEAF =
       new ResultCode(INFO_RC_NOT_ALLOWED_ON_NONLEAF.get(),
                      NOT_ALLOWED_ON_NONLEAF_INT_VALUE);



  /**
   * The integer value (67) for the "NOT_ALLOWED_ON_RDN" result code.
   */
  public static final int NOT_ALLOWED_ON_RDN_INT_VALUE = 67;



  /**
   * The result code (67) that will be used if the requested operation would
   * alter the RDN of the entry but the operation was not a modify DN request.
   */
  @NotNull public static final ResultCode NOT_ALLOWED_ON_RDN =
       new ResultCode(INFO_RC_NOT_ALLOWED_ON_RDN.get(),
                      NOT_ALLOWED_ON_RDN_INT_VALUE);



  /**
   * The integer value (68) for the "ENTRY_ALREADY_EXISTS" result code.
   */
  public static final int ENTRY_ALREADY_EXISTS_INT_VALUE = 68;



  /**
   * The result code (68) that will be used if the requested operation would
   * create a conflict with an entry that already exists in the server.
   */
  @NotNull public static final ResultCode ENTRY_ALREADY_EXISTS =
       new ResultCode(INFO_RC_ENTRY_ALREADY_EXISTS.get(),
                      ENTRY_ALREADY_EXISTS_INT_VALUE);



  /**
   * The integer value (69) for the "OBJECT_CLASS_MODS_PROHIBITED" result code.
   */
  public static final int OBJECT_CLASS_MODS_PROHIBITED_INT_VALUE = 69;



  /**
   * The result code (69) that will be used if the requested operation would
   * alter the set of object classes defined in the entry in a disallowed
   * manner.
   */
  @NotNull public static final ResultCode OBJECT_CLASS_MODS_PROHIBITED =
       new ResultCode(INFO_RC_OBJECT_CLASS_MODS_PROHIBITED.get(),
                      OBJECT_CLASS_MODS_PROHIBITED_INT_VALUE);



  /**
   * The integer value (71) for the "AFFECTS_MULTIPLE_DSAS" result code.
   */
  public static final int AFFECTS_MULTIPLE_DSAS_INT_VALUE = 71;



  /**
   * The result code (71) that will be used if the requested operation would
   * impact entries in multiple data sources.
   */
  @NotNull public static final ResultCode AFFECTS_MULTIPLE_DSAS =
       new ResultCode(INFO_RC_AFFECTS_MULTIPLE_DSAS.get(),
                      AFFECTS_MULTIPLE_DSAS_INT_VALUE);



  /**
   * The integer value (76) for the "VIRTUAL_LIST_VIEW_ERROR" result code.
   */
  public static final int VIRTUAL_LIST_VIEW_ERROR_INT_VALUE = 76;



  /**
   * The result code (76) that will be used if an error occurred while
   * performing processing associated with the virtual list view control.
   */
  @NotNull public static final ResultCode VIRTUAL_LIST_VIEW_ERROR =
       new ResultCode(INFO_RC_VIRTUAL_LIST_VIEW_ERROR.get(),
                      VIRTUAL_LIST_VIEW_ERROR_INT_VALUE);



  /**
   * The integer value (80) for the "OTHER" result code.
   */
  public static final int OTHER_INT_VALUE = 80;



  /**
   * The result code (80) that will be used if none of the other result codes
   * are appropriate.
   */
  @NotNull public static final ResultCode OTHER =
       new ResultCode(INFO_RC_OTHER.get(), OTHER_INT_VALUE);



  /**
   * The integer value (81) for the "SERVER_DOWN" result code.
   */
  public static final int SERVER_DOWN_INT_VALUE = 81;



  /**
   * The client-side result code (81) that will be used if an established
   * connection to the server is lost.
   */
  @NotNull public static final ResultCode SERVER_DOWN =
       new ResultCode(INFO_RC_SERVER_DOWN.get(), SERVER_DOWN_INT_VALUE);



  /**
   * The integer value (82) for the "LOCAL_ERROR" result code.
   */
  public static final int LOCAL_ERROR_INT_VALUE = 82;



  /**
   * The client-side result code (82) that will be used if a generic client-side
   * error occurs during processing.
   */
  @NotNull public static final ResultCode LOCAL_ERROR =
       new ResultCode(INFO_RC_LOCAL_ERROR.get(), LOCAL_ERROR_INT_VALUE);



  /**
   * The integer value (83) for the "ENCODING_ERROR" result code.
   */
  public static final int ENCODING_ERROR_INT_VALUE = 83;



  /**
   * The client-side result code (83) that will be used if an error occurs while
   * encoding a request.
   */
  @NotNull public static final ResultCode ENCODING_ERROR =
       new ResultCode(INFO_RC_ENCODING_ERROR.get(), ENCODING_ERROR_INT_VALUE);



  /**
   * The integer value (84) for the "DECODING_ERROR" result code.
   */
  public static final int DECODING_ERROR_INT_VALUE = 84;



  /**
   * The client-side result code (84) that will be used if an error occurs while
   * decoding a response.
   */
  @NotNull public static final ResultCode DECODING_ERROR =
       new ResultCode(INFO_RC_DECODING_ERROR.get(), DECODING_ERROR_INT_VALUE);



  /**
   * The integer value (85) for the "TIMEOUT" result code.
   */
  public static final int TIMEOUT_INT_VALUE = 85;



  /**
   * The client-side result code (85) that will be used if a client timeout
   * occurs while waiting for a response from the server.
   */
  @NotNull public static final ResultCode TIMEOUT =
       new ResultCode(INFO_RC_TIMEOUT.get(), TIMEOUT_INT_VALUE);



  /**
   * The integer value (86) for the "AUTH_UNKNOWN" result code.
   */
  public static final int AUTH_UNKNOWN_INT_VALUE = 86;



  /**
   * The client-side result code (86) that will be used if the client attempts
   * to use an unknown authentication type.
   */
  @NotNull public static final ResultCode AUTH_UNKNOWN =
       new ResultCode(INFO_RC_AUTH_UNKNOWN.get(), AUTH_UNKNOWN_INT_VALUE);



  /**
   * The integer value (87) for the "FILTER_ERROR" result code.
   */
  public static final int FILTER_ERROR_INT_VALUE = 87;



  /**
   * The client-side result code (87) that will be used if an error occurs while
   * attempting to encode a search filter.
   */
  @NotNull public static final ResultCode FILTER_ERROR =
       new ResultCode(INFO_RC_FILTER_ERROR.get(), FILTER_ERROR_INT_VALUE);



  /**
   * The integer value (88) for the "USER_CANCELED" result code.
   */
  public static final int USER_CANCELED_INT_VALUE = 88;



  /**
   * The client-side result code (88) that will be used if the end user canceled
   * the operation in progress.
   */
  @NotNull public static final ResultCode USER_CANCELED =
       new ResultCode(INFO_RC_USER_CANCELED.get(), USER_CANCELED_INT_VALUE);



  /**
   * The integer value (89) for the "PARAM_ERROR" result code.
   */
  public static final int PARAM_ERROR_INT_VALUE = 89;



  /**
   * The client-side result code (89) that will be used if there is a problem
   * with the parameters provided for a request.
   */
  @NotNull public static final ResultCode PARAM_ERROR =
       new ResultCode(INFO_RC_PARAM_ERROR.get(), PARAM_ERROR_INT_VALUE);



  /**
   * The integer value (90) for the "NO_MEMORY" result code.
   */
  public static final int NO_MEMORY_INT_VALUE = 90;



  /**
   * The client-side result code (90) that will be used if the client does not
   * have sufficient memory to perform the requested operation.
   */
  @NotNull public static final ResultCode NO_MEMORY =
       new ResultCode(INFO_RC_NO_MEMORY.get(), NO_MEMORY_INT_VALUE);



  /**
   * The integer value (91) for the "CONNECT_ERROR" result code.
   */
  public static final int CONNECT_ERROR_INT_VALUE = 91;



  /**
   * The client-side result code (91) that will be used if an error occurs while
   * attempting to connect to a target server.
   */
  @NotNull public static final ResultCode CONNECT_ERROR =
       new ResultCode(INFO_RC_CONNECT_ERROR.get(), CONNECT_ERROR_INT_VALUE);



  /**
   * The integer value (92) for the "NOT_SUPPORTED" result code.
   */
  public static final int NOT_SUPPORTED_INT_VALUE = 92;



  /**
   * The client-side result code (92) that will be used if the requested
   * operation is not supported.
   */
  @NotNull public static final ResultCode NOT_SUPPORTED =
       new ResultCode(INFO_RC_NOT_SUPPORTED.get(), NOT_SUPPORTED_INT_VALUE);



  /**
   * The integer value (93) for the "CONTROL_NOT_FOUND" result code.
   */
  public static final int CONTROL_NOT_FOUND_INT_VALUE = 93;



  /**
   * The client-side result code (93) that will be used if the response from the
   * server did not include an expected control.
   */
  @NotNull public static final ResultCode CONTROL_NOT_FOUND =
       new ResultCode(INFO_RC_CONTROL_NOT_FOUND.get(),
                      CONTROL_NOT_FOUND_INT_VALUE);



  /**
   * The integer value (94) for the "NO_RESULTS_RETURNED" result code.
   */
  public static final int NO_RESULTS_RETURNED_INT_VALUE = 94;



  /**
   * The client-side result code (94) that will be used if the server did not
   * send any results.
   */
  @NotNull public static final ResultCode NO_RESULTS_RETURNED =
       new ResultCode(INFO_RC_NO_RESULTS_RETURNED.get(),
                      NO_RESULTS_RETURNED_INT_VALUE);



  /**
   * The integer value (95) for the "MORE_RESULTS_TO_RETURN" result code.
   */
  public static final int MORE_RESULTS_TO_RETURN_INT_VALUE = 95;



  /**
   * The client-side result code (95) that will be used if there are still more
   * results to return.
   */
  @NotNull public static final ResultCode MORE_RESULTS_TO_RETURN =
       new ResultCode(INFO_RC_MORE_RESULTS_TO_RETURN.get(),
                      MORE_RESULTS_TO_RETURN_INT_VALUE);



  /**
   * The integer value (96) for the "CLIENT_LOOP" result code.
   */
  public static final int CLIENT_LOOP_INT_VALUE = 96;



  /**
   * The client-side result code (96) that will be used if the client detects a
   * loop while attempting to follow referrals.
   */
  @NotNull public static final ResultCode CLIENT_LOOP =
       new ResultCode(INFO_RC_CLIENT_LOOP.get(), CLIENT_LOOP_INT_VALUE);



  /**
   * The integer value (97) for the "REFERRAL_LIMIT_EXCEEDED" result code.
   */
  public static final int REFERRAL_LIMIT_EXCEEDED_INT_VALUE = 97;



  /**
   * The client-side result code (97) that will be used if the client
   * encountered too many referrals in the course of processing an operation.
   */
  @NotNull public static final ResultCode REFERRAL_LIMIT_EXCEEDED =
       new ResultCode(INFO_RC_REFERRAL_LIMIT_EXCEEDED.get(),
                      REFERRAL_LIMIT_EXCEEDED_INT_VALUE);



  /**
   * The integer value (118) for the "CANCELED" result code.
   */
  public static final int CANCELED_INT_VALUE = 118;



  /**
   * The result code (118) that will be used if the operation was canceled.
   */
  @NotNull public static final ResultCode CANCELED =
       new ResultCode(INFO_RC_CANCELED.get(), CANCELED_INT_VALUE);



  /**
   * The integer value (119) for the "NO_SUCH_OPERATION" result code.
   */
  public static final int NO_SUCH_OPERATION_INT_VALUE = 119;



  /**
   * The result code (119) that will be used if the client attempts to cancel an
   * operation that the client doesn't exist in the server.
   */
  @NotNull public static final ResultCode NO_SUCH_OPERATION =
       new ResultCode(INFO_RC_NO_SUCH_OPERATION.get(),
                      NO_SUCH_OPERATION_INT_VALUE);



  /**
   * The integer value (120) for the "TOO_LATE" result code.
   */
  public static final int TOO_LATE_INT_VALUE = 120;



  /**
   * The result code (120) that will be used if the client attempts to cancel an
   * operation too late in the processing for that operation.
   */
  @NotNull public static final ResultCode TOO_LATE =
       new ResultCode(INFO_RC_TOO_LATE.get(), TOO_LATE_INT_VALUE);



  /**
   * The integer value (121) for the "CANNOT_CANCEL" result code.
   */
  public static final int CANNOT_CANCEL_INT_VALUE = 121;



  /**
   * The result code (121) that will be used if the client attempts to cancel an
   * operation that cannot be canceled.
   */
  @NotNull public static final ResultCode CANNOT_CANCEL =
       new ResultCode(INFO_RC_CANNOT_CANCEL.get(), CANNOT_CANCEL_INT_VALUE);



  /**
   * The integer value (122) for the "ASSERTION_FAILED" result code.
   */
  public static final int ASSERTION_FAILED_INT_VALUE = 122;



  /**
   * The result code (122) that will be used if the requested operation included
   * the LDAP assertion control but the assertion did not match the target
   * entry.
   */
  @NotNull public static final ResultCode ASSERTION_FAILED =
       new ResultCode(INFO_RC_ASSERTION_FAILED.get(),
                      ASSERTION_FAILED_INT_VALUE);



  /**
   * The integer value (123) for the "AUTHORIZATION_DENIED" result code.
   */
  public static final int AUTHORIZATION_DENIED_INT_VALUE = 123;



  /**
   * The result code (123) that will be used if the client is denied the ability
   * to use the proxied authorization control.
   */
  @NotNull public static final ResultCode AUTHORIZATION_DENIED =
       new ResultCode(INFO_RC_AUTHORIZATION_DENIED.get(),
                      AUTHORIZATION_DENIED_INT_VALUE);



  /**
   * The integer value (4096) for the "E_SYNC_REFRESH_REQUIRED" result code.
   */
  public static final int E_SYNC_REFRESH_REQUIRED_INT_VALUE = 4096;



  /**
   * The result code (4096) that will be used if a client using the content
   * synchronization request control requests an incremental update but the
   * server is unable to honor that request and requires the client to request
   * an initial content.
   */
  @NotNull public static final ResultCode E_SYNC_REFRESH_REQUIRED =
       new ResultCode(INFO_RC_E_SYNC_REFRESH_REQUIRED.get(),
                      E_SYNC_REFRESH_REQUIRED_INT_VALUE);



  /**
   * The integer value (16654) for the "NO_OPERATION" result code.
   */
  public static final int NO_OPERATION_INT_VALUE = 16_654;



  /**
   * The result code (16654) for operations that completed successfully but no
   * changes were made to the server because the LDAP no-op control was included
   * in the request.
   */
  @NotNull public static final ResultCode NO_OPERATION =
       new ResultCode(INFO_RC_NO_OPERATION.get(), NO_OPERATION_INT_VALUE);



  /**
   * The integer value (30221001) for the "INTERACTIVE_TRANSACTION_ABORTED"
   * result code.
   */
  public static final int INTERACTIVE_TRANSACTION_ABORTED_INT_VALUE =
       30_221_001;



  /**
   * The result code (30221001) for use if an interactive transaction has been
   * aborted, either due to an explicit request from a client or by the server
   * without a client request.
   */
  @NotNull public static final ResultCode INTERACTIVE_TRANSACTION_ABORTED =
       new ResultCode(INFO_RC_INTERACTIVE_TRANSACTION_ABORTED.get(),
                      INTERACTIVE_TRANSACTION_ABORTED_INT_VALUE);



  /**
   * The integer value (30221002) for the "DATABASE_LOCK_CONFLICT" result code.
   */
  public static final int DATABASE_LOCK_CONFLICT_INT_VALUE = 30_221_002;



  /**
   * The result code (30221002) for use if an operation fails because of a
   * database lock conflict (e.g., a deadlock or lock timeout).
   */
  @NotNull public static final ResultCode DATABASE_LOCK_CONFLICT =
       new ResultCode(INFO_RC_DATABASE_LOCK_CONFLICT.get(),
                      DATABASE_LOCK_CONFLICT_INT_VALUE);



  /**
   * The integer value (30221003) for the "MIRRORED_SUBTREE_DIGEST_MISMATCH"
   * result code.
   */
  public static final int MIRRORED_SUBTREE_DIGEST_MISMATCH_INT_VALUE =
       30_221_003;



  /**
   * The result code (30221003) that should be used by a node in a topology of
   * servers to indicate that its subtree digest does not match that of its
   * master's.
   */
  @NotNull public static final ResultCode MIRRORED_SUBTREE_DIGEST_MISMATCH =
      new ResultCode(INFO_RC_MIRRORED_SUBTREE_DIGEST_MISMATCH.get(),
          MIRRORED_SUBTREE_DIGEST_MISMATCH_INT_VALUE);



  /**
   * The integer value (30221004) for the "TOKEN_DELIVERY_MECHANISM_UNAVAILABLE"
   * result code.
   */
  public static final int TOKEN_DELIVERY_MECHANISM_UNAVAILABLE_INT_VALUE =
       30_221_004;



  /**
   * The result code (30221004) that should be used to indicate that the server
   * could not deliver a one-time password, password reset token, or single-use
   * token because none of the attempted delivery mechanisms were supported for
   * the target user.
   */
  @NotNull public static final ResultCode TOKEN_DELIVERY_MECHANISM_UNAVAILABLE =
      new ResultCode(INFO_RC_TOKEN_DELIVERY_MECHANISM_UNAVAILABLE.get(),
          TOKEN_DELIVERY_MECHANISM_UNAVAILABLE_INT_VALUE);



  /**
   * The integer value (30221005) for the "TOKEN_DELIVERY_ATTEMPT_FAILED"
   * result code.
   */
  public static final int TOKEN_DELIVERY_ATTEMPT_FAILED_INT_VALUE = 30_221_005;



  /**
   * The result code (30221005) that should be used to indicate that the server
   * could not deliver a one-time password, password reset token, or single-use
   * token because a failure was encountered while attempting to deliver the
   * token through all of the supported mechanisms.
   */
  @NotNull public static final ResultCode TOKEN_DELIVERY_ATTEMPT_FAILED =
      new ResultCode(INFO_RC_TOKEN_DELIVERY_ATTEMPT_FAILED.get(),
          TOKEN_DELIVERY_ATTEMPT_FAILED_INT_VALUE);



  /**
   * The integer value (30221006) for the "TOKEN_DELIVERY_INVALID_RECIPIENT_ID"
   * result code.
   */
  public static final int TOKEN_DELIVERY_INVALID_RECIPIENT_ID_INT_VALUE =
       30_221_006;



  /**
   * The result code (30221006) that should be used to indicate that the server
   * could not deliver a one-time password, password reset token, or single-use
   * token because the client specified a recipient ID that was not appropriate
   * for the target user.
   */
  @NotNull public static final ResultCode TOKEN_DELIVERY_INVALID_RECIPIENT_ID =
      new ResultCode(INFO_RC_TOKEN_DELIVERY_INVALID_RECIPIENT_ID.get(),
          TOKEN_DELIVERY_INVALID_RECIPIENT_ID_INT_VALUE);



  /**
   * The integer value (30221007) for the "TOKEN_DELIVERY_INVALID_ACCOUNT_STATE"
   * result code.
   */
  public static final int TOKEN_DELIVERY_INVALID_ACCOUNT_STATE_INT_VALUE =
       30_221_007;



  /**
   * The result code (30221007) that should be used to indicate that the server
   * could not deliver a one-time password, password reset token, or single-use
   * token because the target user account was in an invalid state for receiving
   * such tokens (e.g., the account is disabled or locked, the password is
   * expired, etc.).
   */
  @NotNull public static final ResultCode TOKEN_DELIVERY_INVALID_ACCOUNT_STATE =
      new ResultCode(INFO_RC_TOKEN_DELIVERY_INVALID_ACCOUNT_STATE.get(),
          TOKEN_DELIVERY_INVALID_ACCOUNT_STATE_INT_VALUE);



  /**
   * The set of result code objects created with undefined int result code
   * values.
   */
  @NotNull private static final ConcurrentHashMap<Integer,ResultCode>
       UNDEFINED_RESULT_CODES =
            new ConcurrentHashMap<>(StaticUtils.computeMapCapacity(10));



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7609311304252378100L;



  // The integer value for this result code.
  private final int intValue;

  // The name for this result code.
  @NotNull private final String name;

  // The string representation for this result code.
  @NotNull private final String stringRepresentation;



  /**
   * Creates a new result code with the specified integer value.
   *
   * @param  intValue  The integer value for this result code.
   */
  private ResultCode(final int intValue)
  {
    this.intValue = intValue;

    name                 = String.valueOf(intValue);
    stringRepresentation = name;
  }



  /**
   * Creates a new result code with the specified name and integer value.
   *
   * @param  name      The name for this result code.
   * @param  intValue  The integer value for this result code.
   */
  private ResultCode(@NotNull final String name, final int intValue)
  {
    this.name     = name;
    this.intValue = intValue;

    stringRepresentation = intValue + " (" + name + ')';
  }



  /**
   * Retrieves the name for this result code.
   *
   * @return  The name for this result code.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the integer value for this result code.
   *
   * @return  The integer value for this result code.
   */
  public int intValue()
  {
    return intValue;
  }



  /**
   * Retrieves the result code with the specified integer value.  If the
   * provided integer value does not correspond to a predefined
   * {@code ResultCode} object, then a new {@code ResultCode} object will be
   * created and returned.  Any new result codes created will also be cached
   * and returned for any subsequent requests with that integer value so the
   * same object will always be returned for a given integer value.
   *
   * @param  intValue  The integer value for which to retrieve the corresponding
   *                   result code.
   *
   * @return  The result code with the specified integer value, or a new result
   *          code
   */
  @NotNull()
  public static ResultCode valueOf(final int intValue)
  {
    return valueOf(intValue, null);
  }



  /**
   * Retrieves the result code with the specified integer value.  If the
   * provided integer value does not correspond to a predefined
   * {@code ResultCode} object, then a new {@code ResultCode} object will be
   * created and returned.  Any new result codes created will also be cached
   * and returned for any subsequent requests with that integer value so the
   * same object will always be returned for a given integer value.
   *
   * @param  intValue  The integer value for which to retrieve the corresponding
   *                   result code.
   * @param  name      The user-friendly name to use for the result code if no
   *                   result code has been previously accessed with the same
   *                   integer value.  It may be {@code null} if this is not
   *                   known or a string representation of the integer value
   *                   should be used.
   *
   * @return  The result code with the specified integer value, or a new result
   *          code
   */
  @NotNull()
  public static ResultCode valueOf(final int intValue,
                                   @Nullable final String name)
  {
    return valueOf(intValue, name, true);
  }



  /**
   * Retrieves the result code with the specified integer value.  If the
   * provided integer value does not correspond to an already-defined
   * {@code ResultCode} object, then this method may optionally create and
   * return a new {@code ResultCode}.  Any new result codes created will also be
   * cached and returned for any subsequent requests with that integer value so
   * the same object will always be returned for a given integer value.
   *
   * @param  intValue             The integer value for which to retrieve the
   *                              corresponding result code.
   * @param  name                 The user-friendly name to use for the result
   *                              code if no result code has been previously
   *                              accessed with the same integer value.  It may
   *                              be {@code null} if this is not known or a
   *                              string representation of the integer value
   *                              should be used.
   * @param  createNewResultCode  Indicates whether to create a new result code
   *                              object with the specified integer value and
   *                              name if that value does not correspond to
   *                              any already-defined result code.
   *
   * @return  The existing result code with the specified integer value if one
   *          already existed, a newly-created result code with the specified
   *          name and integer value if none already existed but
   *          {@code createNewResultCode} is {@code true}, or {@code null} if no
   *          result code already existed with the specified integer value and
   *          {@code createNewResultCode} is {@code false}.
   */
  @Nullable()
  public static ResultCode valueOf(final int intValue,
                                   @Nullable final String name,
                                   final boolean createNewResultCode)
  {
    switch (intValue)
    {
      case SUCCESS_INT_VALUE:
        return SUCCESS;
      case OPERATIONS_ERROR_INT_VALUE:
        return OPERATIONS_ERROR;
      case PROTOCOL_ERROR_INT_VALUE:
        return PROTOCOL_ERROR;
      case TIME_LIMIT_EXCEEDED_INT_VALUE:
        return TIME_LIMIT_EXCEEDED;
      case SIZE_LIMIT_EXCEEDED_INT_VALUE:
        return SIZE_LIMIT_EXCEEDED;
      case COMPARE_FALSE_INT_VALUE:
        return COMPARE_FALSE;
      case COMPARE_TRUE_INT_VALUE:
        return COMPARE_TRUE;
      case AUTH_METHOD_NOT_SUPPORTED_INT_VALUE:
        return AUTH_METHOD_NOT_SUPPORTED;
      case STRONG_AUTH_REQUIRED_INT_VALUE:
        return STRONG_AUTH_REQUIRED;
      case REFERRAL_INT_VALUE:
        return REFERRAL;
      case ADMIN_LIMIT_EXCEEDED_INT_VALUE:
        return ADMIN_LIMIT_EXCEEDED;
      case UNAVAILABLE_CRITICAL_EXTENSION_INT_VALUE:
        return UNAVAILABLE_CRITICAL_EXTENSION;
      case CONFIDENTIALITY_REQUIRED_INT_VALUE:
        return CONFIDENTIALITY_REQUIRED;
      case SASL_BIND_IN_PROGRESS_INT_VALUE:
        return SASL_BIND_IN_PROGRESS;
      case NO_SUCH_ATTRIBUTE_INT_VALUE:
        return NO_SUCH_ATTRIBUTE;
      case UNDEFINED_ATTRIBUTE_TYPE_INT_VALUE:
        return UNDEFINED_ATTRIBUTE_TYPE;
      case INAPPROPRIATE_MATCHING_INT_VALUE:
        return INAPPROPRIATE_MATCHING;
      case CONSTRAINT_VIOLATION_INT_VALUE:
        return CONSTRAINT_VIOLATION;
      case ATTRIBUTE_OR_VALUE_EXISTS_INT_VALUE:
        return ATTRIBUTE_OR_VALUE_EXISTS;
      case INVALID_ATTRIBUTE_SYNTAX_INT_VALUE:
        return INVALID_ATTRIBUTE_SYNTAX;
      case NO_SUCH_OBJECT_INT_VALUE:
        return NO_SUCH_OBJECT;
      case ALIAS_PROBLEM_INT_VALUE:
        return ALIAS_PROBLEM;
      case INVALID_DN_SYNTAX_INT_VALUE:
        return INVALID_DN_SYNTAX;
      case ALIAS_DEREFERENCING_PROBLEM_INT_VALUE:
        return ALIAS_DEREFERENCING_PROBLEM;
      case INAPPROPRIATE_AUTHENTICATION_INT_VALUE:
        return INAPPROPRIATE_AUTHENTICATION;
      case INVALID_CREDENTIALS_INT_VALUE:
        return INVALID_CREDENTIALS;
      case INSUFFICIENT_ACCESS_RIGHTS_INT_VALUE:
        return INSUFFICIENT_ACCESS_RIGHTS;
      case BUSY_INT_VALUE:
        return BUSY;
      case UNAVAILABLE_INT_VALUE:
        return UNAVAILABLE;
      case UNWILLING_TO_PERFORM_INT_VALUE:
        return UNWILLING_TO_PERFORM;
      case LOOP_DETECT_INT_VALUE:
        return LOOP_DETECT;
      case SORT_CONTROL_MISSING_INT_VALUE:
        return SORT_CONTROL_MISSING;
      case OFFSET_RANGE_ERROR_INT_VALUE:
        return OFFSET_RANGE_ERROR;
      case NAMING_VIOLATION_INT_VALUE:
        return NAMING_VIOLATION;
      case OBJECT_CLASS_VIOLATION_INT_VALUE:
        return OBJECT_CLASS_VIOLATION;
      case NOT_ALLOWED_ON_NONLEAF_INT_VALUE:
        return NOT_ALLOWED_ON_NONLEAF;
      case NOT_ALLOWED_ON_RDN_INT_VALUE:
        return NOT_ALLOWED_ON_RDN;
      case ENTRY_ALREADY_EXISTS_INT_VALUE:
        return ENTRY_ALREADY_EXISTS;
      case OBJECT_CLASS_MODS_PROHIBITED_INT_VALUE:
        return OBJECT_CLASS_MODS_PROHIBITED;
      case AFFECTS_MULTIPLE_DSAS_INT_VALUE:
        return AFFECTS_MULTIPLE_DSAS;
      case VIRTUAL_LIST_VIEW_ERROR_INT_VALUE:
        return VIRTUAL_LIST_VIEW_ERROR;
      case OTHER_INT_VALUE:
        return OTHER;
      case SERVER_DOWN_INT_VALUE:
        return SERVER_DOWN;
      case LOCAL_ERROR_INT_VALUE:
        return LOCAL_ERROR;
      case ENCODING_ERROR_INT_VALUE:
        return ENCODING_ERROR;
      case DECODING_ERROR_INT_VALUE:
        return DECODING_ERROR;
      case TIMEOUT_INT_VALUE:
        return TIMEOUT;
      case AUTH_UNKNOWN_INT_VALUE:
        return AUTH_UNKNOWN;
      case FILTER_ERROR_INT_VALUE:
        return FILTER_ERROR;
      case USER_CANCELED_INT_VALUE:
        return USER_CANCELED;
      case PARAM_ERROR_INT_VALUE:
        return PARAM_ERROR;
      case NO_MEMORY_INT_VALUE:
        return NO_MEMORY;
      case CONNECT_ERROR_INT_VALUE:
        return CONNECT_ERROR;
      case NOT_SUPPORTED_INT_VALUE:
        return NOT_SUPPORTED;
      case CONTROL_NOT_FOUND_INT_VALUE:
        return CONTROL_NOT_FOUND;
      case NO_RESULTS_RETURNED_INT_VALUE:
        return NO_RESULTS_RETURNED;
      case MORE_RESULTS_TO_RETURN_INT_VALUE:
        return MORE_RESULTS_TO_RETURN;
      case CLIENT_LOOP_INT_VALUE:
        return CLIENT_LOOP;
      case REFERRAL_LIMIT_EXCEEDED_INT_VALUE:
        return REFERRAL_LIMIT_EXCEEDED;
      case CANCELED_INT_VALUE:
        return CANCELED;
      case NO_SUCH_OPERATION_INT_VALUE:
        return NO_SUCH_OPERATION;
      case TOO_LATE_INT_VALUE:
        return TOO_LATE;
      case CANNOT_CANCEL_INT_VALUE:
        return CANNOT_CANCEL;
      case ASSERTION_FAILED_INT_VALUE:
        return ASSERTION_FAILED;
      case AUTHORIZATION_DENIED_INT_VALUE:
        return AUTHORIZATION_DENIED;
      case E_SYNC_REFRESH_REQUIRED_INT_VALUE:
        return E_SYNC_REFRESH_REQUIRED;
      case NO_OPERATION_INT_VALUE:
        return NO_OPERATION;
      case INTERACTIVE_TRANSACTION_ABORTED_INT_VALUE:
        return INTERACTIVE_TRANSACTION_ABORTED;
      case DATABASE_LOCK_CONFLICT_INT_VALUE:
        return DATABASE_LOCK_CONFLICT;
      case MIRRORED_SUBTREE_DIGEST_MISMATCH_INT_VALUE:
        return MIRRORED_SUBTREE_DIGEST_MISMATCH;
      case TOKEN_DELIVERY_MECHANISM_UNAVAILABLE_INT_VALUE:
        return TOKEN_DELIVERY_MECHANISM_UNAVAILABLE;
      case TOKEN_DELIVERY_ATTEMPT_FAILED_INT_VALUE:
        return TOKEN_DELIVERY_ATTEMPT_FAILED;
      case TOKEN_DELIVERY_INVALID_RECIPIENT_ID_INT_VALUE:
        return TOKEN_DELIVERY_INVALID_RECIPIENT_ID;
      case TOKEN_DELIVERY_INVALID_ACCOUNT_STATE_INT_VALUE:
        return TOKEN_DELIVERY_INVALID_ACCOUNT_STATE;
    }

    ResultCode rc = UNDEFINED_RESULT_CODES.get(intValue);
    if (rc == null)
    {
      if (! createNewResultCode)
      {
        return null;
      }

      if (name == null)
      {
        rc = new ResultCode(intValue);
      }
      else
      {
        rc = new ResultCode(name, intValue);
      }

      final ResultCode existingRC =
           UNDEFINED_RESULT_CODES.putIfAbsent(intValue, rc);
      if (existingRC != null)
      {
        return existingRC;
      }
    }

    return rc;
  }



  /**
   * Retrieves an array of all result codes defined in the LDAP SDK.  This will
   * not include dynamically-generated values.
   *
   * @return  An array of all result codes defined in the LDAP SDK.
   */
  @NotNull()
  public static ResultCode[] values()
  {
    return new ResultCode[]
    {
      SUCCESS,
      OPERATIONS_ERROR,
      PROTOCOL_ERROR,
      TIME_LIMIT_EXCEEDED,
      SIZE_LIMIT_EXCEEDED,
      COMPARE_FALSE,
      COMPARE_TRUE,
      AUTH_METHOD_NOT_SUPPORTED,
      STRONG_AUTH_REQUIRED,
      REFERRAL,
      ADMIN_LIMIT_EXCEEDED,
      UNAVAILABLE_CRITICAL_EXTENSION,
      CONFIDENTIALITY_REQUIRED,
      SASL_BIND_IN_PROGRESS,
      NO_SUCH_ATTRIBUTE,
      UNDEFINED_ATTRIBUTE_TYPE,
      INAPPROPRIATE_MATCHING,
      CONSTRAINT_VIOLATION,
      ATTRIBUTE_OR_VALUE_EXISTS,
      INVALID_ATTRIBUTE_SYNTAX,
      NO_SUCH_OBJECT,
      ALIAS_PROBLEM,
      INVALID_DN_SYNTAX,
      ALIAS_DEREFERENCING_PROBLEM,
      INAPPROPRIATE_AUTHENTICATION,
      INVALID_CREDENTIALS,
      INSUFFICIENT_ACCESS_RIGHTS,
      BUSY,
      UNAVAILABLE,
      UNWILLING_TO_PERFORM,
      LOOP_DETECT,
      SORT_CONTROL_MISSING,
      OFFSET_RANGE_ERROR,
      NAMING_VIOLATION,
      OBJECT_CLASS_VIOLATION,
      NOT_ALLOWED_ON_NONLEAF,
      NOT_ALLOWED_ON_RDN,
      ENTRY_ALREADY_EXISTS,
      OBJECT_CLASS_MODS_PROHIBITED,
      AFFECTS_MULTIPLE_DSAS,
      VIRTUAL_LIST_VIEW_ERROR,
      OTHER,
      SERVER_DOWN,
      LOCAL_ERROR,
      ENCODING_ERROR,
      DECODING_ERROR,
      TIMEOUT,
      AUTH_UNKNOWN,
      FILTER_ERROR,
      USER_CANCELED,
      PARAM_ERROR,
      NO_MEMORY,
      CONNECT_ERROR,
      NOT_SUPPORTED,
      CONTROL_NOT_FOUND,
      NO_RESULTS_RETURNED,
      MORE_RESULTS_TO_RETURN,
      CLIENT_LOOP,
      REFERRAL_LIMIT_EXCEEDED,
      CANCELED,
      NO_SUCH_OPERATION,
      TOO_LATE,
      CANNOT_CANCEL,
      ASSERTION_FAILED,
      AUTHORIZATION_DENIED,
      E_SYNC_REFRESH_REQUIRED,
      NO_OPERATION,
      INTERACTIVE_TRANSACTION_ABORTED,
      DATABASE_LOCK_CONFLICT,
      MIRRORED_SUBTREE_DIGEST_MISMATCH,
      TOKEN_DELIVERY_MECHANISM_UNAVAILABLE,
      TOKEN_DELIVERY_ATTEMPT_FAILED,
      TOKEN_DELIVERY_INVALID_RECIPIENT_ID,
      TOKEN_DELIVERY_INVALID_ACCOUNT_STATE
    };
  }



  /**
   * Indicates whether this result code is one that should be used for
   * client-side errors rather than returned by the server.
   *
   * @return  {@code true} if this result code is a client-side result code, or
   *          {@code false} if it is one that may be returned by the server.
   */
  public boolean isClientSideResultCode()
  {
    return isClientSideResultCode(this);
  }



  /**
   * Indicates whether the provided result code is one that should be used for
   * client-side errors rather than returned by the server.
   *
   * @param  resultCode  The result code for which to make the determination.
   *
   * @return  {@code true} if the provided result code is a client-side result
   *          code, or {@code false} if it is one that may be returned by the
   *          server.
   */
  public static boolean isClientSideResultCode(
                             @NotNull final ResultCode resultCode)
  {
    switch (resultCode.intValue())
    {
      case SERVER_DOWN_INT_VALUE:
      case LOCAL_ERROR_INT_VALUE:
      case ENCODING_ERROR_INT_VALUE:
      case DECODING_ERROR_INT_VALUE:
      case TIMEOUT_INT_VALUE:
      case AUTH_UNKNOWN_INT_VALUE:
      case FILTER_ERROR_INT_VALUE:
      case USER_CANCELED_INT_VALUE:
      case PARAM_ERROR_INT_VALUE:
      case NO_MEMORY_INT_VALUE:
      case CONNECT_ERROR_INT_VALUE:
      case NOT_SUPPORTED_INT_VALUE:
      case CONTROL_NOT_FOUND_INT_VALUE:
      case NO_RESULTS_RETURNED_INT_VALUE:
      case MORE_RESULTS_TO_RETURN_INT_VALUE:
      case CLIENT_LOOP_INT_VALUE:
      case REFERRAL_LIMIT_EXCEEDED_INT_VALUE:
        return true;
      default:
        return false;
    }
  }



  /**
   * Indicates whether the connection on which this result code was received is
   * likely still usable.  Note that this is a best guess, and it may or may not
   * be correct.  It will attempt to be conservative so that a connection is
   * more likely to be classified as unusable when it may still be valid than to
   * be classified as usable when that is no longer the case.
   *
   * @return  {@code true} if it is likely that the connection on which this
   *          result code was received is still usable, or {@code false} if it
   *          may no longer be valid.
   */
  public boolean isConnectionUsable()
  {
    return isConnectionUsable(this);
  }



  /**
   * Indicates whether the connection on which the provided result code was
   * received is likely still usable.  Note that this is a best guess based on
   * the provided result code, and it may or may not be correct.  It will
   * attempt to be conservative so that a connection is more likely to be
   * classified as unusable when it may still be valid than to be classified
   * as usable when that is no longer the case.
   *
   * @param  resultCode  The result code for which to make the determination.
   *
   * @return  {@code true} if it is likely that the connection on which the
   *          provided result code was received is still usable, or
   *          {@code false} if it may no longer be valid.
   */
  public static boolean isConnectionUsable(@NotNull final ResultCode resultCode)
  {
    switch (resultCode.intValue())
    {
      case OPERATIONS_ERROR_INT_VALUE:
      case PROTOCOL_ERROR_INT_VALUE:
      case BUSY_INT_VALUE:
      case UNAVAILABLE_INT_VALUE:
      case OTHER_INT_VALUE:
      case SERVER_DOWN_INT_VALUE:
      case LOCAL_ERROR_INT_VALUE:
      case ENCODING_ERROR_INT_VALUE:
      case DECODING_ERROR_INT_VALUE:
      case TIMEOUT_INT_VALUE:
      case NO_MEMORY_INT_VALUE:
      case CONNECT_ERROR_INT_VALUE:
        return false;
      default:
        return true;
    }
  }



  /**
   * The hash code for this result code.
   *
   * @return  The hash code for this result code.
   */
  @Override()
  public int hashCode()
  {
    return intValue;
  }



  /**
   * Indicates whether the provided object is equal to this result code.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is a result code that is equal
   *          to this result code, or {@code false} if not.
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    if (o == null)
    {
      return false;
    }
    else if (o == this)
    {
      return true;
    }
    else if (o instanceof ResultCode)
    {
      return (intValue == ((ResultCode) o).intValue);
    }
    else
    {
      return false;
    }
  }



  /**
   * Retrieves a string representation of this result code.
   *
   * @return  A string representation of this result code.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return stringRepresentation;
  }
}
