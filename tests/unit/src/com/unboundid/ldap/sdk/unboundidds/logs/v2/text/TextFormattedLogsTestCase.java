/*
 * Copyright 2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022 Ping Identity Corporation
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
 * Copyright (C) 2022 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.text;



import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.controls.AssuredReplicationLocalLevel;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationRemoteLevel;
import com.unboundid.ldap.sdk.unboundidds.logs.AccessLogMessageType;
import com.unboundid.ldap.sdk.unboundidds.logs.AccessLogOperationType;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.LogField;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;

import static com.unboundid.ldap.sdk.unboundidds.logs.v2.text.
                   TextFormattedAccessLogFields.*;



/**
 * This class provides utility methods for text-formatted access logging test
 * cases.
 */
public abstract class TextFormattedLogsTestCase
       extends LDAPSDKTestCase
{
  /**
   * The default local replication assurance level that will be used for log
   * messages.
   */
  @NotNull protected static final AssuredReplicationLocalLevel
       DEFAULT_LOCAL_ASSURANCE_LEVEL =
            AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER;



  /**
   * The default remote replication assurance level that will be used for log
   * messages.
   */
  @NotNull protected static final AssuredReplicationRemoteLevel
       DEFAULT_REMOTE_ASSURANCE_LEVEL =
            AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION;



  /**
   * The default local assurance satisfied value that will be used for log
   * messages.
   */
  @NotNull protected static final Boolean
       DEFAULT_LOCAL_ASSURANCE_SATISFIED = Boolean.TRUE;



  /**
   * The default remote assurance satisfied value that will be used for log
   * messages.
   */
  @NotNull protected static final Boolean
       DEFAULT_REMOTE_ASSURANCE_SATISFIED = Boolean.FALSE;



  /**
   * The default response delayed by assurance value that will be used for log
   * messages.
   */
  @NotNull protected static final Boolean
       DEFAULT_RESPONSE_DELAYED_BY_ASSURANCE = Boolean.TRUE;



  /**
   * The default uncachedDataAccessed value that will be used for log
   * messages.
   */
  @NotNull protected static final Boolean DEFAULT_UNCACHED_DATA_ACCESSED =
       Boolean.TRUE;



  /**
   * The default usingAdminSessionWorkerThread value that will be used for log
   * messages.
   */
  @NotNull protected static final Boolean
       DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD = Boolean.TRUE;



  /**
   * The default date that will be used for log messages.
   */
  @NotNull protected static final Date DEFAULT_TIMESTAMP_DATE = new Date();



  /**
   * The default work queue wait time that will be used for log messages.
   */
  protected static final double DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS = 1.234d;



  /**
   * The default work processing time that will be used for log messages.
   */
  protected static final double DEFAULT_PROCESSING_TIME_MILLIS = 2.345d;



  /**
   * The default forward target port that will be used for log messages.
   */
  protected static final int DEFAULT_FORWARD_TARGET_PORT = 389;



  /**
   * The default message ID that will be used for log messages.
   */
  protected static final int DEFAULT_MESSAGE_ID = 3;



  /**
   * The default set of referral URLs that will appear in log messages.
   */
  @NotNull protected static final List<String> DEFAULT_REFERRAL_URLS =
       Arrays.asList(
            "ldap://1.2.3.4:389/dc=example,dc=com",
            "ldap://1.2.3.5:389/dc=example,dc=com");



  /**
   * The default set of server assurance results.
   */
  @NotNull protected static final List<String>
       DEFAULT_SERVER_ASSURANCE_RESULTS = Arrays.asList(
            "server-assurance-result-1",
            "server-assurance-result-2");



  /**
   * The default set of servers accessed that will appear in log messages.
   */
  @NotNull protected static final List<String> DEFAULT_SERVERS_ACCESSED =
       Arrays.asList("1.2.3.11:389", "1.2.3.12:389");



  /**
   * The default replication assurance timeout that will be used for log
   * messages.
   */
  protected static final long DEFAULT_ASSURANCE_TIMEOUT_MILLIS = 2345L;



  /**
   * The default connection ID that will be used for log messages.
   */
  protected static final long DEFAULT_CONNECTION_ID = 0L;



  /**
   * The default intermediate responses returned that will be used for log
   * messages.
   */
  protected static final long DEFAULT_INTERMEDIATE_RESPONSES_RETURNED = 4L;



  /**
   * The default operation ID that will be used for log messages.
   */
  protected static final long DEFAULT_OPERATION_ID = 1L;



  /**
   * The default thread ID that will be used for log messages.
   */
  protected static final long DEFAULT_THREAD_ID = 2L;



  /**
   * The default triggered by connection ID value that will be used for log
   * messages.
   */
  protected static final long DEFAULT_TRIGGERED_BY_CONNECTION_ID = 5L;



  /**
   * The default triggered by operation ID value that will be used for log
   * messages.
   */
  protected static final long DEFAULT_TRIGGERED_BY_OPERATION_ID = 6L;



  /**
   * The default result code that will be used for log messages.
   */
  protected static final ResultCode DEFAULT_RESULT_CODE = ResultCode.OTHER;



  /**
   * The default set of missing privileges that will appear in log messages.
   */
  @NotNull protected static final Set<String>
       DEFAULT_MISSING_PRIVILEGES = Collections.singleton("password-reset");



  /**
   * The default set of pre-authorization used privileges that will appear in
   * log messages.
   */
  @NotNull protected static final Set<String>
       DEFAULT_PRE_AUTHZ_USED_PRIVILEGES =
       Collections.singleton("proxied-auth");



  /**
   * The default set of indexes exceeding the entry limit that will appear in
   * log messages.
   */
  @NotNull protected static final Set<String>
       DEFAULT_INDEXES_EXCEEDING_ENTRY_LIMIT =
            StaticUtils.setOf("exceeding-attr-1", "exceeding-attr-2");



  /**
   * The default set of indexes near the entry limit that will appear in log
   * messages.
   */
  @NotNull protected static final Set<String> DEFAULT_INDEXES_NEAR_ENTRY_LIMIT =
       StaticUtils.setOf("near-attr-1", "near-attr-2");



  /**
   * The default set of request control OIDs that will appear in log messages.
   */
  @NotNull protected static final Set<String> DEFAULT_REQUEST_CONTROL_OIDS =
       StaticUtils.setOf("1.2.3.5", "1.2.3.6");



  /**
   * The default set of response control OIDs that will appear in log messages.
   */
  @NotNull protected static final Set<String> DEFAULT_RESPONSE_CONTROL_OIDS =
       StaticUtils.setOf("1.2.3.7", "1.2.3.8");



  /**
   * The default set of used privileges that will appear in log messages.
   */
  @NotNull protected static final Set<String> DEFAULT_USED_PRIVILEGES =
       StaticUtils.setOf("config-read", "config-write");



  /**
   * The access log type that will be used for log messages.
   */
  @NotNull protected static final String ACCESS_LOG_TYPE = "access";



  /**
   * The default additional information message that will be used for log
   * messages.
   */
  @NotNull protected static final String DEFAULT_ADDITIONAL_INFO_MESSAGE =
       "Additional Information";



  /**
   * The default administrative operation message that will be used for log
   * messages.
   */
  @NotNull protected static final String DEFAULT_ADMIN_OP_MESSAGE =
       "Administrative Operation";



  /**
   * The default authorization DN that will be used for log messages.
   */
  @NotNull protected static final String DEFAULT_AUTHZ_DN = "cn=AuthZ,cn=DN";



  /**
   * The default diagnostic message that will be used for log messages.
   */
  @NotNull protected static final String DEFAULT_DIAGNOSTIC_MESSAGE =
       "Diagnostic Message";



  /**
   * The default forward target host that will be used for log messages.
   */
  @NotNull protected static final String DEFAULT_FORWARD_TARGET_HOST =
       "1.2.3.9";



  /**
   * The default forward target protocol that will be used for log messages.
   */
  @NotNull protected static final String DEFAULT_FORWARD_TARGET_PROTOCOL =
       "LDAP";



  /**
   * The default instance name that will be used for log messages.
   */
  @NotNull protected static final String DEFAULT_INSTANCE_NAME =
       "Instance Name";



  /**
   * The default matched DN that will be used for log messages.
   */
  @NotNull protected static final String DEFAULT_MATCHED_DN =
       "cn=Matched,cn=DN";



  /**
   * The default origin that will be used for log messages.
   */
  @NotNull protected static final String DEFAULT_ORIGIN = "Default Origin";



  /**
   * The default product name that will be used for log messages.
   */
  @NotNull protected static final String DEFAULT_PRODUCT_NAME = "Product Name";



  /**
   * The default replication change ID that will be used for log messages.
   */
  @NotNull protected static final String DEFAULT_REPLICATION_CHANGE_ID =
       "replication-change-id";



  /**
   * The default requester DN that will be used for log messages.
   */
  @NotNull protected static final String DEFAULT_REQUESTER_DN =
       "cn=Default,cn=Requester";



  /**
   * The default requester IP address that will be used for log messages.
   */
  @NotNull protected static final String DEFAULT_REQUESTER_IP = "1.2.3.4";



  /**
   * The default startup ID that will be used for log messages.
   */
  @NotNull protected static final String DEFAULT_STARTUP_ID = "Startup ID";



  /**
   * Creates a buffer with the base content for a text-formatted access log
   * message.
   *
   * @param  millisPrecision      Indicates whether the timestamp should include
   *                              millisecond-level precision (if {@code true})
   *                              or second-level precision (if {@code false}).
   * @param  messageType          The message type for the log message.  It must
   *                              not be {@code null} for valid messages, but
   *                              can be {@code null} when testing malformed
   *                              messages.
   * @param  operationType        The operation type for the log message.  It
   *                              may be {@code null} if the message is not for
   *                              an operation.
   * @param  includeCommonFields  Indicates whether to include common fields in
   *                              the log message.  If {@code messageType} is
   *                              {@code null}, then this must be {@code false}.
   *
   * @return  A buffer with the base content for a text-formatted access log
   *          message.
   */
  @NotNull()
  protected static StringBuilder createLogMessage(final boolean millisPrecision,
                 @Nullable final AccessLogMessageType messageType,
                 @Nullable final AccessLogOperationType operationType,
                 final boolean includeCommonFields)
  {
    final StringBuilder buffer = new StringBuilder();

    final SimpleDateFormat dateFormat;
    if (millisPrecision)
    {
      dateFormat = new SimpleDateFormat(
           TextFormattedLogMessage.TIMESTAMP_FORMAT_MILLISECOND);
    }
    else
    {
      dateFormat = new SimpleDateFormat(
           TextFormattedLogMessage.TIMESTAMP_FORMAT_SECOND);
    }

    buffer.append(dateFormat.format(DEFAULT_TIMESTAMP_DATE));
    buffer.append(' ');

    if (operationType != null)
    {
      buffer.append(operationType.getLogIdentifier());
      buffer.append(' ');
    }

    if (messageType != null)
    {
      buffer.append(messageType.getLogIdentifier());
    }

    if (includeCommonFields)
    {
      appendField(buffer, PRODUCT_NAME, DEFAULT_PRODUCT_NAME);
      appendField(buffer, INSTANCE_NAME, DEFAULT_INSTANCE_NAME);
      appendField(buffer, STARTUP_ID, DEFAULT_STARTUP_ID);
      appendField(buffer, THREAD_ID, DEFAULT_THREAD_ID);
      appendField(buffer, CONNECTION_ID, DEFAULT_CONNECTION_ID);

      if (operationType != null)
      {
        appendField(buffer, OPERATION_ID, DEFAULT_OPERATION_ID);
        appendField(buffer, MESSAGE_ID, DEFAULT_MESSAGE_ID);
        appendField(buffer, TRIGGERED_BY_CONNECTION_ID,
             DEFAULT_TRIGGERED_BY_CONNECTION_ID);
        appendField(buffer, TRIGGERED_BY_OPERATION_ID,
             DEFAULT_TRIGGERED_BY_OPERATION_ID);
        appendField(buffer, ORIGIN, DEFAULT_ORIGIN);
        appendField(buffer, REQUESTER_IP_ADDRESS, DEFAULT_REQUESTER_IP);
        appendField(buffer, REQUESTER_DN, DEFAULT_REQUESTER_DN);
        appendField(buffer, REQUEST_CONTROL_OIDS, DEFAULT_REQUEST_CONTROL_OIDS);
        appendField(buffer, USING_ADMIN_SESSION_WORKER_THREAD,
             DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
        appendField(buffer, ADMINISTRATIVE_OPERATION, DEFAULT_ADMIN_OP_MESSAGE);

        if ((messageType == AccessLogMessageType.FORWARD) ||
             (messageType == AccessLogMessageType.FORWARD_FAILED) ||
             (messageType == AccessLogMessageType.RESULT) ||
             (messageType == AccessLogMessageType.ASSURANCE_COMPLETE))
        {
          appendField(buffer, TARGET_HOST, DEFAULT_FORWARD_TARGET_HOST);
          appendField(buffer, TARGET_PORT, DEFAULT_FORWARD_TARGET_PORT);
          appendField(buffer, TARGET_PROTOCOL, DEFAULT_FORWARD_TARGET_PROTOCOL);
        }

        if ((messageType == AccessLogMessageType.FORWARD_FAILED) ||
             (messageType == AccessLogMessageType.RESULT) ||
             (messageType == AccessLogMessageType.ASSURANCE_COMPLETE))
        {
          appendField(buffer, RESULT_CODE_VALUE,
               DEFAULT_RESULT_CODE.intValue());
          appendField(buffer, RESULT_CODE_NAME, DEFAULT_RESULT_CODE.getName());
          appendField(buffer, DIAGNOSTIC_MESSAGE, DEFAULT_DIAGNOSTIC_MESSAGE);
        }

        if ((messageType == AccessLogMessageType.RESULT) ||
             (messageType == AccessLogMessageType.ASSURANCE_COMPLETE) ||
             (messageType == AccessLogMessageType.ENTRY) ||
             (messageType == AccessLogMessageType.REFERENCE) ||
             (messageType == AccessLogMessageType.INTERMEDIATE_RESPONSE))
        {
          appendField(buffer, RESPONSE_CONTROL_OIDS,
               DEFAULT_RESPONSE_CONTROL_OIDS);
        }

        if ((messageType == AccessLogMessageType.RESULT) ||
             (messageType == AccessLogMessageType.ASSURANCE_COMPLETE))
        {
          appendField(buffer, ADDITIONAL_INFO, DEFAULT_ADDITIONAL_INFO_MESSAGE);
          appendField(buffer, MATCHED_DN, DEFAULT_MATCHED_DN);
          appendField(buffer, REFERRAL_URLS, DEFAULT_REFERRAL_URLS);
          appendField(buffer, SERVERS_ACCESSED, DEFAULT_SERVERS_ACCESSED);
          appendField(buffer, UNCACHED_DATA_ACCESSED,
               DEFAULT_UNCACHED_DATA_ACCESSED);
          appendField(buffer, WORK_QUEUE_WAIT_TIME_MILLIS,
               DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
          appendField(buffer, PROCESSING_TIME_MILLIS,
               DEFAULT_PROCESSING_TIME_MILLIS);
          appendField(buffer, INTERMEDIATE_RESPONSES_RETURNED,
               DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
          appendField(buffer, USED_PRIVILEGES, DEFAULT_USED_PRIVILEGES);
          appendField(buffer, PRE_AUTHORIZATION_USED_PRIVILEGES,
               DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
          appendField(buffer, MISSING_PRIVILEGES, DEFAULT_MISSING_PRIVILEGES);

          if ((operationType == AccessLogOperationType.ADD) ||
               (operationType == AccessLogOperationType.COMPARE) ||
               (operationType == AccessLogOperationType.DELETE) ||
               (operationType == AccessLogOperationType.MODIFY) ||
               (operationType == AccessLogOperationType.MODDN) ||
               (operationType == AccessLogOperationType.SEARCH))
          {
            appendField(buffer, AUTHORIZATION_DN, DEFAULT_AUTHZ_DN);
          }

          if ((operationType == AccessLogOperationType.ADD) ||
               (operationType == AccessLogOperationType.DELETE) ||
               (operationType == AccessLogOperationType.MODIFY) ||
               (operationType == AccessLogOperationType.MODDN))
          {
            appendField(buffer, REPLICATION_CHANGE_ID,
                 DEFAULT_REPLICATION_CHANGE_ID);
            appendField(buffer, LOCAL_ASSURANCE_LEVEL,
                 DEFAULT_LOCAL_ASSURANCE_LEVEL.name());
            appendField(buffer, REMOTE_ASSURANCE_LEVEL,
                 DEFAULT_REMOTE_ASSURANCE_LEVEL.name());
            appendField(buffer, ASSURANCE_TIMEOUT_MILLIS,
                 DEFAULT_ASSURANCE_TIMEOUT_MILLIS);
            appendField(buffer, RESPONSE_DELAYED_BY_ASSURANCE,
                 DEFAULT_RESPONSE_DELAYED_BY_ASSURANCE);
          }

          if ((operationType == AccessLogOperationType.ADD) ||
               (operationType == AccessLogOperationType.DELETE) ||
               (operationType == AccessLogOperationType.MODIFY) ||
               (operationType == AccessLogOperationType.MODDN) ||
               (operationType == AccessLogOperationType.SEARCH))
          {
            appendField(buffer, INDEXES_WITH_KEYS_ACCESSED_NEAR_ENTRY_LIMIT,
                 DEFAULT_INDEXES_NEAR_ENTRY_LIMIT);
            appendField(buffer,
                 INDEXES_WITH_KEYS_ACCESSED_EXCEEDING_ENTRY_LIMIT,
                 DEFAULT_INDEXES_EXCEEDING_ENTRY_LIMIT);
          }
        }

        if (messageType == AccessLogMessageType.ASSURANCE_COMPLETE)
        {
          appendField(buffer, LOCAL_ASSURANCE_SATISFIED,
               DEFAULT_LOCAL_ASSURANCE_SATISFIED);
          appendField(buffer, REMOTE_ASSURANCE_SATISFIED,
               DEFAULT_REMOTE_ASSURANCE_SATISFIED);
          appendField(buffer, SERVER_ASSURANCE_RESULTS,
               DEFAULT_SERVER_ASSURANCE_RESULTS);
        }
      }
    }

    return buffer;
  }



  /**
   * Appends the specified field to the given buffer.
   *
   * @param  buffer      The buffer to which the field should be appended.  It
   *                     must not be {@code null}.
   * @param  logField    The field to be added.  It must not be {@code null}.
   * @param  fieldValue  The value to use for the field.  It must not be
   *                     {@code null}.
   */
  protected static void appendField(@NotNull final StringBuilder buffer,
                                    @NotNull final LogField logField,
                                    @NotNull final String fieldValue)
  {
    buffer.append(' ');
    buffer.append(logField.getFieldName());
    buffer.append("=\"");
    buffer.append(fieldValue);
    buffer.append('"');
  }



  /**
   * Appends the specified field to the given buffer.
   *
   * @param  buffer      The buffer to which the field should be appended.  It
   *                     must not be {@code null}.
   * @param  logField    The field to be added.  It must not be {@code null}.
   * @param  fieldValue  The value to use for the field.  It must not be
   *                     {@code null}.
   */
  protected static void appendField(@NotNull final StringBuilder buffer,
                                    @NotNull final LogField logField,
                                    @NotNull final boolean fieldValue)
  {
    buffer.append(' ');
    buffer.append(logField.getFieldName());
    buffer.append('=');
    buffer.append(fieldValue);
  }



  /**
   * Appends the specified field to the given buffer.
   *
   * @param  buffer      The buffer to which the field should be appended.  It
   *                     must not be {@code null}.
   * @param  logField    The field to be added.  It must not be {@code null}.
   * @param  fieldValue  The value to use for the field.  It must not be
   *                     {@code null}.
   */
  protected static void appendField(@NotNull final StringBuilder buffer,
                                    @NotNull final LogField logField,
                                    @NotNull final double fieldValue)
  {
    buffer.append(' ');
    buffer.append(logField.getFieldName());
    buffer.append('=');

    final DecimalFormat decimalFormat = new DecimalFormat("0.000");
    buffer.append(decimalFormat.format(fieldValue));
  }



  /**
   * Appends the specified field to the given buffer.
   *
   * @param  buffer      The buffer to which the field should be appended.  It
   *                     must not be {@code null}.
   * @param  logField    The field to be added.  It must not be {@code null}.
   * @param  fieldValue  The value to use for the field.  It must not be
   *                     {@code null}.
   */
  protected static void appendField(@NotNull final StringBuilder buffer,
                                    @NotNull final LogField logField,
                                    @NotNull final long fieldValue)
  {
    buffer.append(' ');
    buffer.append(logField.getFieldName());
    buffer.append('=');
    buffer.append(fieldValue);
  }



  /**
   * Appends the specified field to the given buffer.
   *
   * @param  buffer       The buffer to which the field should be appended.  It
   *                      must not be {@code null}.
   * @param  logField     The field to be added.  It must not be {@code null}.
   * @param  fieldValues  The values to include in the value of the field.  It
   *                      must not be {@code null} but may be empty.
   */
  protected static void appendField(@NotNull final StringBuilder buffer,
                                    @NotNull final LogField logField,
                                    @NotNull final String... fieldValues)
  {
    buffer.append(' ');
    buffer.append(logField.getFieldName());
    buffer.append("=\"");

    for (int i=0; i < fieldValues.length; i++)
    {
      if (i > 0)
      {
        buffer.append(',');
      }

      buffer.append(fieldValues[i]);
    }

    buffer.append('"');
  }



  /**
   * Appends the specified field to the given buffer.
   *
   * @param  buffer       The buffer to which the field should be appended.  It
   *                      must not be {@code null}.
   * @param  logField     The field to be added.  It must not be {@code null}.
   * @param  fieldValues  The values to include in the value of the field.  It
   *                      must not be {@code null} but may be empty.
   */
  protected static void appendField(@NotNull final StringBuilder buffer,
                 @NotNull final LogField logField,
                 @NotNull final Collection<String> fieldValues)
  {
    buffer.append(' ');
    buffer.append(logField.getFieldName());
    buffer.append("=\"");

    final Iterator<String> iterator = fieldValues.iterator();
    while (iterator.hasNext())
    {
      buffer.append(iterator.next());

      if (iterator.hasNext())
      {
        buffer.append(',');
      }
    }

    buffer.append('"');
  }
}
