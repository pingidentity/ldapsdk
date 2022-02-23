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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.json;



import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.controls.AssuredReplicationLocalLevel;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationRemoteLevel;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationServerResultCode;
import com.unboundid.ldap.sdk.unboundidds.logs.AccessLogMessageType;
import com.unboundid.ldap.sdk.unboundidds.logs.AccessLogOperationType;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.LogField;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.logs.v2.json.
                   JSONFormattedAccessLogFields.*;



/**
 * This class provides utility methods for JSON-formatted access logging test
 * cases.
 */
public abstract class JSONLogsTestCase
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
   * The downstream intermediate client request control that will be included in
   * the default intermediate client request control.
   */
  protected static final JSONIntermediateClientRequestControl
       DEFAULT_INTERMEDIATE_CLIENT_DOWNSTREAM_REQUEST =
       new JSONIntermediateClientRequestControl(new JSONObject(
            new JSONField(
                 INTERMEDIATE_CLIENT_REQUEST_CONTROL_DOWNSTREAM_CLIENT_ADDRESS.
                      getFieldName(),
                 "downstream.client.address"),
            new JSONField(
                 INTERMEDIATE_CLIENT_REQUEST_CONTROL_DOWNSTREAM_CLIENT_SECURE.
                      getFieldName(),
                 false),
            new JSONField(
                 INTERMEDIATE_CLIENT_REQUEST_CONTROL_CLIENT_IDENTITY.
                      getFieldName(),
                 "u:downstreamClientIdentity"),
            new JSONField(
                 INTERMEDIATE_CLIENT_REQUEST_CONTROL_CLIENT_NAME.getFieldName(),
                 "Downstream Client Name"),
            new JSONField(
                 INTERMEDIATE_CLIENT_REQUEST_CONTROL_SESSION_ID.getFieldName(),
                 "downstream-session-id"),
            new JSONField(
                 INTERMEDIATE_CLIENT_REQUEST_CONTROL_REQUEST_ID.getFieldName(),
                 "downstream-request-id")));



  /**
   * The default intermediate client request control that will be used for log
   * messages.
   */
  protected static final JSONIntermediateClientRequestControl
       DEFAULT_INTERMEDIATE_CLIENT_REQUEST =
       new JSONIntermediateClientRequestControl(new JSONObject(
            new JSONField(
                 INTERMEDIATE_CLIENT_REQUEST_CONTROL_DOWNSTREAM_CLIENT_ADDRESS.
                      getFieldName(),
                 "client.address"),
            new JSONField(
                 INTERMEDIATE_CLIENT_REQUEST_CONTROL_DOWNSTREAM_CLIENT_SECURE.
                      getFieldName(),
                 true),
            new JSONField(
                 INTERMEDIATE_CLIENT_REQUEST_CONTROL_CLIENT_IDENTITY.
                      getFieldName(),
                 "u:clientIdentity"),
            new JSONField(
                 INTERMEDIATE_CLIENT_REQUEST_CONTROL_CLIENT_NAME.getFieldName(),
                 "Client Name"),
            new JSONField(
                 INTERMEDIATE_CLIENT_REQUEST_CONTROL_SESSION_ID.getFieldName(),
                 "session-id"),
            new JSONField(
                 INTERMEDIATE_CLIENT_REQUEST_CONTROL_REQUEST_ID.getFieldName(),
                 "request-id"),
            new JSONField(
                 INTERMEDIATE_CLIENT_REQUEST_CONTROL_DOWNSTREAM_REQUEST.
                      getFieldName(),
                 DEFAULT_INTERMEDIATE_CLIENT_DOWNSTREAM_REQUEST.
                      getControlObject())));



  /**
   * The upstream intermediate client response control that will be included
   * in the default intermediate client response control.
   */
  protected static final JSONIntermediateClientResponseControl
       DEFAULT_INTERMEDIATE_CLIENT_UPSTREAM_RESPONSE =
       new JSONIntermediateClientResponseControl(new JSONObject(
            new JSONField(
                 INTERMEDIATE_CLIENT_RESPONSE_CONTROL_UPSTREAM_SERVER_ADDRESS.
                      getFieldName(),
                 "upstream.server.address"),
            new JSONField(
                 INTERMEDIATE_CLIENT_RESPONSE_CONTROL_UPSTREAM_SERVER_SECURE.
                      getFieldName(),
                 false),
            new JSONField(
                 INTERMEDIATE_CLIENT_RESPONSE_CONTROL_SERVER_NAME.
                      getFieldName(),
                 "Upstream Server Name"),
            new JSONField(
                 INTERMEDIATE_CLIENT_RESPONSE_CONTROL_SESSION_ID.getFieldName(),
                 "upstream-session-id"),
            new JSONField(
                 INTERMEDIATE_CLIENT_RESPONSE_CONTROL_RESPONSE_ID.
                      getFieldName(),
                 "upstream-response-id")));



  /**
   * The default intermediate client response control that will be used for log
   * messages.
   */
  protected static final JSONIntermediateClientResponseControl
       DEFAULT_INTERMEDIATE_CLIENT_RESPONSE =
       new JSONIntermediateClientResponseControl(new JSONObject(
            new JSONField(
                 INTERMEDIATE_CLIENT_RESPONSE_CONTROL_UPSTREAM_SERVER_ADDRESS.
                      getFieldName(),
                 "server.address"),
            new JSONField(
                 INTERMEDIATE_CLIENT_RESPONSE_CONTROL_UPSTREAM_SERVER_SECURE.
                      getFieldName(),
                 true),
            new JSONField(
                 INTERMEDIATE_CLIENT_RESPONSE_CONTROL_SERVER_NAME.
                      getFieldName(),
                 "Server Name"),
            new JSONField(
                 INTERMEDIATE_CLIENT_RESPONSE_CONTROL_SESSION_ID.getFieldName(),
                 "session-id"),
            new JSONField(
                 INTERMEDIATE_CLIENT_RESPONSE_CONTROL_RESPONSE_ID.
                      getFieldName(),
                 "response-id"),
            new JSONField(
                 INTERMEDIATE_CLIENT_RESPONSE_CONTROL_UPSTREAM_RESPONSE.
                      getFieldName(),
                 DEFAULT_INTERMEDIATE_CLIENT_UPSTREAM_RESPONSE.
                      getControlObject())));



  /**
   * The default operation purpose request control that will be used for log
   * messages.
   */
  protected static final JSONOperationPurposeRequestControl
       DEFAULT_OPERATION_PURPOSE_REQUEST =
       new JSONOperationPurposeRequestControl(new JSONObject(
            new JSONField(OPERATION_PURPOSE_APPLICATION_NAME.getFieldName(),
                 "Application Name"),
            new JSONField(OPERATION_PURPOSE_APPLICATION_VERSION.getFieldName(),
                 "Application Version"),
            new JSONField(OPERATION_PURPOSE_CODE_LOCATION.getFieldName(),
                 "Code Location"),
            new JSONField(OPERATION_PURPOSE_REQUEST_PURPOSE.getFieldName(),
                 "Request Purpose")));



  /**
   * The default list of server assurance results that will be used for log
   * messages.
   */
  @NotNull protected static final List<JSONAssuredReplicationServerResult>
       DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS = Arrays.asList(
            new JSONAssuredReplicationServerResult(new JSONObject(
                 new JSONField(
                      SERVER_ASSURANCE_RESULTS_RESULT_CODE.getFieldName(),
                      AssuredReplicationServerResultCode.COMPLETE.name()),
                 new JSONField(
                      SERVER_ASSURANCE_RESULTS_REPLICATION_SERVER_ID.
                           getFieldName(),
                      678),
                 new JSONField(
                      SERVER_ASSURANCE_RESULTS_REPLICA_ID.
                           getFieldName(),
                      876))),
            new JSONAssuredReplicationServerResult(new JSONObject(
                 new JSONField(
                      SERVER_ASSURANCE_RESULTS_RESULT_CODE.getFieldName(),
                      AssuredReplicationServerResultCode.TIMEOUT.name()),
                 new JSONField(
                      SERVER_ASSURANCE_RESULTS_REPLICATION_SERVER_ID.
                           getFieldName(),
                      789),
                 new JSONField(
                      SERVER_ASSURANCE_RESULTS_REPLICA_ID.
                           getFieldName(),
                      987))));



  /**
   * The default set of referral URLs that will appear in log messages.
   */
  @NotNull protected static final List<String> DEFAULT_REFERRAL_URLS =
       Arrays.asList(
            "ldap://1.2.3.4:389/dc=example,dc=com",
            "ldap://1.2.3.5:389/dc=example,dc=com");



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
   * The string representation of the default timestamp.
   */
  @NotNull protected static final String DEFAULT_TIMESTAMP_STRING =
       StaticUtils.encodeRFC3339Time(DEFAULT_TIMESTAMP_DATE);



  /**
   * Creates a new JSON field with the provided name and value.
   *
   * @param  logField  The log field to use to create the JSON field.
   * @param  value     The value to use to create the JSON field.
   *
   * @return  The JSON field that was created.
   */
  @NotNull()
  protected static JSONField createField(@NotNull final LogField logField,
                                         final JSONValue value)
  {
    return new JSONField(logField.getFieldName(), value);
  }



  /**
   * Creates a new Boolean JSON field with the provided name and value.
   *
   * @param  logField  The log field to use to create the JSON field.
   * @param  value     The value to use to create the JSON field.
   *
   * @return  The JSON field that was created.
   */
  @NotNull()
  protected static JSONField createField(@NotNull final LogField logField,
                                         final boolean value)
  {
    return new JSONField(logField.getFieldName(), value);
  }



  /**
   * Creates a new numeric JSON field with the provided name and value.
   *
   * @param  logField  The log field to use to create the JSON field.
   * @param  value     The value to use to create the JSON field.
   *
   * @return  The JSON field that was created.
   */
  @NotNull()
  protected static JSONField createField(@NotNull final LogField logField,
                                         final long value)
  {
    return new JSONField(logField.getFieldName(), value);
  }



  /**
   * Creates a new numeric JSON field with the provided name and value.
   *
   * @param  logField  The log field to use to create the JSON field.
   * @param  value     The value to use to create the JSON field.
   *
   * @return  The JSON field that was created.
   */
  @NotNull()
  protected static JSONField createField(@NotNull final LogField logField,
                                         final double value)
  {
    return new JSONField(logField.getFieldName(), value);
  }



  /**
   * Creates a new string JSON field with the provided name and value.
   *
   * @param  logField  The log field to use to create the JSON field.
   * @param  value     The value to use to create the JSON field.
   *
   * @return  The JSON field that was created.
   */
  @NotNull()
  protected static JSONField createField(@NotNull final LogField logField,
                                         final String value)
  {
    return new JSONField(logField.getFieldName(), value);
  }



  /**
   * Creates a new string array JSON field with the provided name and value.
   *
   * @param  logField  The log field to use to create the JSON field.
   * @param  values    The set of values to use to create the JSON field.
   *
   * @return  The JSON field that was created.
   */
  @NotNull()
  protected static JSONField createField(@NotNull final LogField logField,
                                         @NotNull final String... values)
  {
    return new JSONField(logField.getFieldName(), createArray(values));
  }



  /**
   * Creates an array containing the provided set of values.
   *
   * @param  values  The values to include in the array.  It must not be
   *                 {@code null} but may be empty.
   *
   * @return  The array containing the provided set of values.
   */
  @NotNull()
  protected static JSONArray createArray(@NotNull final String... values)
  {
    return createArray(Arrays.asList(values));
  }



  /**
   * Creates an array containing the provided set of values.
   *
   * @param  values  The values to include in the array.  It must not be
   *                 {@code null} but may be empty.
   *
   * @return  The array containing the provided set of values.
   */
  @NotNull()
  protected static JSONArray createArray(
                 @NotNull final Collection<String> values)
  {
    final List<JSONValue> arrayValues = new ArrayList<>(values.size());
    for (final String value : values)
    {
      arrayValues.add(new JSONString(value));
    }

    return new JSONArray(arrayValues);
  }



  /**
   * Creates a JSON object with an encoded representation of a log message with
   * a minimal set of fields populated.
   *
   * @param  messageType    The message type for the log message.  This must not
   *                        be {@code null}.
   * @param  operationType  The operation type for the log message.  This may be
   *                        {@code null} if it is not an operation log message.
   * @param  fields         The set of additional fields to include in the log
   *                        message.  This must not be {@code null} but may be
   *                        empty.
   *
   * @return  The log message that was created.
   */
  @NotNull()
  protected static JSONObject createMinimalMessageObject(
                 @NotNull final AccessLogMessageType messageType,
                 @Nullable final AccessLogOperationType operationType,
                 @NotNull final JSONField... fields)
  {
    final Map<String,JSONValue> fieldMap =
         createMinimalFieldMap(messageType, operationType);
    for (final JSONField field : fields)
    {
      fieldMap.put(field.getName(), field.getValue());
    }

    return new JSONObject(fieldMap);
  }



  /**
   * Creates a JSON object with an encoded representation of a log message that
   * has values populated for most of the optional common fields.
   *
   * @param  messageType    The message type for the log message.  This must not
   *                        be {@code null}.
   * @param  operationType  The operation type for the log message.  This may be
   *                        {@code null} if it is not an operation log message.
   * @param  fields         The set of additional fields to include in the log
   *                        message.  This must not be {@code null} but may be
   *                        empty.
   *
   * @return  The log message that was created.
   */
  @NotNull()
  protected static JSONObject createPopulatedMessageObject(
                 @NotNull final AccessLogMessageType messageType,
                 @Nullable final AccessLogOperationType operationType,
                 @NotNull final JSONField... fields)
  {
    final Map<String,JSONValue> fieldMap =
         createMinimalFieldMap(messageType, operationType);

    fieldMap.put(PRODUCT_NAME.getFieldName(),
         new JSONString(DEFAULT_PRODUCT_NAME));
    fieldMap.put(INSTANCE_NAME.getFieldName(),
         new JSONString(DEFAULT_INSTANCE_NAME));
    fieldMap.put(STARTUP_ID.getFieldName(),
         new JSONString(DEFAULT_STARTUP_ID));
    fieldMap.put(THREAD_ID.getFieldName(),
         new JSONNumber(DEFAULT_THREAD_ID));
    fieldMap.put(CONNECTION_ID.getFieldName(),
         new JSONNumber(DEFAULT_CONNECTION_ID));

    if (operationType != null)
    {
      fieldMap.put(OPERATION_ID.getFieldName(),
           new JSONNumber(DEFAULT_OPERATION_ID));
      fieldMap.put(MESSAGE_ID.getFieldName(),
           new JSONNumber(DEFAULT_MESSAGE_ID));
      fieldMap.put(TRIGGERED_BY_CONNECTION_ID.getFieldName(),
           new JSONNumber(DEFAULT_TRIGGERED_BY_CONNECTION_ID));
      fieldMap.put(TRIGGERED_BY_OPERATION_ID.getFieldName(),
           new JSONNumber(DEFAULT_TRIGGERED_BY_OPERATION_ID));
      fieldMap.put(ORIGIN.getFieldName(),
           new JSONString(DEFAULT_ORIGIN));
      fieldMap.put(REQUESTER_IP_ADDRESS.getFieldName(),
           new JSONString(DEFAULT_REQUESTER_IP));
      fieldMap.put(REQUESTER_DN.getFieldName(),
           new JSONString(DEFAULT_REQUESTER_DN));
      fieldMap.put(REQUEST_CONTROL_OIDS.getFieldName(),
           createArray(DEFAULT_REQUEST_CONTROL_OIDS));
      fieldMap.put(USING_ADMIN_SESSION_WORKER_THREAD.getFieldName(),
           new JSONBoolean(DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD));
      fieldMap.put(ADMINISTRATIVE_OPERATION.getFieldName(),
           new JSONString(DEFAULT_ADMIN_OP_MESSAGE));
      fieldMap.put(INTERMEDIATE_CLIENT_REQUEST_CONTROL.getFieldName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getControlObject());
      fieldMap.put(OPERATION_PURPOSE.getFieldName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getControlObject());

      if ((messageType == AccessLogMessageType.FORWARD) ||
           (messageType == AccessLogMessageType.FORWARD_FAILED) ||
           (messageType == AccessLogMessageType.RESULT) ||
           (messageType == AccessLogMessageType.ASSURANCE_COMPLETE))
      {
        fieldMap.put(TARGET_HOST.getFieldName(),
             new JSONString(DEFAULT_FORWARD_TARGET_HOST));
        fieldMap.put(TARGET_PORT.getFieldName(),
             new JSONNumber(DEFAULT_FORWARD_TARGET_PORT));
        fieldMap.put(TARGET_PROTOCOL.getFieldName(),
             new JSONString(DEFAULT_FORWARD_TARGET_PROTOCOL));
      }

      if ((messageType == AccessLogMessageType.FORWARD_FAILED) ||
           (messageType == AccessLogMessageType.RESULT) ||
           (messageType == AccessLogMessageType.ASSURANCE_COMPLETE))
      {
        fieldMap.put(RESULT_CODE_VALUE.getFieldName(),
             new JSONNumber(DEFAULT_RESULT_CODE.intValue()));
        fieldMap.put(RESULT_CODE_NAME.getFieldName(),
             new JSONString(DEFAULT_RESULT_CODE.getName()));
        fieldMap.put(DIAGNOSTIC_MESSAGE.getFieldName(),
             new JSONString(DEFAULT_DIAGNOSTIC_MESSAGE));
      }

      if ((messageType == AccessLogMessageType.RESULT) ||
           (messageType == AccessLogMessageType.ASSURANCE_COMPLETE) ||
           (messageType == AccessLogMessageType.ENTRY) ||
           (messageType == AccessLogMessageType.REFERENCE) ||
           (messageType == AccessLogMessageType.INTERMEDIATE_RESPONSE))
      {
        fieldMap.put(RESPONSE_CONTROL_OIDS.getFieldName(),
             createArray(DEFAULT_RESPONSE_CONTROL_OIDS));
      }

      if ((messageType == AccessLogMessageType.RESULT) ||
           (messageType == AccessLogMessageType.ASSURANCE_COMPLETE))
      {
        fieldMap.put(ADDITIONAL_INFO.getFieldName(),
             new JSONString(DEFAULT_ADDITIONAL_INFO_MESSAGE));
        fieldMap.put(MATCHED_DN.getFieldName(),
             new JSONString(DEFAULT_MATCHED_DN));
        fieldMap.put(REFERRAL_URLS.getFieldName(),
             createArray(DEFAULT_REFERRAL_URLS));
        fieldMap.put(SERVERS_ACCESSED.getFieldName(),
             createArray(DEFAULT_SERVERS_ACCESSED));
        fieldMap.put(UNCACHED_DATA_ACCESSED.getFieldName(),
             new JSONBoolean(DEFAULT_UNCACHED_DATA_ACCESSED));
        fieldMap.put(WORK_QUEUE_WAIT_TIME_MILLIS.getFieldName(),
             new JSONNumber(DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS));
        fieldMap.put(PROCESSING_TIME_MILLIS.getFieldName(),
             new JSONNumber(DEFAULT_PROCESSING_TIME_MILLIS));
        fieldMap.put(INTERMEDIATE_RESPONSES_RETURNED.getFieldName(),
             new JSONNumber(DEFAULT_INTERMEDIATE_RESPONSES_RETURNED));
        fieldMap.put(USED_PRIVILEGES.getFieldName(),
             createArray(DEFAULT_USED_PRIVILEGES));
        fieldMap.put(PRE_AUTHORIZATION_USED_PRIVILEGES.getFieldName(),
             createArray(DEFAULT_PRE_AUTHZ_USED_PRIVILEGES));
        fieldMap.put(MISSING_PRIVILEGES.getFieldName(),
             createArray(DEFAULT_MISSING_PRIVILEGES));

        if (operationType != AccessLogOperationType.ABANDON)
        {
          fieldMap.put(INTERMEDIATE_CLIENT_RESPONSE_CONTROL.getFieldName(),
               DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getControlObject());
        }

        if ((operationType == AccessLogOperationType.ADD) ||
             (operationType == AccessLogOperationType.COMPARE) ||
             (operationType == AccessLogOperationType.DELETE) ||
             (operationType == AccessLogOperationType.MODIFY) ||
             (operationType == AccessLogOperationType.MODDN) ||
             (operationType == AccessLogOperationType.SEARCH))
        {
          fieldMap.put(AUTHORIZATION_DN.getFieldName(),
               new JSONString(DEFAULT_AUTHZ_DN));
        }

        if ((operationType == AccessLogOperationType.ADD) ||
             (operationType == AccessLogOperationType.DELETE) ||
             (operationType == AccessLogOperationType.MODIFY) ||
             (operationType == AccessLogOperationType.MODDN))
        {
          fieldMap.put(REPLICATION_CHANGE_ID.getFieldName(),
               new JSONString(DEFAULT_REPLICATION_CHANGE_ID));
          fieldMap.put(ASSURED_REPLICATION_REQUIREMENTS.getFieldName(),
               createAssuredReplicationRequirements());
        }

        if ((operationType == AccessLogOperationType.ADD) ||
             (operationType == AccessLogOperationType.DELETE) ||
             (operationType == AccessLogOperationType.MODIFY) ||
             (operationType == AccessLogOperationType.MODDN) ||
             (operationType == AccessLogOperationType.SEARCH))
        {
          fieldMap.put(
               INDEXES_WITH_KEYS_ACCESSED_NEAR_ENTRY_LIMIT.getFieldName(),
               createArray(DEFAULT_INDEXES_NEAR_ENTRY_LIMIT));
          fieldMap.put(
               INDEXES_WITH_KEYS_ACCESSED_EXCEEDING_ENTRY_LIMIT.getFieldName(),
               createArray(DEFAULT_INDEXES_EXCEEDING_ENTRY_LIMIT));
        }
      }

      if (messageType == AccessLogMessageType.ASSURANCE_COMPLETE)
      {
        fieldMap.put(LOCAL_ASSURANCE_SATISFIED.getFieldName(),
             new JSONBoolean(DEFAULT_LOCAL_ASSURANCE_SATISFIED));
        fieldMap.put(REMOTE_ASSURANCE_SATISFIED.getFieldName(),
             new JSONBoolean(DEFAULT_REMOTE_ASSURANCE_SATISFIED));
        fieldMap.put(SERVER_ASSURANCE_RESULTS.getFieldName(),
             new JSONArray(
                  DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(0).
                       getServerResultObject(),
                  DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(1).
                       getServerResultObject()));
      }
    }

    for (final JSONField field : fields)
    {
      fieldMap.put(field.getName(), field.getValue());
    }

    return new JSONObject(fieldMap);
  }



  /**
   * Creates a JSON object that represents a set of assured replication
   * requirements.
   *
   * @return  A JSON object that represents a set of assured replication
   *          requirements.
   */
  @NotNull()
  private static JSONObject createAssuredReplicationRequirements()
  {
    return new JSONObject(
         new JSONField(
              ASSURED_REPLICATION_REQUIREMENTS_LOCAL_ASSURANCE_LEVEL.
                   getFieldName(),
              new JSONString(DEFAULT_LOCAL_ASSURANCE_LEVEL.name())),
         new JSONField(
              ASSURED_REPLICATION_REQUIREMENTS_REMOTE_ASSURANCE_LEVEL.
                   getFieldName(),
              new JSONString(DEFAULT_REMOTE_ASSURANCE_LEVEL.name())),
         new JSONField(
              ASSURED_REPLICATION_REQUIREMENTS_ASSURANCE_TIMEOUT_MILLIS.
                   getFieldName(),
              new JSONNumber(DEFAULT_ASSURANCE_TIMEOUT_MILLIS)),
         new JSONField(
              ASSURED_REPLICATION_REQUIREMENTS_RESPONSE_DELAYED_BY_ASSURANCE.
                   getFieldName(),
              new JSONBoolean(DEFAULT_RESPONSE_DELAYED_BY_ASSURANCE)));
  }



  /**
   * Creates a map with a minimal set of fields for a JSON-formatted log
   * message.
   *
   * @param  messageType    The message type for the log message.  This must not
   *                        be {@code null}.
   * @param  operationType  The operation type for the log message.  This may be
   *                        {@code null} if it is not an operation log message.
   *
   * @return  The map that was created.  It will be updatable.
   */
  @NotNull()
  private static Map<String,JSONValue> createMinimalFieldMap(
                 @NotNull final AccessLogMessageType messageType,
                 @Nullable final AccessLogOperationType operationType)
  {
    final Map<String,JSONValue> fieldMap = new LinkedHashMap<>();
    fieldMap.put(TIMESTAMP.getFieldName(),
         new JSONString(DEFAULT_TIMESTAMP_STRING));
    fieldMap.put(LOG_TYPE.getFieldName(),
         new JSONString(ACCESS_LOG_TYPE));
    fieldMap.put(MESSAGE_TYPE.getFieldName(),
         new JSONString(messageType.getLogIdentifier()));

    if (operationType != null)
    {
      fieldMap.put(OPERATION_TYPE.getFieldName(),
           new JSONString(operationType.getLogIdentifier()));
    }

    return fieldMap;
  }
}
