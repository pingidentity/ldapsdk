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



import java.io.Serializable;
import java.util.List;
import java.util.Set;

import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.controls.AssuredReplicationLocalLevel;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationRemoteLevel;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a helper for use in result access log messages.
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
final class JSONResultAccessLogMessageHelper
      implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1471250711708684260L;



  // The assured replication local level for the log message.
  @Nullable private final AssuredReplicationLocalLevel
       assuredReplicationLocalLevel;

  // The assured replication remote level for the log message.
  @Nullable private final AssuredReplicationRemoteLevel
       assuredReplicationRemoteLevel;

  // Indicates whether the response has been delayed by assurance processing.
  @Nullable private final Boolean responseDelayedByAssurance;

  // Indicates whether uncached data was accessed in the course of processing.
  @Nullable private final Boolean uncachedDataAccessed;

  // The processing time (in milliseconds) for the log message.
  @Nullable private final Double processingTimeMillis;

  // The queue wait time (in milliseconds) for the log message.
  @Nullable private final Double workQueueWaitTimeMillis;

  // The intermediate client response control for the log message.
  @Nullable private final JSONIntermediateClientResponseControl
       intermediateClientResponseControl;

  // The list of referral URLs for the log message.
  @NotNull private final List<String> referralURLs;

  // The list of servers accessed for the log message.
  @NotNull private final List<String> serversAccessed;

  // The assured replication timeout log message.
  @Nullable private final Long assuredReplicationTimeoutMillis;

  // The number of intermediate responses returned for the log message.
  @Nullable private final Long intermediateResponsesReturned;

  // The result code for the log message.
  @Nullable private final ResultCode resultCode;

  // The set of indexes accessed with keys exceeding the index entry limit.
  @NotNull private final Set<String> indexesWithKeysAccessedExceedingEntryLimit;

  // The set of indexes accessed with keys near the index entry limit.
  @NotNull private final Set<String> indexesWithKeysAccessedNearEntryLimit;

  // The set of missing privileges for the log message.
  @NotNull private final Set<String> missingPrivileges;

  // The set of pre-authorization used privileges for the log message.
  @NotNull private final Set<String> preAuthorizationUsedPrivileges;

  // The set of response control OIDs for the log message.
  @NotNull private final Set<String> responseControlOIDs;

  // The set of used privileges for the log message.
  @NotNull private final Set<String> usedPrivileges;

  // The additional information message for the log message.
  @Nullable private final String additionalInformation;

  // The alternate authorization DN for the log message.
  @Nullable private final String alternateAuthorizationDN;

  // The diagnostic message for the log message.
  @Nullable private final String diagnosticMessage;

  // The matched DN for the log message.
  @Nullable private final String matchedDN;

  // The replication change ID for the log message.
  @Nullable private final String replicationChangeID;



  /**
   * Creates a new JSON forward access log message helper for the provided log
   * message.
   *
   * @param  logMessage  The log message to use to create this forward helper.
   */
  JSONResultAccessLogMessageHelper(
       @NotNull final JSONRequestAccessLogMessage logMessage)
  {
    diagnosticMessage = logMessage.getString(
         JSONFormattedAccessLogFields.DIAGNOSTIC_MESSAGE);
    additionalInformation = logMessage.getString(
         JSONFormattedAccessLogFields.ADDITIONAL_INFO);
    matchedDN = logMessage.getString(JSONFormattedAccessLogFields.MATCHED_DN);
    referralURLs = logMessage.getStringList(
         JSONFormattedAccessLogFields.REFERRAL_URLS);
    processingTimeMillis = logMessage.getDoubleNoThrow(
         JSONFormattedAccessLogFields.PROCESSING_TIME_MILLIS);
    workQueueWaitTimeMillis = logMessage.getDoubleNoThrow(
         JSONFormattedAccessLogFields.WORK_QUEUE_WAIT_TIME_MILLIS);
    responseControlOIDs = logMessage.getStringSet(
         JSONFormattedAccessLogFields.RESPONSE_CONTROL_OIDS);
    intermediateResponsesReturned = logMessage.getLongNoThrow(
         JSONFormattedAccessLogFields.INTERMEDIATE_RESPONSES_RETURNED);
    serversAccessed = logMessage.getStringList(
         JSONFormattedAccessLogFields.SERVERS_ACCESSED);
    uncachedDataAccessed = logMessage.getBooleanNoThrow(
         JSONFormattedAccessLogFields.UNCACHED_DATA_ACCESSED);
    usedPrivileges = logMessage.getStringSet(
         JSONFormattedAccessLogFields.USED_PRIVILEGES);
    preAuthorizationUsedPrivileges = logMessage.getStringSet(
         JSONFormattedAccessLogFields.PRE_AUTHORIZATION_USED_PRIVILEGES);
    missingPrivileges = logMessage.getStringSet(
         JSONFormattedAccessLogFields.MISSING_PRIVILEGES);

    alternateAuthorizationDN = logMessage.getString(
         JSONFormattedAccessLogFields.AUTHORIZATION_DN);
    replicationChangeID = logMessage.getString(
         JSONFormattedAccessLogFields.REPLICATION_CHANGE_ID);
    indexesWithKeysAccessedNearEntryLimit = logMessage.getStringSet(
         JSONFormattedAccessLogFields.
              INDEXES_WITH_KEYS_ACCESSED_NEAR_ENTRY_LIMIT);
    indexesWithKeysAccessedExceedingEntryLimit = logMessage.getStringSet(
         JSONFormattedAccessLogFields.
              INDEXES_WITH_KEYS_ACCESSED_EXCEEDING_ENTRY_LIMIT);

    final Integer resultCodeInt = logMessage.getIntegerNoThrow(
         JSONFormattedAccessLogFields.RESULT_CODE_VALUE);
    if (resultCodeInt == null)
    {
      resultCode = null;
    }
    else
    {
      resultCode = ResultCode.valueOf(resultCodeInt);
    }

    final JSONObject assuranceRequirements =
         logMessage.getJSONObject().getFieldAsObject(
              JSONFormattedAccessLogFields.ASSURED_REPLICATION_REQUIREMENTS.
                   getFieldName());
    if (assuranceRequirements == null)
    {
      assuredReplicationLocalLevel = null;
      assuredReplicationRemoteLevel = null;
      assuredReplicationTimeoutMillis = null;
      responseDelayedByAssurance = null;
    }
    else
    {
      assuredReplicationTimeoutMillis = assuranceRequirements.getFieldAsLong(
           JSONFormattedAccessLogFields.
                ASSURED_REPLICATION_REQUIREMENTS_ASSURANCE_TIMEOUT_MILLIS.
                     getFieldName());
      responseDelayedByAssurance = assuranceRequirements.getFieldAsBoolean(
           JSONFormattedAccessLogFields.
                ASSURED_REPLICATION_REQUIREMENTS_RESPONSE_DELAYED_BY_ASSURANCE.
                     getFieldName());

      final String localLevelName = assuranceRequirements.getFieldAsString(
           JSONFormattedAccessLogFields.
                ASSURED_REPLICATION_REQUIREMENTS_LOCAL_ASSURANCE_LEVEL.
                getFieldName());
      if (localLevelName == null)
      {
        assuredReplicationLocalLevel = null;
      }
      else
      {
        assuredReplicationLocalLevel =
             AssuredReplicationLocalLevel.forName(localLevelName);
      }

      final String remoteLevelName = assuranceRequirements.getFieldAsString(
           JSONFormattedAccessLogFields.
                ASSURED_REPLICATION_REQUIREMENTS_REMOTE_ASSURANCE_LEVEL.
                getFieldName());
      if (remoteLevelName == null)
      {
        assuredReplicationRemoteLevel = null;
      }
      else
      {
        assuredReplicationRemoteLevel =
             AssuredReplicationRemoteLevel.forName(remoteLevelName);
      }
    }

    final JSONObject intermediateClientResponseObject =
         logMessage.getJSONObject().getFieldAsObject(
              JSONFormattedAccessLogFields.INTERMEDIATE_CLIENT_RESPONSE_CONTROL.
                   getFieldName());
    if (intermediateClientResponseObject == null)
    {
      intermediateClientResponseControl = null;
    }
    else
    {
      intermediateClientResponseControl =
           new JSONIntermediateClientResponseControl(
                intermediateClientResponseObject);
    }
  }



  /**
   * Retrieves the result code for the operation.
   *
   * @return  The result code for the operation, or {@code null} if it is not
   *          included in the log message.
   */
  @Nullable()
  ResultCode getResultCode()
  {
    return resultCode;
  }



  /**
   * Retrieves the diagnostic message for the operation.
   *
   * @return  The diagnostic message for the operation, or {@code null} if it is
   *          not included in the log message.
   */
  @Nullable()
  String getDiagnosticMessage()
  {
    return diagnosticMessage;
  }



  /**
   * Retrieves a message with additional information about the result of the
   * operation.
   *
   * @return  A message with additional information about the result of the
   *          operation, or {@code null} if it is not included in the log
   *          message.
   */
  @Nullable()
  String getAdditionalInformation()
  {
    return additionalInformation;
  }



  /**
   * Retrieves the matched DN for the operation.
   *
   * @return  The matched DN for the operation, or {@code null} if it is not
   *          included in the log message.
   */
  @Nullable()
  String getMatchedDN()
  {
    return matchedDN;
  }



  /**
   * Retrieves the list of referral URLs for the operation.
   *
   * @return  The list of referral URLs for the operation, or an empty list if
   *          it is not included in the log message.
   */
  @NotNull()
  List<String> getReferralURLs()
  {
    return referralURLs;
  }



  /**
   * Retrieves the length of time in milliseconds required to process the
   * operation.
   *
   * @return  The length of time in milliseconds required to process the
   *          operation, or {@code null} if it is not included in the log
   *          message.
   */
  @Nullable()
  Double getProcessingTimeMillis()
  {
    return processingTimeMillis;
  }



  /**
   * Retrieves the length of time in milliseconds the operation was required to
   * wait on the work queue.
   *
   * @return  The length of time in milliseconds the operation was required to
   *          wait on the work queue, or {@code null} if it is not included in
   *          the log message.
   */
  @Nullable()
  Double getWorkQueueWaitTimeMillis()
  {
    return workQueueWaitTimeMillis;
  }



  /**
   * Retrieves the OIDs of any response controls contained in the log message.
   *
   * @return  The OIDs of any response controls contained in the log message, or
   *          an empty list if it is not included in the log message.
   */
  @NotNull()
  Set<String> getResponseControlOIDs()
  {
    return responseControlOIDs;
  }



  /**
   * Retrieves the number of intermediate response messages returned in the
   * course of processing the operation.
   *
   * @return  The number of intermediate response messages returned to the
   *          client in the course of processing the operation, or {@code null}
   *          if it is not included in the log message.
   */
  @Nullable()
  Long getIntermediateResponsesReturned()
  {
    return intermediateResponsesReturned;
  }



  /**
   * Retrieves a list of the additional servers that were accessed in the course
   * of processing the operation.  For example, if the access log message is
   * from a Directory Proxy Server instance, then this may contain a list of the
   * backend servers used to process the operation.
   *
   * @return  A list of the additional servers that were accessed in the course
   *          of processing the operation, or an empty list if it is not
   *          included in the log message.
   */
  @NotNull()
  List<String> getServersAccessed()
  {
    return serversAccessed;
  }



  /**
   * Indicates whether the server accessed any uncached data in the course of
   * processing the operation.
   *
   * @return  {@code true} if the server was known to access uncached data in
   *          the course of processing the operation, {@code false} if the
   *          server was known not to access uncached data, or {@code null} if
   *          it is not included in the log message (and the server likely did
   *          not access uncached data).
   */
  @Nullable()
  Boolean getUncachedDataAccessed()
  {
    return uncachedDataAccessed;
  }



  /**
   * Retrieves the names of any privileges used during the course of processing
   * the operation.
   *
   * @return  The names of any privileges used during the course of processing
   *          the operation, or an empty list if no privileges were used or this
   *          is not included in the log message.
   */
  @NotNull()
  Set<String> getUsedPrivileges()
  {
    return usedPrivileges;
  }



  /**
   * Retrieves the names of any privileges used during the course of processing
   * the operation before an alternate authorization identity was assigned.
   *
   * @return  The names of any privileges used during the course of processing
   *          the operation before an alternate authorization identity was
   *          assigned, or an empty list if no privileges were used or this is
   *          not included in the log message.
   */
  @NotNull()
  Set<String> getPreAuthorizationUsedPrivileges()
  {
    return preAuthorizationUsedPrivileges;
  }



  /**
   * Retrieves the names of any privileges that would have been required for
   * processing the operation but that the requester did not have.
   *
   * @return  The names of any privileges that would have been required for
   *          processing the operation but that the requester did not have, or
   *          an empty list if there were no missing privileges or this is not
   *          included in the log message.
   */
  @NotNull()
  Set<String> getMissingPrivileges()
  {
    return missingPrivileges;
  }



  /**
   * Retrieves the alternate authorization DN for the operation.
   *
   * @return  The alternate authorization DN for the operation, or {@code null}
   *          if it is not included in the log message.
   */
  @Nullable()
  String getAlternateAuthorizationDN()
  {
    return alternateAuthorizationDN;
  }



  /**
   * Retrieves the replication change ID for the operation, if available.
   *
   * @return  The replication change ID for the operation, or {@code null} if it
   *          is not included in the log message.
   */
  @Nullable()
  String getReplicationChangeID()
  {
    return replicationChangeID;
  }



  /**
   * Retrieves the local level that will be used for assured replication
   * processing, if available.
   *
   * @return  The local level that will be used for assured replication
   *          processing, or {@code null} if this is not included in the log
   *          message (e.g., because assured replication will not be performed
   *          for the operation).
   */
  @Nullable()
  AssuredReplicationLocalLevel getAssuredReplicationLocalLevel()
  {
    return assuredReplicationLocalLevel;
  }



  /**
   * Retrieves the remote level that will be used for assured replication
   * processing, if available.
   *
   * @return  The remote level that will be used for assured replication
   *          processing, or {@code null} if this is not included in the log
   *          message (e.g., because assured replication will not be performed
   *          for the operation).
   */
  @Nullable()
  AssuredReplicationRemoteLevel getAssuredReplicationRemoteLevel()
  {
    return assuredReplicationRemoteLevel;
  }



  /**
   * Retrieves the maximum length of time in milliseconds that the server will
   * delay the response to the client while waiting for the replication
   * assurance requirement to be satisfied.
   *
   * @return  The maximum length of time in milliseconds that the server will
   *          delay the response to the client while waiting for the replication
   *          assurance requirement to be satisfied, or {@code null} if this is
   *          not included in the log message (e.g., because assured replication
   *          will not be performed for the operation).
   */
  @Nullable()
  Long getAssuredReplicationTimeoutMillis()
  {
    return assuredReplicationTimeoutMillis;
  }



  /**
   * Indicates whether the operation response to the client will be delayed
   * until replication assurance has been satisfied or the timeout has occurred.
   *
   * @return  {@code true} if the operation response to the client will be
   *          delayed until replication assurance has been satisfied,
   *          {@code false} if the response will not be delayed by assurance
   *          processing, or {@code null} if this was not included in the
   *          log message (e.g., because assured replication will not be
   *          performed for the operation)
   */
  @Nullable()
  Boolean getResponseDelayedByAssurance()
  {
    return responseDelayedByAssurance;
  }



  /**
   * Retrieves the names of any indexes for which one or more keys near
   * (typically, within 80% of) the index entry limit were accessed while
   * processing the operation.
   *
   * @return  The names of any indexes for which one or more keys near the index
   *          entry limit were accessed while processing the operation, or an
   *          empty list if no such index keys were accessed, or if this is not
   *          included in the log message.
   */
  @NotNull()
  Set<String> getIndexesWithKeysAccessedNearEntryLimit()
  {
    return indexesWithKeysAccessedNearEntryLimit;
  }



  /**
   * Retrieves the names of any indexes for which one or more keys over the
   * index entry limit were accessed while processing the operation.
   *
   * @return  The names of any indexes for which one or more keys over the index
   *          entry limit were accessed while processing the operation, or an
   *          empty list if no such index keys were accessed, or if this is not
   *          included in the log message.
   */
  @NotNull()
  Set<String> getIndexesWithKeysAccessedExceedingEntryLimit()
  {
    return indexesWithKeysAccessedExceedingEntryLimit;
  }



  /**
   * Retrieves information about an intermediate client response control
   * included in the log message.
   *
   * @return  An intermediate client response control included in the log
   *          message, or {@code null} if no intermediate client response
   *          control is available.
   */
  @Nullable()
  JSONIntermediateClientResponseControl getIntermediateClientResponseControl()
  {
    return intermediateClientResponseControl;
  }
}
