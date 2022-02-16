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



import java.util.List;
import java.util.Set;

import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.controls.AssuredReplicationLocalLevel;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationRemoteLevel;
import com.unboundid.ldap.sdk.unboundidds.logs.AccessLogMessageType;
import com.unboundid.ldap.sdk.unboundidds.logs.LogException;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.AddResultAccessLogMessage;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a data structure that holds information about a
 * JSON-formatted add result access log message.
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
@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class JSONAddResultAccessLogMessage
       extends JSONAddRequestAccessLogMessage
       implements AddResultAccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 157458238209990115L;



  // The forward helper for this access log message.
  @NotNull private final JSONForwardAccessLogMessageHelper forwardHelper;

  // The result helper for this access log message.
  @NotNull private final JSONResultAccessLogMessageHelper resultHelper;

  // The undelete from DN for this log message.
  @Nullable private final String undeleteFromDN;



  /**
   * Creates a new JSON add result access log message from the provided JSON
   * object.
   *
   * @param  jsonObject  The JSON object that contains an encoded representation
   *                     of this log message.  It must not be {@code null}.
   *
   * @throws  LogException  If the provided JSON object cannot be parsed as a
   *                        valid log message.
   */
  public JSONAddResultAccessLogMessage(@NotNull final JSONObject jsonObject)
         throws LogException
  {
    super(jsonObject);

    undeleteFromDN =
         getString(JSONFormattedAccessLogFields.ADD_UNDELETE_FROM_DN);

    resultHelper = new JSONResultAccessLogMessageHelper(this);
    forwardHelper = new JSONForwardAccessLogMessageHelper(this);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public AccessLogMessageType getMessageType()
  {
    return AccessLogMessageType.RESULT;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final ResultCode getResultCode()
  {
    return resultHelper.getResultCode();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getDiagnosticMessage()
  {
    return resultHelper.getDiagnosticMessage();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getAdditionalInformation()
  {
    return resultHelper.getAdditionalInformation();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getMatchedDN()
  {
    return resultHelper.getMatchedDN();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public final List<String> getReferralURLs()
  {
    return resultHelper.getReferralURLs();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Double getProcessingTimeMillis()
  {
    return resultHelper.getProcessingTimeMillis();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Double getWorkQueueWaitTimeMillis()
  {
    return resultHelper.getWorkQueueWaitTimeMillis();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public final Set<String> getResponseControlOIDs()
  {
    return resultHelper.getResponseControlOIDs();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Long getIntermediateResponsesReturned()
  {
    return resultHelper.getIntermediateResponsesReturned();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public final List<String> getServersAccessed()
  {
    return resultHelper.getServersAccessed();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Boolean getUncachedDataAccessed()
  {
    return resultHelper.getUncachedDataAccessed();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public final Set<String> getUsedPrivileges()
  {
    return resultHelper.getUsedPrivileges();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public final Set<String> getPreAuthorizationUsedPrivileges()
  {
    return resultHelper.getPreAuthorizationUsedPrivileges();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public final Set<String> getMissingPrivileges()
  {
    return resultHelper.getMissingPrivileges();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getAlternateAuthorizationDN()
  {
    return resultHelper.getAlternateAuthorizationDN();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getReplicationChangeID()
  {
    return resultHelper.getReplicationChangeID();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final AssuredReplicationLocalLevel getAssuredReplicationLocalLevel()
  {
    return resultHelper.getAssuredReplicationLocalLevel();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final AssuredReplicationRemoteLevel getAssuredReplicationRemoteLevel()
  {
    return resultHelper.getAssuredReplicationRemoteLevel();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Long getAssuredReplicationTimeoutMillis()
  {
    return resultHelper.getAssuredReplicationTimeoutMillis();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Boolean getResponseDelayedByAssurance()
  {
    return resultHelper.getResponseDelayedByAssurance();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public final Set<String> getIndexesWithKeysAccessedNearEntryLimit()
  {
    return resultHelper.getIndexesWithKeysAccessedNearEntryLimit();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public final Set<String> getIndexesWithKeysAccessedExceedingEntryLimit()
  {
    return resultHelper.getIndexesWithKeysAccessedExceedingEntryLimit();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getTargetHost()
  {
    return forwardHelper.getTargetHost();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Integer getTargetPort()
  {
    return forwardHelper.getTargetPort();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getTargetProtocol()
  {
    return forwardHelper.getTargetProtocol();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getUndeleteFromDN()
  {
    return undeleteFromDN;
  }
}
