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
package com.unboundid.ldap.sdk.unboundidds.logs.v2;



import java.util.Set;

import com.unboundid.ldap.sdk.unboundidds.controls.AssuredReplicationLocalLevel;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationRemoteLevel;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a modify
 * operation result access log message.
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
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface ModifyResultAccessLogMessage
       extends OperationResultAccessLogMessage,
               ModifyForwardAccessLogMessage
{
  /**
   * Retrieves the alternate authorization DN for the operation.
   *
   * @return  The alternate authorization DN for the operation, or {@code null}
   *          if it is not included in the log message.
   */
  @Nullable()
  String getAlternateAuthorizationDN();



  /**
   * Retrieves the replication change ID for the operation, if available.
   *
   * @return  The replication change ID for the operation, or {@code null} if it
   *          is not included in the log message.
   */
  @Nullable()
  String getReplicationChangeID();



  /**
   * Indicates whether the modify operation targeted a soft-deleted entry.
   *
   * @return  {@code true} if the modify operation was known to target a
   *          soft-deleted entry, {@code false} if it was known to target a
   *          non-soft-deleted entry, or {@code null} if it is not included in
   *          the log message (and likely did not target a soft-deleted entry).
   */
  @Nullable()
  Boolean getChangeToSoftDeletedEntry();



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
  AssuredReplicationLocalLevel getAssuredReplicationLocalLevel();



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
  AssuredReplicationRemoteLevel getAssuredReplicationRemoteLevel();



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
  Long getAssuredReplicationTimeoutMillis();



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
  Boolean getResponseDelayedByAssurance();



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
  Set<String> getIndexesWithKeysAccessedNearEntryLimit();



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
  Set<String> getIndexesWithKeysAccessedExceedingEntryLimit();
}
