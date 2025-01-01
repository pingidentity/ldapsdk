/*
 * Copyright 2022-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2025 Ping Identity Corporation
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
 * Copyright (C) 2022-2025 Ping Identity Corporation
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



import com.unboundid.util.NotExtensible;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about an entry
 * rebalancing request access log message.
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
public interface EntryRebalancingRequestAccessLogMessage
       extends AccessLogMessage
{
  /**
   * Retrieves the unique identifier assigned to the entry rebalancing
   * operation.
   *
   * @return  The unique identifier assigned to the entry rebalancing operation,
   *          or {@code null} if it is not included in the log message.
   */
  @Nullable()
  Long getRebalancingOperationID();



  /**
   * Retrieves the connection ID for the connection that performed an operation
   * to trigger the entry rebalancing operation.
   *
   * @return  Retrieves the connection ID for the connection that performed an
   *          operation to trigger the entry rebalancing operation, or
   *          {@code null} if it is not included in the log message.
   */
  @Nullable()
  Long getTriggeredByConnectionID();



  /**
   * Retrieves the operation ID for the operation that triggered the entry
   * rebalancing operation.
   *
   * @return  Retrieves the operation ID for the operation that triggered the
   *          entry rebalancing operation, or {@code null} if it is not included
   *          in the log message.
   */
  @Nullable()
  Long getTriggeredByOperationID();



  /**
   * Retrieves the base DN of the subtree that will be migrated during the entry
   * rebalancing operation.
   *
   * @return  The base DN of the subtree that will be migrated during the entry
   *          rebalancing operation, or {@code null} if it is not included in
   *          the log message.
   */
  @Nullable()
  String getSubtreeBaseDN();



  /**
   * Retrieves the maximum number of entries that may be contained in the
   * subtree for it to be successfully migrated.
   *
   * @return  The maximum number of entries that may be contained in the subtree
   *          for it to be successfully migrated, or {@code null} if it is not
   *          included in the log message.
   */
  @Nullable()
  Integer getSizeLimit();



  /**
   * Retrieves the name of the backend set containing the subtree to be
   * migrated.
   *
   * @return  The name of the backend set containing the subtree to be migrated,
   *          or {@code null} if it is not included in the log message.
   */
  @Nullable()
  String getSourceBackendSetName();



  /**
   * The address and port of the backend server from which the subtree will be
   * migrated.
   *
   * @return  The address and port of the backend server from which the subtree
   *          will be migrated, or {@code null} if it is not included in the log
   *          message.
   */
  @Nullable()
  String getSourceBackendServer();



  /**
   * Retrieves the name of the backend set to which the subtree will be
   * migrated.
   *
   * @return  The name of the backend set ot which the subtree will be migrated,
   *          or {@code null} if it is not included in the log message.
   */
  @Nullable()
  String getTargetBackendSetName();



  /**
   * Retrieves the address and port of the backend server to which the subtree
   * will be migrated.
   *
   * @return  The address and port of the backend server to which the subtree
   *          will be migrated, or {@code null} if it is not included in the log
   *          message.
   */
  @Nullable()
  String getTargetBackendServer();
}
