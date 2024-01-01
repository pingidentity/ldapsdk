/*
 * Copyright 2022-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2024 Ping Identity Corporation
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
 * Copyright (C) 2022-2024 Ping Identity Corporation
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

import com.unboundid.ldap.sdk.unboundidds.logs.AccessLogOperationType;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about an
 * operation request access log message.
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
public interface OperationRequestAccessLogMessage
       extends AccessLogMessage
{
  /**
   * Retrieves the operation type for the associated operation.
   *
   * @return  The operation type for this access log message.
   */
  @NotNull()
  AccessLogOperationType getOperationType();



  /**
   * Retrieves the operation ID for the associated operation.
   *
   * @return  The operation ID for the associated operation, or {@code null} if
   *          it is not included in the log message.
   */
  @Nullable()
  Long getOperationID();



  /**
   * Retrieves the message ID for the associated operation.
   *
   * @return  The message ID for the associated operation, or {@code null} if
   *          it is not included in the log message.
   */
  @Nullable()
  Integer getMessageID();



  /**
   * Retrieves the origin of the associated operation.  If present, it may be
   * "synchronization" if the operation is replicated, or "internal" if it is an
   * internal operation.
   *
   * @return  The origin for the associated operation, or {@code null} if it is
   *          not included in the log message.
   */
  @Nullable()
  String getOrigin();



  /**
   * Retrieves the connection ID for the connection that triggered the
   * associated operation.  This is generally used for internal operations that
   * are processed as a direct result of an externally-requested operation.
   *
   * @return  The connection ID for the connection that triggered the associated
   *          operation, or {@code null} if it is not included in the log
   *          message.
   */
  @Nullable()
  Long getTriggeredByConnectionID();



  /**
   * Retrieves the operation ID for the operation that triggered the associated
   * operation.  This is generally used for internal operations that are
   * processed as a direct result of an externally-requested operation.
   *
   * @return  The operation ID for the operation that triggered the associated
   *          operation, or {@code null} if it is not included in the log
   *          message.
   */
  @Nullable()
  Long getTriggeredByOperationID();



  /**
   * Retrieves the DN of the user that requested the operation.
   *
   * @return  The DN of the user that requested the operation, or {@code null}
   *          if it is not included in the log message.
   */
  @Nullable()
  String getRequesterDN();



  /**
   * Retrieves the IP address of the client that requested the operation.
   *
   * @return  The IP address of the client that requested the operation, or
   *          {@code null} if it is not included in the log message.
   */
  @Nullable()
  String getRequesterIPAddress();



  /**
   * Retrieves the OIDs of any request controls contained in the log message.
   *
   * @return  The OIDs of any request controls contained in the log message, or
   *          an empty list if it is not included in the log message.
   */
  @NotNull()
  Set<String> getRequestControlOIDs();



  /**
   * Indicates whether the operation was processed using a worker thread from
   * the dedicated administrative session thread pool.
   *
   * @return  {@code true} if the operation was processed using a worker thread
   *          from the dedicated administrative session thread pool,
   *          {@code false} if it was not, or {@code null} if that information
   *          was not included in the log message.
   */
  @Nullable()
  Boolean getUsingAdminSessionWorkerThread();



  /**
   * Retrieves a message from an associated administrative operation request
   * control.
   *
   * @return  A message from an associated administrative operation request
   *          control, or {@code null} if it is not included in teh log message.
   */
  @Nullable()
  String getAdministrativeOperationMessage();
}
