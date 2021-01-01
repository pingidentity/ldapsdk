/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs;



import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a log
 * message that may appear in the Directory Server access log about a the
 * beginning of an entry rebalancing operation.
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
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class EntryRebalancingRequestAccessLogMessage
       extends AccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7183383454122018479L;



  // The maximum number of entries to include in the subtree move.
  @Nullable private final Integer sizeLimit;

  // The unique identifier assigned to the entry rebalancing operation.
  @Nullable private final Long rebalancingOperationID;

  // The connection ID of the client connection that performed an operation to
  // trigger the entry rebalancing operation.
  @Nullable private final Long triggeringConnectionID;

  // The operation ID of the operation that triggered the entry rebalancing
  // operation.
  @Nullable private final Long triggeringOperationID;

  // The name of the backend set containing the subtree to move.
  @Nullable private final String sourceBackendSetName;

  // The address and port of the server in the source backend set from which
  // the entries are being migrated.
  @Nullable private final String sourceBackendServer;

  // The base DN of the subtree being moved from one backend set to another.
  @Nullable private final String subtreeBaseDN;

  // The name of the backend set into which the subtree will be migrated.
  @Nullable private final String targetBackendSetName;

  // The address and port of the server of the server in the target backend set
  // into which the entries are being migrated.
  @Nullable private final String targetBackendServer;



  /**
   * Creates a new entry rebalancing request access log message from the
   * provided message string.
   *
   * @param  s  The string to be parsed as an entry rebalancing request access
   *            log message.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        log message.
   */
  public EntryRebalancingRequestAccessLogMessage(@NotNull final String s)
         throws LogException
  {
    this(new LogMessage(s));
  }



  /**
   * Creates a new entry rebalancing request access log message from the
   * provided log message.
   *
   * @param  m  The log message to be parsed as an entry rebalancing request
   *            access log message.
   */
  public EntryRebalancingRequestAccessLogMessage(@NotNull final LogMessage m)
  {
    super(m);

    rebalancingOperationID = getNamedValueAsLong("rebalancingOp");
    sizeLimit              = getNamedValueAsInteger("sizeLimit");
    sourceBackendServer    = getNamedValue("sourceServer");
    sourceBackendSetName   = getNamedValue("sourceBackendSet");
    subtreeBaseDN          = getNamedValue("base");
    targetBackendServer    = getNamedValue("targetServer");
    targetBackendSetName   = getNamedValue("targetBackendSet");
    triggeringConnectionID = getNamedValueAsLong("triggeredByConn");
    triggeringOperationID  = getNamedValueAsLong("triggeredByOp");
  }



  /**
   * Retrieves the unique identifier assigned to the entry rebalancing
   * operation.
   *
   * @return  The unique identifier assigned to the entry rebalancing operation,
   *          or {@code null} if it is not included in the log message.
   */
  @Nullable()
  public final Long getRebalancingOperationID()
  {
    return rebalancingOperationID;
  }



  /**
   * Retrieves the connection ID for the connection that performed an operation
   * to trigger the entry rebalancing operation.
   *
   * @return  Retrieves the connection ID for the connection that performed an
   *          operation to trigger the entry rebalancing operation, or
   *          {@code null} if it is not included in the log message.
   */
  @Nullable()
  public final Long getTriggeringConnectionID()
  {
    return triggeringConnectionID;
  }



  /**
   * Retrieves the operation ID for the operation that triggered the entry
   * rebalancing operation.
   *
   * @return  Retrieves the operation ID for the operation that triggered the
   *          entry rebalancing operation, or {@code null} if it is not included
   *          in the log message.
   */
  @Nullable()
  public final Long getTriggeringOperationID()
  {
    return triggeringOperationID;
  }



  /**
   * Retrieves the base DN of the subtree that will be migrated during the entry
   * rebalancing operation.
   *
   * @return  The base DN of the subtree that will be migrated during the entry
   *          rebalancing operation, or {@code null} if it is not included in
   *          the log message.
   */
  @Nullable()
  public final String getSubtreeBaseDN()
  {
    return subtreeBaseDN;
  }



  /**
   * Retrieves the maximum number of entries that may be contained in the
   * subtree for it to be successfully migrated.
   *
   * @return  The maximum number of entries that may be contained in the subtree
   *          for it to be successfully migrated, or {@code null} if it is not
   *          included in the log message.
   */
  @Nullable()
  public final Integer getSizeLimit()
  {
    return sizeLimit;
  }



  /**
   * Retrieves the name of the backend set containing the subtree to be
   * migrated.
   *
   * @return  The name of the backend set containing the subtree to be migrated,
   *          or {@code null} if it is not included in the log message.
   */
  @Nullable()
  public final String getSourceBackendSetName()
  {
    return sourceBackendSetName;
  }



  /**
   * The address and port of the backend server from which the subtree will be
   * migrated.
   *
   * @return  The address and port of the backend server from which the subtree
   *          will be migrated, or {@code null} if it is not included in the log
   *          message.
   */
  @Nullable()
  public final String getSourceBackendServer()
  {
    return sourceBackendServer;
  }



  /**
   * Retrieves the name of the backend set to which the subtree will be
   * migrated.
   *
   * @return  The name of the backend set ot which the subtree will be migrated,
   *          or {@code null} if it is not included in the log message.
   */
  @Nullable()
  public final String getTargetBackendSetName()
  {
    return targetBackendSetName;
  }



  /**
   * Retrieves the address and port of the backend server to which the subtree
   * will be migrated.
   *
   * @return  The address and port of the backend server to which the subtree
   *          will be migrated, or {@code null} if it is not included in the log
   *          message.
   */
  @Nullable()
  public final String getTargetBackendServer()
  {
    return targetBackendServer;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public AccessLogMessageType getMessageType()
  {
    return AccessLogMessageType.ENTRY_REBALANCING_REQUEST;
  }
}
