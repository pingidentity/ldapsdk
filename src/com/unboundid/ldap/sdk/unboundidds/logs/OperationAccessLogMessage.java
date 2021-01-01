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
package com.unboundid.ldap.sdk.unboundidds.logs;



import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a log
 * message that may appear in the Directory Server access log about an
 * operation processed by the server.
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
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public abstract class OperationAccessLogMessage
       extends AccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5311424730889643655L;



  // The message ID for this access log message.
  @Nullable private final Integer messageID;

  // The operation ID for this access log message.
  @Nullable private final Long operationID;

  // The connection ID for the operation that triggered the associated
  // operation.
  @Nullable private final Long triggeredByConnectionID;

  // The operation ID for the operation that triggered the associated operation.
  @Nullable private final Long triggeredByOperationID;

  // The message origin for this access log message.
  @Nullable private final String origin;



  /**
   * Creates a new operation access log message from the provided log message.
   *
   * @param  m  The log message to be parsed as an operation access log message.
   */
  protected OperationAccessLogMessage(@NotNull final LogMessage m)
  {
    super(m);

    messageID               = getNamedValueAsInteger("msgID");
    operationID             = getNamedValueAsLong("op");
    triggeredByConnectionID = getNamedValueAsLong("triggeredByConn");
    triggeredByOperationID  = getNamedValueAsLong("triggeredByOp");
    origin                  = getNamedValue("origin");
  }



  /**
   * Retrieves the operation ID for the associated operation.
   *
   * @return  The operation ID for the associated operation, or {@code null} if
   *          it is not included in the log message.
   */
  @Nullable()
  public final Long getOperationID()
  {
    return operationID;
  }



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
  public final Long getTriggeredByConnectionID()
  {
    return triggeredByConnectionID;
  }



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
  public final Long getTriggeredByOperationID()
  {
    return triggeredByOperationID;
  }



  /**
   * Retrieves the message ID for the associated operation.
   *
   * @return  The message ID for the associated operation, or {@code null} if
   *          it is not included in the log message.
   */
  @Nullable()
  public final Integer getMessageID()
  {
    return messageID;
  }



  /**
   * Retrieves the origin of the associated operation.  If present, it may be
   * "synchronization" if the operation is replicated, or "internal" if it is an
   * internal operation.
   *
   * @return  The origin for the associated operation, or {@code null} if it is
   *          not included in the log message.
   */
  @Nullable()
  public final String getOrigin()
  {
    return origin;
  }



  /**
   * Retrieves the operation type for the associated operation.
   *
   * @return  The operation type for this access log message.
   */
  @NotNull()
  public abstract AccessLogOperationType getOperationType();
}
