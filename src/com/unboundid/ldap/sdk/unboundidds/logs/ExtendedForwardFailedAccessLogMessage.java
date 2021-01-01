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



import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a log
 * message that may appear in the Directory Server access log about an extended
 * request that was forwarded to a backend server but did not complete
 * successfully.
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
public final class ExtendedForwardFailedAccessLogMessage
       extends ExtendedRequestAccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 397038373176791392L;



  // The numeric result code for the failure.
  @Nullable private final Integer resultCode;

  // The port of the backend server to which the request has been forwarded.
  @Nullable private final Integer targetPort;

  // The diagnostic message for the failure.
  @Nullable private final String message;

  // The address of the backend server to which the request has been forwarded.
  @Nullable private final String targetHost;

  // The protocol used to forward the request to the backend server.
  @Nullable private final String targetProtocol;



  /**
   * Creates a new extended forward failed access log message from the provided
   * message string.
   *
   * @param  s  The string to be parsed as an extended forward failed access log
   *            message.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        log message.
   */
  public ExtendedForwardFailedAccessLogMessage(@NotNull final String s)
         throws LogException
  {
    this(new LogMessage(s));
  }



  /**
   * Creates a new extended forward failed access log message from the provided
   * log message.
   *
   * @param  m  The log message to be parsed as an extended forward failed
   *            access log message.
   */
  public ExtendedForwardFailedAccessLogMessage(@NotNull final LogMessage m)
  {
    super(m);

    targetHost     = getNamedValue("targetHost");
    targetPort     = getNamedValueAsInteger("targetPort");
    targetProtocol = getNamedValue("targetProtocol");
    resultCode     = getNamedValueAsInteger("resultCode");
    message        = getNamedValue("message");
  }



  /**
   * Retrieves the address of the backend server to which the request has been
   * forwarded.
   *
   * @return  The address of the backend server to which the request has been
   *          forwarded, or {@code null} if it is not included in the log
   *          message.
   */
  @Nullable()
  public String getTargetHost()
  {
    return targetHost;
  }



  /**
   * Retrieves the port of the backend server to which the request has been
   * forwarded.
   *
   * @return  The port of the backend server to which the request has been
   *          forwarded, or {@code null} if it is not included in the log
   *          message.
   */
  @Nullable()
  public Integer getTargetPort()
  {
    return targetPort;
  }



  /**
   * Retrieves the protocol used to forward the request to the backend server.
   *
   * @return  The protocol used to forward the request to the backend server, or
   *          {@code null} if it is not included in the log message.
   */
  @Nullable()
  public String getTargetProtocol()
  {
    return targetProtocol;
  }



  /**
   * Retrieves the result code received for the forwarded operation.
   *
   * @return  The result code received for the forwarded operation, or
   *          {@code null} if it is not included in the log message.
   */
  @Nullable()
  public Integer getResultCode()
  {
    return resultCode;
  }



  /**
   * Retrieves the diagnostic message received for the forwarded operation.
   *
   * @return  The diagnostic message received for the forwarded operation, or
   *          {@code null} if it is not included in the log message.
   */
  @Nullable()
  public String getDiagnosticMessage()
  {
    return message;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public AccessLogMessageType getMessageType()
  {
    return AccessLogMessageType.FORWARD_FAILED;
  }
}
