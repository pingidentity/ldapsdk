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
 * message that may appear in the Directory Server access log.
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
public abstract class AccessLogMessage
       extends LogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 111497572975341652L;



  // The connection ID for this access log message.
  @Nullable private final Long connectionID;

  // The Directory Server instance name for this access log message.
  @Nullable private final String instanceName;

  // The server product name for this access log message.
  @Nullable private final String productName;

  // The startup ID for this access log message;
  @Nullable private final String startupID;



  /**
   * Creates a new access log message from the provided log message.
   *
   * @param  m  The log message to be parsed as an access log message.
   */
  protected AccessLogMessage(@NotNull final LogMessage m)
  {
    super(m);

    productName  = getNamedValue("product");
    instanceName = getNamedValue("instanceName");
    startupID    = getNamedValue("startupID");
    connectionID = getNamedValueAsLong("conn");
  }



  /**
   * Parses the provided string as an access log message.
   *
   * @param  s  The string to parse as an access log message.
   *
   * @return  The parsed access log message.
   *
   * @throws  LogException  If an error occurs while trying to parse the log
   *                        message.
   */
  @NotNull()
  public static AccessLogMessage parse(@NotNull final String s)
         throws LogException
  {
    return AccessLogReader.parse(s);
  }



  /**
   * Retrieves the server product name for this access log message.
   *
   * @return  The server product name for this access log message, or
   *          {@code null} if it is not included in the log message.
   */
  @Nullable()
  public final String getProductName()
  {
    return productName;
  }



  /**
   * Retrieves the Directory Server instance name for this access log message.
   *
   * @return  The Directory Server instance name for this access log message, or
   *          {@code null} if it is not included in the log message.
   */
  @Nullable()
  public final String getInstanceName()
  {
    return instanceName;
  }



  /**
   * Retrieves the Directory Server startup ID for this access log message.
   *
   * @return  The Directory Server startup ID for this access log message, or
   *          {@code null} if it is not included in the log message.
   */
  @Nullable()
  public final String getStartupID()
  {
    return startupID;
  }



  /**
   * Retrieves the connection ID for the connection with which this access log
   * message is associated.
   *
   * @return  The connection ID for the connection with which this access log
   *          message is associated, or {@code null} if it is not included in
   *          the log message.
   */
  @Nullable
  public final Long getConnectionID()
  {
    return connectionID;
  }



  /**
   * Retrieves the message type for this access log message.
   *
   * @return  The message type for this access log message.
   */
  @NotNull()
  public abstract AccessLogMessageType getMessageType();
}
