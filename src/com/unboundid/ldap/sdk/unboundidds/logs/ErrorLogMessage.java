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



import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a log
 * message that may appear in the Directory Server error log.
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
public final class ErrorLogMessage
       extends LogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1743586990943392442L;



  // The name of the category for this error log message.
  @Nullable private final ErrorLogCategory category;

  // The name of the severity for this error log message.
  @Nullable private final ErrorLogSeverity severity;

  // The message ID for this error log message.
  @Nullable private final Long messageID;

  // The connection ID for the operation currently being processed by the thread
  // that generated this error log message.
  @Nullable private final Long triggeredByConnectionID;

  // The operation ID for the operation currently being processed by the thread
  // that generated this error log message.
  @Nullable private final Long triggeredByOperationID;

  // The Directory Server instance name for this error log message.
  @Nullable private final String instanceName;

  // The message string for this error log message.
  @Nullable private final String message;

  // The product name for this error log message.
  @Nullable private final String productName;

  // The startup ID for this error log message;
  @Nullable private final String startupID;



  /**
   * Creates a new error log message from the provided message string.
   *
   * @param  s  The string to be parsed as an error log message.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        log message.
   */
  public ErrorLogMessage(@NotNull final String s)
         throws LogException
  {
    this(new LogMessage(s));
  }



  /**
   * Creates a new error log message from the provided message string.
   *
   * @param  m  The log message to be parsed as an error log message.
   */
  public ErrorLogMessage(@NotNull final LogMessage m)
  {
    super(m);

    productName             = getNamedValue("product");
    instanceName            = getNamedValue("instanceName");
    startupID               = getNamedValue("startupID");
    messageID               = getNamedValueAsLong("msgID");
    message                 = getNamedValue("msg");
    triggeredByConnectionID = getNamedValueAsLong("triggeredByConn");
    triggeredByOperationID  = getNamedValueAsLong("triggeredByOp");

    ErrorLogCategory cat = null;
    try
    {
      cat = ErrorLogCategory.valueOf(getNamedValue("category"));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }
    category = cat;

    ErrorLogSeverity sev = null;
    try
    {
      sev = ErrorLogSeverity.valueOf(getNamedValue("severity"));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }
    severity = sev;
  }



  /**
   * Retrieves the server product name for this error log message.
   *
   * @return  The server product name for this error log message, or
   *          {@code null} if it is not included in the log message.
   */
  @Nullable()
  public String getProductName()
  {
    return productName;
  }



  /**
   * Retrieves the Directory Server instance name for this error log message.
   *
   * @return  The Directory Server instance name for this error log message, or
   *          {@code null} if it is not included in the log message.
   */
  @Nullable()
  public String getInstanceName()
  {
    return instanceName;
  }



  /**
   * Retrieves the Directory Server startup ID for this error log message.
   *
   * @return  The Directory Server startup ID for this error log message, or
   *          {@code null} if it is not included in the log message.
   */
  @Nullable()
  public String getStartupID()
  {
    return startupID;
  }



  /**
   * Retrieves the category for this error log message.
   *
   * @return  The category for this error log message, or {@code null} if it is
   *          not included in the log message.
   */
  @Nullable()
  public ErrorLogCategory getCategory()
  {
    return category;
  }



  /**
   * Retrieves the severity for this error log message.
   *
   * @return  The severity for this error log message, or {@code null} if it is
   *          not included in the log message.
   */
  @Nullable()
  public ErrorLogSeverity getSeverity()
  {
    return severity;
  }



  /**
   * Retrieves the numeric identifier for this error log message.
   *
   * @return  The numeric identifier for this error log message, or {@code null}
   *          if it is not included in the log message.
   */
  @Nullable()
  public Long getMessageID()
  {
    return messageID;
  }



  /**
   * Retrieves the connection ID for the operation currently being processed by
   * the thread that generated this error log message.
   *
   * @return  The connection ID for the operation currently being processed by
   *          the thread that generated this error log message, or {@code null}
   *          if it is not included in the log message.
   */
  @Nullable()
  public Long getTriggeredByConnectionID()
  {
    return triggeredByConnectionID;
  }



  /**
   * Retrieves the operation ID for the operation currently being processed by
   * the thread that generated this error log message.
   *
   * @return  The operation ID for the operation currently being processed by
   *          the thread that generated this error log message, or {@code null}
   *          if it is not included in the log message.
   */
  @Nullable()
  public Long getTriggeredByOperationID()
  {
    return triggeredByOperationID;
  }



  /**
   * Retrieves the message text for this error log message.
   *
   * @return  The message text for this error log message, or {@code null} if it
   *          is not included in the log message.
   */
  @Nullable()
  public String getMessage()
  {
    return message;
  }
}
