/*
 * Copyright 2009-2016 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2016 UnboundID Corp.
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
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Debug.*;



/**
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class is part of the Commercial Edition of the UnboundID
 *   LDAP SDK for Java.  It is not available for use in applications that
 *   include only the Standard Edition of the LDAP SDK, and is not supported for
 *   use in conjunction with non-UnboundID products.
 * </BLOCKQUOTE>
 * This class provides a data structure that holds information about a log
 * message that may appear in the Directory Server error log.
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
  private final ErrorLogCategory category;

  // The name of the severity for this error log message.
  private final ErrorLogSeverity severity;

  // The message ID for this error log message.
  private final Long messageID;

  // The Directory Server instance name for this error log message.
  private final String instanceName;

  // The message string for this error log message.
  private final String message;

  // The product name for this error log message.
  private final String productName;

  // The startup ID for this error log message;
  private final String startupID;



  /**
   * Creates a new error log message from the provided message string.
   *
   * @param  s  The string to be parsed as an error log message.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        log message.
   */
  public ErrorLogMessage(final String s)
         throws LogException
  {
    this(new LogMessage(s));
  }



  /**
   * Creates a new error log message from the provided message string.
   *
   * @param  m  The log message to be parsed as an error log message.
   */
  public ErrorLogMessage(final LogMessage m)
  {
    super(m);

    productName  = getNamedValue("product");
    instanceName = getNamedValue("instanceName");
    startupID    = getNamedValue("startupID");
    messageID    = getNamedValueAsLong("msgID");
    message      = getNamedValue("msg");

    ErrorLogCategory cat = null;
    try
    {
      cat = ErrorLogCategory.valueOf(getNamedValue("category"));
    }
    catch (Exception e)
    {
      debugException(e);
    }
    category = cat;

    ErrorLogSeverity sev = null;
    try
    {
      sev = ErrorLogSeverity.valueOf(getNamedValue("severity"));
    }
    catch (Exception e)
    {
      debugException(e);
    }
    severity = sev;
  }



  /**
   * Retrieves the server product name for this error log message.
   *
   * @return  The server product name for this error log message, or
   *          {@code null} if it is not included in the log message.
   */
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
  public Long getMessageID()
  {
    return messageID;
  }



  /**
   * Retrieves the message text for this error log message.
   *
   * @return  The message text for this error log message, or {@code null} if it
   *          is not included in the log message.
   */
  public String getMessage()
  {
    return message;
  }
}
