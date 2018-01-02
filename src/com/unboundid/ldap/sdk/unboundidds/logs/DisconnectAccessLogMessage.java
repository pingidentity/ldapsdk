/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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



/**
 * This class provides a data structure that holds information about a log
 * message that may appear in the Directory Server access log about a
 * connection that has been closed.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DisconnectAccessLogMessage
       extends AccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6224280874144845557L;



  // The message providing additional information about the disconnect.
  private final String message;

  // The reason for the disconnect.
  private final String reason;



  /**
   * Creates a new disconnect access log message from the provided message
   * string.
   *
   * @param  s  The string to be parsed as a disconnect access log message.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        log message.
   */
  public DisconnectAccessLogMessage(final String s)
         throws LogException
  {
    this(new LogMessage(s));
  }



  /**
   * Creates a new disconnect access log message from the provided log message.
   *
   * @param  m  The log message to be parsed as a disconnect access log message.
   */
  public DisconnectAccessLogMessage(final LogMessage m)
  {
    super(m);

    reason  = getNamedValue("reason");
    message = getNamedValue("msg");
  }



  /**
   * Retrieves the disconnect reason for the log message.
   *
   * @return  The disconnect reason for the log message, or {@code null} if it
   *          is not included in the log message.
   */
  public String getDisconnectReason()
  {
    return reason;
  }



  /**
   * Retrieves a message with additional information about the disconnect.
   *
   * @return  A message with additional information about the disconnect, or
   *          {@code null} if it is not included in the log message.
   */
  public String getMessage()
  {
    return message;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public AccessLogMessageType getMessageType()
  {
    return AccessLogMessageType.DISCONNECT;
  }
}
