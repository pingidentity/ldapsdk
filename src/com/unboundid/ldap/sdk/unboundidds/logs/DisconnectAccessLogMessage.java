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



/**
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class is part of the Commercial Edition of the UnboundID
 *   LDAP SDK for Java.  It is not available for use in applications that
 *   include only the Standard Edition of the LDAP SDK, and is not supported for
 *   use in conjunction with non-UnboundID products.
 * </BLOCKQUOTE>
 * This class provides a data structure that holds information about a log
 * message that may appear in the Directory Server access log about a
 * connection that has been closed.
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
