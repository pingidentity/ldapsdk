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



import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a log
 * message that may appear in the Directory Server access log about an abandon
 * request received from a client.
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
@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class AbandonRequestAccessLogMessage
       extends OperationRequestAccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4681707907192987394L;



  // The message ID of the operation to abandon.
  private final Integer idToAbandon;



  /**
   * Creates a new abandon request access log message from the provided message
   * string.
   *
   * @param  s  The string to be parsed as an abandon request access log
   *            message.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        log message.
   */
  public AbandonRequestAccessLogMessage(final String s)
         throws LogException
  {
    this(new LogMessage(s));
  }



  /**
   * Creates a new abandon request access log message from the provided log
   * message.
   *
   * @param  m  The log message to be parsed as an abandon request access log
   *            message.
   */
  public AbandonRequestAccessLogMessage(final LogMessage m)
  {
    super(m);

    idToAbandon = getNamedValueAsInteger("idToAbandon");
  }



  /**
   * Retrieves the message ID of the operation that should be abandoned.
   *
   * @return  The message ID of the operation that should be abandoned, or
   *          {@code null} if it is not included in the log message.
   */
  public final Integer getMessageIDToAbandon()
  {
    return idToAbandon;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public final AccessLogOperationType getOperationType()
  {
    return AccessLogOperationType.ABANDON;
  }
}
