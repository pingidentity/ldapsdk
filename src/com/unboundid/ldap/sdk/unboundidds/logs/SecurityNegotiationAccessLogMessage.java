/*
 * Copyright 2012-2018 Ping Identity Corporation
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
 * message that may appear in the Directory Server access log about a form of
 * security negotiation performed on a client connection.
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
public final class SecurityNegotiationAccessLogMessage
       extends AccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8588250275523891216L;



  // The negotiated cipher suite.
  private final String cipher;

  // The negotiated protocol.
  private final String protocol;



  /**
   * Creates a new security negotiation access log message from the provided
   * message string.
   *
   * @param  s  The string to be parsed as a security negotiation access log
   *            message.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        log message.
   */
  public SecurityNegotiationAccessLogMessage(final String s)
         throws LogException
  {
    this(new LogMessage(s));
  }



  /**
   * Creates a new security negotiation log message from the provided log
   * message.
   *
   * @param  m  The log message to be parsed as a connect access log message.
   */
  public SecurityNegotiationAccessLogMessage(final LogMessage m)
  {
    super(m);

    protocol = getNamedValue("protocol");
    cipher   = getNamedValue("cipher");
  }



  /**
   * Retrieves the name of the security protocol that was negotiated.
   *
   * @return  The name of the security protocol that was negotiated.
   */
  public String getProtocol()
  {
    return protocol;
  }



  /**
   * Retrieves the name of the cipher suite that was negotiated.
   *
   * @return  The name of the cipher suite that was negotiated.
   */
  public String getCipher()
  {
    return cipher;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public AccessLogMessageType getMessageType()
  {
    return AccessLogMessageType.SECURITY_NEGOTIATION;
  }
}
