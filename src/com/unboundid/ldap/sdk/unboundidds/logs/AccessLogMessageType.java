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



import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines the set of access log message types.
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
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum AccessLogMessageType
{
  /**
   * The message type that will be used for messages about the result of
   * replication assurance processing.
   */
  ASSURANCE_COMPLETE("ASSURANCE-COMPLETE"),



  /**
   * The message type that will be used for messages about connections
   * established to the Directory Server.
   */
  CLIENT_CERTIFICATE("CLIENT-CERTIFICATE"),



  /**
   * The message type that will be used for messages about connections
   * established to the Directory Server.
   */
  CONNECT("CONNECT"),



  /**
   * The message type that will be used for messages about connections
   * disconnected from the Directory Server.
   */
  DISCONNECT("DISCONNECT"),



  /**
   * The message type that will be used for messages about search result entries
   * returned by the Directory Server.
   */
  ENTRY("ENTRY"),



  /**
   * The message type that will be used for messages that provide information
   * about the beginning of an entry-rebalancing operation.
   */
  ENTRY_REBALANCING_REQUEST("ENTRY-REBALANCING-REQUEST"),



  /**
   * The message type that will be used for messages that provide information
   * about the result of an entry-rebalancing operation.
   */
  ENTRY_REBALANCING_RESULT("ENTRY-REBALANCING-RESULT"),



  /**
   * The message type that will be used for messages about operations forwarded
   * to another server.
   */
  FORWARD("FORWARD"),



  /**
   * The message type that will be used for messages about failed attempts to
   * forward a request to another server.
   */
  FORWARD_FAILED("FORWARD-FAILED"),



  /**
   * The message type that will be used for intermediate response messages.
   */
  INTERMEDIATE_RESPONSE("INTERMEDIATE-RESPONSE"),



  /**
   * The message type that will be used for messages about search result
   * references returned by the Directory Server.
   */
  REFERENCE("REFERENCE"),



  /**
   * The message type that will be used for messages about operation requests
   * received from the Directory Server.
   */
  REQUEST("REQUEST"),



  /**
   * The message type that will be used for messages about operation results,
   * which may include responses sent to clients or results for operations with
   * no response.
   */
  RESULT("RESULT"),



  /**
   * The message type that will be used for messages about the processing
   * performed to negotiate a secure form of communication between the client
   * and the server.
   */
  SECURITY_NEGOTIATION("SECURITY-NEGOTIATION");



  // The string that will be used to identify this message type in log files.
  private final String logIdentifier;



  /**
   * Creates a new access log message type with the provided information.
   *
   * @param  logIdentifier  The string that will be used to identify this
   *                        message type in log files.
   */
  AccessLogMessageType(final String logIdentifier)
  {
    this.logIdentifier = logIdentifier;
  }



  /**
   * Retrieves the string that will be used to identify this message type in
   * log files.
   *
   * @return  The string that will be used to identify this message type in log
   *          files.
   */
  public String getLogIdentifier()
  {
    return logIdentifier;
  }



  /**
   * Retrieves the access log message type with the provided identifier.
   *
   * @param  logIdentifier  The identifier string for which to retrieve the
   *                        corresponding access log message type.
   *
   * @return  The appropriate message type, or {@code null} if there is no
   *          message type associated with the provided identifier.
   */
  public static AccessLogMessageType forName(final String logIdentifier)
  {
    for (final AccessLogMessageType t : values())
    {
      if (t.getLogIdentifier().equals(logIdentifier))
      {
        return t;
      }
    }

    return null;
  }
}
