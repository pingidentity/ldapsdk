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



import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;

import com.unboundid.util.NotExtensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a log
 * message that may appear in the Directory Server access log about an
 * operation request received from a client.
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
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public abstract class OperationRequestAccessLogMessage
       extends OperationAccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8942685623238040482L;



  // Indicates whether the request is being processed using a worker thread from
  // the dedicated administrative session pool.
  private final Boolean usingAdminSessionWorkerThread;

  // The OIDs of the request controls contained in the request.
  private final List<String> requestControlOIDs;

  // Information from the intermediate client request control contained in the
  // request.
  private final String intermediateClientRequest;

  // Information from the operation purpose control contained in the request.
  private final String operationPurpose;

  // The DN of the user that requested the message.
  private final String requesterDN;

  // The IP address of the client that requested the message.
  private final String requesterIP;



  /**
   * Creates a new operation request access log message from the provided log
   * message.
   *
   * @param  m  The log message to be parsed as an operation request access log
   *            message.
   */
  protected OperationRequestAccessLogMessage(final LogMessage m)
  {
    super(m);

    intermediateClientRequest = getNamedValue("via");
    operationPurpose          = getNamedValue("opPurpose");
    requesterDN               = getNamedValue("requesterDN");
    requesterIP               = getNamedValue("requesterIP");

    usingAdminSessionWorkerThread =
         getNamedValueAsBoolean("usingAdminSessionWorkerThread");

    final String controlStr = getNamedValue("requestControls");
    if (controlStr == null)
    {
      requestControlOIDs = Collections.emptyList();
    }
    else
    {
      final LinkedList<String> controlList = new LinkedList<String>();
      final StringTokenizer t = new StringTokenizer(controlStr, ",");
      while (t.hasMoreTokens())
      {
        controlList.add(t.nextToken());
      }
      requestControlOIDs = Collections.unmodifiableList(controlList);
    }
  }



  /**
   * Retrieves the DN of the user that requested the operation.
   *
   * @return  The DN of the user that requested the operation, or {@code null}
   *          if it is not included in the log message.
   */
  public final String getRequesterDN()
  {
    return requesterDN;
  }



  /**
   * Retrieves the IP address of the client that requested the operation.
   *
   * @return  The IP address of the client that requested the operation, or
   *          {@code null} if it is not included in the log message.
   */
  public final String getRequesterIPAddress()
  {
    return requesterIP;
  }



  /**
   * Retrieves the content of any intermediate client request control contained
   * in the request.
   *
   * @return  The content of any intermediate client request control contained
   *          in the request, or {@code null} if it is not included in the log
   *          message.
   */
  public final String getIntermediateClientRequest()
  {
    return intermediateClientRequest;
  }



  /**
   * Retrieves the content of any operation purpose request control contained in
   * the request.
   *
   * @return  The content of any operation purpose request control included in
   *          the request, or {@code null} if it is not included in the log
   *          message.
   */
  public final String getOperationPurpose()
  {
    return operationPurpose;
  }



  /**
   * Retrieves the OIDs of any request controls contained in the log message.
   *
   * @return  The OIDs of any request controls contained in the log message, or
   *          an empty list if it is not included in the log message.
   */
  public final List<String> getRequestControlOIDs()
  {
    return requestControlOIDs;
  }



  /**
   * Indicates whether the operation was processed using a worker thread from
   * the dedicated administrative session thread pool.
   *
   * @return  {@code true} if the operation was processed using a worker thread
   *          from the dedicated administrative session thread pool,
   *          {@code false} if it was not, or {@code null} if that information
   *          was not included in the log message.
   */
  public final Boolean usingAdminSessionWorkerThread()
  {
    return usingAdminSessionWorkerThread;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public AccessLogMessageType getMessageType()
  {
    return AccessLogMessageType.REQUEST;
  }
}
