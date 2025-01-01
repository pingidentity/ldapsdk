/*
 * Copyright 2022-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2025 Ping Identity Corporation
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
 * Copyright (C) 2022-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.json;



import java.util.Set;

import com.unboundid.ldap.sdk.unboundidds.logs.AccessLogMessageType;
import com.unboundid.ldap.sdk.unboundidds.logs.LogException;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.
            OperationRequestAccessLogMessage;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a data structure that holds information about a
 * JSON-formatted operation request access log message.
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
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class JSONRequestAccessLogMessage
       extends JSONAccessLogMessage
       implements OperationRequestAccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8154114903633681042L;



  // Indicates whether the operation was processed using an admin session
  // worker thread.
  @Nullable private final Boolean usingAdminSessionWorkerThread;

  // The message ID for this log message.
  @Nullable private final Integer messageID;

  // The intermediate client request control for this log message.
  @Nullable private final JSONIntermediateClientRequestControl
       intermediateClientRequestControl;

  // The operation purpose request control for this log message.
  @Nullable private final JSONOperationPurposeRequestControl
       operationPurposeRequestControl;

  // The operation ID for this log message.
  @Nullable private final Long operationID;

  // The triggered by connection ID for this log message.
  @Nullable private final Long triggeredByConnectionID;

  // The triggered by operation ID for this log message.
  @Nullable private final Long triggeredByOperationID;

  // The request control OIDs for this log message.
  @NotNull private final Set<String> requestControlOIDs;

  // The administrative operation message for this log message.
  @Nullable private final String administrativeOperationMessage;

  // The origin for this log message.
  @Nullable private final String origin;

  // The requester DN for this log message.
  @Nullable private final String requesterDN;

  // The requester IP address for this log message.
  @Nullable private final String requesterIPAddress;



  /**
   * Creates a new JSON request access log message from the provided JSON
   * object.
   *
   * @param  jsonObject  The JSON object that contains an encoded representation
   *                     of this log message.  It must not be {@code null}.
   *
   * @throws  LogException  If the provided JSON object cannot be parsed as a
   *                        valid log message.
   */
  protected JSONRequestAccessLogMessage(@NotNull final JSONObject jsonObject)
            throws LogException
  {
    super(jsonObject);

    operationID = getLongNoThrow(JSONFormattedAccessLogFields.OPERATION_ID);
    messageID = getIntegerNoThrow(JSONFormattedAccessLogFields.MESSAGE_ID);
    origin = getString(JSONFormattedAccessLogFields.ORIGIN);
    triggeredByConnectionID = getLongNoThrow(
         JSONFormattedAccessLogFields.TRIGGERED_BY_CONNECTION_ID);
    triggeredByOperationID = getLongNoThrow(
         JSONFormattedAccessLogFields.TRIGGERED_BY_OPERATION_ID);
    requesterDN = getString(JSONFormattedAccessLogFields.REQUESTER_DN);
    requesterIPAddress = getString(
         JSONFormattedAccessLogFields.REQUESTER_IP_ADDRESS);
    usingAdminSessionWorkerThread = getBooleanNoThrow(
         JSONFormattedAccessLogFields.USING_ADMIN_SESSION_WORKER_THREAD);
    administrativeOperationMessage = getString(
         JSONFormattedAccessLogFields.ADMINISTRATIVE_OPERATION);
    requestControlOIDs = getStringSet(
         JSONFormattedAccessLogFields.REQUEST_CONTROL_OIDS);

    final JSONObject intermediateClientRequestObject =
         jsonObject.getFieldAsObject(
              JSONFormattedAccessLogFields.INTERMEDIATE_CLIENT_REQUEST_CONTROL.
                   getFieldName());
    if (intermediateClientRequestObject == null)
    {
      intermediateClientRequestControl = null;
    }
    else
    {
      intermediateClientRequestControl =
           new JSONIntermediateClientRequestControl(
                intermediateClientRequestObject);
    }

    final JSONObject operationPurposeRequestObject =
         jsonObject.getFieldAsObject(
              JSONFormattedAccessLogFields.OPERATION_PURPOSE.getFieldName());
    if (operationPurposeRequestObject == null)
    {
      operationPurposeRequestControl = null;
    }
    else
    {
      operationPurposeRequestControl = new JSONOperationPurposeRequestControl(
           operationPurposeRequestObject);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public AccessLogMessageType getMessageType()
  {
    return AccessLogMessageType.REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Long getOperationID()
  {
    return operationID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Integer getMessageID()
  {
    return messageID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getOrigin()
  {
    return origin;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Long getTriggeredByConnectionID()
  {
    return triggeredByConnectionID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Long getTriggeredByOperationID()
  {
    return triggeredByOperationID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getRequesterDN()
  {
    return requesterDN;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getRequesterIPAddress()
  {
    return requesterIPAddress;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public final Set<String> getRequestControlOIDs()
  {
    return requestControlOIDs;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Boolean getUsingAdminSessionWorkerThread()
  {
    return usingAdminSessionWorkerThread;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getAdministrativeOperationMessage()
  {
    return administrativeOperationMessage;
  }



  /**
   * Retrieves information about an intermediate client request control included
   * in the log message.
   *
   * @return  An intermediate client request control included in the log
   *          message, or {@code null} if no intermediate client request control
   *          is available.
   */
  @Nullable()
  public final JSONIntermediateClientRequestControl
                    getIntermediateClientRequestControl()
  {
    return intermediateClientRequestControl;
  }



  /**
   * Retrieves information about an operation purpose request control included
   * in the log message.
   *
   * @return  An operation purpose request control included in the log message,
   *          or {@code null} if no operation purpose request control is
   *          available.
   */
  @Nullable()
  public final JSONOperationPurposeRequestControl
                    getOperationPurposeRequestControl()
  {
    return operationPurposeRequestControl;
  }
}
