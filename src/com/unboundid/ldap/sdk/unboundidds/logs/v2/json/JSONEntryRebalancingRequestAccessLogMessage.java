/*
 * Copyright 2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022 Ping Identity Corporation
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
 * Copyright (C) 2022 Ping Identity Corporation
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



import com.unboundid.ldap.sdk.unboundidds.logs.AccessLogMessageType;
import com.unboundid.ldap.sdk.unboundidds.logs.LogException;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.
            EntryRebalancingRequestAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.LogField;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a data structure that holds information about a
 * JSON-formatted entry rebalancing request access log message.
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
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class JSONEntryRebalancingRequestAccessLogMessage
       extends JSONAccessLogMessage
       implements EntryRebalancingRequestAccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 144849488576686304L;



  // The size limit for this log message.
  @Nullable private final Integer sizeLimit;

  // The rebalancing operation ID for this log message.
  @Nullable private final Long rebalancingOperationID;

  // The triggered by connection ID for this log message.
  @Nullable private final Long triggeredByConnectionID;

  // The triggered by operation ID for this log message.
  @Nullable private final Long triggeredByOperationID;

  // The source backend server for this log message.
  @Nullable private final String sourceBackendServer;

  // The source backend set name for this log message.
  @Nullable private final String sourceBackendSetName;

  // The subtree base DN for this log message.
  @Nullable private final String subtreeBaseDN;

  // The target backend server for this log message.
  @Nullable private final String targetBackendServer;

  // The target backend set name for this log message.
  @Nullable private final String targetBackendSetName;



  /**
   * Creates a new JSON entry rebalancing request access log message from the
   * provided JSON object.
   *
   * @param  jsonObject  The JSON object that contains an encoded representation
   *                     of this log message.  It must not be {@code null}.
   *
   * @throws  LogException  If the provided JSON object cannot be parsed as a
   *                        valid log message.
   */
  public JSONEntryRebalancingRequestAccessLogMessage(
              @NotNull final JSONObject jsonObject)
         throws LogException
  {
    super(jsonObject);

    rebalancingOperationID = getLongNoThrow(
         JSONFormattedAccessLogFields.ENTRY_REBALANCING_OPERATION_ID);
    triggeredByConnectionID = getLongNoThrow(
         JSONFormattedAccessLogFields.TRIGGERED_BY_CONNECTION_ID);
    triggeredByOperationID = getLongNoThrow(
         JSONFormattedAccessLogFields.TRIGGERED_BY_OPERATION_ID);
    subtreeBaseDN = getString(
         JSONFormattedAccessLogFields.ENTRY_REBALANCING_BASE_DN);
    sizeLimit = getIntegerNoThrow(
         JSONFormattedAccessLogFields.ENTRY_REBALANCING_SIZE_LIMIT);
    sourceBackendSetName = getString(
         JSONFormattedAccessLogFields.ENTRY_REBALANCING_SOURCE_BACKEND_SET);
    sourceBackendServer = getBackendServer(jsonObject,
         JSONFormattedAccessLogFields.ENTRY_REBALANCING_SOURCE_SERVER);
    targetBackendSetName = getString(
         JSONFormattedAccessLogFields.ENTRY_REBALANCING_TARGET_BACKEND_SET);
    targetBackendServer = getBackendServer(jsonObject,
         JSONFormattedAccessLogFields.ENTRY_REBALANCING_TARGET_SERVER);
  }



  /**
   * Retrieves a string representation of the backend server indicated by the
   * specified field in the given JSON object.
   *
   * @param  jsonObject  The JSON object that contains an encoded representation
   *                     of this log message.  It must not be {@code null}.
   * @param  logField    The log field from which to obtain the information
   *                     about the backend server.
   *
   * @return  A string representation of the backend server indicated by the
   *          specified field in the given JSON object, or {@code null} if it is
   *          not included in the log message.
   */
  @Nullable()
  private static String getBackendServer(@NotNull final JSONObject jsonObject,
                                         @NotNull final LogField logField)
  {
    final JSONObject serverObject =
         jsonObject.getFieldAsObject(logField.getFieldName());
    if (serverObject == null)
    {
      return null;
    }

    final String address = serverObject.getFieldAsString(
         JSONFormattedAccessLogFields.ENTRY_REBALANCING_SOURCE_SERVER_ADDRESS.
              getFieldName());
    if (address == null)
    {
      return null;
    }

    final Integer port = serverObject.getFieldAsInteger(
         JSONFormattedAccessLogFields.ENTRY_REBALANCING_SOURCE_SERVER_PORT.
              getFieldName());
    if (port == null)
    {
      return address;
    }
    else
    {
      return address + ':' + port;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public AccessLogMessageType getMessageType()
  {
    return AccessLogMessageType.ENTRY_REBALANCING_REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Long getRebalancingOperationID()
  {
    return rebalancingOperationID;
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
  public final String getSubtreeBaseDN()
  {
    return subtreeBaseDN;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Integer getSizeLimit()
  {
    return sizeLimit;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getSourceBackendSetName()
  {
    return sourceBackendSetName;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getSourceBackendServer()
  {
    return sourceBackendServer;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getTargetBackendSetName()
  {
    return targetBackendSetName;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getTargetBackendServer()
  {
    return targetBackendServer;
  }
}
