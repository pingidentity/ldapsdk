/*
 * Copyright 2022-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2024 Ping Identity Corporation
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
 * Copyright (C) 2022-2024 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.unboundidds.logs.v2.ConnectAccessLogMessage;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a data structure that holds information about a
 * JSON-formatted connect access log message.
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
public final class JSONConnectAccessLogMessage
       extends JSONAccessLogMessage
       implements ConnectAccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2405380746589337636L;



  // The source port for this log message.
  @Nullable private final Integer sourcePort;

  // The target port for this log message.
  @Nullable private final Integer targetPort;

  // The client connection policy name for this log message.
  @Nullable private final String clientConnectionPolicyName;

  // The protocol name for this log message.
  @Nullable private final String protocolName;

  // The source address for this log message.
  @Nullable private final String sourceAddress;

  // The target address for this log message.
  @Nullable private final String targetAddress;



  /**
   * Creates a new JSON connect access log message from the provided JSON
   * object.
   *
   * @param  jsonObject  The JSON object that contains an encoded representation
   *                     of this log message.  It must not be {@code null}.
   *
   * @throws  LogException  If the provided JSON object cannot be parsed as a
   *                        valid log message.
   */
  public JSONConnectAccessLogMessage(@NotNull final JSONObject jsonObject)
         throws LogException
  {
    super(jsonObject);

    sourceAddress =
         getString(JSONFormattedAccessLogFields.CONNECT_FROM_ADDRESS);
    sourcePort =
         getIntegerNoThrow(JSONFormattedAccessLogFields.CONNECT_FROM_PORT);
    targetAddress =
         getString(JSONFormattedAccessLogFields.CONNECT_TO_ADDRESS);
    targetPort =
         getIntegerNoThrow(JSONFormattedAccessLogFields.CONNECT_TO_PORT);
    protocolName = getString(JSONFormattedAccessLogFields.PROTOCOL);
    clientConnectionPolicyName =
         getString(JSONFormattedAccessLogFields.CLIENT_CONNECTION_POLICY);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public AccessLogMessageType getMessageType()
  {
    return AccessLogMessageType.CONNECT;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public String getSourceAddress()
  {
    return sourceAddress;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Integer getSourcePort()
  {
    return sourcePort;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public String getTargetAddress()
  {
    return targetAddress;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Integer getTargetPort()
  {
    return targetPort;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public String getProtocolName()
  {
    return protocolName;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public String getClientConnectionPolicy()
  {
    return clientConnectionPolicyName;
  }
}
