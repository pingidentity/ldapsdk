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



import java.io.Serializable;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONObject;

import static com.unboundid.ldap.sdk.unboundidds.logs.v2.json.
                   JSONFormattedAccessLogFields.*;



/**
 * This class provides a data structure that contains information about an
 * JSON-formatted intermediate client response control.
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
public final class JSONIntermediateClientResponseControl
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3708412493324053872L;



  // Indicates whether communication with an upstream server is secure.
  @Nullable private final Boolean upstreamServerSecure;

  // An upstream response embedded in the control.
  @Nullable private final JSONIntermediateClientResponseControl
       upstreamResponse;

  // The JSON object with an encoded representation of this control.
  @NotNull private final JSONObject controlObject;

  // The name of the server application.
  @Nullable private final String serverName;

  // The upstream server address.
  @Nullable private final String upstreamServerAddress;

  // The response ID assigned by the upstream server.
  @Nullable private final String responseID;

  // The session ID assigned by the upstream server.
  @Nullable private final String sessionID;



  /**
   * Creates a new JSON intermediate client response control that is decoded
   * from the provided JSON object.
   *
   * @param  controlObject  The JSON object containing an encoded representation
   *                        of this intermediate client response control.
   */
  public JSONIntermediateClientResponseControl(
              @NotNull final JSONObject controlObject)
  {
    this.controlObject = controlObject;

    upstreamServerAddress = controlObject.getFieldAsString(
         INTERMEDIATE_CLIENT_RESPONSE_CONTROL_UPSTREAM_SERVER_ADDRESS.
              getFieldName());
    upstreamServerSecure = controlObject.getFieldAsBoolean(
         INTERMEDIATE_CLIENT_RESPONSE_CONTROL_UPSTREAM_SERVER_SECURE.
              getFieldName());
    serverName = controlObject.getFieldAsString(
         INTERMEDIATE_CLIENT_RESPONSE_CONTROL_SERVER_NAME.getFieldName());
    sessionID = controlObject.getFieldAsString(
         INTERMEDIATE_CLIENT_RESPONSE_CONTROL_SESSION_ID.getFieldName());
    responseID = controlObject.getFieldAsString(
         INTERMEDIATE_CLIENT_RESPONSE_CONTROL_RESPONSE_ID.getFieldName());

    final JSONObject upstreamObject = controlObject.getFieldAsObject(
         INTERMEDIATE_CLIENT_RESPONSE_CONTROL_UPSTREAM_RESPONSE.getFieldName());
    if (upstreamObject == null)
    {
      upstreamResponse = null;
    }
    else
    {
      upstreamResponse =
           new JSONIntermediateClientResponseControl(upstreamObject);
    }
  }



  /**
   * Retrieves a JSON object containing an encoded representation of this
   * intermediate client response control.
   *
   * @return  A JSON object containing an encoded representation of this
   *          intermediate client response control.
   */
  @NotNull()
  public JSONObject getControlObject()
  {
    return controlObject;
  }



  /**
   * Retrieves the address of an upstream server.
   *
   * @return  The address of an upstream server, or {@code null} if no upstream
   *          server address is available.
   */
  @Nullable()
  public String getUpstreamServerAddress()
  {
    return upstreamServerAddress;
  }



  /**
   * Indicates whether communication with the upstream server is secure.
   *
   * @return  {@code Boolean.TRUE} if communication with the upstream server is
   *          secure, {@code Boolean.FALSE} if communication with the upstream
   *          server is not secure, or {@code null} if this information is not
   *          available.
   */
  @Nullable()
  public Boolean getUpstreamServerSecure()
  {
    return upstreamServerSecure;
  }



  /**
   * Retrieves the name of the upstream server application.
   *
   * @return  The name of the upstream server application, or {@code null} if
   *          this information is not available.
   */
  @Nullable()
  public String getServerName()
  {
    return serverName;
  }



  /**
   * Retrieves the session ID assigned by the upstream server.
   *
   * @return  The session ID assigned by the upstream server, or {@code null}
   *          if no session ID is available.
   */
  @Nullable()
  public String getSessionID()
  {
    return sessionID;
  }



  /**
   * Retrieves the response ID assigned by the upstream server.
   *
   * @return  The response ID assigned by the upstream server, or {@code null}
   *          if no response ID is available.
   */
  @Nullable()
  public String getResponseID()
  {
    return responseID;
  }



  /**
   * Retrieves an upstream response embedded in the control.
   *
   * @return  An upstream response embedded in the control, or {@code null} if
   *          no upstream response is available.
   */
  @Nullable()
  public JSONIntermediateClientResponseControl getUpstreamResponse()
  {
    return upstreamResponse;
  }



  /**
   * Retrieves a string representation of this intermediate client request
   * control.
   *
   * @return  A string representation of this intermediate client request
   *          control.
   */
  @NotNull()
  public String toString()
  {
    return controlObject.toSingleLineString();
  }
}
