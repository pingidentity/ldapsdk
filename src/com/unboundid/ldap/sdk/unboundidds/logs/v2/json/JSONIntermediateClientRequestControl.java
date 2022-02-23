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
 * JSON-formatted intermediate client request control.
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
public final class JSONIntermediateClientRequestControl
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -575977471763904665L;



  // Indicates whether communication with the downstream client is secure.
  @Nullable private final Boolean downstreamClientSecure;

  // A downstream request embedded in the control.
  @Nullable private final JSONIntermediateClientRequestControl
       downstreamRequest;

  // The JSON object with an encoded representation of this control.
  @NotNull private final JSONObject controlObject;

  // The requested client authorization identity.
  @Nullable private final String clientIdentity;

  // The name of the client application.
  @Nullable private final String clientName;

  // The downstream client address.
  @Nullable private final String downstreamClientAddress;

  // The request ID assigned by the downstream client.
  @Nullable private final String requestID;

  // The session ID assigned by the downstream client.
  @Nullable private final String sessionID;



  /**
   * Creates a new JSON intermediate client request control that is decoded from
   * the provided JSON object.
   *
   * @param  controlObject  The JSON object containing an encoded representation
   *                        of this intermediate client request control.
   */
  public JSONIntermediateClientRequestControl(
              @NotNull final JSONObject controlObject)
  {
    this.controlObject = controlObject;

    downstreamClientAddress = controlObject.getFieldAsString(
         INTERMEDIATE_CLIENT_REQUEST_CONTROL_DOWNSTREAM_CLIENT_ADDRESS.
              getFieldName());
    downstreamClientSecure = controlObject.getFieldAsBoolean(
         INTERMEDIATE_CLIENT_REQUEST_CONTROL_DOWNSTREAM_CLIENT_SECURE.
              getFieldName());
    clientIdentity = controlObject.getFieldAsString(
         INTERMEDIATE_CLIENT_REQUEST_CONTROL_CLIENT_IDENTITY.getFieldName());
    clientName = controlObject.getFieldAsString(
         INTERMEDIATE_CLIENT_REQUEST_CONTROL_CLIENT_NAME.getFieldName());
    sessionID = controlObject.getFieldAsString(
         INTERMEDIATE_CLIENT_REQUEST_CONTROL_SESSION_ID.getFieldName());
    requestID = controlObject.getFieldAsString(
         INTERMEDIATE_CLIENT_REQUEST_CONTROL_REQUEST_ID.getFieldName());

    final JSONObject downstreamObject = controlObject.getFieldAsObject(
         INTERMEDIATE_CLIENT_REQUEST_CONTROL_DOWNSTREAM_REQUEST.getFieldName());
    if (downstreamObject == null)
    {
      downstreamRequest = null;
    }
    else
    {
      downstreamRequest =
           new JSONIntermediateClientRequestControl(downstreamObject);
    }
  }



  /**
   * Retrieves a JSON object containing an encoded representation of this
   * intermediate client request control.
   *
   * @return  A JSON object containing an encoded representation of this
   *          intermediate client request control.
   */
  @NotNull()
  public JSONObject getControlObject()
  {
    return controlObject;
  }



  /**
   * Retrieves the address of a downstream client.
   *
   * @return  The address of a downstream client, or {@code null} if no
   *          downstream client address is available.
   */
  @Nullable()
  public String getDownstreamClientAddress()
  {
    return downstreamClientAddress;
  }



  /**
   * Indicates whether communication with the downstream client is secure.
   *
   * @return  {@code Boolean.TRUE} if communication with the downstream client
   *          is secure, {@code Boolean.FALSE} if communication with the
   *          downstream client is not secure, or {@code null} if this
   *          information is not available.
   */
  @Nullable()
  public Boolean getDownstreamClientSecure()
  {
    return downstreamClientSecure;
  }



  /**
   * Retrieves the requested client authorization identity.
   *
   * @return  The requested client authorization identity, or {@code null} if
   *          no client identity is available.
   */
  @Nullable()
  public String getClientIdentity()
  {
    return clientIdentity;
  }



  /**
   * Retrieves the name of the client application.
   *
   * @return  The name of the client application, or {@code null} if no client
   *          name is available.
   */
  @Nullable()
  public String getClientName()
  {
    return clientName;
  }



  /**
   * Retrieves the session ID assigned by the downstream client.
   *
   * @return  The session ID assigned by the downstream client, or {@code null}
   *          if no session ID is available.
   */
  @Nullable()
  public String getSessionID()
  {
    return sessionID;
  }



  /**
   * Retrieves the request ID assigned by the downstream client.
   *
   * @return  The request ID assigned by the downstream client, or {@code null}
   *          if no request ID is available.
   */
  @Nullable()
  public String getRequestID()
  {
    return requestID;
  }



  /**
   * Retrieves a downstream request embedded in the control.
   *
   * @return  A downstream request embedded in the control, or {@code null} if
   *          no downstream request is available.
   */
  @Nullable()
  public JSONIntermediateClientRequestControl getDownstreamRequest()
  {
    return downstreamRequest;
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
