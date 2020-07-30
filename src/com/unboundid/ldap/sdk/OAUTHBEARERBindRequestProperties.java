/*
 * Copyright 2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020 Ping Identity Corporation
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
 * Copyright (C) 2020 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.io.Serializable;

import com.unboundid.util.Mutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a data structure that may be used to hold a number of
 * properties used during processing for a OAUTHBEARER SASL bind operation.
 *
 * @see OAUTHBEARERBindRequest
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class OAUTHBEARERBindRequestProperties
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7664683436256231975L;



  // The port of the server to which the request will be sent.
  private Integer serverPort;

  // The access token to include in the bind request.
  private String accessToken;

  // The authorization identity to include in the GS2 header for the bind
  // request.
  private String authorizationID;

  // The method to use for HTTP-based requests.
  private String requestMethod;

  // The path to use for HTTP-based requests.
  private String requestPath;

  // The post data for HTTP-based requests.
  private String requestPostData;

  // The query string for HTTP-based requests.
  private String requestQueryString;

  // The address of the server to which the request will be sent.
  private String serverAddress;



  /**
   * Creates a new set of OAUTHBEARER bind request properties with the provided
   * access token.
   *
   * @param  accessToken  The access token to include in the bind request.  It
   *                      must not be {@code null} or empty.
   */
  public OAUTHBEARERBindRequestProperties(final String accessToken)
  {
    Validator.ensureNotNullOrEmpty(accessToken,
         "OAUTHBEARERBindRequestProperties.accessToken must not be null or " +
              "empty.");

    this.accessToken = accessToken;

    authorizationID = null;
    serverAddress = null;
    serverPort = null;
    requestMethod = null;
    requestPath = null;
    requestPostData = null;
    requestQueryString = null;
  }



  /**
   * Creates a new set of OAUTHBEARER bind request properties that is a copy of
   * the provided set of properties.
   *
   * @param  properties  The set of properties to duplicate.  It must not be
   *                     {@code null}.
   */
  public OAUTHBEARERBindRequestProperties(
              final OAUTHBEARERBindRequestProperties properties)
  {
    Validator.ensureNotNullWithMessage(properties,
         "OAUTHBEARERBindRequestProperties.properties must not be null.");

    accessToken = properties.accessToken;
    authorizationID = properties.authorizationID;
    serverAddress = properties.serverAddress;
    serverPort = properties.serverPort;
    requestMethod = properties.requestMethod;
    requestPath = properties.requestPath;
    requestPostData = properties.requestPostData;
    requestQueryString = properties.requestQueryString;
  }



  /**
   * Creates a new set of OAUTHBEARER bind request properties that is a copy of
   * the properties used for the provided bind request.
   *
   * @param  bindRequest  The OAUTHBEARER bind request to use to create this set
   *                      of properties.  It must not be {@code null}.
   */
  public OAUTHBEARERBindRequestProperties(
              final OAUTHBEARERBindRequest bindRequest)
  {
    Validator.ensureNotNullWithMessage(bindRequest,
         "OAUTHBEARERBindRequestProperties.bindRequest must not be null.");

    accessToken = bindRequest.getAccessToken();
    authorizationID = bindRequest.getAuthorizationID();
    serverAddress = bindRequest.getServerAddress();
    serverPort = bindRequest.getServerPort();
    requestMethod = bindRequest.getRequestMethod();
    requestPath = bindRequest.getRequestPath();
    requestPostData = bindRequest.getRequestPostData();
    requestQueryString = bindRequest.getRequestQueryString();
  }



  /**
   * Retrieves the access token to include in the bind request.
   *
   * @return  The access token to include in the bind request.
   */
  public String getAccessToken()
  {
    return accessToken;
  }



  /**
   * Specifies the access token to include in the bind request.
   *
   * @param  accessToken  The access token to include in the bind request.  It
   *                      must not be {@code null} or empty.
   */
  public void setAccessToken(final String accessToken)
  {
    Validator.ensureNotNullOrEmpty(accessToken,
         "OAUTHBEARERBindRequestProperties.accessToken must not be null or " +
              "empty.");

    this.accessToken = accessToken;
  }



  /**
   * Retrieves the authorization ID to include in the GS2 header for the bind
   * request, if any.
   *
   * @return  The authorization ID to include in the GS2 header for the bind
   *          request, or {@code null} if no authorization ID should be
   *          included.
   */
  public String getAuthorizationID()
  {
    return authorizationID;
  }



  /**
   * Specifies the authorization ID to include in the GS2 header for the bind
   * request, if any.
   *
   * @param  authorizationID  The authorization ID to include in the bind
   *                          request.  It may be {@code null} if no
   *                          authorization ID should be provided.
   */
  public void setAuthorizationID(final String authorizationID)
  {
    this.authorizationID = authorizationID;
  }



  /**
   * Retrieves the server address to include in the bind request, if any.
   *
   * @return  The server address to include in the bind request, or {@code null}
   *          if it should be omitted.
   */
  public String getServerAddress()
  {
    return serverAddress;
  }



  /**
   * Specifies the server address to include in the bind request, if any.
   *
   * @param  serverAddress  The server address to include in the bind request.
   *                        It may be {@code null} if the server address should
   *                        be omitted.
   */
  public void setServerAddress(final String serverAddress)
  {
    this.serverAddress = serverAddress;
  }



  /**
   * Retrieves the server port to include in the bind request, if any.
   *
   * @return  The server port to include in the bind request, or {@code null}
   *          if it should be omitted.
   */
  public Integer getServerPort()
  {
    return serverPort;
  }



  /**
   * Specifies the server port to include in the bind request, if any.
   *
   * @param   serverPort  The server port to include in the bind request.  It
   *                      may be {@code null} if the server port should be
   *                      omitted.  If it is non-{@code null}, then the value
   *                      must be between 1 and 65535, inclusive.
   */
  public void setServerPort(final Integer serverPort)
  {
    if (serverPort != null)
    {
      Validator.ensureTrue(((serverPort >= 1) && (serverPort <= 65535)),
           "If provided, OAUTHBEARERBindRequestProperties.serverPort must be " +
                "between 1 and 65535, inclusive.");
    }

    this.serverPort = serverPort;
  }



  /**
   * Retrieves the method to use for HTTP-based requests, if any.
   *
   * @return  The method to use for HTTP-based requests, or {@code null} if it
   *          should be omitted from the bind request.
   */
  public String getRequestMethod()
  {
    return requestMethod;
  }



  /**
   * Specifies the method to use for HTTP-based requests, if it should be
   * included in the bind request.
   *
   * @param   requestMethod  The method to use for HTTP-based requests.  It may
   *                         be {@code null} if the request method should be
   *                         omitted.
   */
  public void setRequestMethod(final String requestMethod)
  {
    this.requestMethod = requestMethod;
  }



  /**
   * Retrieves the path to use for HTTP-based requests, if any.
   *
   * @return  The path to use for HTTP-based requests, or {@code null} if it
   *          should be omitted from the bind request.
   */
  public String getRequestPath()
  {
    return requestPath;
  }



  /**
   * Specifies the path to use for HTTP-based requests, if it should be included
   * in the bind request.
   *
   * @param  requestPath  The path to use for HTTP-based requests.  It may be
   *                      {@code null} if the request path should be omitted.
   */
  public void setRequestPath(final String requestPath)
  {
    this.requestPath = requestPath;
  }



  /**
   * Retrieves the data to submit when posting an HTTP-based request, if any.
   *
   * @return  The post data for HTTP-based requests, or {@code null} if it
   *          should be omitted from the bind request.
   */
  public String getRequestPostData()
  {
    return requestPostData;
  }



  /**
   * Specifies the data to submit when posting an HTTP-based request, if it
   * should be included in the bind request.
   *
   * @param  requestPostData  The post data for HTTP-based requests.  It may be
   *                          {@code null} if the post data should be omitted.
   */
  public void setRequestPostData(final String requestPostData)
  {
    this.requestPostData = requestPostData;
  }



  /**
   * Retrieves the query string to use for HTTP-based requests, if any.
   *
   * @return  The query string to use for HTTP-based requests, or {@code null}
   *          if it should be omitted from the bind request.
   */
  public String getRequestQueryString()
  {
    return requestQueryString;
  }



  /**
   * Specifies the query string to use for HTTP-based requests, if it should be
   * included in the bind request.
   *
   * @param  requestQueryString  The query string to use for HTTP-based
   *                             requests.  It may be {@code null} if it should
   *                             be omitted from the bind request.
   */
  public void setRequestQueryString(final String requestQueryString)
  {
    this.requestQueryString = requestQueryString;
  }



  /**
   * Retrieves a string representation of the OAUTHBEARER bind request
   * properties.
   *
   * @return  A string representation of the OAUTHBEARER bind request
   *          properties.
   */
  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of the OAUTHBEARER bind request properties
   * to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.  It
   *                 must not be {@code null}.
   */
  public void toString(final StringBuilder buffer)
  {
    buffer.append("OAUTHBEARERBindRequestProperties(accessToken='{redacted}'");

    if (authorizationID != null)
    {
      buffer.append(", authorizationID='");
      buffer.append(authorizationID);
      buffer.append('\'');
    }

    if (serverAddress != null)
    {
      buffer.append(", serverAddress='");
      buffer.append(serverAddress);
      buffer.append('\'');
    }

    if (serverPort != null)
    {
      buffer.append(", serverPort=");
      buffer.append(serverPort);
    }

    if (requestMethod != null)
    {
      buffer.append(", requestMethod='");
      buffer.append(requestMethod);
      buffer.append('\'');
    }

    if (requestPath != null)
    {
      buffer.append(", requestPath='");
      buffer.append(requestPath);
      buffer.append('\'');
    }

    if (requestPostData != null)
    {
      buffer.append(", requestPostData='{redacted}'");
    }

    if (requestQueryString != null)
    {
      buffer.append(", requestQueryString='");
      buffer.append(requestQueryString);
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
