/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
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
  @Nullable private Integer serverPort;

  // A set of additional key-value pairs that should be included in the bind
  // request.
  @NotNull private final Map<String,String> additionalKeyValuePairs;

  // The access token to include in the bind request.
  @NotNull private String accessToken;

  // The authorization identity to include in the GS2 header for the bind
  // request.
  @Nullable private String authorizationID;

  // The method to use for HTTP-based requests.
  @Nullable private String requestMethod;

  // The path to use for HTTP-based requests.
  @Nullable private String requestPath;

  // The post data for HTTP-based requests.
  @Nullable private String requestPostData;

  // The query string for HTTP-based requests.
  @Nullable private String requestQueryString;

  // The address of the server to which the request will be sent.
  @Nullable private String serverAddress;



  /**
   * Creates a new set of OAUTHBEARER bind request properties with the provided
   * access token.
   *
   * @param  accessToken  The access token to include in the bind request.  It
   *                      must not be {@code null} or empty.
   */
  public OAUTHBEARERBindRequestProperties(@NotNull final String accessToken)
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

    additionalKeyValuePairs = new LinkedHashMap<>();
  }



  /**
   * Creates a new set of OAUTHBEARER bind request properties that is a copy of
   * the provided set of properties.
   *
   * @param  properties  The set of properties to duplicate.  It must not be
   *                     {@code null}.
   */
  public OAUTHBEARERBindRequestProperties(
              @NotNull final OAUTHBEARERBindRequestProperties properties)
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
    additionalKeyValuePairs =
         new LinkedHashMap<>(properties.additionalKeyValuePairs);
  }



  /**
   * Creates a new set of OAUTHBEARER bind request properties that is a copy of
   * the properties used for the provided bind request.
   *
   * @param  bindRequest  The OAUTHBEARER bind request to use to create this set
   *                      of properties.  It must not be {@code null}.
   */
  public OAUTHBEARERBindRequestProperties(
              @NotNull final OAUTHBEARERBindRequest bindRequest)
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
    additionalKeyValuePairs =
         new LinkedHashMap<>(bindRequest.getAdditionalKeyValuePairs());
  }



  /**
   * Retrieves the access token to include in the bind request.
   *
   * @return  The access token to include in the bind request.
   */
  @NotNull()
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
  public void setAccessToken(@NotNull final String accessToken)
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
  @Nullable()
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
  public void setAuthorizationID(@Nullable final String authorizationID)
  {
    this.authorizationID = authorizationID;
  }



  /**
   * Retrieves the server address to include in the bind request, if any.
   *
   * @return  The server address to include in the bind request, or {@code null}
   *          if it should be omitted.
   */
  @Nullable()
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
  public void setServerAddress(@Nullable final String serverAddress)
  {
    this.serverAddress = serverAddress;
  }



  /**
   * Retrieves the server port to include in the bind request, if any.
   *
   * @return  The server port to include in the bind request, or {@code null}
   *          if it should be omitted.
   */
  @Nullable()
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
  public void setServerPort(@Nullable final Integer serverPort)
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
  @Nullable()
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
  public void setRequestMethod(@Nullable final String requestMethod)
  {
    this.requestMethod = requestMethod;
  }



  /**
   * Retrieves the path to use for HTTP-based requests, if any.
   *
   * @return  The path to use for HTTP-based requests, or {@code null} if it
   *          should be omitted from the bind request.
   */
  @Nullable()
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
  public void setRequestPath(@Nullable final String requestPath)
  {
    this.requestPath = requestPath;
  }



  /**
   * Retrieves the data to submit when posting an HTTP-based request, if any.
   *
   * @return  The post data for HTTP-based requests, or {@code null} if it
   *          should be omitted from the bind request.
   */
  @Nullable()
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
  public void setRequestPostData(@Nullable final String requestPostData)
  {
    this.requestPostData = requestPostData;
  }



  /**
   * Retrieves the query string to use for HTTP-based requests, if any.
   *
   * @return  The query string to use for HTTP-based requests, or {@code null}
   *          if it should be omitted from the bind request.
   */
  @Nullable()
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
  public void setRequestQueryString(@Nullable final String requestQueryString)
  {
    this.requestQueryString = requestQueryString;
  }



  /**
   * Retrieves an unmodifiable map of additional key-value pairs that should be
   * included in the bind request.
   *
   * @return  An unmodifiable map of additional key-value pairs that should be
   *          included in the bind request.
   */
  @NotNull()
  public Map<String,String> getAdditionalKeyValuePairs()
  {
    return Collections.unmodifiableMap(additionalKeyValuePairs);
  }



  /**
   * Adds an item to the set of additional key-value pairs that should be
   * included in the bind request.  If an item is already defined with the
   * provided key, then its value will be replaced.
   *
   * @param  key    The key to use.  It must not be {@code null} or empty, and
   *                it must contain only alphabetic characters.
   * @param  value  The value to use for the key.  It must not be {@code null},
   *                and it must not contain the 0x00 or 0x01 characters.
   */
  public void addKeyValuePair(@NotNull final String key,
                              @NotNull final String value)
  {
    Validator.ensureNotNullOrEmpty(key,
         "OAUTHBEARERBindRequestProperties.addKeyValuePair.key must not be " +
              "null or empty.");
    for (final char c : key.toCharArray())
    {
      Validator.ensureTrue(
           (((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z'))),
           "OAUTHBEARERBindRequestProperties.addKeyValuePair.key must " +
                "contain only alphabetic characters.");
    }

    Validator.ensureNotNull(value,
         "OAUTHBEARERBindRequestProperties.addKeyValuePair.value must not be " +
              "null.");
    for (final char c : value.toCharArray())
    {
      Validator.ensureFalse(
           ((c == '\u0000') || (c == '\u0001')),
           "OAUTHBEARERBindRequestProperties.addKeyValuePair.value must not " +
                "contain the characters \\u0000 or \\u0001.");
    }

    additionalKeyValuePairs.put(key, value);
  }



  /**
   * Removes the specified additional key-value pair so it will not be included
   * in the bind request.
   *
   * @param  key  The key to remove.
   *
   * @return  The value that was associated with the key.  It may be
   *          {@code null} if the specified key was not set.
   */
  @Nullable()
  public String removeKeyValuePair(@NotNull final String key)
  {
    return additionalKeyValuePairs.remove(key);
  }



  /**
   * Clears the set of additional key-value pairs.
   */
  public void clearAdditionalKeyValuePairs()
  {
    additionalKeyValuePairs.clear();
  }



  /**
   * Retrieves a string representation of the OAUTHBEARER bind request
   * properties.
   *
   * @return  A string representation of the OAUTHBEARER bind request
   *          properties.
   */
  @Override()
  @NotNull()
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
  public void toString(@NotNull final StringBuilder buffer)
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

    if (! additionalKeyValuePairs.isEmpty())
    {
      buffer.append(", additionalKeyValuePairs=[");

      final Iterator<Map.Entry<String,String>> iterator =
           additionalKeyValuePairs.entrySet().iterator();
      while (iterator.hasNext())
      {
        final Map.Entry<String,String> e = iterator.next();
        buffer.append(" \"");
        buffer.append(e.getKey());
        buffer.append("\"=\"");
        buffer.append(e.getValue());
        buffer.append('"');

        if (iterator.hasNext())
        {
          buffer.append(',');
        }
      }

      buffer.append(" ]");
    }

    buffer.append(')');
  }
}
