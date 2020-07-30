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



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides an implementation of a SASL bind request that uses the
 * OAUTHBEARER SASL mechanism described in
 * <A HREF="http://www.ietf.org/rfc/rfc7628.txt">RFC 7628</A> to allow a user
 * to authenticate with an OAuth 2.0 bearer token.
 *
 * @see  OAUTHBEARERBindRequestProperties
 * @see  OAUTHBEARERBindResult
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class OAUTHBEARERBindRequest
       extends SASLBindRequest
{
  /**
   * The name for the OAUTHBEARER SASL mechanism.
   */
  public static final String OAUTHBEARER_MECHANISM_NAME = "OAUTHBEARER";



  /**
   * The delimiter that appears between elements of the GS2 header.
   */
  private static final byte GS2_HEADER_DELIMITER = ',';



  /**
   * The delimiter that appears after each element of the encoded credentials.
   */
  private static final byte OAUTHBEARER_DELIMITER = (byte) 0x01;



  /**
   * The component of the GS2 header that indicates that channel binding is not
   * supported.
   */
  private static final byte[] GS2_HEADER_ELEMENT_NO_CHANNEL_BINDING =
       StaticUtils.getBytes("n");



  /**
   * The component of the GS2 header that precedes the authorization ID.
   */
  private static final byte[] GS2_HEADER_ELEMENT_AUTHZ_ID_PREFIX =
       StaticUtils.getBytes("a=");



  /**
   * The component of the OAUTHBEARER bind request credentials that precedes the
   * access token.
   */
  private static final byte[] OAUTHBEARER_CRED_ELEMENT_ACCESS_TOKEN_PREFIX =
       StaticUtils.getBytes("auth=Bearer ");



  /**
   * The component of the OAUTHBEARER bind request credentials that precedes the
   * server address.
   */
  private static final byte[] OAUTHBEARER_CRED_ELEMENT_SERVER_ADDRESS_PREFIX =
       StaticUtils.getBytes("host=");



  /**
   * The component of the OAUTHBEARER bind request credentials that precedes the
   * server port.
   */
  private static final byte[] OAUTHBEARER_CRED_ELEMENT_SERVER_PORT_PREFIX =
       StaticUtils.getBytes("port=");



  /**
   * The component of the OAUTHBEARER bind request credentials that precedes the
   * request method.
   */
  private static final byte[] OAUTHBEARER_CRED_ELEMENT_REQUEST_METHOD_PREFIX =
       StaticUtils.getBytes("mthd=");



  /**
   * The component of the OAUTHBEARER bind request credentials that precedes the
   * request path.
   */
  private static final byte[] OAUTHBEARER_CRED_ELEMENT_REQUEST_PATH_PREFIX =
       StaticUtils.getBytes("path=");



  /**
   * The component of the OAUTHBEARER bind request credentials that precedes the
   * request post data.
   */
  private static final byte[]
       OAUTHBEARER_CRED_ELEMENT_REQUEST_POST_DATA_PREFIX =
            StaticUtils.getBytes("post=");



  /**
   * The component of the OAUTHBEARER bind request credentials that precedes the
   * request query string.
   */
  private static final byte[]
       OAUTHBEARER_CRED_ELEMENT_REQUEST_QUERY_STRING_PREFIX =
            StaticUtils.getBytes("qs=");



  /**
   * The SASL credentials that should be included in the dummy bind request that
   * is used to complete a failed authentication attempt.
   */
  private static final ASN1OctetString DUMMY_REQUEST_CREDENTIALS =
       new ASN1OctetString(new byte[] { OAUTHBEARER_DELIMITER });



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1216152242833705618L;



  // The message ID from the last LDAP message sent from this request.
  private volatile int messageID;

  // The port of the server to which the request will be sent.
  private final Integer serverPort;

  // The access token to include in the bind request.
  private final String accessToken;

  // The authorization identity to include in the GS2 header for the bind
  // request.
  private final String authorizationID;

  // The method to use for HTTP-based requests.
  private final String requestMethod;

  // The path to use for HTTP-based requests.
  private final String requestPath;

  // The post data for HTTP-based requests.
  private final String requestPostData;

  // The query string for HTTP-based requests.
  private final String requestQueryString;

  // The address of the server to which the request will be sent.
  private final String serverAddress;



  /**
   * Creates a new OAUTHBEARER bind request with the provided access token.
   * All other properties will be unset.
   *
   * @param  accessToken  The access token to use for this bind request.  It
   *                      must not be {@code null} or empty.
   * @param  controls     The set of controls to include in the bind request.
   *                      It may be {@code null} or empty if no controls are
   *                      needed.
   */
  public OAUTHBEARERBindRequest(final String accessToken,
                                final Control... controls)
  {
    super(controls);

    Validator.ensureNotNullOrEmpty(accessToken,
         "OAUTHBEARERBindRequest.accessToken must not be null or empty.");

    this.accessToken = accessToken;

    authorizationID = null;
    serverAddress = null;
    serverPort = null;
    requestMethod = null;
    requestPath = null;
    requestPostData = null;
    requestQueryString = null;

    messageID = -1;
  }



  /**
   * Creates a new OAUTHBEARER bind request with the provided set of properties.
   *
   * @param  properties  The set of properties to use to create this bind
   *                     request.  It must not be {@code null}.
   * @param  controls    The set of controls to include in the bind request.  It
   *                     may be {@code null} or empty if no controls are needed.
   */
  public OAUTHBEARERBindRequest(
              final OAUTHBEARERBindRequestProperties properties,
              final Control... controls)
  {
    super(controls);

    accessToken = properties.getAccessToken();
    authorizationID = properties.getAuthorizationID();
    serverAddress = properties.getServerAddress();
    serverPort = properties.getServerPort();
    requestMethod = properties.getRequestMethod();
    requestPath = properties.getRequestPath();
    requestPostData = properties.getRequestPostData();
    requestQueryString = properties.getRequestQueryString();

    messageID = -1;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getSASLMechanismName()
  {
    return OAUTHBEARER_MECHANISM_NAME;
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
   * {@inheritDoc}
   */
  @Override()
  protected OAUTHBEARERBindResult process(final LDAPConnection connection,
                                          final int depth)
            throws LDAPException
  {
    // Send the initial request.  If the response has a result code that is
    // anything other than SASL_BIND_IN_PROGRESS, then we can just return it
    // directly without needing to do anything else.
    messageID = InternalSDKHelper.nextMessageID(connection);
    final BindResult initialBindResult =  sendBindRequest(connection, "",
         encodeCredentials(), getControls(),
         getResponseTimeoutMillis(connection));
    if (initialBindResult.getResultCode() != ResultCode.SASL_BIND_IN_PROGRESS)
    {
      return new OAUTHBEARERBindResult(initialBindResult);
    }


    // If we've gotten here, then it indicates that the attempt failed.  We need
    // to send a second, dummy request to complete the bind process and get the
    // ultimate failure result.
    BindResult finalBindResult;
    try
    {
      messageID = InternalSDKHelper.nextMessageID(connection);
      finalBindResult = sendBindRequest(connection, "",
           DUMMY_REQUEST_CREDENTIALS, getControls(),
           getResponseTimeoutMillis(connection));
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      finalBindResult = new BindResult(e);
    }

    return new OAUTHBEARERBindResult(initialBindResult, finalBindResult);
  }



  /**
   * Encodes the credentials as appropriate for this bind request.
   *
   * @return  An ASN.1 octet string containing the encoded credentials.
   */
  ASN1OctetString encodeCredentials()
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();

    // Construct the GS2 header and follow it with the necessary delimiter.
    buffer.append(GS2_HEADER_ELEMENT_NO_CHANNEL_BINDING);
    buffer.append(GS2_HEADER_DELIMITER);

    if (authorizationID != null)
    {
      buffer.append(GS2_HEADER_ELEMENT_AUTHZ_ID_PREFIX);
      buffer.append(authorizationID);
    }

    buffer.append(GS2_HEADER_DELIMITER);
    buffer.append(OAUTHBEARER_DELIMITER);


    // Append the access token.
    buffer.append(OAUTHBEARER_CRED_ELEMENT_ACCESS_TOKEN_PREFIX);
    buffer.append(accessToken);
    buffer.append(OAUTHBEARER_DELIMITER);


    // Append the server address, if appropriate.
    if (serverAddress != null)
    {
      buffer.append(OAUTHBEARER_CRED_ELEMENT_SERVER_ADDRESS_PREFIX);
      buffer.append(serverAddress);
      buffer.append(OAUTHBEARER_DELIMITER);
    }


    // Append the server port, if appropriate.
    if (serverPort != null)
    {
      buffer.append(OAUTHBEARER_CRED_ELEMENT_SERVER_PORT_PREFIX);
      buffer.append(serverPort.toString());
      buffer.append(OAUTHBEARER_DELIMITER);
    }


    // Append the request method, if appropriate.
    if (requestMethod != null)
    {
      buffer.append(OAUTHBEARER_CRED_ELEMENT_REQUEST_METHOD_PREFIX);
      buffer.append(requestMethod);
      buffer.append(OAUTHBEARER_DELIMITER);
    }


    // Append the request path, if appropriate.
    if (requestMethod != null)
    {
      buffer.append(OAUTHBEARER_CRED_ELEMENT_REQUEST_PATH_PREFIX);
      buffer.append(requestPath);
      buffer.append(OAUTHBEARER_DELIMITER);
    }


    // Append the request post data, if appropriate.
    if (requestPostData != null)
    {
      buffer.append(OAUTHBEARER_CRED_ELEMENT_REQUEST_POST_DATA_PREFIX);
      buffer.append(requestPostData);
      buffer.append(OAUTHBEARER_DELIMITER);
    }


    // Append the request query string, if appropriate.
    if (requestPostData != null)
    {
      buffer.append(OAUTHBEARER_CRED_ELEMENT_REQUEST_QUERY_STRING_PREFIX);
      buffer.append(requestQueryString);
      buffer.append(OAUTHBEARER_DELIMITER);
    }

    return new ASN1OctetString(buffer.toByteArray());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public OAUTHBEARERBindRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public OAUTHBEARERBindRequest duplicate(final Control[] controls)
  {
    final OAUTHBEARERBindRequestProperties properties =
         new OAUTHBEARERBindRequestProperties(this);
    final OAUTHBEARERBindRequest bindRequest =
         new OAUTHBEARERBindRequest(properties, controls);
    bindRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return bindRequest;
  }



  /**
   * Retrieves a string representation of the OAUTHBEARER bind request.
   *
   * @return  A string representation of the OAUTHBEARER bind request.
   */
  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of the OAUTHBEARER bind request to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.  It
   *                 must not be {@code null}.
   */
  public void toString(final StringBuilder buffer)
  {
    buffer.append("OAUTHBEARERBindRequest(accessToken='{redacted}'");

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
