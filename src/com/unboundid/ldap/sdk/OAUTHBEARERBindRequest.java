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



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
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
  @NotNull public static final String OAUTHBEARER_MECHANISM_NAME =
       "OAUTHBEARER";



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
  @NotNull private static final byte[] GS2_HEADER_ELEMENT_NO_CHANNEL_BINDING =
       StaticUtils.getBytes("n");



  /**
   * The component of the GS2 header that precedes the authorization ID.
   */
  @NotNull private static final byte[] GS2_HEADER_ELEMENT_AUTHZ_ID_PREFIX =
       StaticUtils.getBytes("a=");



  /**
   * The component of the OAUTHBEARER bind request credentials that precedes the
   * access token.
   */
  @NotNull private static final byte[]
       OAUTHBEARER_CRED_ELEMENT_ACCESS_TOKEN_PREFIX =
            StaticUtils.getBytes("auth=Bearer ");



  /**
   * The component of the OAUTHBEARER bind request credentials that precedes the
   * server address.
   */
  @NotNull private static final byte[]
       OAUTHBEARER_CRED_ELEMENT_SERVER_ADDRESS_PREFIX =
            StaticUtils.getBytes("host=");



  /**
   * The component of the OAUTHBEARER bind request credentials that precedes the
   * server port.
   */
  @NotNull private static final byte[]
       OAUTHBEARER_CRED_ELEMENT_SERVER_PORT_PREFIX =
            StaticUtils.getBytes("port=");



  /**
   * The component of the OAUTHBEARER bind request credentials that precedes the
   * request method.
   */
  @NotNull private static final byte[]
       OAUTHBEARER_CRED_ELEMENT_REQUEST_METHOD_PREFIX =
            StaticUtils.getBytes("mthd=");



  /**
   * The component of the OAUTHBEARER bind request credentials that precedes the
   * request path.
   */
  @NotNull private static final byte[]
       OAUTHBEARER_CRED_ELEMENT_REQUEST_PATH_PREFIX =
            StaticUtils.getBytes("path=");



  /**
   * The component of the OAUTHBEARER bind request credentials that precedes the
   * request post data.
   */
  @NotNull private static final byte[]
       OAUTHBEARER_CRED_ELEMENT_REQUEST_POST_DATA_PREFIX =
            StaticUtils.getBytes("post=");



  /**
   * The component of the OAUTHBEARER bind request credentials that precedes the
   * request query string.
   */
  @NotNull private static final byte[]
       OAUTHBEARER_CRED_ELEMENT_REQUEST_QUERY_STRING_PREFIX =
            StaticUtils.getBytes("qs=");



  /**
   * The SASL credentials that should be included in the dummy bind request that
   * is used to complete a failed authentication attempt.
   */
  @NotNull private static final ASN1OctetString DUMMY_REQUEST_CREDENTIALS =
       new ASN1OctetString(new byte[] { OAUTHBEARER_DELIMITER });



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1216152242833705618L;



  // The message ID from the last LDAP message sent from this request.
  private volatile int messageID;

  // The port of the server to which the request will be sent.
  @Nullable private final Integer serverPort;

  // A set of additional key-value pairs that should be included in the bind
  // request.
  @NotNull private final Map<String,String> additionalKeyValuePairs;

  // The access token to include in the bind request.
  @NotNull private final String accessToken;

  // The authorization identity to include in the GS2 header for the bind
  // request.
  @Nullable private final String authorizationID;

  // The method to use for HTTP-based requests.
  @Nullable private final String requestMethod;

  // The path to use for HTTP-based requests.
  @Nullable private final String requestPath;

  // The post data for HTTP-based requests.
  @Nullable private final String requestPostData;

  // The query string for HTTP-based requests.
  @Nullable private final String requestQueryString;

  // The address of the server to which the request will be sent.
  @Nullable private final String serverAddress;



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
  public OAUTHBEARERBindRequest(@NotNull final String accessToken,
                                @Nullable final Control... controls)
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

    additionalKeyValuePairs = Collections.emptyMap();
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
              @NotNull final OAUTHBEARERBindRequestProperties properties,
              @Nullable final Control... controls)
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

    additionalKeyValuePairs = Collections.unmodifiableMap(
         new LinkedHashMap<>(properties.getAdditionalKeyValuePairs()));

    messageID = -1;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getSASLMechanismName()
  {
    return OAUTHBEARER_MECHANISM_NAME;
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
   * Retrieves an unmodifiable map of additional key-value pairs that should be
   * included in the bind request.
   *
   * @return  An unmodifiable map of additional key-value pairs that should be
   *          included in the bind request.  It will not be {@code null} but may
   *          be empty.
   */
  @NotNull()
  public Map<String,String> getAdditionalKeyValuePairs()
  {
    return additionalKeyValuePairs;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected OAUTHBEARERBindResult process(
                 @NotNull final LDAPConnection connection, final int depth)
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
  @NotNull()
  ASN1OctetString encodeCredentials()
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();

    // Construct the GS2 header and follow it with the necessary delimiter.
    buffer.append(GS2_HEADER_ELEMENT_NO_CHANNEL_BINDING);
    buffer.append(GS2_HEADER_DELIMITER);

    if (authorizationID != null)
    {
      buffer.append(GS2_HEADER_ELEMENT_AUTHZ_ID_PREFIX);
      escapeAuthorizationID(authorizationID, buffer);
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
    if (requestPath != null)
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
    if (requestQueryString != null)
    {
      buffer.append(OAUTHBEARER_CRED_ELEMENT_REQUEST_QUERY_STRING_PREFIX);
      buffer.append(requestQueryString);
      buffer.append(OAUTHBEARER_DELIMITER);
    }

    // Append any additional key-value pairs.
    for (final Map.Entry<String,String> e : additionalKeyValuePairs.entrySet())
    {
      buffer.append(e.getKey());
      buffer.append('=');
      buffer.append(e.getValue());
      buffer.append(OAUTHBEARER_DELIMITER);
    }

    return new ASN1OctetString(buffer.toByteArray());
  }



  /**
   * Appends an escaped version of the provided authorization ID to the given
   * buffer.  Any equal signs will be replaced with "=3D" and any commas will be
   * replaced with "=2C".
   *
   * @param  authorizationID  The authorization ID to be escaped.
   * @param  buffer           The buffer to which the escaped authorization ID
   *                          should be appended.
   */
  private static void escapeAuthorizationID(
               @NotNull final String authorizationID,
               @NotNull final ByteStringBuffer buffer)
  {
    final int length = authorizationID.length();
    for (int i=0; i < length; i++)
    {
      final char c = authorizationID.charAt(i);
      switch (c)
      {
        case ',':
          buffer.append("=2C");
          break;
        case '=':
          buffer.append("=3D");
          break;
        default:
          buffer.append(c);
          break;
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public OAUTHBEARERBindRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public OAUTHBEARERBindRequest duplicate(@Nullable final Control[] controls)
  {
    final OAUTHBEARERBindRequestProperties properties =
         new OAUTHBEARERBindRequestProperties(this);
    final OAUTHBEARERBindRequest bindRequest =
         new OAUTHBEARERBindRequest(properties, controls);
    bindRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return bindRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int getLastMessageID()
  {
    return messageID;
  }



  /**
   * Retrieves a string representation of the OAUTHBEARER bind request.
   *
   * @return  A string representation of the OAUTHBEARER bind request.
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
   * Appends a string representation of the OAUTHBEARER bind request to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.  It
   *                 must not be {@code null}.
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
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



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toCode(@NotNull final List<String> lineList,
                     @NotNull final String requestID,
                     final int indentSpaces, final boolean includeProcessing)
  {
    // Create and update the request properties object.
    ToCodeHelper.generateMethodCall(lineList, indentSpaces,
         "OAUTHBEARERBindRequestProperties", requestID + "RequestProperties",
         "new OAUTHBEARERBindRequestProperties",
         ToCodeArgHelper.createString(accessToken, "Access Token"));

    if (authorizationID != null)
    {
      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "RequestProperties.setAuthorizationID",
           ToCodeArgHelper.createString(authorizationID, null));
    }

    if (serverAddress != null)
    {
      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "RequestProperties.setServerAddress",
           ToCodeArgHelper.createString(serverAddress, null));
    }

    if (serverPort != null)
    {
      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "RequestProperties.setServerPort",
           ToCodeArgHelper.createInteger(serverPort, null));
    }

    if (requestMethod != null)
    {
      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "RequestProperties.setRequestMethod",
           ToCodeArgHelper.createString(requestMethod, null));
    }

    if (requestPath != null)
    {
      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "RequestProperties.setRequestPath",
           ToCodeArgHelper.createString(requestPath, null));
    }

    if (requestPostData != null)
    {
      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "RequestProperties.setRequestPostData",
           ToCodeArgHelper.createString(requestPostData, null));
    }

    if (requestQueryString != null)
    {
      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "RequestProperties.setRequestQueryString",
           ToCodeArgHelper.createString(requestQueryString, null));
    }

    for (final Map.Entry<String,String> e : additionalKeyValuePairs.entrySet())
    {
      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "RequestProperties.addKeyValuePair",
           ToCodeArgHelper.createString(e.getKey(), null),
           ToCodeArgHelper.createString(e.getValue(), null));
    }


    // Create the request variable.
    final ArrayList<ToCodeArgHelper> constructorArgs = new ArrayList<>(2);
    constructorArgs.add(
         ToCodeArgHelper.createRaw(requestID + "RequestProperties", null));

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      constructorArgs.add(ToCodeArgHelper.createControlArray(controls,
           "Bind Controls"));
    }

    ToCodeHelper.generateMethodCall(lineList, indentSpaces,
         "OAUTHBEARERBindRequest", requestID + "Request",
         "new OAUTHBEARERBindRequest", constructorArgs);


    // Add lines for processing the request and obtaining the result.
    if (includeProcessing)
    {
      // Generate a string with the appropriate indent.
      final StringBuilder buffer = new StringBuilder();
      for (int i=0; i < indentSpaces; i++)
      {
        buffer.append(' ');
      }
      final String indent = buffer.toString();

      lineList.add("");
      lineList.add(indent + "try");
      lineList.add(indent + '{');
      lineList.add(indent + "  BindResult " + requestID +
           "Result = connection.bind(" + requestID + "Request);");
      lineList.add(indent + "  // The bind was processed successfully.");
      lineList.add(indent + '}');
      lineList.add(indent + "catch (LDAPException e)");
      lineList.add(indent + '{');
      lineList.add(indent + "  // The bind failed.  Maybe the following will " +
           "help explain why.");
      lineList.add(indent + "  // Note that the connection is now likely in " +
           "an unauthenticated state.");
      lineList.add(indent + "  ResultCode resultCode = e.getResultCode();");
      lineList.add(indent + "  String message = e.getMessage();");
      lineList.add(indent + "  String matchedDN = e.getMatchedDN();");
      lineList.add(indent + "  String[] referralURLs = e.getReferralURLs();");
      lineList.add(indent + "  Control[] responseControls = " +
           "e.getResponseControls();");

      lineList.add("");
      lineList.add("OAUTHBEARERBindResult bindResult = " +
                "new OAUTHBEARERBindResult(new BindResult(e));");
      lineList.add("String authorizationErrorCode = " +
           "bindResult.getAuthorizationErrorCode();");
      lineList.add("Set<String> scopes = bindResult.getScopes();");
      lineList.add("String openIDConfigurationURL = " +
           "bindResult.getOpenIDConfigurationURL();");

      lineList.add(indent + '}');
    }
  }
}
