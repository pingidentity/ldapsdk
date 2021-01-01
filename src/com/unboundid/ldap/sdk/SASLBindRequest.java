/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.protocol.BindRequestProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.LDAPResponse;
import com.unboundid.util.Debug;
import com.unboundid.util.Extensible;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides an API that should be used to represent an LDAPv3 SASL
 * bind request.  A SASL bind includes a SASL mechanism name and an optional set
 * of credentials.
 * <BR><BR>
 * See <A HREF="http://www.ietf.org/rfc/rfc4422.txt">RFC 4422</A> for more
 * information about the Simple Authentication and Security Layer.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public abstract class SASLBindRequest
       extends BindRequest
       implements ResponseAcceptor
{
  /**
   * The BER type to use for the credentials element in a simple bind request
   * protocol op.
   */
  protected static final byte CRED_TYPE_SASL = (byte) 0xA3;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5842126553864908312L;



  // The message ID to use for LDAP messages used in bind processing.
  private int messageID;

  // The queue used to receive responses from the server.
  @NotNull private final LinkedBlockingQueue<LDAPResponse> responseQueue;



  /**
   * Creates a new SASL bind request with the provided controls.
   *
   * @param  controls  The set of controls to include in this SASL bind request.
   */
  protected SASLBindRequest(@Nullable final Control[] controls)
  {
    super(controls);

    messageID     = -1;
    responseQueue = new LinkedBlockingQueue<>();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getBindType()
  {
    return getSASLMechanismName();
  }



  /**
   * Retrieves the name of the SASL mechanism used in this SASL bind request.
   *
   * @return  The name of the SASL mechanism used in this SASL bind request.
   */
  @NotNull()
  public abstract String getSASLMechanismName();



  /**
   * {@inheritDoc}
   */
  @Override()
  public int getLastMessageID()
  {
    return messageID;
  }



  /**
   * Sends an LDAP message to the directory server and waits for the response.
   *
   * @param  connection       The connection to the directory server.
   * @param  bindDN           The bind DN to use for the request.  It should be
   *                          {@code null} for most types of SASL bind requests.
   * @param  saslCredentials  The SASL credentials to use for the bind request.
   *                          It may be {@code null} if no credentials are
   *                          required.
   * @param  controls         The set of controls to include in the request.  It
   *                          may be {@code null} if no controls are required.
   * @param  timeoutMillis    The maximum length of time in milliseconds to wait
   *                          for a response, or zero if it should wait forever.
   *
   * @return  The bind response message returned by the directory server.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response, or if a timeout occurred
   *                         while waiting for the response.
   */
  @NotNull()
  protected final BindResult sendBindRequest(
                       @NotNull final LDAPConnection connection,
                       @Nullable final String bindDN,
                       @Nullable final ASN1OctetString saslCredentials,
                       @Nullable final Control[] controls,
                       final long timeoutMillis)
            throws LDAPException
  {
    messageID = connection.nextMessageID();

    final BindRequestProtocolOp protocolOp =
         new BindRequestProtocolOp(bindDN, getSASLMechanismName(),
                                   saslCredentials);

    final LDAPMessage requestMessage =
         new LDAPMessage(messageID, protocolOp, controls);
    return sendMessage(connection, requestMessage, timeoutMillis);
  }



  /**
   * Sends an LDAP message to the directory server and waits for the response.
   *
   * @param  connection      The connection to the directory server.
   * @param  requestMessage  The LDAP message to send to the directory server.
   * @param  timeoutMillis   The maximum length of time in milliseconds to wait
   *                         for a response, or zero if it should wait forever.
   *
   * @return  The response message received from the server.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response, or if a timeout occurred
   *                         while waiting for the response.
   */
  @NotNull()
  protected final BindResult sendMessage(
                                  @NotNull final LDAPConnection connection,
                                  @NotNull final LDAPMessage requestMessage,
                                  final long timeoutMillis)
            throws LDAPException
  {
    if (connection.synchronousMode())
    {
      return sendMessageSync(connection, requestMessage, timeoutMillis);
    }

    final int msgID = requestMessage.getMessageID();
    connection.registerResponseAcceptor(msgID, this);
    try
    {
      Debug.debugLDAPRequest(Level.INFO, this, msgID, connection);

      final LDAPConnectionLogger logger =
           connection.getConnectionOptions().getConnectionLogger();
      if (logger != null)
      {
        logger.logBindRequest(connection, messageID, this);
      }

      final long requestTime = System.nanoTime();
      connection.getConnectionStatistics().incrementNumBindRequests();
      connection.sendMessage(requestMessage, timeoutMillis);

      // Wait for and process the response.
      final LDAPResponse response;
      try
      {
        if (timeoutMillis > 0)
        {
          response = responseQueue.poll(timeoutMillis, TimeUnit.MILLISECONDS);
        }
        else
        {
          response = responseQueue.take();
        }
      }
      catch (final InterruptedException ie)
      {
        Debug.debugException(ie);
        Thread.currentThread().interrupt();
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_BIND_INTERRUPTED.get(connection.getHostPort()), ie);
      }

      return handleResponse(connection, response, requestTime);
    }
    finally
    {
      connection.deregisterResponseAcceptor(msgID);
    }
  }



  /**
   * Sends an LDAP message to the directory server and waits for the response.
   * This should only be used when the connection is operating in synchronous
   * mode.
   *
   * @param  connection      The connection to the directory server.
   * @param  requestMessage  The LDAP message to send to the directory server.
   * @param  timeoutMillis   The maximum length of time in milliseconds to wait
   *                         for a response, or zero if it should wait forever.
   *
   * @return  The response message received from the server.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response, or if a timeout occurred
   *                         while waiting for the response.
   */
  @NotNull()
  private BindResult sendMessageSync(@NotNull final LDAPConnection connection,
                                     @NotNull final LDAPMessage requestMessage,
                                     final long timeoutMillis)
            throws LDAPException
  {
    final int msgID = requestMessage.getMessageID();
    Debug.debugLDAPRequest(Level.INFO, this, msgID, connection);

    final LDAPConnectionLogger logger =
         connection.getConnectionOptions().getConnectionLogger();
    if (logger != null)
    {
      logger.logBindRequest(connection, messageID, this);
    }

    final long requestTime = System.nanoTime();
    connection.getConnectionStatistics().incrementNumBindRequests();
    connection.sendMessage(requestMessage, timeoutMillis);

    while (true)
    {
      final LDAPResponse response = connection.readResponse(messageID);
      if (response instanceof IntermediateResponse)
      {
        final IntermediateResponseListener listener =
             getIntermediateResponseListener();
        if (listener != null)
        {
          listener.intermediateResponseReturned(
               (IntermediateResponse) response);
        }
      }
      else
      {
        return handleResponse(connection, response, requestTime);
      }
    }
  }



  /**
   * Performs the necessary processing for handling a response.
   *
   * @param  connection   The connection used to read the response.
   * @param  response     The response to be processed.
   * @param  requestTime  The time the request was sent to the server.
   *
   * @return  The bind result.
   *
   * @throws  LDAPException  If a problem occurs.
   */
  @NotNull()
  private BindResult handleResponse(@NotNull final LDAPConnection connection,
                                    @Nullable final LDAPResponse response,
                                    final long requestTime)
          throws LDAPException
  {
    if (response == null)
    {
      final long waitTime =
           StaticUtils.nanosToMillis(System.nanoTime() - requestTime);
      throw new LDAPException(ResultCode.TIMEOUT,
           ERR_SASL_BIND_CLIENT_TIMEOUT.get(waitTime, getSASLMechanismName(),
                messageID, connection.getHostPort()));
    }

    if (response instanceof ConnectionClosedResponse)
    {
      final ConnectionClosedResponse ccr = (ConnectionClosedResponse) response;
      final String message = ccr.getMessage();
      if (message == null)
      {
        // The connection was closed while waiting for the response.
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_BIND_RESPONSE.get(
                  connection.getHostPort(), toString()));
      }
      else
      {
        // The connection was closed while waiting for the response.
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_BIND_RESPONSE_WITH_MESSAGE.get(
                  connection.getHostPort(), toString(), message));
      }
    }

    connection.getConnectionStatistics().incrementNumBindResponses(
         System.nanoTime() - requestTime);
    return (BindResult) response;
  }



  /**
   * {@inheritDoc}
   */
  @InternalUseOnly()
  @Override()
  public final void responseReceived(@NotNull final LDAPResponse response)
         throws LDAPException
  {
    try
    {
      responseQueue.put(response);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      if (e instanceof InterruptedException)
      {
        Thread.currentThread().interrupt();
      }

      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_EXCEPTION_HANDLING_RESPONSE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toCode(@NotNull final List<String> lineList,
                     @NotNull final String requestID,
                     final int indentSpaces, final boolean includeProcessing)
  {
    // Create the request variable.
    final ArrayList<ToCodeArgHelper> constructorArgs = new ArrayList<>(4);
    constructorArgs.add(ToCodeArgHelper.createString(null, "Bind DN"));
    constructorArgs.add(ToCodeArgHelper.createString(getSASLMechanismName(),
         "SASL Mechanism Name"));
    constructorArgs.add(ToCodeArgHelper.createByteArray(
         "---redacted-SASL-credentials".getBytes(StandardCharsets.UTF_8), true,
         "SASL Credentials"));

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      constructorArgs.add(ToCodeArgHelper.createControlArray(controls,
           "Bind Controls"));
    }

    ToCodeHelper.generateMethodCall(lineList, indentSpaces,
         "GenericSASLBindRequest", requestID + "Request",
         "new GenericSASLBindRequest", constructorArgs);


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
      lineList.add(indent + '{');
      lineList.add(indent + "  BindResult " + requestID +
           "Result = connection.bind(" + requestID + "Request);");
      lineList.add(indent + "  // The bind was processed successfully.");
      lineList.add(indent + '}');
      lineList.add(indent + "catch (SASLBindInProgressException e)");
      lineList.add(indent + '{');
      lineList.add(indent + "  // The SASL bind requires multiple stages.  " +
           "Continue it here.");
      lineList.add(indent + "  // Do not attempt to use the connection for " +
           "any other purpose until bind processing has completed.");
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
      lineList.add(indent + '}');
    }
  }
}
