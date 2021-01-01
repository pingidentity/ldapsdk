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



import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.LDAPResponse;
import com.unboundid.ldap.protocol.ProtocolOp;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.Debug;
import com.unboundid.util.Extensible;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class implements the processing necessary to perform an LDAPv3 extended
 * operation, which provides a way to request actions not included in the core
 * LDAP protocol.  Subclasses can provide logic to help implement more specific
 * types of extended operations, but it is important to note that if such
 * subclasses include an extended request value, then the request value must be
 * kept up-to-date if any changes are made to custom elements in that class that
 * would impact the request value encoding.
 */
@Extensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public class ExtendedRequest
       extends LDAPRequest
       implements ResponseAcceptor, ProtocolOp
{
  /**
   * The BER type for the extended request OID element.
   */
  protected static final byte TYPE_EXTENDED_REQUEST_OID = (byte) 0x80;



  /**
   * The BER type for the extended request value element.
   */
  protected static final byte TYPE_EXTENDED_REQUEST_VALUE = (byte) 0x81;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5572410770060685796L;



  // The encoded value for this extended request, if available.
  @Nullable private final ASN1OctetString value;

  // The message ID from the last LDAP message sent from this request.
  private int messageID = -1;

  // The queue that will be used to receive response messages from the server.
  @NotNull private final LinkedBlockingQueue<LDAPResponse> responseQueue =
       new LinkedBlockingQueue<>();

  // The OID for this extended request.
  @NotNull private final String oid;



  /**
   * Creates a new extended request with the provided OID and no value.
   *
   * @param  oid  The OID for this extended request.  It must not be
   *              {@code null}.
   */
  public ExtendedRequest(@NotNull final String oid)
  {
    super(null);

    Validator.ensureNotNull(oid);

    this.oid = oid;

    value = null;
  }



  /**
   * Creates a new extended request with the provided OID and no value.
   *
   * @param  oid       The OID for this extended request.  It must not be
   *                   {@code null}.
   * @param  controls  The set of controls for this extended request.
   */
  public ExtendedRequest(@NotNull final String oid,
                         @Nullable final Control[] controls)
  {
    super(controls);

    Validator.ensureNotNull(oid);

    this.oid = oid;

    value = null;
  }



  /**
   * Creates a new extended request with the provided OID and value.
   *
   * @param  oid    The OID for this extended request.  It must not be
   *                {@code null}.
   * @param  value  The encoded value for this extended request.  It may be
   *                {@code null} if this request should not have a value.
   */
  public ExtendedRequest(@NotNull final String oid,
                         @Nullable final ASN1OctetString value)
  {
    super(null);

    Validator.ensureNotNull(oid);

    this.oid   = oid;
    this.value = value;
  }



  /**
   * Creates a new extended request with the provided OID and value.
   *
   * @param  oid       The OID for this extended request.  It must not be
   *                   {@code null}.
   * @param  value     The encoded value for this extended request.  It may be
   *                   {@code null} if this request should not have a value.
   * @param  controls  The set of controls for this extended request.
   */
  public ExtendedRequest(@NotNull final String oid,
                         @Nullable final ASN1OctetString value,
                         @Nullable final Control[] controls)
  {
    super(controls);

    Validator.ensureNotNull(oid);

    this.oid   = oid;
    this.value = value;
  }



  /**
   * Creates a new extended request with the information from the provided
   * extended request.
   *
   * @param  extendedRequest  The extended request that should be used to create
   *                          this new extended request.
   */
  protected ExtendedRequest(@NotNull final ExtendedRequest extendedRequest)
  {
    super(extendedRequest.getControls());

    messageID = extendedRequest.messageID;
    oid = extendedRequest.oid;
    value = extendedRequest.value;
  }



  /**
   * Retrieves the OID for this extended request.
   *
   * @return  The OID for this extended request.
   */
  @NotNull()
  public final String getOID()
  {
    return oid;
  }



  /**
   * Indicates whether this extended request has a value.
   *
   * @return  {@code true} if this extended request has a value, or
   *          {@code false} if not.
   */
  public final boolean hasValue()
  {
    return (value != null);
  }



  /**
   * Retrieves the encoded value for this extended request, if available.
   *
   * @return  The encoded value for this extended request, or {@code null} if
   *          this request does not have a value.
   */
  @Nullable()
  public final ASN1OctetString getValue()
  {
    return value;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public final byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public final void writeTo(@NotNull final ASN1Buffer writer)
  {
    final ASN1BufferSequence requestSequence =
         writer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST);
    writer.addOctetString(TYPE_EXTENDED_REQUEST_OID, oid);

    if (value != null)
    {
      writer.addOctetString(TYPE_EXTENDED_REQUEST_VALUE, value.getValue());
    }
    requestSequence.end();
  }



  /**
   * Encodes the extended request protocol op to an ASN.1 element.
   *
   * @return  The ASN.1 element with the encoded extended request protocol op.
   */
  @Override()
  @NotNull()
  public ASN1Element encodeProtocolOp()
  {
    // Create the extended request protocol op.
    final ASN1Element[] protocolOpElements;
    if (value == null)
    {
      protocolOpElements = new ASN1Element[]
      {
        new ASN1OctetString(TYPE_EXTENDED_REQUEST_OID, oid)
      };
    }
    else
    {
      protocolOpElements = new ASN1Element[]
      {
        new ASN1OctetString(TYPE_EXTENDED_REQUEST_OID, oid),
        new ASN1OctetString(TYPE_EXTENDED_REQUEST_VALUE, value.getValue())
      };
    }

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
                            protocolOpElements);
  }



  /**
   * Sends this extended request to the directory server over the provided
   * connection and returns the associated response.
   *
   * @param  connection  The connection to use to communicate with the directory
   *                     server.
   * @param  depth       The current referral depth for this request.  It should
   *                     always be one for the initial request, and should only
   *                     be incremented when following referrals.
   *
   * @return  An LDAP result object that provides information about the result
   *          of the extended operation processing.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @Override()
  @NotNull()
  protected ExtendedResult process(@NotNull final LDAPConnection connection,
                                   final int depth)
            throws LDAPException
  {
    if (connection.synchronousMode())
    {
      return processSync(connection);
    }

    // Create the LDAP message.
    messageID = connection.nextMessageID();
    final LDAPMessage message = new LDAPMessage(messageID, this, getControls());


    // Register with the connection reader to be notified of responses for the
    // request that we've created.
    connection.registerResponseAcceptor(messageID, this);


    try
    {
      // Send the request to the server.
      final long responseTimeout = getResponseTimeoutMillis(connection);
      Debug.debugLDAPRequest(Level.INFO, this, messageID, connection);

      final LDAPConnectionLogger logger =
           connection.getConnectionOptions().getConnectionLogger();
      if (logger != null)
      {
        logger.logExtendedRequest(connection, messageID, this);
      }

      final long requestTime = System.nanoTime();
      connection.getConnectionStatistics().incrementNumExtendedRequests();
      if (this instanceof StartTLSExtendedRequest)
      {
        connection.sendMessage(message, 50L);
      }
      else
      {
        connection.sendMessage(message, responseTimeout);
      }

      // Wait for and process the response.
      final LDAPResponse response;
      try
      {
        if (responseTimeout > 0)
        {
          response = responseQueue.poll(responseTimeout, TimeUnit.MILLISECONDS);
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
             ERR_EXTOP_INTERRUPTED.get(connection.getHostPort()), ie);
      }

      return handleResponse(connection, response, requestTime);
    }
    finally
    {
      connection.deregisterResponseAcceptor(messageID);
    }
  }



  /**
   * Processes this extended operation in synchronous mode, in which the same
   * thread will send the request and read the response.
   *
   * @param  connection  The connection to use to communicate with the directory
   *                     server.
   *
   * @return  An LDAP result object that provides information about the result
   *          of the extended processing.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @NotNull()
  private ExtendedResult processSync(@NotNull final LDAPConnection connection)
          throws LDAPException
  {
    // Create the LDAP message.
    messageID = connection.nextMessageID();
    final LDAPMessage message =
         new LDAPMessage(messageID,  this, getControls());


    // Send the request to the server.
    final long requestTime = System.nanoTime();
    Debug.debugLDAPRequest(Level.INFO, this, messageID, connection);

    final LDAPConnectionLogger logger =
         connection.getConnectionOptions().getConnectionLogger();
    if (logger != null)
    {
      logger.logExtendedRequest(connection, messageID, this);
    }

    connection.getConnectionStatistics().incrementNumExtendedRequests();
    connection.sendMessage(message, getResponseTimeoutMillis(connection));

    while (true)
    {
      final LDAPResponse response;
      try
      {
        response = connection.readResponse(messageID);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);

        if ((le.getResultCode() == ResultCode.TIMEOUT) &&
            connection.getConnectionOptions().abandonOnTimeout())
        {
          connection.abandon(messageID);
        }

        throw le;
      }

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
   * @return  The extended result.
   *
   * @throws  LDAPException  If a problem occurs.
   */
  @NotNull()
  private ExtendedResult handleResponse(
                              @NotNull final LDAPConnection connection,
                              @Nullable final LDAPResponse response,
                              final long requestTime)
          throws LDAPException
  {
    if (response == null)
    {
      final long waitTime =
           StaticUtils.nanosToMillis(System.nanoTime() - requestTime);
      if (connection.getConnectionOptions().abandonOnTimeout())
      {
        connection.abandon(messageID);
      }

      throw new LDAPException(ResultCode.TIMEOUT,
           ERR_EXTENDED_CLIENT_TIMEOUT.get(waitTime, messageID, oid,
                connection.getHostPort()));
    }

    if (response instanceof ConnectionClosedResponse)
    {
      final ConnectionClosedResponse ccr = (ConnectionClosedResponse) response;
      final String msg = ccr.getMessage();
      if (msg == null)
      {
        // The connection was closed while waiting for the response.
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_EXTENDED_RESPONSE.get(
                  connection.getHostPort(), toString()));
      }
      else
      {
        // The connection was closed while waiting for the response.
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_EXTENDED_RESPONSE_WITH_MESSAGE.get(
                  connection.getHostPort(), toString(), msg));
      }
    }

    connection.getConnectionStatistics().incrementNumExtendedResponses(
         System.nanoTime() - requestTime);
    return (ExtendedResult) response;
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
  public final int getLastMessageID()
  {
    return messageID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public final OperationType getOperationType()
  {
    return OperationType.EXTENDED;
  }



  /**
   * {@inheritDoc}.  Subclasses should override this method to return a
   * duplicate of the appropriate type.
   */
  @Override()
  @NotNull()
  public ExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}.  Subclasses should override this method to return a
   * duplicate of the appropriate type.
   */
  @Override()
  @NotNull()
  public ExtendedRequest duplicate(@Nullable final Control[] controls)
  {
    final ExtendedRequest r = new ExtendedRequest(oid, value, controls);
    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return r;
  }



  /**
   * Retrieves the user-friendly name for the extended request, if available.
   * If no user-friendly name has been defined, then the OID will be returned.
   *
   * @return  The user-friendly name for this extended request, or the OID if no
   *          user-friendly name is available.
   */
  @NotNull()
  public String getExtendedRequestName()
  {
    // By default, we will return the OID.  Subclasses should override this to
    // provide the user-friendly name.
    return oid;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ExtendedRequest(oid='");
    buffer.append(oid);
    buffer.append('\'');

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append(", controls={");
      for (int i=0; i < controls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(controls[i]);
      }
      buffer.append('}');
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
    // Create the request variable.
    final ArrayList<ToCodeArgHelper> constructorArgs = new ArrayList<>(3);
    constructorArgs.add(ToCodeArgHelper.createString(oid, "Request OID"));
    constructorArgs.add(ToCodeArgHelper.createASN1OctetString(value,
         "Request Value"));

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      constructorArgs.add(ToCodeArgHelper.createControlArray(controls,
           "Request Controls"));
    }

    ToCodeHelper.generateMethodCall(lineList, indentSpaces, "ExtendedRequest",
         requestID + "Request", "new ExtendedRequest", constructorArgs);


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
      lineList.add(indent + "  ExtendedResult " + requestID +
           "Result = connection.processExtendedOperation(" + requestID +
           "Request);");
      lineList.add(indent + "  // The extended operation was processed and " +
           "we have a result.");
      lineList.add(indent + "  // This does not necessarily mean that the " +
           "operation was successful.");
      lineList.add(indent + "  // Examine the result details for more " +
           "information.");
      lineList.add(indent + "  ResultCode resultCode = " + requestID +
           "Result.getResultCode();");
      lineList.add(indent + "  String message = " + requestID +
           "Result.getMessage();");
      lineList.add(indent + "  String matchedDN = " + requestID +
           "Result.getMatchedDN();");
      lineList.add(indent + "  String[] referralURLs = " + requestID +
           "Result.getReferralURLs();");
      lineList.add(indent + "  String responseOID = " + requestID +
           "Result.getOID();");
      lineList.add(indent + "  ASN1OctetString responseValue = " + requestID +
           "Result.getValue();");
      lineList.add(indent + "  Control[] responseControls = " + requestID +
           "Result.getResponseControls();");
      lineList.add(indent + '}');
      lineList.add(indent + "catch (LDAPException e)");
      lineList.add(indent + '{');
      lineList.add(indent + "  // A problem was encountered while attempting " +
           "to process the extended operation.");
      lineList.add(indent + "  // Maybe the following will help explain why.");
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
