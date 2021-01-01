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
import java.util.Timer;
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
import com.unboundid.util.Debug;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class implements the processing necessary to perform an LDAPv3 compare
 * operation, which may be used to determine whether a specified entry contains
 * a given attribute value.  Compare requests include the DN of the target
 * entry, the name of the target attribute, and the value for which to make the
 * determination.  It may also include a set of controls to send to the server.
 * <BR><BR>
 * The assertion value may be specified as either a string or a byte array.  If
 * it is specified as a byte array, then it may represent either a binary or a
 * string value.  If a string value is provided as a byte array, then it should
 * use the UTF-8 encoding for that value.
 * <BR><BR>
 * {@code CompareRequest} objects are mutable and therefore can be altered and
 * re-used for multiple requests.  Note, however, that {@code CompareRequest}
 * objects are not threadsafe and therefore a single {@code CompareRequest}
 * object instance should not be used to process multiple requests at the same
 * time.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for performing a compare
 * operation:
 * <PRE>
 * CompareRequest compareRequest =
 *      new CompareRequest("dc=example,dc=com", "description", "test");
 * CompareResult compareResult;
 * try
 * {
 *   compareResult = connection.compare(compareRequest);
 *
 *   // The compare operation didn't throw an exception, so we can try to
 *   // determine whether the compare matched.
 *   if (compareResult.compareMatched())
 *   {
 *     // The entry does have a description value of test.
 *   }
 *   else
 *   {
 *     // The entry does not have a description value of test.
 *   }
 * }
 * catch (LDAPException le)
 * {
 *   // The compare operation failed.
 *   compareResult = new CompareResult(le.toLDAPResult());
 *   ResultCode resultCode = le.getResultCode();
 *   String errorMessageFromServer = le.getDiagnosticMessage();
 * }
 * </PRE>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class CompareRequest
       extends UpdatableLDAPRequest
       implements ReadOnlyCompareRequest, ResponseAcceptor, ProtocolOp
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6343453776330347024L;



  // The queue that will be used to receive response messages from the server.
  @NotNull private final LinkedBlockingQueue<LDAPResponse> responseQueue =
       new LinkedBlockingQueue<>();

  // The assertion value for this compare request.
  @NotNull private ASN1OctetString assertionValue;

  // The message ID from the last LDAP message sent from this request.
  private int messageID = -1;

  // The name of the target attribute.
  @NotNull private String attributeName;

  // The DN of the entry in which the comparison is to be performed.
  @NotNull private String dn;



  /**
   * Creates a new compare request with the provided information.
   *
   * @param  dn              The DN of the entry in which the comparison is to
   *                         be performed.  It must not be {@code null}.
   * @param  attributeName   The name of the target attribute for which the
   *                         comparison is to be performed.  It must not be
   *                         {@code null}.
   * @param  assertionValue  The assertion value to verify within the entry.  It
   *                         must not be {@code null}.
   */
  public CompareRequest(@NotNull final String dn,
                        @NotNull final String attributeName,
                        @NotNull final String assertionValue)
  {
    super(null);

    Validator.ensureNotNull(dn, attributeName, assertionValue);

    this.dn             = dn;
    this.attributeName  = attributeName;
    this.assertionValue = new ASN1OctetString(assertionValue);
  }



  /**
   * Creates a new compare request with the provided information.
   *
   * @param  dn              The DN of the entry in which the comparison is to
   *                         be performed.  It must not be {@code null}.
   * @param  attributeName   The name of the target attribute for which the
   *                         comparison is to be performed.  It must not be
   *                         {@code null}.
   * @param  assertionValue  The assertion value to verify within the entry.  It
   *                         must not be {@code null}.
   */
  public CompareRequest(@NotNull final String dn,
                        @NotNull final String attributeName,
                        @NotNull final byte[] assertionValue)
  {
    super(null);

    Validator.ensureNotNull(dn, attributeName, assertionValue);

    this.dn             = dn;
    this.attributeName  = attributeName;
    this.assertionValue = new ASN1OctetString(assertionValue);
  }



  /**
   * Creates a new compare request with the provided information.
   *
   * @param  dn              The DN of the entry in which the comparison is to
   *                         be performed.  It must not be {@code null}.
   * @param  attributeName   The name of the target attribute for which the
   *                         comparison is to be performed.  It must not be
   *                         {@code null}.
   * @param  assertionValue  The assertion value to verify within the entry.  It
   *                         must not be {@code null}.
   */
  public CompareRequest(@NotNull final DN dn,
                        @NotNull final String attributeName,
                        @NotNull final String assertionValue)
  {
    super(null);

    Validator.ensureNotNull(dn, attributeName, assertionValue);

    this.dn             = dn.toString();
    this.attributeName  = attributeName;
    this.assertionValue = new ASN1OctetString(assertionValue);
  }



  /**
   * Creates a new compare request with the provided information.
   *
   * @param  dn              The DN of the entry in which the comparison is to
   *                         be performed.  It must not be {@code null}.
   * @param  attributeName   The name of the target attribute for which the
   *                         comparison is to be performed.  It must not be
   *                         {@code null}.
   * @param  assertionValue  The assertion value to verify within the entry.  It
   *                         must not be {@code null}.
   */
  public CompareRequest(@NotNull final DN dn,
                        @NotNull final String attributeName,
                        @NotNull final byte[] assertionValue)
  {
    super(null);

    Validator.ensureNotNull(dn, attributeName, assertionValue);

    this.dn             = dn.toString();
    this.attributeName  = attributeName;
    this.assertionValue = new ASN1OctetString(assertionValue);
  }



  /**
   * Creates a new compare request with the provided information.
   *
   * @param  dn              The DN of the entry in which the comparison is to
   *                         be performed.  It must not be {@code null}.
   * @param  attributeName   The name of the target attribute for which the
   *                         comparison is to be performed.  It must not be
   *                         {@code null}.
   * @param  assertionValue  The assertion value to verify within the entry.  It
   *                         must not be {@code null}.
   * @param  controls        The set of controls for this compare request.
   */
  public CompareRequest(@NotNull final String dn,
                        @NotNull final String attributeName,
                        @NotNull final String assertionValue,
                        @Nullable final Control[] controls)
  {
    super(controls);

    Validator.ensureNotNull(dn, attributeName, assertionValue);

    this.dn             = dn;
    this.attributeName  = attributeName;
    this.assertionValue = new ASN1OctetString(assertionValue);
  }



  /**
   * Creates a new compare request with the provided information.
   *
   * @param  dn              The DN of the entry in which the comparison is to
   *                         be performed.  It must not be {@code null}.
   * @param  attributeName   The name of the target attribute for which the
   *                         comparison is to be performed.  It must not be
   *                         {@code null}.
   * @param  assertionValue  The assertion value to verify within the entry.  It
   *                         must not be {@code null}.
   * @param  controls        The set of controls for this compare request.
   */
  public CompareRequest(@NotNull final String dn,
                        @NotNull final String attributeName,
                        @NotNull final byte[] assertionValue,
                        @Nullable final Control[] controls)
  {
    super(controls);

    Validator.ensureNotNull(dn, attributeName, assertionValue);

    this.dn             = dn;
    this.attributeName  = attributeName;
    this.assertionValue = new ASN1OctetString(assertionValue);
  }



  /**
   * Creates a new compare request with the provided information.
   *
   * @param  dn              The DN of the entry in which the comparison is to
   *                         be performed.  It must not be {@code null}.
   * @param  attributeName   The name of the target attribute for which the
   *                         comparison is to be performed.  It must not be
   *                         {@code null}.
   * @param  assertionValue  The assertion value to verify within the entry.  It
   *                         must not be {@code null}.
   * @param  controls        The set of controls for this compare request.
   */
  public CompareRequest(@NotNull final DN dn,
                        @NotNull final String attributeName,
                        @NotNull final String assertionValue,
                        @Nullable final Control[] controls)
  {
    super(controls);

    Validator.ensureNotNull(dn, attributeName, assertionValue);

    this.dn             = dn.toString();
    this.attributeName  = attributeName;
    this.assertionValue = new ASN1OctetString(assertionValue);
  }



  /**
   * Creates a new compare request with the provided information.
   *
   * @param  dn              The DN of the entry in which the comparison is to
   *                         be performed.  It must not be {@code null}.
   * @param  attributeName   The name of the target attribute for which the
   *                         comparison is to be performed.  It must not be
   *                         {@code null}.
   * @param  assertionValue  The assertion value to verify within the entry.  It
   *                         must not be {@code null}.
   * @param  controls        The set of controls for this compare request.
   */
  public CompareRequest(@NotNull final DN dn,
                        @NotNull final String attributeName,
                        @NotNull final ASN1OctetString assertionValue,
                        @Nullable final Control[] controls)
  {
    super(controls);

    Validator.ensureNotNull(dn, attributeName, assertionValue);

    this.dn             = dn.toString();
    this.attributeName  = attributeName;
    this.assertionValue = assertionValue;
  }



  /**
   * Creates a new compare request with the provided information.
   *
   * @param  dn              The DN of the entry in which the comparison is to
   *                         be performed.  It must not be {@code null}.
   * @param  attributeName   The name of the target attribute for which the
   *                         comparison is to be performed.  It must not be
   *                         {@code null}.
   * @param  assertionValue  The assertion value to verify within the entry.  It
   *                         must not be {@code null}.
   * @param  controls        The set of controls for this compare request.
   */
  public CompareRequest(@NotNull final DN dn,
                        @NotNull final String attributeName,
                        @NotNull final byte[] assertionValue,
                        @Nullable final Control[] controls)
  {
    super(controls);

    Validator.ensureNotNull(dn, attributeName, assertionValue);

    this.dn             = dn.toString();
    this.attributeName  = attributeName;
    this.assertionValue = new ASN1OctetString(assertionValue);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getDN()
  {
    return dn;
  }



  /**
   * Specifies the DN of the entry in which the comparison is to be performed.
   *
   * @param  dn  The DN of the entry in which the comparison is to be performed.
   *             It must not be {@code null}.
   */
  public void setDN(@NotNull final String dn)
  {
    Validator.ensureNotNull(dn);

    this.dn = dn;
  }



  /**
   * Specifies the DN of the entry in which the comparison is to be performed.
   *
   * @param  dn  The DN of the entry in which the comparison is to be performed.
   *             It must not be {@code null}.
   */
  public void setDN(@NotNull final DN dn)
  {
    Validator.ensureNotNull(dn);

    this.dn = dn.toString();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getAttributeName()
  {
    return attributeName;
  }



  /**
   * Specifies the name of the attribute for which the comparison is to be
   * performed.
   *
   * @param  attributeName  The name of the attribute for which the comparison
   *                        is to be performed.  It must not be {@code null}.
   */
  public void setAttributeName(@NotNull final String attributeName)
  {
    Validator.ensureNotNull(attributeName);

    this.attributeName = attributeName;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getAssertionValue()
  {
    return assertionValue.stringValue();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public byte[] getAssertionValueBytes()
  {
    return assertionValue.getValue();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1OctetString getRawAssertionValue()
  {
    return assertionValue;
  }



  /**
   * Specifies the assertion value to specify within the target entry.
   *
   * @param  assertionValue  The assertion value to specify within the target
   *                         entry.  It must not be {@code null}.
   */
  public void setAssertionValue(@NotNull final String assertionValue)
  {
    Validator.ensureNotNull(assertionValue);

    this.assertionValue = new ASN1OctetString(assertionValue);
  }



  /**
   * Specifies the assertion value to specify within the target entry.
   *
   * @param  assertionValue  The assertion value to specify within the target
   *                         entry.  It must not be {@code null}.
   */
  public void setAssertionValue(@NotNull final byte[] assertionValue)
  {
    Validator.ensureNotNull(assertionValue);

    this.assertionValue = new ASN1OctetString(assertionValue);
  }



  /**
   * Specifies the assertion value to specify within the target entry.
   *
   * @param  assertionValue  The assertion value to specify within the target
   *                         entry.  It must not be {@code null}.
   */
  public void setAssertionValue(@NotNull final ASN1OctetString assertionValue)
  {
    this.assertionValue = assertionValue;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeTo(@NotNull final ASN1Buffer buffer)
  {
    final ASN1BufferSequence requestSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST);
    buffer.addOctetString(dn);

    final ASN1BufferSequence avaSequence = buffer.beginSequence();
    buffer.addOctetString(attributeName);
    buffer.addElement(assertionValue);
    avaSequence.end();
    requestSequence.end();
  }



  /**
   * Encodes the compare request protocol op to an ASN.1 element.
   *
   * @return  The ASN.1 element with the encoded compare request protocol op.
   */
  @Override()
  @NotNull()
  public ASN1Element encodeProtocolOp()
  {
    // Create the compare request protocol op.
    final ASN1Element[] avaElements =
    {
      new ASN1OctetString(attributeName),
      assertionValue
    };

    final ASN1Element[] protocolOpElements =
    {
      new ASN1OctetString(dn),
      new ASN1Sequence(avaElements)
    };

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
                            protocolOpElements);
  }



  /**
   * Sends this delete request to the directory server over the provided
   * connection and returns the associated response.
   *
   * @param  connection  The connection to use to communicate with the directory
   *                     server.
   * @param  depth       The current referral depth for this request.  It should
   *                     always be one for the initial request, and should only
   *                     be incremented when following referrals.
   *
   * @return  An LDAP result object that provides information about the result
   *          of the delete processing.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @Override()
  @NotNull()
  protected CompareResult process(@NotNull final LDAPConnection connection,
                                  final int depth)
            throws LDAPException
  {
    if (connection.synchronousMode())
    {
      @SuppressWarnings("deprecation")
      final boolean autoReconnect =
           connection.getConnectionOptions().autoReconnect();
      return processSync(connection, depth, autoReconnect);
    }

    final long requestTime = System.nanoTime();
    processAsync(connection, null);

    try
    {
      // Wait for and process the response.
      final LDAPResponse response;
      try
      {
        final long responseTimeout = getResponseTimeoutMillis(connection);
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
             ERR_COMPARE_INTERRUPTED.get(connection.getHostPort()), ie);
      }

      return handleResponse(connection, response,  requestTime, depth, false);
    }
    finally
    {
      connection.deregisterResponseAcceptor(messageID);
    }
  }



  /**
   * Sends this compare request to the directory server over the provided
   * connection and returns the message ID for the request.
   *
   * @param  connection      The connection to use to communicate with the
   *                         directory server.
   * @param  resultListener  The async result listener that is to be notified
   *                         when the response is received.  It may be
   *                         {@code null} only if the result is to be processed
   *                         by this class.
   *
   * @return  The async request ID created for the operation, or {@code null} if
   *          the provided {@code resultListener} is {@code null} and the
   *          operation will not actually be processed asynchronously.
   *
   * @throws  LDAPException  If a problem occurs while sending the request.
   */
  @Nullable()
  AsyncRequestID processAsync(@NotNull final LDAPConnection connection,
                      @Nullable final AsyncCompareResultListener resultListener)
                 throws LDAPException
  {
    // Create the LDAP message.
    messageID = connection.nextMessageID();
    final LDAPMessage message = new LDAPMessage(messageID, this, getControls());


    // If the provided async result listener is {@code null}, then we'll use
    // this class as the message acceptor.  Otherwise, create an async helper
    // and use it as the message acceptor.
    final AsyncRequestID asyncRequestID;
    final long timeout = getResponseTimeoutMillis(connection);
    if (resultListener == null)
    {
      asyncRequestID = null;
      connection.registerResponseAcceptor(messageID, this);
    }
    else
    {
      final AsyncCompareHelper compareHelper =
           new AsyncCompareHelper(connection, messageID, resultListener,
                getIntermediateResponseListener());
      connection.registerResponseAcceptor(messageID, compareHelper);
      asyncRequestID = compareHelper.getAsyncRequestID();

      if (timeout > 0L)
      {
        final Timer timer = connection.getTimer();
        final AsyncTimeoutTimerTask timerTask =
             new AsyncTimeoutTimerTask(compareHelper);
        timer.schedule(timerTask, timeout);
        asyncRequestID.setTimerTask(timerTask);
      }
    }


    // Send the request to the server.
    try
    {
      Debug.debugLDAPRequest(Level.INFO, this, messageID, connection);

      final LDAPConnectionLogger logger =
           connection.getConnectionOptions().getConnectionLogger();
      if (logger != null)
      {
        logger.logCompareRequest(connection, messageID, this);
      }

      connection.getConnectionStatistics().incrementNumCompareRequests();
      connection.sendMessage(message, timeout);
      return asyncRequestID;
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);

      connection.deregisterResponseAcceptor(messageID);
      throw le;
    }
  }



  /**
   * Processes this compare operation in synchronous mode, in which the same
   * thread will send the request and read the response.
   *
   * @param  connection  The connection to use to communicate with the directory
   *                     server.
   * @param  depth       The current referral depth for this request.  It should
   *                     always be one for the initial request, and should only
   *                     be incremented when following referrals.
   * @param  allowRetry   Indicates whether the request may be re-tried on a
   *                      re-established connection if the initial attempt fails
   *                      in a way that indicates the connection is no longer
   *                      valid and autoReconnect is true.
   *
   * @return  An LDAP result object that provides information about the result
   *          of the compare processing.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @NotNull()
  private CompareResult processSync(@NotNull final LDAPConnection connection,
                                    final int depth, final boolean allowRetry)
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
      logger.logCompareRequest(connection, messageID, this);
    }

    connection.getConnectionStatistics().incrementNumCompareRequests();
    try
    {
      connection.sendMessage(message, getResponseTimeoutMillis(connection));
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);

      if (allowRetry)
      {
        final CompareResult retryResult = reconnectAndRetry(connection, depth,
             le.getResultCode());
        if (retryResult != null)
        {
          return retryResult;
        }
      }

      throw le;
    }

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

        if (allowRetry)
        {
          final CompareResult retryResult = reconnectAndRetry(connection, depth,
               le.getResultCode());
          if (retryResult != null)
          {
            return retryResult;
          }
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
        return handleResponse(connection, response, requestTime, depth,
             allowRetry);
      }
    }
  }



  /**
   * Performs the necessary processing for handling a response.
   *
   * @param  connection   The connection used to read the response.
   * @param  response     The response to be processed.
   * @param  requestTime  The time the request was sent to the server.
   * @param  depth        The current referral depth for this request.  It
   *                      should always be one for the initial request, and
   *                      should only be incremented when following referrals.
   * @param  allowRetry   Indicates whether the request may be re-tried on a
   *                      re-established connection if the initial attempt fails
   *                      in a way that indicates the connection is no longer
   *                      valid and autoReconnect is true.
   *
   * @return  The compare result.
   *
   * @throws  LDAPException  If a problem occurs.
   */
  @NotNull()
  private CompareResult handleResponse(@NotNull final LDAPConnection connection,
                                       @Nullable final LDAPResponse response,
                                       final long requestTime, final int depth,
                                       final boolean allowRetry)
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
           ERR_COMPARE_CLIENT_TIMEOUT.get(waitTime, messageID, dn,
                connection.getHostPort()));
    }

    connection.getConnectionStatistics().incrementNumCompareResponses(
         System.nanoTime() - requestTime);
    if (response instanceof ConnectionClosedResponse)
    {
      // The connection was closed while waiting for the response.
      if (allowRetry)
      {
        final CompareResult retryResult = reconnectAndRetry(connection, depth,
             ResultCode.SERVER_DOWN);
        if (retryResult != null)
        {
          return retryResult;
        }
      }

      final ConnectionClosedResponse ccr = (ConnectionClosedResponse) response;
      final String message = ccr.getMessage();
      if (message == null)
      {
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_COMPARE_RESPONSE.get(
                  connection.getHostPort(), toString()));
      }
      else
      {
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_COMPARE_RESPONSE_WITH_MESSAGE.get(
                  connection.getHostPort(), toString(), message));
      }
    }

    final CompareResult result;
    if (response instanceof CompareResult)
    {
      result = (CompareResult) response;
    }
    else
    {
      result = new CompareResult((LDAPResult) response);
    }

    if ((result.getResultCode().equals(ResultCode.REFERRAL)) &&
        followReferrals(connection))
    {
      if (depth >= connection.getConnectionOptions().getReferralHopLimit())
      {
        return new CompareResult(messageID,
                                 ResultCode.REFERRAL_LIMIT_EXCEEDED,
                                 ERR_TOO_MANY_REFERRALS.get(),
                                 result.getMatchedDN(),
                                 result.getReferralURLs(),
                                 result.getResponseControls());
      }

      return followReferral(result, connection, depth);
    }
    else
    {
      if (allowRetry)
      {
        final CompareResult retryResult = reconnectAndRetry(connection, depth,
             result.getResultCode());
        if (retryResult != null)
        {
          return retryResult;
        }
      }

      return result;
    }
  }



  /**
   * Attempts to re-establish the connection and retry processing this request
   * on it.
   *
   * @param  connection  The connection to be re-established.
   * @param  depth       The current referral depth for this request.  It should
   *                     always be one for the initial request, and should only
   *                     be incremented when following referrals.
   * @param  resultCode  The result code for the previous operation attempt.
   *
   * @return  The result from re-trying the compare, or {@code null} if it could
   *          not be re-tried.
   */
  @Nullable()
  private CompareResult reconnectAndRetry(
                             @NotNull final LDAPConnection connection,
                             final int depth,
                             @NotNull final ResultCode resultCode)
  {
    try
    {
      // We will only want to retry for certain result codes that indicate a
      // connection problem.
      switch (resultCode.intValue())
      {
        case ResultCode.SERVER_DOWN_INT_VALUE:
        case ResultCode.DECODING_ERROR_INT_VALUE:
        case ResultCode.CONNECT_ERROR_INT_VALUE:
          connection.reconnect();
          return processSync(connection, depth, false);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    return null;
  }



  /**
   * Attempts to follow a referral to perform a compare operation in the target
   * server.
   *
   * @param  referralResult  The LDAP result object containing information about
   *                         the referral to follow.
   * @param  connection      The connection on which the referral was received.
   * @param  depth           The number of referrals followed in the course of
   *                         processing this request.
   *
   * @return  The result of attempting to process the compare operation by
   *          following the referral.
   *
   * @throws  LDAPException  If a problem occurs while attempting to establish
   *                         the referral connection, sending the request, or
   *                         reading the result.
   */
  @NotNull()
  private CompareResult followReferral(
                             @NotNull final CompareResult referralResult,
                             @NotNull final LDAPConnection connection,
                             final int depth)
          throws LDAPException
  {
    for (final String urlString : referralResult.getReferralURLs())
    {
      try
      {
        final LDAPURL referralURL = new LDAPURL(urlString);
        final String host = referralURL.getHost();

        if (host == null)
        {
          // We can't handle a referral in which there is no host.
          continue;
        }

        final CompareRequest compareRequest;
        if (referralURL.baseDNProvided())
        {
          compareRequest = new CompareRequest(referralURL.getBaseDN(),
                                              attributeName, assertionValue,
                                              getControls());
        }
        else
        {
          compareRequest = this;
        }

        final LDAPConnection referralConn = getReferralConnector(connection).
             getReferralConnection(referralURL, connection);
        try
        {
          return compareRequest.process(referralConn, depth+1);
        }
        finally
        {
          referralConn.setDisconnectInfo(DisconnectType.REFERRAL, null, null);
          referralConn.close();
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
      }
    }

    // If we've gotten here, then we could not follow any of the referral URLs,
    // so we'll just return the original referral result.
    return referralResult;
  }



  /**
   * {@inheritDoc}
   */
  @InternalUseOnly()
  @Override()
  public void responseReceived(@NotNull final LDAPResponse response)
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
  public int getLastMessageID()
  {
    return messageID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public OperationType getOperationType()
  {
    return OperationType.COMPARE;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public CompareRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public CompareRequest duplicate(@Nullable final Control[] controls)
  {
    final CompareRequest r = new CompareRequest(dn, attributeName,
         assertionValue.getValue(), controls);

    if (followReferralsInternal() != null)
    {
      r.setFollowReferrals(followReferralsInternal());
    }

    if (getReferralConnectorInternal() != null)
    {
      r.setReferralConnector(getReferralConnectorInternal());
    }

    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));

    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("CompareRequest(dn='");
    buffer.append(dn);
    buffer.append("', attr='");
    buffer.append(attributeName);
    buffer.append("', value='");
    buffer.append(assertionValue.stringValue());
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
                     final int indentSpaces,
                     final boolean includeProcessing)
  {
    // Create the arguments for the request variable.
    final ArrayList<ToCodeArgHelper> constructorArgs = new ArrayList<>(3);
    constructorArgs.add(ToCodeArgHelper.createString(dn, "Entry DN"));
    constructorArgs.add(ToCodeArgHelper.createString(attributeName,
         "Attribute Name"));

    // If the attribute is one that we consider sensitive, then we'll use a
    // redacted value.  Otherwise, try to use the string value if it's
    // printable, or a byte array value if it's not.
    if (StaticUtils.isSensitiveToCodeAttribute(attributeName))
    {
      constructorArgs.add(ToCodeArgHelper.createString("---redacted-value",
           "Assertion Value (Redacted because " + attributeName + " is " +
                "configured as a sensitive attribute)"));
    }
    else if (StaticUtils.isPrintableString(assertionValue.getValue()))
    {
      constructorArgs.add(ToCodeArgHelper.createString(
           assertionValue.stringValue(),
           "Assertion Value"));
    }
    else
    {
      constructorArgs.add(ToCodeArgHelper.createByteArray(
           assertionValue.getValue(), true,
           "Assertion Value"));
    }

    ToCodeHelper.generateMethodCall(lineList, indentSpaces, "CompareRequest",
         requestID + "Request", "new CompareRequest", constructorArgs);


    // If there are any controls, then add them to the request.
    for (final Control c : getControls())
    {
      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "Request.addControl",
           ToCodeArgHelper.createControl(c, null));
    }


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
      lineList.add(indent + "  CompareResult " + requestID +
           "Result = connection.compare(" + requestID + "Request);");
      lineList.add(indent + "  // The compare was processed successfully.");
      lineList.add(indent + "  boolean compareMatched = " + requestID +
           "Result.compareMatched();");
      lineList.add(indent + '}');
      lineList.add(indent + "catch (LDAPException e)");
      lineList.add(indent + '{');
      lineList.add(indent + "  // The compare failed.  Maybe the following " +
           "will help explain why.");
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
