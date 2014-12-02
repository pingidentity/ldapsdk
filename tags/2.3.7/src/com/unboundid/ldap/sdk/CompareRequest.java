/*
 * Copyright 2007-2014 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2014 UnboundID Corp.
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



import java.util.Timer;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.LDAPResponse;
import com.unboundid.ldap.protocol.ProtocolOp;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.Mutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.LDAPMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



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
  private final LinkedBlockingQueue<LDAPResponse> responseQueue =
       new LinkedBlockingQueue<LDAPResponse>();

  // The assertion value for this compare request.
  private ASN1OctetString assertionValue;

  // The message ID from the last LDAP message sent from this request.
  private int messageID = -1;

  // The name of the target attribute.
  private String attributeName;

  // The DN of the entry in which the comparison is to be performed.
  private String dn;



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
  public CompareRequest(final String dn, final String attributeName,
                        final String assertionValue)
  {
    super(null);

    ensureNotNull(dn, attributeName, assertionValue);

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
  public CompareRequest(final String dn, final String attributeName,
                        final byte[] assertionValue)
  {
    super(null);

    ensureNotNull(dn, attributeName, assertionValue);

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
  public CompareRequest(final DN dn, final String attributeName,
                        final String assertionValue)
  {
    super(null);

    ensureNotNull(dn, attributeName, assertionValue);

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
  public CompareRequest(final DN dn, final String attributeName,
                        final byte[] assertionValue)
  {
    super(null);

    ensureNotNull(dn, attributeName, assertionValue);

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
  public CompareRequest(final String dn, final String attributeName,
                        final String assertionValue, final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, attributeName, assertionValue);

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
  public CompareRequest(final String dn, final String attributeName,
                        final byte[] assertionValue, final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, attributeName, assertionValue);

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
  public CompareRequest(final DN dn, final String attributeName,
                        final String assertionValue, final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, attributeName, assertionValue);

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
  public CompareRequest(final DN dn, final String attributeName,
                        final ASN1OctetString assertionValue,
                        final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, attributeName, assertionValue);

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
  public CompareRequest(final DN dn, final String attributeName,
                        final byte[] assertionValue, final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, attributeName, assertionValue);

    this.dn             = dn.toString();
    this.attributeName  = attributeName;
    this.assertionValue = new ASN1OctetString(assertionValue);
  }



  /**
   * {@inheritDoc}
   */
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
  public void setDN(final String dn)
  {
    ensureNotNull(dn);

    this.dn = dn;
  }



  /**
   * Specifies the DN of the entry in which the comparison is to be performed.
   *
   * @param  dn  The DN of the entry in which the comparison is to be performed.
   *             It must not be {@code null}.
   */
  public void setDN(final DN dn)
  {
    ensureNotNull(dn);

    this.dn = dn.toString();
  }



  /**
   * {@inheritDoc}
   */
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
  public void setAttributeName(final String attributeName)
  {
    ensureNotNull(attributeName);

    this.attributeName = attributeName;
  }



  /**
   * {@inheritDoc}
   */
  public String getAssertionValue()
  {
    return assertionValue.stringValue();
  }



  /**
   * {@inheritDoc}
   */
  public byte[] getAssertionValueBytes()
  {
    return assertionValue.getValue();
  }



  /**
   * {@inheritDoc}
   */
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
  public void setAssertionValue(final String assertionValue)
  {
    ensureNotNull(assertionValue);

    this.assertionValue = new ASN1OctetString(assertionValue);
  }



  /**
   * Specifies the assertion value to specify within the target entry.
   *
   * @param  assertionValue  The assertion value to specify within the target
   *                         entry.  It must not be {@code null}.
   */
  public void setAssertionValue(final byte[] assertionValue)
  {
    ensureNotNull(assertionValue);

    this.assertionValue = new ASN1OctetString(assertionValue);
  }



  /**
   * Specifies the assertion value to specify within the target entry.
   *
   * @param  assertionValue  The assertion value to specify within the target
   *                         entry.  It must not be {@code null}.
   */
  public void setAssertionValue(final ASN1OctetString assertionValue)
  {
    this.assertionValue = assertionValue;
  }



  /**
   * {@inheritDoc}
   */
  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  public void writeTo(final ASN1Buffer buffer)
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
  protected CompareResult process(final LDAPConnection connection,
                                  final int depth)
            throws LDAPException
  {
    if (connection.synchronousMode())
    {
      return processSync(connection, depth,
           connection.getConnectionOptions().autoReconnect());
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
      catch (InterruptedException ie)
      {
        debugException(ie);
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
  AsyncRequestID processAsync(final LDAPConnection connection,
                              final AsyncCompareResultListener resultListener)
                 throws LDAPException
  {
    // Create the LDAP message.
    messageID = connection.nextMessageID();
    final LDAPMessage message = new LDAPMessage(messageID, this, getControls());


    // If the provided async result listener is {@code null}, then we'll use
    // this class as the message acceptor.  Otherwise, create an async helper
    // and use it as the message acceptor.
    final AsyncRequestID asyncRequestID;
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

      final long timeout = getResponseTimeoutMillis(connection);
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
      debugLDAPRequest(this);
      connection.getConnectionStatistics().incrementNumCompareRequests();
      connection.sendMessage(message);
      return asyncRequestID;
    }
    catch (LDAPException le)
    {
      debugException(le);

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
  private CompareResult processSync(final LDAPConnection connection,
                                    final int depth, final boolean allowRetry)
          throws LDAPException
  {
    // Create the LDAP message.
    messageID = connection.nextMessageID();
    final LDAPMessage message =
         new LDAPMessage(messageID,  this, getControls());


    // Set the appropriate timeout on the socket.
    try
    {
      connection.getConnectionInternals(true).getSocket().setSoTimeout(
           (int) getResponseTimeoutMillis(connection));
    }
    catch (Exception e)
    {
      debugException(e);
    }


    // Send the request to the server.
    final long requestTime = System.nanoTime();
    debugLDAPRequest(this);
    connection.getConnectionStatistics().incrementNumCompareRequests();
    try
    {
      connection.sendMessage(message);
    }
    catch (final LDAPException le)
    {
      debugException(le);

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
        debugException(le);

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
  private CompareResult handleResponse(final LDAPConnection connection,
                                       final LDAPResponse response,
                                       final long requestTime, final int depth,
                                       final boolean allowRetry)
          throws LDAPException
  {
    if (response == null)
    {
      final long waitTime = nanosToMillis(System.nanoTime() - requestTime);
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
  private CompareResult reconnectAndRetry(final LDAPConnection connection,
                                          final int depth,
                                          final ResultCode resultCode)
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
      debugException(e);
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
  private CompareResult followReferral(final CompareResult referralResult,
                                       final LDAPConnection connection,
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

        final LDAPConnection referralConn = connection.getReferralConnector().
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
      catch (LDAPException le)
      {
        debugException(le);
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
  public void responseReceived(final LDAPResponse response)
         throws LDAPException
  {
    try
    {
      responseQueue.put(response);
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_EXCEPTION_HANDLING_RESPONSE.get(getExceptionMessage(e)), e);
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
  public OperationType getOperationType()
  {
    return OperationType.COMPARE;
  }



  /**
   * {@inheritDoc}
   */
  public CompareRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  public CompareRequest duplicate(final Control[] controls)
  {
    final CompareRequest r = new CompareRequest(dn, attributeName,
         assertionValue.getValue(), controls);

    if (followReferralsInternal() != null)
    {
      r.setFollowReferrals(followReferralsInternal());
    }

    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));

    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
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
}
