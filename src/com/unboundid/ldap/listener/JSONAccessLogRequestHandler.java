/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import java.net.Socket;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

import com.unboundid.ldap.protocol.AbandonRequestProtocolOp;
import com.unboundid.ldap.protocol.AddRequestProtocolOp;
import com.unboundid.ldap.protocol.AddResponseProtocolOp;
import com.unboundid.ldap.protocol.BindRequestProtocolOp;
import com.unboundid.ldap.protocol.BindResponseProtocolOp;
import com.unboundid.ldap.protocol.CompareRequestProtocolOp;
import com.unboundid.ldap.protocol.CompareResponseProtocolOp;
import com.unboundid.ldap.protocol.DeleteRequestProtocolOp;
import com.unboundid.ldap.protocol.DeleteResponseProtocolOp;
import com.unboundid.ldap.protocol.ExtendedRequestProtocolOp;
import com.unboundid.ldap.protocol.ExtendedResponseProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.ModifyRequestProtocolOp;
import com.unboundid.ldap.protocol.ModifyResponseProtocolOp;
import com.unboundid.ldap.protocol.ModifyDNRequestProtocolOp;
import com.unboundid.ldap.protocol.ModifyDNResponseProtocolOp;
import com.unboundid.ldap.protocol.SearchRequestProtocolOp;
import com.unboundid.ldap.protocol.SearchResultDoneProtocolOp;
import com.unboundid.ldap.protocol.SearchResultEntryProtocolOp;
import com.unboundid.ldap.protocol.UnbindRequestProtocolOp;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.json.JSONBuffer;



/**
 * This class provides a request handler that may be used to log each request
 * and result using the Java logging framework.  Messages will be formatted as
 * JSON objects.  It will be also be associated with another request handler
 * that will actually be used to handle the request.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JSONAccessLogRequestHandler
       extends LDAPListenerRequestHandler
       implements SearchEntryTransformer
{
  // The operation ID counter that will be used for this request handler
  // instance.
  @Nullable private final AtomicLong nextOperationID;

  // A map used to correlate the number of search result entries returned for a
  // particular message ID.
  @NotNull private final ConcurrentHashMap<Integer,AtomicLong> entryCounts;

  // The log handler that will be used to log the messages.
  @NotNull private final Handler logHandler;

  // The client connection with which this request handler is associated.
  @Nullable private final LDAPListenerClientConnection clientConnection;

  // The request handler that actually will be used to process any requests
  // received.
  @NotNull private final LDAPListenerRequestHandler requestHandler;

  // The thread-local decimal formatters that will be used to format etime
  // values.
  @NotNull private final ThreadLocal<DecimalFormat> decimalFormatters;

  // The thread-local JSON buffers that will be used to format log message
  // objects.
  @NotNull private final ThreadLocal<JSONBuffer> jsonBuffers;

  // The thread-local date formatters that will be used to format timestamps.
  @NotNull private final ThreadLocal<SimpleDateFormat> timestampFormatters;



  /**
   * Creates a new JSON-formatted access log request handler that will log
   * request and result messages using the provided log handler, and will
   * process client requests using the provided request handler.
   *
   * @param  logHandler      The log handler that will be used to log request
   *                         and result messages.  Note that all messages will
   *                         be logged at the INFO level.  It must not be
   *                         {@code null}.  Note that the log handler will not
   *                         be automatically closed when the associated
   *                         listener is shut down.
   * @param  requestHandler  The request handler that will actually be used to
   *                         process any requests received.  It must not be
   *                         {@code null}.
   */
  public JSONAccessLogRequestHandler(@NotNull final Handler logHandler,
              @NotNull final LDAPListenerRequestHandler requestHandler)
  {
    Validator.ensureNotNull(logHandler, requestHandler);

    this.logHandler = logHandler;
    this.requestHandler = requestHandler;

    nextOperationID = null;
    clientConnection = null;
    entryCounts = new ConcurrentHashMap<>(StaticUtils.computeMapCapacity(50));
    jsonBuffers = new ThreadLocal<>();
    timestampFormatters = new ThreadLocal<>();
    decimalFormatters = new ThreadLocal<>();
  }



  /**
   * Creates a new JSON-formatted access log request handler that will log
   * request and result messages using the provided log handler, and will
   * process client requests using the provided request handler.
   *
   * @param  logHandler           The log handler that will be used to log
   *                              request and result messages.  Note that all
   *                              messages will be logged at the INFO level.  It
   *                              must not be {@code null}.
   * @param  requestHandler       The request handler that will actually be used
   *                              to process any requests received.  It must not
   *                              be {@code null}.
   * @param  clientConnection     The client connection with which this instance
   *                              is associated.
   * @param  jsonBuffers          The thread-local JSON buffers that will be
   *                              used to format log message objects.
   * @param  timestampFormatters  The thread-local date formatters that will be
   *                              used to format timestamps.
   * @param  decimalFormatters    The thread-local decimal formatters that
   *                              will be used to format etime values.
   */
  private JSONAccessLogRequestHandler(@NotNull final Handler logHandler,
               @NotNull final LDAPListenerRequestHandler requestHandler,
               @NotNull final LDAPListenerClientConnection clientConnection,
               @NotNull final ThreadLocal<JSONBuffer> jsonBuffers,
               @NotNull final ThreadLocal<SimpleDateFormat> timestampFormatters,
               @NotNull final ThreadLocal<DecimalFormat> decimalFormatters)
  {
    this.logHandler = logHandler;
    this.requestHandler = requestHandler;
    this.clientConnection = clientConnection;
    this.jsonBuffers = jsonBuffers;
    this.timestampFormatters = timestampFormatters;
    this.decimalFormatters = decimalFormatters;

    nextOperationID = new AtomicLong(0L);
    entryCounts = new ConcurrentHashMap<>(StaticUtils.computeMapCapacity(50));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public JSONAccessLogRequestHandler newInstance(
              @NotNull final LDAPListenerClientConnection connection)
         throws LDAPException
  {
    final JSONAccessLogRequestHandler h =
         new JSONAccessLogRequestHandler(logHandler,
              requestHandler.newInstance(connection), connection, jsonBuffers,
              timestampFormatters, decimalFormatters);
    connection.addSearchEntryTransformer(h);

    final JSONBuffer buffer = h.getConnectionHeader("connect");

    final Socket s = connection.getSocket();
    buffer.appendString("from-address", s.getInetAddress().getHostAddress());
    buffer.appendNumber("from-port", s.getPort());
    buffer.appendString("to-address", s.getLocalAddress().getHostAddress());
    buffer.appendNumber("to-port", s.getLocalPort());
    buffer.endObject();

    logHandler.publish(new LogRecord(Level.INFO, buffer.toString()));
    logHandler.flush();

    return h;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void closeInstance()
  {
    final JSONBuffer buffer = getConnectionHeader("disconnect");
    buffer.endObject();

    logHandler.publish(new LogRecord(Level.INFO, buffer.toString()));
    logHandler.flush();

    requestHandler.closeInstance();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processAbandonRequest(final int messageID,
                   @NotNull final AbandonRequestProtocolOp request,
                   @NotNull final List<Control> controls)
  {
    final JSONBuffer buffer = getRequestHeader("abandon",
         nextOperationID.incrementAndGet(), messageID);

    buffer.appendNumber("id-to-abandon", request.getIDToAbandon());
    buffer.endObject();

    logHandler.publish(new LogRecord(Level.INFO, buffer.toString()));
    logHandler.flush();

    requestHandler.processAbandonRequest(messageID, request, controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processAddRequest(final int messageID,
                          @NotNull final AddRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    final long opID = nextOperationID.getAndIncrement();
    final JSONBuffer buffer = getRequestHeader("add", opID, messageID);

    buffer.appendString("dn", request.getDN());
    buffer.endObject();

    logHandler.publish(new LogRecord(Level.INFO, buffer.toString()));
    logHandler.flush();

    final long startTimeNanos = System.nanoTime();
    final LDAPMessage responseMessage = requestHandler.processAddRequest(
         messageID, request, controls);
    final long eTimeNanos = System.nanoTime() - startTimeNanos;
    final AddResponseProtocolOp protocolOp =
         responseMessage.getAddResponseProtocolOp();

    generateResponse(buffer, "add", opID, messageID,
         protocolOp.getResultCode(), protocolOp.getDiagnosticMessage(),
         protocolOp.getMatchedDN(), protocolOp.getReferralURLs(), eTimeNanos);
    buffer.endObject();

    logHandler.publish(new LogRecord(Level.INFO, buffer.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processBindRequest(final int messageID,
                          @NotNull final BindRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    final long opID = nextOperationID.getAndIncrement();

    final JSONBuffer buffer = getRequestHeader("bind", opID, messageID);
    buffer.appendNumber("ldap-version", request.getVersion());
    buffer.appendString("dn", request.getBindDN());

    switch (request.getCredentialsType())
    {
      case BindRequestProtocolOp.CRED_TYPE_SIMPLE:
        buffer.appendString("authentication-type", "simple");
        break;

      case BindRequestProtocolOp.CRED_TYPE_SASL:
        buffer.appendString("authentication-type", "sasl");
        buffer.appendString("sasl-mechanism", request.getSASLMechanism());
        break;
    }
    buffer.endObject();

    logHandler.publish(new LogRecord(Level.INFO, buffer.toString()));
    logHandler.flush();

    final long startTimeNanos = System.nanoTime();
    final LDAPMessage responseMessage = requestHandler.processBindRequest(
         messageID, request, controls);
    final long eTimeNanos = System.nanoTime() - startTimeNanos;
    final BindResponseProtocolOp protocolOp =
         responseMessage.getBindResponseProtocolOp();

    generateResponse(buffer, "bind", opID, messageID,
         protocolOp.getResultCode(), protocolOp.getDiagnosticMessage(),
         protocolOp.getMatchedDN(), protocolOp.getReferralURLs(), eTimeNanos);
    buffer.endObject();

    logHandler.publish(new LogRecord(Level.INFO, buffer.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processCompareRequest(final int messageID,
                          @NotNull final CompareRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    final long opID = nextOperationID.getAndIncrement();

    final JSONBuffer buffer = getRequestHeader("compare", opID, messageID);
    buffer.appendString("dn", request.getDN());
    buffer.appendString("attribute-type", request.getAttributeName());
    buffer.endObject();

    logHandler.publish(new LogRecord(Level.INFO, buffer.toString()));
    logHandler.flush();

    final long startTimeNanos = System.nanoTime();
    final LDAPMessage responseMessage = requestHandler.processCompareRequest(
         messageID, request, controls);
    final long eTimeNanos = System.nanoTime() - startTimeNanos;
    final CompareResponseProtocolOp protocolOp =
         responseMessage.getCompareResponseProtocolOp();

    generateResponse(buffer, "compare", opID, messageID,
         protocolOp.getResultCode(), protocolOp.getDiagnosticMessage(),
         protocolOp.getMatchedDN(), protocolOp.getReferralURLs(), eTimeNanos);
    buffer.endObject();

    logHandler.publish(new LogRecord(Level.INFO, buffer.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processDeleteRequest(final int messageID,
                          @NotNull final DeleteRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    final long opID = nextOperationID.getAndIncrement();

    final JSONBuffer buffer = getRequestHeader("delete", opID, messageID);
    buffer.appendString("dn", request.getDN());
    buffer.endObject();

    logHandler.publish(new LogRecord(Level.INFO, buffer.toString()));
    logHandler.flush();

    final long startTimeNanos = System.nanoTime();
    final LDAPMessage responseMessage = requestHandler.processDeleteRequest(
         messageID, request, controls);
    final long eTimeNanos = System.nanoTime() - startTimeNanos;
    final DeleteResponseProtocolOp protocolOp =
         responseMessage.getDeleteResponseProtocolOp();

    generateResponse(buffer, "delete", opID, messageID,
         protocolOp.getResultCode(),
         protocolOp.getDiagnosticMessage(), protocolOp.getMatchedDN(),
         protocolOp.getReferralURLs(), eTimeNanos);
    buffer.endObject();

    logHandler.publish(new LogRecord(Level.INFO, buffer.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processExtendedRequest(final int messageID,
                          @NotNull final ExtendedRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    final long opID = nextOperationID.getAndIncrement();

    final JSONBuffer buffer = getRequestHeader("extended", opID, messageID);
    buffer.appendString("request-oid", request.getOID());
    buffer.endObject();

    logHandler.publish(new LogRecord(Level.INFO, buffer.toString()));
    logHandler.flush();

    final long startTimeNanos = System.nanoTime();
    final LDAPMessage responseMessage = requestHandler.processExtendedRequest(
         messageID, request, controls);
    final long eTimeNanos = System.nanoTime() - startTimeNanos;
    final ExtendedResponseProtocolOp protocolOp =
         responseMessage.getExtendedResponseProtocolOp();

    generateResponse(buffer, "extended", opID, messageID,
         protocolOp.getResultCode(), protocolOp.getDiagnosticMessage(),
         protocolOp.getMatchedDN(), protocolOp.getReferralURLs(), eTimeNanos);

    final String responseOID = protocolOp.getResponseOID();
    if (responseOID != null)
    {
      buffer.appendString("response-oid", responseOID);
    }

    buffer.endObject();

    logHandler.publish(new LogRecord(Level.INFO, buffer.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processModifyRequest(final int messageID,
                          @NotNull final ModifyRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    final long opID = nextOperationID.getAndIncrement();

    final JSONBuffer buffer = getRequestHeader("modify", opID, messageID);
    buffer.appendString("dn", request.getDN());
    buffer.endObject();

    logHandler.publish(new LogRecord(Level.INFO, buffer.toString()));
    logHandler.flush();

    final long startTimeNanos = System.nanoTime();
    final LDAPMessage responseMessage = requestHandler.processModifyRequest(
         messageID, request, controls);
    final long eTimeNanos = System.nanoTime() - startTimeNanos;
    final ModifyResponseProtocolOp protocolOp =
         responseMessage.getModifyResponseProtocolOp();

    generateResponse(buffer, "modify", opID, messageID,
         protocolOp.getResultCode(), protocolOp.getDiagnosticMessage(),
         protocolOp.getMatchedDN(), protocolOp.getReferralURLs(), eTimeNanos);
    buffer.endObject();

    logHandler.publish(new LogRecord(Level.INFO, buffer.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processModifyDNRequest(final int messageID,
                          @NotNull final ModifyDNRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    final long opID = nextOperationID.getAndIncrement();

    final JSONBuffer buffer = getRequestHeader("modify-dn", opID, messageID);
    buffer.appendString("dn", request.getDN());
    buffer.appendString("new-rdn", request.getNewRDN());
    buffer.appendBoolean("delete-old-rdn", request.deleteOldRDN());

    final String newSuperior = request.getNewSuperiorDN();
    if (newSuperior != null)
    {
      buffer.appendString("new-superior", newSuperior);
    }
    buffer.endObject();

    logHandler.publish(new LogRecord(Level.INFO, buffer.toString()));
    logHandler.flush();

    final long startTimeNanos = System.nanoTime();
    final LDAPMessage responseMessage = requestHandler.processModifyDNRequest(
         messageID, request, controls);
    final long eTimeNanos = System.nanoTime() - startTimeNanos;
    final ModifyDNResponseProtocolOp protocolOp =
         responseMessage.getModifyDNResponseProtocolOp();

    generateResponse(buffer, "modify-dn", opID, messageID,
         protocolOp.getResultCode(), protocolOp.getDiagnosticMessage(),
         protocolOp.getMatchedDN(), protocolOp.getReferralURLs(), eTimeNanos);
    buffer.endObject();

    logHandler.publish(new LogRecord(Level.INFO, buffer.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processSearchRequest(final int messageID,
                          @NotNull final SearchRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    final long opID = nextOperationID.getAndIncrement();

    final JSONBuffer buffer = getRequestHeader("search", opID, messageID);
    buffer.appendString("base", request.getBaseDN());
    buffer.appendNumber("scope", request.getScope().intValue());
    buffer.appendString("filter", request.getFilter().toString());

    buffer.beginArray("requested-attributes");
    for (final String requestedAttribute : request.getAttributes())
    {
      buffer.appendString(requestedAttribute);
    }
    buffer.endArray();
    buffer.endObject();

    logHandler.publish(new LogRecord(Level.INFO, buffer.toString()));
    logHandler.flush();

    final AtomicLong entryCounter = new AtomicLong(0L);
    entryCounts.put(messageID, entryCounter);

    try
    {
      final long startTimeNanos = System.nanoTime();
      final LDAPMessage responseMessage = requestHandler.processSearchRequest(
           messageID, request, controls);
      final long eTimeNanos = System.nanoTime() - startTimeNanos;
      final SearchResultDoneProtocolOp protocolOp =
           responseMessage.getSearchResultDoneProtocolOp();

      generateResponse(buffer, "search", opID, messageID,
           protocolOp.getResultCode(), protocolOp.getDiagnosticMessage(),
           protocolOp.getMatchedDN(), protocolOp.getReferralURLs(), eTimeNanos);
      buffer.appendNumber("entries-returned", entryCounter.get());
      buffer.endObject();

      logHandler.publish(new LogRecord(Level.INFO, buffer.toString()));
      logHandler.flush();

      return responseMessage;
    }
    finally
    {
      entryCounts.remove(messageID);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processUnbindRequest(final int messageID,
                   @NotNull final UnbindRequestProtocolOp request,
                   @NotNull final List<Control> controls)
  {
    final JSONBuffer buffer = getRequestHeader("unbind",
         nextOperationID.getAndIncrement(), messageID);
    buffer.endObject();

    logHandler.publish(new LogRecord(Level.INFO, buffer.toString()));
    logHandler.flush();

    requestHandler.processUnbindRequest(messageID, request, controls);
  }



  /**
   * Retrieves a JSON buffer that can be used to construct a log message.
   *
   * @return  A JSON buffer that can be used to construct a log message.
   */
  @NotNull()
  private JSONBuffer getBuffer()
  {
    JSONBuffer buffer = jsonBuffers.get();
    if (buffer == null)
    {
      buffer = new JSONBuffer();
      jsonBuffers.set(buffer);
    }
    else
    {
      buffer.clear();
    }

    return buffer;
  }



  /**
   * Adds a timestamp to the provided buffer.
   *
   * @param  buffer  The buffer to which the timestamp should be added.
   */
  private void addTimestamp(@NotNull final JSONBuffer buffer)
  {
    SimpleDateFormat timestampFormatter = timestampFormatters.get();
    if (timestampFormatter == null)
    {
      timestampFormatter =
           new SimpleDateFormat("yyyy'-'MM'-'dd'T'HH':'mm':'ss.SSS'Z'");
      timestampFormatter.setTimeZone(StaticUtils.getUTCTimeZone());
      timestampFormatters.set(timestampFormatter);
    }

    buffer.appendString("timestamp", timestampFormatter.format(new Date()));
  }



  /**
   * Retrieves a {@code JSONBuffer} with header information for a connect log
   * message for the specified type of operation.
   *
   * @param  messageType  The type of operation being requested.
   *
   * @return  A {@code JSONBuffer} with header information appended for the
   *          connection;
   */
  @NotNull()
  private JSONBuffer getConnectionHeader(@NotNull final String messageType)
  {
    final JSONBuffer buffer = getBuffer();
    buffer.beginObject();
    addTimestamp(buffer);
    buffer.appendString("message-type", messageType);
    buffer.appendNumber("connection-id", clientConnection.getConnectionID());

    return buffer;
  }



  /**
   * Retrieves a {@code JSONBuffer} with header information for a request log
   * message for the specified type of operation.
   *
   * @param  opType  The type of operation being requested.
   * @param  opID    The operation ID for the request.
   * @param  msgID   The message ID for the request.
   *
   * @return  A {@code StringBuilder} with header information appended for the
   *          request;
   */
  @NotNull()
  private JSONBuffer getRequestHeader(@NotNull final String opType,
                                      final long opID, final int msgID)
  {
    final JSONBuffer buffer = getBuffer();
    buffer.beginObject();
    addTimestamp(buffer);
    buffer.appendString("message-type", "request");
    buffer.appendString("operation-type", opType);
    buffer.appendNumber("connection-id", clientConnection.getConnectionID());
    buffer.appendNumber("operation-id", opID);
    buffer.appendNumber("message-id", msgID);

    return buffer;
  }



  /**
   * Updates the provided JSON buffer with information about the result of
   * processing an operation.
   *
   * @param  buffer             The buffer to which the information will be
   *                            written.  It will be cleared before adding any
   *                            content.
   * @param  opType             The type of operation that was processed.
   * @param  opID               The operation ID for the response.
   * @param  msgID              The message ID for the response.
   * @param  resultCode         The result code for the response, if any.
   * @param  diagnosticMessage  The diagnostic message for the response, if any.
   * @param  matchedDN          The matched DN for the response, if any.
   * @param  referralURLs       The referral URLs for the response, if any.
   * @param  eTimeNanos         The length of time in nanoseconds required to
   *                            process the operation.
   */
  private void generateResponse(@NotNull final JSONBuffer buffer,
                                @NotNull final String opType,
                                final long opID, final int msgID,
                                final int resultCode,
                                @Nullable final String diagnosticMessage,
                                @Nullable final String matchedDN,
                                @NotNull final List<String> referralURLs,
                                final long eTimeNanos)
  {
    buffer.clear();

    buffer.beginObject();
    addTimestamp(buffer);
    buffer.appendString("message-type", "response");
    buffer.appendString("operation-type", opType);
    buffer.appendNumber("connection-id", clientConnection.getConnectionID());
    buffer.appendNumber("operation-id", opID);
    buffer.appendNumber("message-id", msgID);
    buffer.appendNumber("result-code-value", resultCode);

    final ResultCode rc = ResultCode.valueOf(resultCode, null, false);
    if (rc != null)
    {
      buffer.appendString("result-code-name", rc.getName());
    }

    if (diagnosticMessage != null)
    {
      buffer.appendString("diagnostic-message", diagnosticMessage);
    }

    if (matchedDN != null)
    {
      buffer.appendString("matched-dn", matchedDN);
    }

    if (! referralURLs.isEmpty())
    {
      buffer.beginArray("referral-urls");
      for (final String url : referralURLs)
      {
        buffer.appendString(url);
      }
      buffer.endArray();
    }

    DecimalFormat decimalFormat = decimalFormatters.get();
    if (decimalFormat == null)
    {
      decimalFormat = new DecimalFormat("0.000");
      decimalFormatters.set(decimalFormat);
    }
    final double eTimeMillis = eTimeNanos / 1_000_000.0d;
    buffer.appendNumber("processing-time-millis",
         decimalFormat.format(eTimeMillis));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ObjectPair<SearchResultEntryProtocolOp,Control[]> transformEntry(
              final int messageID,
              @NotNull final SearchResultEntryProtocolOp entry,
              @NotNull final Control[] controls)
  {
    final AtomicLong l = entryCounts.get(messageID);
    if (l != null)
    {
      l.incrementAndGet();
    }

    return new ObjectPair<>(entry, controls);
  }
}
