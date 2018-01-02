/*
 * Copyright 2010-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2010-2018 Ping Identity Corporation
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
import java.util.Iterator;
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
import com.unboundid.util.NotMutable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a request handler that may be used to log each request
 * and result using the Java logging framework.  It will be also be associated
 * with another request handler that will actually be used to handle the
 * request.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AccessLogRequestHandler
       extends LDAPListenerRequestHandler
       implements SearchEntryTransformer
{
  /**
   * The thread-local decimal formatters that will be used to format etime
   * values.
   */
  private static final ThreadLocal<DecimalFormat> DECIMAL_FORMATTERS =
       new ThreadLocal<DecimalFormat>();



  /**
   * The thread-local date formatters that will be used to format timestamps.
   */
  private static final ThreadLocal<SimpleDateFormat> DATE_FORMATTERS =
       new ThreadLocal<SimpleDateFormat>();



  /**
   * The thread-local buffers that will be used to hold the log messages as they
   * are being generated.
   */
  private static final ThreadLocal<StringBuilder> BUFFERS =
       new ThreadLocal<StringBuilder>();



  // The operation ID counter that will be used for this request handler
  // instance.
  private final AtomicLong nextOperationID;

  // A map used to correlate the number of search result entries returned for a
  // particular message ID.
  private final ConcurrentHashMap<Integer,AtomicLong> entryCounts =
       new ConcurrentHashMap<Integer,AtomicLong>();

  // The log handler that will be used to log the messages.
  private final Handler logHandler;

  // The client connection with which this request handler is associated.
  private final LDAPListenerClientConnection clientConnection;

  // The request handler that actually will be used to process any requests
  // received.
  private final LDAPListenerRequestHandler requestHandler;



  /**
   * Creates a new access log request handler that will log request and result
   * messages using the provided log handler, and will process client requests
   * using the provided request handler.
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
  public AccessLogRequestHandler(final Handler logHandler,
              final LDAPListenerRequestHandler requestHandler)
  {
    Validator.ensureNotNull(logHandler, requestHandler);

    this.logHandler     = logHandler;
    this.requestHandler = requestHandler;

    nextOperationID  = null;
    clientConnection = null;
  }



  /**
   * Creates a new access log request handler that will log request and result
   * messages using the provided log handler, and will process client requests
   * using the provided request handler.
   *
   * @param  logHandler        The log handler that will be used to log request
   *                           and result messages.  Note that all messages will
   *                           be logged at the INFO level.  It must not be
   *                           {@code null}.
   * @param  requestHandler    The request handler that will actually be used to
   *                           process any requests received.  It must not be
   *                           {@code null}.
   * @param  clientConnection  The client connection with which this instance is
   *                           associated.
   */
  private AccessLogRequestHandler(final Handler logHandler,
               final LDAPListenerRequestHandler requestHandler,
               final LDAPListenerClientConnection clientConnection)
  {
    this.logHandler       = logHandler;
    this.requestHandler   = requestHandler;
    this.clientConnection = clientConnection;

    nextOperationID  = new AtomicLong(0L);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public AccessLogRequestHandler newInstance(
              final LDAPListenerClientConnection connection)
         throws LDAPException
  {
    final AccessLogRequestHandler h = new AccessLogRequestHandler(logHandler,
         requestHandler.newInstance(connection), connection);
    connection.addSearchEntryTransformer(h);

    final StringBuilder b = h.getConnectionHeader("CONNECT");

    final Socket s = connection.getSocket();
    b.append(" from=\"");
    b.append(s.getInetAddress().getHostAddress());
    b.append(':');
    b.append(s.getPort());
    b.append("\" to=\"");
    b.append(s.getLocalAddress().getHostAddress());
    b.append(':');
    b.append(s.getLocalPort());
    b.append('"');

    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    return h;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void closeInstance()
  {
    final StringBuilder b = getConnectionHeader("DISCONNECT");
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    requestHandler.closeInstance();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processAbandonRequest(final int messageID,
                                    final AbandonRequestProtocolOp request,
                                    final List<Control> controls)
  {
    final StringBuilder b = getRequestHeader("ABANDON",
         nextOperationID.getAndIncrement(), messageID);

    b.append(" idToAbandon=");
    b.append(request.getIDToAbandon());

    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    requestHandler.processAbandonRequest(messageID, request, controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processAddRequest(final int messageID,
                                       final AddRequestProtocolOp request,
                                       final List<Control> controls)
  {
    final long opID = nextOperationID.getAndIncrement();

    final StringBuilder b = getRequestHeader("ADD", opID, messageID);

    b.append(" dn=\"");
    b.append(request.getDN());
    b.append('"');

    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    final long startTimeNanos = System.nanoTime();
    final LDAPMessage responseMessage = requestHandler.processAddRequest(
         messageID, request, controls);
    final long eTimeNanos = System.nanoTime() - startTimeNanos;
    final AddResponseProtocolOp protocolOp =
         responseMessage.getAddResponseProtocolOp();

    generateResponse(b, "ADD", opID, messageID, protocolOp.getResultCode(),
         protocolOp.getDiagnosticMessage(), protocolOp.getMatchedDN(),
         protocolOp.getReferralURLs(), eTimeNanos);

    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processBindRequest(final int messageID,
                                        final BindRequestProtocolOp request,
                                        final List<Control> controls)
  {
    final long opID = nextOperationID.getAndIncrement();

    final StringBuilder b = getRequestHeader("BIND", opID, messageID);

    b.append(" version=");
    b.append(request.getVersion());
    b.append(" dn=\"");
    b.append(request.getBindDN());
    b.append("\" authType=\"");

    switch (request.getCredentialsType())
    {
      case BindRequestProtocolOp.CRED_TYPE_SIMPLE:
        b.append("SIMPLE");
        break;

      case BindRequestProtocolOp.CRED_TYPE_SASL:
        b.append("SASL ");
        b.append(request.getSASLMechanism());
        break;
    }

    b.append('"');

    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    final long startTimeNanos = System.nanoTime();
    final LDAPMessage responseMessage = requestHandler.processBindRequest(
         messageID, request, controls);
    final long eTimeNanos = System.nanoTime() - startTimeNanos;
    final BindResponseProtocolOp protocolOp =
         responseMessage.getBindResponseProtocolOp();

    generateResponse(b, "BIND", opID, messageID, protocolOp.getResultCode(),
         protocolOp.getDiagnosticMessage(), protocolOp.getMatchedDN(),
         protocolOp.getReferralURLs(), eTimeNanos);

    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processCompareRequest(final int messageID,
                          final CompareRequestProtocolOp request,
                          final List<Control> controls)
  {
    final long opID = nextOperationID.getAndIncrement();

    final StringBuilder b = getRequestHeader("COMPARE", opID, messageID);

    b.append(" dn=\"");
    b.append(request.getDN());
    b.append("\" attr=\"");
    b.append(request.getAttributeName());
    b.append('"');

    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    final long startTimeNanos = System.nanoTime();
    final LDAPMessage responseMessage = requestHandler.processCompareRequest(
         messageID, request, controls);
    final long eTimeNanos = System.nanoTime() - startTimeNanos;
    final CompareResponseProtocolOp protocolOp =
         responseMessage.getCompareResponseProtocolOp();

    generateResponse(b, "COMPARE", opID, messageID, protocolOp.getResultCode(),
         protocolOp.getDiagnosticMessage(), protocolOp.getMatchedDN(),
         protocolOp.getReferralURLs(), eTimeNanos);

    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processDeleteRequest(final int messageID,
                                          final DeleteRequestProtocolOp request,
                                          final List<Control> controls)
  {
    final long opID = nextOperationID.getAndIncrement();

    final StringBuilder b = getRequestHeader("DELETE", opID, messageID);

    b.append(" dn=\"");
    b.append(request.getDN());
    b.append('"');

    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    final long startTimeNanos = System.nanoTime();
    final LDAPMessage responseMessage = requestHandler.processDeleteRequest(
         messageID, request, controls);
    final long eTimeNanos = System.nanoTime() - startTimeNanos;
    final DeleteResponseProtocolOp protocolOp =
         responseMessage.getDeleteResponseProtocolOp();

    generateResponse(b, "DELETE", opID, messageID, protocolOp.getResultCode(),
         protocolOp.getDiagnosticMessage(), protocolOp.getMatchedDN(),
         protocolOp.getReferralURLs(), eTimeNanos);

    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processExtendedRequest(final int messageID,
                          final ExtendedRequestProtocolOp request,
                          final List<Control> controls)
  {
    final long opID = nextOperationID.getAndIncrement();

    final StringBuilder b = getRequestHeader("EXTENDED", opID, messageID);

    b.append(" requestOID=\"");
    b.append(request.getOID());
    b.append('"');

    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    final long startTimeNanos = System.nanoTime();
    final LDAPMessage responseMessage = requestHandler.processExtendedRequest(
         messageID, request, controls);
    final long eTimeNanos = System.nanoTime() - startTimeNanos;
    final ExtendedResponseProtocolOp protocolOp =
         responseMessage.getExtendedResponseProtocolOp();

    generateResponse(b, "EXTENDED", opID, messageID, protocolOp.getResultCode(),
         protocolOp.getDiagnosticMessage(), protocolOp.getMatchedDN(),
         protocolOp.getReferralURLs(), eTimeNanos);

    final String responseOID = protocolOp.getResponseOID();
    if (responseOID != null)
    {
      b.append(" responseOID=\"");
      b.append(responseOID);
      b.append('"');
    }

    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processModifyRequest(final int messageID,
                                          final ModifyRequestProtocolOp request,
                                          final List<Control> controls)
  {
    final long opID = nextOperationID.getAndIncrement();

    final StringBuilder b = getRequestHeader("MODIFY", opID, messageID);

    b.append(" dn=\"");
    b.append(request.getDN());
    b.append('"');

    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    final long startTimeNanos = System.nanoTime();
    final LDAPMessage responseMessage = requestHandler.processModifyRequest(
         messageID, request, controls);
    final long eTimeNanos = System.nanoTime() - startTimeNanos;
    final ModifyResponseProtocolOp protocolOp =
         responseMessage.getModifyResponseProtocolOp();

    generateResponse(b, "MODIFY", opID, messageID, protocolOp.getResultCode(),
         protocolOp.getDiagnosticMessage(), protocolOp.getMatchedDN(),
         protocolOp.getReferralURLs(), eTimeNanos);

    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processModifyDNRequest(final int messageID,
                          final ModifyDNRequestProtocolOp request,
                          final List<Control> controls)
  {
    final long opID = nextOperationID.getAndIncrement();

    final StringBuilder b = getRequestHeader("MODDN", opID, messageID);

    b.append(" dn=\"");
    b.append(request.getDN());
    b.append("\" newRDN=\"");
    b.append(request.getNewRDN());
    b.append("\" deleteOldRDN=");
    b.append(request.deleteOldRDN());

    final String newSuperior = request.getNewSuperiorDN();
    if (newSuperior != null)
    {
      b.append(" newSuperior=\"");
      b.append(newSuperior);
      b.append('"');
    }

    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    final long startTimeNanos = System.nanoTime();
    final LDAPMessage responseMessage = requestHandler.processModifyDNRequest(
         messageID, request, controls);
    final long eTimeNanos = System.nanoTime() - startTimeNanos;
    final ModifyDNResponseProtocolOp protocolOp =
         responseMessage.getModifyDNResponseProtocolOp();

    generateResponse(b, "MODDN", opID, messageID, protocolOp.getResultCode(),
         protocolOp.getDiagnosticMessage(), protocolOp.getMatchedDN(),
         protocolOp.getReferralURLs(), eTimeNanos);

    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processSearchRequest(final int messageID,
                                          final SearchRequestProtocolOp request,
                                          final List<Control> controls)
  {
    final long opID = nextOperationID.getAndIncrement();

    final StringBuilder b = getRequestHeader("SEARCH", opID, messageID);

    b.append(" base=\"");
    b.append(request.getBaseDN());
    b.append("\" scope=");
    b.append(request.getScope().intValue());
    b.append(" filter=\"");
    request.getFilter().toString(b);
    b.append("\" attrs=\"");

    final List<String> attrList = request.getAttributes();
    if (attrList.isEmpty())
    {
      b.append("ALL");
    }
    else
    {
      final Iterator<String> iterator = attrList.iterator();
      while (iterator.hasNext())
      {
        b.append(iterator.next());
        if (iterator.hasNext())
        {
          b.append(',');
        }
      }
    }

    b.append('"');

    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    final AtomicLong l = new AtomicLong(0L);
    entryCounts.put(messageID, l);

    try
    {
      final long startTimeNanos = System.nanoTime();
      final LDAPMessage responseMessage = requestHandler.processSearchRequest(
           messageID, request, controls);
      final long eTimeNanos = System.nanoTime() - startTimeNanos;
      final SearchResultDoneProtocolOp protocolOp =
           responseMessage.getSearchResultDoneProtocolOp();

      generateResponse(b, "SEARCH", opID, messageID, protocolOp.getResultCode(),
           protocolOp.getDiagnosticMessage(), protocolOp.getMatchedDN(),
           protocolOp.getReferralURLs(), eTimeNanos);

      b.append(" entriesReturned=");
      b.append(l.get());

      logHandler.publish(new LogRecord(Level.INFO, b.toString()));
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
                                   final UnbindRequestProtocolOp request,
                                   final List<Control> controls)
  {
    final StringBuilder b = getRequestHeader("UNBIND",
         nextOperationID.getAndIncrement(), messageID);

    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    requestHandler.processUnbindRequest(messageID, request, controls);
  }



  /**
   * Retrieves a string builder that can be used to construct a log message.
   *
   * @return  A string builder that can be used to construct a log message.
   */
  private static StringBuilder getBuffer()
  {
    StringBuilder b = BUFFERS.get();
    if (b == null)
    {
      b = new StringBuilder();
      BUFFERS.set(b);
    }
    else
    {
      b.setLength(0);
    }

    return b;
  }



  /**
   * Adds a timestamp to the beginning of the provided buffer.
   *
   * @param  buffer  The buffer to which the timestamp should be added.
   */
  private static void addTimestamp(final StringBuilder buffer)
  {
    SimpleDateFormat dateFormat = DATE_FORMATTERS.get();
    if (dateFormat == null)
    {
      dateFormat = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
      DATE_FORMATTERS.set(dateFormat);
    }

    buffer.append(dateFormat.format(new Date()));
  }



  /**
   * Retrieves a {@code StringBuilder} with header information for a request log
   * message for the specified type of operation.
   *
   * @param  messageType  The type of operation being requested.
   *
   * @return  A {@code StringBuilder} with header information appended for the
   *          request;
   */
  private StringBuilder getConnectionHeader(final String messageType)
  {
    final StringBuilder b = getBuffer();
    addTimestamp(b);
    b.append(' ');
    b.append(messageType);
    b.append(" conn=");
    b.append(clientConnection.getConnectionID());

    return b;
  }



  /**
   * Retrieves a {@code StringBuilder} with header information for a request log
   * message for the specified type of operation.
   *
   * @param  opType  The type of operation being requested.
   * @param  opID    The operation ID for the request.
   * @param  msgID   The message ID for the request.
   *
   * @return  A {@code StringBuilder} with header information appended for the
   *          request;
   */
  private StringBuilder getRequestHeader(final String opType, final long opID,
                                         final int msgID)
  {
    final StringBuilder b = getBuffer();
    addTimestamp(b);
    b.append(' ');
    b.append(opType);
    b.append(" REQUEST conn=");
    b.append(clientConnection.getConnectionID());
    b.append(" op=");
    b.append(opID);
    b.append(" msgID=");
    b.append(msgID);

    return b;
  }



  /**
   * Writes information about the result of processing an operation to the
   * given buffer.
   *
   * @param  b                  The buffer to which the information should be
   *                            written.  The buffer will be cleared before
   *                            adding any additional content.
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
  private void generateResponse(final StringBuilder b, final String opType,
                                final long opID, final int msgID,
                                final int resultCode,
                                final String diagnosticMessage,
                                final String matchedDN,
                                final List<String> referralURLs,
                                final long eTimeNanos)
  {
    b.setLength(0);
    addTimestamp(b);
    b.append(' ');
    b.append(opType);
    b.append(" RESULT conn=");
    b.append(clientConnection.getConnectionID());
    b.append(" op=");
    b.append(opID);
    b.append(" msgID=");
    b.append(msgID);
    b.append(" resultCode=");
    b.append(resultCode);

    if (diagnosticMessage != null)
    {
      b.append(" diagnosticMessage=\"");
      b.append(diagnosticMessage);
      b.append('"');
    }

    if (matchedDN != null)
    {
      b.append(" matchedDN=\"");
      b.append(matchedDN);
      b.append('"');
    }

    if (! referralURLs.isEmpty())
    {
      b.append(" referralURLs=\"");
      final Iterator<String> iterator = referralURLs.iterator();
      while (iterator.hasNext())
      {
        b.append(iterator.next());

        if (iterator.hasNext())
        {
          b.append(',');
        }
      }

      b.append('"');
    }

    DecimalFormat f = DECIMAL_FORMATTERS.get();
    if (f == null)
    {
      f = new DecimalFormat("0.000");
      DECIMAL_FORMATTERS.set(f);
    }

    b.append(" etime=");
    b.append(f.format(eTimeNanos / 1000000.0d));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ObjectPair<SearchResultEntryProtocolOp,Control[]> transformEntry(
              final int messageID, final SearchResultEntryProtocolOp entry,
              final Control[] controls)
  {
    final AtomicLong l = entryCounts.get(messageID);
    if (l != null)
    {
      l.incrementAndGet();
    }

    return new ObjectPair<SearchResultEntryProtocolOp,Control[]>(entry,
         controls);
  }
}
