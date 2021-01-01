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



import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.protocol.AddResponseProtocolOp;
import com.unboundid.ldap.protocol.BindResponseProtocolOp;
import com.unboundid.ldap.protocol.CompareResponseProtocolOp;
import com.unboundid.ldap.protocol.DeleteResponseProtocolOp;
import com.unboundid.ldap.protocol.ExtendedResponseProtocolOp;
import com.unboundid.ldap.protocol.IntermediateResponseProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.ModifyResponseProtocolOp;
import com.unboundid.ldap.protocol.ModifyDNResponseProtocolOp;
import com.unboundid.ldap.protocol.SearchResultDoneProtocolOp;
import com.unboundid.ldap.protocol.SearchResultEntryProtocolOp;
import com.unboundid.ldap.protocol.SearchResultReferenceProtocolOp;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPRuntimeException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.extensions.NoticeOfDisconnectionExtendedResult;
import com.unboundid.util.Debug;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class provides an object which will be used to represent a connection to
 * a client accepted by an {@link LDAPListener}, although connections may also
 * be created independently if they were accepted in some other way.  Each
 * connection has its own thread that will be used to read requests from the
 * client, and connections created outside of an {@code LDAPListener} instance,
 * then the thread must be explicitly started.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPListenerClientConnection
       extends Thread
       implements Closeable
{
  /**
   * A pre-allocated empty array of controls.
   */
  @NotNull private static final Control[] EMPTY_CONTROL_ARRAY = new Control[0];



  // The buffer used to hold responses to be sent to the client.
  @NotNull private final ASN1Buffer asn1Buffer;

  // The ASN.1 stream reader used to read requests from the client.
  @NotNull private volatile ASN1StreamReader asn1Reader;

  // Indicates whether to suppress the next call to sendMessage to send a
  // response to the client.
  @NotNull private final AtomicBoolean suppressNextResponse;

  // The set of intermediate response transformers for this connection.
  @NotNull private final CopyOnWriteArrayList<IntermediateResponseTransformer>
       intermediateResponseTransformers;

  // The set of search result entry transformers for this connection.
  @NotNull private final CopyOnWriteArrayList<SearchEntryTransformer>
       searchEntryTransformers;

  // The set of search result reference transformers for this connection.
  @NotNull private final CopyOnWriteArrayList<SearchReferenceTransformer>
       searchReferenceTransformers;

  // The listener that accepted this connection.
  @Nullable private final LDAPListener listener;

  // The exception handler to use for this connection, if any.
  @Nullable private final LDAPListenerExceptionHandler exceptionHandler;

  // The request handler to use for this connection.
  @NotNull private final LDAPListenerRequestHandler requestHandler;

  // The connection ID assigned to this connection.
  private final long connectionID;

  // The output stream used to write responses to the client.
  @NotNull private volatile OutputStream outputStream;

  // The socket used to communicate with the client.
  @NotNull private volatile Socket socket;



  /**
   * Creates a new LDAP listener client connection that will communicate with
   * the client using the provided socket.  The {@link #start} method must be
   * called to start listening for requests from the client.
   *
   * @param  listener          The listener that accepted this client
   *                           connection.  It may be {@code null} if this
   *                           connection was not accepted by a listener.
   * @param  socket            The socket that may be used to communicate with
   *                           the client.  It must not be {@code null}.
   * @param  requestHandler    The request handler that will be used to process
   *                           requests read from the client.  The
   *                           {@link LDAPListenerRequestHandler#newInstance}
   *                           method will be called on the provided object to
   *                           obtain a new instance to use for this connection.
   *                           The provided request handler must not be
   *                           {@code null}.
   * @param  exceptionHandler  The disconnect handler to be notified when this
   *                           connection is closed.  It may be {@code null} if
   *                           no disconnect handler should be used.
   *
   * @throws  LDAPException  If a problem occurs while preparing this client
   *                         connection. for use.  If this is thrown, then the
   *                         provided socket will be closed.
   */
  public LDAPListenerClientConnection(@Nullable final LDAPListener listener,
              @NotNull final Socket socket,
              @NotNull final LDAPListenerRequestHandler requestHandler,
              @Nullable final LDAPListenerExceptionHandler exceptionHandler)
         throws LDAPException
  {
    Validator.ensureNotNull(socket, requestHandler);

    setName("LDAPListener client connection reader for connection from " +
         socket.getInetAddress().getHostAddress() + ':' +
         socket.getPort() + " to " + socket.getLocalAddress().getHostAddress() +
         ':' + socket.getLocalPort());

    this.listener         = listener;
    this.socket           = socket;
    this.exceptionHandler = exceptionHandler;

    asn1Buffer           = new ASN1Buffer();
    suppressNextResponse = new AtomicBoolean(false);

    intermediateResponseTransformers = new CopyOnWriteArrayList<>();
    searchEntryTransformers = new CopyOnWriteArrayList<>();
    searchReferenceTransformers = new CopyOnWriteArrayList<>();

    if (listener == null)
    {
      connectionID = -1L;
    }
    else
    {
      connectionID = listener.nextConnectionID();
    }

    try
    {
      final LDAPListenerConfig config;
      if (listener == null)
      {
        config = new LDAPListenerConfig(0, requestHandler);
      }
      else
      {
        config = listener.getConfig();
      }

      socket.setKeepAlive(config.useKeepAlive());
      socket.setReuseAddress(config.useReuseAddress());
      socket.setSoLinger(config.useLinger(), config.getLingerTimeoutSeconds());
      socket.setTcpNoDelay(config.useTCPNoDelay());

      final int sendBufferSize = config.getSendBufferSize();
      if (sendBufferSize > 0)
      {
        socket.setSendBufferSize(sendBufferSize);
      }

      if (socket instanceof SSLSocket)
      {
        final SSLSocket sslSocket = (SSLSocket) socket;
        if (config.requestClientCertificate())
        {
          if (config.requireClientCertificate())
          {
            sslSocket.setNeedClientAuth(true);
          }
          else
          {
            sslSocket.setWantClientAuth(true);
          }
        }
        else
        {
          sslSocket.setWantClientAuth(false);
        }
      }

      final int maxMessageSizeBytes;
      if (listener == null)
      {
        asn1Reader = new ASN1StreamReader(socket.getInputStream());
      }
      else
      {
        asn1Reader = new ASN1StreamReader(socket.getInputStream(),
             listener.getConfig().getMaxMessageSizeBytes());
      }

    }
    catch (final IOException ioe)
    {
      Debug.debugException(ioe);

      try
      {
        socket.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }

      throw new LDAPException(ResultCode.CONNECT_ERROR,
           ERR_CONN_CREATE_IO_EXCEPTION.get(
                StaticUtils.getExceptionMessage(ioe)),
           ioe);
    }

    try
    {
      outputStream = socket.getOutputStream();
    }
    catch (final IOException ioe)
    {
      Debug.debugException(ioe);

      try
      {
        asn1Reader.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }

      try
      {
        socket.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }

      throw new LDAPException(ResultCode.CONNECT_ERROR,
           ERR_CONN_CREATE_IO_EXCEPTION.get(
                StaticUtils.getExceptionMessage(ioe)),
           ioe);
    }

    try
    {
      this.requestHandler = requestHandler.newInstance(this);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);

      try
      {
        asn1Reader.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }

      try
      {
        outputStream.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }

      try
      {
        socket.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }

      throw le;
    }
  }



  /**
   * Closes the connection to the client.
   *
   * @throws  IOException  If a problem occurs while closing the socket.
   */
  @Override()
  public synchronized void close()
         throws IOException
  {
    try
    {
      requestHandler.closeInstance();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    try
    {
      asn1Reader.close();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    try
    {
      outputStream.close();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    socket.close();
  }



  /**
   * Closes the connection to the client as a result of an exception encountered
   * during processing.  Any associated exception handler will be notified
   * prior to the connection closure.
   *
   * @param  le  The exception providing information about the reason that this
   *             connection will be terminated.
   */
  void close(@NotNull final LDAPException le)
  {
    if (exceptionHandler == null)
    {
      Debug.debugException(le);
    }
    else
    {
      try
      {
        exceptionHandler.connectionTerminated(this, le);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    try
    {
      sendUnsolicitedNotification(new NoticeOfDisconnectionExtendedResult(le));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    try
    {
      close();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }
  }



  /**
   * Operates in a loop, waiting for a request to arrive from the client and
   * handing it off to the request handler for processing.  This method is for
   * internal use only and must not be invoked by external callers.
   */
  @InternalUseOnly()
  @Override()
  public void run()
  {
    try
    {
      while (true)
      {
        final LDAPMessage requestMessage;
        try
        {
          requestMessage = LDAPMessage.readFrom(asn1Reader, false);
          if (requestMessage == null)
          {
            // This indicates that the client has closed the connection without
            // an unbind request.  It's not all that nice, but it isn't an error
            // so we won't notify the exception handler.
            try
            {
              close();
            }
            catch (final IOException ioe)
            {
              Debug.debugException(ioe);
            }

            return;
          }
        }
        catch (final LDAPException le)
        {
          // This indicates that the client sent a malformed request.
          Debug.debugException(le);
          close(le);
          return;
        }

        try
        {
          final int messageID = requestMessage.getMessageID();
          final List<Control> controls = requestMessage.getControls();

          LDAPMessage responseMessage;
          switch (requestMessage.getProtocolOpType())
          {
            case LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST:
              requestHandler.processAbandonRequest(messageID,
                   requestMessage.getAbandonRequestProtocolOp(), controls);
              responseMessage = null;
              break;

            case LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST:
              try
              {
                responseMessage = requestHandler.processAddRequest(messageID,
                     requestMessage.getAddRequestProtocolOp(), controls);
              }
              catch (final Exception e)
              {
                Debug.debugException(e);
                responseMessage = new LDAPMessage(messageID,
                     new AddResponseProtocolOp(
                          ResultCode.OTHER_INT_VALUE, null,
                          ERR_CONN_REQUEST_HANDLER_FAILURE.get(
                               StaticUtils.getExceptionMessage(e)),
                          null));
              }
              break;

            case LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST:
              try
              {
                responseMessage = requestHandler.processBindRequest(messageID,
                     requestMessage.getBindRequestProtocolOp(), controls);
              }
              catch (final Exception e)
              {
                Debug.debugException(e);
                responseMessage = new LDAPMessage(messageID,
                     new BindResponseProtocolOp(
                          ResultCode.OTHER_INT_VALUE, null,
                          ERR_CONN_REQUEST_HANDLER_FAILURE.get(
                               StaticUtils.getExceptionMessage(e)),
                          null, null));
              }
              break;

            case LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST:
              try
              {
                responseMessage = requestHandler.processCompareRequest(
                     messageID, requestMessage.getCompareRequestProtocolOp(),
                     controls);
              }
              catch (final Exception e)
              {
                Debug.debugException(e);
                responseMessage = new LDAPMessage(messageID,
                     new CompareResponseProtocolOp(
                          ResultCode.OTHER_INT_VALUE, null,
                          ERR_CONN_REQUEST_HANDLER_FAILURE.get(
                               StaticUtils.getExceptionMessage(e)),
                          null));
              }
              break;

            case LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST:
              try
              {
                responseMessage = requestHandler.processDeleteRequest(messageID,
                     requestMessage.getDeleteRequestProtocolOp(), controls);
              }
              catch (final Exception e)
              {
                Debug.debugException(e);
                responseMessage = new LDAPMessage(messageID,
                     new DeleteResponseProtocolOp(
                          ResultCode.OTHER_INT_VALUE, null,
                          ERR_CONN_REQUEST_HANDLER_FAILURE.get(
                               StaticUtils.getExceptionMessage(e)),
                          null));
              }
              break;

            case LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST:
              try
              {
                responseMessage = requestHandler.processExtendedRequest(
                     messageID, requestMessage.getExtendedRequestProtocolOp(),
                     controls);
              }
              catch (final Exception e)
              {
                Debug.debugException(e);
                responseMessage = new LDAPMessage(messageID,
                     new ExtendedResponseProtocolOp(
                          ResultCode.OTHER_INT_VALUE, null,
                          ERR_CONN_REQUEST_HANDLER_FAILURE.get(
                               StaticUtils.getExceptionMessage(e)),
                          null, null, null));
              }
              break;

            case LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST:
              try
              {
                responseMessage = requestHandler.processModifyRequest(messageID,
                     requestMessage.getModifyRequestProtocolOp(), controls);
              }
              catch (final Exception e)
              {
                Debug.debugException(e);
                responseMessage = new LDAPMessage(messageID,
                     new ModifyResponseProtocolOp(
                          ResultCode.OTHER_INT_VALUE, null,
                          ERR_CONN_REQUEST_HANDLER_FAILURE.get(
                               StaticUtils.getExceptionMessage(e)),
                          null));
              }
              break;

            case LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST:
              try
              {
                responseMessage = requestHandler.processModifyDNRequest(
                     messageID, requestMessage.getModifyDNRequestProtocolOp(),
                     controls);
              }
              catch (final Exception e)
              {
                Debug.debugException(e);
                responseMessage = new LDAPMessage(messageID,
                     new ModifyDNResponseProtocolOp(
                          ResultCode.OTHER_INT_VALUE, null,
                          ERR_CONN_REQUEST_HANDLER_FAILURE.get(
                               StaticUtils.getExceptionMessage(e)),
                          null));
              }
              break;

            case LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST:
              try
              {
                responseMessage = requestHandler.processSearchRequest(messageID,
                     requestMessage.getSearchRequestProtocolOp(), controls);
              }
              catch (final Exception e)
              {
                Debug.debugException(e);
                responseMessage = new LDAPMessage(messageID,
                     new SearchResultDoneProtocolOp(
                          ResultCode.OTHER_INT_VALUE, null,
                          ERR_CONN_REQUEST_HANDLER_FAILURE.get(
                               StaticUtils.getExceptionMessage(e)),
                          null));
              }
              break;

            case LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST:
              requestHandler.processUnbindRequest(messageID,
                   requestMessage.getUnbindRequestProtocolOp(), controls);
              close();
              return;

            default:
              close(new LDAPException(ResultCode.PROTOCOL_ERROR,
                   ERR_CONN_INVALID_PROTOCOL_OP_TYPE.get(StaticUtils.toHex(
                        requestMessage.getProtocolOpType()))));
              return;
          }

          if (responseMessage != null)
          {
            try
            {
              sendMessage(responseMessage);
            }
            catch (final LDAPException le)
            {
              Debug.debugException(le);
              close(le);
              return;
            }
          }
        }
        catch (final Throwable t)
        {
          close(new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_CONN_EXCEPTION_IN_REQUEST_HANDLER.get(
                    String.valueOf(requestMessage),
                    StaticUtils.getExceptionMessage(t))));
          StaticUtils.throwErrorOrRuntimeException(t);
        }
      }
    }
    finally
    {
      if (listener != null)
      {
        listener.connectionClosed(this);
      }
    }
  }



  /**
   * Sends the provided message to the client.
   *
   * @param  message  The message to be written to the client.
   *
   * @throws  LDAPException  If a problem occurs while attempting to send the
   *                         response to the client.
   */
  private synchronized void sendMessage(@NotNull final LDAPMessage message)
          throws LDAPException
  {
    // If we should suppress this response (which will only be because the
    // response has already been sent through some other means, for example as
    // part of StartTLS processing), then do so.
    if (suppressNextResponse.compareAndSet(true, false))
    {
      return;
    }

    asn1Buffer.clear();

    try
    {
      message.writeTo(asn1Buffer);
    }
    catch (final LDAPRuntimeException lre)
    {
      Debug.debugException(lre);
      lre.throwLDAPException();
    }

    try
    {
      asn1Buffer.writeTo(outputStream);
    }
    catch (final IOException ioe)
    {
      Debug.debugException(ioe);

      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_CONN_SEND_MESSAGE_EXCEPTION.get(
                StaticUtils.getExceptionMessage(ioe)),
           ioe);
    }
    finally
    {
      if (asn1Buffer.zeroBufferOnClear())
      {
        asn1Buffer.clear();
      }
    }
  }



  /**
   * Sends a search result entry message to the client with the provided
   * information.
   *
   * @param  messageID   The message ID for the LDAP message to send to the
   *                     client.  It must match the message ID of the associated
   *                     search request.
   * @param  protocolOp  The search result entry protocol op to include in the
   *                     LDAP message to send to the client.  It must not be
   *                     {@code null}.
   * @param  controls    The set of controls to include in the response message.
   *                     It may be empty or {@code null} if no controls should
   *                     be included.
   *
   * @throws  LDAPException  If a problem occurs while attempting to send the
   *                         provided response message.  If an exception is
   *                         thrown, then the client connection will have been
   *                         terminated.
   */
  public void sendSearchResultEntry(final int messageID,
                   @NotNull final SearchResultEntryProtocolOp protocolOp,
                   @Nullable final Control... controls)
         throws LDAPException
  {
    if (searchEntryTransformers.isEmpty())
    {
      sendMessage(new LDAPMessage(messageID, protocolOp, controls));
    }
    else
    {
      Control[] c;
      SearchResultEntryProtocolOp op = protocolOp;
      if (controls == null)
      {
        c = EMPTY_CONTROL_ARRAY;
      }
      else
      {
        c = controls;
      }

      for (final SearchEntryTransformer t : searchEntryTransformers)
      {
        try
        {
          final ObjectPair<SearchResultEntryProtocolOp,Control[]> p =
               t.transformEntry(messageID, op, c);
          if (p == null)
          {
            return;
          }

          op = p.getFirst();
          c  = p.getSecond();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          sendMessage(new LDAPMessage(messageID, protocolOp, c));
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_CONN_SEARCH_ENTRY_TRANSFORMER_EXCEPTION.get(
                    t.getClass().getName(), String.valueOf(op),
                    StaticUtils.getExceptionMessage(e)),
               e);
        }
      }

      sendMessage(new LDAPMessage(messageID, op, c));
    }
  }



  /**
   * Sends a search result entry message to the client with the provided
   * information.
   *
   * @param  messageID  The message ID for the LDAP message to send to the
   *                    client.  It must match the message ID of the associated
   *                    search request.
   * @param  entry      The entry to return to the client.  It must not be
   *                    {@code null}.
   * @param  controls   The set of controls to include in the response message.
   *                    It may be empty or {@code null} if no controls should be
   *                    included.
   *
   * @throws  LDAPException  If a problem occurs while attempting to send the
   *                         provided response message.  If an exception is
   *                         thrown, then the client connection will have been
   *                         terminated.
   */
  public void sendSearchResultEntry(final int messageID,
                                    @NotNull final Entry entry,
                                    @Nullable final Control... controls)
         throws LDAPException
  {
    sendSearchResultEntry(messageID,
         new SearchResultEntryProtocolOp(entry.getDN(),
              new ArrayList<>(entry.getAttributes())),
         controls);
  }



  /**
   * Sends a search result reference message to the client with the provided
   * information.
   *
   * @param  messageID   The message ID for the LDAP message to send to the
   *                     client.  It must match the message ID of the associated
   *                     search request.
   * @param  protocolOp  The search result reference protocol op to include in
   *                     the LDAP message to send to the client.
   * @param  controls    The set of controls to include in the response message.
   *                     It may be empty or {@code null} if no controls should
   *                     be included.
   *
   * @throws  LDAPException  If a problem occurs while attempting to send the
   *                         provided response message.  If an exception is
   *                         thrown, then the client connection will have been
   *                         terminated.
   */
  public void sendSearchResultReference(final int messageID,
                   @NotNull final SearchResultReferenceProtocolOp protocolOp,
                   @Nullable final Control... controls)
         throws LDAPException
  {
    if (searchReferenceTransformers.isEmpty())
    {
      sendMessage(new LDAPMessage(messageID, protocolOp, controls));
    }
    else
    {
      Control[] c;
      SearchResultReferenceProtocolOp op = protocolOp;
      if (controls == null)
      {
        c = EMPTY_CONTROL_ARRAY;
      }
      else
      {
        c = controls;
      }

      for (final SearchReferenceTransformer t : searchReferenceTransformers)
      {
        try
        {
          final ObjectPair<SearchResultReferenceProtocolOp,Control[]> p =
               t.transformReference(messageID, op, c);
          if (p == null)
          {
            return;
          }

          op = p.getFirst();
          c  = p.getSecond();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          sendMessage(new LDAPMessage(messageID, protocolOp, c));
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_CONN_SEARCH_REFERENCE_TRANSFORMER_EXCEPTION.get(
                    t.getClass().getName(), String.valueOf(op),
                    StaticUtils.getExceptionMessage(e)),
               e);
        }
      }

      sendMessage(new LDAPMessage(messageID, op, c));
    }
  }



  /**
   * Sends an intermediate response message to the client with the provided
   * information.
   *
   * @param  messageID   The message ID for the LDAP message to send to the
   *                     client.  It must match the message ID of the associated
   *                     search request.
   * @param  protocolOp  The intermediate response protocol op to include in the
   *                     LDAP message to send to the client.
   * @param  controls    The set of controls to include in the response message.
   *                     It may be empty or {@code null} if no controls should
   *                     be included.
   *
   * @throws  LDAPException  If a problem occurs while attempting to send the
   *                         provided response message.  If an exception is
   *                         thrown, then the client connection will have been
   *                         terminated.
   */
  public void sendIntermediateResponse(final int messageID,
                   @NotNull final IntermediateResponseProtocolOp protocolOp,
                   @Nullable final Control... controls)
         throws LDAPException
  {
    if (intermediateResponseTransformers.isEmpty())
    {
      sendMessage(new LDAPMessage(messageID, protocolOp, controls));
    }
    else
    {
      Control[] c;
      IntermediateResponseProtocolOp op = protocolOp;
      if (controls == null)
      {
        c = EMPTY_CONTROL_ARRAY;
      }
      else
      {
        c = controls;
      }

      for (final IntermediateResponseTransformer t :
           intermediateResponseTransformers)
      {
        try
        {
          final ObjectPair<IntermediateResponseProtocolOp,Control[]> p =
               t.transformIntermediateResponse(messageID, op, c);
          if (p == null)
          {
            return;
          }

          op = p.getFirst();
          c  = p.getSecond();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          sendMessage(new LDAPMessage(messageID, protocolOp, c));
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_CONN_INTERMEDIATE_RESPONSE_TRANSFORMER_EXCEPTION.get(
                    t.getClass().getName(), String.valueOf(op),
                    StaticUtils.getExceptionMessage(e)),
               e);
        }
      }

      sendMessage(new LDAPMessage(messageID, op, c));
    }
  }



  /**
   * Sends an unsolicited notification message to the client with the provided
   * extended result.
   *
   * @param  result  The extended result to use for the unsolicited
   *                 notification.
   *
   * @throws  LDAPException  If a problem occurs while attempting to send the
   *                         unsolicited notification.  If an exception is
   *                         thrown, then the client connection will have been
   *                         terminated.
   */
  public void sendUnsolicitedNotification(@NotNull final ExtendedResult result)
         throws LDAPException
  {
    sendUnsolicitedNotification(
         new ExtendedResponseProtocolOp(result.getResultCode().intValue(),
              result.getMatchedDN(), result.getDiagnosticMessage(),
              StaticUtils.toList(result.getReferralURLs()), result.getOID(),
              result.getValue()),
         result.getResponseControls()
    );
  }



  /**
   * Sends an unsolicited notification message to the client with the provided
   * information.
   *
   * @param  extendedResponse  The extended response to use for the unsolicited
   *                           notification.
   * @param  controls          The set of controls to include with the
   *                           unsolicited notification.  It may be empty or
   *                           {@code null} if no controls should be included.
   *
   * @throws  LDAPException  If a problem occurs while attempting to send the
   *                         unsolicited notification.  If an exception is
   *                         thrown, then the client connection will have been
   *                         terminated.
   */
  public void sendUnsolicitedNotification(
                   @NotNull final ExtendedResponseProtocolOp extendedResponse,
                   @Nullable final Control... controls)
         throws LDAPException
  {
    sendMessage(new LDAPMessage(0, extendedResponse, controls));
  }



  /**
   * Retrieves the socket used to communicate with the client.
   *
   * @return  The socket used to communicate with the client.
   */
  @NotNull()
  public synchronized Socket getSocket()
  {
    return socket;
  }



  /**
   * Attempts to convert this unencrypted connection to one that uses TLS
   * encryption, as would be used during the course of invoking the StartTLS
   * extended operation.  If this is called, then the response that would have
   * been returned from the associated request will be suppressed, so the
   * returned output stream must be used to send the appropriate response to
   * the client.
   *
   * @param  sslSocketFactory  The SSL socket factory that will be used to
   *                           convert the existing {@code Socket} to an
   *                           {@code SSLSocket}.
   *
   * @return  An output stream that can be used to send a clear-text message to
   *          the client (e.g., the StartTLS response message).
   *
   * @throws  LDAPException  If a problem is encountered while trying to convert
   *                         the existing socket to an SSL socket.  If this is
   *                         thrown, then the connection will have been closed.
   */
  @NotNull()
  public synchronized OutputStream convertToTLS(
              @NotNull final SSLSocketFactory sslSocketFactory)
         throws LDAPException
  {
    return convertToTLS(sslSocketFactory, false, false);
  }



  /**
   * Attempts to convert this unencrypted connection to one that uses TLS
   * encryption, as would be used during the course of invoking the StartTLS
   * extended operation.  If this is called, then the response that would have
   * been returned from the associated request will be suppressed, so the
   * returned output stream must be used to send the appropriate response to
   * the client.
   *
   * @param  sslSocketFactory          The SSL socket factory that will be used
   *                                   to convert the existing {@code Socket} to
   *                                   an {@code SSLSocket}.
   * @param  requestClientCertificate  Indicates whether the listener should
   *                                   request that the client present its own
   *                                   certificate chain during TLS negotiation.
   *                                   This will be ignored for non-TLS-based
   *                                   connections.
   * @param  requireClientCertificate  Indicates whether the listener should
   *                                   require that the client present its own
   *                                   certificate chain during TLS negotiation,
   *                                   and should fail negotiation if the client
   *                                   does not present one.  This will be
   *                                   ignored for non-TLS-based connections or
   *                                   if {@code requestClientCertificate} is
   *                                   {@code false}.
   *
   * @return  An output stream that can be used to send a clear-text message to
   *          the client (e.g., the StartTLS response message).
   *
   * @throws  LDAPException  If a problem is encountered while trying to convert
   *                         the existing socket to an SSL socket.  If this is
   *                         thrown, then the connection will have been closed.
   */
  @NotNull()
  public synchronized OutputStream convertToTLS(
              @NotNull final SSLSocketFactory sslSocketFactory,
              final boolean requestClientCertificate,
              final boolean requireClientCertificate)
         throws LDAPException
  {
    final OutputStream clearOutputStream = outputStream;

    final Socket origSocket = socket;
    final String hostname   = LDAPConnectionOptions.DEFAULT_NAME_RESOLVER.
         getHostName(origSocket.getInetAddress());
    final int port          = origSocket.getPort();

    try
    {
      synchronized (sslSocketFactory)
      {
        socket = sslSocketFactory.createSocket(socket, hostname, port, true);
      }

      final SSLSocket sslSocket = (SSLSocket) socket;
      sslSocket.setUseClientMode(false);

      if (requestClientCertificate)
      {
        if (requireClientCertificate)
        {
          sslSocket.setNeedClientAuth(true);
        }
        else
        {
          sslSocket.setWantClientAuth(true);
        }
      }
      else
      {
        sslSocket.setWantClientAuth(false);
      }


      outputStream = socket.getOutputStream();
      asn1Reader = new ASN1StreamReader(socket.getInputStream());
      suppressNextResponse.set(true);
      return clearOutputStream;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      final LDAPException le = new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_CONN_CONVERT_TO_TLS_FAILURE.get(
                StaticUtils.getExceptionMessage(e)),
           e);

      close(le);

      throw le;
    }
  }



  /**
   * Retrieves the connection ID that has been assigned to this connection by
   * the associated listener.
   *
   * @return  The connection ID that has been assigned to this connection by
   *          the associated listener, or -1 if it is not associated with a
   *          listener.
   */
  public long getConnectionID()
  {
    return connectionID;
  }



  /**
   * Adds the provided search entry transformer to this client connection.
   *
   * @param  t  A search entry transformer to be used to intercept and/or alter
   *            search result entries before they are returned to the client.
   */
  public void addSearchEntryTransformer(
                   @NotNull final SearchEntryTransformer t)
  {
    searchEntryTransformers.add(t);
  }



  /**
   * Removes the provided search entry transformer from this client connection.
   *
   * @param  t  The search entry transformer to be removed.
   */
  public void removeSearchEntryTransformer(
                   @NotNull final SearchEntryTransformer t)
  {
    searchEntryTransformers.remove(t);
  }



  /**
   * Adds the provided search reference transformer to this client connection.
   *
   * @param  t  A search reference transformer to be used to intercept and/or
   *            alter search result references before they are returned to the
   *            client.
   */
  public void addSearchReferenceTransformer(
                   @NotNull final SearchReferenceTransformer t)
  {
    searchReferenceTransformers.add(t);
  }



  /**
   * Removes the provided search reference transformer from this client
   * connection.
   *
   * @param  t  The search reference transformer to be removed.
   */
  public void removeSearchReferenceTransformer(
                   @NotNull final SearchReferenceTransformer t)
  {
    searchReferenceTransformers.remove(t);
  }



  /**
   * Adds the provided intermediate response transformer to this client
   * connection.
   *
   * @param  t  An intermediate response transformer to be used to intercept
   *            and/or alter intermediate responses before they are returned to
   *            the client.
   */
  public void addIntermediateResponseTransformer(
                   @NotNull final IntermediateResponseTransformer t)
  {
    intermediateResponseTransformers.add(t);
  }



  /**
   * Removes the provided intermediate response transformer from this client
   * connection.
   *
   * @param  t  The intermediate response transformer to be removed.
   */
  public void removeIntermediateResponseTransformer(
                   @NotNull final IntermediateResponseTransformer t)
  {
    intermediateResponseTransformers.remove(t);
  }
}
