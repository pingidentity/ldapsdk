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



import java.io.BufferedInputStream;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.security.sasl.SaslClient;

import com.unboundid.asn1.ASN1Exception;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.InternalASN1Helper;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.LDAPResponse;
import com.unboundid.ldap.sdk.extensions.NoticeOfDisconnectionExtendedResult;
import com.unboundid.util.Debug;
import com.unboundid.util.DebugType;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.WakeableSleeper;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides a thread that will read data from the socket associated
 * with an LDAP connection.  It will accept messages from the server, and
 * associate responses with their corresponding requests.
 */
@InternalUseOnly()
final class LDAPConnectionReader
      extends Thread
{
  /**
   * The default size that will be used for the input stream buffer.
   */
  private static final int DEFAULT_INPUT_BUFFER_SIZE = 4096;



  // The ASN.1 stream reader used to read LDAP messages from the server.
  @NotNull private volatile ASN1StreamReader asn1StreamReader;

  // Indicates whether a request has been made to close the associated socket.
  private volatile boolean closeRequested;

  // The map that will be used to associate message IDs with the corresponding
  // response acceptors.
  @NotNull private final ConcurrentHashMap<Integer,ResponseAcceptor>
       acceptorMap;

  // The exception encountered during StartTLS processing.
  @Nullable private volatile Exception startTLSException;

  // The input stream used to read data from the socket.
  @Nullable private volatile InputStream inputStream;

  // The SSL-enabled output stream resulting from StartTLS negotiation.  It will
  // be non-null only immediately after StartTLS negotiation has completed and
  // this output stream is ready to be handed back to the connection.
  @Nullable private volatile OutputStream startTLSOutputStream;

  // The LDAP connection with which this reader is associated.
  @NotNull private final LDAPConnection connection;

  // The socket with which this reader is associated.
  @NotNull private volatile Socket socket;

  // The SSL socket factory to use to convert an insecure connection to a secure
  // one when performing StartTLS processing.  It will be null unless there is
  // an outstanding StartTLS request.
  @Nullable private volatile SSLSocketFactory sslSocketFactory;

  // The thread that is used to read data from the client.
  @Nullable private volatile Thread thread;

  // The wakeable sleeper that will be used during StartTLS processing.
  @NotNull private final WakeableSleeper startTLSSleeper;



  /**
   * Creates a new LDAP connection reader instance that will read data from the
   * provided socket.
   *
   * @param  connection           The LDAP connection with which this reader is
   *                              associated.
   * @param  connectionInternals  The elements of the LDAP connection actually
   *                              used to communicate with the directory server.
   *
   * @throws  IOException  If a problem occurs while preparing to read data from
   *                       the provided socket.
   */
  LDAPConnectionReader(@NotNull final LDAPConnection connection,
       @NotNull final LDAPConnectionInternals connectionInternals)
       throws IOException
  {
    this.connection = connection;

    setName(constructThreadName(connectionInternals));
    setDaemon(true);

    socket               = connectionInternals.getSocket();
    inputStream          = new BufferedInputStream(socket.getInputStream(),
                                                   DEFAULT_INPUT_BUFFER_SIZE);
    asn1StreamReader = new ASN1StreamReader(inputStream,
         connection.getConnectionOptions().getMaxMessageSize());

    acceptorMap = new ConcurrentHashMap<>(StaticUtils.computeMapCapacity(10));
    closeRequested = false;
    sslSocketFactory = null;
    startTLSException = null;
    startTLSOutputStream = null;
    startTLSSleeper = new WakeableSleeper();
  }



  /**
   * Registers the provided response acceptor to be notified of any responses
   * with the given message ID.
   *
   * @param  messageID  The message ID for which to register the acceptor.
   * @param  acceptor   The response acceptor that should be notified for any
   *                    responses with the provided message ID.
   *
   * @throws  LDAPException  If another acceptor is already registered for the
   *                         provided message ID.
   */
  void registerResponseAcceptor(final int messageID,
                                @NotNull final ResponseAcceptor acceptor)
       throws LDAPException
  {
    final ResponseAcceptor existingAcceptor =
         acceptorMap.putIfAbsent(messageID, acceptor);
    if (existingAcceptor != null)
    {
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_CONNREADER_MSGID_IN_USE.get(String.valueOf(acceptor), messageID,
                String.valueOf(connection), String.valueOf(existingAcceptor)));
    }
  }



  /**
   * Deregisters the response acceptor that has been registered with the
   * specified message ID.  This will have no effect if no response acceptor is
   * registered for the provided message ID.
   *
   * @param  messageID  The message ID for the response acceptor to deregister.
   */
  void deregisterResponseAcceptor(final int messageID)
  {
    acceptorMap.remove(messageID);
  }



  /**
   * Retrieves the number of outstanding operations on the LDAP connection,
   * which are operations for which the request has been sent but the final
   * result has not yet been received.  The value will only be valid for
   * connections not configured to use synchronous mode.
   *
   * @return  The number of outstanding operations on the associated LDAP
   *          connection.
   */
  int getActiveOperationCount()
  {
    return acceptorMap.size();
  }



  /**
   * Operates in a loop, reading data from the server and decoding the
   * responses, and associating them with their corresponding requests.
   */
  @Override()
  @SuppressWarnings("deprecation")
  public void run()
  {
    boolean reconnect  = false;

    thread = Thread.currentThread();

    while (! closeRequested)
    {
      try
      {
        final LDAPResponse response;
        try
        {
          response = LDAPMessage.readLDAPResponseFrom(asn1StreamReader, true,
               connection.getCachedSchema());
        }
        catch (final LDAPException le)
        {
          final Throwable t = le.getCause();
          if ((t != null) && (t instanceof SocketTimeoutException))
          {
            // This is rarely a problem, so we can make the debug message for
            // this exception only visible at a verbose log level.
            final SocketTimeoutException ste = (SocketTimeoutException) t;
            Debug.debugException(Level.FINEST,  ste);
            if (sslSocketFactory != null)
            {
              final LDAPConnectionOptions connectionOptions =
                   connection.getConnectionOptions();
              try
              {
                final int responseTimeoutMillis =
                     (int) connectionOptions.getResponseTimeoutMillis();
                if (responseTimeoutMillis > 0)
                {
                  InternalSDKHelper.setSoTimeout(connection,
                       responseTimeoutMillis);
                }
                else
                {
                  InternalSDKHelper.setSoTimeout(connection, 0);
                }

                final SSLSocket sslSocket;
                synchronized (sslSocketFactory)
                {
                  sslSocket = (SSLSocket) sslSocketFactory.createSocket(socket,
                       connection.getConnectedAddress(), socket.getPort(),
                       true);
                  sslSocket.startHandshake();
                }
                connectionOptions.getSSLSocketVerifier().verifySSLSocket(
                     connection.getConnectedAddress(), socket.getPort(),
                     sslSocket);
                inputStream =
                     new BufferedInputStream(sslSocket.getInputStream(),
                                             DEFAULT_INPUT_BUFFER_SIZE);
                asn1StreamReader = new ASN1StreamReader(inputStream,
                     connectionOptions.getMaxMessageSize());
                startTLSOutputStream = sslSocket.getOutputStream();
                socket = sslSocket;
                connection.getConnectionInternals(true).setSocket(sslSocket);
                startTLSSleeper.wakeup();
              }
              catch (final Exception e)
              {
                Debug.debugException(e);
                connection.setDisconnectInfo(DisconnectType.SECURITY_PROBLEM,
                     StaticUtils.getExceptionMessage(e), e);
                startTLSException = e;
                closeRequested = true;
                if (thread != null)
                {
                  thread.setName(thread.getName() + " (closed)");
                  thread = null;
                }
                closeInternal(true, StaticUtils.getExceptionMessage(e));
                startTLSSleeper.wakeup();
                return;
              }

              sslSocketFactory = null;
            }

            continue;
          }

          if (closeRequested || connection.closeRequested() ||
              (connection.getDisconnectType() != null))
          {
            // This exception resulted from the connection being closed in a way
            // that we already knew about.  We don't want to debug it at the
            // same level as a newly-detected invalidity.
            closeRequested = true;
            Debug.debugException(Level.FINEST, le);
          }
          else
          {
            Debug.debugException(le);
          }

          // We should terminate the connection regardless of the type of
          // exception, but might want to customize the debug message.
          final String message;
          Level debugLevel = Level.SEVERE;

          if (t == null)
          {
            connection.setDisconnectInfo(DisconnectType.DECODE_ERROR,
                 le.getMessage(), t);
            message = le.getMessage();
            debugLevel = Level.WARNING;
          }
          else if ((t instanceof InterruptedIOException) && socket.isClosed())
          {
            connection.setDisconnectInfo(
                 DisconnectType.SERVER_CLOSED_WITHOUT_NOTICE, le.getMessage(),
                 t);
            message = ERR_READER_CLOSING_DUE_TO_INTERRUPTED_IO.get(
                 connection.getHostPort());
            debugLevel = Level.WARNING;
          }
          else if (t instanceof IOException)
          {
            connection.setDisconnectInfo(DisconnectType.IO_ERROR,
                 le.getMessage(), t);
            message = ERR_READER_CLOSING_DUE_TO_IO_EXCEPTION.get(
                 connection.getHostPort(), StaticUtils.getExceptionMessage(t));
            debugLevel = Level.WARNING;
          }
          else if (t instanceof ASN1Exception)
          {
            connection.setDisconnectInfo(DisconnectType.DECODE_ERROR,
                 le.getMessage(), t);
            message = ERR_READER_CLOSING_DUE_TO_ASN1_EXCEPTION.get(
                 connection.getHostPort(), StaticUtils.getExceptionMessage(t));
          }
          else
          {
            connection.setDisconnectInfo(DisconnectType.LOCAL_ERROR,
                 le.getMessage(), t);
            message = ERR_READER_CLOSING_DUE_TO_EXCEPTION.get(
                 connection.getHostPort(), StaticUtils.getExceptionMessage(t));
          }

          Debug.debug(debugLevel, DebugType.LDAP, message, t);

          // If the connection is configured to try to auto-reconnect, then set
          // things up to do that.  Otherwise, terminate the connection.
          @SuppressWarnings("deprecation")
          final boolean autoReconnect =
               connection.getConnectionOptions().autoReconnect();
          if ((! closeRequested) && autoReconnect)
          {
            reconnect = true;
            break;
          }
          else
          {
            closeRequested = true;
            if (thread != null)
            {
              thread.setName(thread.getName() + " (closed)");
              thread = null;
            }
            closeInternal(true, message);
            return;
          }
        }

        if (response == null)
        {
          // This should only happen if the socket has been closed.
          connection.setDisconnectInfo(
               DisconnectType.SERVER_CLOSED_WITHOUT_NOTICE, null, null);
          @SuppressWarnings("deprecation")
          final boolean autoReconnect =
               connection.getConnectionOptions().autoReconnect();
          if ((! closeRequested) && (! connection.unbindRequestSent()) &&
              autoReconnect)
          {
            reconnect = true;
            break;
          }
          else
          {
            closeRequested = true;
            if (thread != null)
            {
              thread.setName(thread.getName() + " (closed)");
              thread = null;
            }
            closeInternal(true, null);
            return;
          }
        }

        connection.setLastCommunicationTime();
        Debug.debugLDAPResult(response, connection);
        logResponse(response);

        final ResponseAcceptor responseAcceptor;
        if ((response instanceof SearchResultEntry) ||
            (response instanceof SearchResultReference))
        {
          responseAcceptor = acceptorMap.get(response.getMessageID());
        }
        else if (response instanceof IntermediateResponse)
        {
          final IntermediateResponse ir = (IntermediateResponse) response;
          responseAcceptor = acceptorMap.get(response.getMessageID());
           IntermediateResponseListener l = null;
          if (responseAcceptor instanceof LDAPRequest)
          {
            final LDAPRequest r = (LDAPRequest) responseAcceptor;
            l = r.getIntermediateResponseListener();

          }
          else if (responseAcceptor instanceof IntermediateResponseListener)
          {
            l = (IntermediateResponseListener) responseAcceptor;
          }

          if (l == null)
          {
            Debug.debug(Level.WARNING, DebugType.LDAP,
                 WARN_INTERMEDIATE_RESPONSE_WITH_NO_LISTENER.get(
                      String.valueOf(ir)));
          }
          else
          {
            try
            {
              l.intermediateResponseReturned(ir);
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
            }
          }
          continue;
        }
        else
        {
          responseAcceptor = acceptorMap.remove(response.getMessageID());
        }


        if (responseAcceptor == null)
        {
          if ((response instanceof ExtendedResult) &&
              (response.getMessageID() == 0))
          {
            // This is an intermediate response message, so handle it
            // appropriately.
            ExtendedResult extendedResult = (ExtendedResult) response;

            final String oid = extendedResult.getOID();
            if (NoticeOfDisconnectionExtendedResult.
                     NOTICE_OF_DISCONNECTION_RESULT_OID.equals(oid))
            {
              extendedResult = new NoticeOfDisconnectionExtendedResult(
                                        extendedResult);
              connection.setDisconnectInfo(
                   DisconnectType.SERVER_CLOSED_WITH_NOTICE,
                   extendedResult.getDiagnosticMessage(), null);
            }
            else if (com.unboundid.ldap.sdk.unboundidds.extensions.
                 InteractiveTransactionAbortedExtendedResult.
                      INTERACTIVE_TRANSACTION_ABORTED_RESULT_OID.equals(oid))
            {
              extendedResult = new com.unboundid.ldap.sdk.unboundidds.
                   extensions.InteractiveTransactionAbortedExtendedResult(
                        extendedResult);
            }

            final UnsolicitedNotificationHandler handler =
                 connection.getConnectionOptions().
                      getUnsolicitedNotificationHandler();
            if (handler == null)
            {
              if (Debug.debugEnabled(DebugType.LDAP))
              {
                Debug.debug(Level.WARNING, DebugType.LDAP,
                     WARN_READER_UNHANDLED_UNSOLICITED_NOTIFICATION.get(
                          response));
              }
            }
            else
            {
              handler.handleUnsolicitedNotification(connection,
                                                    extendedResult);
            }
            continue;
          }

          if (Debug.debugEnabled(DebugType.LDAP))
          {
            Debug.debug(Level.WARNING, DebugType.LDAP,
                  WARN_READER_NO_ACCEPTOR.get(response));
          }
          continue;
        }

        try
        {
          responseAcceptor.responseReceived(response);
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          Debug.debug(Level.WARNING, DebugType.LDAP,
                ERR_READER_ACCEPTOR_ERROR.get(String.valueOf(response),
                     connection.getHostPort(),
                     StaticUtils.getExceptionMessage(le)),
               le);
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        // We should terminate the connection regardless of the type of
        // exception, but might want to customize the debug message.
        final String message;
        Level debugLevel = Level.SEVERE;
        if (e instanceof IOException)
        {
          connection.setDisconnectInfo(DisconnectType.IO_ERROR, null, e);
          message = ERR_READER_CLOSING_DUE_TO_IO_EXCEPTION.get(
               connection.getHostPort(), StaticUtils.getExceptionMessage(e));
          debugLevel = Level.WARNING;
        }
        else if (e instanceof ASN1Exception)
        {
          connection.setDisconnectInfo(DisconnectType.DECODE_ERROR, null, e);
          message = ERR_READER_CLOSING_DUE_TO_ASN1_EXCEPTION.get(
               connection.getHostPort(), StaticUtils.getExceptionMessage(e));
        }
        else
        {
          connection.setDisconnectInfo(DisconnectType.LOCAL_ERROR, null, e);
          message = ERR_READER_CLOSING_DUE_TO_EXCEPTION.get(
               connection.getHostPort(), StaticUtils.getExceptionMessage(e));
        }

        Debug.debug(debugLevel, DebugType.LDAP, message, e);

        // If the connection is configured to try to auto-reconnect, then set
        // things up to do that.  Otherwise, terminate the connection.
        @SuppressWarnings("deprecation")
        final boolean autoReconnect =
             connection.getConnectionOptions().autoReconnect();
        if (autoReconnect)
        {
          reconnect = true;
          break;
        }
        else
        {
          closeRequested = true;
          if (thread != null)
          {
            thread.setName(thread.getName() + " (closed)");
            thread = null;
          }
          closeInternal(true, message);
          return;
        }
      }
    }

    if (thread != null)
    {
      thread.setName(constructThreadName(null));
      thread = null;
    }

    if (reconnect && (! connection.closeRequested()))
    {
      try
      {
        connection.setNeedsReconnect();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }
    else
    {
      // Ensure that the connection has properly been closed.
      closeInternal(true, null);
    }
  }



  /**
   * Reads a response from the server, blocking if necessary until the response
   * has been received.  This should only be used for connections operating in
   * synchronous mode.
   *
   * @param  messageID  The message ID for the response to be read.  Any
   *                    response read with a different message ID will be
   *                    discarded, unless it is an unsolicited notification in
   *                    which case it will be provided to any registered
   *                    unsolicited notification handler.
   *
   * @return  The response read from the server.
   *
   * @throws  LDAPException  If a problem occurs while reading the response.
   */
  @NotNull()
  @SuppressWarnings("deprecation")
  LDAPResponse readResponse(final int messageID)
               throws LDAPException
  {
    while (true)
    {
      try
      {
        final LDAPResponse response = LDAPMessage.readLDAPResponseFrom(
             asn1StreamReader, false, connection.getCachedSchema());
        if (response == null)
        {
          return new ConnectionClosedResponse(ResultCode.SERVER_DOWN, null);
        }

        connection.setLastCommunicationTime();
        if (response.getMessageID() == messageID)
        {
          return response;
        }

        if ((response instanceof ExtendedResult) &&
            (response.getMessageID() == 0))
        {
          // This is an intermediate response message, so handle it
          // appropriately.
          ExtendedResult extendedResult = (ExtendedResult) response;

          final String oid = extendedResult.getOID();
          if (NoticeOfDisconnectionExtendedResult.
                   NOTICE_OF_DISCONNECTION_RESULT_OID.equals(oid))
          {
            extendedResult = new NoticeOfDisconnectionExtendedResult(
                                      extendedResult);
            connection.setDisconnectInfo(
                 DisconnectType.SERVER_CLOSED_WITH_NOTICE,
                 extendedResult.getDiagnosticMessage(), null);
          }
          else if (com.unboundid.ldap.sdk.unboundidds.extensions.
               InteractiveTransactionAbortedExtendedResult.
                    INTERACTIVE_TRANSACTION_ABORTED_RESULT_OID.equals(oid))
          {
            extendedResult = new com.unboundid.ldap.sdk.unboundidds.extensions.
                 InteractiveTransactionAbortedExtendedResult(extendedResult);
          }

          final UnsolicitedNotificationHandler handler =
               connection.getConnectionOptions().
                    getUnsolicitedNotificationHandler();
          if (handler == null)
          {
            if (Debug.debugEnabled(DebugType.LDAP))
            {
              Debug.debug(Level.WARNING, DebugType.LDAP,
                   WARN_READER_UNHANDLED_UNSOLICITED_NOTIFICATION.get(
                        response));
            }
          }
          else
          {
            handler.handleUnsolicitedNotification(connection,
                                                  extendedResult);
          }
          continue;
        }

        if (Debug.debugEnabled(DebugType.LDAP))
        {
          Debug.debug(Level.WARNING, DebugType.LDAP,
               WARN_READER_DISCARDING_UNEXPECTED_RESPONSE.get(response,
                    messageID));
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        final Throwable t = le.getCause();


        // If the cause was a SocketTimeoutException, then we shouldn't
        // terminate the connection, but we should propagate the failure to
        // the client with the appropriate result.
        if ((t != null) && (t instanceof SocketTimeoutException))
        {
          throw new LDAPException(ResultCode.TIMEOUT, le.getMessage(), le);
        }


        // We should terminate the connection regardless of the type of
        // exception, but might want to customize the debug message.
        final String message;
        Level debugLevel = Level.SEVERE;

        if (t == null)
        {
          connection.setDisconnectInfo(DisconnectType.DECODE_ERROR,
               le.getMessage(), t);
          message = le.getMessage();
          debugLevel = Level.WARNING;
        }
        else if (t instanceof IOException)
        {
          connection.setDisconnectInfo(DisconnectType.IO_ERROR,
               le.getMessage(), t);
          message = ERR_READER_CLOSING_DUE_TO_IO_EXCEPTION.get(
               connection.getHostPort(), StaticUtils.getExceptionMessage(t));
          debugLevel = Level.WARNING;
        }
        else if (t instanceof ASN1Exception)
        {
          connection.setDisconnectInfo(DisconnectType.DECODE_ERROR,
               le.getMessage(), t);
          message = ERR_READER_CLOSING_DUE_TO_ASN1_EXCEPTION.get(
               connection.getHostPort(), StaticUtils.getExceptionMessage(t));
        }
        else
        {
          connection.setDisconnectInfo(DisconnectType.LOCAL_ERROR,
               le.getMessage(), t);
          message = ERR_READER_CLOSING_DUE_TO_EXCEPTION.get(
               connection.getHostPort(), StaticUtils.getExceptionMessage(t));
        }

        Debug.debug(debugLevel, DebugType.LDAP, message, t);
        @SuppressWarnings("deprecation")
        final boolean autoReconnect =
             connection.getConnectionOptions().autoReconnect();
        if (! autoReconnect)
        {
          closeRequested = true;
        }
        closeInternal(true, message);
        throw le;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        // We should terminate the connection regardless of the type of
        // exception, but might want to customize the debug message.
        final String message;
        Level debugLevel = Level.SEVERE;
        if (e instanceof IOException)
        {
          connection.setDisconnectInfo(DisconnectType.IO_ERROR, null, e);
          message = ERR_READER_CLOSING_DUE_TO_IO_EXCEPTION.get(
               connection.getHostPort(), StaticUtils.getExceptionMessage(e));
          debugLevel = Level.WARNING;
        }
        else if (e instanceof ASN1Exception)
        {
          connection.setDisconnectInfo(DisconnectType.DECODE_ERROR, null, e);
          message = ERR_READER_CLOSING_DUE_TO_ASN1_EXCEPTION.get(
               connection.getHostPort(), StaticUtils.getExceptionMessage(e));
        }
        else
        {
          connection.setDisconnectInfo(DisconnectType.LOCAL_ERROR, null, e);
          message = ERR_READER_CLOSING_DUE_TO_EXCEPTION.get(
               connection.getHostPort(), StaticUtils.getExceptionMessage(e));
        }

        Debug.debug(debugLevel, DebugType.LDAP, message, e);
        @SuppressWarnings("deprecation")
        final boolean autoReconnect =
             connection.getConnectionOptions().autoReconnect();
        if (! autoReconnect)
        {
          closeRequested = true;
        }
        closeInternal(true, message);
        throw new LDAPException(ResultCode.SERVER_DOWN,  message, e);
      }
    }
  }



  /**
   * Logs the provided response, if appropriate.
   *
   * @param  response  The response to be logged.  It must not be {@code null}.
   */
  void logResponse(@NotNull final LDAPResponse response)
  {
    final LDAPConnectionLogger logger =
         connection.getConnectionOptions().getConnectionLogger();
    if (logger == null)
    {
      return;
    }

    final int messageID = response.getMessageID();

    if (response instanceof BindResult)
    {
      logger.logBindResult(connection, messageID, (BindResult) response);
    }
    else if (response instanceof ExtendedResult)
    {
      logger.logExtendedResult(connection, messageID,
           (ExtendedResult) response);
    }
    else if (response instanceof SearchResult)
    {
      logger.logSearchResult(connection, messageID, (SearchResult) response);
    }
    else if (response instanceof LDAPResult)
    {
      final LDAPResult ldapResult = (LDAPResult) response;
      final OperationType operationType = ldapResult.getOperationType();
      if (operationType != null)
      {
        switch (operationType)
        {
          case ADD:
            logger.logAddResult(connection, messageID, ldapResult);
            break;
          case COMPARE:
            logger.logCompareResult(connection, messageID, ldapResult);
            break;
          case DELETE:
            logger.logDeleteResult(connection, messageID, ldapResult);
            break;
          case MODIFY:
            logger.logModifyResult(connection, messageID, ldapResult);
            break;
          case MODIFY_DN:
            logger.logModifyDNResult(connection, messageID, ldapResult);
            break;
        }
      }
    }
    else if (response instanceof SearchResultEntry)
    {
      logger.logSearchEntry(connection, messageID,
           (SearchResultEntry) response);
    }
    else if (response instanceof SearchResultReference)
    {
      logger.logSearchReference(connection, messageID,
           (SearchResultReference) response);
    }
    else if (response instanceof IntermediateResponse)
    {
      logger.logIntermediateResponse(connection, messageID,
           (IntermediateResponse) response);
    }
  }



  /**
   * Converts this clear-text connection to one that uses TLS.
   *
   * @param  sslSocketFactory  The SSL socket factory to use to convert an
   *                           insecure connection into a secure connection.  It
   *                           must not be {@code null}.
   *
   * @return  The TLS-enabled output stream that may be used to send encrypted
   *          requests to the server.
   *
   * @throws  LDAPException  If a problem occurs while attempting to convert the
   *                         connection to use TLS security.
   */
  @NotNull()
  OutputStream doStartTLS(@NotNull final SSLSocketFactory sslSocketFactory)
       throws LDAPException
  {
    final LDAPConnectionOptions connectionOptions =
         connection.getConnectionOptions();
    if (connection.synchronousMode())
    {
      try
      {
        final int connectTimeout = connectionOptions.getConnectTimeoutMillis();
        if (connectTimeout > 0)
        {
          InternalSDKHelper.setSoTimeout(connection, connectTimeout);
        }
        else
        {
          InternalSDKHelper.setSoTimeout(connection, 0);
        }

        final SSLSocket sslSocket;
        synchronized (sslSocketFactory)
        {
          sslSocket = (SSLSocket) sslSocketFactory.createSocket(socket,
               connection.getConnectedAddress(), socket.getPort(), true);
          sslSocket.startHandshake();
        }
        connectionOptions.getSSLSocketVerifier().verifySSLSocket(
             connection.getConnectedAddress(), socket.getPort(), sslSocket);
        inputStream =
             new BufferedInputStream(sslSocket.getInputStream(),
                                     DEFAULT_INPUT_BUFFER_SIZE);
        asn1StreamReader = new ASN1StreamReader(inputStream,
             connectionOptions.getMaxMessageSize());
        startTLSOutputStream = sslSocket.getOutputStream();
        socket = sslSocket;
        connection.getConnectionInternals(true).setSocket(sslSocket);
        final OutputStream outputStream = startTLSOutputStream;
        startTLSOutputStream = null;
        return outputStream;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        connection.setDisconnectInfo(DisconnectType.SECURITY_PROBLEM,
             StaticUtils.getExceptionMessage(e), e);
        startTLSException = e;
        closeRequested = true;
        closeInternal(true, StaticUtils.getExceptionMessage(e));
        throw new LDAPException(ResultCode.SERVER_DOWN,
             ERR_CONNREADER_STARTTLS_FAILED.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }
    else
    {
      this.sslSocketFactory = sslSocketFactory;

      // Since the connection isn't operating in synchronous mode, we'll want to
      // use a relatively small SO_TIMEOUT for the connection during this
      // process so that it'll be more responsive.  The original SO_TIMEOUT will
      // be restored after the TLS negotiation.
      final int originalSOTimeout = InternalSDKHelper.getSoTimeout(connection);
      try
      {
        InternalSDKHelper.setSoTimeout(connection, 50);

        while (true)
        {
          if (startTLSOutputStream != null)
          {
            final OutputStream outputStream = startTLSOutputStream;
            startTLSOutputStream = null;
            return outputStream;
          }
          else if (thread == null)
          {
            if (startTLSException == null)
            {
              throw new LDAPException(ResultCode.LOCAL_ERROR,
                   ERR_CONNREADER_STARTTLS_FAILED_NO_EXCEPTION.get());
            }
            else
            {
              final Exception e = startTLSException;
              startTLSException = null;

              throw new LDAPException(ResultCode.LOCAL_ERROR,
                   ERR_CONNREADER_STARTTLS_FAILED.get(
                        StaticUtils.getExceptionMessage(e)),
                   e);
            }
          }

          startTLSSleeper.sleep(10);
        }
      }
      finally
      {
        InternalSDKHelper.setSoTimeout(connection, originalSOTimeout);
      }
    }
  }



  /**
   * Updates this connection reader to ensure that any subsequent data read
   * over this connection will be decoded using the provided SASL client.
   *
   * @param  saslClient  The SASL client to use to decode data read over this
   *                     connection.
   */
  void applySASLQoP(@NotNull final SaslClient saslClient)
  {
    InternalASN1Helper.setSASLClient(asn1StreamReader, saslClient);
  }



  /**
   * Closes the connection and interrupts the reader thread.
   *
   * @param  notifyConnection  Indicates whether the associated connection
   *                           should be notified.
   */
   void close(final boolean notifyConnection)
   {
     closeRequested = true;

     for (int i=0; i < 5; i++)
     {
       try
       {
         final Thread t = thread;
         if ((t == null) || (t == Thread.currentThread()) || (! t.isAlive()))
         {
           break;
         }
         else
         {
           t.interrupt();
           t.join(100L);
         }
       }
       catch (final Exception e)
       {
         Debug.debugException(e);

         if (e instanceof InterruptedException)
         {
           Thread.currentThread().interrupt();
           break;
         }
       }
     }

     closeInternal(notifyConnection, null);
   }



   /**
    * Performs an internal close without interrupting the read thread.
    *
    * @param  notifyConnection  Indicates whether the associated connection
    *                           should be notified.
    * @param  message           A message with additional information about the
    *                           reason for the closure, if available.
    */
   private void closeInternal(final boolean notifyConnection,
                              @Nullable final String message)
   {
     final InputStream is = inputStream;
     inputStream = null;

     try
     {
       if (is != null)
       {
         is.close();
       }
     }
     catch (final Exception e)
     {
       Debug.debugException(e);
     }

     if (notifyConnection)
     {
       connection.setClosed();
     }

     final Iterator<Integer> iterator = acceptorMap.keySet().iterator();
     while (iterator.hasNext())
     {
       final int messageID = iterator.next();
       final ResponseAcceptor acceptor = acceptorMap.get(messageID);

       try
       {
         if (message == null)
         {
           final DisconnectType disconnectType = connection.getDisconnectType();
           if (disconnectType == null)
           {
             acceptor.responseReceived(new ConnectionClosedResponse(
                  ResultCode.SERVER_DOWN, null));
           }
           else
           {
             acceptor.responseReceived(new ConnectionClosedResponse(
                  disconnectType.getResultCode(),
                  connection.getDisconnectMessage()));
           }
         }
         else
         {
           acceptor.responseReceived(new ConnectionClosedResponse(
                ResultCode.SERVER_DOWN, message));
         }
       }
       catch (final Exception e)
       {
         Debug.debugException(e);
       }

       iterator.remove();
     }
   }



  /**
   * Retrieves the handle to the thread used to read data from the server.  This
   * must not be used for any purpose other than test validation.
   *
   * @return  The handle to the thread used to read data from the server, or
   *          {@code null} if it is not available.
   */
  @Nullable()
  Thread getReaderThread()
  {
    return thread;
  }



  /**
   * Updates the name of the reader thread (if active) based on the information
   * known about the provided connection.
   */
  void updateThreadName()
  {
    final Thread t = thread;
    if (t != null)
    {
      try
      {
        t.setName(constructThreadName(connection.getConnectionInternals(true)));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }
  }



  /**
   * Determines the name that should be used for the reader thread based on
   * information about the associated client connection.
   *
   * @param  connectionInternals  The connection internals to use for
   *                              information about the address and port of the
   *                              directory server, or {@code null} if the
   *                              connection is not established.
   *
   * @return  The name that should be used for the reader thread based on
   *          information about the associated client connection.
   */
  @NotNull()
  private String constructThreadName(
       @Nullable final LDAPConnectionInternals connectionInternals)
  {
    final StringBuilder buffer = new StringBuilder();
    buffer.append("Connection reader for connection ");
    buffer.append(connection.getConnectionID());
    buffer.append(' ');

    String name = connection.getConnectionName();
    if (name != null)
    {
      buffer.append('\'');
      buffer.append(name);
      buffer.append("' ");
    }

    name = connection.getConnectionPoolName();
    if (name != null)
    {
      buffer.append("in pool '");
      buffer.append(name);
      buffer.append("' ");
    }

    if (connectionInternals == null)
    {
      buffer.append("(not connected)");
    }
    else
    {
      buffer.append("to ");
      buffer.append(connectionInternals.getHost());
      buffer.append(':');
      buffer.append(connectionInternals.getPort());
    }

    return buffer.toString();
  }
}
