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



import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ServerSocketFactory;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.extensions.NoticeOfDisconnectionExtendedResult;
import com.unboundid.util.Debug;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class provides a framework that may be used to accept connections from
 * LDAP clients and ensure that any requests received on those connections will
 * be processed appropriately.  It can be used to easily allow applications to
 * accept LDAP requests, to create a simple proxy that can intercept and
 * examine LDAP requests and responses passing between a client and server, or
 * helping to test LDAP clients.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process that can be used to create an
 * LDAP listener that will listen for LDAP requests on a randomly-selected port
 * and immediately respond to them with a "success" result:
 * <PRE>
 * // Create a canned response request handler that will always return a
 * // "SUCCESS" result in response to any request.
 * CannedResponseRequestHandler requestHandler =
 *    new CannedResponseRequestHandler(ResultCode.SUCCESS, null, null,
 *         null);
 *
 * // A listen port of zero indicates that the listener should
 * // automatically pick a free port on the system.
 * int listenPort = 0;
 *
 * // Create and start an LDAP listener to accept requests and blindly
 * // return success results.
 * LDAPListenerConfig listenerConfig = new LDAPListenerConfig(listenPort,
 *      requestHandler);
 * LDAPListener listener = new LDAPListener(listenerConfig);
 * listener.startListening();
 *
 * // Establish a connection to the listener and verify that a search
 * // request will get a success result.
 * LDAPConnection connection = new LDAPConnection("localhost",
 *      listener.getListenPort());
 * SearchResult searchResult = connection.search("dc=example,dc=com",
 *      SearchScope.BASE, Filter.createPresenceFilter("objectClass"));
 * LDAPTestUtils.assertResultCodeEquals(searchResult,
 *      ResultCode.SUCCESS);
 *
 * // Close the connection and stop the listener.
 * connection.close();
 * listener.shutDown(true);
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDAPListener
       extends Thread
{
  // Indicates whether a request has been received to stop running.
  private final AtomicBoolean stopRequested;

  // The connection ID value that should be assigned to the next connection that
  // is established.
  private final AtomicLong nextConnectionID;

  // The server socket that is being used to accept connections.
  private final AtomicReference<ServerSocket> serverSocket;

  // The thread that is currently listening for new client connections.
  private final AtomicReference<Thread> thread;

  // A map of all established connections.
  private final ConcurrentHashMap<Long,LDAPListenerClientConnection>
       establishedConnections;

  // The latch used to wait for the listener to have started.
  private final CountDownLatch startLatch;

  // The configuration to use for this listener.
  private final LDAPListenerConfig config;



  /**
   * Creates a new {@code LDAPListener} object with the provided configuration.
   * The {@link #startListening} method must be called after creating the object
   * to actually start listening for requests.
   *
   * @param  config  The configuration to use for this listener.
   */
  public LDAPListener(final LDAPListenerConfig config)
  {
    this.config = config.duplicate();

    stopRequested = new AtomicBoolean(false);
    nextConnectionID = new AtomicLong(0L);
    serverSocket = new AtomicReference<ServerSocket>(null);
    thread = new AtomicReference<Thread>(null);
    startLatch = new CountDownLatch(1);
    establishedConnections =
         new ConcurrentHashMap<Long,LDAPListenerClientConnection>();
    setName("LDAP Listener Thread (not listening");
  }



  /**
   * Creates the server socket for this listener and starts listening for client
   * connections.  This method will return after the listener has stated.
   *
   * @throws  IOException  If a problem occurs while creating the server socket.
   */
  public void startListening()
         throws IOException
  {
    final ServerSocketFactory f = config.getServerSocketFactory();
    final InetAddress a = config.getListenAddress();
    final int p = config.getListenPort();
    if (a == null)
    {
      serverSocket.set(f.createServerSocket(config.getListenPort(), 128));
    }
    else
    {
      serverSocket.set(f.createServerSocket(config.getListenPort(), 128, a));
    }

    final int receiveBufferSize = config.getReceiveBufferSize();
    if (receiveBufferSize > 0)
    {
      serverSocket.get().setReceiveBufferSize(receiveBufferSize);
    }

    setName("LDAP Listener Thread (listening on port " +
         serverSocket.get().getLocalPort() + ')');

    start();

    try
    {
      startLatch.await();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }
  }



  /**
   * Operates in a loop, waiting for client connections to arrive and ensuring
   * that they are handled properly.  This method is for internal use only and
   * must not be called by third-party code.
   */
  @InternalUseOnly()
  @Override()
  public void run()
  {
    thread.set(Thread.currentThread());
    final LDAPListenerExceptionHandler exceptionHandler =
         config.getExceptionHandler();

    try
    {
      startLatch.countDown();
      while (! stopRequested.get())
      {
        final Socket s;
        try
        {
          s = serverSocket.get().accept();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);

          if ((e instanceof SocketException) &&
              serverSocket.get().isClosed())
          {
            return;
          }

          if (exceptionHandler != null)
          {
            exceptionHandler.connectionCreationFailure(null, e);
          }

          continue;
        }

        final LDAPListenerClientConnection c;
        try
        {
          c = new LDAPListenerClientConnection(this, s,
               config.getRequestHandler(), config.getExceptionHandler());
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);

          if (exceptionHandler != null)
          {
            exceptionHandler.connectionCreationFailure(s, le);
          }

          continue;
        }

        final int maxConnections = config.getMaxConnections();
        if ((maxConnections > 0) &&
            (establishedConnections.size() >= maxConnections))
        {
          c.close(new LDAPException(ResultCode.BUSY,
               ERR_LDAP_LISTENER_MAX_CONNECTIONS_ESTABLISHED.get(
                    maxConnections)));
          continue;
        }

        establishedConnections.put(c.getConnectionID(), c);
        c.start();
      }
    }
    finally
    {
      final ServerSocket s = serverSocket.getAndSet(null);
      if (s != null)
      {
        try
        {
          s.close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }

      serverSocket.set(null);
      thread.set(null);
    }
  }



  /**
   * Closes all connections that are currently established to this listener.
   * This has no effect on the ability to accept new connections.
   *
   * @param  sendNoticeOfDisconnection  Indicates whether to send the client a
   *                                    notice of disconnection unsolicited
   *                                    notification before closing the
   *                                    connection.
   */
  public void closeAllConnections(final boolean sendNoticeOfDisconnection)
  {
    final NoticeOfDisconnectionExtendedResult noticeOfDisconnection =
         new NoticeOfDisconnectionExtendedResult(ResultCode.OTHER, null);

    final ArrayList<LDAPListenerClientConnection> connList =
         new ArrayList<LDAPListenerClientConnection>(
              establishedConnections.values());
    for (final LDAPListenerClientConnection c : connList)
    {
      if (sendNoticeOfDisconnection)
      {
        try
        {
          c.sendUnsolicitedNotification(noticeOfDisconnection);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }

      try
      {
        c.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }
  }



  /**
   * Indicates that this listener should stop accepting connections.  It may
   * optionally also terminate any existing connections that are already
   * established.
   *
   * @param  closeExisting  Indicates whether to close existing connections that
   *                        may already be established.
   */
  public void shutDown(final boolean closeExisting)
  {
    stopRequested.set(true);

    final ServerSocket s = serverSocket.get();
    if (s != null)
    {
      try
      {
        s.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    final Thread t = thread.get();
    if (t != null)
    {
      while (t.isAlive())
      {
        try
        {
          t.join(100L);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);

          if (e instanceof InterruptedException)
          {
            Thread.currentThread().interrupt();
          }
        }

        if (t.isAlive())
        {

          try
          {
            t.interrupt();
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
          }
        }
      }
    }

    if (closeExisting)
    {
      closeAllConnections(false);
    }
  }



  /**
   * Retrieves the address on which this listener is accepting client
   * connections.  Note that if no explicit listen address was configured, then
   * the address returned may not be usable by clients.  In the event that the
   * {@code InetAddress.isAnyLocalAddress} method returns {@code true}, then
   * clients should generally use {@code localhost} to attempt to establish
   * connections.
   *
   * @return  The address on which this listener is accepting client
   *          connections, or {@code null} if it is not currently listening for
   *          client connections.
   */
  public InetAddress getListenAddress()
  {
    final ServerSocket s = serverSocket.get();
    if (s == null)
    {
      return null;
    }
    else
    {
      return s.getInetAddress();
    }
  }



  /**
   * Retrieves the port on which this listener is accepting client connections.
   *
   * @return  The port on which this listener is accepting client connections,
   *          or -1 if it is not currently listening for client connections.
   */
  public int getListenPort()
  {
    final ServerSocket s = serverSocket.get();
    if (s == null)
    {
      return -1;
    }
    else
    {
      return s.getLocalPort();
    }
  }



  /**
   * Retrieves the configuration in use for this listener.  It must not be
   * altered in any way.
   *
   * @return  The configuration in use for this listener.
   */
  LDAPListenerConfig getConfig()
  {
    return config;
  }



  /**
   * Retrieves the connection ID that should be used for the next connection
   * accepted by this listener.
   *
   * @return  The connection ID that should be used for the next connection
   *          accepted by this listener.
   */
  long nextConnectionID()
  {
    return nextConnectionID.getAndIncrement();
  }



  /**
   * Indicates that the provided client connection has been closed and is no
   * longer listening for client connections.
   *
   * @param  connection  The connection that has been closed.
   */
  void connectionClosed(final LDAPListenerClientConnection connection)
  {
    establishedConnections.remove(connection.getConnectionID());
  }
}
