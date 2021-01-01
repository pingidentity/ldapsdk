/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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



import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;

import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides a thread that may be used to create an establish a
 * socket using a provided socket factory with a specified timeout.  This
 * provides a more reliable mechanism for attempting to establish a connection
 * with a timeout than using the {@code Socket.connect} method that takes a
 * timeout because this method cannot be used with some socket factories (like
 * SSL socket factories), and that method is also not reliable for hung servers
 * which are listening for connections but are not responsive.  The
 * {@link #getConnectedSocket} method should be called immediately after
 * starting the thread to wait for the connection to be established, or to fail
 * if it cannot be successfully established within the given timeout period.
 */
final class ConnectThread
      extends Thread
{
  // Indicates whether the connection has been successfully established.
  @NotNull private final AtomicBoolean connected;

  // The socket used for the connection.
  @NotNull private final AtomicReference<Socket> socket;

  // The thread being used to establish the connection.
  @NotNull private final AtomicReference<Thread> thread;

  // The exception caught while trying to establish the connection.
  @NotNull private final AtomicReference<Throwable> exception;

  // A latch that will be used to indicate that the thread has actually started.
  @NotNull private final CountDownLatch startLatch;

  // The maximum length of time in milliseconds that the connection attempt
  // should be allowed to block.
  private final int connectTimeoutMillis;

  // The port to which the connection should be established.
  private final int port;

  // The socket factory that will be used to create the connection.
  @NotNull private final SocketFactory socketFactory;

  // The address to which the connection should be established.
  @NotNull private final InetAddress address;



  /**
   * Creates a new instance of this connect thread with the provided
   * information.
   *
   * @param  socketFactory         The socket factory to use to create the
   *                               socket.
   * @param  address               The address to which the connection should be
   *                               established.
   * @param  port                  The port to which the connection should be
   *                               established.
   * @param  connectTimeoutMillis  The maximum length of time in milliseconds
   *                               that the connection attempt should be allowed
   *                               to block.
   */
  ConnectThread(@NotNull final SocketFactory socketFactory,
                @NotNull final InetAddress address,
                final int port, final int connectTimeoutMillis)
  {
    super("Background connect thread for " + address + ':' + port);
    setDaemon(true);

    this.socketFactory        = socketFactory;
    this.address              = address;
    this.port                 = port;
    this.connectTimeoutMillis = connectTimeoutMillis;

    connected  = new AtomicBoolean(false);
    socket     = new AtomicReference<>();
    thread     = new AtomicReference<>();
    exception  = new AtomicReference<>();
    startLatch = new CountDownLatch(1);
  }



  /**
   * Attempts to establish the connection.
   */
  @Override()
  public void run()
  {
    thread.set(Thread.currentThread());
    startLatch.countDown();

    try
    {
      boolean connectNeeded;
      Socket s;
      try
      {
        s = socketFactory.createSocket();
        connectNeeded = true;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        s = socketFactory.createSocket(address, port);
        connectNeeded = false;
      }
      socket.set(s);

      if (connectNeeded)
      {
        s.connect(new InetSocketAddress(address, port), connectTimeoutMillis);
      }
      connected.set(true);

      if (s instanceof SSLSocket)
      {
        try
        {
          ((SSLSocket) s).startHandshake();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          s.close();
          throw e;
        }
      }
    }
    catch (final Throwable t)
    {
      Debug.debugException(t);
      socket.set(null);
      connected.set(false);
      exception.set(t);
    }
    finally
    {
      thread.set(null);
    }
  }



  /**
   * Gets the connection after it has been established.  This should be called
   * immediately after starting the thread.
   *
   * @return  The socket that has been connected to the target server.
   *
   * @throws  LDAPException  If a problem occurs while attempting to establish
   *                         the connection, or if it cannot be established
   *                         within the specified time limit.
   */
  @NotNull()
  Socket getConnectedSocket()
         throws LDAPException
  {
    while (startLatch.getCount() > 0L)
    {
      try
      {
        startLatch.await();
        break;
      }
      catch (final InterruptedException ie)
      {
        Debug.debugException(ie);
        Thread.currentThread().interrupt();
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_CONNECT_THREAD_INTERRUPTED.get(address.getHostAddress(), port,
                  StaticUtils.getExceptionMessage(ie)),
             ie);
      }
    }

    final Thread t = thread.get();
    if (t != null)
    {
      try
      {
        t.join(connectTimeoutMillis);
      }
      catch (final InterruptedException ie)
      {
        Debug.debugException(ie);
        Thread.currentThread().interrupt();
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_CONNECT_THREAD_INTERRUPTED.get(address.getHostAddress(), port,
                  StaticUtils.getExceptionMessage(ie)),
             ie);
      }
    }

    if (connected.get())
    {
      return socket.get();
    }

    try
    {
      if (t != null)
      {
        t.interrupt();
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    try
    {
      final Socket s = socket.get();
      if (s != null)
      {
        s.close();
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    final Throwable cause = exception.get();
    if (cause == null)
    {
      throw new LDAPException(ResultCode.CONNECT_ERROR,
           ERR_CONNECT_THREAD_TIMEOUT.get(address, port, connectTimeoutMillis));
    }
    else
    {
      StaticUtils.rethrowIfError(cause);
      throw new LDAPException(ResultCode.CONNECT_ERROR,
           ERR_CONNECT_THREAD_EXCEPTION.get(address, port,
                StaticUtils.getExceptionMessage(cause)), cause);
    }
  }
}
