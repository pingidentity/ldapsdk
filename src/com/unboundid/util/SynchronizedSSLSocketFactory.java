/*
 * Copyright 2012-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2012-2018 Ping Identity Corporation
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
package com.unboundid.util;



import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import javax.net.ssl.SSLSocketFactory;



/**
 * This class provides an implementation of a Java socket factory that will
 * wrap a provided socket factory but will synchronize on each use of that
 * factory to ensure that only a single thread may use that factory to create
 * a socket at any given time.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SynchronizedSSLSocketFactory
       extends SSLSocketFactory
{
  // The wrapped SSL socket factory.
  private final SSLSocketFactory factory;



  /**
   * Creates a new synchronous socket factory instance that will wrap the
   * provided socket factory.
   *
   * @param  factory  The socket factory to be wrapped.
   */
  public SynchronizedSSLSocketFactory(final SSLSocketFactory factory)
  {
    this.factory = factory;
  }



  /**
   * Retrieves the {@code SSLSocketFactory} instance wrapped by this
   * synchronized SSL socket factory.
   *
   * @return  The {@code SSLSocketFactory} instance wrapped by this synchronized
   *          SSL socket factory.
   */
  public SSLSocketFactory getWrappedSocketFactory()
  {
    return factory;
  }



  /**
   * Creates a new SSL socket to the specified server.
   *
   * @param  host  The host to which the connection should be established.
   * @param  port  The port to which the connection should be established.
   *
   * @return  The SSL socket that was created.
   *
   * @throws  IOException  If a problem occurs while creating the socket.
   */
  @Override()
  public Socket createSocket(final String host, final int port)
         throws IOException
  {
    synchronized (factory)
    {
      return factory.createSocket(host, port);
    }
  }



  /**
   * Creates a new SSL socket to the specified server.
   *
   * @param  host          The host to which the connection should be
   *                       established.
   * @param  port          The port to which the connection should be
   *                       established.
   * @param  localAddress  The local address to use for the connection.  This
   *                       will be ignored.
   * @param  localPort     The local port to use for the connection.  This will
   *                       be ignored.
   *
   * @return  The SSL socket that was created.
   *
   * @throws  IOException  If a problem occurs while creating the socket.
   */
  @Override()
  public Socket createSocket(final String host, final int port,
                             final InetAddress localAddress,
                             final int localPort)
         throws IOException
  {
    synchronized (factory)
    {
      return factory.createSocket(host, port, localAddress, localPort);
    }
  }



  /**
   * Creates a new SSL socket to the specified server.
   *
   * @param  address  The address to which the connection should be established.
   * @param  port     The port to which the connection should be established.
   *
   * @return  The SSL socket that was created.
   *
   * @throws  IOException  If a problem occurs while creating the socket.
   */
  @Override()
  public Socket createSocket(final InetAddress address, final int port)
         throws IOException
  {
    synchronized (factory)
    {
      return factory.createSocket(address, port);
    }
  }



  /**
   * Creates a new SSL socket to the specified server.
   *
   * @param  address       The address to which the connection should be
   *                       established.
   * @param  port          The port to which the connection should be
   *                       established.
   * @param  localAddress  The local address to use for the connection.  This
   *                       will be ignored.
   * @param  localPort     The local port to use for the connection.  This will
   *                       be ignored.
   *
   * @return  The SSL socket that was created.
   *
   * @throws  IOException  If a problem occurs while creating the socket.
   */
  @Override()
  public Socket createSocket(final InetAddress address, final int port,
                             final InetAddress localAddress,
                             final int localPort)
         throws IOException
  {
    synchronized (factory)
    {
      return factory.createSocket(address, port, localAddress, localPort);
    }
  }



  /**
   * Creates a new SSL socket that wraps the provided socket.
   *
   * @param  s          The existing socket to be wrapped to create an SSL
   *                    socket.
   * @param  host       The host to which the connection is established.
   * @param  port       The port to which the connection is established.
   * @param  autoClose  Indicates whether the provided socket should be closed
   *                    when the created SSL socket is closed.
   *
   * @return  The SSL socket that was created.
   *
   * @throws  IOException  If a problem occurs while creating the socket.
   */
  @Override()
  public Socket createSocket(final Socket s, final String host, final int port,
                             final boolean autoClose)
         throws IOException
  {
    synchronized (factory)
    {
      return factory.createSocket(s, host, port, autoClose);
    }
  }



  /**
   * Retrieves the set of cipher suites which are enabled by default.
   *
   * @return  The set of cipher suites which are enabled by default.
   */
  @Override()
  public String[] getDefaultCipherSuites()
  {
    synchronized (factory)
    {
      return factory.getDefaultCipherSuites();
    }
  }



  /**
   * Retrieves the entire set of cipher suites that could be used.
   *
   * @return  The entire set of cipher suites that could be used.
   */
  @Override()
  public String[] getSupportedCipherSuites()
  {
    synchronized (factory)
    {
      return factory.getSupportedCipherSuites();
    }
  }
}
