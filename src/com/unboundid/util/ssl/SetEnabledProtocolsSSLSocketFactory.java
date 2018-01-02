/*
 * Copyright 2015-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
package com.unboundid.util.ssl;



import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import javax.net.ssl.SSLSocketFactory;

import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of an {@code SSLSocketFactory} that
 * will update the set of enabled protocols as soon as the socket is connected.
 * Note that although not all socket factory implementations are threadsafe,
 * the LDAP SDK will only use this factory in a way that is threadsafe.
 */
@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.MOSTLY_THREADSAFE)
final class SetEnabledProtocolsSSLSocketFactory
      extends SSLSocketFactory
{
  // The set of protocols that should be enabled for sockets created by this
  // socket factory.
  private final Set<String> protocols;

  // The SSL socket factory to which most of the work will be delegated.
  private final SSLSocketFactory delegateFactory;



  /**
   * Creates a new instance of this socket factory with the provided
   * information.
   *
   * @param  delegateFactory  The SSL socket factory to which most processing
   *                          will be delegated.
   * @param  defaultProtocol  The default protocol to use.
   */
  SetEnabledProtocolsSSLSocketFactory(final SSLSocketFactory delegateFactory,
                                      final String defaultProtocol)
  {
    this.delegateFactory = delegateFactory;

    if (defaultProtocol.equalsIgnoreCase("TLSv1.2"))
    {
      protocols = new HashSet<String>(
           Arrays.asList("TLSv1.2", "TLSv1.1", "TLSv1"));
    }
    else if (defaultProtocol.equalsIgnoreCase("TLSv1.1"))
    {
      protocols = new HashSet<String>(Arrays.asList("TLSv1.1", "TLSv1"));
    }
    else if (defaultProtocol.equalsIgnoreCase("TLSv1"))
    {
      protocols = new HashSet<String>(Collections.singletonList("TLSv1"));
    }
    else
    {
      // This will cause the socket to just use its default set of protocols.
      protocols = Collections.emptySet();
    }
  }



  /**
   * Creates a new instance of this socket factory with the provided
   * information.
   *
   * @param  delegateFactory  The SSL socket factory to which most processing
   *                          will be delegated.
   * @param  protocols        The protocols to be enabled on sockets created by
   *                          this socket factory.
   */
  SetEnabledProtocolsSSLSocketFactory(final SSLSocketFactory delegateFactory,
                                      final Set<String> protocols)
  {
    this.delegateFactory = delegateFactory;
    this.protocols       = protocols;
  }



  /**
   * Creates a new unconnected socket.
   *
   * @return  The socket that was created.
   *
   * @throws  IOException  If the socket cannot be created.
   */
  @Override()
  public Socket createSocket()
         throws IOException
  {
    return new SetEnabledProtocolsSocket(delegateFactory.createSocket(),
         protocols);
  }



  /**
   * Creates a new socket with the provided information.
   *
   * @param  host  The remote address to which the socket should be connected.
   * @param  port  The remote port to which the socket should be connected.
   *
   * @return  The socket that was created.
   *
   * @throws  IOException  If the socket cannot be created.
   */
  @Override()
  public Socket createSocket(final String host, final int port)
         throws IOException
  {
    final Socket createdSocket =
         delegateFactory.createSocket(host, port);
    SSLUtil.applyEnabledSSLProtocols(createdSocket, protocols);
    return createdSocket;
  }



  /**
   * Creates a new socket with the provided information.
   *
   * @param  host       The remote address to which the socket should be
   *                    connected.
   * @param  port       The remote port to which the socket should be
   *                    connected.
   * @param  localHost  The local address to which the socket should be
   *                    connected.
   * @param  localPort  The local port to which the socket should be connected.
   *
   * @return  The socket that was created.
   *
   * @throws  IOException  If the socket cannot be created.
   */
  @Override()
  public Socket createSocket(final String host, final int port,
                             final InetAddress localHost, final int localPort)
         throws IOException
  {
    final Socket createdSocket =
         delegateFactory.createSocket(host, port, localHost, localPort);
    SSLUtil.applyEnabledSSLProtocols(createdSocket, protocols);
    return createdSocket;
  }



  /**
   * Creates a new socket with the provided information.
   *
   * @param  host  The remote address to which the socket should be connected.
   * @param  port  The remote port to which the socket should be connected.
   *
   * @return  The socket that was created.
   *
   * @throws  IOException  If the socket cannot be created.
   */
  @Override()
  public Socket createSocket(final InetAddress host, final int port)
         throws IOException
  {
    final Socket createdSocket =
         delegateFactory.createSocket(host, port);
    SSLUtil.applyEnabledSSLProtocols(createdSocket, protocols);
    return createdSocket;
  }



  /**
   * Creates a new socket with the provided information.
   *
   * @param  host       The remote address to which the socket should be
   *                    connected.
   * @param  port       The remote port to which the socket should be
   *                    connected.
   * @param  localHost  The local address to which the socket should be
   *                    connected.
   * @param  localPort  The local port to which the socket should be connected.
   *
   * @return  The socket that was created.
   *
   * @throws  IOException  If the socket cannot be created.
   */
  @Override()
  public Socket createSocket(final InetAddress host, final int port,
                             final InetAddress localHost, final int localPort)
         throws IOException
  {
    final Socket createdSocket =
         delegateFactory.createSocket(host, port, localHost, localPort);
    SSLUtil.applyEnabledSSLProtocols(createdSocket, protocols);
    return createdSocket;
  }



  /**
   * Creates a new socket that adds TLS protection to the provided socket.
   *
   * @param  s          The socket to use to create the {@code SSLSocket}.
   * @param  host       The host to which the socket is connected.
   * @param  port       The port to which the socket is connected.
   * @param  autoClose  Indicates whether to close the underlying socket when
   *                    the {@code SSLSocket} is closed.
   *
   * @return  The socket that was created.
   *
   * @throws  IOException  If a problem is encountered while creating the
   *                       socket.
   */
  @Override()
  public Socket createSocket(final Socket s, final String host, final int port,
                             final boolean autoClose)
         throws IOException
  {
    final Socket createdSocket =
         delegateFactory.createSocket(s, host, port, autoClose);
    SSLUtil.applyEnabledSSLProtocols(createdSocket, protocols);
    return createdSocket;
  }



  /**
   * Retrieves the set of cipher suites that are enabled by default.
   *
   * @return  The set of cipher suites that are enabled by default.
   */
  @Override()
  public String[] getDefaultCipherSuites()
  {
    return delegateFactory.getDefaultCipherSuites();
  }



  /**
   * Retrieves the set of cipher suites that could be enabled.
   *
   * @return  The set of cipher suites that could be enabled.
   */
  @Override()
  public String[] getSupportedCipherSuites()
  {
    return delegateFactory.getSupportedCipherSuites();
  }
}
