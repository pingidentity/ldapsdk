/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
import java.net.ServerSocket;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import javax.net.ssl.SSLServerSocketFactory;

import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of an {@code SSLServerSocketFactory}
 * that will update the set of enabled protocols and cipher suites for a
 * {@code ServerSocket} upon creating the socket.  Note that although not all
 * server socket factory implementations are threadsafe, the LDAP SDK will only
 * use this factory in a way that is threadsafe.
 */
@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.MOSTLY_THREADSAFE)
final class SetEnabledProtocolsAndCipherSuitesSSLServerSocketFactory
      extends SSLServerSocketFactory
{
  // The set of cipher suites that should be enabled for server sockets created
  // by this socket factory.
  @NotNull private final Set<String> cipherSuites;

  // The set of protocols that should be enabled for server sockets created by
  // this socket factory.
  @NotNull private final Set<String> protocols;

  // The SSL server socket factory to which most of the work will be delegated.
  @NotNull private final SSLServerSocketFactory delegateFactory;



  /**
   * Creates a new instance of this server socket factory with the provided
   * information.
   *
   * @param  delegateFactory  The SSL server socket factory to which most
   *                          processing will be delegated.
   * @param  defaultProtocol  The default protocol to use.
   * @param  cipherSuites     The cipher suites to be enabled on sockets created
   *                          by this socket factory.
   */
  SetEnabledProtocolsAndCipherSuitesSSLServerSocketFactory(
       @NotNull final SSLServerSocketFactory delegateFactory,
       @NotNull final String defaultProtocol,
       @NotNull final Set<String> cipherSuites)
  {
    this.delegateFactory = delegateFactory;
    this.cipherSuites = cipherSuites;

    if (defaultProtocol.equalsIgnoreCase("TLSv1.2"))
    {
      protocols = new HashSet<>(
           Arrays.asList("TLSv1.2", "TLSv1.1", "TLSv1"));
    }
    else if (defaultProtocol.equalsIgnoreCase("TLSv1.1"))
    {
      protocols = new HashSet<>(Arrays.asList("TLSv1.1", "TLSv1"));
    }
    else if (defaultProtocol.equalsIgnoreCase("TLSv1"))
    {
      protocols = new HashSet<>(Collections.singletonList("TLSv1"));
    }
    else
    {
      // This will cause the socket to just use its default set of protocols.
      protocols = Collections.emptySet();
    }
  }



  /**
   * Creates a new instance of this server socket factory with the provided
   * information.
   *
   * @param  delegateFactory  The SSL server socket factory to which most
   *                          processing will be delegated.
   * @param  protocols        The protocols to be enabled on sockets created by
   *                          this socket factory.
   * @param  cipherSuites     The cipher suties to be enabled on sockets created
   *                          by this socket factory.
   */
  SetEnabledProtocolsAndCipherSuitesSSLServerSocketFactory(
       @NotNull final SSLServerSocketFactory delegateFactory,
       @NotNull final Set<String> protocols,
       @NotNull final Set<String> cipherSuites)
  {
    this.delegateFactory = delegateFactory;
    this.protocols       = protocols;
    this.cipherSuites    = cipherSuites;
  }



  /**
   * Creates a new unbound SSL server socket.
   *
   * @return  The SSL server socket that was created.
   *
   * @throws  IOException  If a problem is encountered while creating the server
   *                       socket.
   */
  @Override()
  @NotNull()
  public ServerSocket createServerSocket()
         throws IOException
  {
    final ServerSocket serverSocket = delegateFactory.createServerSocket();
    SSLUtil.applyEnabledSSLProtocols(serverSocket, protocols);
    SSLUtil.applyEnabledSSLCipherSuites(serverSocket, cipherSuites);
    return serverSocket;
  }



  /**
   * Creates a new SSL server socket that is bound to the specified port.
   *
   * @param  port  The port to which the SSL server socket should be bound.
   *
   * @return  The SSL server socket that was created.
   *
   * @throws  IOException  If a problem is encountered while creating the server
   *                       socket.
   */
  @Override()
  @NotNull()
  public ServerSocket createServerSocket(final int port)
         throws IOException
  {
    final ServerSocket serverSocket = delegateFactory.createServerSocket(port);
    SSLUtil.applyEnabledSSLProtocols(serverSocket, protocols);
    SSLUtil.applyEnabledSSLCipherSuites(serverSocket, cipherSuites);
    return serverSocket;
  }



  /**
   * Creates a new SSL server socket that is bound to the specified port.
   *
   * @param  port     The port to which the SSL server socket should be bound.
   * @param  backlog  The desired backlog size (i.e., the maximum number of
   *                  outstanding connection requests to support at any given
   *                  time) for the server socket.
   *
   * @return  The SSL server socket that was created.
   *
   * @throws  IOException  If a problem is encountered while creating the server
   *                       socket.
   */
  @Override()
  @NotNull()
  public ServerSocket createServerSocket(final int port, final int backlog)
         throws IOException
  {
    final ServerSocket serverSocket =
         delegateFactory.createServerSocket(port, backlog);
    SSLUtil.applyEnabledSSLProtocols(serverSocket, protocols);
    SSLUtil.applyEnabledSSLCipherSuites(serverSocket, cipherSuites);
    return serverSocket;
  }



  /**
   * Creates a new SSL server socket that is bound to the specified port.
   *
   * @param  port       The port to which the SSL server socket should be bound.
   * @param  backlog    The desired backlog size (i.e., the maximum number of
   *                    outstanding connection requests to support at any given
   *                    time) for the server socket.
   * @param  ifAddress  The network address ot which the SSL server socket
   *                    should be bound.
   *
   * @return  The SSL server socket that was created.
   *
   * @throws  IOException  If a problem is encountered while creating the server
   *                       socket.
   */
  @Override()
  @NotNull()
  public ServerSocket createServerSocket(final int port, final int backlog,
                                         @NotNull final InetAddress ifAddress)
         throws IOException
  {
    final ServerSocket serverSocket =
         delegateFactory.createServerSocket(port, backlog, ifAddress);
    SSLUtil.applyEnabledSSLProtocols(serverSocket, protocols);
    SSLUtil.applyEnabledSSLCipherSuites(serverSocket, cipherSuites);
    return serverSocket;
  }



  /**
   * Retrieves the set of cipher suites that are enabled by default.
   *
   * @return  The set of cipher suites that are enabled by default.
   */
  @Override()
  @NotNull()
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
  @NotNull()
  public String[] getSupportedCipherSuites()
  {
    return delegateFactory.getSupportedCipherSuites();
  }
}
