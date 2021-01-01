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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import javax.net.SocketFactory;

import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an {@link LDAPSocketFactory} implementation that wraps a
 * standard Java socket factory to use when creating sockets.  It will also
 * appear as a standard Java socket factory.
 * <BR><BR>
 * This class is primarily intended to be used in the process of updating
 * applications which use the Netscape Directory SDK for Java to switch to or
 * coexist with the UnboundID LDAP SDK for Java.  For applications not written
 * using the Netscape Directory SDK for Java, the standard Java socket factory
 * may be used directly without the need for the {@code LDAPSocketFactory}
 * interface.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JavaToLDAPSocketFactory
       extends SocketFactory
       implements LDAPSocketFactory
{
  // The socket factory that will be used.
  @NotNull private final SocketFactory f;



  /**
   * Creates a new instance of this class that will use the provided socket
   * factory.
   *
   * @param  f  The socket factory to use to create the LDAP socket factory.
   */
  public JavaToLDAPSocketFactory(@NotNull final SocketFactory f)
  {
    this.f = f;
  }



  /**
   * Creates a new socket to the specified server.
   *
   * @param  host  The host to which the connection should be established.
   * @param  port  The port to which the connection should be established.
   *
   * @return  The socket that was created.
   *
   * @throws  IOException  If a problem occurs while creating the socket.
   */
  @Override()
  @NotNull()
  public Socket createSocket(@NotNull final String host, final int port)
         throws IOException
  {
    synchronized (f)
    {
      return f.createSocket(host, port);
    }
  }



  /**
   * Creates a new socket to the specified server.
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
   * @return  The socket that was created.
   *
   * @throws  IOException  If a problem occurs while creating the socket.
   */
  @Override()
  @NotNull()
  public Socket createSocket(@NotNull final String host, final int port,
                             @NotNull final InetAddress localAddress,
                             final int localPort)
         throws IOException
  {
    synchronized (f)
    {
      return f.createSocket(host, port, localAddress, localPort);
    }
  }



  /**
   * Creates a new socket to the specified server.
   *
   * @param  address  The address to which the connection should be established.
   * @param  port     The port to which the connection should be established.
   *
   * @return  The socket that was created.
   *
   * @throws  IOException  If a problem occurs while creating the socket.
   */
  @Override()
  @NotNull()
  public Socket createSocket(@NotNull final InetAddress address, final int port)
         throws IOException
  {
    synchronized (f)
    {
      return f.createSocket(address, port);
    }
  }



  /**
   * Creates a new socket to the specified server.
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
   * @return  The socket that was created.
   *
   * @throws  IOException  If a problem occurs while creating the socket.
   */
  @Override()
  @NotNull()
  public Socket createSocket(@NotNull final InetAddress address, final int port,
                             @NotNull final InetAddress localAddress,
                             final int localPort)
         throws IOException
  {
    synchronized (f)
    {
      return f.createSocket(address, port, localAddress, localPort);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Socket makeSocket(@NotNull final String host, final int port)
         throws LDAPException
  {
    try
    {
      synchronized (f)
      {
        return f.createSocket(host, port);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(StaticUtils.getExceptionMessage(e),
           LDAPException.CONNECT_ERROR);
    }
  }
}
