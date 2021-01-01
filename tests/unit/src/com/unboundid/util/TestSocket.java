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
package com.unboundid.util;



import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.channels.SocketChannel;



/**
 * This class provides a {@code Socket} implementation that will use a provided
 * input and output stream for reading and writing.
 */
public final class TestSocket
       extends Socket
{
  // Indicates whether to throw an exception on an attempt to close the socket.
  private boolean throwOnClose;

  // Indicates whether to throw an exception on an attempt to get the input
  // stream.
  private boolean throwOnGetInputStream;

  // Indicates whether to throw an exception on an attempt to get the output
  // stream.
  private boolean throwOnGetOutputStream;

  // The input stream to use for this socket.
  private final InputStream inputStream;

  // The output stream to use for this socket.
  private final OutputStream outputStream;



  /**
   * Creates a new instance of this class that will use the provided input and
   * output streams.
   *
   * @param  inputStream   The input stream to use for this socket.
   * @param  outputStream  The output stream to use for this socket.
   */
  public TestSocket(final InputStream inputStream,
                    final OutputStream outputStream)
  {
    this.inputStream  = inputStream;
    this.outputStream = outputStream;
  }



  /**
   * Connects this socket to the provided remote address.  This method has no
   * effect.
   *
   * @param  address  The address to which this socket should be connected.
   */
  @Override()
  public void connect(final SocketAddress address)
  {
    // No implementation required.
  }



  /**
   * Connects this socket to the provided remote address.  This method has no
   * effect.
   *
   * @param  address  The address to which this socket should be connected.
   * @param  timeout  The connect timeout in milliseconds.
   */
  @Override()
  public void connect(final SocketAddress address, final int timeout)
  {
    // No implementation required.
  }



  /**
   * Binds this socket to the provided local address.  This method has no
   * effect.
   *
   * @param  address The local address to which to bind this socket.
   */
  @Override()
  public void bind(final SocketAddress address)
  {
    // No implementation required.
  }



  /**
   * Indicates whether to throw an exception when trying to close the socket.
   *
   * @return  {@code true} if an exception should be thrown, or {@code false} if
   *          not.
   */
  public boolean throwOnClose()
  {
    return throwOnClose;
  }



  /**
   * Specifies whether to throw an exception when trying to close the socket.
   *
   * @param  shouldThrow  Indicates whether to throw an exception when trying to
   *                      close the socket.
   */
  public void setThrowOnClose(final boolean shouldThrow)
  {
    throwOnClose = shouldThrow;
  }



  /**
   * Closes this socket and the underlying input and output streams.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public void close()
         throws IOException
  {
    inputStream.close();
    outputStream.close();

    if (throwOnClose)
    {
      throw new IOException("Error closing the socket");
    }
  }



  /**
   * Retrieves the remote address to which this socket is connected.
   *
   * @return  The remote address to which this socket is connected, or
   *          {@code null} if it is not connected.
   */
  @Override()
  public InetAddress getInetAddress()
  {
    try
    {
      return InetAddress.getLocalHost();
    }
    catch (final Exception e)
    {
      return null;
    }
  }



  /**
   * Retrieves the local address to which this socket is bound.
   *
   * @return  The local address to which this socket is bound, or {@code null}
   *          if it is not connected.
   */
  @Override()
  public InetAddress getLocalAddress()
  {
    try
    {
      return InetAddress.getLocalHost();
    }
    catch (final Exception e)
    {
      return null;
    }
  }



  /**
   * Retrieves the remote port to which this socket is connected.
   *
   * @return  The remote port to which this socket is connected.
   */
  @Override()
  public int getPort()
  {
    return 12345;
  }



  /**
   * Retrieves the local port to which this socket is bound.
   *
   * @return  The local port to which this socket is bound.
   */
  @Override()
  public int getLocalPort()
  {
    return 54321;
  }



  /**
   * Retrieves the remote address to which this socket is connected.
   *
   * @return  The remote address to which this socket is connected, or
   *          {@code null} if it is not connected.
   */
  @Override()
  public SocketAddress getRemoteSocketAddress()
  {
    try
    {
      return new InetSocketAddress(InetAddress.getLocalHost(), 12345);
    }
    catch (final Exception e)
    {
      return null;
    }
  }



  /**
   * Retrieves the local address to which this socket is bound.
   *
   * @return  The local address to which this socket is bound, or {@code null}
   *          if it is not connected.
   */
  @Override()
  public SocketAddress getLocalSocketAddress()
  {
    try
    {
      return new InetSocketAddress(InetAddress.getLocalHost(), 54321);
    }
    catch (final Exception e)
    {
      return null;
    }
  }



  /**
   * Retrieves the socket channel for this socket.
   *
   * @return  {@code null} because it is not associated with a channel.
   */
  @Override()
  public SocketChannel getChannel()
  {
    return null;
  }



  /**
   * Indicates whether to throw an exception when trying to get the input
   * stream.
   *
   * @return  {@code true} if an exception should be thrown, or {@code false} if
   *          not.
   */
  public boolean throwOnGetInputStream()
  {
    return throwOnGetInputStream;
  }



  /**
   * Specifies whether to throw an exception when trying to get the input
   * stream.
   *
   * @param  shouldThrow  Indicates whether to throw an exception when trying to
   *                      get the input stream.
   */
  public void setThrowOnGetInputStream(final boolean shouldThrow)
  {
    throwOnGetInputStream = shouldThrow;
  }



  /**
   * Retrieves the input stream for this socket.
   *
   * @return  The input stream for this socket.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public InputStream getInputStream()
         throws IOException
  {
    if (throwOnGetInputStream)
    {
      throw new IOException("Can't get the input stream");
    }

    return inputStream;
  }



  /**
   * Indicates whether to throw an exception when trying to get the output
   * stream.
   *
   * @return  {@code true} if an exception should be thrown, or {@code false} if
   *          not.
   */
  public boolean throwOnGetOutputStream()
  {
    return throwOnGetOutputStream;
  }



  /**
   * Specifies whether to throw an exception when trying to get the output
   * stream.
   *
   * @param  shouldThrow  Indicates whether to throw an exception when trying to
   *                      get the output stream.
   */
  public void setThrowOnGetOutputStream(final boolean shouldThrow)
  {
    throwOnGetOutputStream = shouldThrow;
  }



  /**
   * Retrieves the output stream for this socket.
   *
   * @return  The output stream for this socket.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public OutputStream getOutputStream()
         throws IOException
  {
    if (throwOnGetOutputStream)
    {
      throw new IOException("Can't get the output stream");
    }

    return outputStream;
  }



  /**
   * Gets the TCP_NODELAY value for this socket.  This method always returns
   * {@code true}.
   *
   * @return  {@code true}.
   */
  @Override()
  public boolean getTcpNoDelay()
  {
    return true;
  }



  /**
   * Sets the TCP_NODELAY value for this socket.  This method has no effect.
   *
   * @param  value  The value to use for TCP_NODELAY.
   */
  @Override()
  public void setTcpNoDelay(final boolean value)
  {
    // No implementation is required.
  }



  /**
   * Retrieves the linger timeout for this socket in seconds.  This method
   * always returns 5.
   *
   * @return  The linger timeout for this socket in seconds.
   */
  @Override()
  public int getSoLinger()
  {
    return 5;
  }



  /**
   * Sets the SO_LINGER value for this socket.  This method has no effect.
   *
   * @param  useLinger  Indicates whether to use linger.
   * @param  time       The linger time to use in seconds.
   */
  @Override()
  public void setSoLinger(final boolean useLinger, final int time)
  {
    // No implementation is required.
  }



  /**
   * Sends a single byte of urgent data.
   *
   * @param  data  The byte to be sent.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public void sendUrgentData(final int data)
         throws IOException
  {
    outputStream.write(data);
  }



  /**
   * Indicates whether OOBINLINE is enabled.  This method always returns
   * {@code false}.
   *
   * @return  {@code false}.
   */
  @Override()
  public boolean getOOBInline()
  {
    return false;
  }



  /**
   * Specifies whether to use OOBINLINE.  This method has no effect.
   *
   * @param  value  The value to use.
   */
  @Override()
  public void setOOBInline(final boolean value)
  {
    // No implementation required.
  }



  /**
   * Retrieves the SO_TIMEOUT value for this socket.  This method always returns
   * 0.
   *
   * @return  Zero.
   */
  @Override()
  public int getSoTimeout()
  {
    return 0;
  }



  /**
   * Specifies the SO_TIMEOUT value to use.  This method has no effect.
   *
   * @param  value  The value to use.
   */
  @Override()
  public void setSoTimeout(final int value)
  {
    // No implementation required.
  }



  /**
   * Retrieves the send buffer size for this socket.  This method always returns
   * 8192.
   *
   * @return  8192.
   */
  @Override()
  public int getSendBufferSize()
  {
    return 8192;
  }



  /**
   * Specifies the send buffer size for this socket.  This method has no effect.
   *
   * @param  value  The value to use.
   */
  @Override()
  public void setSendBufferSize(final int value)
  {
    // No implementation required.
  }



  /**
   * Retrieves the receive buffer size for this socket.  This method always
   * returns 8192.
   *
   * @return  8192.
   */
  @Override()
  public int getReceiveBufferSize()
  {
    return 8192;
  }



  /**
   * Specifies the receive buffer size for this socket.  This method has no
   * effect.
   *
   * @param  value  The value to use.
   */
  @Override()
  public void setReceiveBufferSize(final int value)
  {
    // No implementation required.
  }



  /**
   * Retrieves the SO_KEEPALIVE value for this socket.  This method always
   * returns {@code true}.
   *
   * @return  {@code true}.
   */
  @Override()
  public boolean getKeepAlive()
  {
    return true;
  }



  /**
   * Specifies the SO_KEEPALIVE value to use.  This method has no effect.
   *
   * @param  value  The value to use.
   */
  @Override()
  public void setKeepAlive(final boolean value)
  {
    // No implementation required.
  }



  /**
   * Retrieves the traffic class value for this socket.  This method always
   * returns zero.
   *
   * @return  Zero.
   */
  @Override()
  public int getTrafficClass()
  {
    return 0;
  }



  /**
   * Specifies the traffic class value to use.  This method has no effect.
   *
   * @param  value  The value to use.
   */
  @Override()
  public void setTrafficClass(final int value)
  {
    // No implementation required.
  }



  /**
   * Retrieves the SO_REUSEADDR value for this socket.  This method always
   * returns {@code true}.
   *
   * @return  {@code true}.
   */
  @Override()
  public boolean getReuseAddress()
  {
    return true;
  }



  /**
   * Specifies the SO_REUSEADDR value to use.  This method has no effect.
   *
   * @param  value  The value to use.
   */
  @Override()
  public void setReuseAddress(final boolean value)
  {
    // No implementation required.
  }



  /**
   * Closes the input stream for this socket.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public void shutdownInput()
         throws IOException
  {
    inputStream.close();
  }



  /**
   * Indicates whether the input stream has been closed.  This method will
   * always return {@code false}.
   *
   * @return  {@code false}.
   */
  @Override()
  public boolean isInputShutdown()
  {
    return false;
  }



  /**
   * Closes the output stream for this socket.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public void shutdownOutput()
         throws IOException
  {
    inputStream.close();
  }



  /**
   * Indicates whether the output stream has been closed.  This method will
   * always return {@code false}.
   *
   * @return  {@code false}.
   */
  @Override()
  public boolean isOutputShutdown()
  {
    return false;
  }



  /**
   * Indicates whether this socket is connected.  This method will always return
   * {@code true}.
   *
   * @return  {@code true}.
   */
  @Override()
  public boolean isConnected()
  {
    return true;
  }



  /**
   * Indicates whether this socket is bound.  This method will always return
   * {@code true}.
   *
   * @return  {@code true}.
   */
  @Override()
  public boolean isBound()
  {
    return true;
  }



  /**
   * Indicates whether this socket is closed.  This method will always return
   * {@code false}.
   *
   * @return  {@code false}.
   */
  @Override()
  public boolean isClosed()
  {
    return false;
  }



  /**
   * Sets performance preferences for this socket.  This method has no effect.
   *
   * @param  connectionTime  The connection time value to use.
   * @param  latency         The latency value to use.
   * @param  bandwidth       The bandwidth value to use.
   */
  @Override()
  public void setPerformancePreferences(final int connectionTime,
                                        final int latency, final int bandwidth)
  {
    // No implementation required.
  }
}
