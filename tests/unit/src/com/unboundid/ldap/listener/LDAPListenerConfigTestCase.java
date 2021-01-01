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



import java.io.IOException;
import java.net.InetAddress;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.ThrowsOnCreateServerSocketFactory;



/**
 * This class provides a set of test cases for the {@code LDAPListenerConfig}
 * class.
 */
public final class LDAPListenerConfigTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the listen port configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testListenPort()
         throws Exception
  {
    LDAPListenerConfig c = new LDAPListenerConfig(1234,
         new CannedResponseRequestHandler());
    assertEquals(c.getListenPort(), 1234);
    c = c.duplicate();
    assertEquals(c.getListenPort(), 1234);

    assertNotNull(c.toString());

    try
    {
      c.setListenPort(-1);
    }
    catch (LDAPSDKUsageException lue)
    {
      // This was expected.
    }
    assertEquals(c.getListenPort(), 1234);

    assertNotNull(c.toString());

    c.setListenPort(5678);
    assertEquals(c.getListenPort(), 5678);
    c = c.duplicate();
    assertEquals(c.getListenPort(), 5678);

    assertNotNull(c.toString());

    try
    {
      c.setListenPort(123456);
    }
    catch (LDAPSDKUsageException lue)
    {
      // This was expected.
    }
    assertEquals(c.getListenPort(), 5678);

    assertNotNull(c.toString());

    c.setListenPort(0);
    assertEquals(c.getListenPort(), 0);
    c = c.duplicate();
    assertEquals(c.getListenPort(), 0);

    assertNotNull(c.toString());

    try
    {
      c = new LDAPListenerConfig(-1, new CannedResponseRequestHandler());
    }
    catch (LDAPSDKUsageException lue)
    {
      // This was expected.
    }

    assertNotNull(c.toString());

    try
    {
      c = new LDAPListenerConfig(123456, new CannedResponseRequestHandler());
    }
    catch (LDAPSDKUsageException lue)
    {
      // This was expected.
    }

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the request handler configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequestHandler()
         throws Exception
  {
    final CannedResponseRequestHandler originalHandler =
         new CannedResponseRequestHandler();

    LDAPListenerConfig c = new LDAPListenerConfig(1234, originalHandler);
    assertNotNull(c.getRequestHandler());
    assertSame(c.getRequestHandler(), originalHandler);
    c = c.duplicate();
    assertNotNull(c.getRequestHandler());
    assertSame(c.getRequestHandler(), originalHandler);

    assertNotNull(c.toString());

    try
    {
      c.setRequestHandler(null);
    }
    catch (LDAPSDKUsageException lue)
    {
      // This was expected.
    }
    assertNotNull(c.getRequestHandler());
    assertSame(c.getRequestHandler(), originalHandler);
    c = c.duplicate();
    assertNotNull(c.getRequestHandler());
    assertSame(c.getRequestHandler(), originalHandler);

    assertNotNull(c.toString());

    c.setRequestHandler(new CannedResponseRequestHandler());
    assertNotNull(c.getRequestHandler());
    assertNotSame(c.getRequestHandler(), originalHandler);
    c = c.duplicate();
    assertNotNull(c.getRequestHandler());
    assertNotSame(c.getRequestHandler(), originalHandler);

    assertNotNull(c.toString());

    c.setRequestHandler(originalHandler);
    assertNotNull(c.getRequestHandler());
    assertSame(c.getRequestHandler(), originalHandler);
    c = c.duplicate();
    assertNotNull(c.getRequestHandler());
    assertSame(c.getRequestHandler(), originalHandler);

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the useKeepAlive configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUseKeepAlive()
         throws Exception
  {
    LDAPListenerConfig c = new LDAPListenerConfig(1234,
         new CannedResponseRequestHandler());
    assertTrue(c.useKeepAlive());
    c = c.duplicate();
    assertTrue(c.useKeepAlive());

    assertNotNull(c.toString());

    c.setUseKeepAlive(false);
    assertFalse(c.useKeepAlive());
    c = c.duplicate();
    assertFalse(c.useKeepAlive());

    assertNotNull(c.toString());

    c.setUseKeepAlive(true);
    assertTrue(c.useKeepAlive());
    c = c.duplicate();
    assertTrue(c.useKeepAlive());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the useLinger configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUseLinger()
         throws Exception
  {
    LDAPListenerConfig c = new LDAPListenerConfig(1234,
         new CannedResponseRequestHandler());
    assertTrue(c.useLinger());
    c = c.duplicate();
    assertTrue(c.useLinger());

    assertNotNull(c.toString());

    c.setUseLinger(false);
    assertFalse(c.useLinger());
    c = c.duplicate();
    assertFalse(c.useLinger());

    assertNotNull(c.toString());

    c.setUseLinger(true);
    assertTrue(c.useLinger());
    c = c.duplicate();
    assertTrue(c.useLinger());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the useReuseAddress configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUseReuseAddress()
         throws Exception
  {
    LDAPListenerConfig c = new LDAPListenerConfig(1234,
         new CannedResponseRequestHandler());
    assertTrue(c.useReuseAddress());
    c = c.duplicate();
    assertTrue(c.useReuseAddress());

    assertNotNull(c.toString());

    c.setUseReuseAddress(false);
    assertFalse(c.useReuseAddress());
    c = c.duplicate();
    assertFalse(c.useReuseAddress());

    assertNotNull(c.toString());

    c.setUseReuseAddress(true);
    assertTrue(c.useReuseAddress());
    c = c.duplicate();
    assertTrue(c.useReuseAddress());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the useTCPNoDelay configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUseTCPNoDelay()
         throws Exception
  {
    LDAPListenerConfig c = new LDAPListenerConfig(1234,
         new CannedResponseRequestHandler());
    assertTrue(c.useTCPNoDelay());
    c = c.duplicate();
    assertTrue(c.useTCPNoDelay());

    assertNotNull(c.toString());

    c.setUseTCPNoDelay(false);
    assertFalse(c.useTCPNoDelay());
    c = c.duplicate();
    assertFalse(c.useTCPNoDelay());

    assertNotNull(c.toString());

    c.setUseTCPNoDelay(true);
    assertTrue(c.useTCPNoDelay());
    c = c.duplicate();
    assertTrue(c.useTCPNoDelay());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the listen address configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testListenAddress()
         throws Exception
  {
    LDAPListenerConfig c = new LDAPListenerConfig(1234,
         new CannedResponseRequestHandler());
    assertNull(c.getListenAddress());
    c = c.duplicate();
    assertNull(c.getListenAddress());

    assertNotNull(c.toString());

    final InetAddress localHost = InetAddress.getLocalHost();
    c.setListenAddress(localHost);
    assertNotNull(c.getListenAddress());
    assertEquals(c.getListenAddress(), localHost);
    c = c.duplicate();
    assertNotNull(c.getListenAddress());
    assertEquals(c.getListenAddress(), localHost);

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the linger timeout configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLingerTimeout()
         throws Exception
  {
    LDAPListenerConfig c = new LDAPListenerConfig(1234,
         new CannedResponseRequestHandler());
    assertEquals(c.getLingerTimeoutSeconds(), 5);
    c = c.duplicate();
    assertEquals(c.getLingerTimeoutSeconds(), 5);

    assertNotNull(c.toString());

    c.setLingerTimeoutSeconds(1234);
    assertEquals(c.getLingerTimeoutSeconds(), 1234);

    assertNotNull(c.toString());

    try
    {
      c.setLingerTimeoutSeconds(-1);
    }
    catch (LDAPSDKUsageException lse)
    {
      // This was expected.
    }
    assertEquals(c.getLingerTimeoutSeconds(), 1234);

    assertNotNull(c.toString());

    try
    {
      c.setLingerTimeoutSeconds(123456);
    }
    catch (LDAPSDKUsageException lse)
    {
      // This was expected.
    }
    assertEquals(c.getLingerTimeoutSeconds(), 1234);

    assertNotNull(c.toString());

    c.setLingerTimeoutSeconds(1);
    assertEquals(c.getLingerTimeoutSeconds(), 1);
    c = c.duplicate();
    assertEquals(c.getLingerTimeoutSeconds(), 1);

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the max connections configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMaxConnections()
         throws Exception
  {
    LDAPListenerConfig c = new LDAPListenerConfig(1234,
         new CannedResponseRequestHandler());
    assertEquals(c.getMaxConnections(), 0);
    c = c.duplicate();
    assertEquals(c.getMaxConnections(), 0);

    assertNotNull(c.toString());

    c.setMaxConnections(1234);
    assertEquals(c.getMaxConnections(), 1234);
    c = c.duplicate();
    assertEquals(c.getMaxConnections(), 1234);

    assertNotNull(c.toString());

    c.setMaxConnections(-1);
    assertEquals(c.getMaxConnections(), 0);
    c = c.duplicate();
    assertEquals(c.getMaxConnections(), 0);

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the max message size configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMaxMessageSize()
         throws Exception
  {
    LDAPListenerConfig c = new LDAPListenerConfig(1234,
         new CannedResponseRequestHandler());
    assertEquals(c.getMaxMessageSizeBytes(),
         new LDAPConnectionOptions().getMaxMessageSize());
    c = c.duplicate();
    assertEquals(c.getMaxMessageSizeBytes(),
         new LDAPConnectionOptions().getMaxMessageSize());

    assertNotNull(c.toString());

    c.setMaxMessageSizeBytes(123_456_789);
    assertEquals(c.getMaxMessageSizeBytes(), 123_456_789);
    c = c.duplicate();
    assertEquals(c.getMaxMessageSizeBytes(), 123_456_789);

    assertNotNull(c.toString());

    c.setMaxMessageSizeBytes(-1);
    assertEquals(c.getMaxMessageSizeBytes(), Integer.MAX_VALUE);
    c = c.duplicate();
    assertEquals(c.getMaxMessageSizeBytes(), Integer.MAX_VALUE);

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the receive buffer size configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReceiveBufferSize()
         throws Exception
  {
    LDAPListenerConfig c = new LDAPListenerConfig(1234,
         new CannedResponseRequestHandler());
    assertEquals(c.getReceiveBufferSize(), 0);
    c = c.duplicate();
    assertEquals(c.getReceiveBufferSize(), 0);

    assertNotNull(c.toString());

    c.setReceiveBufferSize(1234);
    assertEquals(c.getReceiveBufferSize(), 1234);
    c = c.duplicate();
    assertEquals(c.getReceiveBufferSize(), 1234);

    assertNotNull(c.toString());

    c.setReceiveBufferSize(0);
    assertEquals(c.getReceiveBufferSize(), 0);
    c = c.duplicate();
    assertEquals(c.getReceiveBufferSize(), 0);

    assertNotNull(c.toString());

    c.setReceiveBufferSize(5678);
    assertEquals(c.getReceiveBufferSize(), 5678);
    c = c.duplicate();
    assertEquals(c.getReceiveBufferSize(), 5678);

    assertNotNull(c.toString());

    c.setReceiveBufferSize(-1);
    assertEquals(c.getReceiveBufferSize(), 0);
    c = c.duplicate();
    assertEquals(c.getReceiveBufferSize(), 0);

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the send buffer size configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendBufferSize()
         throws Exception
  {
    LDAPListenerConfig c = new LDAPListenerConfig(1234,
         new CannedResponseRequestHandler());
    assertEquals(c.getSendBufferSize(), 0);
    c = c.duplicate();
    assertEquals(c.getSendBufferSize(), 0);

    assertNotNull(c.toString());

    c.setSendBufferSize(1234);
    assertEquals(c.getSendBufferSize(), 1234);
    c = c.duplicate();
    assertEquals(c.getSendBufferSize(), 1234);

    assertNotNull(c.toString());

    c.setSendBufferSize(0);
    assertEquals(c.getSendBufferSize(), 0);
    c = c.duplicate();
    assertEquals(c.getSendBufferSize(), 0);

    assertNotNull(c.toString());

    c.setSendBufferSize(5678);
    assertEquals(c.getSendBufferSize(), 5678);
    c = c.duplicate();
    assertEquals(c.getSendBufferSize(), 5678);

    assertNotNull(c.toString());

    c.setSendBufferSize(-1);
    assertEquals(c.getSendBufferSize(), 0);
    c = c.duplicate();
    assertEquals(c.getSendBufferSize(), 0);

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the exception handler configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExceptionHandler()
         throws Exception
  {
    LDAPListenerConfig c = new LDAPListenerConfig(1234,
         new CannedResponseRequestHandler());
    assertNull(c.getExceptionHandler());
    c = c.duplicate();
    assertNull(c.getExceptionHandler());

    assertNotNull(c.toString());

    final TestLDAPListenerExceptionHandler handler =
         new TestLDAPListenerExceptionHandler();
    c.setExceptionHandler(handler);
    assertNotNull(c.getExceptionHandler());
    assertSame(c.getExceptionHandler(), handler);
    c = c.duplicate();
    assertNotNull(c.getExceptionHandler());
    assertSame(c.getExceptionHandler(), handler);

    assertNotNull(c.toString());

    c.setExceptionHandler(null);
    assertNull(c.getExceptionHandler());
    c = c.duplicate();
    assertNull(c.getExceptionHandler());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the server socket factory configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testServerSocketFactory()
         throws Exception
  {
    LDAPListenerConfig c = new LDAPListenerConfig(1234,
         new CannedResponseRequestHandler());
    assertNotNull(c.getServerSocketFactory());
    c = c.duplicate();
    assertNotNull(c.getServerSocketFactory());

    assertNotNull(c.toString());

    final ThrowsOnCreateServerSocketFactory factory =
         new ThrowsOnCreateServerSocketFactory(new IOException("foo"));
    c.setServerSocketFactory(factory);
    assertNotNull(c.getServerSocketFactory());
    assertSame(c.getServerSocketFactory(), factory);
    c = c.duplicate();
    assertNotNull(c.getServerSocketFactory());
    assertSame(c.getServerSocketFactory(), factory);

    assertNotNull(c.toString());

    c.setServerSocketFactory(null);
    assertNotNull(c.getServerSocketFactory());
    assertNotSame(c.getServerSocketFactory(), factory);
    c = c.duplicate();
    assertNotNull(c.getServerSocketFactory());
    assertNotSame(c.getServerSocketFactory(), factory);

    assertNotNull(c.toString());
  }
}
