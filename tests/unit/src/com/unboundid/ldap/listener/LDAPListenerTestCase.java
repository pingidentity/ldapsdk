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

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.ThrowsOnAcceptServerSocketFactory;
import com.unboundid.util.ThrowsOnCreateServerSocketFactory;



/**
 * This class provides a set of test cases for the {@code LDAPListener} class.
 */
public final class LDAPListenerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when an exception is thrown on attempting to create
   * the server socket.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testThrowsOnCreateServerSocket()
         throws Exception
  {
    final LDAPListenerConfig config = new LDAPListenerConfig(0,
         new CannedResponseRequestHandler());
    config.setServerSocketFactory(
         new ThrowsOnCreateServerSocketFactory(new IOException("foo")));

    final LDAPListener listener = new LDAPListener(config);

    assertNull(listener.getListenAddress());
    assertEquals(listener.getListenPort(), -1);
    assertNotNull(listener.getConfig());

    listener.startListening();
    listener.shutDown(true);
  }



  /**
   * Tests the behavior when an exception is thrown on attempting to accept a
   * client socket.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testThrowsOnAcceptServerSocket()
         throws Exception
  {
    final TestLDAPListenerExceptionHandler exceptionHandler =
         new TestLDAPListenerExceptionHandler();
    assertEquals(exceptionHandler.getConnectionCreationFailuresWithoutSocket(),
         0);

    final LDAPListenerConfig config = new LDAPListenerConfig(0,
         new CannedResponseRequestHandler());
    config.setServerSocketFactory(
         new ThrowsOnAcceptServerSocketFactory());
    config.setExceptionHandler(exceptionHandler);

    final LDAPListener listener = new LDAPListener(config);

    assertNull(listener.getListenAddress());
    assertEquals(listener.getListenPort(), -1);
    assertNotNull(listener.getConfig());

    listener.startListening();
    assertTrue(listener.getListenPort() > 0);
    assertNotNull(listener.getListenAddress());

    while (exceptionHandler.getConnectionCreationFailuresWithoutSocket() == 0)
    {
      Thread.sleep(1L);
    }

    listener.shutDown(true);
  }



  /**
   * Tests the behavior when actually creating a valid listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidListener()
         throws Exception
  {
    final LDAPListenerConfig config = new LDAPListenerConfig(0,
         new CannedResponseRequestHandler());
    config.setListenAddress(InetAddress.getLocalHost());
    config.setReceiveBufferSize(8192);
    config.setSendBufferSize(8192);

    final LDAPListener listener = new LDAPListener(config);

    assertNull(listener.getListenAddress());
    assertEquals(listener.getListenPort(), -1);
    assertNotNull(listener.getConfig());

    listener.startListening();
    final int listenPort = listener.getListenPort();
    assertTrue(listenPort > 0);

    final InetAddress listenAddress = listener.getListenAddress();
    assertNotNull(listenAddress);

    final LDAPConnection conn =
         new LDAPConnection(listenAddress.getHostAddress(), listenPort);
    assertNull(conn.getEntry(""));
    conn.close();

    listener.shutDown(true);
  }
}
