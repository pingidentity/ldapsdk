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



import java.util.ArrayList;
import javax.net.SocketFactory;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.matchingrules.CaseIgnoreStringMatchingRule;
import com.unboundid.ldap.matchingrules.DistinguishedNameMatchingRule;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.UnbindRequestProtocolOp;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.extensions.CancelExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedResult;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldap.sdk.unboundidds.controls.
            IntermediateClientRequestControl;



/**
 * This class provides a set of test cases for the LDAPConnection class.
 */
public class LDAPConnectionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor, which does not take any arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    LDAPConnection conn = new LDAPConnection();

    assertFalse(conn.isConnected());
    assertNull(conn.getConnectedAddress());
    assertNull(conn.getConnectedIPAddress());
    assertNull(conn.getConnectedInetAddress());
    assertTrue(conn.getConnectedPort() < 0);
    assertNotNull(conn.getHostPort());
    assertFalse(conn.synchronousMode());
    assertEquals(conn.getConnectTime(), -1L);
    assertEquals(conn.getLastCommunicationTime(), -1L);
    assertEquals(conn.getActiveOperationCount(), -1);
    assertNotNull(conn.toString());

    assertEquals(LDAPConnectionInternals.getActiveConnectionCount(), 0L);

    if (isDirectoryInstanceAvailable())
    {
      conn.connect(getTestHost(), getTestPort());
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertNotNull(conn.getConnectedIPAddress());
      assertNotNull(conn.getConnectedInetAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
           (conn.getConnectedPort() <= 65535));
      assertEquals(conn.getActiveOperationCount(), 0);
      assertTrue(conn.getConnectTime() > 0L);
      assertTrue(conn.getLastCommunicationTime() > 0L);
      assertNotNull(conn.toString());

      assertEquals(LDAPConnectionInternals.getActiveConnectionCount(), 1L);

      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertNull(conn.getConnectedIPAddress());
      assertNull(conn.getConnectedInetAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertEquals(conn.getActiveOperationCount(), -1);
      assertEquals(conn.getConnectTime(), -1L);
      assertEquals(conn.getLastCommunicationTime(), -1L);
      assertNotNull(conn.toString());

      assertEquals(LDAPConnectionInternals.getActiveConnectionCount(), 0L);
    }
  }



  /**
   * Tests the second constructor, which takes a set of connection options.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    LDAPConnection conn = new LDAPConnection(new LDAPConnectionOptions());

    assertFalse(conn.isConnected());
    assertNull(conn.getConnectedAddress());
    assertNull(conn.getConnectedIPAddress());
    assertNull(conn.getConnectedInetAddress());
    assertTrue(conn.getConnectedPort() < 0);
    assertEquals(conn.getActiveOperationCount(), -1);
    assertEquals(conn.getConnectTime(), -1L);
    assertEquals(conn.getLastCommunicationTime(), -1L);
    assertNotNull(conn.toString());

    if (isDirectoryInstanceAvailable())
    {
      conn.connect(getTestHost(), getTestPort());
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertNotNull(conn.getConnectedIPAddress());
      assertNotNull(conn.getConnectedInetAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertEquals(conn.getActiveOperationCount(), 0);
      assertTrue(conn.getConnectTime() > 0L);
      assertTrue(conn.getLastCommunicationTime() > 0L);
      assertNotNull(conn.toString());

      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertNull(conn.getConnectedIPAddress());
      assertNull(conn.getConnectedInetAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertEquals(conn.getActiveOperationCount(), -1);
      assertEquals(conn.getConnectTime(), -1L);
      assertEquals(conn.getLastCommunicationTime(), -1L);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the third constructor, which takes a socket factory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    LDAPConnection conn = new LDAPConnection(SocketFactory.getDefault());

    assertFalse(conn.isConnected());
    assertNull(conn.getConnectedAddress());
    assertNull(conn.getConnectedIPAddress());
    assertNull(conn.getConnectedInetAddress());
    assertTrue(conn.getConnectedPort() < 0);
    assertEquals(conn.getActiveOperationCount(), -1);
    assertEquals(conn.getConnectTime(), -1L);
    assertEquals(conn.getLastCommunicationTime(), -1L);
    assertNotNull(conn.toString());

    if (isDirectoryInstanceAvailable())
    {
      conn.connect(getTestHost(), getTestPort());
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertNotNull(conn.getConnectedIPAddress());
      assertNotNull(conn.getConnectedInetAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
           (conn.getConnectedPort() <= 65535));
      assertEquals(conn.getActiveOperationCount(), 0);
      assertTrue(conn.getConnectTime() > 0L);
      assertTrue(conn.getLastCommunicationTime() > 0L);
      assertNotNull(conn.toString());

      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertNull(conn.getConnectedIPAddress());
      assertNull(conn.getConnectedInetAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertEquals(conn.getActiveOperationCount(), -1);
      assertEquals(conn.getConnectTime(), -1L);
      assertEquals(conn.getLastCommunicationTime(), -1L);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the fourth constructor, which takes a directory server host and port.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn =
         new LDAPConnection(getTestHost(), getTestPort());

    assertTrue(conn.isConnected());
    assertNotNull(conn.getConnectedAddress());
    assertNotNull(conn.getConnectedIPAddress());
    assertNotNull(conn.getConnectedInetAddress());
    assertTrue((conn.getConnectedPort() >= 1) &&
               (conn.getConnectedPort() <= 65535));
    assertEquals(conn.getActiveOperationCount(), 0);
    assertTrue(conn.getConnectTime() > 0L);
    assertTrue(conn.getLastCommunicationTime() > 0L);
    assertNotNull(conn.toString());

    conn.close();
    assertFalse(conn.isConnected());
    assertNull(conn.getConnectedAddress());
    assertNull(conn.getConnectedIPAddress());
    assertNull(conn.getConnectedInetAddress());
    assertTrue(conn.getConnectedPort() < 0);
    assertEquals(conn.getActiveOperationCount(), -1);
    assertEquals(conn.getConnectTime(), -1L);
    assertEquals(conn.getLastCommunicationTime(), -1L);
    assertNotNull(conn.toString());
  }



  /**
   * Tests the fifth constructor, which takes a socket factory and a directory
   * server host and port.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn =
         new LDAPConnection(SocketFactory.getDefault(), getTestHost(),
                            getTestPort());

    assertTrue(conn.isConnected());
    assertNotNull(conn.getConnectedAddress());
    assertNotNull(conn.getConnectedIPAddress());
    assertNotNull(conn.getConnectedInetAddress());
    assertTrue((conn.getConnectedPort() >= 1) &&
               (conn.getConnectedPort() <= 65535));
    assertEquals(conn.getActiveOperationCount(), 0);
    assertTrue(conn.getConnectTime() > 0L);
    assertTrue(conn.getLastCommunicationTime() > 0L);
    assertNotNull(conn.toString());

    conn.close();
    assertFalse(conn.isConnected());
    assertNull(conn.getConnectedAddress());
    assertNull(conn.getConnectedIPAddress());
    assertNull(conn.getConnectedInetAddress());
    assertTrue(conn.getConnectedPort() < 0);
    assertEquals(conn.getActiveOperationCount(), -1);
    assertEquals(conn.getConnectTime(), -1L);
    assertEquals(conn.getLastCommunicationTime(), -1L);
    assertNotNull(conn.toString());
  }



  /**
   * Tests the sixth constructor, which takes a directory server host, port,
   * bind DN, and password.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn =
         new LDAPConnection(getTestHost(), getTestPort(), getTestBindDN(),
                            getTestBindPassword());

    assertTrue(conn.isConnected());
    assertNotNull(conn.getConnectedAddress());
    assertNotNull(conn.getConnectedIPAddress());
    assertNotNull(conn.getConnectedInetAddress());
    assertTrue((conn.getConnectedPort() >= 1) &&
               (conn.getConnectedPort() <= 65535));
    assertEquals(conn.getActiveOperationCount(), 0);
    assertTrue(conn.getConnectTime() > 0L);
    assertTrue(conn.getLastCommunicationTime() > 0L);
    assertNotNull(conn.toString());

    conn.close();
    assertFalse(conn.isConnected());
    assertNull(conn.getConnectedAddress());
    assertNull(conn.getConnectedIPAddress());
    assertNull(conn.getConnectedInetAddress());
    assertTrue(conn.getConnectedPort() < 0);
    assertEquals(conn.getActiveOperationCount(), -1);
    assertEquals(conn.getConnectTime(), -1L);
    assertEquals(conn.getLastCommunicationTime(), -1L);
    assertNotNull(conn.toString());
  }



  /**
   * Tests the sixth constructor, which takes a directory server host, port,
   * bind DN, and password, using an incorrect password.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor6WrongPassword()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPException(ResultCode.CONNECT_ERROR);
    }

    String password;
    if (getTestBindPassword().equals("wrong"))
    {
      password = "nogright";
    }
    else
    {
      password = "wrong";
    }

    new LDAPConnection(getTestHost(), getTestPort(), getTestBindDN(),
                       password);
  }



  /**
   * Tests the seventh constructor, which takes a socket factory and a directory
   * server host, port, bind DN, and password.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor7()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn =
         new LDAPConnection(SocketFactory.getDefault(), getTestHost(),
                            getTestPort(), getTestBindDN(),
                            getTestBindPassword());

    assertTrue(conn.isConnected());
    assertNotNull(conn.getConnectedAddress());
    assertNotNull(conn.getConnectedIPAddress());
    assertNotNull(conn.getConnectedInetAddress());
    assertTrue((conn.getConnectedPort() >= 1) &&
               (conn.getConnectedPort() <= 65535));
    assertEquals(conn.getActiveOperationCount(), 0);
    assertTrue(conn.getConnectTime() > 0L);
    assertTrue(conn.getLastCommunicationTime() > 0L);
    assertNotNull(conn.toString());

    conn.close();
    assertFalse(conn.isConnected());
    assertNull(conn.getConnectedAddress());
    assertNull(conn.getConnectedIPAddress());
    assertNull(conn.getConnectedInetAddress());
    assertTrue(conn.getConnectedPort() < 0);
    assertEquals(conn.getActiveOperationCount(), -1);
    assertEquals(conn.getConnectTime(), -1L);
    assertEquals(conn.getLastCommunicationTime(), -1L);
    assertNotNull(conn.toString());
  }



  /**
   * Tests the seventh constructor, which takes a socket factory and a directory
   * server host, port, bind DN, and password, using an incorrect password.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor7WrongPassword()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPException(ResultCode.CONNECT_ERROR);
    }

    String password;
    if (getTestBindPassword().equals("wrong"))
    {
      password = "nogright";
    }
    else
    {
      password = "wrong";
    }

    new LDAPConnection(SocketFactory.getDefault(), getTestHost(),
                       getTestPort(), getTestBindDN(), password);
  }



  /**
   * Tests the tenth constructor, which takes a set of connection options and
   * a directory server host, port, bind DN, and password.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor10()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn =
         new LDAPConnection(new LDAPConnectionOptions(), getTestHost(),
                            getTestPort(), getTestBindDN(),
                            getTestBindPassword());

    assertTrue(conn.isConnected());
    assertNotNull(conn.getConnectedAddress());
    assertNotNull(conn.getConnectedIPAddress());
    assertNotNull(conn.getConnectedInetAddress());
    assertTrue((conn.getConnectedPort() >= 1) &&
               (conn.getConnectedPort() <= 65535));
    assertEquals(conn.getActiveOperationCount(), 0);
    assertTrue(conn.getConnectTime() > 0L);
    assertTrue(conn.getLastCommunicationTime() > 0L);
    assertNotNull(conn.toString());

    conn.close();
    assertFalse(conn.isConnected());
    assertNull(conn.getConnectedAddress());
    assertNull(conn.getConnectedIPAddress());
    assertNull(conn.getConnectedInetAddress());
    assertTrue(conn.getConnectedPort() < 0);
    assertEquals(conn.getActiveOperationCount(), -1);
    assertEquals(conn.getConnectTime(), -1L);
    assertEquals(conn.getLastCommunicationTime(), -1L);
    assertNotNull(conn.toString());
  }



  /**
   * Tests the {@code connect} method with a connection that is already
   * established.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectAlreadyEstablished()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getUnauthenticatedConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertNotNull(conn.getConnectedIPAddress());
      assertNotNull(conn.getConnectedInetAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertEquals(conn.getActiveOperationCount(), 0);
      assertTrue(conn.getConnectTime() > 0L);
      assertTrue(conn.getLastCommunicationTime() > 0L);
      assertNotNull(conn.toString());

      conn.connect(getTestHost(), getTestPort());
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertNotNull(conn.getConnectedIPAddress());
      assertNotNull(conn.getConnectedInetAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertEquals(conn.getActiveOperationCount(), 0);
      assertTrue(conn.getConnectTime() > 0L);
      assertTrue(conn.getLastCommunicationTime() > 0L);
      assertNotNull(conn.toString());
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertNull(conn.getConnectedIPAddress());
      assertNull(conn.getConnectedInetAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertEquals(conn.getActiveOperationCount(), -1);
      assertEquals(conn.getConnectTime(), -1L);
      assertEquals(conn.getLastCommunicationTime(), -1L);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code connect} method with a timeout of zero milliseconds.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectZeroTimeout()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = new LDAPConnection();
    assertFalse(conn.isConnected());
    assertNull(conn.getConnectedAddress());
    assertNull(conn.getConnectedIPAddress());
    assertNull(conn.getConnectedInetAddress());
    assertTrue(conn.getConnectedPort() < 0);
    assertEquals(conn.getActiveOperationCount(), -1);
    assertEquals(conn.getConnectTime(), -1L);
    assertEquals(conn.getLastCommunicationTime(), -1L);
    assertNotNull(conn.toString());

    conn.connect(getTestHost(), getTestPort(), 0);

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertNotNull(conn.getConnectedIPAddress());
      assertNotNull(conn.getConnectedInetAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertEquals(conn.getActiveOperationCount(), 0);
      assertTrue(conn.getConnectTime() > 0L);
      assertTrue(conn.getLastCommunicationTime() > 0L);
      assertNotNull(conn.toString());
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertNull(conn.getConnectedIPAddress());
      assertNull(conn.getConnectedInetAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertEquals(conn.getActiveOperationCount(), -1);
      assertEquals(conn.getConnectTime(), -1L);
      assertEquals(conn.getLastCommunicationTime(), -1L);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code connect} method with an invalid port number.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConnectInvalidPort()
         throws Exception
  {
    LDAPConnection conn = new LDAPConnection();
    conn.connect("127.0.0.1", 100000);
  }



  /**
   * Tests the {@code reconnect} method with an unauthenticated connection.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReconnectUnauthenticated()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getUnauthenticatedConnection();
    assertTrue(conn.getConnectTime() > 0L);
    assertTrue(conn.getLastCommunicationTime() > 0L);
    assertNotNull(conn.getRootDSE());
    assertTrue(conn.getConnectTime() > 0L);
    assertTrue(conn.getLastCommunicationTime() > 0L);

    try
    {
      conn.setClosed();
      assertEquals(conn.getConnectTime(), -1L);
      assertEquals(conn.getLastCommunicationTime(), -1L);
      conn.reconnect();
      assertTrue(conn.getConnectTime() > 0L);
      assertTrue(conn.getLastCommunicationTime() > 0L);
      assertNotNull(conn.getRootDSE());
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertNull(conn.getConnectedIPAddress());
      assertNull(conn.getConnectedInetAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertEquals(conn.getConnectTime(), -1L);
      assertEquals(conn.getLastCommunicationTime(), -1L);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code reconnect} method with an authenticated connection.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReconnectAuthenticated()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    assertTrue(conn.getConnectTime() > 0L);
    assertTrue(conn.getLastCommunicationTime() > 0L);
    assertNotNull(conn.getRootDSE());
    assertTrue(conn.getConnectTime() > 0L);
    assertTrue(conn.getLastCommunicationTime() > 0L);

    try
    {
      conn.setClosed();
      assertEquals(conn.getConnectTime(), -1L);
      assertEquals(conn.getLastCommunicationTime(), -1L);
      conn.reconnect();
      assertTrue(conn.getConnectTime() > 0L);
      assertTrue(conn.getLastCommunicationTime() > 0L);
      assertNotNull(conn.getRootDSE());
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertNull(conn.getConnectedIPAddress());
      assertNull(conn.getConnectedInetAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertEquals(conn.getConnectTime(), -1L);
      assertEquals(conn.getLastCommunicationTime(), -1L);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the methods involving connection options.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetConnectionOptions()
         throws Exception
  {
    LDAPConnection conn = new LDAPConnection();
    assertNotNull(conn.getConnectionOptions());

    conn.setConnectionOptions(null);
    assertNotNull(conn.getConnectionOptions());

    conn.setConnectionOptions(new LDAPConnectionOptions());
    assertNotNull(conn.getConnectionOptions());
  }



  /**
   * Tests the {@code close} method variant that allows controls to be included.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCloseWithControls()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    Control[] controls =
    {
      new IntermediateClientRequestControl(null, null, null, null,
                                           "testCloseWithControls", null, null)
    };

    LDAPConnection conn = getAdminConnection();
    conn.close(controls);
  }



  /**
   * Tests the {@code close} method on a connection that is not established.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCloseNotConnected()
         throws Exception
  {
    LDAPConnection conn = new LDAPConnection();
    assertFalse(conn.isConnected());
    assertNull(conn.getConnectedAddress());
    assertNull(conn.getConnectedIPAddress());
    assertNull(conn.getConnectedInetAddress());
    assertTrue(conn.getConnectedPort() < 0);
    assertNotNull(conn.toString());

    conn.close();
  }



  /**
   * Provides test coverage for the {@code closeRequested} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCloseRequested()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    assertFalse(conn.closeRequested());

    conn.close();
    assertTrue(conn.closeRequested());
  }



  /**
   * Provides test coverage for the {@code unbindRequestSent} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnbindRequestSent()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    assertFalse(conn.unbindRequestSent());

    conn.close();
    assertTrue(conn.unbindRequestSent());
  }



  /**
   * Ensures that no unbind request is sent when the {@code closeWithoutUnbind}
   * method is called.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnbindRequestNotSentForCloseWithoutUnbind()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    assertFalse(conn.unbindRequestSent());

    conn.closeWithoutUnbind();
    assertFalse(conn.unbindRequestSent());
  }



  /**
   * Provides test coverage for the methods making it possible to get and set
   * the connection name.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetConnectionName()
         throws Exception
  {
    LDAPConnection c = new LDAPConnection();

    assertNull(c.getConnectionName());

    assertNotNull(c.toString());

    c.setConnectionName("test not connected");
    assertNotNull(c.getConnectionName());
    assertEquals(c.getConnectionName(), "test not connected");

    assertNotNull(c.toString());

    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    c.connect(getTestHost(), getTestPort());
    c.bind(getTestBindDN(), getTestBindPassword());

    assertNotNull(c.getConnectionName());
    assertEquals(c.getConnectionName(), "test not connected");

    assertNotNull(c.toString());

    LDAPConnectionInternals internals = c.getConnectionInternals(true);
    assertNotNull(internals);

    LDAPConnectionReader reader = internals.getConnectionReader();
    assertNotNull(reader);

    Thread t = reader.getReaderThread();
    assertNotNull(t);
    assertTrue(t.getName().contains("test not connected"));

    c.setConnectionName("now it is connected");

    assertNotNull(c.getConnectionName());
    assertEquals(c.getConnectionName(), "now it is connected");

    assertTrue(t.getName().contains("now it is connected"));

    assertNotNull(c.toString());

    c.setConnectionName(null);

    assertNull(c.getConnectionName());

    c.close();
  }




  /**
   * Tests the {@code getRootDSE} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetRootDSE()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    RootDSE rootDSE = conn.getRootDSE();
    conn.close();

    assertNotNull(rootDSE);
    assertNotNull(rootDSE.getNamingContextDNs());
    assertNotNull(rootDSE.getSubschemaSubentryDN());
    assertNotNull(rootDSE.getSupportedAuthPasswordSchemeNames());
    assertNotNull(rootDSE.getSupportedControlOIDs());
    assertNotNull(rootDSE.getSupportedExtendedOperationOIDs());
    assertNotNull(rootDSE.getSupportedFeatureOIDs());
    assertNotNull(rootDSE.getSupportedSASLMechanismNames());
  }



  /**
   * Tests the {@code getSchema} method that retrieves the associated with the
   * server's root DSE.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSchemaRootDSE()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    Schema schema = conn.getSchema();
    conn.close();

    assertNotNull(schema);
    assertNotNull(schema.getAttributeSyntaxes());
    assertNotNull(schema.getAttributeTypes());
    assertNotNull(schema.getDITContentRules());
    assertNotNull(schema.getDITStructureRules());
    assertNotNull(schema.getMatchingRules());
    assertNotNull(schema.getMatchingRuleUses());
    assertNotNull(schema.getNameForms());
    assertNotNull(schema.getObjectClasses());

    assertFalse(schema.getAttributeSyntaxes().isEmpty());
    assertFalse(schema.getAttributeTypes().isEmpty());
    assertFalse(schema.getMatchingRules().isEmpty());
    assertFalse(schema.getObjectClasses().isEmpty());
  }



  /**
   * Tests the {@code getSchema} method that retrieves the associated with a
   * specified entry DN.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSchemaTargetEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      Schema schema = conn.getSchema("");

      assertNotNull(schema);
      assertNotNull(schema.getAttributeSyntaxes());
      assertNotNull(schema.getAttributeTypes());
      assertNotNull(schema.getDITContentRules());
      assertNotNull(schema.getDITStructureRules());
      assertNotNull(schema.getMatchingRules());
      assertNotNull(schema.getMatchingRuleUses());
      assertNotNull(schema.getNameForms());
      assertNotNull(schema.getObjectClasses());

      assertFalse(schema.getAttributeSyntaxes().isEmpty());
      assertFalse(schema.getAttributeTypes().isEmpty());
      assertFalse(schema.getMatchingRules().isEmpty());
      assertFalse(schema.getObjectClasses().isEmpty());
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the {@code getEntry} method variant that requires only a DN.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetEntryNoAttrs()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertNotNull(conn.getConnectedIPAddress());
      assertNotNull(conn.getConnectedInetAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
           (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(getTestBaseDN(), getBaseEntryAttributes());
      assertNotNull(conn.getEntry(getTestBaseDN()));
    }
    finally
    {
      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertNull(conn.getConnectedIPAddress());
      assertNull(conn.getConnectedInetAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code getEntry} method variant that takes a DN and set of
   * requested attributes.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetEntrySpecificAttrs()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertNotNull(conn.getConnectedIPAddress());
      assertNotNull(conn.getConnectedInetAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
           (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(getTestBaseDN(), getBaseEntryAttributes());
      assertNotNull(conn.getEntry(getTestBaseDN(),
           SearchRequest.ALL_USER_ATTRIBUTES,
           SearchRequest.ALL_OPERATIONAL_ATTRIBUTES));
    }
    finally
    {
      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertNull(conn.getConnectedIPAddress());
      assertNull(conn.getConnectedInetAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code getEntry} method with an entry that doesn't exist.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetEntryNoSuchEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    assertTrue(conn.isConnected());
    assertNotNull(conn.getConnectedAddress());
    assertNotNull(conn.getConnectedIPAddress());
    assertNotNull(conn.getConnectedInetAddress());
    assertTrue((conn.getConnectedPort() >= 1) &&
               (conn.getConnectedPort() <= 65535));
    assertNotNull(conn.toString());

    try
    {
      assertNull(conn.getEntry(getTestBaseDN(),
           SearchRequest.ALL_USER_ATTRIBUTES,
           SearchRequest.ALL_OPERATIONAL_ATTRIBUTES));
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertNull(conn.getConnectedIPAddress());
      assertNull(conn.getConnectedInetAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code add} method variant that takes a string DN and an array of
   * attributes, and the delete method that takes a string DN.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddAttrArray()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertNotNull(conn.getConnectedIPAddress());
      assertNotNull(conn.getConnectedInetAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(getTestBaseDN(), getBaseEntryAttributes());
      conn.delete(getTestBaseDN());
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertNull(conn.getConnectedIPAddress());
      assertNull(conn.getConnectedInetAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code add} method variant that takes a string DN and a
   * collection of attributes, and the delete method that takes a string DN.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddAttrCollection()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    ArrayList<Attribute> attrList = new ArrayList<Attribute>();
    for (Attribute a : getBaseEntryAttributes())
    {
      attrList.add(a);
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertNotNull(conn.getConnectedIPAddress());
      assertNotNull(conn.getConnectedInetAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(getTestBaseDN(), attrList);
      conn.delete(getTestBaseDN());
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertNull(conn.getConnectedIPAddress());
      assertNull(conn.getConnectedInetAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code add} method variant that takes an entry, and the delete
   * method that takes a string DN.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    Entry entry = new Entry(getTestBaseDN(), getBaseEntryAttributes());

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertNotNull(conn.getConnectedIPAddress());
      assertNotNull(conn.getConnectedInetAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(entry);
      conn.delete(getTestBaseDN());
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertNull(conn.getConnectedIPAddress());
      assertNull(conn.getConnectedInetAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code add} method variant that takes an LDIF representation of
   * the entry to add, and the delete method that takes a string DN.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddLDIFEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    Entry entry = new Entry(getTestBaseDN(), getBaseEntryAttributes());

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertNotNull(conn.getConnectedIPAddress());
      assertNotNull(conn.getConnectedInetAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(getTestBaseDN(), getBaseEntryAttributes());
      conn.add("dn: ou=LDIF Test," + getTestBaseDN(),
               "objectClass: top",
               "objectClass: organizationalUnit",
               "ou: LDIF Test");


      conn.delete("ou=LDIF Test," + getTestBaseDN());
      conn.delete(getTestBaseDN());
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertNull(conn.getConnectedIPAddress());
      assertNull(conn.getConnectedInetAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code add} method variant with an entry that should result in an
   * object class violation, causing the add to fail.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testAddEntryObjectClassViolation()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPException(ResultCode.CONNECT_ERROR);
    }

    Entry entry = new Entry(getTestBaseDN(), getBaseEntryAttributes());
    entry.addAttribute("invalid", "invalid");

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertNotNull(conn.getConnectedIPAddress());
      assertNotNull(conn.getConnectedInetAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(entry);
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertNull(conn.getConnectedIPAddress());
      assertNull(conn.getConnectedInetAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code add} method variant that takes a read-only request.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddReadOnly()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    Entry entry = new Entry(getTestBaseDN(), getBaseEntryAttributes());
    ReadOnlyAddRequest r = new AddRequest(entry);

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertNotNull(conn.getConnectedIPAddress());
      assertNotNull(conn.getConnectedInetAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(r);
      conn.delete(getTestBaseDN());
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertNull(conn.getConnectedIPAddress());
      assertNull(conn.getConnectedInetAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code bind} method variant that takes a string DN and a string
   * password.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindString()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getUnauthenticatedConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertNotNull(conn.getConnectedIPAddress());
      assertNotNull(conn.getConnectedInetAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.bind(getTestBindDN(), getTestBindPassword());
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertNull(conn.getConnectedIPAddress());
      assertNull(conn.getConnectedInetAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code bind} method variant that takes a string DN and a string
   * password, using the wrong password.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testBindStringWrongPassword()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPException(ResultCode.CONNECT_ERROR);
    }

    String password;
    if (getTestBindPassword().equals("wrong"))
    {
      password = "notright";
    }
    else
    {
      password = "wrong";
    }

    LDAPConnection conn = getUnauthenticatedConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertNotNull(conn.getConnectedIPAddress());
      assertNotNull(conn.getConnectedInetAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.bind(getTestBindDN(), password);
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertNull(conn.getConnectedIPAddress());
      assertNull(conn.getConnectedInetAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code bind} method variant that takes a bind request.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindRequest()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getUnauthenticatedConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.bind(new SimpleBindRequest(getTestBindDN(),
                                      getTestBindPassword()));
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code bind} method variant that takes a bind request, using the
   * wrong password.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testBindRequestWrongPassword()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPException(ResultCode.CONNECT_ERROR);
    }

    String password;
    if (getTestBindPassword().equals("wrong"))
    {
      password = "notright";
    }
    else
    {
      password = "wrong";
    }

    LDAPConnection conn = getUnauthenticatedConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.bind(new SimpleBindRequest(getTestBindDN(), password));
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code compare} method with assertions that should and should not
   * match.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompare()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(getTestBaseDN(), getBaseEntryAttributes());

      CompareResult compareResult =
           conn.compare(getTestBaseDN(), "objectClass", "top");
      assertTrue(compareResult.compareMatched());

      compareResult =
           conn.compare(getTestBaseDN(), "objectClass", "missing");
      assertFalse(compareResult.compareMatched());
    }
    finally
    {
      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code compare} method with a target entry that doesn't exist.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testCompareNoSuchEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPException(ResultCode.CONNECT_ERROR);
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.compare(getTestBaseDN(), "objectClass", "top");
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code compare} method that takes a read-only request.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareReadOnly()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    ReadOnlyCompareRequest r1 =
         new CompareRequest(getTestBaseDN(), "objectClass", "top");
    ReadOnlyCompareRequest r2 =
         new CompareRequest(getTestBaseDN(), "objectClass", "missing");
    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(getTestBaseDN(), getBaseEntryAttributes());

      CompareResult compareResult = conn.compare(r1);
      assertTrue(compareResult.compareMatched());

      compareResult = conn.compare(r2);
      assertFalse(compareResult.compareMatched());
    }
    finally
    {
      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code delete} method with a target entry that doesn't exist.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDeleteNoSuchEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPException(ResultCode.CONNECT_ERROR);
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.delete(getTestBaseDN());
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code delete} method variant that takes a read-only request.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteReadOnly()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    ReadOnlyDeleteRequest r = new DeleteRequest(getTestBaseDN());
    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(getTestBaseDN(), getBaseEntryAttributes());
      conn.delete(r);
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code processExtendedOperation} method variant that takes only
   * a request OID.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedOID()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      ExtendedResult extendedResult =
           conn.processExtendedOperation("1.3.6.1.4.1.4203.1.11.3");

      assertNotNull(extendedResult);
      assertEquals(extendedResult.getResultCode(), ResultCode.SUCCESS);

      assertNull(extendedResult.getOID());
      assertNotNull(extendedResult.getValue());

      assertFalse(extendedResult instanceof WhoAmIExtendedResult);

      WhoAmIExtendedResult whoAmIResult =
           new WhoAmIExtendedResult(extendedResult);
      assertNotNull(whoAmIResult);
      assertNotNull(whoAmIResult.getAuthorizationID());
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code processExtendedOperation} method variant that takes both
   * a request OID and a request value, using a {@code null} value.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedOIDNullValue()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      ExtendedResult extendedResult =
           conn.processExtendedOperation("1.3.6.1.4.1.4203.1.11.3", null);

      assertNotNull(extendedResult);
      assertEquals(extendedResult.getResultCode(), ResultCode.SUCCESS);

      assertNull(extendedResult.getOID());
      assertNotNull(extendedResult.getValue());

      assertFalse(extendedResult instanceof WhoAmIExtendedResult);

      WhoAmIExtendedResult whoAmIResult =
           new WhoAmIExtendedResult(extendedResult);
      assertNotNull(whoAmIResult);
      assertNotNull(whoAmIResult.getAuthorizationID());
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code processExtendedOperation} method variant that takes an
   * extended request object, using a generic form of the object.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedGenericObject()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      ExtendedRequest extendedRequest =
           new ExtendedRequest("1.3.6.1.4.1.4203.1.11.3");
      ExtendedResult extendedResult =
           conn.processExtendedOperation(extendedRequest);

      assertNotNull(extendedResult);
      assertEquals(extendedResult.getResultCode(), ResultCode.SUCCESS);

      assertNull(extendedResult.getOID());
      assertNotNull(extendedResult.getValue());

      assertFalse(extendedResult instanceof WhoAmIExtendedResult);

      WhoAmIExtendedResult whoAmIResult =
           new WhoAmIExtendedResult(extendedResult);
      assertNotNull(whoAmIResult);
      assertNotNull(whoAmIResult.getAuthorizationID());
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code processExtendedOperation} method variant that takes an
   * extended request object, using the "Who Am I?" extended request object.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedWhoAmI()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      WhoAmIExtendedRequest extendedRequest = new WhoAmIExtendedRequest();
      ExtendedResult extendedResult =
           conn.processExtendedOperation(extendedRequest);

      assertNotNull(extendedResult);
      assertEquals(extendedResult.getResultCode(), ResultCode.SUCCESS);

      assertNull(extendedResult.getOID());
      assertNotNull(extendedResult.getValue());

      assertTrue(extendedResult instanceof WhoAmIExtendedResult);

      WhoAmIExtendedResult whoAmIResult =
           (WhoAmIExtendedResult) extendedResult;
      assertNotNull(whoAmIResult);
      assertNotNull(whoAmIResult.getAuthorizationID());
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code processExtendedOperation} method variant that takes an
   * extended request object, using the cancel extended request object.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedCancel()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      CancelExtendedRequest extendedRequest = new CancelExtendedRequest(999);
      ExtendedResult extendedResult =
           conn.processExtendedOperation(extendedRequest);

      assertNotNull(extendedResult);
      assertEquals(extendedResult.getResultCode(),
                   ResultCode.NO_SUCH_OPERATION);

      assertNull(extendedResult.getOID());
      assertNull(extendedResult.getValue());
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code modify} method with single and multiple modifications.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModify()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(getTestBaseDN(), getBaseEntryAttributes());

      conn.modify(getTestBaseDN(),
                  new Modification(ModificationType.REPLACE, "description",
                                   "foo"));

      CompareResult compareResult =
           conn.compare(getTestBaseDN(), "description", "foo");
      assertTrue(compareResult.compareMatched());

      compareResult = conn.compare(getTestBaseDN(), "description", "bar");
      assertFalse(compareResult.compareMatched());

      Modification[] mods =
      {
        new Modification(ModificationType.DELETE, "description", "foo"),
        new Modification(ModificationType.ADD, "description", "bar"),
      };
      conn.modify(getTestBaseDN(), mods);

      compareResult = conn.compare(getTestBaseDN(), "description", "foo");
      assertFalse(compareResult.compareMatched());

      compareResult = conn.compare(getTestBaseDN(), "description", "bar");
      assertTrue(compareResult.compareMatched());

      ArrayList<Modification> modList = new ArrayList<Modification>(1);
      modList.add(new Modification(ModificationType.REPLACE, "description",
                                   "foo"));
      conn.modify(getTestBaseDN(), modList);

      compareResult = conn.compare(getTestBaseDN(), "description", "foo");
      assertTrue(compareResult.compareMatched());

      compareResult = conn.compare(getTestBaseDN(), "description", "bar");
      assertFalse(compareResult.compareMatched());

      conn.modify("dn: " + getTestBaseDN(),
                  "changetype: modify",
                  "replace: description",
                  "description: baz");

      compareResult = conn.compare(getTestBaseDN(), "description", "foo");
      assertFalse(compareResult.compareMatched());

      compareResult = conn.compare(getTestBaseDN(), "description", "bar");
      assertFalse(compareResult.compareMatched());

      compareResult = conn.compare(getTestBaseDN(), "description", "baz");
      assertTrue(compareResult.compareMatched());
    }
    finally
    {
      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code modify} method with a target entry that doesn't exist.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testModifyNoSuchEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPException(ResultCode.CONNECT_ERROR);
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.modify(getTestBaseDN(),
                  new Modification(ModificationType.REPLACE, "description",
                                   "foo"));
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code modify} method variant that takes a read-only request.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyReadOnly()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    ReadOnlyModifyRequest r = new ModifyRequest(
         "dn: " + getTestBaseDN(),
         "changetype: modify",
         "replace: description",
         "description: foo");

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(getTestBaseDN(), getBaseEntryAttributes());

      conn.modify(r);

      CompareResult compareResult =
           conn.compare(getTestBaseDN(), "description", "foo");
      assertTrue(compareResult.compareMatched());
    }
    finally
    {
      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code modifyDN} method to rename an entry.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDN()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String currentEntryDN = "ou=Current," + getTestBaseDN();
    String newEntryDN     = "ou=New," + getTestBaseDN();

    Attribute[] currentAttrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "Current")
    };

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(getTestBaseDN(), getBaseEntryAttributes());
      conn.add(currentEntryDN, currentAttrs);

      conn.modifyDN(currentEntryDN, "ou=New", true);
    }
    finally
    {
      try
      {
        conn.delete(newEntryDN);
      } catch (Exception e) {}

      try
      {
        conn.delete(currentEntryDN);
      } catch (Exception e) {}

      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code modifyDN} method to rename an entry and move it below a
   * new superior entry.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNNewSuperior()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String currentEntryDN = "ou=Current," + getTestBaseDN();
    String subEntryDN     = "ou=Sub," + getTestBaseDN();
    String newEntryDN     = "ou=New," + subEntryDN;

    Attribute[] currentAttrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "Current")
    };

    Attribute[] subAttrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "Sub")
    };

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(getTestBaseDN(), getBaseEntryAttributes());
      conn.add(subEntryDN, subAttrs);
      conn.add(currentEntryDN, currentAttrs);

      conn.modifyDN(currentEntryDN, "ou=New", true, subEntryDN);
    }
    finally
    {
      try
      {
        conn.delete(newEntryDN);
      } catch (Exception e) {}

      try
      {
        conn.delete(currentEntryDN);
      } catch (Exception e) {}

      try
      {
        conn.delete(subEntryDN);
      } catch (Exception e) {}

      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code modifyDN} method with a target entry that does not exist.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testModifyDNNoSuchEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPException(ResultCode.CONNECT_ERROR);
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());
      conn.modifyDN(getTestBaseDN(), "ou=New", true);
    }
    finally
    {
      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code modifyDN} method variant that takes a read-only request.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNReadOnly()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String currentEntryDN = "ou=Current," + getTestBaseDN();
    String newEntryDN     = "ou=New," + getTestBaseDN();

    Attribute[] currentAttrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "Current")
    };

    LDAPConnection conn = getAdminConnection();
    ReadOnlyModifyDNRequest r =
         new ModifyDNRequest(currentEntryDN, "ou=New", true);

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(getTestBaseDN(), getBaseEntryAttributes());
      conn.add(currentEntryDN, currentAttrs);

      conn.modifyDN(r);
    }
    finally
    {
      try
      {
        conn.delete(newEntryDN);
      } catch (Exception e) {}

      try
      {
        conn.delete(currentEntryDN);
      } catch (Exception e) {}

      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the first {@code search} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearch1()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String sub1DN = "ou=sub1," + getTestBaseDN();
    String sub2DN = "ou=sub2," + sub1DN;

    Attribute[] sub1Attrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "sub1")
    };

    Attribute[] sub2Attrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "sub2")
    };

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(getTestBaseDN(), getBaseEntryAttributes());
      conn.add(sub1DN, sub1Attrs);
      conn.add(sub2DN, sub2Attrs);

      SearchResult searchResult = conn.search(getTestBaseDN(), SearchScope.BASE,
                                              "(objectClass=*)");
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);
      assertEquals(searchResult.getEntryCount(),
                   searchResult.getSearchEntries().size());
      assertEquals(searchResult.getSearchEntries().get(0).getDN(),
                   getTestBaseDN());

      searchResult = conn.search(getTestBaseDN(), SearchScope.ONE,
                                 "(objectClass=*)");
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);
      assertEquals(searchResult.getEntryCount(),
                   searchResult.getSearchEntries().size());
      assertEquals(searchResult.getSearchEntries().get(0).getDN(), sub1DN);

      searchResult = conn.search(getTestBaseDN(), SearchScope.SUB,
                                 "(objectClass=*)");
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 3);
      assertEquals(searchResult.getEntryCount(),
                   searchResult.getSearchEntries().size());

      searchResult = conn.search(getTestBaseDN(),
                                 SearchScope.SUBORDINATE_SUBTREE,
                                 "(objectClass=*)");
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 2);
      assertEquals(searchResult.getEntryCount(),
                   searchResult.getSearchEntries().size());
    }
    finally
    {
      try
      {
        conn.delete(sub2DN);
      } catch (Exception e) {}

      try
      {
        conn.delete(sub1DN);
      } catch (Exception e) {}

      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the second {@code search} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearch2()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String sub1DN = "ou=sub1," + getTestBaseDN();
    String sub2DN = "ou=sub2," + sub1DN;

    Attribute[] sub1Attrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "sub1")
    };

    Attribute[] sub2Attrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "sub2")
    };

    LDAPConnection conn = getAdminConnection();

    try
    {
      Filter filter = Filter.createPresenceFilter("objectClass");

      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(getTestBaseDN(), getBaseEntryAttributes());
      conn.add(sub1DN, sub1Attrs);
      conn.add(sub2DN, sub2Attrs);

      SearchResult searchResult = conn.search(getTestBaseDN(), SearchScope.BASE,
                                              filter);
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);
      assertEquals(searchResult.getEntryCount(),
                   searchResult.getSearchEntries().size());
      assertEquals(searchResult.getSearchEntries().get(0).getDN(),
                   getTestBaseDN());

      searchResult = conn.search(getTestBaseDN(), SearchScope.ONE, filter);
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);
      assertEquals(searchResult.getEntryCount(),
                   searchResult.getSearchEntries().size());
      assertEquals(searchResult.getSearchEntries().get(0).getDN(), sub1DN);

      searchResult = conn.search(getTestBaseDN(), SearchScope.SUB, filter);
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 3);
      assertEquals(searchResult.getEntryCount(),
                   searchResult.getSearchEntries().size());

      searchResult = conn.search(getTestBaseDN(),
                                 SearchScope.SUBORDINATE_SUBTREE, filter);
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 2);
      assertEquals(searchResult.getEntryCount(),
                   searchResult.getSearchEntries().size());
    }
    finally
    {
      try
      {
        conn.delete(sub2DN);
      } catch (Exception e) {}

      try
      {
        conn.delete(sub1DN);
      } catch (Exception e) {}

      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the third {@code search} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearch3()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String sub1DN = "ou=sub1," + getTestBaseDN();
    String sub2DN = "ou=sub2," + sub1DN;

    Attribute[] sub1Attrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "sub1")
    };

    Attribute[] sub2Attrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "sub2")
    };

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
           (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(getTestBaseDN(), getBaseEntryAttributes());
      conn.add(sub1DN, sub1Attrs);
      conn.add(sub2DN, sub2Attrs);

      TestSearchResultListener listener = new TestSearchResultListener();

      SearchResult searchResult = conn.search(listener, getTestBaseDN(),
                                              SearchScope.BASE,
                                              "(objectClass=*)");
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);
      assertEquals(searchResult.getEntryCount(), listener.getNumEntries());
      assertEquals(listener.getFirstEntryDN(), getTestBaseDN());

      listener.reset();
      searchResult = conn.search(listener, getTestBaseDN(), SearchScope.ONE,
                                 "(objectClass=*)");
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);
      assertEquals(searchResult.getEntryCount(), listener.getNumEntries());
      assertEquals(listener.getFirstEntryDN(), sub1DN);

      listener.reset();
      searchResult = conn.search(listener, getTestBaseDN(), SearchScope.SUB,
                                 "(objectClass=*)");
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 3);
      assertEquals(searchResult.getEntryCount(), listener.getNumEntries());

      listener.reset();
      searchResult = conn.search(listener, getTestBaseDN(),
                                 SearchScope.SUBORDINATE_SUBTREE,
                                 "(objectClass=*)");
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 2);
      assertEquals(searchResult.getEntryCount(), listener.getNumEntries());
    }
    finally
    {
      try
      {
        conn.delete(sub2DN);
      } catch (Exception e) {}

      try
      {
        conn.delete(sub1DN);
      } catch (Exception e) {}

      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the fourth {@code search} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearch4()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String sub1DN = "ou=sub1," + getTestBaseDN();
    String sub2DN = "ou=sub2," + sub1DN;

    Attribute[] sub1Attrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "sub1")
    };

    Attribute[] sub2Attrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "sub2")
    };

    LDAPConnection conn = getAdminConnection();

    try
    {
      Filter filter = Filter.createPresenceFilter("objectClass");

      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
           (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(getTestBaseDN(), getBaseEntryAttributes());
      conn.add(sub1DN, sub1Attrs);
      conn.add(sub2DN, sub2Attrs);

      TestSearchResultListener listener = new TestSearchResultListener();

      SearchResult searchResult = conn.search(listener, getTestBaseDN(),
                                              SearchScope.BASE,
                                              filter);
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);
      assertEquals(searchResult.getEntryCount(), listener.getNumEntries());
      assertEquals(listener.getFirstEntryDN(), getTestBaseDN());

      listener.reset();
      searchResult = conn.search(listener, getTestBaseDN(), SearchScope.ONE,
                                 filter);
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);
      assertEquals(searchResult.getEntryCount(), listener.getNumEntries());
      assertEquals(listener.getFirstEntryDN(), sub1DN);

      listener.reset();
      searchResult = conn.search(listener, getTestBaseDN(), SearchScope.SUB,
                                 filter);
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 3);
      assertEquals(searchResult.getEntryCount(), listener.getNumEntries());

      listener.reset();
      searchResult = conn.search(listener, getTestBaseDN(),
                                 SearchScope.SUBORDINATE_SUBTREE, filter);
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 2);
      assertEquals(searchResult.getEntryCount(), listener.getNumEntries());
    }
    finally
    {
      try
      {
        conn.delete(sub2DN);
      } catch (Exception e) {}

      try
      {
        conn.delete(sub1DN);
      } catch (Exception e) {}

      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the fifth {@code search} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearch5()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String sub1DN = "ou=sub1," + getTestBaseDN();
    String sub2DN = "ou=sub2," + sub1DN;

    Attribute[] sub1Attrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "sub1")
    };

    Attribute[] sub2Attrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "sub2")
    };

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
           (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(getTestBaseDN(), getBaseEntryAttributes());
      conn.add(sub1DN, sub1Attrs);
      conn.add(sub2DN, sub2Attrs);

      SearchResult searchResult = conn.search(getTestBaseDN(), SearchScope.BASE,
                                              DereferencePolicy.NEVER, 0, 0,
                                              false, "(objectClass=*)");
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);
      assertEquals(searchResult.getEntryCount(),
                   searchResult.getSearchEntries().size());
      assertEquals(searchResult.getSearchEntries().get(0).getDN(),
                   getTestBaseDN());

      searchResult = conn.search(getTestBaseDN(), SearchScope.ONE,
                                 DereferencePolicy.NEVER, 0, 0, false,
                                 "(objectClass=*)");
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);
      assertEquals(searchResult.getEntryCount(),
           searchResult.getSearchEntries().size());
      assertEquals(searchResult.getSearchEntries().get(0).getDN(), sub1DN);

      searchResult = conn.search(getTestBaseDN(), SearchScope.SUB,
                                 DereferencePolicy.NEVER, 0, 0, false,
                                 "(objectClass=*)");
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 3);
      assertEquals(searchResult.getEntryCount(),
                   searchResult.getSearchEntries().size());

      searchResult = conn.search(getTestBaseDN(),
                                 SearchScope.SUBORDINATE_SUBTREE,
                                 DereferencePolicy.NEVER, 0, 0, false,
                                 "(objectClass=*)");
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 2);
      assertEquals(searchResult.getEntryCount(),
                   searchResult.getSearchEntries().size());
    }
    finally
    {
      try
      {
        conn.delete(sub2DN);
      } catch (Exception e) {}

      try
      {
        conn.delete(sub1DN);
      } catch (Exception e) {}

      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the sixth {@code search} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearch6()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String sub1DN = "ou=sub1," + getTestBaseDN();
    String sub2DN = "ou=sub2," + sub1DN;

    Attribute[] sub1Attrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "sub1")
    };

    Attribute[] sub2Attrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "sub2")
    };

    LDAPConnection conn = getAdminConnection();

    try
    {
      Filter filter = Filter.createPresenceFilter("objectClass");

      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
           (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(getTestBaseDN(), getBaseEntryAttributes());
      conn.add(sub1DN, sub1Attrs);
      conn.add(sub2DN, sub2Attrs);

      SearchResult searchResult = conn.search(getTestBaseDN(), SearchScope.BASE,
                                              DereferencePolicy.NEVER, 0, 0,
                                              false, filter);
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);
      assertEquals(searchResult.getEntryCount(),
                   searchResult.getSearchEntries().size());
      assertEquals(searchResult.getSearchEntries().get(0).getDN(),
                   getTestBaseDN());

      searchResult = conn.search(getTestBaseDN(), SearchScope.ONE,
                                 DereferencePolicy.NEVER, 0, 0, false, filter);
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);
      assertEquals(searchResult.getEntryCount(),
           searchResult.getSearchEntries().size());
      assertEquals(searchResult.getSearchEntries().get(0).getDN(), sub1DN);

      searchResult = conn.search(getTestBaseDN(), SearchScope.SUB,
                                 DereferencePolicy.NEVER, 0, 0, false, filter);
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 3);
      assertEquals(searchResult.getEntryCount(),
                   searchResult.getSearchEntries().size());

      searchResult = conn.search(getTestBaseDN(),
                                 SearchScope.SUBORDINATE_SUBTREE,
                                 DereferencePolicy.NEVER, 0, 0, false, filter);
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 2);
      assertEquals(searchResult.getEntryCount(),
                   searchResult.getSearchEntries().size());
    }
    finally
    {
      try
      {
        conn.delete(sub2DN);
      } catch (Exception e) {}

      try
      {
        conn.delete(sub1DN);
      } catch (Exception e) {}

      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the seventh {@code search} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearch7()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String sub1DN = "ou=sub1," + getTestBaseDN();
    String sub2DN = "ou=sub2," + sub1DN;

    Attribute[] sub1Attrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "sub1")
    };

    Attribute[] sub2Attrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "sub2")
    };

    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
           (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(getTestBaseDN(), getBaseEntryAttributes());
      conn.add(sub1DN, sub1Attrs);
      conn.add(sub2DN, sub2Attrs);

      TestSearchResultListener listener = new TestSearchResultListener();

      SearchResult searchResult =
           conn.search(listener, getTestBaseDN(), SearchScope.BASE,
                       DereferencePolicy.NEVER, 0, 0, false,
                       "(objectClass=*)");
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);
      assertEquals(searchResult.getEntryCount(), listener.getNumEntries());
      assertEquals(listener.getFirstEntryDN(), getTestBaseDN());

      listener.reset();
      searchResult = conn.search(listener, getTestBaseDN(), SearchScope.ONE,
                                 DereferencePolicy.NEVER, 0, 0, false,
                                 "(objectClass=*)");
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);
      assertEquals(searchResult.getEntryCount(), listener.getNumEntries());
      assertEquals(listener.getFirstEntryDN(), sub1DN);

      listener.reset();
      searchResult = conn.search(listener, getTestBaseDN(), SearchScope.SUB,
                                 DereferencePolicy.NEVER, 0, 0, false,
                                 "(objectClass=*)");
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 3);
      assertEquals(searchResult.getEntryCount(), listener.getNumEntries());

      listener.reset();
      searchResult = conn.search(listener, getTestBaseDN(),
                                 SearchScope.SUBORDINATE_SUBTREE,
                                 DereferencePolicy.NEVER, 0, 0, false,
                                 "(objectClass=*)");
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 2);
      assertEquals(searchResult.getEntryCount(), listener.getNumEntries());
    }
    finally
    {
      try
      {
        conn.delete(sub2DN);
      } catch (Exception e) {}

      try
      {
        conn.delete(sub1DN);
      } catch (Exception e) {}

      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the eighth {@code search} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearch8()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String sub1DN = "ou=sub1," + getTestBaseDN();
    String sub2DN = "ou=sub2," + sub1DN;

    Attribute[] sub1Attrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "sub1")
    };

    Attribute[] sub2Attrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "sub2")
    };

    LDAPConnection conn = getAdminConnection();

    try
    {
      Filter filter = Filter.createPresenceFilter("objectClass");

      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
           (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      conn.add(getTestBaseDN(), getBaseEntryAttributes());
      conn.add(sub1DN, sub1Attrs);
      conn.add(sub2DN, sub2Attrs);

      TestSearchResultListener listener = new TestSearchResultListener();

      SearchResult searchResult = conn.search(listener, getTestBaseDN(),
                                              SearchScope.BASE,
                                              DereferencePolicy.NEVER,
                                              0, 0, false, filter);
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);
      assertEquals(searchResult.getEntryCount(), listener.getNumEntries());
      assertEquals(listener.getFirstEntryDN(), getTestBaseDN());

      listener.reset();
      searchResult = conn.search(listener, getTestBaseDN(), SearchScope.ONE,
                                 DereferencePolicy.NEVER, 0, 0, false,
                                 filter);
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);
      assertEquals(searchResult.getEntryCount(), listener.getNumEntries());
      assertEquals(listener.getFirstEntryDN(), sub1DN);

      listener.reset();
      searchResult = conn.search(listener, getTestBaseDN(), SearchScope.SUB,
                                 DereferencePolicy.NEVER, 0, 0, false,
                                 filter);
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 3);
      assertEquals(searchResult.getEntryCount(), listener.getNumEntries());

      listener.reset();
      searchResult = conn.search(listener, getTestBaseDN(),
                                 SearchScope.SUBORDINATE_SUBTREE,
                                 DereferencePolicy.NEVER, 0, 0, false,
                                 filter);
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 2);
      assertEquals(searchResult.getEntryCount(), listener.getNumEntries());
    }
    finally
    {
      try
      {
        conn.delete(sub2DN);
      } catch (Exception e) {}

      try
      {
        conn.delete(sub1DN);
      } catch (Exception e) {}

      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Tests the {@code search} method variant that takes a read-only request.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchReadOnly()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    ReadOnlySearchRequest r = new SearchRequest("", SearchScope.BASE,
                                                "(objectClass=*)");
    LDAPConnection conn = getAdminConnection();

    try
    {
      assertTrue(conn.isConnected());
      assertNotNull(conn.getConnectedAddress());
      assertTrue((conn.getConnectedPort() >= 1) &&
                 (conn.getConnectedPort() <= 65535));
      assertNotNull(conn.toString());

      SearchResult searchResult = conn.search(r);
      assertNotNull(searchResult);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);
    }
    finally
    {
      conn.close();
      assertFalse(conn.isConnected());
      assertNull(conn.getConnectedAddress());
      assertTrue(conn.getConnectedPort() < 0);
      assertNotNull(conn.toString());
    }
  }



  /**
   * Provides test coverage for the {@code searchForEntry} methods with a valid,
   * matching search.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchForEntryValidMatching()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection c = getAdminConnection();

    c.add(getTestBaseDN(), getBaseEntryAttributes());

    c.add(
         "dn: uid=test," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test",
         "givenName: Test",
         "sn: User",
         "cn: Test User");

    SearchResultEntry e = c.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         "(uid=test)");
    assertNotNull(e);
    assertNotNull(e.toString());

    e = c.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         Filter.create("(uid=test)"));
    assertNotNull(e);

    e = c.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         DereferencePolicy.NEVER, 0, false, "(uid=test)");
    assertNotNull(e);

    e = c.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         DereferencePolicy.NEVER, 0, false, Filter.create("(uid=test)"));
    assertNotNull(e);

    final SearchRequest req = new SearchRequest(getTestBaseDN(),
         SearchScope.SUB, "(uid=test)");
    req.setTimeLimitSeconds(1000);
    req.addControl(new ManageDsaITRequestControl());
    e = c.searchForEntry(req);
    assertNotNull(e);

    e = c.searchForEntry((ReadOnlySearchRequest) req);
    assertNotNull(e);


    c.delete("uid=test," + getTestBaseDN());
    c.delete(getTestBaseDN());

    c.close();
  }



  /**
   * Provides test coverage for the {@code searchForEntry} methods with a valid,
   * non-matching search.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchForEntryValidNonMatching()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection c = getAdminConnection();

    c.add(getTestBaseDN(), getBaseEntryAttributes());

    SearchResultEntry e = c.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         "(uid=test)");
    assertNull(e);

    e = c.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         Filter.create("(uid=test)"));
    assertNull(e);

    e = c.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         DereferencePolicy.NEVER, 0, false, "(uid=test)");
    assertNull(e);

    e = c.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         DereferencePolicy.NEVER, 0, false, Filter.create("(uid=test)"));
    assertNull(e);

    final SearchRequest req = new SearchRequest(getTestBaseDN(),
         SearchScope.SUB, "(uid=test)");
    req.setTimeLimitSeconds(1000);
    req.addControl(new ManageDsaITRequestControl());
    e = c.searchForEntry(req);
    assertNull(e);

    e = c.searchForEntry((ReadOnlySearchRequest) req);
    assertNull(e);


    c.delete(getTestBaseDN());

    c.close();
  }



  /**
   * Provides test coverage for the {@code searchForEntry} methods with a valid,
   * non-matching search.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchForEntryValidMissingBase()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection c = getAdminConnection();

    SearchResultEntry e = c.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         "(uid=test)");
    assertNull(e);

    e = c.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         Filter.create("(uid=test)"));
    assertNull(e);

    e = c.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         DereferencePolicy.NEVER, 0, false, "(uid=test)");
    assertNull(e);

    e = c.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         DereferencePolicy.NEVER, 0, false, Filter.create("(uid=test)"));
    assertNull(e);

    final SearchRequest req = new SearchRequest(getTestBaseDN(),
         SearchScope.SUB, "(uid=test)");
    req.setTimeLimitSeconds(1000);
    req.addControl(new ManageDsaITRequestControl());
    e = c.searchForEntry(req);
    assertNull(e);

    e = c.searchForEntry((ReadOnlySearchRequest) req);
    assertNull(e);


    c.close();
  }



  /**
   * Provides test coverage for the {@code searchForEntry} methods which take
   * search filter strings using invalid filters.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchForEntryInvalidFilterString()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection c = getAdminConnection();

    try
    {
      c.searchForEntry(getTestBaseDN(), SearchScope.SUB, "invalidFilter");
      fail("Expected an exception with an invalid filter");
    }
    catch (final LDAPSearchException lse)
    {
      assertEquals(lse.getResultCode(), ResultCode.FILTER_ERROR);
    }


    try
    {
      c.searchForEntry(getTestBaseDN(), SearchScope.SUB,
           DereferencePolicy.NEVER, 0, false, "invalidFilter");
      fail("Expected an exception with an invalid filter");
    }
    catch (final LDAPSearchException lse)
    {
      assertEquals(lse.getResultCode(), ResultCode.FILTER_ERROR);
    }


    c.close();
  }



  /**
   * Provides test coverage for the {@code searchForEntry} method for a search
   * that matches multiple entries.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchForEntryMultipleMatches()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection c = getAdminConnection();

    c.add(getTestBaseDN(), getBaseEntryAttributes());

    c.add(
         "dn: uid=test.1," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test",
         "givenName: Test",
         "sn: 1",
         "cn: Test 1");
    c.add(
         "dn: uid=test.2," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test",
         "givenName: Test",
         "sn: 2",
         "cn: Test 2");

    try
    {
      c.searchForEntry(getTestBaseDN(), SearchScope.SUB, "(givenName=Test)");
      fail("Expected an exception when searching with multiple matches");
    }
    catch (final LDAPSearchException lse)
    {
      assertEquals(lse.getResultCode(), ResultCode.SIZE_LIMIT_EXCEEDED);
    }

    c.delete("uid=test.1," + getTestBaseDN());
    c.delete("uid=test.2," + getTestBaseDN());
    c.delete(getTestBaseDN());

    c.close();
  }



  /**
   * Tests the methods involving a referral connector.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReferralConnector()
         throws Exception
  {
    LDAPConnection conn = new LDAPConnection();
    assertNotNull(conn.getReferralConnector());

    conn.setReferralConnector(new TestReferralConnector());
    assertNotNull(conn.getReferralConnector());

    conn.setReferralConnector(null);
    assertNotNull(conn.getReferralConnector());
  }



  /**
   * Tests the {@code sendMessage} method with a connection that is not
   * established.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class})
  public void testSendMessageNotConnected()
         throws Exception
  {
    LDAPConnection conn = new LDAPConnection();
    assertFalse(conn.isConnected());
    assertNull(conn.getConnectedAddress());
    assertTrue(conn.getConnectedPort() < 0);
    assertNotNull(conn.toString());

    conn.sendMessage(new LDAPMessage(conn.nextMessageID(),
         new UnbindRequestProtocolOp()), 10000L);
  }



  /**
   * Tests to ensure that a disconnect handler is properly invoked when a
   * connection is closed.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDisconnectHandlerDefaultClose()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    TestDisconnectHandler handler = new TestDisconnectHandler();

    LDAPConnection conn = getAdminConnection();
    LDAPConnectionOptions opts = conn.getConnectionOptions();
    opts.setDisconnectHandler(handler);
    conn.setConnectionOptions(opts);

    assertEquals(handler.getNotificationCount(), 0);
    assertNull(conn.getDisconnectType());
    assertNull(conn.getDisconnectMessage());
    assertNull(conn.getDisconnectCause());

    conn.close();
    assertEquals(handler.getNotificationCount(), 1);

    assertNotNull(conn.getDisconnectType());
    assertEquals(conn.getDisconnectType(), DisconnectType.UNBIND);
    assertNull(conn.getDisconnectMessage());
    assertNull(conn.getDisconnectCause());
  }



  /**
   * Tests to ensure that a disconnect handler is properly invoked when a
   * connection is closed and custom disconnect information has been provided.
   * It also tests to ensure that only the first set of disconnect information
   * will be used.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDisconnectHandlerCustomClose()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    TestDisconnectHandler handler = new TestDisconnectHandler();

    LDAPConnection conn = getAdminConnection();
    LDAPConnectionOptions opts = conn.getConnectionOptions();
    opts.setDisconnectHandler(handler);
    conn.setConnectionOptions(opts);

    assertEquals(handler.getNotificationCount(), 0);
    assertNull(conn.getDisconnectType());
    assertNull(conn.getDisconnectMessage());
    assertNull(conn.getDisconnectCause());

    conn.setDisconnectInfo(DisconnectType.OTHER,
         "testDisconnectHandlerCustomClose", new Exception());

    final DisconnectInfo di = new DisconnectInfo(conn, DisconnectType.UNKNOWN,
         "somethingElse", new LDAPException(ResultCode.OTHER));
    assertNotNull(di.toString());
    conn.setDisconnectInfo(di);

    conn.close();
    assertEquals(handler.getNotificationCount(), 1);

    assertNotNull(conn.getDisconnectType());
    assertEquals(conn.getDisconnectType(), DisconnectType.OTHER);
    assertNotNull(conn.getDisconnectMessage());
    assertEquals(conn.getDisconnectMessage(),
         "testDisconnectHandlerCustomClose");
    assertNotNull(conn.getDisconnectCause());
    assertTrue(conn.getDisconnectCause() instanceof Exception);
    assertFalse(conn.getDisconnectCause() instanceof LDAPException);
  }



  /**
   * Tests the methods used to perform asynchronous operations.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAsyncOperations()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }


    LDAPConnection conn = getAdminConnection();
    TestAsyncListener listener = new TestAsyncListener();

    ReadOnlyAddRequest addRequest =
         new AddRequest(getTestBaseDN(), getBaseEntryAttributes());
    AsyncRequestID requestID = conn.asyncAdd(addRequest, listener);
    assertTrue(requestID.getMessageID() > 0);
    assertEquals(requestID.getMessageID(),
                 ((AddRequest) addRequest).getLastMessageID());

    listener.waitForResult();
    assertEquals(listener.getLastMessageID(), requestID.getMessageID());
    assertNotNull(listener.getLastResult());
    assertEquals(listener.getLastResult().getResultCode(), ResultCode.SUCCESS);


    listener.clear();


    addRequest = new AddRequest(
         "dn: ou=test," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test",
         "description: foo");
    requestID = conn.asyncAdd(addRequest, listener);
    assertTrue(requestID.getMessageID() > 0);
    assertEquals(requestID.getMessageID(),
                 ((AddRequest) addRequest).getLastMessageID());

    listener.waitForResult();
    assertEquals(listener.getLastMessageID(), requestID.getMessageID());
    assertNotNull(listener.getLastResult());
    assertEquals(listener.getLastResult().getResultCode(), ResultCode.SUCCESS);


    listener.clear();


    ReadOnlyModifyRequest modifyRequest =
         new ModifyRequest("ou=test," + getTestBaseDN(),
                  new Modification(ModificationType.REPLACE, "description",
                                   "bar"));
    requestID = conn.asyncModify(modifyRequest, listener);
    assertTrue(requestID.getMessageID() > 0);
    assertEquals(requestID.getMessageID(),
                 ((ModifyRequest) modifyRequest).getLastMessageID());

    listener.waitForResult();
    assertEquals(listener.getLastMessageID(), requestID.getMessageID());
    assertNotNull(listener.getLastResult());
    assertEquals(listener.getLastResult().getResultCode(), ResultCode.SUCCESS);


    listener.clear();


    ReadOnlyCompareRequest compareRequest =
         new CompareRequest("ou=test," + getTestBaseDN(), "description", "bar");
    requestID = conn.asyncCompare(compareRequest, listener);
    assertTrue(requestID.getMessageID() > 0);
    assertEquals(requestID.getMessageID(),
                 ((CompareRequest) compareRequest).getLastMessageID());

    listener.waitForResult();
    assertEquals(listener.getLastMessageID(), requestID.getMessageID());
    assertNotNull(listener.getLastResult());
    assertEquals(listener.getLastResult().getResultCode(),
                 ResultCode.COMPARE_TRUE);
    assertTrue(listener.getLastResult() instanceof CompareResult);


    listener.clear();


    ReadOnlySearchRequest searchRequest =
         new SearchRequest(listener, getTestBaseDN(), SearchScope.SUB,
                           "(objectClass=*)");
    requestID = conn.asyncSearch(searchRequest);
    assertTrue(requestID.getMessageID() > 0);
    assertEquals(requestID.getMessageID(),
                 ((SearchRequest) searchRequest).getLastMessageID());

    listener.waitForResult();
    assertEquals(listener.getLastMessageID(), requestID.getMessageID());
    assertNotNull(listener.getLastResult());
    assertEquals(listener.getLastResult().getResultCode(), ResultCode.SUCCESS);
    assertTrue(listener.getLastResult() instanceof SearchResult);


    listener.clear();


    ReadOnlyModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("ou=test," + getTestBaseDN(), "ou=test2", true);
    requestID = conn.asyncModifyDN(modifyDNRequest, listener);
    assertTrue(requestID.getMessageID() > 0);
    assertEquals(requestID.getMessageID(),
                 ((ModifyDNRequest) modifyDNRequest).getLastMessageID());

    listener.waitForResult();
    assertEquals(listener.getLastMessageID(), requestID.getMessageID());
    assertNotNull(listener.getLastResult());
    assertEquals(listener.getLastResult().getResultCode(), ResultCode.SUCCESS);


    listener.clear();


    ReadOnlyDeleteRequest deleteRequest =
         new DeleteRequest("ou=test2," + getTestBaseDN());
    requestID = conn.asyncDelete(deleteRequest, listener);
    assertTrue(requestID.getMessageID() > 0);
    assertEquals(requestID.getMessageID(),
                 ((DeleteRequest) deleteRequest).getLastMessageID());

    listener.waitForResult();
    assertEquals(listener.getLastMessageID(), requestID.getMessageID());
    assertNotNull(listener.getLastResult());
    assertEquals(listener.getLastResult().getResultCode(), ResultCode.SUCCESS);


    listener.clear();


    deleteRequest = new DeleteRequest(getTestBaseDN());
    requestID = conn.asyncDelete(deleteRequest, listener);
    assertTrue(requestID.getMessageID() > 0);
    assertEquals(requestID.getMessageID(),
                 ((DeleteRequest) deleteRequest).getLastMessageID());

    listener.waitForResult();
    assertEquals(listener.getLastMessageID(), requestID.getMessageID());
    assertNotNull(listener.getLastResult());
    assertEquals(listener.getLastResult().getResultCode(), ResultCode.SUCCESS);


    // Send an abandon request over this connection for the last operation.  It
    // won't hurt anything and it will provide coverage.
    conn.abandon(requestID);


    conn.close();
  }



  /**
   * Tests the methods used to perform asynchronous operations using the
   * {@code AsyncRequestID} object as a {@code Future}.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAsyncOperationsAsFuture()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }


    LDAPConnection conn = getAdminConnection();

    BasicAsyncResultListener addListener = new BasicAsyncResultListener();
    ReadOnlyAddRequest addRequest =
         new AddRequest(getTestBaseDN(), getBaseEntryAttributes());
    AsyncRequestID requestID = conn.asyncAdd(addRequest, addListener);
    assertTrue(requestID.getMessageID() > 0);
    assertEquals(requestID.getMessageID(),
                 ((AddRequest) addRequest).getLastMessageID());

    LDAPResult addResult = requestID.get();
    assertNotNull(addResult);
    assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);
    assertTrue(requestID.isDone());
    assertFalse(requestID.cancel(true));

    assertNotNull(addListener.getLDAPResult());
    assertEquals(addListener.getLDAPResult().getResultCode(),
         ResultCode.SUCCESS);


    addRequest = new AddRequest(
         "dn: ou=test," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test",
         "description: foo");
    requestID = conn.asyncAdd(addRequest, null);
    assertTrue(requestID.getMessageID() > 0);
    assertEquals(requestID.getMessageID(),
                 ((AddRequest) addRequest).getLastMessageID());

    addResult = requestID.get();
    assertNotNull(addResult);
    assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);
    assertTrue(requestID.isDone());
    assertFalse(requestID.cancel(true));


    BasicAsyncResultListener modifyListener = new BasicAsyncResultListener();
    ReadOnlyModifyRequest modifyRequest =
         new ModifyRequest("ou=test," + getTestBaseDN(),
                  new Modification(ModificationType.REPLACE, "description",
                                   "bar"));
    requestID = conn.asyncModify(modifyRequest, modifyListener);
    assertTrue(requestID.getMessageID() > 0);
    assertEquals(requestID.getMessageID(),
                 ((ModifyRequest) modifyRequest).getLastMessageID());

    LDAPResult modifyResult = requestID.get();
    assertNotNull(modifyResult);
    assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);
    assertTrue(requestID.isDone());
    assertFalse(requestID.cancel(true));

    assertNotNull(modifyListener.getLDAPResult());
    assertEquals(modifyListener.getLDAPResult().getResultCode(),
         ResultCode.SUCCESS);


    modifyRequest = new ModifyRequest("ou=test," + getTestBaseDN(),
         new Modification(ModificationType.REPLACE, "description", "baz"));
    requestID = conn.asyncModify(modifyRequest, null);
    assertTrue(requestID.getMessageID() > 0);
    assertEquals(requestID.getMessageID(),
                 ((ModifyRequest) modifyRequest).getLastMessageID());

    modifyResult = requestID.get();
    assertNotNull(modifyResult);
    assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);
    assertTrue(requestID.isDone());
    assertFalse(requestID.cancel(true));


    BasicAsyncCompareResultListener compareListener =
         new BasicAsyncCompareResultListener();
    ReadOnlyCompareRequest compareRequest =
         new CompareRequest("ou=test," + getTestBaseDN(), "description", "bar");
    requestID = conn.asyncCompare(compareRequest, compareListener);
    assertTrue(requestID.getMessageID() > 0);
    assertEquals(requestID.getMessageID(),
                 ((CompareRequest) compareRequest).getLastMessageID());

    LDAPResult compareResult = requestID.get();
    assertNotNull(compareResult);
    assertTrue(compareResult instanceof CompareResult);
    assertEquals(compareResult.getResultCode(), ResultCode.COMPARE_FALSE);
    assertTrue(requestID.isDone());
    assertFalse(requestID.cancel(true));

    assertNotNull(compareListener.getCompareResult());
    assertEquals(compareListener.getCompareResult().getResultCode(),
         ResultCode.COMPARE_FALSE);


    compareRequest = new CompareRequest("ou=test," + getTestBaseDN(),
         "description", "baz");
    requestID = conn.asyncCompare(compareRequest, null);
    assertTrue(requestID.getMessageID() > 0);
    assertEquals(requestID.getMessageID(),
                 ((CompareRequest) compareRequest).getLastMessageID());

    compareResult = requestID.get();
    assertNotNull(compareResult);
    assertTrue(compareResult instanceof CompareResult);
    assertEquals(compareResult.getResultCode(), ResultCode.COMPARE_TRUE);
    assertTrue(requestID.isDone());
    assertFalse(requestID.cancel(true));


    BasicAsyncSearchResultListener searchListener =
         new BasicAsyncSearchResultListener();
    ReadOnlySearchRequest searchRequest = new SearchRequest(searchListener,
         getTestBaseDN(), SearchScope.SUB, "(objectClass=*)");
    requestID = conn.asyncSearch(searchRequest);
    assertTrue(requestID.getMessageID() > 0);
    assertEquals(requestID.getMessageID(),
                 ((SearchRequest) searchRequest).getLastMessageID());

    LDAPResult searchResult = requestID.get();
    assertNotNull(searchResult);
    assertTrue(searchResult instanceof SearchResult);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertTrue(requestID.isDone());
    assertFalse(requestID.cancel(true));

    assertNotNull(searchListener.getSearchResult());
    assertEquals(searchListener.getSearchResult().getResultCode(),
         ResultCode.SUCCESS);

    assertNotNull(searchListener.getSearchEntries());
    assertEquals(searchListener.getSearchEntries().size(),
         ((SearchResult) searchResult).getEntryCount());

    assertNotNull(searchListener.getSearchReferences());
    assertEquals(searchListener.getSearchReferences().size(),
         ((SearchResult) searchResult).getReferenceCount());


    // Perform the search again, and this time use the methods that are related
    // to cancel it.  Since this is completely based on timing, we can't know
    // whether the cancel will be successful or not.
    searchListener = new BasicAsyncSearchResultListener();
    searchRequest = new SearchRequest(searchListener,
         getTestBaseDN(), SearchScope.SUB, "(objectClass=*)");
    requestID = conn.asyncSearch(searchRequest);

    if (requestID.cancel(true))
    {
      assertTrue(requestID.isCancelled());
    }
    else
    {
      assertFalse(requestID.isCancelled());
    }
    requestID.cancel(true);
    assertTrue(requestID.isDone());


    // Perform the search again, and this time wait a while before checking the
    // response to give it time to complete.
    searchListener = new BasicAsyncSearchResultListener();
    searchRequest = new SearchRequest(searchListener,
         getTestBaseDN(), SearchScope.SUB, "(objectClass=*)");
    requestID = conn.asyncSearch(searchRequest);

    Thread.sleep(1000L);
    if (requestID.cancel(true))
    {
      assertTrue(requestID.isCancelled());
    }
    else
    {
      assertFalse(requestID.isCancelled());
    }
    requestID.cancel(true);
    assertTrue(requestID.isDone());


    BasicAsyncResultListener modifyDNListener = new BasicAsyncResultListener();
    ReadOnlyModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("ou=test," + getTestBaseDN(), "ou=test2", true);
    requestID = conn.asyncModifyDN(modifyDNRequest, modifyDNListener);
    assertTrue(requestID.getMessageID() > 0);
    assertEquals(requestID.getMessageID(),
                 ((ModifyDNRequest) modifyDNRequest).getLastMessageID());

    LDAPResult modifyDNResult = requestID.get();
    assertNotNull(modifyDNResult);
    assertEquals(modifyDNResult.getResultCode(), ResultCode.SUCCESS);
    assertTrue(requestID.isDone());
    assertFalse(requestID.cancel(true));

    assertNotNull(modifyDNListener.getLDAPResult());
    assertEquals(modifyDNListener.getLDAPResult().getResultCode(),
         ResultCode.SUCCESS);


    modifyDNRequest = new ModifyDNRequest("ou=test2," + getTestBaseDN(),
         "ou=test", true);
    requestID = conn.asyncModifyDN(modifyDNRequest, null);
    assertTrue(requestID.getMessageID() > 0);
    assertEquals(requestID.getMessageID(),
                 ((ModifyDNRequest) modifyDNRequest).getLastMessageID());

    modifyDNResult = requestID.get();
    assertNotNull(modifyDNResult);
    assertEquals(modifyDNResult.getResultCode(), ResultCode.SUCCESS);
    assertTrue(requestID.isDone());
    assertFalse(requestID.cancel(true));


    BasicAsyncResultListener deleteListener = new BasicAsyncResultListener();
    ReadOnlyDeleteRequest deleteRequest =
         new DeleteRequest("ou=test," + getTestBaseDN());
    requestID = conn.asyncDelete(deleteRequest, deleteListener);
    assertTrue(requestID.getMessageID() > 0);
    assertEquals(requestID.getMessageID(),
                 ((DeleteRequest) deleteRequest).getLastMessageID());

    LDAPResult deleteResult = requestID.get();
    assertNotNull(deleteResult);
    assertEquals(deleteResult.getResultCode(), ResultCode.SUCCESS);
    assertTrue(requestID.isDone());
    assertFalse(requestID.cancel(true));

    assertNotNull(deleteListener.getLDAPResult());
    assertEquals(deleteListener.getLDAPResult().getResultCode(),
         ResultCode.SUCCESS);


    deleteListener = new BasicAsyncResultListener();
    deleteRequest = new DeleteRequest(getTestBaseDN());
    requestID = conn.asyncDelete(deleteRequest, null);
    assertTrue(requestID.getMessageID() > 0);
    assertEquals(requestID.getMessageID(),
                 ((DeleteRequest) deleteRequest).getLastMessageID());

    deleteResult = requestID.get();
    assertNotNull(deleteResult);
    assertEquals(deleteResult.getResultCode(), ResultCode.SUCCESS);
    assertTrue(requestID.isDone());
    assertFalse(requestID.cancel(true));


    conn.close();
  }



  /**
   * Tests the methods used to perform asynchronous operations for a connection
   * in synchronous mode.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAsyncOperationsInSynchronousMode()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }


    LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);

    LDAPConnection conn = new LDAPConnection(options, getTestHost(),
         getTestPort(), getTestBindDN(), getTestBindPassword());
    assertEquals(conn.getActiveOperationCount(), -1);

    TestAsyncListener listener = new TestAsyncListener();

    ReadOnlyAddRequest addRequest =
         new AddRequest(getTestBaseDN(), getBaseEntryAttributes());
    try
    {
      conn.asyncAdd(addRequest, listener);
      fail("Expected an exception when performing an async add in " +
           "synchronous mode");
    }
    catch (LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NOT_SUPPORTED);
    }


    ReadOnlyModifyRequest modifyRequest =
         new ModifyRequest("ou=test," + getTestBaseDN(),
                  new Modification(ModificationType.REPLACE, "description",
                                   "bar"));
    try
    {
      conn.asyncModify(modifyRequest, listener);
      fail("Expected an exception when performing an async modify in " +
           "synchronous mode");
    }
    catch (LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NOT_SUPPORTED);
    }


    ReadOnlyCompareRequest compareRequest =
         new CompareRequest("ou=test," + getTestBaseDN(), "description", "bar");
    try
    {
      conn.asyncCompare(compareRequest, listener);
      fail("Expected an exception when performing an async compare in " +
           "synchronous mode");
    }
    catch (LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NOT_SUPPORTED);
    }


    ReadOnlySearchRequest searchRequest =
         new SearchRequest(listener, getTestBaseDN(), SearchScope.SUB,
                           "(objectClass=*)");
    try
    {
      conn.asyncSearch(searchRequest);
      fail("Expected an exception when performing an async search in " +
           "synchronous mode");
    }
    catch (LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NOT_SUPPORTED);
    }


    ReadOnlyModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("ou=test," + getTestBaseDN(), "ou=test2", true);
    try
    {
      conn.asyncModifyDN(modifyDNRequest, listener);
      fail("Expected an exception when performing an async modify DN in " +
           "synchronous mode");
    }
    catch (LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NOT_SUPPORTED);
    }


    ReadOnlyDeleteRequest deleteRequest =
         new DeleteRequest("ou=test2," + getTestBaseDN());
    try
    {
      conn.asyncDelete(deleteRequest, listener);
      fail("Expected an exception when performing an async delete in " +
           "synchronous mode");
    }
    catch (LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NOT_SUPPORTED);
    }


    // Send an abandon request over this connection for the last operation.  It
    // won't hurt anything and it will provide coverage.
    try
    {
      conn.abandon(new AsyncRequestID(1, conn));
      fail("Expected an exception when performing an abandon in " +
           "synchronous mode");
    }
    catch (LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NOT_SUPPORTED);
    }


    conn.close();
  }



  /**
   * Provides basic test coverage for the {@code LDAPConnectionInternals} class
   * used by a connection.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectionInternals()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    long beforeConnectTime = System.currentTimeMillis();

    LDAPConnection conn = getAdminConnection();
    LDAPConnectionInternals internals = conn.getConnectionInternals(true);

    assertNotNull(internals);

    assertNotNull(internals.getConnection());
    assertEquals(internals.getConnection(), conn);

    assertNotNull(internals.getConnectionReader());

    assertNotNull(internals.getHost());
    assertEquals(internals.getHost(), getTestHost());

    assertNotNull(internals.getPort());
    assertEquals(internals.getPort(), getTestPort());

    assertNotNull(internals.getSocket());

    assertNotNull(internals.getOutputStream());

    assertTrue(internals.isConnected());

    assertTrue(internals.getConnectTime() >= beforeConnectTime);

    assertNotNull(internals.toString());

    conn.close();
    assertNull(conn.getConnectionInternals(false));

    try
    {
      conn.getConnectionInternals(true);
      fail("Expected an exception when trying to get connection internals " +
           "for a closed connection");
    }
    catch (final LDAPException le)
    {
      assertResultCodeEquals(le, ResultCode.SERVER_DOWN);
    }
  }



  /**
   * Tests behavior related to capturing connect stack traces.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectStackTrace()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnectionOptions opts = new LDAPConnectionOptions();
    assertFalse(opts.captureConnectStackTrace());

    LDAPConnection conn = new LDAPConnection(opts);
    assertNull(conn.getConnectStackTrace());

    conn.connect(getTestHost(), getTestPort());
    assertNull(conn.getConnectStackTrace());
    conn.close();
    assertNull(conn.getConnectStackTrace());

    opts.setCaptureConnectStackTrace(true);
    conn.setConnectionOptions(opts);
    conn.connect(getTestHost(), getTestPort());
    assertNotNull(conn.getConnectStackTrace());
    conn.close();
    assertNotNull(conn.getConnectStackTrace());

    opts.setCaptureConnectStackTrace(false);
    conn.setConnectionOptions(opts);
    conn = new LDAPConnection(opts, getTestHost(), getTestPort());
    assertNull(conn.getConnectStackTrace());
    conn.close();
    assertNull(conn.getConnectStackTrace());
  }



  /**
   * Provides a set of test cases that cover methods related to the connection
   * socket factory.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSocketFactory()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = new LDAPConnection();
    assertNotNull(conn.getSocketFactory());
    assertNull(conn.getLastUsedSocketFactory());

    conn.connect(getTestHost(), getTestPort());
    assertNotNull(conn.getSocketFactory());
    assertNotNull(conn.getLastUsedSocketFactory());

    conn.setSocketFactory(SocketFactory.getDefault());
    assertNotNull(conn.getSocketFactory());
    assertNotNull(conn.getLastUsedSocketFactory());

    conn.close();
    assertNotNull(conn.getSocketFactory());
    assertNotNull(conn.getLastUsedSocketFactory());
  }



  /**
   * Tests the behavior of the connection when configured to use schema when
   * reading responses.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUseSchema()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = new LDAPConnection(getTestHost(), getTestPort(),
         getTestBindDN(), getTestBindPassword());
    assertFalse(conn.getConnectionOptions().useSchema());

    conn.add(getTestBaseDN(), getBaseEntryAttributes());

    conn.add(
         "dn: cn=test," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: groupOfNames",
         "cn: test",
         "member: uid=test.user,ou=People,dc=example,dc=com");

    Entry testEntry = conn.getEntry("cn=test," + getTestBaseDN());
    assertNotNull(testEntry);

    assertTrue(testEntry.hasAttribute("member"));

    assertEquals(testEntry.getAttribute("member").getMatchingRule(),
         CaseIgnoreStringMatchingRule.getInstance());

    assertTrue(testEntry.hasAttributeValue("member",
         "uid=test.user,ou=People,dc=example,dc=com"));

    assertFalse(testEntry.hasAttributeValue("member",
         "uid = test.user, ou=People, dc=example, dc=com"));

    conn.close();

    LDAPConnectionOptions opts = new LDAPConnectionOptions();
    opts.setUseSchema(true);
    conn = new LDAPConnection(opts, getTestHost(), getTestPort(),
         getTestBindDN(), getTestBindPassword());
    assertTrue(conn.getConnectionOptions().useSchema());

    testEntry = conn.getEntry("cn=test," + getTestBaseDN());
    assertNotNull(testEntry);

    assertTrue(testEntry.hasAttribute("member"));

    assertEquals(testEntry.getAttribute("member").getMatchingRule(),
         DistinguishedNameMatchingRule.getInstance());

    assertTrue(testEntry.hasAttributeValue("member",
         "uid=test.user,ou=People,dc=example,dc=com"));

    assertTrue(testEntry.hasAttributeValue("member",
         "uid = test.user, ou=People, dc=example, dc=com"));

    conn.delete("cn=test," + getTestBaseDN());
    conn.delete(getTestBaseDN());
    conn.close();
  }



  /**
   * Provides test coverage for the {@code processOperation} method for various
   * types of operations.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcessOperation()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }


    final LDAPConnection conn = new LDAPConnection(getTestHost(),
         getTestPort());

    // Test the ability to process a bind.
    LDAPResult result = conn.processOperation(new SimpleBindRequest(
         getTestBindDN(), getTestBindPassword()));
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);


    // Test the ability to process add operations.
    result = conn.processOperation(new AddRequest(getTestBaseDN(),
         getBaseEntryAttributes()));
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    result = conn.processOperation(new AddRequest(
         "dn: ou=People," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People"));
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);


    // Test the ability to process compare operations.
    result = conn.processOperation(new CompareRequest(
         "ou=People," + getTestBaseDN(), "ou", "People"));
    assertEquals(result.getResultCode(), ResultCode.COMPARE_TRUE);
    assertTrue(result instanceof CompareResult);


    // Test the ability to process modify operations.
    result = conn.processOperation(new ModifyRequest(
         "dn: ou=People," + getTestBaseDN(),
         "changeType: modify",
         "replace: description",
         "description: foo"));
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);


    // Test the ability to process modify DN operations.
    result = conn.processOperation(new ModifyDNRequest(
         "ou=People," + getTestBaseDN(), "ou=Users", true));
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);


    // Test the ability to process search operations.
    result = conn.processOperation(new SearchRequest(getTestBaseDN(),
         SearchScope.BASE, "(objectClass=*)"));
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    assertTrue(result instanceof SearchResult);


    // Test the ability to process extended operations.
    result = conn.processOperation(new WhoAmIExtendedRequest());
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    assertTrue(result instanceof WhoAmIExtendedResult);


    // Test the ability to process delete operations.
    result = conn.processOperation(new DeleteRequest(
         "ou=Users," + getTestBaseDN()));
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    result = conn.processOperation(new DeleteRequest(getTestBaseDN()));
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);


    // Test the behavior when attempting to process an operation that won't
    // succeed.  It should return a failure result rather than throwing an
    // exception.
    result = conn.processOperation(new DeleteRequest(getTestBaseDN()));
    assertEquals(result.getResultCode(), ResultCode.NO_SUCH_OBJECT);


    conn.close();
  }



  /**
   * Tests to ensure that the last communication time is properly updated for
   * connections operating in synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLastCommunicationTimeSynchronousMode()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    opts.setUseSynchronousMode(true);

    final LDAPConnection conn = new LDAPConnection(opts);
    assertEquals(conn.getConnectTime(), -1L);
    assertEquals(conn.getLastCommunicationTime(), -1L);

    conn.connect("localhost", ds.getListenPort());
    final long connectTime = conn.getConnectTime();
    assertTrue(connectTime > 0L);

    long lastCommunicationTime = conn.getLastCommunicationTime();
    assertTrue(lastCommunicationTime > 0L);
    assertTrue(lastCommunicationTime >= connectTime);

    // Get entry.
    Thread.sleep(10L);
    conn.getEntry("dc=example,dc=com");
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Get root DSE.
    Thread.sleep(10L);
    conn.getRootDSE();
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Get schema.
    Thread.sleep(10L);
    conn.getSchema();
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Add.
    Thread.sleep(10L);
    conn.add(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test");
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Simple bind.
    Thread.sleep(10L);
    conn.bind("cn=Directory Manager", "password");
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // SASL bind.
    Thread.sleep(10L);
    conn.bind(new PLAINBindRequest("dn:cn=Directory Manager", "password"));
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Compare.
    Thread.sleep(10L);
    conn.compare("dc=example,dc=com", "dc", "example");
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Delete.
    Thread.sleep(10L);
    conn.delete("ou=test,dc=example,dc=com");
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Extended.
    Thread.sleep(10L);
    conn.processExtendedOperation(new WhoAmIExtendedRequest());
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Modify.
    Thread.sleep(10L);
    conn.modify(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Modify DN.
    Thread.sleep(10L);
    conn.modifyDN("uid=test.user,ou=People,dc=example,dc=com", "cn=Test User",
         false);
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Search.
    Thread.sleep(10L);
    conn.search("dc=example,dc=com", SearchScope.SUB, "(objectClass=*)");
    assertLastCommunicationTimeUpdated(conn, lastCommunicationTime);

    // Close.
    conn.close();
    assertEquals(conn.getConnectTime(), -1L);
    assertEquals(conn.getLastCommunicationTime(), -1L);
  }



  /**
   * Tests to ensure that the last communication time is properly updated for
   * connections operating in non-synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLastCommunicationTimeNonSynchronousMode()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    opts.setUseSynchronousMode(false);

    final LDAPConnection conn = new LDAPConnection(opts);
    assertEquals(conn.getConnectTime(), -1L);
    assertEquals(conn.getLastCommunicationTime(), -1L);

    conn.connect("localhost", ds.getListenPort());
    final long connectTime = conn.getConnectTime();
    assertTrue(connectTime > 0L);

    long lastCommunicationTime = conn.getLastCommunicationTime();
    assertTrue(lastCommunicationTime > 0L);
    assertTrue(lastCommunicationTime >= connectTime);

    // Get entry.
    Thread.sleep(10L);
    conn.getEntry("dc=example,dc=com");
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Get root DSE.
    Thread.sleep(10L);
    conn.getRootDSE();
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Get schema.
    Thread.sleep(10L);
    conn.getSchema();
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Add.
    Thread.sleep(10L);
    conn.add(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test");
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Simple bind.
    Thread.sleep(10L);
    conn.bind("cn=Directory Manager", "password");
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // SASL bind.
    Thread.sleep(10L);
    conn.bind(new PLAINBindRequest("dn:cn=Directory Manager", "password"));
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Compare.
    Thread.sleep(10L);
    conn.compare("dc=example,dc=com", "dc", "example");
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Delete.
    Thread.sleep(10L);
    conn.delete("ou=test,dc=example,dc=com");
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Extended.
    Thread.sleep(10L);
    conn.processExtendedOperation(new WhoAmIExtendedRequest());
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Modify.
    Thread.sleep(10L);
    conn.modify(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Modify DN.
    Thread.sleep(10L);
    conn.modifyDN("uid=test.user,ou=People,dc=example,dc=com", "cn=Test User",
         false);
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Search.
    Thread.sleep(10L);
    conn.search("dc=example,dc=com", SearchScope.SUB, "(objectClass=*)");
    assertLastCommunicationTimeUpdated(conn, lastCommunicationTime);

    // Close.
    conn.close();
    assertEquals(conn.getConnectTime(), -1L);
    assertEquals(conn.getLastCommunicationTime(), -1L);
  }



  /**
   * Tests to ensure that the last communication time is properly updated for
   * asynchronous operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLastCommunicationTimeAsynchronousOperations()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    opts.setUseSynchronousMode(false);

    final LDAPConnection conn = new LDAPConnection(opts);
    assertEquals(conn.getConnectTime(), -1L);
    assertEquals(conn.getLastCommunicationTime(), -1L);

    conn.connect("localhost", ds.getListenPort());
    final long connectTime = conn.getConnectTime();
    assertTrue(connectTime > 0L);

    long lastCommunicationTime = conn.getLastCommunicationTime();
    assertTrue(lastCommunicationTime > 0L);
    assertTrue(lastCommunicationTime >= connectTime);

    final TestAsyncListener listener = new TestAsyncListener();

    // Add.
    Thread.sleep(10L);
    AsyncRequestID requestID = conn.asyncAdd(
         new AddRequest(
              "dn: ou=test,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test"),
         listener);
    assertNotNull(requestID.get());
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Compare.
    Thread.sleep(10L);
    requestID = conn.asyncCompare(
         new CompareRequest("dc=example,dc=com", "dc", "example"),
         listener);
    assertNotNull(requestID.get());
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Delete.
    Thread.sleep(10L);
    requestID = conn.asyncDelete(
         new DeleteRequest("ou=test,dc=example,dc=com"),
         listener);
    assertNotNull(requestID.get());
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Modify.
    Thread.sleep(10L);
    requestID = conn.asyncModify(
         new ModifyRequest(
              "dn: uid=test.user,ou=People,dc=example,dc=com",
              "changetype: modify",
              "replace: description",
              "description: foo"),
         listener);
    assertNotNull(requestID.get());
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Modify DN.
    Thread.sleep(10L);
    requestID = conn.asyncModifyDN(
         new ModifyDNRequest("uid=test.user,ou=People,dc=example,dc=com",
              "cn=Test User", false),
         listener);
    assertNotNull(requestID.get());
    lastCommunicationTime = assertLastCommunicationTimeUpdated(conn,
         lastCommunicationTime);

    // Search.
    Thread.sleep(10L);
    requestID = conn.asyncSearch(new SearchRequest(listener,
         "dc=example,dc=com", SearchScope.SUB, "(objectClass=*)"));
    assertNotNull(requestID.get());
    assertLastCommunicationTimeUpdated(conn, lastCommunicationTime);

    // Close.
    conn.close();
    assertEquals(conn.getConnectTime(), -1L);
    assertEquals(conn.getLastCommunicationTime(), -1L);
  }



  /**
   * Ensures that the last communication time for the provided connection has
   * been updated since the last value.
   *
   * @param  conn                           The connection to examine.
   * @param  previousLastCommunicationTime  The last communication time that was
   *                                        determined after the last request.
   *
   * @return  The new last communication time for the connection.
   *
   * @throws  AssertionError  If the last communication time has not been
   *                          updated, or if the last communication time is not
   *                          positive.
   */
  private static long assertLastCommunicationTimeUpdated(
                           final LDAPConnection conn,
                           final long previousLastCommunicationTime)
          throws AssertionError
  {
    final long lastCommunicationTime = conn.getLastCommunicationTime();
    assertTrue(lastCommunicationTime > 0L);
    assertTrue(lastCommunicationTime > previousLastCommunicationTime);

    final long connectTime = conn.getConnectTime();
    assertTrue(connectTime > 0L);
    assertTrue(lastCommunicationTime > connectTime);

    return lastCommunicationTime;
  }
}
