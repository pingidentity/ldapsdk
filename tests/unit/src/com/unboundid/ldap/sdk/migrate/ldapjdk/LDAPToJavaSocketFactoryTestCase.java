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

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the {@code LDAPToJavaSocketFactory}
 * class.
 */
public class LDAPToJavaSocketFactoryTestCase
       extends LDAPSDKTestCase
{
  // An unused port number that may be used for testing failures.
  private int unusedPort;



  /**
   * Identifies a port number that is not in use on the system, which may be
   * used to generate test failures.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    Socket s = new Socket();
    s.bind(null);

    unusedPort = s.getLocalPort();

    s.close();
  }



  /**
   * Tests the ability to create a socket using a remote host and port.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidRemoteHostPort()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPToJavaSocketFactory f =
         new LDAPToJavaSocketFactory(new TestLDAPSocketFactory());
    Socket s = f.createSocket(getTestHost(), getTestPort());
    s.close();
  }



  /**
   * Tests the ability to create a socket using a remote host and port.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidRemoteHostPortWithSocketFactory()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPToJavaSocketFactory f = new LDAPToJavaSocketFactory(
         new JavaToLDAPSocketFactory(SocketFactory.getDefault()));
    Socket s = f.createSocket(getTestHost(), getTestPort());
    s.close();
  }



  /**
   * Tests the behavior when trying to connect to a port on which nothing is
   * listening.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testInvalidRemoteHostPort()
         throws Exception
  {
    LDAPToJavaSocketFactory f =
         new LDAPToJavaSocketFactory(new TestLDAPSocketFactory());
    f.createSocket("127.0.0.1", unusedPort);
  }



  /**
   * Tests the ability to create a socket using a host and port, and local
   * address and port.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidRemoteHostPortLocalAddressPort()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPToJavaSocketFactory f =
         new LDAPToJavaSocketFactory(new TestLDAPSocketFactory());
    Socket s = f.createSocket(getTestHost(), getTestPort(),
         InetAddress.getLocalHost(), 0);
    s.close();
  }



  /**
   * Tests the ability to create a socket using a host and port, and local
   * address and port.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidRemoteHostPortLocalAddressPortWithSocketFactory()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPToJavaSocketFactory f = new LDAPToJavaSocketFactory(
         new JavaToLDAPSocketFactory(SocketFactory.getDefault()));
    Socket s = f.createSocket(getTestHost(), getTestPort(),
         InetAddress.getLocalHost(), 0);
    s.close();
  }



  /**
   * Tests the behavior when trying to connect to a port on which nothing is
   * listening.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testInvalidHostPort()
         throws Exception
  {
    LDAPToJavaSocketFactory f =
         new LDAPToJavaSocketFactory(new TestLDAPSocketFactory());
    f.createSocket("127.0.0.1", unusedPort, InetAddress.getLocalHost(), 0);
  }



  /**
   * Tests the ability to create a socket using a remote address and port.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidRemoteAddressPort()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPToJavaSocketFactory f =
         new LDAPToJavaSocketFactory(new TestLDAPSocketFactory());
    Socket s = f.createSocket(InetAddress.getByName(getTestHost()),
         getTestPort());
    s.close();
  }



  /**
   * Tests the ability to create a socket using a remote address and port.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidRemoteAddressPortWithSocketFactory()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPToJavaSocketFactory f = new LDAPToJavaSocketFactory(
         new JavaToLDAPSocketFactory(SocketFactory.getDefault()));
    Socket s = f.createSocket(InetAddress.getByName(getTestHost()),
         getTestPort());
    s.close();
  }



  /**
   * Tests the behavior when trying to connect to a port on which nothing is
   * listening.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testInvalidRemoteAddressPort()
         throws Exception
  {
    LDAPToJavaSocketFactory f =
         new LDAPToJavaSocketFactory(new TestLDAPSocketFactory());
    f.createSocket(InetAddress.getLocalHost(), unusedPort);
  }



  /**
   * Tests the ability to create a socket using an address and port, and local
   * address and port.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidRemoteAddressPortLocalAddressPort()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPToJavaSocketFactory f =
         new LDAPToJavaSocketFactory(new TestLDAPSocketFactory());
    Socket s = f.createSocket(InetAddress.getByName(getTestHost()),
         getTestPort(), InetAddress.getLocalHost(), 0);
    s.close();
  }



  /**
   * Tests the ability to create a socket using an address and port, and local
   * address and port.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidRemoteAddressPortLocalAddressPortWithSocketFactory()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPToJavaSocketFactory f = new LDAPToJavaSocketFactory(
         new JavaToLDAPSocketFactory(SocketFactory.getDefault()));
    Socket s = f.createSocket(InetAddress.getByName(getTestHost()),
         getTestPort(), InetAddress.getLocalHost(), 0);
    s.close();
  }



  /**
   * Tests the behavior when trying to connect to a port on which nothing is
   * listening.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testInvalidAddressPort()
         throws Exception
  {
    LDAPToJavaSocketFactory f =
         new LDAPToJavaSocketFactory(new TestLDAPSocketFactory());
    f.createSocket(InetAddress.getLocalHost(), unusedPort,
         InetAddress.getLocalHost(), 0);
  }
}
