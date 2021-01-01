/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the SynchronizedSocketFactory
 * class.
 */
public final class SynchronizedSocketFactoryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the createSocket method that takes string and
   * int arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateDisconnectedSocketStringInt()
         throws Exception
  {
    final SynchronizedSocketFactory f =
         new SynchronizedSocketFactory(new DisconnectedSocketFactory());

    assertNotNull(f.getWrappedSocketFactory());

    final Socket s = f.createSocket("127.0.0.1", 389);
    assertNotNull(s);
    assertFalse(s.isConnected());
  }



  /**
   * Provides test coverage for the createSocket method that takes string, int,
   * InetAddress, and int arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateDisconnectedSocketStringIntInetAddressInt()
         throws Exception
  {
    final SynchronizedSocketFactory f =
         new SynchronizedSocketFactory(new DisconnectedSocketFactory());

    assertNotNull(f.getWrappedSocketFactory());

    final Socket s =
         f.createSocket("127.0.0.1", 389, InetAddress.getLocalHost(), 1234);
    assertNotNull(s);
    assertFalse(s.isConnected());
  }



  /**
   * Provides test coverage for the createSocket method that takes InetAddress
   * and int arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateDisconnectedSocketInetAddressInt()
         throws Exception
  {
    final SynchronizedSocketFactory f =
         new SynchronizedSocketFactory(new DisconnectedSocketFactory());

    assertNotNull(f.getWrappedSocketFactory());

    final Socket s = f.createSocket(InetAddress.getLocalHost(), 389);
    assertNotNull(s);
    assertFalse(s.isConnected());
  }



  /**
   * Provides test coverage for the createSocket method that takes InetAddress,
   * int, InetAddress, and int arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateDisconnectedSocketInetAddressIntInetAddressInt()
         throws Exception
  {
    final SynchronizedSocketFactory f =
         new SynchronizedSocketFactory(new DisconnectedSocketFactory());

    assertNotNull(f.getWrappedSocketFactory());

    final Socket s = f.createSocket(InetAddress.getLocalHost(), 389,
         InetAddress.getLocalHost(), 1234);
    assertNotNull(s);
    assertFalse(s.isConnected());
  }



  /**
   * Provides test coverage for the createSocket method that takes string and
   * int arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testCreateExceptionSocketStringInt()
         throws Exception
  {
    final SynchronizedSocketFactory f =
         new SynchronizedSocketFactory(new ExceptionSocketFactory());

    assertNotNull(f.getWrappedSocketFactory());

    f.createSocket("127.0.0.1", 389);
  }



  /**
   * Provides test coverage for the createSocket method that takes string, int,
   * InetAddress, and int arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testCreateExceptionSocketStringIntInetAddressInt()
         throws Exception
  {
    final SynchronizedSocketFactory f =
         new SynchronizedSocketFactory(new ExceptionSocketFactory());

    assertNotNull(f.getWrappedSocketFactory());

    f.createSocket("127.0.0.1", 389, InetAddress.getLocalHost(), 1234);
  }



  /**
   * Provides test coverage for the createSocket method that takes InetAddress
   * and int arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testCreateExceptionSocketInetAddressInt()
         throws Exception
  {
    final SynchronizedSocketFactory f =
         new SynchronizedSocketFactory(new ExceptionSocketFactory());

    assertNotNull(f.getWrappedSocketFactory());

    f.createSocket(InetAddress.getLocalHost(), 389);
  }



  /**
   * Provides test coverage for the createSocket method that takes InetAddress,
   * int, InetAddress, and int arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testCreateExceptionSocketInetAddressIntInetAddressInt()
         throws Exception
  {
    final SynchronizedSocketFactory f =
         new SynchronizedSocketFactory(new ExceptionSocketFactory());

    assertNotNull(f.getWrappedSocketFactory());

    f.createSocket(InetAddress.getLocalHost(), 389, InetAddress.getLocalHost(),
         1234);
  }
}
