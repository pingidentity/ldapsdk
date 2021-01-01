/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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



import org.testng.annotations.Test;

import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for SASL authentication that uses
 * quality of protection to secure communication.
 */
public final class SASLAuthenticationWithQoPTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of a SASL bind that uses the auth QoP.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithAuth()
         throws Exception
  {
    // Create and start the test server.
    final UNBOUNDIDTESTServer testServer = new UNBOUNDIDTESTServer();
    testServer.start();

    try
    {
      int listenPort;
      while (true)
      {
        listenPort = testServer.getListenPort();
        if (listenPort > 0)
        {
          break;
        }
        else
        {
          Thread.sleep(1);
        }
      }

      final LDAPConnection conn = new LDAPConnection("localhost", listenPort);

      final BindResult bindResult = conn.bind(new UNBOUNDIDTESTBindRequest("",
           StaticUtils.NO_BYTES, SASLQualityOfProtection.AUTH));
      assertResultCodeEquals(bindResult, ResultCode.SUCCESS);

      final SearchResult searchResult = conn.search("", SearchScope.BASE,
           "(objectClass=*)", "1.1");
      assertResultCodeEquals(searchResult, ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);

      conn.close();
    }
    finally
    {
      testServer.stopServer();
    }
  }



  /**
   * Tests the behavior of a SASL bind that uses the auth-int QoP.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithAuthInt()
         throws Exception
  {
    // Create and start the test server.
    final UNBOUNDIDTESTServer testServer = new UNBOUNDIDTESTServer();
    testServer.start();

    try
    {
      int listenPort;
      while (true)
      {
        listenPort = testServer.getListenPort();
        if (listenPort > 0)
        {
          break;
        }
        else
        {
          Thread.sleep(1);
        }
      }

      final LDAPConnection conn = new LDAPConnection("localhost", listenPort);

      final BindResult bindResult = conn.bind(new UNBOUNDIDTESTBindRequest("",
           StaticUtils.NO_BYTES, SASLQualityOfProtection.AUTH_INT));
      assertResultCodeEquals(bindResult, ResultCode.SUCCESS);

      final SearchResult searchResult = conn.search("", SearchScope.BASE,
           "(objectClass=*)", "1.1");
      assertResultCodeEquals(searchResult, ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);

      conn.close();
    }
    finally
    {
      testServer.stopServer();
    }
  }



  /**
   * Tests the behavior of a SASL bind that uses the auth-conf QoP.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithAuthConf()
         throws Exception
  {
    // Create and start the test server.
    final UNBOUNDIDTESTServer testServer = new UNBOUNDIDTESTServer();
    testServer.start();

    try
    {
      int listenPort;
      while (true)
      {
        listenPort = testServer.getListenPort();
        if (listenPort > 0)
        {
          break;
        }
        else
        {
          Thread.sleep(1);
        }
      }

      final LDAPConnection conn = new LDAPConnection("localhost", listenPort);

      final BindResult bindResult = conn.bind(new UNBOUNDIDTESTBindRequest("",
           StaticUtils.NO_BYTES, SASLQualityOfProtection.AUTH_CONF));
      assertResultCodeEquals(bindResult, ResultCode.SUCCESS);

      final SearchResult searchResult = conn.search("", SearchScope.BASE,
           "(objectClass=*)", "1.1");
      assertResultCodeEquals(searchResult, ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);

      conn.close();
    }
    finally
    {
      testServer.stopServer();
    }
  }
}
