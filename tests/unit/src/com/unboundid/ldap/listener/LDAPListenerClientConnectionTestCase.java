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



import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.util.TestInputStream;
import com.unboundid.util.TestOutputStream;
import com.unboundid.util.TestSocket;



/**
 * This class provides a set of test cases for the
 * {@code AccessLogRequestHandler} class.
 */
public final class LDAPListenerClientConnectionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when a client connection has been created without a
   * listener and with a socket that throws an exception when trying to get the
   * input stream.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testThrowOnGetInputStream()
         throws Exception
  {
    final TestSocket s = new TestSocket(
         new TestInputStream(new ByteArrayInputStream(new byte[1024]),
              new IOException("foo"), 100, true),
         new TestOutputStream(new ByteArrayOutputStream(),
              new IOException("bar"), 1024, true));
    s.setThrowOnGetInputStream(true);
    s.setThrowOnClose(true);

    new LDAPListenerClientConnection(null, s,
         new CannedResponseRequestHandler(), null);
  }



  /**
   * Tests the behavior when a client connection has been created without a
   * listener and with a socket that throws an exception when trying to get the
   * output stream.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testThrowOnGetOutputStream()
         throws Exception
  {
    final TestSocket s = new TestSocket(
         new TestInputStream(new ByteArrayInputStream(new byte[1024]),
              new IOException("foo"), 100, true),
         new TestOutputStream(new ByteArrayOutputStream(),
              new IOException("bar"), 1024, true));
    s.setThrowOnGetOutputStream(true);
    s.setThrowOnClose(true);

    new LDAPListenerClientConnection(null, s,
         new CannedResponseRequestHandler(), null);
  }



  /**
   * Tests the behavior when a client connection has been created without a
   * listener and with a request handler that throws an exception when trying to
   * create a new instance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testThrowOnNewRequestHandlerInstance()
         throws Exception
  {
    final TestSocket s = new TestSocket(
         new TestInputStream(new ByteArrayInputStream(new byte[1024]),
              new IOException("foo"), 100, true),
         new TestOutputStream(new ByteArrayOutputStream(),
              new IOException("bar"), 1024, true));
    s.setThrowOnClose(true);

    TestRequestHandler.setThrowOnNewInstance(true);

    try
    {
      new LDAPListenerClientConnection(null, s, new TestRequestHandler(), null);
    }
    finally
    {
      TestRequestHandler.setThrowOnNewInstance(false);
    }
  }



  /**
   * Tests the behavior when a client connection has been created without a
   * listener and with elements that throw exceptions on closure.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testThrowOnClose()
         throws Exception
  {
    final TestSocket s = new TestSocket(
         new TestInputStream(new ByteArrayInputStream(new byte[1024]),
              new IOException("foo"), 100, true),
         new TestOutputStream(new ByteArrayOutputStream(),
              new IOException("bar"), 1024, true));
    s.setThrowOnClose(true);

    final LDAPListenerClientConnection conn =
         new LDAPListenerClientConnection(null, s,
              new CannedResponseRequestHandler(),
              new TestLDAPListenerExceptionHandler());

    conn.removeSearchEntryTransformer(null);
    conn.removeSearchReferenceTransformer(null);
    conn.removeIntermediateResponseTransformer(null);

    conn.close(new LDAPException(ResultCode.LOCAL_ERROR, "foo"));
  }



  /**
   * Tests the behavior when the request handler throws an unexpected exception
   * in the course of processing a request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testThrowOnRequest()
         throws Exception
  {
    TestRequestHandler.setThrowOnProcessRequest(true);

    try
    {
      final LDAPListener listener = new LDAPListener(new LDAPListenerConfig(0,
           new TestRequestHandler()));
      listener.startListening();

      final LDAPConnection conn =
           new LDAPConnection("127.0.0.1", listener.getListenPort());

      final AddRequest addRequest = new AddRequest(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");
      assertResultCodeEquals(conn, addRequest, ResultCode.OTHER);

      final SimpleBindRequest bindRequest =
           new SimpleBindRequest("cn=Directory Manager", "password");
      assertResultCodeEquals(conn, bindRequest, ResultCode.OTHER);

      final CompareRequest compareRequest = new CompareRequest(
           "dc=example,dc=com", "foo", "bar");
      assertResultCodeEquals(conn, compareRequest, ResultCode.OTHER);

      final DeleteRequest deleteRequest =
           new DeleteRequest("dc=example,dc=com");
      assertResultCodeEquals(conn, deleteRequest, ResultCode.OTHER);

      final ExtendedRequest extendedRequest = new ExtendedRequest("1.2.3.4");
      assertResultCodeEquals(conn, extendedRequest, ResultCode.OTHER);

      final ModifyRequest modifyRequest = new ModifyRequest(
           "dn: dc=example,dc=com",
           "changeType: modify",
           "replace: description",
           "description: foo");
      assertResultCodeEquals(conn, modifyRequest, ResultCode.OTHER);

      final ModifyDNRequest modifyDNRequest = new ModifyDNRequest(
           "ou=People,dc=example,dc=com", "ou=Users", true);
      assertResultCodeEquals(conn, modifyDNRequest, ResultCode.OTHER);

      final SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
           SearchScope.BASE, "(objectClass=*)");
      assertResultCodeEquals(conn, searchRequest, ResultCode.OTHER);

      conn.close();
      listener.shutDown(true);
    }
    finally
    {
      TestRequestHandler.setThrowOnProcessRequest(false);
    }
  }
}
