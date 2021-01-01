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



import java.util.Arrays;
import java.util.logging.Level;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.AsyncRequestID;
import com.unboundid.ldap.sdk.EXTERNALBindRequest;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.MemoryBasedLogHandler;
import com.unboundid.util.MinimalLogFormatter;



/**
 * This class provides a set of test cases for the
 * {@code AccessLogRequestHandler} class.
 */
public final class AccessLogRequestHandlerTestCase
       extends LDAPSDKTestCase
{
  // The port on which the failure listener is waiting for connections.
  private int failurePort;

  // The port on which the success listener is waiting for connections.
  private int successPort;

  // The listener that was created to always return an error response.
  private LDAPListener failureListener;

  // The listener that was created to always return a successful response.
  private LDAPListener successListener;

  // The log handler that is being used.
  private MemoryBasedLogHandler logHandler;



  /**
   * Creates a new listener that will write log messages to an in-memory buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void createListener()
         throws Exception
  {
    logHandler = new MemoryBasedLogHandler();
    logHandler.setFormatter(new MinimalLogFormatter());
    logHandler.setLevel(Level.INFO);

    final CannedResponseRequestHandler successHandler =
         new CannedResponseRequestHandler();

    final LDAPListenerConfig successConfig = new LDAPListenerConfig(0,
         new AccessLogRequestHandler(logHandler, successHandler));

    successListener = new LDAPListener(successConfig);
    successListener.startListening();
    successPort = successListener.getListenPort();
    assertTrue(successPort > 0);

    final CannedResponseRequestHandler failureHandler =
         new CannedResponseRequestHandler(ResultCode.NO_SUCH_OBJECT,
              "dc=example,dc=com", "The target entry was not found",
              Arrays.asList("ldap://server1.example.com/dc=example,dc=com",
                   "ldap://server2.example.com/dc=example,dc=com"));

    final LDAPListenerConfig failureConfig = new LDAPListenerConfig(0,
         new AccessLogRequestHandler(logHandler, failureHandler));

    failureListener = new LDAPListener(failureConfig);
    failureListener.startListening();
    failurePort = failureListener.getListenPort();
    assertTrue(failurePort > 0);
  }



  /**
   * Shuts down the listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void shutDownListener()
         throws Exception
  {
    successListener.shutDown(true);
    failureListener.shutDown(true);
  }



  /**
   * Provides test coverage for an abandon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAbandon()
         throws Exception
  {
    logHandler.clear();

    final LDAPConnection conn = new LDAPConnection("127.0.0.1", successPort);
    waitForCount(1); // The CONNECT message.
    logHandler.clear();

    final AsyncRequestID requestID =
         InternalSDKHelper.createAsyncRequestID(1, conn);
    conn.abandon(requestID);
    waitForCount(1);

    final String[] messages = logHandler.getMessages(true);
    final String message = messages[0];
    assertTrue(message.contains(" ABANDON REQUEST "), message);
    assertTrue(message.contains(" idToAbandon=1"), message);

    conn.close();
    waitForCount(1); // The DISCONNECT message.
    logHandler.clear();
  }



  /**
   * Provides test coverage for a successful add operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddSuccessful()
         throws Exception
  {
    logHandler.clear();

    final LDAPConnection conn = new LDAPConnection("127.0.0.1", successPort);
    waitForCount(1); // The CONNECT message.
    logHandler.clear();

    conn.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    waitForCount(2);  // The request and response

    final String[] messages = logHandler.getMessages(true);

    final String requestMessage = messages[0];
    assertTrue(requestMessage.contains(" ADD REQUEST "), requestMessage);
    assertTrue(requestMessage.contains(" dn=\"dc=example,dc=com\""),
         requestMessage);

    final String responseMessage = messages[1];
    assertTrue(responseMessage.contains(" ADD RESULT "), responseMessage);
    assertTrue(responseMessage.contains(" resultCode=0"), responseMessage);
    assertTrue(responseMessage.contains(" etime="), responseMessage);
    assertFalse(responseMessage.contains(" matchedDN="), responseMessage);
    assertFalse(responseMessage.contains( "diagnosticMessage="),
         responseMessage);
    assertFalse(responseMessage.contains( "referralURLs="), responseMessage);

    conn.close();
    waitForCount(1); // The DISCONNECT message.
    logHandler.clear();
  }



  /**
   * Provides test coverage for a successful simple bind operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimpleBindSuccessful()
         throws Exception
  {
    logHandler.clear();

    final LDAPConnection conn = new LDAPConnection("127.0.0.1", successPort);
    waitForCount(1); // The CONNECT message.
    logHandler.clear();

    conn.bind("uid=admin,dc=example,dc=com", "password");

    waitForCount(2);  // The request and response

    final String[] messages = logHandler.getMessages(true);

    final String requestMessage = messages[0];
    assertTrue(requestMessage.contains(" BIND REQUEST "), requestMessage);
    assertTrue(requestMessage.contains(" version=3"), requestMessage);
    assertTrue(requestMessage.contains(" dn=\"uid=admin,dc=example,dc=com\""),
         requestMessage);
    assertTrue(requestMessage.contains(" authType=\"SIMPLE\""), requestMessage);

    final String responseMessage = messages[1];
    assertTrue(responseMessage.contains(" BIND RESULT "), responseMessage);
    assertTrue(responseMessage.contains(" resultCode=0"), responseMessage);
    assertTrue(responseMessage.contains(" etime="), responseMessage);
    assertFalse(responseMessage.contains( "matchedDN="), responseMessage);
    assertFalse(responseMessage.contains(" diagnosticMessage="),
         responseMessage);
    assertFalse(responseMessage.contains(" referralURLs="), responseMessage);

    conn.close();
    waitForCount(1); // The DISCONNECT message.
    logHandler.clear();
  }



  /**
   * Provides test coverage for a failed SASL EXTERNAL bind operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEXTERNALBindFailure()
         throws Exception
  {
    logHandler.clear();

    final LDAPConnection conn = new LDAPConnection("127.0.0.1", failurePort);
    waitForCount(1); // The CONNECT message.
    logHandler.clear();

    try
    {
      conn.bind(new EXTERNALBindRequest());
    }
    catch (final Exception e)
    {
      // This was expected.
    }

    waitForCount(2);  // The request and response

    final String[] messages = logHandler.getMessages(true);

    final String requestMessage = messages[0];
    assertTrue(requestMessage.contains(" BIND REQUEST "), requestMessage);
    assertTrue(requestMessage.contains(" version=3"), requestMessage);
    assertTrue(requestMessage.contains(" dn=\"\""), requestMessage);
    assertTrue(requestMessage.contains(" authType=\"SASL EXTERNAL\""),
         requestMessage);

    final String responseMessage = messages[1];
    assertTrue(responseMessage.contains(" BIND RESULT "), responseMessage);
    assertTrue(responseMessage.contains(" resultCode=32"), responseMessage);
    assertTrue(responseMessage.contains(" etime="), responseMessage);
    assertTrue(responseMessage.contains(" matchedDN="), responseMessage);
    assertTrue(responseMessage.contains(" diagnosticMessage="),
         responseMessage);
    assertTrue(responseMessage.contains(" referralURLs="), responseMessage);

    conn.close();
    waitForCount(1); // The DISCONNECT message.
    logHandler.clear();
  }



  /**
   * Provides test coverage for a failed compare operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareFailed()
         throws Exception
  {
    logHandler.clear();

    final LDAPConnection conn = new LDAPConnection("127.0.0.1", failurePort);
    waitForCount(1); // The CONNECT message.
    logHandler.clear();

    try
    {
      conn.compare("dc=example,dc=com", "foo", "bar");
    }
    catch (final Exception e)
    {
      // This was expected.
    }

    waitForCount(2);  // The request and response

    final String[] messages = logHandler.getMessages(true);

    final String requestMessage = messages[0];
    assertTrue(requestMessage.contains(" COMPARE REQUEST "), requestMessage);
    assertTrue(requestMessage.contains(" dn=\"dc=example,dc=com\""),
         requestMessage);
    assertTrue(requestMessage.contains(" attr=\"foo\""), requestMessage);

    final String responseMessage = messages[1];
    assertTrue(responseMessage.contains(" COMPARE RESULT "), responseMessage);
    assertTrue(responseMessage.contains(" resultCode=32"), responseMessage);
    assertTrue(responseMessage.contains(" etime="), responseMessage);
    assertTrue(responseMessage.contains(" matchedDN="), responseMessage);
    assertTrue(responseMessage.contains(" diagnosticMessage="),
         responseMessage);
    assertTrue(responseMessage.contains(" referralURLs="), responseMessage);

    conn.close();
    waitForCount(1); // The DISCONNECT message.
    logHandler.clear();
  }



  /**
   * Provides test coverage for a successful delete operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteSuccessful()
         throws Exception
  {
    logHandler.clear();

    final LDAPConnection conn = new LDAPConnection("127.0.0.1", successPort);
    waitForCount(1); // The CONNECT message.
    logHandler.clear();

    conn.delete("dc=example,dc=com");

    waitForCount(2);  // The request and response

    final String[] messages = logHandler.getMessages(true);

    final String requestMessage = messages[0];
    assertTrue(requestMessage.contains(" DELETE REQUEST "), requestMessage);
    assertTrue(requestMessage.contains(" dn=\"dc=example,dc=com\""),
         requestMessage);

    final String responseMessage = messages[1];
    assertTrue(responseMessage.contains(" DELETE RESULT "), responseMessage);
    assertTrue(responseMessage.contains(" resultCode=0"), responseMessage);
    assertTrue(responseMessage.contains(" etime="), responseMessage);
    assertFalse(responseMessage.contains(" matchedDN="), responseMessage);
    assertFalse(responseMessage.contains(" diagnosticMessage="),
         responseMessage);
    assertFalse(responseMessage.contains(" referralURLs="), responseMessage);

    conn.close();
    waitForCount(1); // The DISCONNECT message.
    logHandler.clear();
  }



  /**
   * Provides test coverage for a successful extended operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedSuccessful()
         throws Exception
  {
    logHandler.clear();

    final LDAPConnection conn = new LDAPConnection("127.0.0.1", successPort);
    waitForCount(1); // The CONNECT message.
    logHandler.clear();

    conn.processExtendedOperation("1.2.3.4");

    waitForCount(2);  // The request and response

    final String[] messages = logHandler.getMessages(true);

    final String requestMessage = messages[0];
    assertTrue(requestMessage.contains(" EXTENDED REQUEST "), requestMessage);
    assertTrue(requestMessage.contains(" requestOID=\"1.2.3.4\""),
         requestMessage);

    final String responseMessage = messages[1];
    assertTrue(responseMessage.contains(" EXTENDED RESULT "), responseMessage);
    assertTrue(responseMessage.contains(" resultCode=0"), responseMessage);
    assertTrue(responseMessage.contains(" etime="), responseMessage);
    assertFalse(responseMessage.contains(" matchedDN="), responseMessage);
    assertFalse(responseMessage.contains(" diagnosticMessage="),
         responseMessage);
    assertFalse(responseMessage.contains(" referralURLs="), responseMessage);

    conn.close();
    waitForCount(1); // The DISCONNECT message.
    logHandler.clear();
  }



  /**
   * Provides test coverage for a successful modify operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifySuccessful()
         throws Exception
  {
    logHandler.clear();

    final LDAPConnection conn = new LDAPConnection("127.0.0.1", successPort);
    waitForCount(1); // The CONNECT message.
    logHandler.clear();

    conn.modify(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");

    waitForCount(2);  // The request and response

    final String[] messages = logHandler.getMessages(true);

    final String requestMessage = messages[0];
    assertTrue(requestMessage.contains(" MODIFY REQUEST "), requestMessage);
    assertTrue(requestMessage.contains(" dn=\"dc=example,dc=com\""),
         requestMessage);

    final String responseMessage = messages[1];
    assertTrue(responseMessage.contains(" MODIFY RESULT "), responseMessage);
    assertTrue(responseMessage.contains(" resultCode=0"), responseMessage);
    assertTrue(responseMessage.contains(" etime="), responseMessage);
    assertFalse(responseMessage.contains(" matchedDN="), responseMessage);
    assertFalse(responseMessage.contains(" diagnosticMessage="),
         responseMessage);
    assertFalse(responseMessage.contains(" referralURLs="), responseMessage);

    conn.close();
    waitForCount(1); // The DISCONNECT message.
    logHandler.clear();
  }



  /**
   * Provides test coverage for a successful modify DN operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNSuccessful()
         throws Exception
  {
    logHandler.clear();

    final LDAPConnection conn = new LDAPConnection("127.0.0.1", successPort);
    waitForCount(1); // The CONNECT message.
    logHandler.clear();

    conn.modifyDN("ou=People,dc=example,dc=com", "ou=Users", true,
         "o=example.com");

    waitForCount(2);  // The request and response

    final String[] messages = logHandler.getMessages(true);

    final String requestMessage = messages[0];
    assertTrue(requestMessage.contains(" MODDN REQUEST "), requestMessage);
    assertTrue(requestMessage.contains(" dn=\"ou=People,dc=example,dc=com\""),
         requestMessage);
    assertTrue(requestMessage.contains(" newRDN=\"ou=Users\""), requestMessage);
    assertTrue(requestMessage.contains(" deleteOldRDN=true"), requestMessage);
    assertTrue(requestMessage.contains(" newSuperior=\"o=example.com\""),
         requestMessage);

    final String responseMessage = messages[1];
    assertTrue(responseMessage.contains(" MODDN RESULT "), responseMessage);
    assertTrue(responseMessage.contains(" resultCode=0"), responseMessage);
    assertTrue(responseMessage.contains(" etime="), responseMessage);
    assertFalse(responseMessage.contains(" matchedDN="), responseMessage);
    assertFalse(responseMessage.contains(" diagnosticMessage="),
         responseMessage);
    assertFalse(responseMessage.contains(" referralURLs="), responseMessage);

    conn.close();
    waitForCount(1); // The DISCONNECT message.
    logHandler.clear();
  }



  /**
   * Provides test coverage for a successful search operation that does not
   * match any entries and does not include any requested attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchSuccessfulNoEntriesNoRequestAttrs()
         throws Exception
  {
    logHandler.clear();

    final LDAPConnection conn = new LDAPConnection("127.0.0.1", successPort);
    waitForCount(1); // The CONNECT message.
    logHandler.clear();

    conn.search("dc=example,dc=com", SearchScope.SUB, "(uid=john.doe)");

    waitForCount(2);  // The request and response

    final String[] messages = logHandler.getMessages(true);

    final String requestMessage = messages[0];
    assertTrue(requestMessage.contains(" SEARCH REQUEST "), requestMessage);
    assertTrue(requestMessage.contains(" base=\"dc=example,dc=com\""),
         requestMessage);
    assertTrue(requestMessage.contains(" scope=2"), requestMessage);
    assertTrue(requestMessage.contains(" filter=\"(uid=john.doe)\""),
         requestMessage);
    assertTrue(requestMessage.contains(" attrs=\"ALL\""), requestMessage);

    final String responseMessage = messages[1];
    assertTrue(responseMessage.contains(" SEARCH RESULT "), responseMessage);
    assertTrue(responseMessage.contains(" resultCode=0"), responseMessage);
    assertTrue(responseMessage.contains(" etime="), responseMessage);
    assertFalse(responseMessage.contains(" matchedDN="), responseMessage);
    assertFalse(responseMessage.contains(" diagnosticMessage="),
         responseMessage);
    assertFalse(responseMessage.contains(" referralURLs="), responseMessage);
    assertTrue(responseMessage.contains(" entriesReturned=0"), responseMessage);

    conn.close();
    waitForCount(1); // The DISCONNECT message.
    logHandler.clear();
  }



  /**
   * Provides test coverage for a failed search operation includes requested
   * attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchFailureWithRequestAttrs()
         throws Exception
  {
    logHandler.clear();

    final LDAPConnection conn = new LDAPConnection("127.0.0.1", failurePort);
    waitForCount(1); // The CONNECT message.
    logHandler.clear();

    try
    {
      conn.search("dc=example,dc=com", SearchScope.SUB, "(uid=john.doe)", "*",
           "+");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    waitForCount(2);  // The request and response

    final String[] messages = logHandler.getMessages(true);

    final String requestMessage = messages[0];
    assertTrue(requestMessage.contains(" SEARCH REQUEST "), requestMessage);
    assertTrue(requestMessage.contains(" base=\"dc=example,dc=com\""),
         requestMessage);
    assertTrue(requestMessage.contains(" scope=2"), requestMessage);
    assertTrue(requestMessage.contains(" filter=\"(uid=john.doe)\""),
         requestMessage);
    assertTrue(requestMessage.contains(" attrs=\"*,+\""), requestMessage);

    final String responseMessage = messages[1];
    assertTrue(responseMessage.contains(" SEARCH RESULT "), responseMessage);
    assertTrue(responseMessage.contains(" resultCode=32"), responseMessage);
    assertTrue(responseMessage.contains(" etime="), responseMessage);
    assertTrue(responseMessage.contains(" matchedDN="), responseMessage);
    assertTrue(responseMessage.contains(" diagnosticMessage="),
         responseMessage);
    assertTrue(responseMessage.contains(" referralURLs="), responseMessage);
    assertTrue(responseMessage.contains(" entriesReturned=0"), responseMessage);

    conn.close();
    waitForCount(1); // The DISCONNECT message.
    logHandler.clear();
  }



  /**
   * Waits for the available message count to be greater than or equal to the
   * provided value.
   *
   * @param  count  The minimum count to require.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private void waitForCount(final int count)
          throws Exception
  {
    while (true)
    {
      final int size = logHandler.size();
      if (size >= count)
      {
        return;
      }

      Thread.sleep(1);
    }
  }
}
