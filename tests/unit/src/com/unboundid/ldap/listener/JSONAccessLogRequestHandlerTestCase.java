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



import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for the
 * {@code JSONAccessLogRequestHandler} class.
 */
public final class JSONAccessLogRequestHandlerTestCase
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
    logHandler.setFormatter(new MinimalLogFormatter(null, false, false, false));
    logHandler.setLevel(Level.INFO);

    final CannedResponseRequestHandler successHandler =
         new CannedResponseRequestHandler();

    final LDAPListenerConfig successConfig = new LDAPListenerConfig(0,
         new JSONAccessLogRequestHandler(logHandler, successHandler));

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
         new JSONAccessLogRequestHandler(logHandler, failureHandler));

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
    waitForCount(1); // The connect message.
    List<JSONObject> logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 1);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "connect");

    logHandler.clear();

    final AsyncRequestID requestID =
         InternalSDKHelper.createAsyncRequestID(1, conn);
    conn.abandon(requestID);
    waitForCount(1);

    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 1);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "abandon");
    assertEquals(
         logMessages.get(0).getFieldAsInteger("id-to-abandon").intValue(), 1);

    conn.close();
    waitForCount(2); // The unbind and disconnect messages.
    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 2);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "unbind");

    assertEquals(logMessages.get(1).getFieldAsString("message-type"),
         "disconnect");
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
    waitForCount(1); // The connect message.
    List<JSONObject> logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 1);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "connect");

    conn.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    waitForCount(2);  // The request and response

    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 2);

    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "add");
    assertEquals(logMessages.get(0).getFieldAsString("dn"),
         "dc=example,dc=com");

    assertEquals(logMessages.get(1).getFieldAsString("message-type"),
         "response");
    assertEquals(logMessages.get(1).getFieldAsString("operation-type"),
         "add");
    assertEquals(
         logMessages.get(1).getFieldAsInteger("result-code-value").intValue(),
         0);
    assertFalse(logMessages.get(1).hasField("diagnostic-message"));
    assertFalse(logMessages.get(1).hasField("matched-dn"));
    assertFalse(logMessages.get(1).hasField("referral-urls"));

    conn.close();
    waitForCount(2); // The unbind and disconnect messages.
    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 2);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "unbind");

    assertEquals(logMessages.get(1).getFieldAsString("message-type"),
         "disconnect");
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
    waitForCount(1); // The connect message.
    List<JSONObject> logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 1);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "connect");

    conn.bind("uid=admin,dc=example,dc=com", "password");

    waitForCount(2);  // The request and response

    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 2);

    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "bind");
    assertEquals(logMessages.get(0).getFieldAsString("dn"),
         "uid=admin,dc=example,dc=com");
    assertEquals(logMessages.get(0).getFieldAsString("authentication-type"),
         "simple");

    assertEquals(logMessages.get(1).getFieldAsString("message-type"),
         "response");
    assertEquals(logMessages.get(1).getFieldAsString("operation-type"),
         "bind");
    assertEquals(
         logMessages.get(1).getFieldAsInteger("result-code-value").intValue(),
         0);
    assertFalse(logMessages.get(1).hasField("diagnostic-message"));
    assertFalse(logMessages.get(1).hasField("matched-dn"));
    assertFalse(logMessages.get(1).hasField("referral-urls"));

    conn.close();
    waitForCount(2); // The unbind and disconnect messages.
    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 2);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "unbind");

    assertEquals(logMessages.get(1).getFieldAsString("message-type"),
         "disconnect");
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
    waitForCount(1); // The connect message.
    List<JSONObject> logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 1);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "connect");

    try
    {
      conn.bind(new EXTERNALBindRequest());
    }
    catch (final Exception e)
    {
      // This was expected.
    }

    waitForCount(2);  // The request and response

    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 2);

    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "bind");
    assertEquals(logMessages.get(0).getFieldAsString("dn"), "");
    assertEquals(logMessages.get(0).getFieldAsString("authentication-type"),
         "sasl");
    assertEquals(logMessages.get(0).getFieldAsString("sasl-mechanism"),
         "EXTERNAL");

    assertEquals(logMessages.get(1).getFieldAsString("message-type"),
         "response");
    assertEquals(logMessages.get(1).getFieldAsString("operation-type"),
         "bind");
    assertEquals(
         logMessages.get(1).getFieldAsInteger("result-code-value").intValue(),
         32);
    assertTrue(logMessages.get(1).hasField("diagnostic-message"));
    assertTrue(logMessages.get(1).hasField("matched-dn"));
    assertTrue(logMessages.get(1).hasField("referral-urls"));

    conn.close();
    waitForCount(2); // The unbind and disconnect messages.
    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 2);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "unbind");

    assertEquals(logMessages.get(1).getFieldAsString("message-type"),
         "disconnect");
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
    waitForCount(1); // The connect message.
    List<JSONObject> logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 1);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "connect");

    try
    {
      conn.compare("dc=example,dc=com", "foo", "bar");
    }
    catch (final Exception e)
    {
      // This was expected.
    }

    waitForCount(2);  // The request and response

    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 2);

    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "compare");
    assertEquals(logMessages.get(0).getFieldAsString("dn"),
         "dc=example,dc=com");
    assertEquals(logMessages.get(0).getFieldAsString("attribute-type"), "foo");

    assertEquals(logMessages.get(1).getFieldAsString("message-type"),
         "response");
    assertEquals(logMessages.get(1).getFieldAsString("operation-type"),
         "compare");
    assertEquals(
         logMessages.get(1).getFieldAsInteger("result-code-value").intValue(),
         32);
    assertTrue(logMessages.get(1).hasField("diagnostic-message"));
    assertTrue(logMessages.get(1).hasField("matched-dn"));
    assertTrue(logMessages.get(1).hasField("referral-urls"));

    conn.close();
    waitForCount(2); // The unbind and disconnect messages.
    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 2);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "unbind");

    assertEquals(logMessages.get(1).getFieldAsString("message-type"),
         "disconnect");
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
    waitForCount(1); // The connect message.
    List<JSONObject> logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 1);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "connect");

    conn.delete("dc=example,dc=com");

    waitForCount(2);  // The request and response

    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 2);

    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "delete");
    assertEquals(logMessages.get(0).getFieldAsString("dn"),
         "dc=example,dc=com");

    assertEquals(logMessages.get(1).getFieldAsString("message-type"),
         "response");
    assertEquals(logMessages.get(1).getFieldAsString("operation-type"),
         "delete");
    assertEquals(
         logMessages.get(1).getFieldAsInteger("result-code-value").intValue(),
         0);
    assertFalse(logMessages.get(1).hasField("diagnostic-message"));
    assertFalse(logMessages.get(1).hasField("matched-dn"));
    assertFalse(logMessages.get(1).hasField("referral-urls"));

    conn.close();
    waitForCount(2); // The unbind and disconnect messages.
    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 2);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "unbind");

    assertEquals(logMessages.get(1).getFieldAsString("message-type"),
         "disconnect");
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
    waitForCount(1); // The connect message.
    List<JSONObject> logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 1);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "connect");

    conn.processExtendedOperation("1.2.3.4");

    waitForCount(2);  // The request and response

    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 2);

    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "extended");
    assertEquals(logMessages.get(0).getFieldAsString("request-oid"), "1.2.3.4");

    assertEquals(logMessages.get(1).getFieldAsString("message-type"),
         "response");
    assertEquals(logMessages.get(1).getFieldAsString("operation-type"),
         "extended");
    assertEquals(
         logMessages.get(1).getFieldAsInteger("result-code-value").intValue(),
         0);
    assertFalse(logMessages.get(1).hasField("diagnostic-message"));
    assertFalse(logMessages.get(1).hasField("matched-dn"));
    assertFalse(logMessages.get(1).hasField("referral-urls"));

    conn.close();
    waitForCount(2); // The unbind and disconnect messages.
    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 2);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "unbind");

    assertEquals(logMessages.get(1).getFieldAsString("message-type"),
         "disconnect");
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
    waitForCount(1); // The connect message.
    List<JSONObject> logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 1);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "connect");

    conn.modify(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");

    waitForCount(2);  // The request and response

    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 2);

    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "modify");
    assertEquals(logMessages.get(0).getFieldAsString("dn"),
         "dc=example,dc=com");

    assertEquals(logMessages.get(1).getFieldAsString("message-type"),
         "response");
    assertEquals(logMessages.get(1).getFieldAsString("operation-type"),
         "modify");
    assertEquals(
         logMessages.get(1).getFieldAsInteger("result-code-value").intValue(),
         0);
    assertFalse(logMessages.get(1).hasField("diagnostic-message"));
    assertFalse(logMessages.get(1).hasField("matched-dn"));
    assertFalse(logMessages.get(1).hasField("referral-urls"));

    conn.close();
    waitForCount(2); // The unbind and disconnect messages.
    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 2);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "unbind");

    assertEquals(logMessages.get(1).getFieldAsString("message-type"),
         "disconnect");
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
    waitForCount(1); // The connect message.
    List<JSONObject> logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 1);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "connect");

    conn.modifyDN("ou=People,dc=example,dc=com", "ou=Users", true,
         "o=example.com");

    waitForCount(2);  // The request and response

    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 2);

    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "modify-dn");
    assertEquals(logMessages.get(0).getFieldAsString("dn"),
         "ou=People,dc=example,dc=com");
    assertEquals(logMessages.get(0).getFieldAsString("new-rdn"),
         "ou=Users");
    assertTrue(logMessages.get(0).getFieldAsBoolean("delete-old-rdn"));
    assertEquals(logMessages.get(0).getFieldAsString("new-superior"),
         "o=example.com");

    assertEquals(logMessages.get(1).getFieldAsString("message-type"),
         "response");
    assertEquals(logMessages.get(1).getFieldAsString("operation-type"),
         "modify-dn");
    assertEquals(
         logMessages.get(1).getFieldAsInteger("result-code-value").intValue(),
         0);
    assertFalse(logMessages.get(1).hasField("diagnostic-message"));
    assertFalse(logMessages.get(1).hasField("matched-dn"));
    assertFalse(logMessages.get(1).hasField("referral-urls"));

    conn.close();
    waitForCount(2); // The unbind and disconnect messages.
    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 2);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "unbind");

    assertEquals(logMessages.get(1).getFieldAsString("message-type"),
         "disconnect");
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
    waitForCount(1); // The connect message.
    List<JSONObject> logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 1);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "connect");

    conn.search("dc=example,dc=com", SearchScope.SUB, "(uid=john.doe)");

    waitForCount(2);  // The request and response

    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 2);

    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "search");
    assertEquals(logMessages.get(0).getFieldAsString("base"),
         "dc=example,dc=com");
    assertEquals(logMessages.get(0).getFieldAsInteger("scope").intValue(), 2);
    assertEquals(logMessages.get(0).getFieldAsString("filter"),
         "(uid=john.doe)");
    assertTrue(logMessages.get(0).hasField("requested-attributes"));

    assertEquals(logMessages.get(1).getFieldAsString("message-type"),
         "response");
    assertEquals(logMessages.get(1).getFieldAsString("operation-type"),
         "search");
    assertEquals(
         logMessages.get(1).getFieldAsInteger("result-code-value").intValue(),
         0);
    assertFalse(logMessages.get(1).hasField("diagnostic-message"));
    assertFalse(logMessages.get(1).hasField("matched-dn"));
    assertFalse(logMessages.get(1).hasField("referral-urls"));
    assertEquals(
         logMessages.get(1).getFieldAsInteger("entries-returned").intValue(),
         0);

    conn.close();
    waitForCount(2); // The unbind and disconnect messages.
    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 2);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "unbind");

    assertEquals(logMessages.get(1).getFieldAsString("message-type"),
         "disconnect");
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
    waitForCount(1); // The connect message.
    List<JSONObject> logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 1);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "connect");

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

    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 2);

    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "search");
    assertEquals(logMessages.get(0).getFieldAsString("base"),
         "dc=example,dc=com");
    assertEquals(logMessages.get(0).getFieldAsInteger("scope").intValue(), 2);
    assertEquals(logMessages.get(0).getFieldAsString("filter"),
         "(uid=john.doe)");
    assertTrue(logMessages.get(0).hasField("requested-attributes"));

    assertEquals(logMessages.get(1).getFieldAsString("message-type"),
         "response");
    assertEquals(logMessages.get(1).getFieldAsString("operation-type"),
         "search");
    assertEquals(
         logMessages.get(1).getFieldAsInteger("result-code-value").intValue(),
         32);
    assertTrue(logMessages.get(1).hasField("diagnostic-message"));
    assertTrue(logMessages.get(1).hasField("matched-dn"));
    assertTrue(logMessages.get(1).hasField("referral-urls"));
    assertEquals(
         logMessages.get(1).getFieldAsInteger("entries-returned").intValue(),
         0);

    conn.close();
    waitForCount(2); // The unbind and disconnect messages.
    logMessages = getLogMessageObjects();
    assertEquals(logMessages.size(), 2);
    assertEquals(logMessages.get(0).getFieldAsString("message-type"),
         "request");
    assertEquals(logMessages.get(0).getFieldAsString("operation-type"),
         "unbind");

    assertEquals(logMessages.get(1).getFieldAsString("message-type"),
         "disconnect");
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



  /**
   * Reads the logged messages as JSON objects.  Note that this will clear the
   * set of messages so that a subsequent call will not return any of the
   * messages from the previous call.
   *
   * @return  The logged messages as JSON objects.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private List<JSONObject> getLogMessageObjects()
          throws Exception
  {
    final List<JSONObject> messageObjects = new ArrayList<>();
    for (final String messageString : logHandler.getMessages(true))
    {
      final JSONObject messageObject = new JSONObject(messageString);
      assertTrue(messageObject.hasField("timestamp"));
      assertTrue(messageObject.hasField("message-type"));
      assertTrue(messageObject.hasField("connection-id"));

      messageObjects.add(messageObject);
    }

    return messageObjects;
  }
}
