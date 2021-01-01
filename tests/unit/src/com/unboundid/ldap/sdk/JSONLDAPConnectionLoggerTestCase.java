/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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



import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.TestIntermediateResponseExtendedOperationHandler;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.TestLogHandler;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONObjectReader;



/**
 * This class provides a set of test cases for hte JSON LDAP connection logger.
 */
public final class JSONLDAPConnectionLoggerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the getter methods with all the default property values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetterMethodsDefaults()
         throws Exception
  {
    final TestLogHandler logHandler = new TestLogHandler();

    final JSONLDAPConnectionLoggerProperties properties =
         new JSONLDAPConnectionLoggerProperties();
    final JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(logHandler, properties);

    assertTrue(logger.logConnects());
    assertTrue(logger.logDisconnects());
    assertTrue(logger.logRequests());
    assertTrue(logger.logFinalResults());
    assertFalse(logger.logSearchEntries());
    assertFalse(logger.logSearchReferences());
    assertTrue(logger.logIntermediateResponses());

    assertNotNull(logger.getOperationTypes());
    assertFalse(logger.getOperationTypes().isEmpty());
    assertEquals(logger.getOperationTypes(),
         EnumSet.allOf(OperationType.class));

    assertTrue(logger.includeAddAttributeNames());
    assertFalse(logger.includeAddAttributeValues());

    assertTrue(logger.includeModifyAttributeNames());
    assertFalse(logger.includeModifyAttributeValues());

    assertTrue(logger.includeSearchEntryAttributeNames());
    assertFalse(logger.includeSearchEntryAttributeValues());

    assertNotNull(logger.getAttributesToRedact());
    assertFalse(logger.getAttributesToRedact().isEmpty());
    assertEquals(logger.getAttributesToRedact(),
         StaticUtils.setOf("userPassword", "authPassword", "unicodePwd"));

    assertTrue(logger.includeControlOIDs());

    assertNotNull(logger.getSchema());

    assertTrue(logger.flushAfterConnectMessages());
    assertTrue(logger.flushAfterDisconnectMessages());
    assertFalse(logger.flushAfterRequestMessages());
    assertTrue(logger.flushAfterFinalResultMessages());
    assertFalse(logger.flushAfterNonFinalResultMessages());
  }



  /**
   * Tests the getter methods with all non-default property values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetterMethodsNonDefaults()
         throws Exception
  {
    final TestLogHandler logHandler = new TestLogHandler();

    final JSONLDAPConnectionLoggerProperties properties =
         new JSONLDAPConnectionLoggerProperties();
    properties.setLogConnects(false);
    properties.setLogDisconnects(false);
    properties.setLogRequests(false);
    properties.setLogFinalResults(false);
    properties.setLogSearchEntries(true);
    properties.setLogSearchReferences(true);
    properties.setLogIntermediateResponses(false);
    properties.setOperationTypes();
    properties.setIncludeAddAttributeNames(false);
    properties.setIncludeAddAttributeValues(true);
    properties.setIncludeModifyAttributeNames(false);
    properties.setIncludeModifyAttributeValues(true);
    properties.setIncludeSearchEntryAttributeNames(false);
    properties.setIncludeSearchEntryAttributeValues(true);
    properties.setAttributesToRedact();
    properties.setIncludeControlOIDs(false);
    properties.setSchema(null);
    properties.setFlushAfterConnectMessages(false);
    properties.setFlushAfterDisconnectMessages(false);
    properties.setFlushAfterRequestMessages(true);
    properties.setFlushAfterFinalResultMessages(false);
    properties.setFlushAfterNonFinalResultMessages(true);

    final JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(logHandler, properties);

    assertFalse(logger.logConnects());
    assertFalse(logger.logDisconnects());
    assertFalse(logger.logRequests());
    assertFalse(logger.logFinalResults());
    assertTrue(logger.logSearchEntries());
    assertTrue(logger.logSearchReferences());
    assertFalse(logger.logIntermediateResponses());

    assertNotNull(logger.getOperationTypes());
    assertTrue(logger.getOperationTypes().isEmpty());

    assertFalse(logger.includeAddAttributeNames());
    assertTrue(logger.includeAddAttributeValues());

    assertFalse(logger.includeModifyAttributeNames());
    assertTrue(logger.includeModifyAttributeValues());

    assertFalse(logger.includeSearchEntryAttributeNames());
    assertTrue(logger.includeSearchEntryAttributeValues());

    assertNotNull(logger.getAttributesToRedact());
    assertTrue(logger.getAttributesToRedact().isEmpty());

    assertFalse(logger.includeControlOIDs());

    assertNull(logger.getSchema());

    assertFalse(logger.flushAfterConnectMessages());
    assertFalse(logger.flushAfterDisconnectMessages());
    assertTrue(logger.flushAfterRequestMessages());
    assertFalse(logger.flushAfterFinalResultMessages());
    assertTrue(logger.flushAfterNonFinalResultMessages());
  }



  /**
   * Tests the behavior when a connection attempt fails.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailedConnectionLogging()
         throws Exception
  {
    // Get the in-memory directory server instance and shut it down.
    final InMemoryDirectoryServer ds = getTestDS();
    final int port = ds.getListenPort();
    ds.shutDown(true);

    try
    {
      // Create a logger to use for the test.
      final TestLogHandler logHandler = new TestLogHandler();

      final JSONLDAPConnectionLoggerProperties properties =
           new JSONLDAPConnectionLoggerProperties();
      final JSONLDAPConnectionLogger logger =
           new JSONLDAPConnectionLogger(logHandler, properties);

      final LDAPConnectionOptions options = new LDAPConnectionOptions();
      options.setConnectionLogger(logger);


      // Try and fail to establish a connection to the offline server.
      try (LDAPConnection connection =
                new LDAPConnection(options, "localhost", port))
      {
        assertFalse(connection.isConnected());
        fail("Unexpectedly connected to an offline server");
      }
      catch (final LDAPException e)
      {
        // This was expected.
      }


      // Make sure that there was one log message, and that it was a
      // connect failure message.
      assertEquals(logHandler.getMessageCount(), 1);

      final List<JSONObject> logMessages = parseLogMessages(logHandler);
      assertMessageIs(logMessages.get(0), "connect-failure", null);
    }
    finally
    {
      ds.startListening();
    }
  }



  /**
   * Tests the behavior when logging abandon requests.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAbandonLogging()
         throws Exception
  {
    // Get the in-memory directory server instance.
    final InMemoryDirectoryServer ds = getTestDS();


    // Create a logger to use for the test.
    final TestLogHandler logHandler = new TestLogHandler();

    final JSONLDAPConnectionLoggerProperties properties =
         new JSONLDAPConnectionLoggerProperties();
    final JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(logHandler, properties);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);


    // Establish a connection and send an abandon request on it.
    try (LDAPConnection connection =
              new LDAPConnection(options, "localhost", ds.getListenPort()))
    {
      connection.abandon(1);
    }


    // Make sure that there were four log messages:
    // - Connect
    // - Abandon
    // - Unbind
    // - Disconnect
    assertEquals(logHandler.getMessageCount(), 4,
         logHandler.getMessagesString());

    final List<JSONObject> logMessages = parseLogMessages(logHandler);
    assertMessageIs(logMessages.get(0), "connect", null);
    assertMessageIs(logMessages.get(1), "request", OperationType.ABANDON);
    assertMessageIs(logMessages.get(2), "request", OperationType.UNBIND);
    assertMessageIs(logMessages.get(3), "disconnect", null);
  }



  /**
   * Tests the behavior when logging add operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddLogging()
         throws Exception
  {
    // Get the in-memory directory server instance.
    final InMemoryDirectoryServer ds = getTestDS();


    // Create a logger to use for the test.
    final TestLogHandler logHandler = new TestLogHandler();

    final JSONLDAPConnectionLoggerProperties properties =
         new JSONLDAPConnectionLoggerProperties();
    final JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(logHandler, properties);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);


    // Establish a connection and send an add request on it.
    try (LDAPConnection connection =
              new LDAPConnection(options, "localhost", ds.getListenPort()))
    {
      connection.add(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");
    }


    // Make sure that there were five log messages:
    // - Connect
    // - Add request
    // - Add result
    // - Unbind
    // - Disconnect
    assertEquals(logHandler.getMessageCount(), 5,
         logHandler.getMessagesString());

    final List<JSONObject> logMessages = parseLogMessages(logHandler);
    assertMessageIs(logMessages.get(0), "connect", null);
    assertMessageIs(logMessages.get(1), "request", OperationType.ADD);
    assertMessageIs(logMessages.get(2), "result", OperationType.ADD);
    assertMessageIs(logMessages.get(3), "request", OperationType.UNBIND);
    assertMessageIs(logMessages.get(4), "disconnect", null);
  }



  /**
   * Tests the behavior when logging simple bind operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimpleBindLogging()
         throws Exception
  {
    // Get the in-memory directory server instance.
    final InMemoryDirectoryServer ds = getTestDS();


    // Create a logger to use for the test.
    final TestLogHandler logHandler = new TestLogHandler();

    final JSONLDAPConnectionLoggerProperties properties =
         new JSONLDAPConnectionLoggerProperties();
    final JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(logHandler, properties);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);


    // Establish a connection and send a simple bind request on it.
    try (LDAPConnection connection =
              new LDAPConnection(options, "localhost", ds.getListenPort()))
    {
      connection.bind("cn=Directory Manager", "password");
    }


    // Make sure that there were five log messages:
    // - Connect
    // - Bind request
    // - Bind result
    // - Unbind
    // - Disconnect
    assertEquals(logHandler.getMessageCount(), 5,
         logHandler.getMessagesString());

    final List<JSONObject> logMessages = parseLogMessages(logHandler);
    assertMessageIs(logMessages.get(0), "connect", null);
    assertMessageIs(logMessages.get(1), "request", OperationType.BIND);
    assertMessageIs(logMessages.get(2), "result", OperationType.BIND);
    assertMessageIs(logMessages.get(3), "request", OperationType.UNBIND);
    assertMessageIs(logMessages.get(4), "disconnect", null);
  }



  /**
   * Tests the behavior when logging SASL bind operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSASLBindLogging()
         throws Exception
  {
    // Get the in-memory directory server instance.
    final InMemoryDirectoryServer ds = getTestDS();


    // Create a logger to use for the test.
    final TestLogHandler logHandler = new TestLogHandler();

    final JSONLDAPConnectionLoggerProperties properties =
         new JSONLDAPConnectionLoggerProperties();
    final JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(logHandler, properties);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);


    // Establish a connection and send a SASL bind request on it.
    try (LDAPConnection connection =
              new LDAPConnection(options, "localhost", ds.getListenPort()))
    {
      connection.bind(new PLAINBindRequest("dn:cn=Directory Manager",
           "password"));
    }


    // Make sure that there were five log messages:
    // - Connect
    // - Bind request
    // - Bind result
    // - Unbind
    // - Disconnect
    assertEquals(logHandler.getMessageCount(), 5,
         logHandler.getMessagesString());

    final List<JSONObject> logMessages = parseLogMessages(logHandler);
    assertMessageIs(logMessages.get(0), "connect", null);
    assertMessageIs(logMessages.get(1), "request", OperationType.BIND);
    assertMessageIs(logMessages.get(2), "result", OperationType.BIND);
    assertMessageIs(logMessages.get(3), "request", OperationType.UNBIND);
    assertMessageIs(logMessages.get(4), "disconnect", null);
  }



  /**
   * Tests the behavior when logging compare operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareLogging()
         throws Exception
  {
    // Get the in-memory directory server instance.
    final InMemoryDirectoryServer ds = getTestDS(true, false);


    // Create a logger to use for the test.
    final TestLogHandler logHandler = new TestLogHandler();

    final JSONLDAPConnectionLoggerProperties properties =
         new JSONLDAPConnectionLoggerProperties();
    final JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(logHandler, properties);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);


    // Establish a connection and send a compare request on it.
    try (LDAPConnection connection =
              new LDAPConnection(options, "localhost", ds.getListenPort()))
    {
      assertTrue(connection.compare("dc=example,dc=com", "dc",
           "example").compareMatched());
    }


    // Make sure that there were five log messages:
    // - Connect
    // - Compare request
    // - Compare result
    // - Unbind
    // - Disconnect
    assertEquals(logHandler.getMessageCount(), 5,
         logHandler.getMessagesString());

    final List<JSONObject> logMessages = parseLogMessages(logHandler);
    assertMessageIs(logMessages.get(0), "connect", null);
    assertMessageIs(logMessages.get(1), "request", OperationType.COMPARE);
    assertMessageIs(logMessages.get(2), "result", OperationType.COMPARE);
    assertMessageIs(logMessages.get(3), "request", OperationType.UNBIND);
    assertMessageIs(logMessages.get(4), "disconnect", null);
  }



  /**
   * Tests the behavior when logging delete operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteLogging()
         throws Exception
  {
    // Get the in-memory directory server instance.
    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Create a logger to use for the test.
    final TestLogHandler logHandler = new TestLogHandler();

    final JSONLDAPConnectionLoggerProperties properties =
         new JSONLDAPConnectionLoggerProperties();
    final JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(logHandler, properties);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);


    // Establish a connection and send a delete request on it.
    try (LDAPConnection connection =
              new LDAPConnection(options, "localhost", ds.getListenPort()))
    {
      connection.delete("uid=test.user,ou=People,dc=example,dc=com");
    }


    // Make sure that there were five log messages:
    // - Connect
    // - Delete request
    // - Delete result
    // - Unbind
    // - Disconnect
    assertEquals(logHandler.getMessageCount(), 5,
         logHandler.getMessagesString());

    final List<JSONObject> logMessages = parseLogMessages(logHandler);
    assertMessageIs(logMessages.get(0), "connect", null);
    assertMessageIs(logMessages.get(1), "request", OperationType.DELETE);
    assertMessageIs(logMessages.get(2), "result", OperationType.DELETE);
    assertMessageIs(logMessages.get(3), "request", OperationType.UNBIND);
    assertMessageIs(logMessages.get(4), "disconnect", null);
  }



  /**
   * Tests the behavior when logging extended operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedOperationLogging()
         throws Exception
  {
    // Get the in-memory directory server instance.
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.addAdditionalBindCredentials("cn=Directory Manager", "password");
    config.addExtendedOperationHandler(
         new TestIntermediateResponseExtendedOperationHandler("1.2.3.4",
              "1.2.3.5", "1.2.3.6", 1, 1));

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
    ds.startListening();

    try
    {
      // Create a logger to use for the test.
      final TestLogHandler logHandler = new TestLogHandler();

      final JSONLDAPConnectionLoggerProperties properties =
           new JSONLDAPConnectionLoggerProperties();
      final JSONLDAPConnectionLogger logger =
           new JSONLDAPConnectionLogger(logHandler, properties);

      final LDAPConnectionOptions options = new LDAPConnectionOptions();
      options.setConnectionLogger(logger);


      // Establish a connection and send an extended request on it.
      try (LDAPConnection connection =
                new LDAPConnection(options, "localhost", ds.getListenPort()))
      {
        assertResultCodeEquals(connection,
             new ExtendedRequest("1.2.3.4"),
             ResultCode.SUCCESS);
      }


      // Make sure that there were seven log messages:
      // - Connect
      // - Extended request
      // - Intermediate response with value
      // - Intermediate response without value
      // - Extended result
      // - Unbind
      // - Disconnect
      assertEquals(logHandler.getMessageCount(), 7,
           logHandler.getMessagesString());

      final List<JSONObject> logMessages = parseLogMessages(logHandler);
      assertMessageIs(logMessages.get(0), "connect", null);
      assertMessageIs(logMessages.get(1), "request", OperationType.EXTENDED);
      assertMessageIs(logMessages.get(2), "intermediate-response", null);
      assertMessageIs(logMessages.get(3), "intermediate-response", null);
      assertMessageIs(logMessages.get(4), "result", OperationType.EXTENDED);
      assertMessageIs(logMessages.get(5), "request", OperationType.UNBIND);
      assertMessageIs(logMessages.get(6), "disconnect", null);
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Tests the behavior when logging modify operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyLogging()
         throws Exception
  {
    // Get the in-memory directory server instance.
    final InMemoryDirectoryServer ds = getTestDS(true, false);


    // Create a logger to use for the test.
    final TestLogHandler logHandler = new TestLogHandler();

    final JSONLDAPConnectionLoggerProperties properties =
         new JSONLDAPConnectionLoggerProperties();
    final JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(logHandler, properties);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);


    // Establish a connection and send a modify request on it.
    try (LDAPConnection connection =
              new LDAPConnection(options, "localhost", ds.getListenPort()))
    {
      connection.modify(
           "dn: dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: foo");
    }


    // Make sure that there were five log messages:
    // - Connect
    // - Modify request
    // - Modify result
    // - Unbind
    // - Disconnect
    assertEquals(logHandler.getMessageCount(), 5,
         logHandler.getMessagesString());

    final List<JSONObject> logMessages = parseLogMessages(logHandler);
    assertMessageIs(logMessages.get(0), "connect", null);
    assertMessageIs(logMessages.get(1), "request", OperationType.MODIFY);
    assertMessageIs(logMessages.get(2), "result", OperationType.MODIFY);
    assertMessageIs(logMessages.get(3), "request", OperationType.UNBIND);
    assertMessageIs(logMessages.get(4), "disconnect", null);
  }



  /**
   * Tests the behavior when logging modify DN operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNLogging()
         throws Exception
  {
    // Get the in-memory directory server instance.
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ds.add(
         "dn: ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Users");

    // Create a logger to use for the test.
    final TestLogHandler logHandler = new TestLogHandler();

    final JSONLDAPConnectionLoggerProperties properties =
         new JSONLDAPConnectionLoggerProperties();
    final JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(logHandler, properties);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);


    // Establish a connection and send a modify request on it.
    try (LDAPConnection connection =
              new LDAPConnection(options, "localhost", ds.getListenPort()))
    {
      connection.modifyDN("uid=test.user,ou=People,dc=example,dc=com",
           "cn=Test User", false, "ou=Users,dc=example,dc=com");
    }


    // Make sure that there were five log messages:
    // - Connect
    // - Modify DN request
    // - Modify DN result
    // - Unbind
    // - Disconnect
    assertEquals(logHandler.getMessageCount(), 5,
         logHandler.getMessagesString());

    final List<JSONObject> logMessages = parseLogMessages(logHandler);
    assertMessageIs(logMessages.get(0), "connect", null);
    assertMessageIs(logMessages.get(1), "request", OperationType.MODIFY_DN);
    assertMessageIs(logMessages.get(2), "result", OperationType.MODIFY_DN);
    assertMessageIs(logMessages.get(3), "request", OperationType.UNBIND);
    assertMessageIs(logMessages.get(4), "disconnect", null);
  }



  /**
   * Tests the behavior when logging search operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchLogging()
         throws Exception
  {
    // Get the in-memory directory server instance.
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ds.add(
         "dn: ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ref: ldap://localhost:" + ds.getListenPort() +
              "/ou=People,dc=example,dc=com");


    // Create a logger to use for the test.
    final TestLogHandler logHandler = new TestLogHandler();

    final JSONLDAPConnectionLoggerProperties properties =
         new JSONLDAPConnectionLoggerProperties();
    properties.setLogSearchEntries(true);
    properties.setLogSearchReferences(true);
    properties.setIncludeSearchEntryAttributeNames(true);
    properties.setIncludeSearchEntryAttributeValues(true);

    final JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(logHandler, properties);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);


    // Establish a connection and perform a search on it.
    try (LDAPConnection connection =
              new LDAPConnection(options, "localhost", ds.getListenPort()))
    {
      connection.search("dc=example,dc=com", SearchScope.SUB,
           Filter.createPresenceFilter("objectClass"), "*", "+");
    }


    // Make sure that there were nine log messages:
    // - Connect
    // - Search request
    // - Search result entry (dc=example,dc=com)
    // - Search result entry (ou=People,dc=example,dc=com)
    // - Search result entry (uid=test.user,ou=People,dc=example,dc=com)
    // - Search result reference
    // - Search result done
    // - Unbind
    // - Disconnect
    assertEquals(logHandler.getMessageCount(), 9,
         logHandler.getMessagesString());

    final List<JSONObject> logMessages = parseLogMessages(logHandler);
    assertMessageIs(logMessages.get(0), "connect", null);
    assertMessageIs(logMessages.get(1), "request", OperationType.SEARCH);
    assertMessageIs(logMessages.get(2), "search-entry", OperationType.SEARCH);
    assertMessageIs(logMessages.get(3), "search-entry", OperationType.SEARCH);
    assertMessageIs(logMessages.get(4), "search-entry", OperationType.SEARCH);
    assertMessageIs(logMessages.get(5), "search-reference",
         OperationType.SEARCH);
    assertMessageIs(logMessages.get(6), "result", OperationType.SEARCH);
    assertMessageIs(logMessages.get(7), "request", OperationType.UNBIND);
    assertMessageIs(logMessages.get(8), "disconnect", null);
  }



  /**
   * Provides coverage for the case in which a disconnect log message contains
   * all elements.
   *
   * Tests the behavior when logging search operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDisconnectLoggingAllElements()
         throws Exception
  {
    // Get the in-memory directory server instance.
    final InMemoryDirectoryServer ds = getTestDS(false, false);


    // Create a logger to use for the test.
    final TestLogHandler logHandler = new TestLogHandler();

    final JSONLDAPConnectionLoggerProperties properties =
         new JSONLDAPConnectionLoggerProperties();

    final JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(logHandler, properties);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);


    // Generate a log message.
    try (LDAPConnection connection = ds.getConnection())
    {
      logger.logDisconnect(connection, "localhost", ds.getListenPort(),
           DisconnectType.OTHER, "Testing disconnect logging", new Exception());
    }


    // Make sure that we can decode the message.
    assertEquals(logHandler.getMessageCount(), 1,
         logHandler.getMessagesString());

    final List<JSONObject> logMessages = parseLogMessages(logHandler);
    assertMessageIs(logMessages.get(0), "disconnect", null);
  }



  /**
   * Provides coverage for the case in which a compare request log message
   * targets an attribute whose value should be redacted.
   *
   * Tests the behavior when logging search operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareWithRedactedAttribute()
         throws Exception
  {
    // Get the in-memory directory server instance.
    final InMemoryDirectoryServer ds = getTestDS(false, false);


    // Create a logger to use for the test.
    final TestLogHandler logHandler = new TestLogHandler();

    final JSONLDAPConnectionLoggerProperties properties =
         new JSONLDAPConnectionLoggerProperties();

    final JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(logHandler, properties);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);


    // Generate a log message.
    try (LDAPConnection connection = ds.getConnection())
    {
      logger.logCompareRequest(connection, 1, new CompareRequest(
           "uid=test.user,ou=People,dc=example,dc=com", "userPassword",
           "password"));
    }


    // Make sure that we can decode the message.
    assertEquals(logHandler.getMessageCount(), 1,
         logHandler.getMessagesString());

    final List<JSONObject> logMessages = parseLogMessages(logHandler);
    assertMessageIs(logMessages.get(0), "request", OperationType.COMPARE);
  }



  /**
   * Provides coverage for the case in which a modify request log message
   * contains modifications and both names and values are to be logged.
   *
   * Tests the behavior when logging search operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyWithAllDetailsIncluded()
         throws Exception
  {
    // Get the in-memory directory server instance.
    final InMemoryDirectoryServer ds = getTestDS(false, false);


    // Create a logger to use for the test.
    final TestLogHandler logHandler = new TestLogHandler();

    final JSONLDAPConnectionLoggerProperties properties =
         new JSONLDAPConnectionLoggerProperties();
    properties.setIncludeModifyAttributeNames(true);
    properties.setIncludeModifyAttributeValues(true);

    final JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(logHandler, properties);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);


    // Generate a log message.
    try (LDAPConnection connection = ds.getConnection())
    {
      connection.setConnectionName("The connection name");
      connection.setConnectionPoolName("The connection pool name");

      final ModifyRequest modifyRequest = new ModifyRequest(
           "dn: uid=test.user,ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: userPassword",
           "userPassword: newPassword",
           "-",
           "replace: authpassword",
           "authpassword: anotherNewPassword",
           "-",
           "replace: description",
           "-",
           "delete: givenName",
           "-",
           "add: givenName",
           "givenName: Foo",
           "-",
           "delete: givenName",
           "givenName: Foo",
           "-",
           "add: givenName",
           "givenName: Test",
           "-",
           "increment: intValueAttr",
           "intValueAttr: 1",
           "-");

      logger.logModifyRequest(connection, 1, modifyRequest);
    }


    // Make sure that we can decode the message.
    assertEquals(logHandler.getMessageCount(), 1,
         logHandler.getMessagesString());

    final List<JSONObject> logMessages = parseLogMessages(logHandler);
    assertMessageIs(logMessages.get(0), "request", OperationType.MODIFY);
  }



  /**
   * Provides coverage for the case in which an abandon request includes
   * controls, which will  be processed as a list.
   *
   * Tests the behavior when logging search operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAbandonWithControls()
         throws Exception
  {
    // Get the in-memory directory server instance.
    final InMemoryDirectoryServer ds = getTestDS(false, false);


    // Create a logger to use for the test.
    final TestLogHandler logHandler = new TestLogHandler();

    final JSONLDAPConnectionLoggerProperties properties =
         new JSONLDAPConnectionLoggerProperties();

    final JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(logHandler, properties);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);


    // Generate a log message.
    try (LDAPConnection connection = ds.getConnection())
    {
      logger.logAbandonRequest(connection, 2, 1,
           Arrays.asList(
                new Control("1.2.3.4", false, null),
                new Control("1.2.3.5", true, new ASN1OctetString("foo"))));
    }


    // Make sure that we can decode the message.
    assertEquals(logHandler.getMessageCount(), 1,
         logHandler.getMessagesString());

    final List<JSONObject> logMessages = parseLogMessages(logHandler);
    assertMessageIs(logMessages.get(0), "request", OperationType.ABANDON);
  }



  /**
   * Provides coverage for the case in which an add request includes controls,
   * which will  be processed as an array.
   *
   * Tests the behavior when logging search operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddWithControls()
         throws Exception
  {
    // Get the in-memory directory server instance.
    final InMemoryDirectoryServer ds = getTestDS(false, false);


    // Create a logger to use for the test.
    final TestLogHandler logHandler = new TestLogHandler();

    final JSONLDAPConnectionLoggerProperties properties =
         new JSONLDAPConnectionLoggerProperties();

    final JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(logHandler, properties);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);


    // Generate a log message.
    try (LDAPConnection connection = ds.getConnection())
    {
      final AddRequest addRequest = new AddRequest(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");
      addRequest.addControl(new Control("1.2.3.4", false, null));
      addRequest.addControl(new Control("1.2.3.5", true,
           new ASN1OctetString("foo")));

      logger.logAddRequest(connection, 1, addRequest);
    }


    // Make sure that we can decode the message.
    assertEquals(logHandler.getMessageCount(), 1,
         logHandler.getMessagesString());

    final List<JSONObject> logMessages = parseLogMessages(logHandler);
    assertMessageIs(logMessages.get(0), "request", OperationType.ADD);
  }



  /**
   * Provides coverage for the case in which an add request includes a DN and
   * attribute values that require redaction.
   *
   * Tests the behavior when logging search operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddWithRedactionNeededInDNAndAttributes()
         throws Exception
  {
    // Get the in-memory directory server instance.
    final InMemoryDirectoryServer ds = getTestDS(false, false);


    // Create a logger to use for the test.
    final TestLogHandler logHandler = new TestLogHandler();

    final JSONLDAPConnectionLoggerProperties properties =
         new JSONLDAPConnectionLoggerProperties();
    properties.setAttributesToRedact("userPassword", "authPassword", "ssn");
    properties.setIncludeAddAttributeNames(true);
    properties.setIncludeAddAttributeValues(true);

    final JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(logHandler, properties);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);


    // Generate a log message.
    try (LDAPConnection connection = ds.getConnection())
    {
      final AddRequest addRequest = new AddRequest(
           "dn: userPassword=password,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: test.user",
           "givenName: Test",
           "sn: user",
           "cn: Test User",
           "userPassword: password");

      logger.logAddRequest(connection, 1, addRequest);
    }


    // Make sure that we can decode the message.
    assertEquals(logHandler.getMessageCount(), 1,
         logHandler.getMessagesString());

    final List<JSONObject> logMessages = parseLogMessages(logHandler);
    assertMessageIs(logMessages.get(0), "request", OperationType.ADD);
  }



  /**
   * Provides coverage for the case in which no redaction is required because
   * there are no defined attributes to redact.
   *
   * Tests the behavior when logging search operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddWithRedactionNotNeeded()
         throws Exception
  {
    // Get the in-memory directory server instance.
    final InMemoryDirectoryServer ds = getTestDS(false, false);


    // Create a logger to use for the test.
    final TestLogHandler logHandler = new TestLogHandler();

    final JSONLDAPConnectionLoggerProperties properties =
         new JSONLDAPConnectionLoggerProperties();
    properties.setAttributesToRedact();
    properties.setIncludeAddAttributeNames(true);
    properties.setIncludeAddAttributeValues(true);

    final JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(logHandler, properties);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);


    // Generate a log message.
    try (LDAPConnection connection = ds.getConnection())
    {
      final AddRequest addRequest = new AddRequest(
           "dn: userPassword=password,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: test.user",
           "givenName: Test",
           "sn: user",
           "cn: Test User",
           "userPassword: password");

      logger.logAddRequest(connection, 1, addRequest);
    }


    // Make sure that we can decode the message.
    assertEquals(logHandler.getMessageCount(), 1,
         logHandler.getMessagesString());

    final List<JSONObject> logMessages = parseLogMessages(logHandler);
    assertMessageIs(logMessages.get(0), "request", OperationType.ADD);
  }



  /**
   * Provides coverage for the case in which a search filter contains attributes
   * that do and do not need to be redacted.
   *
   * Tests the behavior when logging search operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchFilterWithRedactionNeeded()
         throws Exception
  {
    // Get the in-memory directory server instance.
    final InMemoryDirectoryServer ds = getTestDS(false, false);


    // Create a logger to use for the test.
    final TestLogHandler logHandler = new TestLogHandler();

    final JSONLDAPConnectionLoggerProperties properties =
         new JSONLDAPConnectionLoggerProperties();

    final JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(logHandler, properties);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);


    // Generate a log message.
    try (LDAPConnection connection = ds.getConnection())
    {
      final SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
           SearchScope.SUB,
           Filter.createANDFilter(
                Filter.createORFilter(
                     Filter.createPresenceFilter("userPassword"),
                     Filter.createPresenceFilter("objectClass")),
                Filter.createORFilter(
                     Filter.createEqualityFilter("userPassword", "password"),
                     Filter.createEqualityFilter("objectClass", "top")),
                Filter.createORFilter(
                     Filter.createGreaterOrEqualFilter("userPassword",
                          "password"),
                     Filter.createGreaterOrEqualFilter("objectClass", "top")),
                Filter.createORFilter(
                     Filter.createLessOrEqualFilter("userPassword", "password"),
                     Filter.createLessOrEqualFilter("objectClass", "top")),
                Filter.createORFilter(
                     Filter.createSubstringFilter("userPassword", "password",
                          null, null),
                     Filter.createSubstringFilter("userPassword", null,
                          new String[] { "password" }, null),
                     Filter.createSubstringFilter("userPassword", null,
                          new String[] { "password", "password" }, null),
                     Filter.createSubstringFilter("userPassword", null, null,
                          "password"),
                     Filter.createSubstringFilter("objectClass", "top",
                          null, null),
                     Filter.createSubstringFilter("objectClass", null,
                          new String[] { "top" }, null),
                     Filter.createSubstringFilter("objectClass", null,
                          new String[] { "top", "top" }, null),
                     Filter.createSubstringFilter("objectClass", null, null,
                          "top")),
                Filter.createORFilter(
                     Filter.createApproximateMatchFilter("userPassword",
                          "password"),
                     Filter.createApproximateMatchFilter("objectClass", "top")),
                Filter.createORFilter(
                     Filter.createExtensibleMatchFilter("userPassword", null,
                          false, "password"),
                     Filter.createExtensibleMatchFilter("objectClass", null,
                          false, "top"),
                     Filter.createExtensibleMatchFilter(null,
                          "2.5.13.2", false, "password")),
                Filter.createNOTFilter(
                     Filter.createEqualityFilter("userPassword", "password"))));

      logger.logSearchRequest(connection, 1, searchRequest);
    }


    // Make sure that we can decode the message.
    assertEquals(logHandler.getMessageCount(), 1,
         logHandler.getMessagesString());

    final List<JSONObject> logMessages = parseLogMessages(logHandler);
    assertMessageIs(logMessages.get(0), "request", OperationType.SEARCH);
  }



  /**
   * Provides coverage for the case in which an add result message contains
   * all components.
   *
   * Tests the behavior when logging search operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddResultWithAllComponents()
         throws Exception
  {
    // Get the in-memory directory server instance.
    final InMemoryDirectoryServer ds = getTestDS(false, false);


    // Create a logger to use for the test.
    final TestLogHandler logHandler = new TestLogHandler();

    final JSONLDAPConnectionLoggerProperties properties =
         new JSONLDAPConnectionLoggerProperties();

    final JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(logHandler, properties);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);


    // Generate a log message.
    try (LDAPConnection connection = ds.getConnection())
    {
      final LDAPResult addResult = new LDAPResult(1, ResultCode.REFERRAL,
           "Try the operation somewhere else",
           "dc=example,dc=com",
           new String[]
           {
             "ldap://ds1.example.com:389/dc=example,dc=com",
             "ldap://ds2.example.com:389/dc=example,dc=com"
           },
           new Control[]
           {
             new Control("1.2.3.4", false, null),
             new Control("1.2.3.5", true, new ASN1OctetString("foo"))
           });

      logger.logAddResult(connection, 1, addResult);
    }


    // Make sure that we can decode the message.
    assertEquals(logHandler.getMessageCount(), 1,
         logHandler.getMessagesString());

    final List<JSONObject> logMessages = parseLogMessages(logHandler);
    assertMessageIs(logMessages.get(0), "result", OperationType.ADD);
  }



  /**
   * Provides coverage for the case in which a bind result message includes
   * server SASL credentials.
   *
   * Tests the behavior when logging search operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindResultWithServerSASLCredentials()
         throws Exception
  {
    // Get the in-memory directory server instance.
    final InMemoryDirectoryServer ds = getTestDS(false, false);


    // Create a logger to use for the test.
    final TestLogHandler logHandler = new TestLogHandler();

    final JSONLDAPConnectionLoggerProperties properties =
         new JSONLDAPConnectionLoggerProperties();

    final JSONLDAPConnectionLogger logger =
         new JSONLDAPConnectionLogger(logHandler, properties);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectionLogger(logger);


    // Generate a log message.
    try (LDAPConnection connection = ds.getConnection())
    {
      final BindResult bindResult = new BindResult(1, ResultCode.SUCCESS,
           null, null, null, null, new ASN1OctetString("creds"));

      logger.logBindResult(connection, 1, bindResult);
    }


    // Make sure that we can decode the message.
    assertEquals(logHandler.getMessageCount(), 1,
         logHandler.getMessagesString());

    final List<JSONObject> logMessages = parseLogMessages(logHandler);
    assertMessageIs(logMessages.get(0), "result", OperationType.BIND);
  }



  /**
   * Parses the messages logged to the provided handler as JSON objects.
   *
   * @param  logHandler  The log handler for which to parse the messages.  It
   *                     must not be {@code null}.
   *
   * @return  The JSON objects parsed from the log messags.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static List<JSONObject> parseLogMessages(
                                       final TestLogHandler logHandler)
          throws Exception
  {
    final List<JSONObject> messageObjects = new ArrayList<>();

    try (ByteArrayInputStream inputStream =
              new ByteArrayInputStream(
                   StaticUtils.getBytes(logHandler.getMessagesString()));
         JSONObjectReader reader = new JSONObjectReader(inputStream))
    {
      while (true)
      {
        final JSONObject messageObject = reader.readObject();
        if (messageObject == null)
        {
          return messageObjects;
        }
        else
        {
          messageObjects.add(messageObject);
        }
      }
    }
  }



  /**
   * Ensures that the provided JSON object represents a log message with the
   * given message and operation type.
   *
   * @param   messageObject  The JSON object representing the message to
   *                         validate.  It must not be {@code null}.
   * @param   messageType    The expected message type.  It must not be
   *                         {@code null}.
   * @param   operationType  The expected operation type.  It may be
   *                         {@code null} if no operation type is expected.
   */
  private static void assertMessageIs(final JSONObject messageObject,
                                      final String messageType,
                                      final OperationType operationType)
  {
    assertTrue(messageObject.hasField("message-type"));
    assertEquals(messageObject.getFieldAsString("message-type"), messageType);

    if (operationType == null)
    {
      assertFalse(messageObject.hasField("operation-type"));
    }
    else
    {
      assertTrue(messageObject.hasField("operation-type"));
      assertEquals(
           OperationType.forName(messageObject.getFieldAsString(
                "operation-type")),
           operationType);
    }
  }
}
