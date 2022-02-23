/*
 * Copyright 2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022 Ping Identity Corporation
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
 * Copyright (C) 2022 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.text;



import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.unboundidds.controls.AuthenticationFailureReason;
import com.unboundid.ldap.sdk.unboundidds.logs.BindRequestAuthenticationType;
import com.unboundid.ldap.sdk.unboundidds.logs.LogException;
import com.unboundid.util.StaticUtils;

import static com.unboundid.ldap.sdk.unboundidds.logs.AccessLogMessageType.*;
import static com.unboundid.ldap.sdk.unboundidds.logs.AccessLogOperationType.*;
import static com.unboundid.ldap.sdk.unboundidds.logs.v2.text.
                   TextFormattedAccessLogFields.*;



/**
 * This class provides a set of test cases for the text-formatted access log
 * reader.
 */
public final class TextFormattedAccessLogReaderTestCase
       extends TextFormattedLogsTestCase
{
  /**
   * Tests the ability to read connect log messages.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, CONNECT, null, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, CONNECT, null, true);
    appendField(populatedBuffer, CONNECT_FROM_ADDRESS, "2.3.4.5");
    appendField(populatedBuffer, CONNECT_FROM_PORT, 1234);
    appendField(populatedBuffer, CONNECT_TO_ADDRESS, "2.3.4.6");
    appendField(populatedBuffer, CONNECT_TO_PORT, 4567);
    appendField(populatedBuffer, PROTOCOL, "LDAP");
    appendField(populatedBuffer, CLIENT_CONNECTION_POLICY, "Default");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader = new
         TextFormattedAccessLogReader(logFile.getAbsolutePath()))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedConnectAccessLogMessage minimalMessage =
           (TextFormattedConnectAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedConnectAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), CONNECT);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());

      // Message-specific fields.
      assertNull(minimalMessage.getSourceAddress());
      assertNull(minimalMessage.getSourcePort());
      assertNull(minimalMessage.getTargetAddress());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getProtocolName());
      assertNull(minimalMessage.getClientConnectionPolicy());


      // Read the fully-populated log message.
      TextFormattedConnectAccessLogMessage populatedMessage =
           (TextFormattedConnectAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedConnectAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), CONNECT);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);

      // Message-specific fields.
      assertEquals(populatedMessage.getSourceAddress(), "2.3.4.5");
      assertEquals(populatedMessage.getSourcePort().intValue(), 1234);
      assertEquals(populatedMessage.getTargetAddress(), "2.3.4.6");
      assertEquals(populatedMessage.getTargetPort().intValue(), 4567);
      assertEquals(populatedMessage.getProtocolName(), "LDAP");
      assertEquals(populatedMessage.getClientConnectionPolicy(), "Default");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a disconnect log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDisconnectLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, DISCONNECT, null, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, DISCONNECT, null, true);
    appendField(populatedBuffer, DISCONNECT_REASON, "Disconnect Reason");
    appendField(populatedBuffer, DISCONNECT_MESSAGE, "Disconnect Message");
    appendField(populatedBuffer, REQUESTER_IP_ADDRESS, DEFAULT_REQUESTER_IP);

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedDisconnectAccessLogMessage minimalMessage =
           (TextFormattedDisconnectAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedDisconnectAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), DISCONNECT);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());

      // Message-specific fields.
      assertNull(minimalMessage.getDisconnectReason());
      assertNull(minimalMessage.getDisconnectMessage());
      assertNull(minimalMessage.getRequesterIPAddress());


      // Read the fully-populated log message.
      TextFormattedDisconnectAccessLogMessage populatedMessage =
           (TextFormattedDisconnectAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedDisconnectAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), DISCONNECT);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);

      // Message-specific fields.
      assertEquals(populatedMessage.getDisconnectReason(),
           "Disconnect Reason");
      assertEquals(populatedMessage.getDisconnectMessage(),
           "Disconnect Message");
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a security negotiation log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityNegotiationLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, SECURITY_NEGOTIATION, null, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, SECURITY_NEGOTIATION, null, true);
    appendField(populatedBuffer, PROTOCOL, "TLSv1.3");
    appendField(populatedBuffer, CIPHER, "TSL_AES_256_GCM_SHA384");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedSecurityNegotiationAccessLogMessage minimalMessage =
           (TextFormattedSecurityNegotiationAccessLogMessage)
           reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedSecurityNegotiationAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), SECURITY_NEGOTIATION);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());

      // Message-specific fields.
      assertNull(minimalMessage.getProtocol());
      assertNull(minimalMessage.getCipher());


      // Read the fully-populated log message.
      TextFormattedSecurityNegotiationAccessLogMessage populatedMessage =
           (TextFormattedSecurityNegotiationAccessLogMessage)
           reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedSecurityNegotiationAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), SECURITY_NEGOTIATION);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);

      // Message-specific fields.
      assertEquals(populatedMessage.getProtocol(), "TLSv1.3");
      assertEquals(populatedMessage.getCipher(), "TSL_AES_256_GCM_SHA384");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a client certificate log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testClientCertificateLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, CLIENT_CERTIFICATE, null, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, CLIENT_CERTIFICATE, null, true);
    appendField(populatedBuffer, PEER_CERTIFICATE_SUBJECT_DN,
         "CN=server.example.com,O=Example Corp,C=US");
    appendField(populatedBuffer, ISSUER_CERTIFICATE_SUBJECT_DN,
         "CN=Intermediate CA,O=Example Corp,C=US");
    appendField(populatedBuffer, ISSUER_CERTIFICATE_SUBJECT_DN,
         "CN=Root CA,O=Example Corp,C=US");
    appendField(populatedBuffer, AUTO_AUTHENTICATED_AS,
         "cn=Auto,cn=Authenticated");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedClientCertificateAccessLogMessage minimalMessage =
           (TextFormattedClientCertificateAccessLogMessage)
           reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedClientCertificateAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), CLIENT_CERTIFICATE);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());

      // Message-specific fields.
      assertNull(minimalMessage.getPeerSubjectDN());
      assertEquals(minimalMessage.getIssuerSubjectDNs(),
           Collections.emptyList());
      assertNull(minimalMessage.getAutoAuthenticatedAsDN());


      // Read the fully-populated log message.
      TextFormattedClientCertificateAccessLogMessage populatedMessage =
           (TextFormattedClientCertificateAccessLogMessage)
           reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedClientCertificateAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), CLIENT_CERTIFICATE);

      // Message-specific fields.
      assertEquals(populatedMessage.getPeerSubjectDN(),
           "CN=server.example.com,O=Example Corp,C=US");
      assertEquals(populatedMessage.getIssuerSubjectDNs(),
           Arrays.asList(
                "CN=Intermediate CA,O=Example Corp,C=US",
                "CN=Root CA,O=Example Corp,C=US"));
      assertEquals(populatedMessage.getAutoAuthenticatedAsDN(),
           "cn=Auto,cn=Authenticated");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read an entry rebalancing request log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEntryRebalancingRequestLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, ENTRY_REBALANCING_REQUEST, null, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, ENTRY_REBALANCING_REQUEST, null, true);
    appendField(populatedBuffer, ENTRY_REBALANCING_OPERATION_ID, 1234L);
    appendField(populatedBuffer, TRIGGERED_BY_CONNECTION_ID, 5678L);
    appendField(populatedBuffer, TRIGGERED_BY_OPERATION_ID, 8765L);
    appendField(populatedBuffer, ENTRY_REBALANCING_BASE_DN,
         "ou=People,dc=example,dc=com");
    appendField(populatedBuffer, ENTRY_REBALANCING_SIZE_LIMIT, 1000L);
    appendField(populatedBuffer, ENTRY_REBALANCING_SOURCE_BACKEND_SET, "Set A");
    appendField(populatedBuffer, ENTRY_REBALANCING_SOURCE_SERVER,
         "source.example.com:1389");
    appendField(populatedBuffer, ENTRY_REBALANCING_TARGET_BACKEND_SET, "Set B");
    appendField(populatedBuffer, ENTRY_REBALANCING_TARGET_SERVER,
         "target.example.com:2389");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedEntryRebalancingRequestAccessLogMessage minimalMessage =
           (TextFormattedEntryRebalancingRequestAccessLogMessage)
           reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedEntryRebalancingRequestAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(),
           ENTRY_REBALANCING_REQUEST);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());

      // Message-specific fields.
      assertNull(minimalMessage.getRebalancingOperationID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getSubtreeBaseDN());
      assertNull(minimalMessage.getSizeLimit());
      assertNull(minimalMessage.getSourceBackendSetName());
      assertNull(minimalMessage.getSourceBackendServer());
      assertNull(minimalMessage.getTargetBackendSetName());
      assertNull(minimalMessage.getTargetBackendServer());


      // Read the fully-populated log message.
      TextFormattedEntryRebalancingRequestAccessLogMessage populatedMessage =
           (TextFormattedEntryRebalancingRequestAccessLogMessage)
           reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage =
           new TextFormattedEntryRebalancingRequestAccessLogMessage(
                populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(),
           ENTRY_REBALANCING_REQUEST);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);

      // Message-specific fields.
      assertEquals(populatedMessage.getRebalancingOperationID().longValue(),
           1234L);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           5678L);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           8765L);
      assertEquals(populatedMessage.getSubtreeBaseDN(),
           "ou=People,dc=example,dc=com");
      assertEquals(populatedMessage.getSizeLimit().intValue(), 1000);
      assertEquals(populatedMessage.getSourceBackendSetName(), "Set A");
      assertEquals(populatedMessage.getSourceBackendServer(),
           "source.example.com:1389");
      assertEquals(populatedMessage.getTargetBackendSetName(), "Set B");
      assertEquals(populatedMessage.getTargetBackendServer(),
           "target.example.com:2389");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read an entry rebalancing result log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEntryRebalancingResultLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, ENTRY_REBALANCING_RESULT, null, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, ENTRY_REBALANCING_RESULT, null, true);
    appendField(populatedBuffer, ENTRY_REBALANCING_OPERATION_ID, 1234L);
    appendField(populatedBuffer, TRIGGERED_BY_CONNECTION_ID, 5678L);
    appendField(populatedBuffer, TRIGGERED_BY_OPERATION_ID, 8765L);
    appendField(populatedBuffer, ENTRY_REBALANCING_BASE_DN,
         "ou=People,dc=example,dc=com");
    appendField(populatedBuffer, ENTRY_REBALANCING_SIZE_LIMIT, 1000L);
    appendField(populatedBuffer, ENTRY_REBALANCING_SOURCE_BACKEND_SET, "Set A");
    appendField(populatedBuffer, ENTRY_REBALANCING_SOURCE_SERVER,
         "source.example.com:1389");
    appendField(populatedBuffer, ENTRY_REBALANCING_TARGET_BACKEND_SET, "Set B");
    appendField(populatedBuffer, ENTRY_REBALANCING_TARGET_SERVER,
         "target.example.com:2389");
    appendField(populatedBuffer, RESULT_CODE_VALUE, 0L);
    appendField(populatedBuffer, RESULT_CODE_NAME, "SUCCESS");
    appendField(populatedBuffer, ENTRY_REBALANCING_ERROR_MESSAGE,
         "Error Message");
    appendField(populatedBuffer, ENTRY_REBALANCING_ADMIN_ACTION_MESSAGE,
         "Admin Action Message");
    appendField(populatedBuffer, ENTRY_REBALANCING_SOURCE_SERVER_ALTERED, true);
    appendField(populatedBuffer, ENTRY_REBALANCING_TARGET_SERVER_ALTERED,
         false);
    appendField(populatedBuffer, ENTRY_REBALANCING_ENTRIES_READ_FROM_SOURCE,
         123L);
    appendField(populatedBuffer, ENTRY_REBALANCING_ENTRIES_ADDED_TO_TARGET, 0L);
    appendField(populatedBuffer, ENTRY_REBALANCING_ENTRIES_DELETED_FROM_SOURCE,
         1L);

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedEntryRebalancingResultAccessLogMessage minimalMessage =
           (TextFormattedEntryRebalancingResultAccessLogMessage)
           reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedEntryRebalancingResultAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(),
           ENTRY_REBALANCING_RESULT);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());

      // Message-specific fields.
      assertNull(minimalMessage.getRebalancingOperationID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getSubtreeBaseDN());
      assertNull(minimalMessage.getSizeLimit());
      assertNull(minimalMessage.getSourceBackendSetName());
      assertNull(minimalMessage.getSourceBackendServer());
      assertNull(minimalMessage.getTargetBackendSetName());
      assertNull(minimalMessage.getTargetBackendServer());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getErrorMessage());
      assertNull(minimalMessage.getAdminActionMessage());
      assertNull(minimalMessage.getSourceServerAltered());
      assertNull(minimalMessage.getTargetServerAltered());
      assertNull(minimalMessage.getEntriesReadFromSource());
      assertNull(minimalMessage.getEntriesAddedToTarget());
      assertNull(minimalMessage.getEntriesDeletedFromSource());


      // Read the fully-populated log message.
      TextFormattedEntryRebalancingResultAccessLogMessage populatedMessage =
           (TextFormattedEntryRebalancingResultAccessLogMessage)
           reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage =
           new TextFormattedEntryRebalancingResultAccessLogMessage(
                populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(),
           ENTRY_REBALANCING_RESULT);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);

      // Message-specific fields.
      assertEquals(populatedMessage.getRebalancingOperationID().longValue(),
           1234L);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           5678L);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           8765L);
      assertEquals(populatedMessage.getSubtreeBaseDN(),
           "ou=People,dc=example,dc=com");
      assertEquals(populatedMessage.getSizeLimit().intValue(), 1000);
      assertEquals(populatedMessage.getSourceBackendSetName(), "Set A");
      assertEquals(populatedMessage.getSourceBackendServer(),
           "source.example.com:1389");
      assertEquals(populatedMessage.getTargetBackendSetName(), "Set B");
      assertEquals(populatedMessage.getTargetBackendServer(),
           "target.example.com:2389");
      assertEquals(populatedMessage.getResultCode(), ResultCode.SUCCESS);
      assertEquals(populatedMessage.getErrorMessage(), "Error Message");
      assertEquals(populatedMessage.getAdminActionMessage(),
           "Admin Action Message");
      assertEquals(populatedMessage.getSourceServerAltered(), Boolean.TRUE);
      assertEquals(populatedMessage.getTargetServerAltered(), Boolean.FALSE);
      assertEquals(populatedMessage.getEntriesReadFromSource().intValue(),
           123);
      assertEquals(populatedMessage.getEntriesAddedToTarget().intValue(), 0);
      assertEquals(populatedMessage.getEntriesDeletedFromSource().intValue(),
           1);


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read an abandon request log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAbandonRequestLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, REQUEST, ABANDON, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, REQUEST, ABANDON, true);
    appendField(populatedBuffer, ABANDON_MESSAGE_ID, 123);

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedAbandonRequestAccessLogMessage minimalMessage =
           (TextFormattedAbandonRequestAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedAbandonRequestAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), REQUEST);
      assertEquals(minimalMessage.getOperationType(), ABANDON);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());

      // Message-specific fields.
      assertNull(minimalMessage.getMessageIDToAbandon());


      // Read the fully-populated log message.
      TextFormattedAbandonRequestAccessLogMessage populatedMessage =
           (TextFormattedAbandonRequestAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedAbandonRequestAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), REQUEST);
      assertEquals(populatedMessage.getOperationType(), ABANDON);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);

      // Message-specific fields.
      assertEquals(populatedMessage.getMessageIDToAbandon().intValue(), 123);


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read an abandon forward log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAbandonForwardLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, FORWARD, ABANDON, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, FORWARD, ABANDON, true);
    appendField(populatedBuffer, ABANDON_MESSAGE_ID, 123);

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedAbandonForwardAccessLogMessage minimalMessage =
           (TextFormattedAbandonForwardAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedAbandonForwardAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), FORWARD);
      assertEquals(minimalMessage.getOperationType(), ABANDON);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());

      // Message-specific fields.
      assertNull(minimalMessage.getMessageIDToAbandon());


      // Read the fully-populated log message.
      TextFormattedAbandonForwardAccessLogMessage populatedMessage =
           (TextFormattedAbandonForwardAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedAbandonForwardAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), FORWARD);
      assertEquals(populatedMessage.getOperationType(), ABANDON);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);

      // Message-specific fields.
      assertEquals(populatedMessage.getMessageIDToAbandon().intValue(), 123);


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read an abandon forward failed log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAbandonForwardFailedLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, FORWARD_FAILED, ABANDON, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, FORWARD_FAILED, ABANDON, true);
    appendField(populatedBuffer, ABANDON_MESSAGE_ID, 123);

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedAbandonForwardFailedAccessLogMessage minimalMessage =
           (TextFormattedAbandonForwardFailedAccessLogMessage)
           reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedAbandonForwardFailedAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(minimalMessage.getOperationType(), ABANDON);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());

      // Message-specific fields.
      assertNull(minimalMessage.getMessageIDToAbandon());


      // Read the fully-populated log message.
      TextFormattedAbandonForwardFailedAccessLogMessage populatedMessage =
           (TextFormattedAbandonForwardFailedAccessLogMessage)
           reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedAbandonForwardFailedAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(populatedMessage.getOperationType(), ABANDON);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);

      // Message-specific fields.
      assertEquals(populatedMessage.getMessageIDToAbandon().intValue(), 123);


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read an abandon result log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAbandonResultLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, RESULT, ABANDON, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, RESULT, ABANDON, true);
    appendField(populatedBuffer, ABANDON_MESSAGE_ID, 123);

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedAbandonResultAccessLogMessage minimalMessage =
           (TextFormattedAbandonResultAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedAbandonResultAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), RESULT);
      assertEquals(minimalMessage.getOperationType(), ABANDON);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());
      assertNull(minimalMessage.getAdditionalInformation());
      assertNull(minimalMessage.getMatchedDN());
      assertEquals(minimalMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalMessage.getUncachedDataAccessed());
      assertNull(minimalMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalMessage.getProcessingTimeMillis());
      assertNull(minimalMessage.getIntermediateResponsesReturned());
      assertEquals(minimalMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getMissingPrivileges(),
           Collections.emptySet());

      // Message-specific fields.
      assertNull(minimalMessage.getMessageIDToAbandon());


      // Read the fully-populated log message.
      TextFormattedAbandonResultAccessLogMessage populatedMessage =
           (TextFormattedAbandonResultAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedAbandonResultAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), RESULT);
      assertEquals(populatedMessage.getOperationType(), ABANDON);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);

      // Message-specific fields.
      assertEquals(populatedMessage.getMessageIDToAbandon().intValue(), 123);


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read an add request log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddRequestLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, REQUEST, ADD, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, REQUEST, ADD, true);
    appendField(populatedBuffer, ADD_ENTRY_DN, "ou=test,dc=example,dc=com");
    appendField(populatedBuffer, ADD_ATTRIBUTES, "objectClass", "ou");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedAddRequestAccessLogMessage minimalMessage =
           (TextFormattedAddRequestAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedAddRequestAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), REQUEST);
      assertEquals(minimalMessage.getOperationType(), ADD);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());
      assertEquals(minimalMessage.getAttributeNames(),
           Collections.emptySet());


      // Read the fully-populated log message.
      TextFormattedAddRequestAccessLogMessage populatedMessage =
           (TextFormattedAddRequestAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedAddRequestAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), REQUEST);
      assertEquals(populatedMessage.getOperationType(), ADD);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "ou=test,dc=example,dc=com");
      assertEquals(populatedMessage.getAttributeNames(),
           StaticUtils.setOf("objectClass", "ou"));


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read an add forward log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddForwardLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, FORWARD, ADD, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, FORWARD, ADD, true);
    appendField(populatedBuffer, ADD_ENTRY_DN, "ou=test,dc=example,dc=com");
    appendField(populatedBuffer, ADD_ATTRIBUTES, "objectClass", "ou");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedAddForwardAccessLogMessage minimalMessage =
           (TextFormattedAddForwardAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedAddForwardAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), FORWARD);
      assertEquals(minimalMessage.getOperationType(), ADD);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());
      assertEquals(minimalMessage.getAttributeNames(),
           Collections.emptySet());


      // Read the fully-populated log message.
      TextFormattedAddForwardAccessLogMessage populatedMessage =
           (TextFormattedAddForwardAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedAddForwardAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), FORWARD);
      assertEquals(populatedMessage.getOperationType(), ADD);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "ou=test,dc=example,dc=com");
      assertEquals(populatedMessage.getAttributeNames(),
           StaticUtils.setOf("objectClass", "ou"));


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read an add forward failed log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddForwardFailedLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, FORWARD_FAILED, ADD, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, FORWARD_FAILED, ADD, true);
    appendField(populatedBuffer, ADD_ENTRY_DN, "ou=test,dc=example,dc=com");
    appendField(populatedBuffer, ADD_ATTRIBUTES, "objectClass", "ou");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedAddForwardFailedAccessLogMessage minimalMessage =
           (TextFormattedAddForwardFailedAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedAddForwardFailedAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(minimalMessage.getOperationType(), ADD);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());
      assertEquals(minimalMessage.getAttributeNames(),
           Collections.emptySet());


      // Read the fully-populated log message.
      TextFormattedAddForwardFailedAccessLogMessage populatedMessage =
           (TextFormattedAddForwardFailedAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedAddForwardFailedAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(populatedMessage.getOperationType(), ADD);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "ou=test,dc=example,dc=com");
      assertEquals(populatedMessage.getAttributeNames(),
           StaticUtils.setOf("objectClass", "ou"));


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read an add result log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddResultLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, RESULT, ADD, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, RESULT, ADD, true);
    appendField(populatedBuffer, ADD_ENTRY_DN, "ou=test,dc=example,dc=com");
    appendField(populatedBuffer, ADD_ATTRIBUTES, "objectClass", "ou");
    appendField(populatedBuffer, ADD_UNDELETE_FROM_DN,
         "cn=undelete,cn=from,cn=dn");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedAddResultAccessLogMessage minimalMessage =
           (TextFormattedAddResultAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedAddResultAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), RESULT);
      assertEquals(minimalMessage.getOperationType(), ADD);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());
      assertNull(minimalMessage.getAdditionalInformation());
      assertNull(minimalMessage.getMatchedDN());
      assertEquals(minimalMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalMessage.getUncachedDataAccessed());
      assertNull(minimalMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalMessage.getProcessingTimeMillis());
      assertNull(minimalMessage.getIntermediateResponsesReturned());
      assertEquals(minimalMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getMissingPrivileges(),
           Collections.emptySet());
      assertNull(minimalMessage.getAlternateAuthorizationDN());
      assertNull(minimalMessage.getAssuredReplicationLocalLevel());
      assertNull(minimalMessage.getAssuredReplicationRemoteLevel());
      assertNull(minimalMessage.getAssuredReplicationTimeoutMillis());
      assertNull(minimalMessage.getResponseDelayedByAssurance());
      assertEquals(minimalMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           Collections.emptySet());
      assertEquals(
           minimalMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           Collections.emptySet());
      assertNull(minimalMessage.getReplicationChangeID());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());
      assertEquals(minimalMessage.getAttributeNames(),
           Collections.emptySet());
      assertNull(minimalMessage.getUndeleteFromDN());


      // Read the fully-populated log message.
      TextFormattedAddResultAccessLogMessage populatedMessage =
           (TextFormattedAddResultAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedAddResultAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), RESULT);
      assertEquals(populatedMessage.getOperationType(), ADD);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);
      assertEquals(populatedMessage.getAlternateAuthorizationDN(),
           DEFAULT_AUTHZ_DN);
      assertEquals(populatedMessage.getAssuredReplicationLocalLevel(),
           DEFAULT_LOCAL_ASSURANCE_LEVEL);
      assertEquals(populatedMessage.getAssuredReplicationRemoteLevel(),
           DEFAULT_REMOTE_ASSURANCE_LEVEL);
      assertEquals(
           populatedMessage.getAssuredReplicationTimeoutMillis().longValue(),
           DEFAULT_ASSURANCE_TIMEOUT_MILLIS);
      assertEquals(populatedMessage.getResponseDelayedByAssurance(),
           DEFAULT_RESPONSE_DELAYED_BY_ASSURANCE);
      assertEquals(
           populatedMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           DEFAULT_INDEXES_NEAR_ENTRY_LIMIT);
      assertEquals(
           populatedMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           DEFAULT_INDEXES_EXCEEDING_ENTRY_LIMIT);
      assertEquals(populatedMessage.getReplicationChangeID(),
           DEFAULT_REPLICATION_CHANGE_ID);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "ou=test,dc=example,dc=com");
      assertEquals(populatedMessage.getAttributeNames(),
           StaticUtils.setOf("objectClass", "ou"));
      assertEquals(populatedMessage.getUndeleteFromDN(),
           "cn=undelete,cn=from,cn=dn");

      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read an add assurance complete log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddAssuranceCompleteLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, ASSURANCE_COMPLETE, ADD, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, ASSURANCE_COMPLETE, ADD, true);
    appendField(populatedBuffer, ADD_ENTRY_DN, "ou=test,dc=example,dc=com");
    appendField(populatedBuffer, ADD_ATTRIBUTES, "objectClass", "ou");
    appendField(populatedBuffer, ADD_UNDELETE_FROM_DN,
         "cn=undelete,cn=from,cn=dn");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedAddAssuranceCompletedAccessLogMessage minimalMessage =
           (TextFormattedAddAssuranceCompletedAccessLogMessage)
           reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedAddAssuranceCompletedAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), ASSURANCE_COMPLETE);
      assertEquals(minimalMessage.getOperationType(), ADD);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());
      assertNull(minimalMessage.getAdditionalInformation());
      assertNull(minimalMessage.getMatchedDN());
      assertEquals(minimalMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalMessage.getUncachedDataAccessed());
      assertNull(minimalMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalMessage.getProcessingTimeMillis());
      assertNull(minimalMessage.getIntermediateResponsesReturned());
      assertEquals(minimalMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getMissingPrivileges(),
           Collections.emptySet());
      assertNull(minimalMessage.getAlternateAuthorizationDN());
      assertNull(minimalMessage.getAssuredReplicationLocalLevel());
      assertNull(minimalMessage.getAssuredReplicationRemoteLevel());
      assertNull(minimalMessage.getAssuredReplicationTimeoutMillis());
      assertNull(minimalMessage.getResponseDelayedByAssurance());
      assertEquals(minimalMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           Collections.emptySet());
      assertEquals(
           minimalMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           Collections.emptySet());
      assertNull(minimalMessage.getReplicationChangeID());
      assertNull(minimalMessage.getLocalAssuranceSatisfied());
      assertNull(minimalMessage.getRemoteAssuranceSatisfied());
      assertEquals(minimalMessage.getServerResults(),
           Collections.emptyList());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());
      assertEquals(minimalMessage.getAttributeNames(),
           Collections.emptySet());
      assertNull(minimalMessage.getUndeleteFromDN());


      // Read the fully-populated log message.
      TextFormattedAddAssuranceCompletedAccessLogMessage populatedMessage =
           (TextFormattedAddAssuranceCompletedAccessLogMessage)
           reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedAddAssuranceCompletedAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), ASSURANCE_COMPLETE);
      assertEquals(populatedMessage.getOperationType(), ADD);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);
      assertEquals(populatedMessage.getAlternateAuthorizationDN(),
           DEFAULT_AUTHZ_DN);
      assertEquals(populatedMessage.getAssuredReplicationLocalLevel(),
           DEFAULT_LOCAL_ASSURANCE_LEVEL);
      assertEquals(populatedMessage.getAssuredReplicationRemoteLevel(),
           DEFAULT_REMOTE_ASSURANCE_LEVEL);
      assertEquals(
           populatedMessage.getAssuredReplicationTimeoutMillis().longValue(),
           DEFAULT_ASSURANCE_TIMEOUT_MILLIS);
      assertEquals(populatedMessage.getResponseDelayedByAssurance(),
           DEFAULT_RESPONSE_DELAYED_BY_ASSURANCE);
      assertEquals(
           populatedMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           DEFAULT_INDEXES_NEAR_ENTRY_LIMIT);
      assertEquals(
           populatedMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           DEFAULT_INDEXES_EXCEEDING_ENTRY_LIMIT);
      assertEquals(populatedMessage.getReplicationChangeID(),
           DEFAULT_REPLICATION_CHANGE_ID);
      assertEquals(populatedMessage.getLocalAssuranceSatisfied(),
           DEFAULT_LOCAL_ASSURANCE_SATISFIED);
      assertEquals(populatedMessage.getRemoteAssuranceSatisfied(),
           DEFAULT_REMOTE_ASSURANCE_SATISFIED);
      assertEquals(populatedMessage.getServerResults(),
           DEFAULT_SERVER_ASSURANCE_RESULTS);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "ou=test,dc=example,dc=com");
      assertEquals(populatedMessage.getAttributeNames(),
           StaticUtils.setOf("objectClass", "ou"));
      assertEquals(populatedMessage.getUndeleteFromDN(),
           "cn=undelete,cn=from,cn=dn");

      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a bind request log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindRequestLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, REQUEST, BIND, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, REQUEST, BIND, true);
    appendField(populatedBuffer, BIND_PROTOCOL_VERSION, "3");
    appendField(populatedBuffer, BIND_AUTHENTICATION_TYPE,
              BindRequestAuthenticationType.SASL.name());
    appendField(populatedBuffer, BIND_DN, "");
    appendField(populatedBuffer, BIND_SASL_MECHANISM, "PLAIN");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedBindRequestAccessLogMessage minimalMessage =
           (TextFormattedBindRequestAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedBindRequestAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), REQUEST);
      assertEquals(minimalMessage.getOperationType(), BIND);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());

      // Message-specific fields.
      assertNull(minimalMessage.getProtocolVersion());
      assertNull(minimalMessage.getAuthenticationType());
      assertNull(minimalMessage.getDN());
      assertNull(minimalMessage.getSASLMechanismName());


      // Read the fully-populated log message.
      TextFormattedBindRequestAccessLogMessage populatedMessage =
           (TextFormattedBindRequestAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedBindRequestAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), REQUEST);
      assertEquals(populatedMessage.getOperationType(), BIND);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);

      // Message-specific fields.
      assertEquals(populatedMessage.getProtocolVersion(), "3");
      assertEquals(populatedMessage.getAuthenticationType(),
           BindRequestAuthenticationType.SASL);
      assertEquals(populatedMessage.getDN(), "");
      assertEquals(populatedMessage.getSASLMechanismName(), "PLAIN");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a bind forward log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindForwardLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, FORWARD, BIND, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, FORWARD, BIND, true);
    appendField(populatedBuffer, BIND_PROTOCOL_VERSION, "3");
    appendField(populatedBuffer, BIND_AUTHENTICATION_TYPE,
              BindRequestAuthenticationType.SASL.name());
    appendField(populatedBuffer, BIND_DN, "");
    appendField(populatedBuffer, BIND_SASL_MECHANISM, "PLAIN");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedBindForwardAccessLogMessage minimalMessage =
           (TextFormattedBindForwardAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedBindForwardAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), FORWARD);
      assertEquals(minimalMessage.getOperationType(), BIND);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());

      // Message-specific fields.
      assertNull(minimalMessage.getProtocolVersion());
      assertNull(minimalMessage.getAuthenticationType());
      assertNull(minimalMessage.getDN());
      assertNull(minimalMessage.getSASLMechanismName());


      // Read the fully-populated log message.
      TextFormattedBindForwardAccessLogMessage populatedMessage =
           (TextFormattedBindForwardAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedBindForwardAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), FORWARD);
      assertEquals(populatedMessage.getOperationType(), BIND);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);

      // Message-specific fields.
      assertEquals(populatedMessage.getProtocolVersion(), "3");
      assertEquals(populatedMessage.getAuthenticationType(),
           BindRequestAuthenticationType.SASL);
      assertEquals(populatedMessage.getDN(), "");
      assertEquals(populatedMessage.getSASLMechanismName(), "PLAIN");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a bind forward failed log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindForwardFailedLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, FORWARD_FAILED, BIND, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, FORWARD_FAILED, BIND, true);
    appendField(populatedBuffer, BIND_PROTOCOL_VERSION, "3");
    appendField(populatedBuffer, BIND_AUTHENTICATION_TYPE,
              BindRequestAuthenticationType.SASL.name());
    appendField(populatedBuffer, BIND_DN, "");
    appendField(populatedBuffer, BIND_SASL_MECHANISM, "PLAIN");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedBindForwardFailedAccessLogMessage minimalMessage =
           (TextFormattedBindForwardFailedAccessLogMessage)
           reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedBindForwardFailedAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(minimalMessage.getOperationType(), BIND);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());

      // Message-specific fields.
      assertNull(minimalMessage.getProtocolVersion());
      assertNull(minimalMessage.getAuthenticationType());
      assertNull(minimalMessage.getDN());
      assertNull(minimalMessage.getSASLMechanismName());


      // Read the fully-populated log message.
      TextFormattedBindForwardFailedAccessLogMessage populatedMessage =
           (TextFormattedBindForwardFailedAccessLogMessage)
           reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedBindForwardFailedAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(populatedMessage.getOperationType(), BIND);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);

      // Message-specific fields.
      assertEquals(populatedMessage.getProtocolVersion(), "3");
      assertEquals(populatedMessage.getAuthenticationType(),
           BindRequestAuthenticationType.SASL);
      assertEquals(populatedMessage.getDN(), "");
      assertEquals(populatedMessage.getSASLMechanismName(), "PLAIN");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a bind result log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindResultLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, RESULT, BIND, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, RESULT, BIND, true);
    appendField(populatedBuffer, BIND_PROTOCOL_VERSION, "3");
    appendField(populatedBuffer, BIND_AUTHENTICATION_TYPE,
              BindRequestAuthenticationType.SASL.name());
    appendField(populatedBuffer, BIND_DN, "");
    appendField(populatedBuffer, BIND_SASL_MECHANISM, "PLAIN");
    appendField(populatedBuffer, BIND_AUTHENTICATION_DN,
         "cn=authentication,cn=dn");
    appendField(populatedBuffer, BIND_AUTHORIZATION_DN,
         "cn=authorization,cn=dn");
    appendField(populatedBuffer, BIND_AUTHENTICATION_FAILURE_ID,
          AuthenticationFailureReason.FAILURE_TYPE_ACCOUNT_NOT_USABLE);
    appendField(populatedBuffer, BIND_AUTHENTICATION_FAILURE_NAME,
          AuthenticationFailureReason.FAILURE_NAME_ACCOUNT_NOT_USABLE);
    appendField(populatedBuffer, BIND_AUTHENTICATION_FAILURE_REASON,
          "failure-reason-message");
    appendField(populatedBuffer, BIND_RETIRED_PASSWORD_USED, false);
    appendField(populatedBuffer, CLIENT_CONNECTION_POLICY,
         "client-connection-policy");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());


    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedBindResultAccessLogMessage minimalMessage =
           (TextFormattedBindResultAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), RESULT);
      assertEquals(minimalMessage.getOperationType(), BIND);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());
      assertNull(minimalMessage.getAdditionalInformation());
      assertNull(minimalMessage.getMatchedDN());
      assertEquals(minimalMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalMessage.getUncachedDataAccessed());
      assertNull(minimalMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalMessage.getProcessingTimeMillis());
      assertNull(minimalMessage.getIntermediateResponsesReturned());
      assertEquals(minimalMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getMissingPrivileges(),
           Collections.emptySet());

      // Message-specific fields.
      assertNull(minimalMessage.getProtocolVersion());
      assertNull(minimalMessage.getAuthenticationType());
      assertNull(minimalMessage.getDN());
      assertNull(minimalMessage.getSASLMechanismName());
      assertNull(minimalMessage.getAuthenticationDN());
      assertNull(minimalMessage.getAuthorizationDN());
      assertNull(minimalMessage.getAuthenticationFailureID());
      assertNull(minimalMessage.getAuthenticationFailureName());
      assertNull(minimalMessage.getAuthenticationFailureMessage());
      assertNull(minimalMessage.getRetiredPasswordUsed());
      assertNull(minimalMessage.getClientConnectionPolicy());


      // Read the fully-populated log message.
      TextFormattedBindResultAccessLogMessage populatedMessage =
           (TextFormattedBindResultAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedBindResultAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), RESULT);
      assertEquals(populatedMessage.getOperationType(), BIND);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);

      // Message-specific fields.
      assertEquals(populatedMessage.getProtocolVersion(), "3");
      assertEquals(populatedMessage.getAuthenticationType(),
           BindRequestAuthenticationType.SASL);
      assertEquals(populatedMessage.getDN(), "");
      assertEquals(populatedMessage.getSASLMechanismName(), "PLAIN");
      assertEquals(populatedMessage.getAuthenticationDN(),
           "cn=authentication,cn=dn");
      assertEquals(populatedMessage.getAuthorizationDN(),
           "cn=authorization,cn=dn");
      assertEquals(populatedMessage.getAuthenticationFailureID().intValue(),
           AuthenticationFailureReason.FAILURE_TYPE_ACCOUNT_NOT_USABLE);
      assertEquals(populatedMessage.getAuthenticationFailureName(),
           AuthenticationFailureReason.FAILURE_NAME_ACCOUNT_NOT_USABLE);
      assertEquals(populatedMessage.getAuthenticationFailureMessage(),
           "failure-reason-message");
      assertEquals(populatedMessage.getRetiredPasswordUsed(),
           Boolean.FALSE);
      assertEquals(populatedMessage.getClientConnectionPolicy(),
           "client-connection-policy");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a compare request log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareRequestLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, REQUEST, COMPARE, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, REQUEST, COMPARE, true);
    appendField(populatedBuffer, COMPARE_ENTRY_DN, "cn=compare,cn=dn");
    appendField(populatedBuffer, COMPARE_ATTRIBUTE_NAME, "description");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedCompareRequestAccessLogMessage minimalMessage =
           (TextFormattedCompareRequestAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedCompareRequestAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), REQUEST);
      assertEquals(minimalMessage.getOperationType(), COMPARE);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());
      assertNull(minimalMessage.getAttributeName());


      // Read the fully-populated log message.
      TextFormattedCompareRequestAccessLogMessage populatedMessage =
           (TextFormattedCompareRequestAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedCompareRequestAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), REQUEST);
      assertEquals(populatedMessage.getOperationType(), COMPARE);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "cn=compare,cn=dn");
      assertEquals(populatedMessage.getAttributeName(), "description");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a compare forward log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareForwardLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, FORWARD, COMPARE, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, FORWARD, COMPARE, true);
    appendField(populatedBuffer, COMPARE_ENTRY_DN, "cn=compare,cn=dn");
    appendField(populatedBuffer, COMPARE_ATTRIBUTE_NAME, "description");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedCompareForwardAccessLogMessage minimalMessage =
           (TextFormattedCompareForwardAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedCompareForwardAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), FORWARD);
      assertEquals(minimalMessage.getOperationType(), COMPARE);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());
      assertNull(minimalMessage.getAttributeName());


      // Read the fully-populated log message.
      TextFormattedCompareForwardAccessLogMessage populatedMessage =
           (TextFormattedCompareForwardAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedCompareForwardAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), FORWARD);
      assertEquals(populatedMessage.getOperationType(), COMPARE);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "cn=compare,cn=dn");
      assertEquals(populatedMessage.getAttributeName(), "description");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a compare forward failed log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareForwardFailedLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, FORWARD_FAILED, COMPARE, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, FORWARD_FAILED, COMPARE, true);
    appendField(populatedBuffer, COMPARE_ENTRY_DN, "cn=compare,cn=dn");
    appendField(populatedBuffer, COMPARE_ATTRIBUTE_NAME, "description");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedCompareForwardFailedAccessLogMessage minimalMessage =
           (TextFormattedCompareForwardFailedAccessLogMessage)
           reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedCompareForwardFailedAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(minimalMessage.getOperationType(), COMPARE);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());
      assertNull(minimalMessage.getAttributeName());


      // Read the fully-populated log message.
      TextFormattedCompareForwardFailedAccessLogMessage populatedMessage =
           (TextFormattedCompareForwardFailedAccessLogMessage)
           reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedCompareForwardFailedAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(populatedMessage.getOperationType(), COMPARE);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "cn=compare,cn=dn");
      assertEquals(populatedMessage.getAttributeName(), "description");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a compare result log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareResultLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, RESULT, COMPARE, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, RESULT, COMPARE, true);
    appendField(populatedBuffer, COMPARE_ENTRY_DN, "cn=compare,cn=dn");
    appendField(populatedBuffer, COMPARE_ATTRIBUTE_NAME, "description");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedCompareResultAccessLogMessage minimalMessage =
           (TextFormattedCompareResultAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedCompareResultAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), RESULT);
      assertEquals(minimalMessage.getOperationType(), COMPARE);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());
      assertNull(minimalMessage.getAdditionalInformation());
      assertNull(minimalMessage.getMatchedDN());
      assertEquals(minimalMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalMessage.getUncachedDataAccessed());
      assertNull(minimalMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalMessage.getProcessingTimeMillis());
      assertNull(minimalMessage.getIntermediateResponsesReturned());
      assertEquals(minimalMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getMissingPrivileges(),
           Collections.emptySet());
      assertNull(minimalMessage.getAlternateAuthorizationDN());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());
      assertNull(minimalMessage.getAttributeName());


      // Read the fully-populated log message.
      TextFormattedCompareResultAccessLogMessage populatedMessage =
           (TextFormattedCompareResultAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedCompareResultAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), RESULT);
      assertEquals(populatedMessage.getOperationType(), COMPARE);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);
      assertEquals(populatedMessage.getAlternateAuthorizationDN(),
           DEFAULT_AUTHZ_DN);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "cn=compare,cn=dn");
      assertEquals(populatedMessage.getAttributeName(), "description");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a delete request log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteRequestLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, REQUEST, DELETE, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, REQUEST, DELETE, true);
    appendField(populatedBuffer, DELETE_ENTRY_DN, "cn=delete,cn=dn");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedDeleteRequestAccessLogMessage minimalMessage =
           (TextFormattedDeleteRequestAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedDeleteRequestAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), REQUEST);
      assertEquals(minimalMessage.getOperationType(), DELETE);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());


      // Read the fully-populated log message.
      TextFormattedDeleteRequestAccessLogMessage populatedMessage =
           (TextFormattedDeleteRequestAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedDeleteRequestAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), REQUEST);
      assertEquals(populatedMessage.getOperationType(), DELETE);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "cn=delete,cn=dn");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a delete forward log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteForwardLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, FORWARD, DELETE, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, FORWARD, DELETE, true);
    appendField(populatedBuffer, DELETE_ENTRY_DN, "cn=delete,cn=dn");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedDeleteForwardAccessLogMessage minimalMessage =
           (TextFormattedDeleteForwardAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedDeleteForwardAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), FORWARD);
      assertEquals(minimalMessage.getOperationType(), DELETE);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());


      // Read the fully-populated log message.
      TextFormattedDeleteForwardAccessLogMessage populatedMessage =
           (TextFormattedDeleteForwardAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedDeleteForwardAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), FORWARD);
      assertEquals(populatedMessage.getOperationType(), DELETE);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "cn=delete,cn=dn");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a delete forward failed log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteForwardFailedLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, FORWARD_FAILED, DELETE, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, FORWARD_FAILED, DELETE, true);
    appendField(populatedBuffer, DELETE_ENTRY_DN, "cn=delete,cn=dn");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedDeleteForwardFailedAccessLogMessage minimalMessage =
           (TextFormattedDeleteForwardFailedAccessLogMessage)
           reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedDeleteForwardFailedAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(minimalMessage.getOperationType(), DELETE);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());


      // Read the fully-populated log message.
      TextFormattedDeleteForwardFailedAccessLogMessage populatedMessage =
           (TextFormattedDeleteForwardFailedAccessLogMessage)
           reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedDeleteForwardFailedAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(populatedMessage.getOperationType(), DELETE);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "cn=delete,cn=dn");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a delete result log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteResultLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, RESULT, DELETE, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, RESULT, DELETE, true);
    appendField(populatedBuffer, DELETE_ENTRY_DN, "cn=delete,cn=dn");
    appendField(populatedBuffer, DELETE_SOFT_DELETED_ENTRY_DN,
         "cn=soft,cn=deleted");
    appendField(populatedBuffer, CHANGE_TO_SOFT_DELETED_ENTRY, false);

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedDeleteResultAccessLogMessage minimalMessage =
           (TextFormattedDeleteResultAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedDeleteResultAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), RESULT);
      assertEquals(minimalMessage.getOperationType(), DELETE);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());
      assertNull(minimalMessage.getAdditionalInformation());
      assertNull(minimalMessage.getMatchedDN());
      assertEquals(minimalMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalMessage.getUncachedDataAccessed());
      assertNull(minimalMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalMessage.getProcessingTimeMillis());
      assertNull(minimalMessage.getIntermediateResponsesReturned());
      assertEquals(minimalMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getMissingPrivileges(),
           Collections.emptySet());
      assertNull(minimalMessage.getAlternateAuthorizationDN());
      assertNull(minimalMessage.getAssuredReplicationLocalLevel());
      assertNull(minimalMessage.getAssuredReplicationRemoteLevel());
      assertNull(minimalMessage.getAssuredReplicationTimeoutMillis());
      assertNull(minimalMessage.getResponseDelayedByAssurance());
      assertEquals(minimalMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           Collections.emptySet());
      assertEquals(
           minimalMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           Collections.emptySet());
      assertNull(minimalMessage.getReplicationChangeID());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());
      assertNull(minimalMessage.getSoftDeletedEntryDN());
      assertNull(minimalMessage.getChangeToSoftDeletedEntry());


      // Read the fully-populated log message.
      TextFormattedDeleteResultAccessLogMessage populatedMessage =
           (TextFormattedDeleteResultAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedDeleteResultAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), RESULT);
      assertEquals(populatedMessage.getOperationType(), DELETE);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);
      assertEquals(populatedMessage.getAlternateAuthorizationDN(),
           DEFAULT_AUTHZ_DN);
      assertEquals(populatedMessage.getAssuredReplicationLocalLevel(),
           DEFAULT_LOCAL_ASSURANCE_LEVEL);
      assertEquals(populatedMessage.getAssuredReplicationRemoteLevel(),
           DEFAULT_REMOTE_ASSURANCE_LEVEL);
      assertEquals(
           populatedMessage.getAssuredReplicationTimeoutMillis().longValue(),
           DEFAULT_ASSURANCE_TIMEOUT_MILLIS);
      assertEquals(populatedMessage.getResponseDelayedByAssurance(),
           DEFAULT_RESPONSE_DELAYED_BY_ASSURANCE);
      assertEquals(
           populatedMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           DEFAULT_INDEXES_NEAR_ENTRY_LIMIT);
      assertEquals(
           populatedMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           DEFAULT_INDEXES_EXCEEDING_ENTRY_LIMIT);
      assertEquals(populatedMessage.getReplicationChangeID(),
           DEFAULT_REPLICATION_CHANGE_ID);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "cn=delete,cn=dn");
      assertEquals(populatedMessage.getSoftDeletedEntryDN(),
           "cn=soft,cn=deleted");
      assertEquals(populatedMessage.getChangeToSoftDeletedEntry(),
           Boolean.FALSE);

      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a delete assurance complete log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteAssuranceCompleteLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, ASSURANCE_COMPLETE, DELETE, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, ASSURANCE_COMPLETE, DELETE, true);
    appendField(populatedBuffer, DELETE_ENTRY_DN, "cn=delete,cn=dn");
    appendField(populatedBuffer, DELETE_SOFT_DELETED_ENTRY_DN,
         "cn=soft,cn=deleted");
    appendField(populatedBuffer, CHANGE_TO_SOFT_DELETED_ENTRY, false);

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedDeleteAssuranceCompletedAccessLogMessage minimalMessage =
           (TextFormattedDeleteAssuranceCompletedAccessLogMessage)
           reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage =
           new TextFormattedDeleteAssuranceCompletedAccessLogMessage(
                minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), ASSURANCE_COMPLETE);
      assertEquals(minimalMessage.getOperationType(), DELETE);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());
      assertNull(minimalMessage.getAdditionalInformation());
      assertNull(minimalMessage.getMatchedDN());
      assertEquals(minimalMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalMessage.getUncachedDataAccessed());
      assertNull(minimalMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalMessage.getProcessingTimeMillis());
      assertNull(minimalMessage.getIntermediateResponsesReturned());
      assertEquals(minimalMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getMissingPrivileges(),
           Collections.emptySet());
      assertNull(minimalMessage.getAlternateAuthorizationDN());
      assertNull(minimalMessage.getAssuredReplicationLocalLevel());
      assertNull(minimalMessage.getAssuredReplicationRemoteLevel());
      assertNull(minimalMessage.getAssuredReplicationTimeoutMillis());
      assertNull(minimalMessage.getResponseDelayedByAssurance());
      assertEquals(minimalMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           Collections.emptySet());
      assertEquals(
           minimalMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           Collections.emptySet());
      assertNull(minimalMessage.getReplicationChangeID());
      assertNull(minimalMessage.getLocalAssuranceSatisfied());
      assertNull(minimalMessage.getRemoteAssuranceSatisfied());
      assertEquals(minimalMessage.getServerResults(),
           Collections.emptyList());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());
      assertNull(minimalMessage.getSoftDeletedEntryDN());
      assertNull(minimalMessage.getChangeToSoftDeletedEntry());


      // Read the fully-populated log message.
      TextFormattedDeleteAssuranceCompletedAccessLogMessage populatedMessage =
           (TextFormattedDeleteAssuranceCompletedAccessLogMessage)
           reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage =
           new TextFormattedDeleteAssuranceCompletedAccessLogMessage(
                populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), ASSURANCE_COMPLETE);
      assertEquals(populatedMessage.getOperationType(), DELETE);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);
      assertEquals(populatedMessage.getAlternateAuthorizationDN(),
           DEFAULT_AUTHZ_DN);
      assertEquals(populatedMessage.getAssuredReplicationLocalLevel(),
           DEFAULT_LOCAL_ASSURANCE_LEVEL);
      assertEquals(populatedMessage.getAssuredReplicationRemoteLevel(),
           DEFAULT_REMOTE_ASSURANCE_LEVEL);
      assertEquals(
           populatedMessage.getAssuredReplicationTimeoutMillis().longValue(),
           DEFAULT_ASSURANCE_TIMEOUT_MILLIS);
      assertEquals(populatedMessage.getResponseDelayedByAssurance(),
           DEFAULT_RESPONSE_DELAYED_BY_ASSURANCE);
      assertEquals(
           populatedMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           DEFAULT_INDEXES_NEAR_ENTRY_LIMIT);
      assertEquals(
           populatedMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           DEFAULT_INDEXES_EXCEEDING_ENTRY_LIMIT);
      assertEquals(populatedMessage.getReplicationChangeID(),
           DEFAULT_REPLICATION_CHANGE_ID);
      assertEquals(populatedMessage.getLocalAssuranceSatisfied(),
           DEFAULT_LOCAL_ASSURANCE_SATISFIED);
      assertEquals(populatedMessage.getRemoteAssuranceSatisfied(),
           DEFAULT_REMOTE_ASSURANCE_SATISFIED);
      assertEquals(populatedMessage.getServerResults(),
           DEFAULT_SERVER_ASSURANCE_RESULTS);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "cn=delete,cn=dn");
      assertEquals(populatedMessage.getSoftDeletedEntryDN(),
           "cn=soft,cn=deleted");
      assertEquals(populatedMessage.getChangeToSoftDeletedEntry(),
           Boolean.FALSE);

      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read an extended request log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedRequestLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, REQUEST, EXTENDED, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, REQUEST, EXTENDED, true);
    appendField(populatedBuffer, EXTENDED_REQUEST_OID, "1.2.3.4.5");
    appendField(populatedBuffer, EXTENDED_REQUEST_TYPE,
         "extended-request-type");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedExtendedRequestAccessLogMessage minimalMessage =
           (TextFormattedExtendedRequestAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedExtendedRequestAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), REQUEST);
      assertEquals(minimalMessage.getOperationType(), EXTENDED);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());

      // Message-specific fields.
      assertNull(minimalMessage.getRequestOID());
      assertNull(minimalMessage.getRequestType());


      // Read the fully-populated log message.
      TextFormattedExtendedRequestAccessLogMessage populatedMessage =
           (TextFormattedExtendedRequestAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedExtendedRequestAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), REQUEST);
      assertEquals(populatedMessage.getOperationType(), EXTENDED);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);

      // Message-specific fields.
      assertEquals(populatedMessage.getRequestOID(), "1.2.3.4.5");
      assertEquals(populatedMessage.getRequestType(),
           "extended-request-type");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read an extended forward log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedForwardLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, FORWARD, EXTENDED, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, FORWARD, EXTENDED, true);
    appendField(populatedBuffer, EXTENDED_REQUEST_OID, "1.2.3.4.5");
    appendField(populatedBuffer, EXTENDED_REQUEST_TYPE,
         "extended-request-type");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedExtendedForwardAccessLogMessage minimalMessage =
           (TextFormattedExtendedForwardAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedExtendedForwardAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), FORWARD);
      assertEquals(minimalMessage.getOperationType(), EXTENDED);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());

      // Message-specific fields.
      assertNull(minimalMessage.getRequestOID());
      assertNull(minimalMessage.getRequestType());


      // Read the fully-populated log message.
      TextFormattedExtendedForwardAccessLogMessage populatedMessage =
           (TextFormattedExtendedForwardAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedExtendedForwardAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), FORWARD);
      assertEquals(populatedMessage.getOperationType(), EXTENDED);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);

      // Message-specific fields.
      assertEquals(populatedMessage.getRequestOID(), "1.2.3.4.5");
      assertEquals(populatedMessage.getRequestType(),
           "extended-request-type");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read an extended forward failed log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedForwardFailedLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, FORWARD_FAILED, EXTENDED, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, FORWARD_FAILED, EXTENDED, true);
    appendField(populatedBuffer, EXTENDED_REQUEST_OID, "1.2.3.4.5");
    appendField(populatedBuffer, EXTENDED_REQUEST_TYPE,
         "extended-request-type");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedExtendedForwardFailedAccessLogMessage minimalMessage =
           (TextFormattedExtendedForwardFailedAccessLogMessage)
           reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedExtendedForwardFailedAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(minimalMessage.getOperationType(), EXTENDED);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());

      // Message-specific fields.
      assertNull(minimalMessage.getRequestOID());
      assertNull(minimalMessage.getRequestType());


      // Read the fully-populated log message.
      TextFormattedExtendedForwardFailedAccessLogMessage populatedMessage =
           (TextFormattedExtendedForwardFailedAccessLogMessage)
           reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedExtendedForwardFailedAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(populatedMessage.getOperationType(), EXTENDED);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);

      // Message-specific fields.
      assertEquals(populatedMessage.getRequestOID(), "1.2.3.4.5");
      assertEquals(populatedMessage.getRequestType(),
           "extended-request-type");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read an extended result log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedResultLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, RESULT, EXTENDED, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, RESULT, EXTENDED, true);
    appendField(populatedBuffer, EXTENDED_REQUEST_OID, "1.2.3.4.5");
    appendField(populatedBuffer, EXTENDED_REQUEST_TYPE,
         "extended-request-type");
    appendField(populatedBuffer, EXTENDED_RESPONSE_OID, "1.2.3.4.6");
    appendField(populatedBuffer, EXTENDED_RESPONSE_TYPE,
         "extended-response-type");
    appendField(populatedBuffer, CLIENT_CONNECTION_POLICY,
         "client-connection-policy");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedExtendedResultAccessLogMessage minimalMessage =
           (TextFormattedExtendedResultAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedExtendedResultAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), RESULT);
      assertEquals(minimalMessage.getOperationType(), EXTENDED);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());
      assertNull(minimalMessage.getAdditionalInformation());
      assertNull(minimalMessage.getMatchedDN());
      assertEquals(minimalMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalMessage.getUncachedDataAccessed());
      assertNull(minimalMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalMessage.getProcessingTimeMillis());
      assertNull(minimalMessage.getIntermediateResponsesReturned());
      assertEquals(minimalMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getMissingPrivileges(),
           Collections.emptySet());

      // Message-specific fields.
      assertNull(minimalMessage.getRequestOID());
      assertNull(minimalMessage.getRequestType());
      assertNull(minimalMessage.getResponseOID());
      assertNull(minimalMessage.getResponseType());
      assertNull(minimalMessage.getClientConnectionPolicy());


      // Read the fully-populated log message.
      TextFormattedExtendedResultAccessLogMessage populatedMessage =
           (TextFormattedExtendedResultAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedExtendedResultAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), RESULT);
      assertEquals(populatedMessage.getOperationType(), EXTENDED);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);

      // Message-specific fields.
      assertEquals(populatedMessage.getRequestOID(), "1.2.3.4.5");
      assertEquals(populatedMessage.getRequestType(),
           "extended-request-type");
      assertEquals(populatedMessage.getResponseOID(), "1.2.3.4.6");
      assertEquals(populatedMessage.getResponseType(),
           "extended-response-type");
      assertEquals(populatedMessage.getClientConnectionPolicy(),
           "client-connection-policy");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a modify request log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyRequestLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, REQUEST, MODIFY, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, REQUEST, MODIFY, true);
    appendField(populatedBuffer, MODIFY_ENTRY_DN, "cn=modify,cn=dn");
    appendField(populatedBuffer, MODIFY_ATTRIBUTES, "mod-attr-1", "mod-attr-2");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedModifyRequestAccessLogMessage minimalMessage =
           (TextFormattedModifyRequestAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedModifyRequestAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), REQUEST);
      assertEquals(minimalMessage.getOperationType(), MODIFY);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());
      assertEquals(minimalMessage.getAttributeNames(),
           Collections.emptySet());


      // Read the fully-populated log message.
      TextFormattedModifyRequestAccessLogMessage populatedMessage =
           (TextFormattedModifyRequestAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedModifyRequestAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), REQUEST);
      assertEquals(populatedMessage.getOperationType(), MODIFY);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "cn=modify,cn=dn");
      assertEquals(populatedMessage.getAttributeNames(),
           StaticUtils.setOf("mod-attr-1", "mod-attr-2"));


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a modify forward log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyForwardLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, FORWARD, MODIFY, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, FORWARD, MODIFY, true);
    appendField(populatedBuffer, MODIFY_ENTRY_DN, "cn=modify,cn=dn");
    appendField(populatedBuffer, MODIFY_ATTRIBUTES, "mod-attr-1", "mod-attr-2");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedModifyForwardAccessLogMessage minimalMessage =
           (TextFormattedModifyForwardAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedModifyForwardAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), FORWARD);
      assertEquals(minimalMessage.getOperationType(), MODIFY);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());
      assertEquals(minimalMessage.getAttributeNames(),
           Collections.emptySet());


      // Read the fully-populated log message.
      TextFormattedModifyForwardAccessLogMessage populatedMessage =
           (TextFormattedModifyForwardAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedModifyForwardAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), FORWARD);
      assertEquals(populatedMessage.getOperationType(), MODIFY);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "cn=modify,cn=dn");
      assertEquals(populatedMessage.getAttributeNames(),
           StaticUtils.setOf("mod-attr-1", "mod-attr-2"));


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a modify forward failed log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyForwardFailedLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, FORWARD_FAILED, MODIFY, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, FORWARD_FAILED, MODIFY, true);
    appendField(populatedBuffer, MODIFY_ENTRY_DN, "cn=modify,cn=dn");
    appendField(populatedBuffer, MODIFY_ATTRIBUTES, "mod-attr-1", "mod-attr-2");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedModifyForwardFailedAccessLogMessage minimalMessage =
           (TextFormattedModifyForwardFailedAccessLogMessage)
           reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedModifyForwardFailedAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(minimalMessage.getOperationType(), MODIFY);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());
      assertEquals(minimalMessage.getAttributeNames(),
           Collections.emptySet());


      // Read the fully-populated log message.
      TextFormattedModifyForwardFailedAccessLogMessage populatedMessage =
           (TextFormattedModifyForwardFailedAccessLogMessage)
           reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedModifyForwardFailedAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(populatedMessage.getOperationType(), MODIFY);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "cn=modify,cn=dn");
      assertEquals(populatedMessage.getAttributeNames(),
           StaticUtils.setOf("mod-attr-1", "mod-attr-2"));


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a modify result log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyResultLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, RESULT, MODIFY, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, RESULT, MODIFY, true);
    appendField(populatedBuffer, MODIFY_ENTRY_DN, "cn=modify,cn=dn");
    appendField(populatedBuffer, MODIFY_ATTRIBUTES, "mod-attr-1", "mod-attr-2");
    appendField(populatedBuffer, CHANGE_TO_SOFT_DELETED_ENTRY, false);

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedModifyResultAccessLogMessage minimalMessage =
           (TextFormattedModifyResultAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedModifyResultAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), RESULT);
      assertEquals(minimalMessage.getOperationType(), MODIFY);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());
      assertNull(minimalMessage.getAdditionalInformation());
      assertNull(minimalMessage.getMatchedDN());
      assertEquals(minimalMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalMessage.getUncachedDataAccessed());
      assertNull(minimalMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalMessage.getProcessingTimeMillis());
      assertNull(minimalMessage.getIntermediateResponsesReturned());
      assertEquals(minimalMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getMissingPrivileges(),
           Collections.emptySet());
      assertNull(minimalMessage.getAlternateAuthorizationDN());
      assertNull(minimalMessage.getAssuredReplicationLocalLevel());
      assertNull(minimalMessage.getAssuredReplicationRemoteLevel());
      assertNull(minimalMessage.getAssuredReplicationTimeoutMillis());
      assertNull(minimalMessage.getResponseDelayedByAssurance());
      assertEquals(minimalMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           Collections.emptySet());
      assertEquals(
           minimalMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           Collections.emptySet());
      assertNull(minimalMessage.getReplicationChangeID());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());
      assertEquals(minimalMessage.getAttributeNames(),
           Collections.emptySet());
      assertNull(minimalMessage.getChangeToSoftDeletedEntry());


      // Read the fully-populated log message.
      TextFormattedModifyResultAccessLogMessage populatedMessage =
           (TextFormattedModifyResultAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedModifyResultAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), RESULT);
      assertEquals(populatedMessage.getOperationType(), MODIFY);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);
      assertEquals(populatedMessage.getAlternateAuthorizationDN(),
           DEFAULT_AUTHZ_DN);
      assertEquals(populatedMessage.getAssuredReplicationLocalLevel(),
           DEFAULT_LOCAL_ASSURANCE_LEVEL);
      assertEquals(populatedMessage.getAssuredReplicationRemoteLevel(),
           DEFAULT_REMOTE_ASSURANCE_LEVEL);
      assertEquals(
           populatedMessage.getAssuredReplicationTimeoutMillis().longValue(),
           DEFAULT_ASSURANCE_TIMEOUT_MILLIS);
      assertEquals(populatedMessage.getResponseDelayedByAssurance(),
           DEFAULT_RESPONSE_DELAYED_BY_ASSURANCE);
      assertEquals(
           populatedMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           DEFAULT_INDEXES_NEAR_ENTRY_LIMIT);
      assertEquals(
           populatedMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           DEFAULT_INDEXES_EXCEEDING_ENTRY_LIMIT);
      assertEquals(populatedMessage.getReplicationChangeID(),
           DEFAULT_REPLICATION_CHANGE_ID);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "cn=modify,cn=dn");
      assertEquals(populatedMessage.getAttributeNames(),
           StaticUtils.setOf("mod-attr-1", "mod-attr-2"));
      assertEquals(populatedMessage.getChangeToSoftDeletedEntry(),
           Boolean.FALSE);

      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a modify assurance complete log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyAssuranceCompleteLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, ASSURANCE_COMPLETE, MODIFY, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, ASSURANCE_COMPLETE, MODIFY, true);
    appendField(populatedBuffer, MODIFY_ENTRY_DN, "cn=modify,cn=dn");
    appendField(populatedBuffer, MODIFY_ATTRIBUTES, "mod-attr-1", "mod-attr-2");
    appendField(populatedBuffer, CHANGE_TO_SOFT_DELETED_ENTRY, false);

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedModifyAssuranceCompletedAccessLogMessage minimalMessage =
           (TextFormattedModifyAssuranceCompletedAccessLogMessage)
           reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage =
           new TextFormattedModifyAssuranceCompletedAccessLogMessage(
                minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), ASSURANCE_COMPLETE);
      assertEquals(minimalMessage.getOperationType(), MODIFY);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());
      assertNull(minimalMessage.getAdditionalInformation());
      assertNull(minimalMessage.getMatchedDN());
      assertEquals(minimalMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalMessage.getUncachedDataAccessed());
      assertNull(minimalMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalMessage.getProcessingTimeMillis());
      assertNull(minimalMessage.getIntermediateResponsesReturned());
      assertEquals(minimalMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getMissingPrivileges(),
           Collections.emptySet());
      assertNull(minimalMessage.getAlternateAuthorizationDN());
      assertNull(minimalMessage.getAssuredReplicationLocalLevel());
      assertNull(minimalMessage.getAssuredReplicationRemoteLevel());
      assertNull(minimalMessage.getAssuredReplicationTimeoutMillis());
      assertNull(minimalMessage.getResponseDelayedByAssurance());
      assertEquals(minimalMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           Collections.emptySet());
      assertEquals(
           minimalMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           Collections.emptySet());
      assertNull(minimalMessage.getReplicationChangeID());
      assertNull(minimalMessage.getLocalAssuranceSatisfied());
      assertNull(minimalMessage.getRemoteAssuranceSatisfied());
      assertEquals(minimalMessage.getServerResults(),
           Collections.emptyList());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());
      assertNull(minimalMessage.getChangeToSoftDeletedEntry());


      // Read the fully-populated log message.
      TextFormattedModifyAssuranceCompletedAccessLogMessage populatedMessage =
           (TextFormattedModifyAssuranceCompletedAccessLogMessage)
           reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage =
           new TextFormattedModifyAssuranceCompletedAccessLogMessage(
                populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), ASSURANCE_COMPLETE);
      assertEquals(populatedMessage.getOperationType(), MODIFY);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);
      assertEquals(populatedMessage.getAlternateAuthorizationDN(),
           DEFAULT_AUTHZ_DN);
      assertEquals(populatedMessage.getAssuredReplicationLocalLevel(),
           DEFAULT_LOCAL_ASSURANCE_LEVEL);
      assertEquals(populatedMessage.getAssuredReplicationRemoteLevel(),
           DEFAULT_REMOTE_ASSURANCE_LEVEL);
      assertEquals(
           populatedMessage.getAssuredReplicationTimeoutMillis().longValue(),
           DEFAULT_ASSURANCE_TIMEOUT_MILLIS);
      assertEquals(populatedMessage.getResponseDelayedByAssurance(),
           DEFAULT_RESPONSE_DELAYED_BY_ASSURANCE);
      assertEquals(
           populatedMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           DEFAULT_INDEXES_NEAR_ENTRY_LIMIT);
      assertEquals(
           populatedMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           DEFAULT_INDEXES_EXCEEDING_ENTRY_LIMIT);
      assertEquals(populatedMessage.getReplicationChangeID(),
           DEFAULT_REPLICATION_CHANGE_ID);
      assertEquals(populatedMessage.getLocalAssuranceSatisfied(),
           DEFAULT_LOCAL_ASSURANCE_SATISFIED);
      assertEquals(populatedMessage.getRemoteAssuranceSatisfied(),
           DEFAULT_REMOTE_ASSURANCE_SATISFIED);
      assertEquals(populatedMessage.getServerResults(),
           DEFAULT_SERVER_ASSURANCE_RESULTS);


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a modify DN request log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNRequestLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, REQUEST, MODDN, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, REQUEST, MODDN, true);
    appendField(populatedBuffer, MODDN_ENTRY_DN, "cn=moddn,cn=entry,cn=dn");
    appendField(populatedBuffer, MODDN_NEW_RDN, "cn=newrdn");
    appendField(populatedBuffer, MODDN_DELETE_OLD_RDN, true);
    appendField(populatedBuffer, MODDN_NEW_SUPERIOR_DN,
         "cn=new,cn=superior,cn=dn");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedModifyDNRequestAccessLogMessage minimalMessage =
           (TextFormattedModifyDNRequestAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedModifyDNRequestAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), REQUEST);
      assertEquals(minimalMessage.getOperationType(), MODDN);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());
      assertNull(minimalMessage.getNewRDN());
      assertNull(minimalMessage.getDeleteOldRDN());
      assertNull(minimalMessage.getNewSuperiorDN());


      // Read the fully-populated log message.
      TextFormattedModifyDNRequestAccessLogMessage populatedMessage =
           (TextFormattedModifyDNRequestAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedModifyDNRequestAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), REQUEST);
      assertEquals(populatedMessage.getOperationType(), MODDN);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "cn=moddn,cn=entry,cn=dn");
      assertEquals(populatedMessage.getNewRDN(), "cn=newrdn");
      assertEquals(populatedMessage.getDeleteOldRDN(), Boolean.TRUE);
      assertEquals(populatedMessage.getNewSuperiorDN(),
           "cn=new,cn=superior,cn=dn");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a modify DN forward log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNForwardLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, FORWARD, MODDN, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, FORWARD, MODDN, true);
    appendField(populatedBuffer, MODDN_ENTRY_DN, "cn=moddn,cn=entry,cn=dn");
    appendField(populatedBuffer, MODDN_NEW_RDN, "cn=newrdn");
    appendField(populatedBuffer, MODDN_DELETE_OLD_RDN, true);
    appendField(populatedBuffer, MODDN_NEW_SUPERIOR_DN,
         "cn=new,cn=superior,cn=dn");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedModifyDNForwardAccessLogMessage minimalMessage =
           (TextFormattedModifyDNForwardAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedModifyDNForwardAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), FORWARD);
      assertEquals(minimalMessage.getOperationType(), MODDN);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());
      assertNull(minimalMessage.getNewRDN());
      assertNull(minimalMessage.getDeleteOldRDN());
      assertNull(minimalMessage.getNewSuperiorDN());


      // Read the fully-populated log message.
      TextFormattedModifyDNForwardAccessLogMessage populatedMessage =
           (TextFormattedModifyDNForwardAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedModifyDNForwardAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), FORWARD);
      assertEquals(populatedMessage.getOperationType(), MODDN);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "cn=moddn,cn=entry,cn=dn");
      assertEquals(populatedMessage.getNewRDN(), "cn=newrdn");
      assertEquals(populatedMessage.getDeleteOldRDN(), Boolean.TRUE);
      assertEquals(populatedMessage.getNewSuperiorDN(),
           "cn=new,cn=superior,cn=dn");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a modify DN forward failed log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNForwardFailedLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, FORWARD_FAILED, MODDN, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, FORWARD_FAILED, MODDN, true);
    appendField(populatedBuffer, MODDN_ENTRY_DN, "cn=moddn,cn=entry,cn=dn");
    appendField(populatedBuffer, MODDN_NEW_RDN, "cn=newrdn");
    appendField(populatedBuffer, MODDN_DELETE_OLD_RDN, true);
    appendField(populatedBuffer, MODDN_NEW_SUPERIOR_DN,
         "cn=new,cn=superior,cn=dn");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedModifyDNForwardFailedAccessLogMessage minimalMessage =
           (TextFormattedModifyDNForwardFailedAccessLogMessage)
           reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedModifyDNForwardFailedAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(minimalMessage.getOperationType(), MODDN);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());
      assertNull(minimalMessage.getNewRDN());
      assertNull(minimalMessage.getDeleteOldRDN());
      assertNull(minimalMessage.getNewSuperiorDN());


      // Read the fully-populated log message.
      TextFormattedModifyDNForwardFailedAccessLogMessage populatedMessage =
           (TextFormattedModifyDNForwardFailedAccessLogMessage)
           reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedModifyDNForwardFailedAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(populatedMessage.getOperationType(), MODDN);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "cn=moddn,cn=entry,cn=dn");
      assertEquals(populatedMessage.getNewRDN(), "cn=newrdn");
      assertEquals(populatedMessage.getDeleteOldRDN(), Boolean.TRUE);
      assertEquals(populatedMessage.getNewSuperiorDN(),
           "cn=new,cn=superior,cn=dn");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a modify DN result log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNResultLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, RESULT, MODDN, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, RESULT, MODDN, true);
    appendField(populatedBuffer, MODDN_ENTRY_DN, "cn=moddn,cn=entry,cn=dn");
    appendField(populatedBuffer, MODDN_NEW_RDN, "cn=newrdn");
    appendField(populatedBuffer, MODDN_DELETE_OLD_RDN, true);
    appendField(populatedBuffer, MODDN_NEW_SUPERIOR_DN,
         "cn=new,cn=superior,cn=dn");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedModifyDNResultAccessLogMessage minimalMessage =
           (TextFormattedModifyDNResultAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedModifyDNResultAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), RESULT);
      assertEquals(minimalMessage.getOperationType(), MODDN);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());
      assertNull(minimalMessage.getAdditionalInformation());
      assertNull(minimalMessage.getMatchedDN());
      assertEquals(minimalMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalMessage.getUncachedDataAccessed());
      assertNull(minimalMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalMessage.getProcessingTimeMillis());
      assertNull(minimalMessage.getIntermediateResponsesReturned());
      assertEquals(minimalMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getMissingPrivileges(),
           Collections.emptySet());
      assertNull(minimalMessage.getAlternateAuthorizationDN());
      assertNull(minimalMessage.getAssuredReplicationLocalLevel());
      assertNull(minimalMessage.getAssuredReplicationRemoteLevel());
      assertNull(minimalMessage.getAssuredReplicationTimeoutMillis());
      assertNull(minimalMessage.getResponseDelayedByAssurance());
      assertEquals(minimalMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           Collections.emptySet());
      assertEquals(
           minimalMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           Collections.emptySet());
      assertNull(minimalMessage.getReplicationChangeID());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());
      assertNull(minimalMessage.getNewRDN());
      assertNull(minimalMessage.getDeleteOldRDN());
      assertNull(minimalMessage.getNewSuperiorDN());


      // Read the fully-populated log message.
      TextFormattedModifyDNResultAccessLogMessage populatedMessage =
           (TextFormattedModifyDNResultAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedModifyDNResultAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), RESULT);
      assertEquals(populatedMessage.getOperationType(), MODDN);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);
      assertEquals(populatedMessage.getAlternateAuthorizationDN(),
           DEFAULT_AUTHZ_DN);
      assertEquals(populatedMessage.getAssuredReplicationLocalLevel(),
           DEFAULT_LOCAL_ASSURANCE_LEVEL);
      assertEquals(populatedMessage.getAssuredReplicationRemoteLevel(),
           DEFAULT_REMOTE_ASSURANCE_LEVEL);
      assertEquals(
           populatedMessage.getAssuredReplicationTimeoutMillis().longValue(),
           DEFAULT_ASSURANCE_TIMEOUT_MILLIS);
      assertEquals(populatedMessage.getResponseDelayedByAssurance(),
           DEFAULT_RESPONSE_DELAYED_BY_ASSURANCE);
      assertEquals(
           populatedMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           DEFAULT_INDEXES_NEAR_ENTRY_LIMIT);
      assertEquals(
           populatedMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           DEFAULT_INDEXES_EXCEEDING_ENTRY_LIMIT);
      assertEquals(populatedMessage.getReplicationChangeID(),
           DEFAULT_REPLICATION_CHANGE_ID);

      // Message-specific fields.
      assertEquals(populatedMessage.getDN(), "cn=moddn,cn=entry,cn=dn");
      assertEquals(populatedMessage.getNewRDN(), "cn=newrdn");
      assertEquals(populatedMessage.getDeleteOldRDN(), Boolean.TRUE);
      assertEquals(populatedMessage.getNewSuperiorDN(),
           "cn=new,cn=superior,cn=dn");

      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a modify DN assurance complete log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNAssuranceCompleteLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, ASSURANCE_COMPLETE, MODDN, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, ASSURANCE_COMPLETE, MODDN, true);
    appendField(populatedBuffer, MODDN_ENTRY_DN, "cn=moddn,cn=entry,cn=dn");
    appendField(populatedBuffer, MODDN_NEW_RDN, "cn=newrdn");
    appendField(populatedBuffer, MODDN_DELETE_OLD_RDN, true);
    appendField(populatedBuffer, MODDN_NEW_SUPERIOR_DN,
         "cn=new,cn=superior,cn=dn");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedModifyDNAssuranceCompletedAccessLogMessage minimalMessage =
           (TextFormattedModifyDNAssuranceCompletedAccessLogMessage)
           reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage =
           new TextFormattedModifyDNAssuranceCompletedAccessLogMessage(
                minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), ASSURANCE_COMPLETE);
      assertEquals(minimalMessage.getOperationType(), MODDN);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());
      assertNull(minimalMessage.getAdditionalInformation());
      assertNull(minimalMessage.getMatchedDN());
      assertEquals(minimalMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalMessage.getUncachedDataAccessed());
      assertNull(minimalMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalMessage.getProcessingTimeMillis());
      assertNull(minimalMessage.getIntermediateResponsesReturned());
      assertEquals(minimalMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getMissingPrivileges(),
           Collections.emptySet());
      assertNull(minimalMessage.getAlternateAuthorizationDN());
      assertNull(minimalMessage.getAssuredReplicationLocalLevel());
      assertNull(minimalMessage.getAssuredReplicationRemoteLevel());
      assertNull(minimalMessage.getAssuredReplicationTimeoutMillis());
      assertNull(minimalMessage.getResponseDelayedByAssurance());
      assertEquals(minimalMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           Collections.emptySet());
      assertEquals(
           minimalMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           Collections.emptySet());
      assertNull(minimalMessage.getReplicationChangeID());
      assertNull(minimalMessage.getLocalAssuranceSatisfied());
      assertNull(minimalMessage.getRemoteAssuranceSatisfied());
      assertEquals(minimalMessage.getServerResults(),
           Collections.emptyList());

      // Message-specific fields.
      assertNull(minimalMessage.getDN());
      assertNull(minimalMessage.getNewRDN());
      assertNull(minimalMessage.getDeleteOldRDN());
      assertNull(minimalMessage.getNewSuperiorDN());


      // Read the fully-populated log message.
      TextFormattedModifyDNAssuranceCompletedAccessLogMessage populatedMessage =
           (TextFormattedModifyDNAssuranceCompletedAccessLogMessage)
           reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage =
           new TextFormattedModifyDNAssuranceCompletedAccessLogMessage(
                populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), ASSURANCE_COMPLETE);
      assertEquals(populatedMessage.getOperationType(), MODDN);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);
      assertEquals(populatedMessage.getAlternateAuthorizationDN(),
           DEFAULT_AUTHZ_DN);
      assertEquals(populatedMessage.getAssuredReplicationLocalLevel(),
           DEFAULT_LOCAL_ASSURANCE_LEVEL);
      assertEquals(populatedMessage.getAssuredReplicationRemoteLevel(),
           DEFAULT_REMOTE_ASSURANCE_LEVEL);
      assertEquals(
           populatedMessage.getAssuredReplicationTimeoutMillis().longValue(),
           DEFAULT_ASSURANCE_TIMEOUT_MILLIS);
      assertEquals(populatedMessage.getResponseDelayedByAssurance(),
           DEFAULT_RESPONSE_DELAYED_BY_ASSURANCE);
      assertEquals(
           populatedMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           DEFAULT_INDEXES_NEAR_ENTRY_LIMIT);
      assertEquals(
           populatedMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           DEFAULT_INDEXES_EXCEEDING_ENTRY_LIMIT);
      assertEquals(populatedMessage.getReplicationChangeID(),
           DEFAULT_REPLICATION_CHANGE_ID);
      assertEquals(populatedMessage.getLocalAssuranceSatisfied(),
           DEFAULT_LOCAL_ASSURANCE_SATISFIED);
      assertEquals(populatedMessage.getRemoteAssuranceSatisfied(),
           DEFAULT_REMOTE_ASSURANCE_SATISFIED);
      assertEquals(populatedMessage.getServerResults(),
           DEFAULT_SERVER_ASSURANCE_RESULTS);


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a search request log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchRequestLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, REQUEST, SEARCH, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, REQUEST, SEARCH, true);
    appendField(populatedBuffer, SEARCH_BASE_DN, "cn=base,cn=dn");
    appendField(populatedBuffer, SEARCH_SCOPE_VALUE,
         SearchScope.SUB.intValue());
    appendField(populatedBuffer, SEARCH_FILTER, "(filter=value)");
    appendField(populatedBuffer, SEARCH_SIZE_LIMIT, 2345);
    appendField(populatedBuffer, SEARCH_TIME_LIMIT_SECONDS, 3456);
    appendField(populatedBuffer, SEARCH_DEREF_POLICY,
         DereferencePolicy.NEVER.getName());
    appendField(populatedBuffer, SEARCH_TYPES_ONLY, false);
    appendField(populatedBuffer, SEARCH_REQUESTED_ATTRIBUTES,
         "requested-attr-1", "requested-attr-2");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedSearchRequestAccessLogMessage minimalMessage =
           (TextFormattedSearchRequestAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedSearchRequestAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), REQUEST);
      assertEquals(minimalMessage.getOperationType(), SEARCH);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());

      // Message-specific fields.
      assertNull(minimalMessage.getBaseDN());
      assertNull(minimalMessage.getScope());
      assertNull(minimalMessage.getFilter());
      assertNull(minimalMessage.getSizeLimit());
      assertNull(minimalMessage.getTimeLimitSeconds());
      assertNull(minimalMessage.getDereferencePolicy());
      assertNull(minimalMessage.getTypesOnly());
      assertEquals(minimalMessage.getRequestedAttributes(),
           Collections.emptyList());


      // Read the fully-populated log message.
      TextFormattedSearchRequestAccessLogMessage populatedMessage =
           (TextFormattedSearchRequestAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedSearchRequestAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), REQUEST);
      assertEquals(populatedMessage.getOperationType(), SEARCH);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);


      // Message-specific fields.
      assertEquals(populatedMessage.getBaseDN(), "cn=base,cn=dn");
      assertEquals(populatedMessage.getScope(), SearchScope.SUB);
      assertEquals(populatedMessage.getFilter(), "(filter=value)");
      assertEquals(populatedMessage.getSizeLimit().intValue(), 2345);
      assertEquals(populatedMessage.getTimeLimitSeconds().intValue(), 3456);
      assertEquals(populatedMessage.getDereferencePolicy(),
           DereferencePolicy.NEVER);
      assertEquals(populatedMessage.getTypesOnly(), Boolean.FALSE);
      assertEquals(populatedMessage.getRequestedAttributes(),
           Arrays.asList("requested-attr-1", "requested-attr-2"));


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a search entry log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchEntryLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, ENTRY, SEARCH, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, ENTRY, SEARCH, true);
    appendField(populatedBuffer, SEARCH_BASE_DN, "cn=base,cn=dn");
    appendField(populatedBuffer, SEARCH_SCOPE_VALUE,
         SearchScope.SUB.intValue());
    appendField(populatedBuffer, SEARCH_FILTER, "(filter=value)");
    appendField(populatedBuffer, SEARCH_SIZE_LIMIT, 2345);
    appendField(populatedBuffer, SEARCH_TIME_LIMIT_SECONDS, 3456);
    appendField(populatedBuffer, SEARCH_DEREF_POLICY,
         DereferencePolicy.NEVER.getName());
    appendField(populatedBuffer, SEARCH_TYPES_ONLY, false);
    appendField(populatedBuffer, SEARCH_REQUESTED_ATTRIBUTES,
         "requested-attr-1", "requested-attr-2");
    appendField(populatedBuffer, SEARCH_RESULT_ENTRY_DN,
         "cn=search,cn=entry,cn=dn");
    appendField(populatedBuffer, SEARCH_RESULT_ENTRY_ATTRIBUTES, "entry-attr-1",
         "entry-attr-2");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedSearchEntryAccessLogMessage minimalMessage =
           (TextFormattedSearchEntryAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedSearchEntryAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), ENTRY);
      assertEquals(minimalMessage.getOperationType(), SEARCH);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertEquals(minimalMessage.getResponseControlOIDs(),
           Collections.emptySet());

      // Message-specific fields.
      assertNull(minimalMessage.getBaseDN());
      assertNull(minimalMessage.getScope());
      assertNull(minimalMessage.getFilter());
      assertNull(minimalMessage.getSizeLimit());
      assertNull(minimalMessage.getTimeLimitSeconds());
      assertNull(minimalMessage.getDereferencePolicy());
      assertNull(minimalMessage.getTypesOnly());
      assertEquals(minimalMessage.getRequestedAttributes(),
           Collections.emptyList());
      assertNull(minimalMessage.getDN());
      assertEquals(minimalMessage.getAttributesReturned(),
           Collections.emptySet());


      // Read the fully-populated log message.
      TextFormattedSearchEntryAccessLogMessage populatedMessage =
           (TextFormattedSearchEntryAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedSearchEntryAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), ENTRY);
      assertEquals(populatedMessage.getOperationType(), SEARCH);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);


      // Message-specific fields.
      assertEquals(populatedMessage.getBaseDN(), "cn=base,cn=dn");
      assertEquals(populatedMessage.getScope(), SearchScope.SUB);
      assertEquals(populatedMessage.getFilter(), "(filter=value)");
      assertEquals(populatedMessage.getSizeLimit().intValue(), 2345);
      assertEquals(populatedMessage.getTimeLimitSeconds().intValue(), 3456);
      assertEquals(populatedMessage.getDereferencePolicy(),
           DereferencePolicy.NEVER);
      assertEquals(populatedMessage.getTypesOnly(), Boolean.FALSE);
      assertEquals(populatedMessage.getRequestedAttributes(),
           Arrays.asList("requested-attr-1", "requested-attr-2"));
      assertEquals(populatedMessage.getDN(), "cn=search,cn=entry,cn=dn");
      assertEquals(populatedMessage.getAttributesReturned(),
           StaticUtils.setOf("entry-attr-1", "entry-attr-2"));


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a search reference log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchReferenceLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, REFERENCE, SEARCH, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, REFERENCE, SEARCH, true);
    appendField(populatedBuffer, SEARCH_BASE_DN, "cn=base,cn=dn");
    appendField(populatedBuffer, SEARCH_SCOPE_VALUE,
         SearchScope.SUB.intValue());
    appendField(populatedBuffer, SEARCH_FILTER, "(filter=value)");
    appendField(populatedBuffer, SEARCH_SIZE_LIMIT, 2345);
    appendField(populatedBuffer, SEARCH_TIME_LIMIT_SECONDS, 3456);
    appendField(populatedBuffer, SEARCH_DEREF_POLICY,
         DereferencePolicy.NEVER.getName());
    appendField(populatedBuffer, SEARCH_TYPES_ONLY, false);
    appendField(populatedBuffer, SEARCH_REQUESTED_ATTRIBUTES,
         "requested-attr-1", "requested-attr-2");
    appendField(populatedBuffer, REFERRAL_URLS,
         "ldap://server1.example.com:389/",
         "ldap://server2.example.com:389/");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedSearchReferenceAccessLogMessage minimalMessage =
           (TextFormattedSearchReferenceAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedSearchReferenceAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), REFERENCE);
      assertEquals(minimalMessage.getOperationType(), SEARCH);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertEquals(minimalMessage.getResponseControlOIDs(),
           Collections.emptySet());

      // Message-specific fields.
      assertNull(minimalMessage.getBaseDN());
      assertNull(minimalMessage.getScope());
      assertNull(minimalMessage.getFilter());
      assertNull(minimalMessage.getSizeLimit());
      assertNull(minimalMessage.getTimeLimitSeconds());
      assertNull(minimalMessage.getDereferencePolicy());
      assertNull(minimalMessage.getTypesOnly());
      assertEquals(minimalMessage.getRequestedAttributes(),
           Collections.emptyList());
      assertEquals(minimalMessage.getReferralURLs(),
           Collections.emptyList());


      // Read the fully-populated log message.
      TextFormattedSearchReferenceAccessLogMessage populatedMessage =
           (TextFormattedSearchReferenceAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedSearchReferenceAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), REFERENCE);
      assertEquals(populatedMessage.getOperationType(), SEARCH);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);


      // Message-specific fields.
      assertEquals(populatedMessage.getBaseDN(), "cn=base,cn=dn");
      assertEquals(populatedMessage.getScope(), SearchScope.SUB);
      assertEquals(populatedMessage.getFilter(), "(filter=value)");
      assertEquals(populatedMessage.getSizeLimit().intValue(), 2345);
      assertEquals(populatedMessage.getTimeLimitSeconds().intValue(), 3456);
      assertEquals(populatedMessage.getDereferencePolicy(),
           DereferencePolicy.NEVER);
      assertEquals(populatedMessage.getTypesOnly(), Boolean.FALSE);
      assertEquals(populatedMessage.getRequestedAttributes(),
           Arrays.asList("requested-attr-1", "requested-attr-2"));
      assertEquals(populatedMessage.getReferralURLs(),
           Arrays.asList(
                "ldap://server1.example.com:389/",
                "ldap://server2.example.com:389/"));


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a search forward log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchForwardLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, FORWARD, SEARCH, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, FORWARD, SEARCH, true);
    appendField(populatedBuffer, SEARCH_BASE_DN, "cn=base,cn=dn");
    appendField(populatedBuffer, SEARCH_SCOPE_VALUE,
         SearchScope.SUB.intValue());
    appendField(populatedBuffer, SEARCH_FILTER, "(filter=value)");
    appendField(populatedBuffer, SEARCH_SIZE_LIMIT, 2345);
    appendField(populatedBuffer, SEARCH_TIME_LIMIT_SECONDS, 3456);
    appendField(populatedBuffer, SEARCH_DEREF_POLICY,
         DereferencePolicy.NEVER.getName());
    appendField(populatedBuffer, SEARCH_TYPES_ONLY, false);
    appendField(populatedBuffer, SEARCH_REQUESTED_ATTRIBUTES,
         "requested-attr-1", "requested-attr-2");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedSearchForwardAccessLogMessage minimalMessage =
           (TextFormattedSearchForwardAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedSearchForwardAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), FORWARD);
      assertEquals(minimalMessage.getOperationType(), SEARCH);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());

      // Message-specific fields.
      assertNull(minimalMessage.getBaseDN());
      assertNull(minimalMessage.getScope());
      assertNull(minimalMessage.getFilter());
      assertNull(minimalMessage.getSizeLimit());
      assertNull(minimalMessage.getTimeLimitSeconds());
      assertNull(minimalMessage.getDereferencePolicy());
      assertNull(minimalMessage.getTypesOnly());
      assertEquals(minimalMessage.getRequestedAttributes(),
           Collections.emptyList());


      // Read the fully-populated log message.
      TextFormattedSearchForwardAccessLogMessage populatedMessage =
           (TextFormattedSearchForwardAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedSearchForwardAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), FORWARD);
      assertEquals(populatedMessage.getOperationType(), SEARCH);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);

      // Message-specific fields.
      assertEquals(populatedMessage.getBaseDN(), "cn=base,cn=dn");
      assertEquals(populatedMessage.getScope(), SearchScope.SUB);
      assertEquals(populatedMessage.getFilter(), "(filter=value)");
      assertEquals(populatedMessage.getSizeLimit().intValue(), 2345);
      assertEquals(populatedMessage.getTimeLimitSeconds().intValue(), 3456);
      assertEquals(populatedMessage.getDereferencePolicy(),
           DereferencePolicy.NEVER);
      assertEquals(populatedMessage.getTypesOnly(), Boolean.FALSE);
      assertEquals(populatedMessage.getRequestedAttributes(),
           Arrays.asList("requested-attr-1", "requested-attr-2"));


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a search forward failed log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchForwardFailedLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, FORWARD_FAILED, SEARCH, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, FORWARD_FAILED, SEARCH, true);
    appendField(populatedBuffer, SEARCH_BASE_DN, "cn=base,cn=dn");
    appendField(populatedBuffer, SEARCH_SCOPE_VALUE,
         SearchScope.SUB.intValue());
    appendField(populatedBuffer, SEARCH_FILTER, "(filter=value)");
    appendField(populatedBuffer, SEARCH_SIZE_LIMIT, 2345);
    appendField(populatedBuffer, SEARCH_TIME_LIMIT_SECONDS, 3456);
    appendField(populatedBuffer, SEARCH_DEREF_POLICY,
         DereferencePolicy.NEVER.getName());
    appendField(populatedBuffer, SEARCH_TYPES_ONLY, false);
    appendField(populatedBuffer, SEARCH_REQUESTED_ATTRIBUTES,
         "requested-attr-1", "requested-attr-2");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedSearchForwardFailedAccessLogMessage minimalMessage =
           (TextFormattedSearchForwardFailedAccessLogMessage)
           reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedSearchForwardFailedAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(minimalMessage.getOperationType(), SEARCH);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());

      // Message-specific fields.
      assertNull(minimalMessage.getBaseDN());
      assertNull(minimalMessage.getScope());
      assertNull(minimalMessage.getFilter());
      assertNull(minimalMessage.getSizeLimit());
      assertNull(minimalMessage.getTimeLimitSeconds());
      assertNull(minimalMessage.getDereferencePolicy());
      assertNull(minimalMessage.getTypesOnly());
      assertEquals(minimalMessage.getRequestedAttributes(),
           Collections.emptyList());


      // Read the fully-populated log message.
      TextFormattedSearchForwardFailedAccessLogMessage populatedMessage =
           (TextFormattedSearchForwardFailedAccessLogMessage)
           reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedSearchForwardFailedAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(populatedMessage.getOperationType(), SEARCH);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);

      // Message-specific fields.
      assertEquals(populatedMessage.getBaseDN(), "cn=base,cn=dn");
      assertEquals(populatedMessage.getScope(), SearchScope.SUB);
      assertEquals(populatedMessage.getFilter(), "(filter=value)");
      assertEquals(populatedMessage.getSizeLimit().intValue(), 2345);
      assertEquals(populatedMessage.getTimeLimitSeconds().intValue(), 3456);
      assertEquals(populatedMessage.getDereferencePolicy(),
           DereferencePolicy.NEVER);
      assertEquals(populatedMessage.getTypesOnly(), Boolean.FALSE);
      assertEquals(populatedMessage.getRequestedAttributes(),
           Arrays.asList("requested-attr-1", "requested-attr-2"));


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read a search result log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchResultLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, RESULT, SEARCH, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, RESULT, SEARCH, true);
    appendField(populatedBuffer, SEARCH_BASE_DN, "cn=base,cn=dn");
    appendField(populatedBuffer, SEARCH_SCOPE_VALUE,
         SearchScope.SUB.intValue());
    appendField(populatedBuffer, SEARCH_FILTER, "(filter=value)");
    appendField(populatedBuffer, SEARCH_SIZE_LIMIT, 2345);
    appendField(populatedBuffer, SEARCH_TIME_LIMIT_SECONDS, 3456);
    appendField(populatedBuffer, SEARCH_DEREF_POLICY,
         DereferencePolicy.NEVER.getName());
    appendField(populatedBuffer, SEARCH_TYPES_ONLY, false);
    appendField(populatedBuffer, SEARCH_REQUESTED_ATTRIBUTES,
         "requested-attr-1", "requested-attr-2");
    appendField(populatedBuffer, SEARCH_ENTRIES_RETURNED, 4567);
    appendField(populatedBuffer, SEARCH_UNINDEXED, false);

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedSearchResultAccessLogMessage minimalMessage =
           (TextFormattedSearchResultAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedSearchResultAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), RESULT);
      assertEquals(minimalMessage.getOperationType(), SEARCH);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());
      assertNull(minimalMessage.getTargetHost());
      assertNull(minimalMessage.getTargetPort());
      assertNull(minimalMessage.getTargetProtocol());
      assertNull(minimalMessage.getResultCode());
      assertNull(minimalMessage.getDiagnosticMessage());
      assertNull(minimalMessage.getAdditionalInformation());
      assertNull(minimalMessage.getMatchedDN());
      assertEquals(minimalMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalMessage.getUncachedDataAccessed());
      assertNull(minimalMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalMessage.getProcessingTimeMillis());
      assertNull(minimalMessage.getIntermediateResponsesReturned());
      assertEquals(minimalMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalMessage.getMissingPrivileges(),
           Collections.emptySet());
      assertNull(minimalMessage.getAlternateAuthorizationDN());
      assertEquals(minimalMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           Collections.emptySet());
      assertEquals(
           minimalMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           Collections.emptySet());

      // Message-specific fields.
      assertNull(minimalMessage.getBaseDN());
      assertNull(minimalMessage.getScope());
      assertNull(minimalMessage.getFilter());
      assertNull(minimalMessage.getSizeLimit());
      assertNull(minimalMessage.getTimeLimitSeconds());
      assertNull(minimalMessage.getDereferencePolicy());
      assertNull(minimalMessage.getTypesOnly());
      assertEquals(minimalMessage.getRequestedAttributes(),
           Collections.emptyList());
      assertNull(minimalMessage.getEntriesReturned());
      assertNull(minimalMessage.getUnindexed());


      // Read the fully-populated log message.
      TextFormattedSearchResultAccessLogMessage populatedMessage =
           (TextFormattedSearchResultAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedSearchResultAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), RESULT);
      assertEquals(populatedMessage.getOperationType(), SEARCH);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);
      assertEquals(populatedMessage.getAlternateAuthorizationDN(),
           DEFAULT_AUTHZ_DN);
      assertEquals(
           populatedMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           DEFAULT_INDEXES_NEAR_ENTRY_LIMIT);
      assertEquals(
           populatedMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           DEFAULT_INDEXES_EXCEEDING_ENTRY_LIMIT);

      // Message-specific fields.
      assertEquals(populatedMessage.getBaseDN(), "cn=base,cn=dn");
      assertEquals(populatedMessage.getScope(), SearchScope.SUB);
      assertEquals(populatedMessage.getFilter(), "(filter=value)");
      assertEquals(populatedMessage.getSizeLimit().intValue(), 2345);
      assertEquals(populatedMessage.getTimeLimitSeconds().intValue(), 3456);
      assertEquals(populatedMessage.getDereferencePolicy(),
           DereferencePolicy.NEVER);
      assertEquals(populatedMessage.getTypesOnly(), Boolean.FALSE);
      assertEquals(populatedMessage.getRequestedAttributes(),
           Arrays.asList("requested-attr-1", "requested-attr-2"));
      assertEquals(populatedMessage.getUnindexed(), Boolean.FALSE);


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read an unbind request log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnbindRequestLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, REQUEST, UNBIND, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, REQUEST, UNBIND, true);

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      TextFormattedUnbindRequestAccessLogMessage minimalMessage =
           (TextFormattedUnbindRequestAccessLogMessage) reader.readMessage();
      assertNotNull(minimalMessage);
      minimalMessage = new TextFormattedUnbindRequestAccessLogMessage(
           minimalMessage.toString());

      // Common fields.
      assertEquals(minimalMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalMessage.getMessageType(), REQUEST);
      assertEquals(minimalMessage.getOperationType(), UNBIND);
      assertNull(minimalMessage.getProductName());
      assertNull(minimalMessage.getInstanceName());
      assertNull(minimalMessage.getStartupID());
      assertNull(minimalMessage.getThreadID());
      assertNull(minimalMessage.getConnectionID());
      assertNull(minimalMessage.getOperationID());
      assertNull(minimalMessage.getMessageID());
      assertNull(minimalMessage.getTriggeredByConnectionID());
      assertNull(minimalMessage.getTriggeredByOperationID());
      assertNull(minimalMessage.getOrigin());
      assertNull(minimalMessage.getRequesterIPAddress());
      assertNull(minimalMessage.getRequesterDN());
      assertEquals(minimalMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalMessage.getAdministrativeOperationMessage());


      // Read the fully-populated log message.
      TextFormattedUnbindRequestAccessLogMessage populatedMessage =
           (TextFormattedUnbindRequestAccessLogMessage) reader.readMessage();
      assertNotNull(populatedMessage);
      populatedMessage = new TextFormattedUnbindRequestAccessLogMessage(
           populatedMessage.toString());

      // Common fields.
      assertEquals(populatedMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedMessage.getMessageType(), REQUEST);
      assertEquals(populatedMessage.getOperationType(), UNBIND);
      assertEquals(populatedMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the ability to read an intermediate response log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntermediateResponseLogMessage()
         throws Exception
  {
    final StringBuilder minimalBuffer =
         createLogMessage(true, INTERMEDIATE_RESPONSE, EXTENDED, false);

    final StringBuilder populatedBuffer =
         createLogMessage(true, INTERMEDIATE_RESPONSE, EXTENDED, true);
    appendField(populatedBuffer, EXTENDED_REQUEST_OID, "1.2.3.4.5");
    appendField(populatedBuffer, EXTENDED_REQUEST_TYPE,
         "extended-request-type");
    appendField(populatedBuffer, INTERMEDIATE_RESPONSE_OID, "1.2.3.4.5.6");
    appendField(populatedBuffer, INTERMEDIATE_RESPONSE_NAME,
         "intermediate-response-name");
    appendField(populatedBuffer, INTERMEDIATE_RESPONSE_VALUE,
         "intermediate-response-value");

    final File logFile = createTempFile(
         minimalBuffer.toString(),
         populatedBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final TextFormattedIntermediateResponseAccessLogMessage
           minimalLogMessage =
           (TextFormattedIntermediateResponseAccessLogMessage)
           reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getMessageType(), INTERMEDIATE_RESPONSE);
      assertEquals(minimalLogMessage.getOperationType(), EXTENDED);
      assertNull(minimalLogMessage.getProductName());
      assertNull(minimalLogMessage.getInstanceName());
      assertNull(minimalLogMessage.getStartupID());
      assertNull(minimalLogMessage.getThreadID());
      assertNull(minimalLogMessage.getConnectionID());
      assertNull(minimalLogMessage.getOperationID());
      assertNull(minimalLogMessage.getMessageID());
      assertNull(minimalLogMessage.getTriggeredByConnectionID());
      assertNull(minimalLogMessage.getTriggeredByOperationID());
      assertNull(minimalLogMessage.getOrigin());
      assertNull(minimalLogMessage.getRequesterIPAddress());
      assertNull(minimalLogMessage.getRequesterDN());
      assertEquals(minimalLogMessage.getRequestControlOIDs(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getUsingAdminSessionWorkerThread());
      assertNull(minimalLogMessage.getAdministrativeOperationMessage());
      assertEquals(minimalLogMessage.getResponseControlOIDs(),
           Collections.emptySet());

      // Message-specific fields.
      assertNull(minimalLogMessage.getOID());
      assertNull(minimalLogMessage.getResponseName());
      assertNull(minimalLogMessage.getValueString());


      // Read the fully-populated log message.
      final TextFormattedIntermediateResponseAccessLogMessage
           populatedLogMessage =
           (TextFormattedIntermediateResponseAccessLogMessage)
           reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getMessageType(), INTERMEDIATE_RESPONSE);
      assertEquals(populatedLogMessage.getOperationType(), EXTENDED);
      assertEquals(populatedLogMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedLogMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedLogMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedLogMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedLogMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);
      assertEquals(populatedLogMessage.getOperationID().longValue(),
           DEFAULT_OPERATION_ID);
      assertEquals(populatedLogMessage.getMessageID().intValue(),
           DEFAULT_MESSAGE_ID);
      assertEquals(populatedLogMessage.getTriggeredByConnectionID().longValue(),
           DEFAULT_TRIGGERED_BY_CONNECTION_ID);
      assertEquals(populatedLogMessage.getTriggeredByOperationID().longValue(),
           DEFAULT_TRIGGERED_BY_OPERATION_ID);
      assertEquals(populatedLogMessage.getOrigin(), DEFAULT_ORIGIN);
      assertEquals(populatedLogMessage.getRequesterIPAddress(),
           DEFAULT_REQUESTER_IP);
      assertEquals(populatedLogMessage.getRequesterDN(),
           DEFAULT_REQUESTER_DN);
      assertEquals(populatedLogMessage.getRequestControlOIDs(),
           DEFAULT_REQUEST_CONTROL_OIDS);
      assertEquals(populatedLogMessage.getUsingAdminSessionWorkerThread(),
           DEFAULT_USING_ADMIN_SESSION_WORKER_THREAD);
      assertEquals(populatedLogMessage.getAdministrativeOperationMessage(),
           DEFAULT_ADMIN_OP_MESSAGE);
      assertEquals(populatedLogMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);

      // Message-specific fields.
      assertEquals(populatedLogMessage.getOID(), "1.2.3.4.5.6");
      assertEquals(populatedLogMessage.getResponseName(),
           "intermediate-response-name");
      assertEquals(populatedLogMessage.getValueString(),
           "intermediate-response-value");


      // Make sure there are no more messages to read.
      assertNull(reader.readMessage());
    }
  }



  /**
   * Tests the behavior when trying to read from a file that does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoSuchFile()
         throws Exception
  {
    final File logFile = createTempFile();
    assertTrue(logFile.delete());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for a file that doesn't exist.");
    }
    catch(final IOException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read a file that doesn't contain valid
   * log messages.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFileMalformedLogMessage()
         throws Exception
  {
    final File logFile = createTempFile(
         "# This is a comment",
         "# The next line will be blank",
         "",
         "# The next line will be parsed as a log message, but it's " +
              "malformed.",
         "This is a malformed log message");

    try (FileInputStream inputStream = new FileInputStream(logFile);
         TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(inputStream))
    {
      reader.readMessage();
      fail("Expected an exception for a file that contains a malformed " +
           "message.");
    }
    catch(final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read a file that contains a log message
   * that doesn't have any unnamed fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadMessageWithoutAnyUnnamedFields()
         throws Exception
  {
    final StringBuilder messageBuffer = createLogMessage(true, null, null,
         false);
    appendField(messageBuffer, DIAGNOSTIC_MESSAGE, "value1");
    appendField(messageBuffer, ADDITIONAL_INFO, "value2");

    final File logFile = createTempFile(messageBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for a file that contains a message without " +
           "any unnamed fields");
    }
    catch(final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read a file that contains a log message
   * that has one unnamed field in which the first is neither a valid message
   * type nor a valid operation type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadMessageWithUnsupportedFirstUnnamedField()
         throws Exception
  {
    final StringBuilder messageBuffer = createLogMessage(true, null, null,
         false);
    messageBuffer.append("UNSUPPORTED");
    appendField(messageBuffer, DIAGNOSTIC_MESSAGE, "value1");
    appendField(messageBuffer, ADDITIONAL_INFO, "value2");

    final File logFile = createTempFile(messageBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for a file that contains a message with " +
           "an unsupported first unnamed field");
    }
    catch(final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read a file that contains a log message
   * that has two unnamed fields in which the second is not a valid message
   * type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadMessageWithUnsupportedSecondUnnamedField()
         throws Exception
  {
    final StringBuilder messageBuffer = createLogMessage(true, null, null,
         false);
    messageBuffer.append("ADD UNSUPPORTED");
    appendField(messageBuffer, DIAGNOSTIC_MESSAGE, "value1");
    appendField(messageBuffer, ADDITIONAL_INFO, "value2");

    final File logFile = createTempFile(messageBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for a file that contains a message with " +
           "an unsupported second unnamed field");
    }
    catch(final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read a file that contains a log message
   * that has one unnamed field that is an operation type rather than a message
   * type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadMessageOperationTypeWithoutMessageType()
         throws Exception
  {
    final StringBuilder messageBuffer = createLogMessage(true, null, null,
         false);
    messageBuffer.append("ADD");
    appendField(messageBuffer, DIAGNOSTIC_MESSAGE, "value1");
    appendField(messageBuffer, ADDITIONAL_INFO, "value2");

    final File logFile = createTempFile(messageBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for a file that contains a message with " +
           "an unsupported second unnamed field");
    }
    catch(final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read a file that contains a log message
   * that should be for an operation but doesn't have the operation type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadOperationMessageWithoutOperationType()
         throws Exception
  {
    final StringBuilder messageBuffer =
         createLogMessage(true, REQUEST, null, false);

    final File logFile = createTempFile(messageBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for a file that contains a request message " +
           "without an operation type");
    }
    catch(final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read a file that contains a log message
   * that attempts to create an unbind forward message, which is not valid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadUnbindForwardMessage()
         throws Exception
  {
    final StringBuilder messageBuffer =
         createLogMessage(true, FORWARD, UNBIND, false);

    final File logFile = createTempFile(messageBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for a file that contains an unbind forward " +
           "message");
    }
    catch(final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read a file that contains a log message
   * that attempts to create an unbind forward failed message, which is not
   * valid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadUnbindForwardFailedMessage()
         throws Exception
  {
    final StringBuilder messageBuffer =
         createLogMessage(true, FORWARD_FAILED, UNBIND, false);

    final File logFile = createTempFile(messageBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for a file that contains an unbind forward " +
           "failed message");
    }
    catch(final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read a file that contains a log message
   * that attempts to create an unbind result message, which is not valid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadUnbindResultMessage()
         throws Exception
  {
    final StringBuilder messageBuffer =
         createLogMessage(true, RESULT, UNBIND, false);

    final File logFile = createTempFile(messageBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for a file that contains an unbind result " +
           "message");
    }
    catch(final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read a file that contains a log message
   * that attempts to create an unbind assurance completed message, which is not
   * valid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadUnbindAssuranceCompletedMessage()
         throws Exception
  {
    final StringBuilder messageBuffer =
         createLogMessage(true, ASSURANCE_COMPLETE, UNBIND, false);

    final File logFile = createTempFile(messageBuffer.toString());

    try (TextFormattedAccessLogReader reader =
              new TextFormattedAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for a file that contains an unbind " +
           "assurance completed message");
    }
    catch(final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the ability to read a result message that has several referral URLs
   * that mix LDAP and LDAPS schemes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testResultWithLDAPAndLDAPSReferralURLs()
         throws Exception
  {
    final StringBuilder messageBuffer =
         createLogMessage(true, RESULT, COMPARE, false);
    appendField(messageBuffer, COMPARE_ENTRY_DN, "cn=compare,cn=dn");
    appendField(messageBuffer, COMPARE_ATTRIBUTE_NAME, "description");
    appendField(messageBuffer, RESULT_CODE_VALUE,
         ResultCode.REFERRAL.intValue());
    appendField(messageBuffer, RESULT_CODE_NAME, ResultCode.REFERRAL.getName());
    appendField(messageBuffer, REFERRAL_URLS,
         "ldap://ds1.example.com:389/dc=example,dc=com?uid,cn?sub?(cn=*)",
         "ldaps://ds2.example.com:389/dc=example,dc=com?uid,cn?sub?(cn=*)",
         "ldaps://ds3.example.com:389/dc=example,dc=com?uid,cn?sub?(cn=*)",
         "ldap://ds4.example.com:389/dc=example,dc=com?uid,cn?sub?(cn=*)",
         "ldaps://ds5.example.com:389/dc=example,dc=com?uid,cn?sub?(cn=*)");

    final TextFormattedCompareResultAccessLogMessage message =
         (TextFormattedCompareResultAccessLogMessage)
         TextFormattedAccessLogReader.parseMessage(messageBuffer.toString());
    assertNotNull(message);

    assertEquals(message.getReferralURLs(),
         Arrays.asList(
              "ldap://ds1.example.com:389/dc=example,dc=com?uid,cn?sub?(cn=*)",
              "ldaps://ds2.example.com:389/dc=example,dc=com?uid,cn?sub?(cn=*)",
              "ldaps://ds3.example.com:389/dc=example,dc=com?uid,cn?sub?(cn=*)",
              "ldap://ds4.example.com:389/dc=example,dc=com?uid,cn?sub?(cn=*)",
              "ldaps://ds5.example.com:389/dc=example,dc=com?uid,cn?sub" +
                   "?(cn=*)"));
  }



  /**
   * Tests the ability to read a search request log message that has the
   * requested attributes set to ALL.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchRequestWithALLRequestedAttributes()
         throws Exception
  {
    final StringBuilder messageBuffer =
         createLogMessage(true, REQUEST, SEARCH, true);
    appendField(messageBuffer, SEARCH_BASE_DN, "cn=base,cn=dn");
    appendField(messageBuffer, SEARCH_SCOPE_VALUE,
         SearchScope.SUB.intValue());
    appendField(messageBuffer, SEARCH_FILTER, "(filter=value)");
    appendField(messageBuffer, SEARCH_SIZE_LIMIT, 2345);
    appendField(messageBuffer, SEARCH_TIME_LIMIT_SECONDS, 3456);
    appendField(messageBuffer, SEARCH_DEREF_POLICY,
         DereferencePolicy.NEVER.getName());
    appendField(messageBuffer, SEARCH_TYPES_ONLY, false);
    appendField(messageBuffer, SEARCH_REQUESTED_ATTRIBUTES, "ALL");

    final TextFormattedSearchRequestAccessLogMessage message =
         (TextFormattedSearchRequestAccessLogMessage)
         TextFormattedAccessLogReader.parseMessage(messageBuffer.toString());
    assertNotNull(message);

    assertEquals(message.getRequestedAttributes(),
         Collections.emptyList());
  }



  /**
   * Tests the ability to read a search request log message that has one
   * requested attribute that is not ALL.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchRequestWithOneRequestedAttributeNotALL()
         throws Exception
  {
    final StringBuilder messageBuffer =
         createLogMessage(true, REQUEST, SEARCH, true);
    appendField(messageBuffer, SEARCH_BASE_DN, "cn=base,cn=dn");
    appendField(messageBuffer, SEARCH_SCOPE_VALUE,
         SearchScope.SUB.intValue());
    appendField(messageBuffer, SEARCH_FILTER, "(filter=value)");
    appendField(messageBuffer, SEARCH_SIZE_LIMIT, 2345);
    appendField(messageBuffer, SEARCH_TIME_LIMIT_SECONDS, 3456);
    appendField(messageBuffer, SEARCH_DEREF_POLICY,
         DereferencePolicy.NEVER.getName());
    appendField(messageBuffer, SEARCH_TYPES_ONLY, false);
    appendField(messageBuffer, SEARCH_REQUESTED_ATTRIBUTES, "notAll");

    final TextFormattedSearchRequestAccessLogMessage message =
         (TextFormattedSearchRequestAccessLogMessage)
         TextFormattedAccessLogReader.parseMessage(messageBuffer.toString());
    assertNotNull(message);

    assertEquals(message.getRequestedAttributes(),
         Collections.singletonList("notAll"));
  }
}
