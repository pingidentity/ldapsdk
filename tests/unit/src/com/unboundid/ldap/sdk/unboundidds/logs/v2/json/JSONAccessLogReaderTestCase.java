/*
 * Copyright 2022-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2023 Ping Identity Corporation
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
 * Copyright (C) 2022-2023 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.json;



import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.unboundidds.controls.AuthenticationFailureReason;
import com.unboundid.ldap.sdk.unboundidds.logs.BindRequestAuthenticationType;
import com.unboundid.ldap.sdk.unboundidds.logs.LogException;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.logs.AccessLogMessageType.*;
import static com.unboundid.ldap.sdk.unboundidds.logs.AccessLogOperationType.*;
import static com.unboundid.ldap.sdk.unboundidds.logs.v2.json.
                   JSONFormattedAccessLogFields.*;



/**
 * This class provides a set of test cases for the JSON access log reader.
 */
public final class JSONAccessLogReaderTestCase
       extends JSONLogsTestCase
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         CONNECT, null);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         CONNECT, null,
         createField(CONNECT_FROM_ADDRESS, "2.3.4.5"),
         createField(CONNECT_FROM_PORT, 1234),
         createField(CONNECT_TO_ADDRESS, "2.3.4.6"),
         createField(CONNECT_TO_PORT, 4567),
         createField(PROTOCOL, "LDAP"),
         createField(CLIENT_CONNECTION_POLICY, "Default"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new
         JSONAccessLogReader(logFile.getAbsolutePath()))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONConnectAccessLogMessage minimalLogMessage =
           (JSONConnectAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), CONNECT);
      assertNull(minimalLogMessage.getProductName());
      assertNull(minimalLogMessage.getInstanceName());
      assertNull(minimalLogMessage.getStartupID());
      assertNull(minimalLogMessage.getThreadID());
      assertNull(minimalLogMessage.getConnectionID());

      // Message-specific fields.
      assertNull(minimalLogMessage.getSourceAddress());
      assertNull(minimalLogMessage.getSourcePort());
      assertNull(minimalLogMessage.getTargetAddress());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getProtocolName());
      assertNull(minimalLogMessage.getClientConnectionPolicy());


      // Read the fully-populated log message.
      final JSONConnectAccessLogMessage populatedLogMessage =
           (JSONConnectAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), CONNECT);
      assertEquals(populatedLogMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedLogMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedLogMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedLogMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedLogMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);

      // Message-specific fields.
      assertEquals(populatedLogMessage.getSourceAddress(), "2.3.4.5");
      assertEquals(populatedLogMessage.getSourcePort().intValue(), 1234);
      assertEquals(populatedLogMessage.getTargetAddress(), "2.3.4.6");
      assertEquals(populatedLogMessage.getTargetPort().intValue(), 4567);
      assertEquals(populatedLogMessage.getProtocolName(), "LDAP");
      assertEquals(populatedLogMessage.getClientConnectionPolicy(), "Default");


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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         DISCONNECT, null);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         DISCONNECT, null,
         createField(DISCONNECT_REASON, "Disconnect Reason"),
         createField(DISCONNECT_MESSAGE, "Disconnect Message"),
         createField(REQUESTER_IP_ADDRESS, DEFAULT_REQUESTER_IP));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONDisconnectAccessLogMessage minimalLogMessage =
           (JSONDisconnectAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), DISCONNECT);
      assertNull(minimalLogMessage.getProductName());
      assertNull(minimalLogMessage.getInstanceName());
      assertNull(minimalLogMessage.getStartupID());
      assertNull(minimalLogMessage.getThreadID());
      assertNull(minimalLogMessage.getConnectionID());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDisconnectReason());
      assertNull(minimalLogMessage.getDisconnectMessage());
      assertNull(minimalLogMessage.getRequesterIPAddress());


      // Read the fully-populated log message.
      final JSONDisconnectAccessLogMessage populatedLogMessage =
           (JSONDisconnectAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), DISCONNECT);
      assertEquals(populatedLogMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedLogMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedLogMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedLogMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedLogMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDisconnectReason(),
           "Disconnect Reason");
      assertEquals(populatedLogMessage.getDisconnectMessage(),
           "Disconnect Message");
      assertEquals(populatedLogMessage.getRequesterIPAddress(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         SECURITY_NEGOTIATION, null);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         SECURITY_NEGOTIATION, null,
         createField(PROTOCOL, "TLSv1.3"),
         createField(CIPHER, "TSL_AES_256_GCM_SHA384"),
         createField(SECURITY_NEGOTIATION_PROPERTIES, new JSONArray(
              new JSONObject(
                   createField(SECURITY_NEGOTIATION_PROPERTIES_NAME, "prop1"),
                   createField(SECURITY_NEGOTIATION_PROPERTIES_VALUE, "val1")),
              new JSONObject(
                   createField(SECURITY_NEGOTIATION_PROPERTIES_NAME, "prop2"),
                   createField(SECURITY_NEGOTIATION_PROPERTIES_VALUE,
                        "val2")))));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONSecurityNegotiationAccessLogMessage minimalLogMessage =
           (JSONSecurityNegotiationAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), SECURITY_NEGOTIATION);
      assertNull(minimalLogMessage.getProductName());
      assertNull(minimalLogMessage.getInstanceName());
      assertNull(minimalLogMessage.getStartupID());
      assertNull(minimalLogMessage.getThreadID());
      assertNull(minimalLogMessage.getConnectionID());

      // Message-specific fields.
      assertNull(minimalLogMessage.getProtocol());
      assertNull(minimalLogMessage.getCipher());
      assertEquals(minimalLogMessage.getNegotiationProperties(),
           Collections.emptyMap());


      // Read the fully-populated log message.
      final JSONSecurityNegotiationAccessLogMessage populatedLogMessage =
           (JSONSecurityNegotiationAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), SECURITY_NEGOTIATION);
      assertEquals(populatedLogMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedLogMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedLogMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedLogMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedLogMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);

      // Message-specific fields.
      assertEquals(populatedLogMessage.getProtocol(), "TLSv1.3");
      assertEquals(populatedLogMessage.getCipher(), "TSL_AES_256_GCM_SHA384");
      assertEquals(populatedLogMessage.getNegotiationProperties(),
           StaticUtils.mapOf(
                "prop1", "val1",
                "prop2", "val2"));


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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         CLIENT_CERTIFICATE, null);

    final Date peerNotBefore =
         new Date(DEFAULT_TIMESTAMP_DATE.getTime() - 86_400_000L);
    final Date peerNotAfter =
         new Date(DEFAULT_TIMESTAMP_DATE.getTime() + 8_600_400_000L);
    final Date caNotBefore =
         new Date(DEFAULT_TIMESTAMP_DATE.getTime() - 864_000_000L);
    final Date caNotAfter =
         new Date(DEFAULT_TIMESTAMP_DATE.getTime() + 864_000_000_000L);
    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         CLIENT_CERTIFICATE, null,
         createField(PEER_CERTIFICATE_CHAIN, new JSONArray(
              new JSONObject(
                   createField(PEER_CERTIFICATE_CHAIN_CERTIFICATE_TYPE,
                        "X.509"),
                   createField(PEER_CERTIFICATE_CHAIN_SUBJECT_DN,
                        "CN=server.example.com,O=Example Corp,C=US"),
                   createField(PEER_CERTIFICATE_CHAIN_ISSUER_SUBJECT_DN,
                        "CN=Intermediate CA,O=Example Corp,C=US"),
                   createField(PEER_CERTIFICATE_CHAIN_NOT_BEFORE,
                        StaticUtils.encodeRFC3339Time(peerNotBefore)),
                   createField(PEER_CERTIFICATE_CHAIN_NOT_AFTER,
                        StaticUtils.encodeRFC3339Time(peerNotAfter)),
                   createField(PEER_CERTIFICATE_CHAIN_SERIAL_NUMBER,
                        "peer-serial-number"),
                   createField(PEER_CERTIFICATE_CHAIN_SIGNATURE_ALGORITHM,
                        "peer-signature-algorithm")),
              new JSONObject(
                   createField(PEER_CERTIFICATE_CHAIN_CERTIFICATE_TYPE,
                        "X.509"),
                   createField(PEER_CERTIFICATE_CHAIN_SUBJECT_DN,
                        "CN=Intermediate CA,O=Example Corp,C=US"),
                   createField(PEER_CERTIFICATE_CHAIN_ISSUER_SUBJECT_DN,
                        "CN=Root CA,O=Example Corp,C=US"),
                   createField(PEER_CERTIFICATE_CHAIN_NOT_BEFORE,
                        StaticUtils.encodeRFC3339Time(caNotBefore)),
                   createField(PEER_CERTIFICATE_CHAIN_NOT_AFTER,
                        StaticUtils.encodeRFC3339Time(caNotAfter)),
                   createField(PEER_CERTIFICATE_CHAIN_SERIAL_NUMBER,
                        "intermediate-ca-serial-number"),
                   createField(PEER_CERTIFICATE_CHAIN_SIGNATURE_ALGORITHM,
                        "intermediate-ca-signature-algorithm")),
              new JSONObject(
                   createField(PEER_CERTIFICATE_CHAIN_SUBJECT_DN,
                        "CN=Root CA,O=Example Corp,C=US"),
                   createField(PEER_CERTIFICATE_CHAIN_ISSUER_SUBJECT_DN,
                        "CN=Root CA,O=Example Corp,C=US"),
                   createField(PEER_CERTIFICATE_CHAIN_NOT_BEFORE,
                        "malformed-not-before")))),
         createField(AUTO_AUTHENTICATED_AS, "cn=Auto,cn=Authenticated"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONClientCertificateAccessLogMessage minimalLogMessage =
           (JSONClientCertificateAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), CLIENT_CERTIFICATE);
      assertNull(minimalLogMessage.getProductName());
      assertNull(minimalLogMessage.getInstanceName());
      assertNull(minimalLogMessage.getStartupID());
      assertNull(minimalLogMessage.getThreadID());
      assertNull(minimalLogMessage.getConnectionID());

      // Message-specific fields.
      assertEquals(minimalLogMessage.getPeerCertificateChain(),
           Collections.emptyList());
      assertNull(minimalLogMessage.getPeerSubjectDN());
      assertEquals(minimalLogMessage.getIssuerSubjectDNs(),
           Collections.emptyList());
      assertNull(minimalLogMessage.getAutoAuthenticatedAsDN());


      // Read the fully-populated log message.
      final JSONClientCertificateAccessLogMessage populatedLogMessage =
           (JSONClientCertificateAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), CLIENT_CERTIFICATE);

      // Message-specific fields.
      assertEquals(populatedLogMessage.getPeerCertificateChain().size(), 3);
      assertEquals(populatedLogMessage.getPeerSubjectDN(),
           "CN=server.example.com,O=Example Corp,C=US");
      assertEquals(populatedLogMessage.getIssuerSubjectDNs(),
           Arrays.asList(
                "CN=Intermediate CA,O=Example Corp,C=US",
                "CN=Root CA,O=Example Corp,C=US"));
      assertEquals(populatedLogMessage.getAutoAuthenticatedAsDN(),
           "cn=Auto,cn=Authenticated");

      // The peer certificate.
      final JSONCertificate peerCert =
           populatedLogMessage.getPeerCertificateChain().get(0);
      assertNotNull(peerCert.getCertificateObject());
      assertEquals(peerCert.getSubjectDN(),
           "CN=server.example.com,O=Example Corp,C=US");
      assertEquals(peerCert.getIssuerSubjectDN(),
           "CN=Intermediate CA,O=Example Corp,C=US");
      assertEquals(peerCert.getCertificateType(), "X.509");
      assertEquals(peerCert.getNotBeforeTime(), peerNotBefore);
      assertEquals(peerCert.getNotAfterTime(), peerNotAfter);
      assertEquals(peerCert.getSerialNumber(), "peer-serial-number");
      assertEquals(peerCert.getSignatureAlgorithm(),
           "peer-signature-algorithm");
      assertNotNull(peerCert.toString());

      // The intermediate CA certificate.
      final JSONCertificate intermediateCACert =
           populatedLogMessage.getPeerCertificateChain().get(1);
      assertNotNull(intermediateCACert.getCertificateObject());
      assertEquals(intermediateCACert.getSubjectDN(),
           "CN=Intermediate CA,O=Example Corp,C=US");
      assertEquals(intermediateCACert.getIssuerSubjectDN(),
           "CN=Root CA,O=Example Corp,C=US");
      assertEquals(intermediateCACert.getCertificateType(), "X.509");
      assertEquals(intermediateCACert.getNotBeforeTime(), caNotBefore);
      assertEquals(intermediateCACert.getNotAfterTime(), caNotAfter);
      assertEquals(intermediateCACert.getSerialNumber(),
           "intermediate-ca-serial-number");
      assertEquals(intermediateCACert.getSignatureAlgorithm(),
           "intermediate-ca-signature-algorithm");
      assertNotNull(intermediateCACert.toString());

      // The root CA certificate.
      final JSONCertificate rootCACert =
           populatedLogMessage.getPeerCertificateChain().get(2);
      assertNotNull(rootCACert.getCertificateObject());
      assertEquals(rootCACert.getSubjectDN(),
           "CN=Root CA,O=Example Corp,C=US");
      assertEquals(rootCACert.getIssuerSubjectDN(),
           "CN=Root CA,O=Example Corp,C=US");
      assertNull(rootCACert.getCertificateType());
      assertNull(rootCACert.getNotBeforeTime());
      assertNull(rootCACert.getNotAfterTime());
      assertNull(rootCACert.getSerialNumber());
      assertNull(rootCACert.getSignatureAlgorithm());
      assertNotNull(rootCACert.toString());


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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         ENTRY_REBALANCING_REQUEST, null);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         ENTRY_REBALANCING_REQUEST, null,
         createField(ENTRY_REBALANCING_OPERATION_ID, 1234L),
         createField(TRIGGERED_BY_CONNECTION_ID, 5678L),
         createField(TRIGGERED_BY_OPERATION_ID, 8765L),
         createField(ENTRY_REBALANCING_BASE_DN, "ou=People,dc=example,dc=com"),
         createField(ENTRY_REBALANCING_SIZE_LIMIT, 1000L),
         createField(ENTRY_REBALANCING_SOURCE_BACKEND_SET, "Set A"),
         createField(ENTRY_REBALANCING_SOURCE_SERVER, new JSONObject(
              createField(ENTRY_REBALANCING_SOURCE_SERVER_ADDRESS,
                   "source.example.com"),
              createField(ENTRY_REBALANCING_SOURCE_SERVER_PORT, 1389))),
         createField(ENTRY_REBALANCING_TARGET_BACKEND_SET, "Set B"),
         createField(ENTRY_REBALANCING_TARGET_SERVER, new JSONObject(
              createField(ENTRY_REBALANCING_TARGET_SERVER_ADDRESS,
                   "target.example.com"))));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONEntryRebalancingRequestAccessLogMessage minimalLogMessage =
           (JSONEntryRebalancingRequestAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(),
           ENTRY_REBALANCING_REQUEST);
      assertNull(minimalLogMessage.getProductName());
      assertNull(minimalLogMessage.getInstanceName());
      assertNull(minimalLogMessage.getStartupID());
      assertNull(minimalLogMessage.getThreadID());
      assertNull(minimalLogMessage.getConnectionID());

      // Message-specific fields.
      assertNull(minimalLogMessage.getRebalancingOperationID());
      assertNull(minimalLogMessage.getTriggeredByConnectionID());
      assertNull(minimalLogMessage.getTriggeredByOperationID());
      assertNull(minimalLogMessage.getSubtreeBaseDN());
      assertNull(minimalLogMessage.getSizeLimit());
      assertNull(minimalLogMessage.getSourceBackendSetName());
      assertNull(minimalLogMessage.getSourceBackendServer());
      assertNull(minimalLogMessage.getTargetBackendSetName());
      assertNull(minimalLogMessage.getTargetBackendServer());


      // Read the fully-populated log message.
      final JSONEntryRebalancingRequestAccessLogMessage populatedLogMessage =
           (JSONEntryRebalancingRequestAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(),
           ENTRY_REBALANCING_REQUEST);
      assertEquals(populatedLogMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedLogMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedLogMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedLogMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedLogMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);

      // Message-specific fields.
      assertEquals(populatedLogMessage.getRebalancingOperationID().longValue(),
           1234L);
      assertEquals(populatedLogMessage.getTriggeredByConnectionID().longValue(),
           5678L);
      assertEquals(populatedLogMessage.getTriggeredByOperationID().longValue(),
           8765L);
      assertEquals(populatedLogMessage.getSubtreeBaseDN(),
           "ou=People,dc=example,dc=com");
      assertEquals(populatedLogMessage.getSizeLimit().intValue(), 1000);
      assertEquals(populatedLogMessage.getSourceBackendSetName(), "Set A");
      assertEquals(populatedLogMessage.getSourceBackendServer(),
           "source.example.com:1389");
      assertEquals(populatedLogMessage.getTargetBackendSetName(), "Set B");
      assertEquals(populatedLogMessage.getTargetBackendServer(),
           "target.example.com");


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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         ENTRY_REBALANCING_RESULT, null);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         ENTRY_REBALANCING_RESULT, null,
         createField(ENTRY_REBALANCING_OPERATION_ID, 1234L),
         createField(TRIGGERED_BY_CONNECTION_ID, 5678L),
         createField(TRIGGERED_BY_OPERATION_ID, 8765L),
         createField(ENTRY_REBALANCING_BASE_DN, "ou=People,dc=example,dc=com"),
         createField(ENTRY_REBALANCING_SIZE_LIMIT, 1000L),
         createField(ENTRY_REBALANCING_SOURCE_BACKEND_SET, "Set A"),
         createField(ENTRY_REBALANCING_SOURCE_SERVER, new JSONObject(
              createField(ENTRY_REBALANCING_SOURCE_SERVER_PORT, 1389))),
         createField(ENTRY_REBALANCING_TARGET_BACKEND_SET, "Set B"),
         createField(RESULT_CODE_VALUE, 0L),
         createField(RESULT_CODE_NAME, "SUCCESS"),
         createField(ENTRY_REBALANCING_ERROR_MESSAGE, "Error Message"),
         createField(ENTRY_REBALANCING_ADMIN_ACTION_MESSAGE,
              "Admin Action Message"),
         createField(ENTRY_REBALANCING_SOURCE_SERVER_ALTERED, true),
         createField(ENTRY_REBALANCING_TARGET_SERVER_ALTERED, false),
         createField(ENTRY_REBALANCING_ENTRIES_READ_FROM_SOURCE, 123L),
         createField(ENTRY_REBALANCING_ENTRIES_ADDED_TO_TARGET, 0L),
         createField(ENTRY_REBALANCING_ENTRIES_DELETED_FROM_SOURCE, 1L));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONEntryRebalancingResultAccessLogMessage minimalLogMessage =
           (JSONEntryRebalancingResultAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(),
           ENTRY_REBALANCING_RESULT);
      assertNull(minimalLogMessage.getProductName());
      assertNull(minimalLogMessage.getInstanceName());
      assertNull(minimalLogMessage.getStartupID());
      assertNull(minimalLogMessage.getThreadID());
      assertNull(minimalLogMessage.getConnectionID());

      // Message-specific fields.
      assertNull(minimalLogMessage.getRebalancingOperationID());
      assertNull(minimalLogMessage.getTriggeredByConnectionID());
      assertNull(minimalLogMessage.getTriggeredByOperationID());
      assertNull(minimalLogMessage.getSubtreeBaseDN());
      assertNull(minimalLogMessage.getSizeLimit());
      assertNull(minimalLogMessage.getSourceBackendSetName());
      assertNull(minimalLogMessage.getSourceBackendServer());
      assertNull(minimalLogMessage.getTargetBackendSetName());
      assertNull(minimalLogMessage.getTargetBackendServer());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getErrorMessage());
      assertNull(minimalLogMessage.getAdminActionMessage());
      assertNull(minimalLogMessage.getSourceServerAltered());
      assertNull(minimalLogMessage.getTargetServerAltered());
      assertNull(minimalLogMessage.getEntriesReadFromSource());
      assertNull(minimalLogMessage.getEntriesAddedToTarget());
      assertNull(minimalLogMessage.getEntriesDeletedFromSource());


      // Read the fully-populated log message.
      final JSONEntryRebalancingResultAccessLogMessage populatedLogMessage =
           (JSONEntryRebalancingResultAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(),
           ENTRY_REBALANCING_RESULT);
      assertEquals(populatedLogMessage.getProductName(), DEFAULT_PRODUCT_NAME);
      assertEquals(populatedLogMessage.getInstanceName(),
           DEFAULT_INSTANCE_NAME);
      assertEquals(populatedLogMessage.getStartupID(), DEFAULT_STARTUP_ID);
      assertEquals(populatedLogMessage.getThreadID().longValue(),
           DEFAULT_THREAD_ID);
      assertEquals(populatedLogMessage.getConnectionID().longValue(),
           DEFAULT_CONNECTION_ID);

      // Message-specific fields.
      assertEquals(populatedLogMessage.getRebalancingOperationID().longValue(),
           1234L);
      assertEquals(populatedLogMessage.getTriggeredByConnectionID().longValue(),
           5678L);
      assertEquals(populatedLogMessage.getTriggeredByOperationID().longValue(),
           8765L);
      assertEquals(populatedLogMessage.getSubtreeBaseDN(),
           "ou=People,dc=example,dc=com");
      assertEquals(populatedLogMessage.getSizeLimit().intValue(), 1000);
      assertEquals(populatedLogMessage.getSourceBackendSetName(), "Set A");
      assertNull(populatedLogMessage.getSourceBackendServer());
      assertEquals(populatedLogMessage.getTargetBackendSetName(), "Set B");
      assertNull(populatedLogMessage.getTargetBackendServer());
      assertEquals(populatedLogMessage.getResultCode(), ResultCode.SUCCESS);
      assertEquals(populatedLogMessage.getErrorMessage(), "Error Message");
      assertEquals(populatedLogMessage.getAdminActionMessage(),
           "Admin Action Message");
      assertEquals(populatedLogMessage.getSourceServerAltered(), Boolean.TRUE);
      assertEquals(populatedLogMessage.getTargetServerAltered(), Boolean.FALSE);
      assertEquals(populatedLogMessage.getEntriesReadFromSource().intValue(),
           123);
      assertEquals(populatedLogMessage.getEntriesAddedToTarget().intValue(), 0);
      assertEquals(populatedLogMessage.getEntriesDeletedFromSource().intValue(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         REQUEST, ABANDON);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         REQUEST, ABANDON,
         createField(ABANDON_MESSAGE_ID, 123));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONAbandonRequestAccessLogMessage minimalLogMessage =
           (JSONAbandonRequestAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), REQUEST);
      assertEquals(minimalLogMessage.getOperationType(), ABANDON);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());

      // Message-specific fields.
      assertNull(minimalLogMessage.getMessageIDToAbandon());


      // Read the fully-populated log message.
      final JSONAbandonRequestAccessLogMessage populatedLogMessage =
           (JSONAbandonRequestAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), REQUEST);
      assertEquals(populatedLogMessage.getOperationType(), ABANDON);
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

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getMessageIDToAbandon().intValue(), 123);


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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         FORWARD, ABANDON);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         FORWARD, ABANDON,
         createField(ABANDON_MESSAGE_ID, 123));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONAbandonForwardAccessLogMessage minimalLogMessage =
           (JSONAbandonForwardAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), FORWARD);
      assertEquals(minimalLogMessage.getOperationType(), ABANDON);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());

      // Message-specific fields.
      assertNull(minimalLogMessage.getMessageIDToAbandon());


      // Read the fully-populated log message.
      final JSONAbandonForwardAccessLogMessage populatedLogMessage =
           (JSONAbandonForwardAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), FORWARD);
      assertEquals(populatedLogMessage.getOperationType(), ABANDON);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getMessageIDToAbandon().intValue(), 123);


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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         FORWARD_FAILED, ABANDON);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         FORWARD_FAILED, ABANDON,
         createField(ABANDON_MESSAGE_ID, 123));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONAbandonForwardFailedAccessLogMessage minimalLogMessage =
           (JSONAbandonForwardFailedAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(minimalLogMessage.getOperationType(), ABANDON);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());

      // Message-specific fields.
      assertNull(minimalLogMessage.getMessageIDToAbandon());


      // Read the fully-populated log message.
      final JSONAbandonForwardFailedAccessLogMessage populatedLogMessage =
           (JSONAbandonForwardFailedAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(populatedLogMessage.getOperationType(), ABANDON);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getMessageIDToAbandon().intValue(), 123);


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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         RESULT, ABANDON);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         RESULT, ABANDON,
         createField(ABANDON_MESSAGE_ID, 123));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONAbandonResultAccessLogMessage minimalLogMessage =
           (JSONAbandonResultAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), RESULT);
      assertEquals(minimalLogMessage.getOperationType(), ABANDON);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());
      assertNull(minimalLogMessage.getAdditionalInformation());
      assertNull(minimalLogMessage.getMatchedDN());
      assertEquals(minimalLogMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalLogMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalLogMessage.getUncachedDataAccessed());
      assertNull(minimalLogMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalLogMessage.getProcessingTimeMillis());
      assertNull(minimalLogMessage.getIntermediateResponsesReturned());
      assertEquals(minimalLogMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getMissingPrivileges(),
           Collections.emptySet());

      // Message-specific fields.
      assertNull(minimalLogMessage.getMessageIDToAbandon());


      // Read the fully-populated log message.
      final JSONAbandonResultAccessLogMessage populatedLogMessage =
           (JSONAbandonResultAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), RESULT);
      assertEquals(populatedLogMessage.getOperationType(), ABANDON);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedLogMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedLogMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedLogMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedLogMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedLogMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedLogMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedLogMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedLogMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedLogMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedLogMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getMessageIDToAbandon().intValue(), 123);


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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         REQUEST, ADD);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         REQUEST, ADD,
         createField(ADD_ENTRY_DN, "ou=test,dc=example,dc=com"),
         createField(ADD_ATTRIBUTES, createArray("objectClass", "ou")));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONAddRequestAccessLogMessage minimalLogMessage =
           (JSONAddRequestAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), REQUEST);
      assertEquals(minimalLogMessage.getOperationType(), ADD);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());
      assertEquals(minimalLogMessage.getAttributeNames(),
           Collections.emptySet());


      // Read the fully-populated log message.
      final JSONAddRequestAccessLogMessage populatedLogMessage =
           (JSONAddRequestAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), REQUEST);
      assertEquals(populatedLogMessage.getOperationType(), ADD);
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

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "ou=test,dc=example,dc=com");
      assertEquals(populatedLogMessage.getAttributeNames(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         FORWARD, ADD);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         FORWARD, ADD,
         createField(ADD_ENTRY_DN, "ou=test,dc=example,dc=com"),
         createField(ADD_ATTRIBUTES, createArray("objectClass", "ou")));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONAddForwardAccessLogMessage minimalLogMessage =
           (JSONAddForwardAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), FORWARD);
      assertEquals(minimalLogMessage.getOperationType(), ADD);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());
      assertEquals(minimalLogMessage.getAttributeNames(),
           Collections.emptySet());


      // Read the fully-populated log message.
      final JSONAddForwardAccessLogMessage populatedLogMessage =
           (JSONAddForwardAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), FORWARD);
      assertEquals(populatedLogMessage.getOperationType(), ADD);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "ou=test,dc=example,dc=com");
      assertEquals(populatedLogMessage.getAttributeNames(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         FORWARD_FAILED, ADD);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         FORWARD_FAILED, ADD,
         createField(ADD_ENTRY_DN, "ou=test,dc=example,dc=com"),
         createField(ADD_ATTRIBUTES, createArray("objectClass", "ou")));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONAddForwardFailedAccessLogMessage minimalLogMessage =
           (JSONAddForwardFailedAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(minimalLogMessage.getOperationType(), ADD);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());
      assertEquals(minimalLogMessage.getAttributeNames(),
           Collections.emptySet());


      // Read the fully-populated log message.
      final JSONAddForwardFailedAccessLogMessage populatedLogMessage =
           (JSONAddForwardFailedAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(populatedLogMessage.getOperationType(), ADD);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "ou=test,dc=example,dc=com");
      assertEquals(populatedLogMessage.getAttributeNames(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         RESULT, ADD);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         RESULT, ADD,
         createField(ADD_ENTRY_DN, "ou=test,dc=example,dc=com"),
         createField(ADD_ATTRIBUTES, createArray("objectClass", "ou")),
         createField(ADD_UNDELETE_FROM_DN, "cn=undelete,cn=from,cn=dn"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONAddResultAccessLogMessage minimalLogMessage =
           (JSONAddResultAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), RESULT);
      assertEquals(minimalLogMessage.getOperationType(), ADD);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());
      assertNull(minimalLogMessage.getAdditionalInformation());
      assertNull(minimalLogMessage.getMatchedDN());
      assertEquals(minimalLogMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalLogMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalLogMessage.getUncachedDataAccessed());
      assertNull(minimalLogMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalLogMessage.getProcessingTimeMillis());
      assertNull(minimalLogMessage.getIntermediateResponsesReturned());
      assertEquals(minimalLogMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getMissingPrivileges(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getAlternateAuthorizationDN());
      assertNull(minimalLogMessage.getAssuredReplicationLocalLevel());
      assertNull(minimalLogMessage.getAssuredReplicationRemoteLevel());
      assertNull(minimalLogMessage.getAssuredReplicationTimeoutMillis());
      assertNull(minimalLogMessage.getResponseDelayedByAssurance());
      assertEquals(minimalLogMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           Collections.emptySet());
      assertEquals(
           minimalLogMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getReplicationChangeID());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());
      assertEquals(minimalLogMessage.getAttributeNames(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getUndeleteFromDN());


      // Read the fully-populated log message.
      final JSONAddResultAccessLogMessage populatedLogMessage =
           (JSONAddResultAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), RESULT);
      assertEquals(populatedLogMessage.getOperationType(), ADD);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedLogMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedLogMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedLogMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedLogMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedLogMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedLogMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedLogMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedLogMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedLogMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedLogMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);
      assertEquals(populatedLogMessage.getAlternateAuthorizationDN(),
           DEFAULT_AUTHZ_DN);
      assertEquals(populatedLogMessage.getAssuredReplicationLocalLevel(),
           DEFAULT_LOCAL_ASSURANCE_LEVEL);
      assertEquals(populatedLogMessage.getAssuredReplicationRemoteLevel(),
           DEFAULT_REMOTE_ASSURANCE_LEVEL);
      assertEquals(
           populatedLogMessage.getAssuredReplicationTimeoutMillis().longValue(),
           DEFAULT_ASSURANCE_TIMEOUT_MILLIS);
      assertEquals(populatedLogMessage.getResponseDelayedByAssurance(),
           DEFAULT_RESPONSE_DELAYED_BY_ASSURANCE);
      assertEquals(
           populatedLogMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           DEFAULT_INDEXES_NEAR_ENTRY_LIMIT);
      assertEquals(
           populatedLogMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           DEFAULT_INDEXES_EXCEEDING_ENTRY_LIMIT);
      assertEquals(populatedLogMessage.getReplicationChangeID(),
           DEFAULT_REPLICATION_CHANGE_ID);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      final JSONIntermediateClientResponseControl intermediateClientResponse =
           populatedLogMessage.getIntermediateClientResponseControl();
      assertNotNull(intermediateClientResponse);
      assertNotNull(intermediateClientResponse.getControlObject());
      assertEquals(intermediateClientResponse.getUpstreamServerAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerAddress());
      assertEquals(intermediateClientResponse.getUpstreamServerSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerSecure());
      assertEquals(intermediateClientResponse.getServerName(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getServerName());
      assertEquals(intermediateClientResponse.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getSessionID());
      assertEquals(intermediateClientResponse.getResponseID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getResponseID());
      assertNotNull(intermediateClientResponse.getUpstreamResponse());
      assertNotNull(intermediateClientResponse.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "ou=test,dc=example,dc=com");
      assertEquals(populatedLogMessage.getAttributeNames(),
           StaticUtils.setOf("objectClass", "ou"));
      assertEquals(populatedLogMessage.getUndeleteFromDN(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         ASSURANCE_COMPLETE, ADD);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         ASSURANCE_COMPLETE, ADD,
         createField(ADD_ENTRY_DN, "ou=test,dc=example,dc=com"),
         createField(ADD_ATTRIBUTES, createArray("objectClass", "ou")),
         createField(ADD_UNDELETE_FROM_DN, "cn=undelete,cn=from,cn=dn"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONAddAssuranceCompletedAccessLogMessage minimalLogMessage =
           (JSONAddAssuranceCompletedAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), ASSURANCE_COMPLETE);
      assertEquals(minimalLogMessage.getOperationType(), ADD);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());
      assertNull(minimalLogMessage.getAdditionalInformation());
      assertNull(minimalLogMessage.getMatchedDN());
      assertEquals(minimalLogMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalLogMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalLogMessage.getUncachedDataAccessed());
      assertNull(minimalLogMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalLogMessage.getProcessingTimeMillis());
      assertNull(minimalLogMessage.getIntermediateResponsesReturned());
      assertEquals(minimalLogMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getMissingPrivileges(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getAlternateAuthorizationDN());
      assertNull(minimalLogMessage.getAssuredReplicationLocalLevel());
      assertNull(minimalLogMessage.getAssuredReplicationRemoteLevel());
      assertNull(minimalLogMessage.getAssuredReplicationTimeoutMillis());
      assertNull(minimalLogMessage.getResponseDelayedByAssurance());
      assertEquals(minimalLogMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           Collections.emptySet());
      assertEquals(
           minimalLogMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getReplicationChangeID());
      assertNull(minimalLogMessage.getLocalAssuranceSatisfied());
      assertNull(minimalLogMessage.getRemoteAssuranceSatisfied());
      assertEquals(minimalLogMessage.getServerResults(),
           Collections.emptyList());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());
      assertEquals(minimalLogMessage.getAttributeNames(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getUndeleteFromDN());


      // Read the fully-populated log message.
      final JSONAddAssuranceCompletedAccessLogMessage populatedLogMessage =
           (JSONAddAssuranceCompletedAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), ASSURANCE_COMPLETE);
      assertEquals(populatedLogMessage.getOperationType(), ADD);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedLogMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedLogMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedLogMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedLogMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedLogMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedLogMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedLogMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedLogMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedLogMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedLogMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);
      assertEquals(populatedLogMessage.getAlternateAuthorizationDN(),
           DEFAULT_AUTHZ_DN);
      assertEquals(populatedLogMessage.getAssuredReplicationLocalLevel(),
           DEFAULT_LOCAL_ASSURANCE_LEVEL);
      assertEquals(populatedLogMessage.getAssuredReplicationRemoteLevel(),
           DEFAULT_REMOTE_ASSURANCE_LEVEL);
      assertEquals(
           populatedLogMessage.getAssuredReplicationTimeoutMillis().longValue(),
           DEFAULT_ASSURANCE_TIMEOUT_MILLIS);
      assertEquals(populatedLogMessage.getResponseDelayedByAssurance(),
           DEFAULT_RESPONSE_DELAYED_BY_ASSURANCE);
      assertEquals(
           populatedLogMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           DEFAULT_INDEXES_NEAR_ENTRY_LIMIT);
      assertEquals(
           populatedLogMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           DEFAULT_INDEXES_EXCEEDING_ENTRY_LIMIT);
      assertEquals(populatedLogMessage.getReplicationChangeID(),
           DEFAULT_REPLICATION_CHANGE_ID);
      assertEquals(populatedLogMessage.getLocalAssuranceSatisfied(),
           DEFAULT_LOCAL_ASSURANCE_SATISFIED);
      assertEquals(populatedLogMessage.getRemoteAssuranceSatisfied(),
           DEFAULT_REMOTE_ASSURANCE_SATISFIED);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      final JSONIntermediateClientResponseControl intermediateClientResponse =
           populatedLogMessage.getIntermediateClientResponseControl();
      assertNotNull(intermediateClientResponse);
      assertNotNull(intermediateClientResponse.getControlObject());
      assertEquals(intermediateClientResponse.getUpstreamServerAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerAddress());
      assertEquals(intermediateClientResponse.getUpstreamServerSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerSecure());
      assertEquals(intermediateClientResponse.getServerName(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getServerName());
      assertEquals(intermediateClientResponse.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getSessionID());
      assertEquals(intermediateClientResponse.getResponseID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getResponseID());
      assertNotNull(intermediateClientResponse.getUpstreamResponse());
      assertNotNull(intermediateClientResponse.toString());

      final List<JSONAssuredReplicationServerResult> serverResults =
           populatedLogMessage.getServerResults();
      assertEquals(serverResults.size(), 2);
      assertNotNull(serverResults.get(0).toString());
      assertEquals(serverResults.get(0).getResultCode(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(0).getResultCode());
      assertEquals(serverResults.get(0).getReplicationServerID(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(0).
                getReplicationServerID());
      assertEquals(serverResults.get(0).getReplicaID(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(0).getReplicaID());
      assertNotNull(serverResults.get(1).toString());
      assertEquals(serverResults.get(1).getResultCode(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(1).getResultCode());
      assertEquals(serverResults.get(1).getReplicationServerID(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(1).
                getReplicationServerID());
      assertEquals(serverResults.get(1).getReplicaID(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(1).getReplicaID());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "ou=test,dc=example,dc=com");
      assertEquals(populatedLogMessage.getAttributeNames(),
           StaticUtils.setOf("objectClass", "ou"));
      assertEquals(populatedLogMessage.getUndeleteFromDN(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         REQUEST, BIND);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         REQUEST, BIND,
         createField(BIND_PROTOCOL_VERSION, "3"),
         createField(BIND_AUTHENTICATION_TYPE,
              BindRequestAuthenticationType.SASL.name()),
         createField(BIND_DN, ""),
         createField(BIND_SASL_MECHANISM, "PLAIN"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONBindRequestAccessLogMessage minimalLogMessage =
           (JSONBindRequestAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), REQUEST);
      assertEquals(minimalLogMessage.getOperationType(), BIND);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());

      // Message-specific fields.
      assertNull(minimalLogMessage.getProtocolVersion());
      assertNull(minimalLogMessage.getAuthenticationType());
      assertNull(minimalLogMessage.getDN());
      assertNull(minimalLogMessage.getSASLMechanismName());


      // Read the fully-populated log message.
      final JSONBindRequestAccessLogMessage populatedLogMessage =
           (JSONBindRequestAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), REQUEST);
      assertEquals(populatedLogMessage.getOperationType(), BIND);
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

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getProtocolVersion(), "3");
      assertEquals(populatedLogMessage.getAuthenticationType(),
           BindRequestAuthenticationType.SASL);
      assertEquals(populatedLogMessage.getDN(), "");
      assertEquals(populatedLogMessage.getSASLMechanismName(), "PLAIN");


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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         FORWARD, BIND);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         FORWARD, BIND,
         createField(BIND_PROTOCOL_VERSION, "3"),
         createField(BIND_AUTHENTICATION_TYPE,
              BindRequestAuthenticationType.SASL.name()),
         createField(BIND_DN, ""),
         createField(BIND_SASL_MECHANISM, "PLAIN"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONBindForwardAccessLogMessage minimalLogMessage =
           (JSONBindForwardAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), FORWARD);
      assertEquals(minimalLogMessage.getOperationType(), BIND);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());

      // Message-specific fields.
      assertNull(minimalLogMessage.getProtocolVersion());
      assertNull(minimalLogMessage.getAuthenticationType());
      assertNull(minimalLogMessage.getDN());
      assertNull(minimalLogMessage.getSASLMechanismName());


      // Read the fully-populated log message.
      final JSONBindForwardAccessLogMessage populatedLogMessage =
           (JSONBindForwardAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), FORWARD);
      assertEquals(populatedLogMessage.getOperationType(), BIND);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getProtocolVersion(), "3");
      assertEquals(populatedLogMessage.getAuthenticationType(),
           BindRequestAuthenticationType.SASL);
      assertEquals(populatedLogMessage.getDN(), "");
      assertEquals(populatedLogMessage.getSASLMechanismName(), "PLAIN");


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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         FORWARD_FAILED, BIND);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         FORWARD_FAILED, BIND,
         createField(BIND_PROTOCOL_VERSION, "3"),
         createField(BIND_AUTHENTICATION_TYPE,
              BindRequestAuthenticationType.SASL.name()),
         createField(BIND_DN, ""),
         createField(BIND_SASL_MECHANISM, "PLAIN"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONBindForwardFailedAccessLogMessage minimalLogMessage =
           (JSONBindForwardFailedAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(minimalLogMessage.getOperationType(), BIND);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());

      // Message-specific fields.
      assertNull(minimalLogMessage.getProtocolVersion());
      assertNull(minimalLogMessage.getAuthenticationType());
      assertNull(minimalLogMessage.getDN());
      assertNull(minimalLogMessage.getSASLMechanismName());


      // Read the fully-populated log message.
      final JSONBindForwardFailedAccessLogMessage populatedLogMessage =
           (JSONBindForwardFailedAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(populatedLogMessage.getOperationType(), BIND);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getProtocolVersion(), "3");
      assertEquals(populatedLogMessage.getAuthenticationType(),
           BindRequestAuthenticationType.SASL);
      assertEquals(populatedLogMessage.getDN(), "");
      assertEquals(populatedLogMessage.getSASLMechanismName(), "PLAIN");


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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         RESULT, BIND);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         RESULT, BIND,
         createField(BIND_PROTOCOL_VERSION, "3"),
         createField(BIND_AUTHENTICATION_TYPE,
              BindRequestAuthenticationType.SASL.name()),
         createField(BIND_DN, ""),
         createField(BIND_SASL_MECHANISM, "PLAIN"),
         createField(BIND_AUTHENTICATION_DN, "cn=authentication,cn=dn"),
         createField(BIND_AUTHORIZATION_DN, "cn=authorization,cn=dn"),
         createField(BIND_AUTHENTICATION_FAILURE_REASON, new JSONObject(
           createField(BIND_AUTHENTICATION_FAILURE_REASON_ID,
                AuthenticationFailureReason.FAILURE_TYPE_ACCOUNT_NOT_USABLE),
           createField(BIND_AUTHENTICATION_FAILURE_REASON_NAME,
                AuthenticationFailureReason.FAILURE_NAME_ACCOUNT_NOT_USABLE),
           createField(BIND_AUTHENTICATION_FAILURE_REASON_MESSAGE,
                "failure-reason-message"))),
         createField(BIND_RETIRED_PASSWORD_USED, false),
         createField(CLIENT_CONNECTION_POLICY, "client-connection-policy"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONBindResultAccessLogMessage minimalLogMessage =
           (JSONBindResultAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), RESULT);
      assertEquals(minimalLogMessage.getOperationType(), BIND);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());
      assertNull(minimalLogMessage.getAdditionalInformation());
      assertNull(minimalLogMessage.getMatchedDN());
      assertEquals(minimalLogMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalLogMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalLogMessage.getUncachedDataAccessed());
      assertNull(minimalLogMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalLogMessage.getProcessingTimeMillis());
      assertNull(minimalLogMessage.getIntermediateResponsesReturned());
      assertEquals(minimalLogMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getMissingPrivileges(),
           Collections.emptySet());

      // Message-specific fields.
      assertNull(minimalLogMessage.getProtocolVersion());
      assertNull(minimalLogMessage.getAuthenticationType());
      assertNull(minimalLogMessage.getDN());
      assertNull(minimalLogMessage.getSASLMechanismName());
      assertNull(minimalLogMessage.getAuthenticationDN());
      assertNull(minimalLogMessage.getAuthorizationDN());
      assertNull(minimalLogMessage.getAuthenticationFailureID());
      assertNull(minimalLogMessage.getAuthenticationFailureName());
      assertNull(minimalLogMessage.getAuthenticationFailureMessage());
      assertNull(minimalLogMessage.getRetiredPasswordUsed());
      assertNull(minimalLogMessage.getClientConnectionPolicy());


      // Read the fully-populated log message.
      final JSONBindResultAccessLogMessage populatedLogMessage =
           (JSONBindResultAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), RESULT);
      assertEquals(populatedLogMessage.getOperationType(), BIND);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedLogMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedLogMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedLogMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedLogMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedLogMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedLogMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedLogMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedLogMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedLogMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedLogMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      final JSONIntermediateClientResponseControl intermediateClientResponse =
           populatedLogMessage.getIntermediateClientResponseControl();
      assertNotNull(intermediateClientResponse);
      assertNotNull(intermediateClientResponse.getControlObject());
      assertEquals(intermediateClientResponse.getUpstreamServerAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerAddress());
      assertEquals(intermediateClientResponse.getUpstreamServerSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerSecure());
      assertEquals(intermediateClientResponse.getServerName(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getServerName());
      assertEquals(intermediateClientResponse.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getSessionID());
      assertEquals(intermediateClientResponse.getResponseID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getResponseID());
      assertNotNull(intermediateClientResponse.getUpstreamResponse());
      assertNotNull(intermediateClientResponse.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getProtocolVersion(), "3");
      assertEquals(populatedLogMessage.getAuthenticationType(),
           BindRequestAuthenticationType.SASL);
      assertEquals(populatedLogMessage.getDN(), "");
      assertEquals(populatedLogMessage.getSASLMechanismName(), "PLAIN");
      assertEquals(populatedLogMessage.getAuthenticationDN(),
           "cn=authentication,cn=dn");
      assertEquals(populatedLogMessage.getAuthorizationDN(),
           "cn=authorization,cn=dn");
      assertEquals(populatedLogMessage.getAuthenticationFailureID().intValue(),
           AuthenticationFailureReason.FAILURE_TYPE_ACCOUNT_NOT_USABLE);
      assertEquals(populatedLogMessage.getAuthenticationFailureName(),
           AuthenticationFailureReason.FAILURE_NAME_ACCOUNT_NOT_USABLE);
      assertEquals(populatedLogMessage.getAuthenticationFailureMessage(),
           "failure-reason-message");
      assertEquals(populatedLogMessage.getRetiredPasswordUsed(),
           Boolean.FALSE);
      assertEquals(populatedLogMessage.getClientConnectionPolicy(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         REQUEST, COMPARE);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         REQUEST, COMPARE,
         createField(COMPARE_ENTRY_DN, "cn=compare,cn=dn"),
         createField(COMPARE_ATTRIBUTE_NAME, "description"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONCompareRequestAccessLogMessage minimalLogMessage =
           (JSONCompareRequestAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), REQUEST);
      assertEquals(minimalLogMessage.getOperationType(), COMPARE);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());
      assertNull(minimalLogMessage.getAttributeName());


      // Read the fully-populated log message.
      final JSONCompareRequestAccessLogMessage populatedLogMessage =
           (JSONCompareRequestAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), REQUEST);
      assertEquals(populatedLogMessage.getOperationType(), COMPARE);
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

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "cn=compare,cn=dn");
      assertEquals(populatedLogMessage.getAttributeName(), "description");


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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         FORWARD, COMPARE);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         FORWARD, COMPARE,
         createField(COMPARE_ENTRY_DN, "cn=compare,cn=dn"),
         createField(COMPARE_ATTRIBUTE_NAME, "description"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONCompareForwardAccessLogMessage minimalLogMessage =
           (JSONCompareForwardAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), FORWARD);
      assertEquals(minimalLogMessage.getOperationType(), COMPARE);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());
      assertNull(minimalLogMessage.getAttributeName());


      // Read the fully-populated log message.
      final JSONCompareForwardAccessLogMessage populatedLogMessage =
           (JSONCompareForwardAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), FORWARD);
      assertEquals(populatedLogMessage.getOperationType(), COMPARE);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "cn=compare,cn=dn");
      assertEquals(populatedLogMessage.getAttributeName(), "description");


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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         FORWARD_FAILED, COMPARE);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         FORWARD_FAILED, COMPARE,
         createField(COMPARE_ENTRY_DN, "cn=compare,cn=dn"),
         createField(COMPARE_ATTRIBUTE_NAME, "description"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONCompareForwardFailedAccessLogMessage minimalLogMessage =
           (JSONCompareForwardFailedAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(minimalLogMessage.getOperationType(), COMPARE);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());
      assertNull(minimalLogMessage.getAttributeName());


      // Read the fully-populated log message.
      final JSONCompareForwardFailedAccessLogMessage populatedLogMessage =
           (JSONCompareForwardFailedAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(populatedLogMessage.getOperationType(), COMPARE);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "cn=compare,cn=dn");
      assertEquals(populatedLogMessage.getAttributeName(), "description");


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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         RESULT, COMPARE);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         RESULT, COMPARE,
         createField(COMPARE_ENTRY_DN, "cn=compare,cn=dn"),
         createField(COMPARE_ATTRIBUTE_NAME, "description"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONCompareResultAccessLogMessage minimalLogMessage =
           (JSONCompareResultAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), RESULT);
      assertEquals(minimalLogMessage.getOperationType(), COMPARE);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());
      assertNull(minimalLogMessage.getAdditionalInformation());
      assertNull(minimalLogMessage.getMatchedDN());
      assertEquals(minimalLogMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalLogMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalLogMessage.getUncachedDataAccessed());
      assertNull(minimalLogMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalLogMessage.getProcessingTimeMillis());
      assertNull(minimalLogMessage.getIntermediateResponsesReturned());
      assertEquals(minimalLogMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getMissingPrivileges(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getAlternateAuthorizationDN());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());
      assertNull(minimalLogMessage.getAttributeName());


      // Read the fully-populated log message.
      final JSONCompareResultAccessLogMessage populatedLogMessage =
           (JSONCompareResultAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), RESULT);
      assertEquals(populatedLogMessage.getOperationType(), COMPARE);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedLogMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedLogMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedLogMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedLogMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedLogMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedLogMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedLogMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedLogMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedLogMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedLogMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);
      assertEquals(populatedLogMessage.getAlternateAuthorizationDN(),
           DEFAULT_AUTHZ_DN);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      final JSONIntermediateClientResponseControl intermediateClientResponse =
           populatedLogMessage.getIntermediateClientResponseControl();
      assertNotNull(intermediateClientResponse);
      assertNotNull(intermediateClientResponse.getControlObject());
      assertEquals(intermediateClientResponse.getUpstreamServerAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerAddress());
      assertEquals(intermediateClientResponse.getUpstreamServerSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerSecure());
      assertEquals(intermediateClientResponse.getServerName(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getServerName());
      assertEquals(intermediateClientResponse.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getSessionID());
      assertEquals(intermediateClientResponse.getResponseID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getResponseID());
      assertNotNull(intermediateClientResponse.getUpstreamResponse());
      assertNotNull(intermediateClientResponse.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "cn=compare,cn=dn");
      assertEquals(populatedLogMessage.getAttributeName(), "description");


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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         REQUEST, DELETE);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         REQUEST, DELETE,
         createField(DELETE_ENTRY_DN, "cn=delete,cn=dn"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONDeleteRequestAccessLogMessage minimalLogMessage =
           (JSONDeleteRequestAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), REQUEST);
      assertEquals(minimalLogMessage.getOperationType(), DELETE);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());


      // Read the fully-populated log message.
      final JSONDeleteRequestAccessLogMessage populatedLogMessage =
           (JSONDeleteRequestAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), REQUEST);
      assertEquals(populatedLogMessage.getOperationType(), DELETE);
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

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "cn=delete,cn=dn");


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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         FORWARD, DELETE);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         FORWARD, DELETE,
         createField(DELETE_ENTRY_DN, "cn=delete,cn=dn"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONDeleteForwardAccessLogMessage minimalLogMessage =
           (JSONDeleteForwardAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), FORWARD);
      assertEquals(minimalLogMessage.getOperationType(), DELETE);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());


      // Read the fully-populated log message.
      final JSONDeleteForwardAccessLogMessage populatedLogMessage =
           (JSONDeleteForwardAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), FORWARD);
      assertEquals(populatedLogMessage.getOperationType(), DELETE);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "cn=delete,cn=dn");


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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         FORWARD_FAILED, DELETE);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         FORWARD_FAILED, DELETE,
         createField(DELETE_ENTRY_DN, "cn=delete,cn=dn"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONDeleteForwardFailedAccessLogMessage minimalLogMessage =
           (JSONDeleteForwardFailedAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(minimalLogMessage.getOperationType(), DELETE);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());


      // Read the fully-populated log message.
      final JSONDeleteForwardFailedAccessLogMessage populatedLogMessage =
           (JSONDeleteForwardFailedAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(populatedLogMessage.getOperationType(), DELETE);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "cn=delete,cn=dn");


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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         RESULT, DELETE);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         RESULT, DELETE,
         createField(DELETE_ENTRY_DN, "cn=delete,cn=dn"),
         createField(DELETE_SOFT_DELETED_ENTRY_DN, "cn=soft,cn=deleted"),
         createField(CHANGE_TO_SOFT_DELETED_ENTRY, false));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONDeleteResultAccessLogMessage minimalLogMessage =
           (JSONDeleteResultAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), RESULT);
      assertEquals(minimalLogMessage.getOperationType(), DELETE);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());
      assertNull(minimalLogMessage.getAdditionalInformation());
      assertNull(minimalLogMessage.getMatchedDN());
      assertEquals(minimalLogMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalLogMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalLogMessage.getUncachedDataAccessed());
      assertNull(minimalLogMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalLogMessage.getProcessingTimeMillis());
      assertNull(minimalLogMessage.getIntermediateResponsesReturned());
      assertEquals(minimalLogMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getMissingPrivileges(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getAlternateAuthorizationDN());
      assertNull(minimalLogMessage.getAssuredReplicationLocalLevel());
      assertNull(minimalLogMessage.getAssuredReplicationRemoteLevel());
      assertNull(minimalLogMessage.getAssuredReplicationTimeoutMillis());
      assertNull(minimalLogMessage.getResponseDelayedByAssurance());
      assertEquals(minimalLogMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           Collections.emptySet());
      assertEquals(
           minimalLogMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getReplicationChangeID());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());
      assertNull(minimalLogMessage.getSoftDeletedEntryDN());
      assertNull(minimalLogMessage.getChangeToSoftDeletedEntry());


      // Read the fully-populated log message.
      final JSONDeleteResultAccessLogMessage populatedLogMessage =
           (JSONDeleteResultAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), RESULT);
      assertEquals(populatedLogMessage.getOperationType(), DELETE);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedLogMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedLogMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedLogMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedLogMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedLogMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedLogMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedLogMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedLogMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedLogMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedLogMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);
      assertEquals(populatedLogMessage.getAlternateAuthorizationDN(),
           DEFAULT_AUTHZ_DN);
      assertEquals(populatedLogMessage.getAssuredReplicationLocalLevel(),
           DEFAULT_LOCAL_ASSURANCE_LEVEL);
      assertEquals(populatedLogMessage.getAssuredReplicationRemoteLevel(),
           DEFAULT_REMOTE_ASSURANCE_LEVEL);
      assertEquals(
           populatedLogMessage.getAssuredReplicationTimeoutMillis().longValue(),
           DEFAULT_ASSURANCE_TIMEOUT_MILLIS);
      assertEquals(populatedLogMessage.getResponseDelayedByAssurance(),
           DEFAULT_RESPONSE_DELAYED_BY_ASSURANCE);
      assertEquals(
           populatedLogMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           DEFAULT_INDEXES_NEAR_ENTRY_LIMIT);
      assertEquals(
           populatedLogMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           DEFAULT_INDEXES_EXCEEDING_ENTRY_LIMIT);
      assertEquals(populatedLogMessage.getReplicationChangeID(),
           DEFAULT_REPLICATION_CHANGE_ID);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      final JSONIntermediateClientResponseControl intermediateClientResponse =
           populatedLogMessage.getIntermediateClientResponseControl();
      assertNotNull(intermediateClientResponse);
      assertNotNull(intermediateClientResponse.getControlObject());
      assertEquals(intermediateClientResponse.getUpstreamServerAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerAddress());
      assertEquals(intermediateClientResponse.getUpstreamServerSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerSecure());
      assertEquals(intermediateClientResponse.getServerName(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getServerName());
      assertEquals(intermediateClientResponse.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getSessionID());
      assertEquals(intermediateClientResponse.getResponseID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getResponseID());
      assertNotNull(intermediateClientResponse.getUpstreamResponse());
      assertNotNull(intermediateClientResponse.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "cn=delete,cn=dn");
      assertEquals(populatedLogMessage.getSoftDeletedEntryDN(),
           "cn=soft,cn=deleted");
      assertEquals(populatedLogMessage.getChangeToSoftDeletedEntry(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         ASSURANCE_COMPLETE, DELETE);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         ASSURANCE_COMPLETE, DELETE,
         createField(DELETE_ENTRY_DN, "cn=delete,cn=dn"),
         createField(DELETE_SOFT_DELETED_ENTRY_DN, "cn=soft,cn=deleted"),
         createField(CHANGE_TO_SOFT_DELETED_ENTRY, false));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONDeleteAssuranceCompletedAccessLogMessage minimalLogMessage =
           (JSONDeleteAssuranceCompletedAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), ASSURANCE_COMPLETE);
      assertEquals(minimalLogMessage.getOperationType(), DELETE);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());
      assertNull(minimalLogMessage.getAdditionalInformation());
      assertNull(minimalLogMessage.getMatchedDN());
      assertEquals(minimalLogMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalLogMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalLogMessage.getUncachedDataAccessed());
      assertNull(minimalLogMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalLogMessage.getProcessingTimeMillis());
      assertNull(minimalLogMessage.getIntermediateResponsesReturned());
      assertEquals(minimalLogMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getMissingPrivileges(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getAlternateAuthorizationDN());
      assertNull(minimalLogMessage.getAssuredReplicationLocalLevel());
      assertNull(minimalLogMessage.getAssuredReplicationRemoteLevel());
      assertNull(minimalLogMessage.getAssuredReplicationTimeoutMillis());
      assertNull(minimalLogMessage.getResponseDelayedByAssurance());
      assertEquals(minimalLogMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           Collections.emptySet());
      assertEquals(
           minimalLogMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getReplicationChangeID());
      assertNull(minimalLogMessage.getLocalAssuranceSatisfied());
      assertNull(minimalLogMessage.getRemoteAssuranceSatisfied());
      assertEquals(minimalLogMessage.getServerResults(),
           Collections.emptyList());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());
      assertNull(minimalLogMessage.getSoftDeletedEntryDN());
      assertNull(minimalLogMessage.getChangeToSoftDeletedEntry());


      // Read the fully-populated log message.
      final JSONDeleteAssuranceCompletedAccessLogMessage populatedLogMessage =
           (JSONDeleteAssuranceCompletedAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), ASSURANCE_COMPLETE);
      assertEquals(populatedLogMessage.getOperationType(), DELETE);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedLogMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedLogMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedLogMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedLogMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedLogMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedLogMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedLogMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedLogMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedLogMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedLogMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);
      assertEquals(populatedLogMessage.getAlternateAuthorizationDN(),
           DEFAULT_AUTHZ_DN);
      assertEquals(populatedLogMessage.getAssuredReplicationLocalLevel(),
           DEFAULT_LOCAL_ASSURANCE_LEVEL);
      assertEquals(populatedLogMessage.getAssuredReplicationRemoteLevel(),
           DEFAULT_REMOTE_ASSURANCE_LEVEL);
      assertEquals(
           populatedLogMessage.getAssuredReplicationTimeoutMillis().longValue(),
           DEFAULT_ASSURANCE_TIMEOUT_MILLIS);
      assertEquals(populatedLogMessage.getResponseDelayedByAssurance(),
           DEFAULT_RESPONSE_DELAYED_BY_ASSURANCE);
      assertEquals(
           populatedLogMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           DEFAULT_INDEXES_NEAR_ENTRY_LIMIT);
      assertEquals(
           populatedLogMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           DEFAULT_INDEXES_EXCEEDING_ENTRY_LIMIT);
      assertEquals(populatedLogMessage.getReplicationChangeID(),
           DEFAULT_REPLICATION_CHANGE_ID);
      assertEquals(populatedLogMessage.getLocalAssuranceSatisfied(),
           DEFAULT_LOCAL_ASSURANCE_SATISFIED);
      assertEquals(populatedLogMessage.getRemoteAssuranceSatisfied(),
           DEFAULT_REMOTE_ASSURANCE_SATISFIED);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      final JSONIntermediateClientResponseControl intermediateClientResponse =
           populatedLogMessage.getIntermediateClientResponseControl();
      assertNotNull(intermediateClientResponse);
      assertNotNull(intermediateClientResponse.getControlObject());
      assertEquals(intermediateClientResponse.getUpstreamServerAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerAddress());
      assertEquals(intermediateClientResponse.getUpstreamServerSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerSecure());
      assertEquals(intermediateClientResponse.getServerName(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getServerName());
      assertEquals(intermediateClientResponse.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getSessionID());
      assertEquals(intermediateClientResponse.getResponseID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getResponseID());
      assertNotNull(intermediateClientResponse.getUpstreamResponse());
      assertNotNull(intermediateClientResponse.toString());

      final List<JSONAssuredReplicationServerResult> serverResults =
           populatedLogMessage.getServerResults();
      assertEquals(serverResults.size(), 2);
      assertNotNull(serverResults.get(0).toString());
      assertEquals(serverResults.get(0).getResultCode(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(0).getResultCode());
      assertEquals(serverResults.get(0).getReplicationServerID(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(0).
                getReplicationServerID());
      assertEquals(serverResults.get(0).getReplicaID(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(0).getReplicaID());
      assertNotNull(serverResults.get(1).toString());
      assertEquals(serverResults.get(1).getResultCode(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(1).getResultCode());
      assertEquals(serverResults.get(1).getReplicationServerID(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(1).
                getReplicationServerID());
      assertEquals(serverResults.get(1).getReplicaID(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(1).getReplicaID());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "cn=delete,cn=dn");
      assertEquals(populatedLogMessage.getSoftDeletedEntryDN(),
           "cn=soft,cn=deleted");
      assertEquals(populatedLogMessage.getChangeToSoftDeletedEntry(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         REQUEST, EXTENDED);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         REQUEST, EXTENDED,
         createField(EXTENDED_REQUEST_OID, "1.2.3.4.5"),
         createField(EXTENDED_REQUEST_TYPE, "extended-request-type"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONExtendedRequestAccessLogMessage minimalLogMessage =
           (JSONExtendedRequestAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), REQUEST);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());

      // Message-specific fields.
      assertNull(minimalLogMessage.getRequestOID());
      assertNull(minimalLogMessage.getRequestType());


      // Read the fully-populated log message.
      final JSONExtendedRequestAccessLogMessage populatedLogMessage =
           (JSONExtendedRequestAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), REQUEST);
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

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getRequestOID(), "1.2.3.4.5");
      assertEquals(populatedLogMessage.getRequestType(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         FORWARD, EXTENDED);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         FORWARD, EXTENDED,
         createField(EXTENDED_REQUEST_OID, "1.2.3.4.5"),
         createField(EXTENDED_REQUEST_TYPE, "extended-request-type"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONExtendedForwardAccessLogMessage minimalLogMessage =
           (JSONExtendedForwardAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), FORWARD);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());

      // Message-specific fields.
      assertNull(minimalLogMessage.getRequestOID());
      assertNull(minimalLogMessage.getRequestType());


      // Read the fully-populated log message.
      final JSONExtendedForwardAccessLogMessage populatedLogMessage =
           (JSONExtendedForwardAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), FORWARD);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getRequestOID(), "1.2.3.4.5");
      assertEquals(populatedLogMessage.getRequestType(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         FORWARD_FAILED, EXTENDED);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         FORWARD_FAILED, EXTENDED,
         createField(EXTENDED_REQUEST_OID, "1.2.3.4.5"),
         createField(EXTENDED_REQUEST_TYPE, "extended-request-type"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONExtendedForwardFailedAccessLogMessage minimalLogMessage =
           (JSONExtendedForwardFailedAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), FORWARD_FAILED);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());

      // Message-specific fields.
      assertNull(minimalLogMessage.getRequestOID());
      assertNull(minimalLogMessage.getRequestType());


      // Read the fully-populated log message.
      final JSONExtendedForwardFailedAccessLogMessage populatedLogMessage =
           (JSONExtendedForwardFailedAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), FORWARD_FAILED);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getRequestOID(), "1.2.3.4.5");
      assertEquals(populatedLogMessage.getRequestType(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         RESULT, EXTENDED);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         RESULT, EXTENDED,
         createField(EXTENDED_REQUEST_OID, "1.2.3.4.5"),
         createField(EXTENDED_REQUEST_TYPE, "extended-request-type"),
         createField(EXTENDED_RESPONSE_OID, "1.2.3.4.6"),
         createField(EXTENDED_RESPONSE_TYPE, "extended-response-type"),
         createField(CLIENT_CONNECTION_POLICY, "client-connection-policy"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONExtendedResultAccessLogMessage minimalLogMessage =
           (JSONExtendedResultAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), RESULT);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());
      assertNull(minimalLogMessage.getAdditionalInformation());
      assertNull(minimalLogMessage.getMatchedDN());
      assertEquals(minimalLogMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalLogMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalLogMessage.getUncachedDataAccessed());
      assertNull(minimalLogMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalLogMessage.getProcessingTimeMillis());
      assertNull(minimalLogMessage.getIntermediateResponsesReturned());
      assertEquals(minimalLogMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getMissingPrivileges(),
           Collections.emptySet());

      // Message-specific fields.
      assertNull(minimalLogMessage.getRequestOID());
      assertNull(minimalLogMessage.getRequestType());
      assertNull(minimalLogMessage.getResponseOID());
      assertNull(minimalLogMessage.getResponseType());
      assertNull(minimalLogMessage.getClientConnectionPolicy());


      // Read the fully-populated log message.
      final JSONExtendedResultAccessLogMessage populatedLogMessage =
           (JSONExtendedResultAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), RESULT);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedLogMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedLogMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedLogMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedLogMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedLogMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedLogMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedLogMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedLogMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedLogMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedLogMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      final JSONIntermediateClientResponseControl intermediateClientResponse =
           populatedLogMessage.getIntermediateClientResponseControl();
      assertNotNull(intermediateClientResponse);
      assertNotNull(intermediateClientResponse.getControlObject());
      assertEquals(intermediateClientResponse.getUpstreamServerAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerAddress());
      assertEquals(intermediateClientResponse.getUpstreamServerSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerSecure());
      assertEquals(intermediateClientResponse.getServerName(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getServerName());
      assertEquals(intermediateClientResponse.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getSessionID());
      assertEquals(intermediateClientResponse.getResponseID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getResponseID());
      assertNotNull(intermediateClientResponse.getUpstreamResponse());
      assertNotNull(intermediateClientResponse.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getRequestOID(), "1.2.3.4.5");
      assertEquals(populatedLogMessage.getRequestType(),
           "extended-request-type");
      assertEquals(populatedLogMessage.getResponseOID(), "1.2.3.4.6");
      assertEquals(populatedLogMessage.getResponseType(),
           "extended-response-type");
      assertEquals(populatedLogMessage.getClientConnectionPolicy(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         REQUEST, MODIFY);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         REQUEST, MODIFY,
         createField(MODIFY_ENTRY_DN, "cn=modify,cn=dn"),
         createField(MODIFY_ATTRIBUTES,
              createArray("mod-attr-1", "mod-attr-2")));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONModifyRequestAccessLogMessage minimalLogMessage =
           (JSONModifyRequestAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), REQUEST);
      assertEquals(minimalLogMessage.getOperationType(), MODIFY);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());
      assertEquals(minimalLogMessage.getAttributeNames(),
           Collections.emptySet());


      // Read the fully-populated log message.
      final JSONModifyRequestAccessLogMessage populatedLogMessage =
           (JSONModifyRequestAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), REQUEST);
      assertEquals(populatedLogMessage.getOperationType(), MODIFY);
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

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "cn=modify,cn=dn");
      assertEquals(populatedLogMessage.getAttributeNames(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         FORWARD, MODIFY);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         FORWARD, MODIFY,
         createField(MODIFY_ENTRY_DN, "cn=modify,cn=dn"),
         createField(MODIFY_ATTRIBUTES,
              createArray("mod-attr-1", "mod-attr-2")));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONModifyForwardAccessLogMessage minimalLogMessage =
           (JSONModifyForwardAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), FORWARD);
      assertEquals(minimalLogMessage.getOperationType(), MODIFY);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());
      assertEquals(minimalLogMessage.getAttributeNames(),
           Collections.emptySet());


      // Read the fully-populated log message.
      final JSONModifyForwardAccessLogMessage populatedLogMessage =
           (JSONModifyForwardAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), FORWARD);
      assertEquals(populatedLogMessage.getOperationType(), MODIFY);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "cn=modify,cn=dn");
      assertEquals(populatedLogMessage.getAttributeNames(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         FORWARD_FAILED, MODIFY);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         FORWARD_FAILED, MODIFY,
         createField(MODIFY_ENTRY_DN, "cn=modify,cn=dn"),
         createField(MODIFY_ATTRIBUTES,
              createArray("mod-attr-1", "mod-attr-2")));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONModifyForwardFailedAccessLogMessage minimalLogMessage =
           (JSONModifyForwardFailedAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(minimalLogMessage.getOperationType(), MODIFY);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());
      assertEquals(minimalLogMessage.getAttributeNames(),
           Collections.emptySet());


      // Read the fully-populated log message.
      final JSONModifyForwardFailedAccessLogMessage populatedLogMessage =
           (JSONModifyForwardFailedAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(populatedLogMessage.getOperationType(), MODIFY);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "cn=modify,cn=dn");
      assertEquals(populatedLogMessage.getAttributeNames(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         RESULT, MODIFY);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         RESULT, MODIFY,
         createField(MODIFY_ENTRY_DN, "cn=modify,cn=dn"),
         createField(MODIFY_ATTRIBUTES,
              createArray("mod-attr-1", "mod-attr-2")),
         createField(CHANGE_TO_SOFT_DELETED_ENTRY, false));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONModifyResultAccessLogMessage minimalLogMessage =
           (JSONModifyResultAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), RESULT);
      assertEquals(minimalLogMessage.getOperationType(), MODIFY);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());
      assertNull(minimalLogMessage.getAdditionalInformation());
      assertNull(minimalLogMessage.getMatchedDN());
      assertEquals(minimalLogMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalLogMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalLogMessage.getUncachedDataAccessed());
      assertNull(minimalLogMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalLogMessage.getProcessingTimeMillis());
      assertNull(minimalLogMessage.getIntermediateResponsesReturned());
      assertEquals(minimalLogMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getMissingPrivileges(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getAlternateAuthorizationDN());
      assertNull(minimalLogMessage.getAssuredReplicationLocalLevel());
      assertNull(minimalLogMessage.getAssuredReplicationRemoteLevel());
      assertNull(minimalLogMessage.getAssuredReplicationTimeoutMillis());
      assertNull(minimalLogMessage.getResponseDelayedByAssurance());
      assertEquals(minimalLogMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           Collections.emptySet());
      assertEquals(
           minimalLogMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getReplicationChangeID());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());
      assertEquals(minimalLogMessage.getAttributeNames(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getChangeToSoftDeletedEntry());


      // Read the fully-populated log message.
      final JSONModifyResultAccessLogMessage populatedLogMessage =
           (JSONModifyResultAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), RESULT);
      assertEquals(populatedLogMessage.getOperationType(), MODIFY);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedLogMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedLogMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedLogMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedLogMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedLogMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedLogMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedLogMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedLogMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedLogMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedLogMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);
      assertEquals(populatedLogMessage.getAlternateAuthorizationDN(),
           DEFAULT_AUTHZ_DN);
      assertEquals(populatedLogMessage.getAssuredReplicationLocalLevel(),
           DEFAULT_LOCAL_ASSURANCE_LEVEL);
      assertEquals(populatedLogMessage.getAssuredReplicationRemoteLevel(),
           DEFAULT_REMOTE_ASSURANCE_LEVEL);
      assertEquals(
           populatedLogMessage.getAssuredReplicationTimeoutMillis().longValue(),
           DEFAULT_ASSURANCE_TIMEOUT_MILLIS);
      assertEquals(populatedLogMessage.getResponseDelayedByAssurance(),
           DEFAULT_RESPONSE_DELAYED_BY_ASSURANCE);
      assertEquals(
           populatedLogMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           DEFAULT_INDEXES_NEAR_ENTRY_LIMIT);
      assertEquals(
           populatedLogMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           DEFAULT_INDEXES_EXCEEDING_ENTRY_LIMIT);
      assertEquals(populatedLogMessage.getReplicationChangeID(),
           DEFAULT_REPLICATION_CHANGE_ID);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      final JSONIntermediateClientResponseControl intermediateClientResponse =
           populatedLogMessage.getIntermediateClientResponseControl();
      assertNotNull(intermediateClientResponse);
      assertNotNull(intermediateClientResponse.getControlObject());
      assertEquals(intermediateClientResponse.getUpstreamServerAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerAddress());
      assertEquals(intermediateClientResponse.getUpstreamServerSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerSecure());
      assertEquals(intermediateClientResponse.getServerName(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getServerName());
      assertEquals(intermediateClientResponse.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getSessionID());
      assertEquals(intermediateClientResponse.getResponseID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getResponseID());
      assertNotNull(intermediateClientResponse.getUpstreamResponse());
      assertNotNull(intermediateClientResponse.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "cn=modify,cn=dn");
      assertEquals(populatedLogMessage.getAttributeNames(),
           StaticUtils.setOf("mod-attr-1", "mod-attr-2"));
      assertEquals(populatedLogMessage.getChangeToSoftDeletedEntry(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         ASSURANCE_COMPLETE, MODIFY);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         ASSURANCE_COMPLETE, MODIFY,
         createField(MODIFY_ENTRY_DN, "cn=modify,cn=dn"),
         createField(MODIFY_ATTRIBUTES,
              createArray("mod-attr-1", "mod-attr-2")),
         createField(CHANGE_TO_SOFT_DELETED_ENTRY, false));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONModifyAssuranceCompletedAccessLogMessage minimalLogMessage =
           (JSONModifyAssuranceCompletedAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), ASSURANCE_COMPLETE);
      assertEquals(minimalLogMessage.getOperationType(), MODIFY);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());
      assertNull(minimalLogMessage.getAdditionalInformation());
      assertNull(minimalLogMessage.getMatchedDN());
      assertEquals(minimalLogMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalLogMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalLogMessage.getUncachedDataAccessed());
      assertNull(minimalLogMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalLogMessage.getProcessingTimeMillis());
      assertNull(minimalLogMessage.getIntermediateResponsesReturned());
      assertEquals(minimalLogMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getMissingPrivileges(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getAlternateAuthorizationDN());
      assertNull(minimalLogMessage.getAssuredReplicationLocalLevel());
      assertNull(minimalLogMessage.getAssuredReplicationRemoteLevel());
      assertNull(minimalLogMessage.getAssuredReplicationTimeoutMillis());
      assertNull(minimalLogMessage.getResponseDelayedByAssurance());
      assertEquals(minimalLogMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           Collections.emptySet());
      assertEquals(
           minimalLogMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getReplicationChangeID());
      assertNull(minimalLogMessage.getLocalAssuranceSatisfied());
      assertNull(minimalLogMessage.getRemoteAssuranceSatisfied());
      assertEquals(minimalLogMessage.getServerResults(),
           Collections.emptyList());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());
      assertNull(minimalLogMessage.getChangeToSoftDeletedEntry());


      // Read the fully-populated log message.
      final JSONModifyAssuranceCompletedAccessLogMessage populatedLogMessage =
           (JSONModifyAssuranceCompletedAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), ASSURANCE_COMPLETE);
      assertEquals(populatedLogMessage.getOperationType(), MODIFY);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedLogMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedLogMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedLogMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedLogMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedLogMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedLogMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedLogMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedLogMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedLogMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedLogMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);
      assertEquals(populatedLogMessage.getAlternateAuthorizationDN(),
           DEFAULT_AUTHZ_DN);
      assertEquals(populatedLogMessage.getAssuredReplicationLocalLevel(),
           DEFAULT_LOCAL_ASSURANCE_LEVEL);
      assertEquals(populatedLogMessage.getAssuredReplicationRemoteLevel(),
           DEFAULT_REMOTE_ASSURANCE_LEVEL);
      assertEquals(
           populatedLogMessage.getAssuredReplicationTimeoutMillis().longValue(),
           DEFAULT_ASSURANCE_TIMEOUT_MILLIS);
      assertEquals(populatedLogMessage.getResponseDelayedByAssurance(),
           DEFAULT_RESPONSE_DELAYED_BY_ASSURANCE);
      assertEquals(
           populatedLogMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           DEFAULT_INDEXES_NEAR_ENTRY_LIMIT);
      assertEquals(
           populatedLogMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           DEFAULT_INDEXES_EXCEEDING_ENTRY_LIMIT);
      assertEquals(populatedLogMessage.getReplicationChangeID(),
           DEFAULT_REPLICATION_CHANGE_ID);
      assertEquals(populatedLogMessage.getLocalAssuranceSatisfied(),
           DEFAULT_LOCAL_ASSURANCE_SATISFIED);
      assertEquals(populatedLogMessage.getRemoteAssuranceSatisfied(),
           DEFAULT_REMOTE_ASSURANCE_SATISFIED);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      final JSONIntermediateClientResponseControl intermediateClientResponse =
           populatedLogMessage.getIntermediateClientResponseControl();
      assertNotNull(intermediateClientResponse);
      assertNotNull(intermediateClientResponse.getControlObject());
      assertEquals(intermediateClientResponse.getUpstreamServerAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerAddress());
      assertEquals(intermediateClientResponse.getUpstreamServerSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerSecure());
      assertEquals(intermediateClientResponse.getServerName(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getServerName());
      assertEquals(intermediateClientResponse.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getSessionID());
      assertEquals(intermediateClientResponse.getResponseID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getResponseID());
      assertNotNull(intermediateClientResponse.getUpstreamResponse());
      assertNotNull(intermediateClientResponse.toString());

      final List<JSONAssuredReplicationServerResult> serverResults =
           populatedLogMessage.getServerResults();
      assertEquals(serverResults.size(), 2);
      assertNotNull(serverResults.get(0).toString());
      assertEquals(serverResults.get(0).getResultCode(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(0).getResultCode());
      assertEquals(serverResults.get(0).getReplicationServerID(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(0).
                getReplicationServerID());
      assertEquals(serverResults.get(0).getReplicaID(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(0).getReplicaID());
      assertNotNull(serverResults.get(1).toString());
      assertEquals(serverResults.get(1).getResultCode(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(1).getResultCode());
      assertEquals(serverResults.get(1).getReplicationServerID(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(1).
                getReplicationServerID());
      assertEquals(serverResults.get(1).getReplicaID(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(1).getReplicaID());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "cn=modify,cn=dn");
      assertEquals(populatedLogMessage.getAttributeNames(),
           StaticUtils.setOf("mod-attr-1", "mod-attr-2"));
      assertEquals(populatedLogMessage.getChangeToSoftDeletedEntry(),
           Boolean.FALSE);

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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         REQUEST, MODDN);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         REQUEST, MODDN,
         createField(MODDN_ENTRY_DN, "cn=moddn,cn=entry,cn=dn"),
         createField(MODDN_NEW_RDN, "cn=newrdn"),
         createField(MODDN_DELETE_OLD_RDN, true),
         createField(MODDN_NEW_SUPERIOR_DN, "cn=new,cn=superior,cn=dn"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONModifyDNRequestAccessLogMessage minimalLogMessage =
           (JSONModifyDNRequestAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), REQUEST);
      assertEquals(minimalLogMessage.getOperationType(), MODDN);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());
      assertNull(minimalLogMessage.getNewRDN());
      assertNull(minimalLogMessage.getDeleteOldRDN());
      assertNull(minimalLogMessage.getNewSuperiorDN());


      // Read the fully-populated log message.
      final JSONModifyDNRequestAccessLogMessage populatedLogMessage =
           (JSONModifyDNRequestAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), REQUEST);
      assertEquals(populatedLogMessage.getOperationType(), MODDN);
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

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "cn=moddn,cn=entry,cn=dn");
      assertEquals(populatedLogMessage.getNewRDN(), "cn=newrdn");
      assertEquals(populatedLogMessage.getDeleteOldRDN(), Boolean.TRUE);
      assertEquals(populatedLogMessage.getNewSuperiorDN(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         FORWARD, MODDN);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         FORWARD, MODDN,
         createField(MODDN_ENTRY_DN, "cn=moddn,cn=entry,cn=dn"),
         createField(MODDN_NEW_RDN, "cn=newrdn"),
         createField(MODDN_DELETE_OLD_RDN, true),
         createField(MODDN_NEW_SUPERIOR_DN, "cn=new,cn=superior,cn=dn"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONModifyDNForwardAccessLogMessage minimalLogMessage =
           (JSONModifyDNForwardAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), FORWARD);
      assertEquals(minimalLogMessage.getOperationType(), MODDN);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());
      assertNull(minimalLogMessage.getNewRDN());
      assertNull(minimalLogMessage.getDeleteOldRDN());
      assertNull(minimalLogMessage.getNewSuperiorDN());


      // Read the fully-populated log message.
      final JSONModifyDNForwardAccessLogMessage populatedLogMessage =
           (JSONModifyDNForwardAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), FORWARD);
      assertEquals(populatedLogMessage.getOperationType(), MODDN);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "cn=moddn,cn=entry,cn=dn");
      assertEquals(populatedLogMessage.getNewRDN(), "cn=newrdn");
      assertEquals(populatedLogMessage.getDeleteOldRDN(), Boolean.TRUE);
      assertEquals(populatedLogMessage.getNewSuperiorDN(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         FORWARD_FAILED, MODDN);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         FORWARD_FAILED, MODDN,
         createField(MODDN_ENTRY_DN, "cn=moddn,cn=entry,cn=dn"),
         createField(MODDN_NEW_RDN, "cn=newrdn"),
         createField(MODDN_DELETE_OLD_RDN, true),
         createField(MODDN_NEW_SUPERIOR_DN, "cn=new,cn=superior,cn=dn"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONModifyDNForwardFailedAccessLogMessage minimalLogMessage =
           (JSONModifyDNForwardFailedAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(minimalLogMessage.getOperationType(), MODDN);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());
      assertNull(minimalLogMessage.getNewRDN());
      assertNull(minimalLogMessage.getDeleteOldRDN());
      assertNull(minimalLogMessage.getNewSuperiorDN());


      // Read the fully-populated log message.
      final JSONModifyDNForwardFailedAccessLogMessage populatedLogMessage =
           (JSONModifyDNForwardFailedAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(populatedLogMessage.getOperationType(), MODDN);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "cn=moddn,cn=entry,cn=dn");
      assertEquals(populatedLogMessage.getNewRDN(), "cn=newrdn");
      assertEquals(populatedLogMessage.getDeleteOldRDN(), Boolean.TRUE);
      assertEquals(populatedLogMessage.getNewSuperiorDN(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         RESULT, MODDN);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         RESULT, MODDN,
         createField(MODDN_ENTRY_DN, "cn=moddn,cn=entry,cn=dn"),
         createField(MODDN_NEW_RDN, "cn=newrdn"),
         createField(MODDN_DELETE_OLD_RDN, true),
         createField(MODDN_NEW_SUPERIOR_DN, "cn=new,cn=superior,cn=dn"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONModifyDNResultAccessLogMessage minimalLogMessage =
           (JSONModifyDNResultAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), RESULT);
      assertEquals(minimalLogMessage.getOperationType(), MODDN);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());
      assertNull(minimalLogMessage.getAdditionalInformation());
      assertNull(minimalLogMessage.getMatchedDN());
      assertEquals(minimalLogMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalLogMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalLogMessage.getUncachedDataAccessed());
      assertNull(minimalLogMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalLogMessage.getProcessingTimeMillis());
      assertNull(minimalLogMessage.getIntermediateResponsesReturned());
      assertEquals(minimalLogMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getMissingPrivileges(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getAlternateAuthorizationDN());
      assertNull(minimalLogMessage.getAssuredReplicationLocalLevel());
      assertNull(minimalLogMessage.getAssuredReplicationRemoteLevel());
      assertNull(minimalLogMessage.getAssuredReplicationTimeoutMillis());
      assertNull(minimalLogMessage.getResponseDelayedByAssurance());
      assertEquals(minimalLogMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           Collections.emptySet());
      assertEquals(
           minimalLogMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getReplicationChangeID());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());
      assertNull(minimalLogMessage.getNewRDN());
      assertNull(minimalLogMessage.getDeleteOldRDN());
      assertNull(minimalLogMessage.getNewSuperiorDN());


      // Read the fully-populated log message.
      final JSONModifyDNResultAccessLogMessage populatedLogMessage =
           (JSONModifyDNResultAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), RESULT);
      assertEquals(populatedLogMessage.getOperationType(), MODDN);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedLogMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedLogMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedLogMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedLogMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedLogMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedLogMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedLogMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedLogMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedLogMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedLogMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);
      assertEquals(populatedLogMessage.getAlternateAuthorizationDN(),
           DEFAULT_AUTHZ_DN);
      assertEquals(populatedLogMessage.getAssuredReplicationLocalLevel(),
           DEFAULT_LOCAL_ASSURANCE_LEVEL);
      assertEquals(populatedLogMessage.getAssuredReplicationRemoteLevel(),
           DEFAULT_REMOTE_ASSURANCE_LEVEL);
      assertEquals(
           populatedLogMessage.getAssuredReplicationTimeoutMillis().longValue(),
           DEFAULT_ASSURANCE_TIMEOUT_MILLIS);
      assertEquals(populatedLogMessage.getResponseDelayedByAssurance(),
           DEFAULT_RESPONSE_DELAYED_BY_ASSURANCE);
      assertEquals(
           populatedLogMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           DEFAULT_INDEXES_NEAR_ENTRY_LIMIT);
      assertEquals(
           populatedLogMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           DEFAULT_INDEXES_EXCEEDING_ENTRY_LIMIT);
      assertEquals(populatedLogMessage.getReplicationChangeID(),
           DEFAULT_REPLICATION_CHANGE_ID);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      final JSONIntermediateClientResponseControl intermediateClientResponse =
           populatedLogMessage.getIntermediateClientResponseControl();
      assertNotNull(intermediateClientResponse);
      assertNotNull(intermediateClientResponse.getControlObject());
      assertEquals(intermediateClientResponse.getUpstreamServerAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerAddress());
      assertEquals(intermediateClientResponse.getUpstreamServerSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerSecure());
      assertEquals(intermediateClientResponse.getServerName(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getServerName());
      assertEquals(intermediateClientResponse.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getSessionID());
      assertEquals(intermediateClientResponse.getResponseID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getResponseID());
      assertNotNull(intermediateClientResponse.getUpstreamResponse());
      assertNotNull(intermediateClientResponse.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "cn=moddn,cn=entry,cn=dn");
      assertEquals(populatedLogMessage.getNewRDN(), "cn=newrdn");
      assertEquals(populatedLogMessage.getDeleteOldRDN(), Boolean.TRUE);
      assertEquals(populatedLogMessage.getNewSuperiorDN(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         ASSURANCE_COMPLETE, MODDN);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         ASSURANCE_COMPLETE, MODDN,
         createField(MODDN_ENTRY_DN, "cn=moddn,cn=entry,cn=dn"),
         createField(MODDN_NEW_RDN, "cn=newrdn"),
         createField(MODDN_DELETE_OLD_RDN, true),
         createField(MODDN_NEW_SUPERIOR_DN, "cn=new,cn=superior,cn=dn"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONModifyDNAssuranceCompletedAccessLogMessage minimalLogMessage =
           (JSONModifyDNAssuranceCompletedAccessLogMessage)
           reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), ASSURANCE_COMPLETE);
      assertEquals(minimalLogMessage.getOperationType(), MODDN);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());
      assertNull(minimalLogMessage.getAdditionalInformation());
      assertNull(minimalLogMessage.getMatchedDN());
      assertEquals(minimalLogMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalLogMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalLogMessage.getUncachedDataAccessed());
      assertNull(minimalLogMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalLogMessage.getProcessingTimeMillis());
      assertNull(minimalLogMessage.getIntermediateResponsesReturned());
      assertEquals(minimalLogMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getMissingPrivileges(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getAlternateAuthorizationDN());
      assertNull(minimalLogMessage.getAssuredReplicationLocalLevel());
      assertNull(minimalLogMessage.getAssuredReplicationRemoteLevel());
      assertNull(minimalLogMessage.getAssuredReplicationTimeoutMillis());
      assertNull(minimalLogMessage.getResponseDelayedByAssurance());
      assertEquals(minimalLogMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           Collections.emptySet());
      assertEquals(
           minimalLogMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getReplicationChangeID());
      assertNull(minimalLogMessage.getLocalAssuranceSatisfied());
      assertNull(minimalLogMessage.getRemoteAssuranceSatisfied());
      assertEquals(minimalLogMessage.getServerResults(),
           Collections.emptyList());

      // Message-specific fields.
      assertNull(minimalLogMessage.getDN());
      assertNull(minimalLogMessage.getNewRDN());
      assertNull(minimalLogMessage.getDeleteOldRDN());
      assertNull(minimalLogMessage.getNewSuperiorDN());


      // Read the fully-populated log message.
      final JSONModifyDNAssuranceCompletedAccessLogMessage populatedLogMessage =
           (JSONModifyDNAssuranceCompletedAccessLogMessage)
           reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), ASSURANCE_COMPLETE);
      assertEquals(populatedLogMessage.getOperationType(), MODDN);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedLogMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedLogMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedLogMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedLogMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedLogMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedLogMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedLogMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedLogMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedLogMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedLogMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);
      assertEquals(populatedLogMessage.getAlternateAuthorizationDN(),
           DEFAULT_AUTHZ_DN);
      assertEquals(populatedLogMessage.getAssuredReplicationLocalLevel(),
           DEFAULT_LOCAL_ASSURANCE_LEVEL);
      assertEquals(populatedLogMessage.getAssuredReplicationRemoteLevel(),
           DEFAULT_REMOTE_ASSURANCE_LEVEL);
      assertEquals(
           populatedLogMessage.getAssuredReplicationTimeoutMillis().longValue(),
           DEFAULT_ASSURANCE_TIMEOUT_MILLIS);
      assertEquals(populatedLogMessage.getResponseDelayedByAssurance(),
           DEFAULT_RESPONSE_DELAYED_BY_ASSURANCE);
      assertEquals(
           populatedLogMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           DEFAULT_INDEXES_NEAR_ENTRY_LIMIT);
      assertEquals(
           populatedLogMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           DEFAULT_INDEXES_EXCEEDING_ENTRY_LIMIT);
      assertEquals(populatedLogMessage.getReplicationChangeID(),
           DEFAULT_REPLICATION_CHANGE_ID);
      assertEquals(populatedLogMessage.getLocalAssuranceSatisfied(),
           DEFAULT_LOCAL_ASSURANCE_SATISFIED);
      assertEquals(populatedLogMessage.getRemoteAssuranceSatisfied(),
           DEFAULT_REMOTE_ASSURANCE_SATISFIED);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      final JSONIntermediateClientResponseControl intermediateClientResponse =
           populatedLogMessage.getIntermediateClientResponseControl();
      assertNotNull(intermediateClientResponse);
      assertNotNull(intermediateClientResponse.getControlObject());
      assertEquals(intermediateClientResponse.getUpstreamServerAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerAddress());
      assertEquals(intermediateClientResponse.getUpstreamServerSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerSecure());
      assertEquals(intermediateClientResponse.getServerName(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getServerName());
      assertEquals(intermediateClientResponse.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getSessionID());
      assertEquals(intermediateClientResponse.getResponseID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getResponseID());
      assertNotNull(intermediateClientResponse.getUpstreamResponse());
      assertNotNull(intermediateClientResponse.toString());

      final List<JSONAssuredReplicationServerResult> serverResults =
           populatedLogMessage.getServerResults();
      assertEquals(serverResults.size(), 2);
      assertNotNull(serverResults.get(0).toString());
      assertEquals(serverResults.get(0).getResultCode(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(0).getResultCode());
      assertEquals(serverResults.get(0).getReplicationServerID(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(0).
                getReplicationServerID());
      assertEquals(serverResults.get(0).getReplicaID(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(0).getReplicaID());
      assertNotNull(serverResults.get(1).toString());
      assertEquals(serverResults.get(1).getResultCode(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(1).getResultCode());
      assertEquals(serverResults.get(1).getReplicationServerID(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(1).
                getReplicationServerID());
      assertEquals(serverResults.get(1).getReplicaID(),
           DEFAULT_ASSURED_REPLICATION_SERVER_RESULTS.get(1).getReplicaID());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getDN(), "cn=moddn,cn=entry,cn=dn");
      assertEquals(populatedLogMessage.getNewRDN(), "cn=newrdn");
      assertEquals(populatedLogMessage.getDeleteOldRDN(), Boolean.TRUE);
      assertEquals(populatedLogMessage.getNewSuperiorDN(),
           "cn=new,cn=superior,cn=dn");

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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         REQUEST, SEARCH);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         REQUEST, SEARCH,
         createField(SEARCH_BASE_DN, "cn=base,cn=dn"),
         createField(SEARCH_SCOPE_VALUE, SearchScope.SUB.intValue()),
         createField(SEARCH_SCOPE_NAME, SearchScope.SUB.getName()),
         createField(SEARCH_FILTER, "(filter=value)"),
         createField(SEARCH_SIZE_LIMIT, 2345),
         createField(SEARCH_TIME_LIMIT_SECONDS, 3456),
         createField(SEARCH_DEREF_POLICY, DereferencePolicy.NEVER.getName()),
         createField(SEARCH_TYPES_ONLY, false),
         createField(SEARCH_REQUESTED_ATTRIBUTES,
              createArray("requested-attr-1", "requested-attr-2")));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONSearchRequestAccessLogMessage minimalLogMessage =
           (JSONSearchRequestAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), REQUEST);
      assertEquals(minimalLogMessage.getOperationType(), SEARCH);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());

      // Message-specific fields.
      assertNull(minimalLogMessage.getBaseDN());
      assertNull(minimalLogMessage.getScope());
      assertNull(minimalLogMessage.getFilter());
      assertNull(minimalLogMessage.getSizeLimit());
      assertNull(minimalLogMessage.getTimeLimitSeconds());
      assertNull(minimalLogMessage.getDereferencePolicy());
      assertNull(minimalLogMessage.getTypesOnly());
      assertEquals(minimalLogMessage.getRequestedAttributes(),
           Collections.emptyList());


      // Read the fully-populated log message.
      final JSONSearchRequestAccessLogMessage populatedLogMessage =
           (JSONSearchRequestAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), REQUEST);
      assertEquals(populatedLogMessage.getOperationType(), SEARCH);
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

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());


      // Message-specific fields.
      assertEquals(populatedLogMessage.getBaseDN(), "cn=base,cn=dn");
      assertEquals(populatedLogMessage.getScope(), SearchScope.SUB);
      assertEquals(populatedLogMessage.getFilter(), "(filter=value)");
      assertEquals(populatedLogMessage.getSizeLimit().intValue(), 2345);
      assertEquals(populatedLogMessage.getTimeLimitSeconds().intValue(), 3456);
      assertEquals(populatedLogMessage.getDereferencePolicy(),
           DereferencePolicy.NEVER);
      assertEquals(populatedLogMessage.getTypesOnly(), Boolean.FALSE);
      assertEquals(populatedLogMessage.getRequestedAttributes(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         ENTRY, SEARCH);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         ENTRY, SEARCH,
         createField(SEARCH_BASE_DN, "cn=base,cn=dn"),
         createField(SEARCH_SCOPE_VALUE, SearchScope.SUB.intValue()),
         createField(SEARCH_SCOPE_NAME, SearchScope.SUB.getName()),
         createField(SEARCH_FILTER, "(filter=value)"),
         createField(SEARCH_SIZE_LIMIT, 2345),
         createField(SEARCH_TIME_LIMIT_SECONDS, 3456),
         createField(SEARCH_DEREF_POLICY, DereferencePolicy.NEVER.getName()),
         createField(SEARCH_TYPES_ONLY, false),
         createField(SEARCH_REQUESTED_ATTRIBUTES,
              createArray("requested-attr-1", "requested-attr-2")),
         createField(SEARCH_RESULT_ENTRY_DN, "cn=search,cn=entry,cn=dn"),
         createField(SEARCH_RESULT_ENTRY_ATTRIBUTES,
              createArray("entry-attr-1", "entry-attr-2")));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONSearchEntryAccessLogMessage minimalLogMessage =
           (JSONSearchEntryAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), ENTRY);
      assertEquals(minimalLogMessage.getOperationType(), SEARCH);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertEquals(minimalLogMessage.getResponseControlOIDs(),
           Collections.emptySet());

      // Message-specific fields.
      assertNull(minimalLogMessage.getBaseDN());
      assertNull(minimalLogMessage.getScope());
      assertNull(minimalLogMessage.getFilter());
      assertNull(minimalLogMessage.getSizeLimit());
      assertNull(minimalLogMessage.getTimeLimitSeconds());
      assertNull(minimalLogMessage.getDereferencePolicy());
      assertNull(minimalLogMessage.getTypesOnly());
      assertEquals(minimalLogMessage.getRequestedAttributes(),
           Collections.emptyList());
      assertNull(minimalLogMessage.getDN());
      assertEquals(minimalLogMessage.getAttributesReturned(),
           Collections.emptySet());


      // Read the fully-populated log message.
      final JSONSearchEntryAccessLogMessage populatedLogMessage =
           (JSONSearchEntryAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), ENTRY);
      assertEquals(populatedLogMessage.getOperationType(), SEARCH);
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

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());


      // Message-specific fields.
      assertEquals(populatedLogMessage.getBaseDN(), "cn=base,cn=dn");
      assertEquals(populatedLogMessage.getScope(), SearchScope.SUB);
      assertEquals(populatedLogMessage.getFilter(), "(filter=value)");
      assertEquals(populatedLogMessage.getSizeLimit().intValue(), 2345);
      assertEquals(populatedLogMessage.getTimeLimitSeconds().intValue(), 3456);
      assertEquals(populatedLogMessage.getDereferencePolicy(),
           DereferencePolicy.NEVER);
      assertEquals(populatedLogMessage.getTypesOnly(), Boolean.FALSE);
      assertEquals(populatedLogMessage.getRequestedAttributes(),
           Arrays.asList("requested-attr-1", "requested-attr-2"));
      assertEquals(populatedLogMessage.getDN(), "cn=search,cn=entry,cn=dn");
      assertEquals(populatedLogMessage.getAttributesReturned(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         REFERENCE, SEARCH);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         REFERENCE, SEARCH,
         createField(SEARCH_BASE_DN, "cn=base,cn=dn"),
         createField(SEARCH_SCOPE_VALUE, SearchScope.SUB.intValue()),
         createField(SEARCH_SCOPE_NAME, SearchScope.SUB.getName()),
         createField(SEARCH_FILTER, "(filter=value)"),
         createField(SEARCH_SIZE_LIMIT, 2345),
         createField(SEARCH_TIME_LIMIT_SECONDS, 3456),
         createField(SEARCH_DEREF_POLICY, DereferencePolicy.NEVER.getName()),
         createField(SEARCH_TYPES_ONLY, false),
         createField(SEARCH_REQUESTED_ATTRIBUTES,
              createArray("requested-attr-1", "requested-attr-2")),
         createField(REFERRAL_URLS,
              createArray(
                   "ldap://server1.example.com:389/",
                   "ldap://server2.example.com:389/")));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONSearchReferenceAccessLogMessage minimalLogMessage =
           (JSONSearchReferenceAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), REFERENCE);
      assertEquals(minimalLogMessage.getOperationType(), SEARCH);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertEquals(minimalLogMessage.getResponseControlOIDs(),
           Collections.emptySet());

      // Message-specific fields.
      assertNull(minimalLogMessage.getBaseDN());
      assertNull(minimalLogMessage.getScope());
      assertNull(minimalLogMessage.getFilter());
      assertNull(minimalLogMessage.getSizeLimit());
      assertNull(minimalLogMessage.getTimeLimitSeconds());
      assertNull(minimalLogMessage.getDereferencePolicy());
      assertNull(minimalLogMessage.getTypesOnly());
      assertEquals(minimalLogMessage.getRequestedAttributes(),
           Collections.emptyList());
      assertEquals(minimalLogMessage.getReferralURLs(),
           Collections.emptyList());


      // Read the fully-populated log message.
      final JSONSearchReferenceAccessLogMessage populatedLogMessage =
           (JSONSearchReferenceAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), REFERENCE);
      assertEquals(populatedLogMessage.getOperationType(), SEARCH);
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

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());


      // Message-specific fields.
      assertEquals(populatedLogMessage.getBaseDN(), "cn=base,cn=dn");
      assertEquals(populatedLogMessage.getScope(), SearchScope.SUB);
      assertEquals(populatedLogMessage.getFilter(), "(filter=value)");
      assertEquals(populatedLogMessage.getSizeLimit().intValue(), 2345);
      assertEquals(populatedLogMessage.getTimeLimitSeconds().intValue(), 3456);
      assertEquals(populatedLogMessage.getDereferencePolicy(),
           DereferencePolicy.NEVER);
      assertEquals(populatedLogMessage.getTypesOnly(), Boolean.FALSE);
      assertEquals(populatedLogMessage.getRequestedAttributes(),
           Arrays.asList("requested-attr-1", "requested-attr-2"));
      assertEquals(populatedLogMessage.getReferralURLs(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         FORWARD, SEARCH);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         FORWARD, SEARCH,
         createField(SEARCH_BASE_DN, "cn=base,cn=dn"),
         createField(SEARCH_SCOPE_VALUE, SearchScope.SUB.intValue()),
         createField(SEARCH_SCOPE_NAME, SearchScope.SUB.getName()),
         createField(SEARCH_FILTER, "(filter=value)"),
         createField(SEARCH_SIZE_LIMIT, 2345),
         createField(SEARCH_TIME_LIMIT_SECONDS, 3456),
         createField(SEARCH_DEREF_POLICY, DereferencePolicy.NEVER.getName()),
         createField(SEARCH_TYPES_ONLY, false),
         createField(SEARCH_REQUESTED_ATTRIBUTES,
              createArray("requested-attr-1", "requested-attr-2")));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONSearchForwardAccessLogMessage minimalLogMessage =
           (JSONSearchForwardAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), FORWARD);
      assertEquals(minimalLogMessage.getOperationType(), SEARCH);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());

      // Message-specific fields.
      assertNull(minimalLogMessage.getBaseDN());
      assertNull(minimalLogMessage.getScope());
      assertNull(minimalLogMessage.getFilter());
      assertNull(minimalLogMessage.getSizeLimit());
      assertNull(minimalLogMessage.getTimeLimitSeconds());
      assertNull(minimalLogMessage.getDereferencePolicy());
      assertNull(minimalLogMessage.getTypesOnly());
      assertEquals(minimalLogMessage.getRequestedAttributes(),
           Collections.emptyList());


      // Read the fully-populated log message.
      final JSONSearchForwardAccessLogMessage populatedLogMessage =
           (JSONSearchForwardAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), FORWARD);
      assertEquals(populatedLogMessage.getOperationType(), SEARCH);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getBaseDN(), "cn=base,cn=dn");
      assertEquals(populatedLogMessage.getScope(), SearchScope.SUB);
      assertEquals(populatedLogMessage.getFilter(), "(filter=value)");
      assertEquals(populatedLogMessage.getSizeLimit().intValue(), 2345);
      assertEquals(populatedLogMessage.getTimeLimitSeconds().intValue(), 3456);
      assertEquals(populatedLogMessage.getDereferencePolicy(),
           DereferencePolicy.NEVER);
      assertEquals(populatedLogMessage.getTypesOnly(), Boolean.FALSE);
      assertEquals(populatedLogMessage.getRequestedAttributes(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         FORWARD_FAILED, SEARCH);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         FORWARD_FAILED, SEARCH,
         createField(SEARCH_BASE_DN, "cn=base,cn=dn"),
         createField(SEARCH_SCOPE_VALUE, SearchScope.SUB.intValue()),
         createField(SEARCH_SCOPE_NAME, SearchScope.SUB.getName()),
         createField(SEARCH_FILTER, "(filter=value)"),
         createField(SEARCH_SIZE_LIMIT, 2345),
         createField(SEARCH_TIME_LIMIT_SECONDS, 3456),
         createField(SEARCH_DEREF_POLICY, DereferencePolicy.NEVER.getName()),
         createField(SEARCH_TYPES_ONLY, false),
         createField(SEARCH_REQUESTED_ATTRIBUTES,
              createArray("requested-attr-1", "requested-attr-2")));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONSearchForwardFailedAccessLogMessage minimalLogMessage =
           (JSONSearchForwardFailedAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(minimalLogMessage.getOperationType(), SEARCH);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());

      // Message-specific fields.
      assertNull(minimalLogMessage.getBaseDN());
      assertNull(minimalLogMessage.getScope());
      assertNull(minimalLogMessage.getFilter());
      assertNull(minimalLogMessage.getSizeLimit());
      assertNull(minimalLogMessage.getTimeLimitSeconds());
      assertNull(minimalLogMessage.getDereferencePolicy());
      assertNull(minimalLogMessage.getTypesOnly());
      assertEquals(minimalLogMessage.getRequestedAttributes(),
           Collections.emptyList());


      // Read the fully-populated log message.
      final JSONSearchForwardFailedAccessLogMessage populatedLogMessage =
           (JSONSearchForwardFailedAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), FORWARD_FAILED);
      assertEquals(populatedLogMessage.getOperationType(), SEARCH);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getBaseDN(), "cn=base,cn=dn");
      assertEquals(populatedLogMessage.getScope(), SearchScope.SUB);
      assertEquals(populatedLogMessage.getFilter(), "(filter=value)");
      assertEquals(populatedLogMessage.getSizeLimit().intValue(), 2345);
      assertEquals(populatedLogMessage.getTimeLimitSeconds().intValue(), 3456);
      assertEquals(populatedLogMessage.getDereferencePolicy(),
           DereferencePolicy.NEVER);
      assertEquals(populatedLogMessage.getTypesOnly(), Boolean.FALSE);
      assertEquals(populatedLogMessage.getRequestedAttributes(),
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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         RESULT, SEARCH);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         RESULT, SEARCH,
         createField(SEARCH_BASE_DN, "cn=base,cn=dn"),
         createField(SEARCH_SCOPE_VALUE, SearchScope.SUB.intValue()),
         createField(SEARCH_SCOPE_NAME, SearchScope.SUB.getName()),
         createField(SEARCH_FILTER, "(filter=value)"),
         createField(SEARCH_SIZE_LIMIT, 2345),
         createField(SEARCH_TIME_LIMIT_SECONDS, 3456),
         createField(SEARCH_DEREF_POLICY, DereferencePolicy.NEVER.getName()),
         createField(SEARCH_TYPES_ONLY, false),
         createField(SEARCH_REQUESTED_ATTRIBUTES,
              createArray("requested-attr-1", "requested-attr-2")),
         createField(SEARCH_ENTRIES_RETURNED, 4567),
         createField(SEARCH_INDEXED, true));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONSearchResultAccessLogMessage minimalLogMessage =
           (JSONSearchResultAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), RESULT);
      assertEquals(minimalLogMessage.getOperationType(), SEARCH);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());
      assertNull(minimalLogMessage.getTargetHost());
      assertNull(minimalLogMessage.getTargetPort());
      assertNull(minimalLogMessage.getTargetProtocol());
      assertNull(minimalLogMessage.getResultCode());
      assertNull(minimalLogMessage.getDiagnosticMessage());
      assertNull(minimalLogMessage.getAdditionalInformation());
      assertNull(minimalLogMessage.getMatchedDN());
      assertEquals(minimalLogMessage.getReferralURLs(),
           Collections.emptyList());
      assertEquals(minimalLogMessage.getServersAccessed(),
           Collections.emptyList());
      assertNull(minimalLogMessage.getUncachedDataAccessed());
      assertNull(minimalLogMessage.getWorkQueueWaitTimeMillis());
      assertNull(minimalLogMessage.getProcessingTimeMillis());
      assertNull(minimalLogMessage.getIntermediateResponsesReturned());
      assertEquals(minimalLogMessage.getResponseControlOIDs(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getPreAuthorizationUsedPrivileges(),
           Collections.emptySet());
      assertEquals(minimalLogMessage.getMissingPrivileges(),
           Collections.emptySet());
      assertNull(minimalLogMessage.getAlternateAuthorizationDN());
      assertEquals(minimalLogMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           Collections.emptySet());
      assertEquals(
           minimalLogMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           Collections.emptySet());

      // Message-specific fields.
      assertNull(minimalLogMessage.getBaseDN());
      assertNull(minimalLogMessage.getScope());
      assertNull(minimalLogMessage.getFilter());
      assertNull(minimalLogMessage.getSizeLimit());
      assertNull(minimalLogMessage.getTimeLimitSeconds());
      assertNull(minimalLogMessage.getDereferencePolicy());
      assertNull(minimalLogMessage.getTypesOnly());
      assertEquals(minimalLogMessage.getRequestedAttributes(),
           Collections.emptyList());
      assertNull(minimalLogMessage.getEntriesReturned());
      assertNull(minimalLogMessage.getUnindexed());


      // Read the fully-populated log message.
      final JSONSearchResultAccessLogMessage populatedLogMessage =
           (JSONSearchResultAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), RESULT);
      assertEquals(populatedLogMessage.getOperationType(), SEARCH);
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
      assertEquals(populatedLogMessage.getTargetHost(),
           DEFAULT_FORWARD_TARGET_HOST);
      assertEquals(populatedLogMessage.getTargetPort().intValue(),
           DEFAULT_FORWARD_TARGET_PORT);
      assertEquals(populatedLogMessage.getTargetProtocol(),
           DEFAULT_FORWARD_TARGET_PROTOCOL);
      assertEquals(populatedLogMessage.getResultCode(),
           DEFAULT_RESULT_CODE);
      assertEquals(populatedLogMessage.getDiagnosticMessage(),
           DEFAULT_DIAGNOSTIC_MESSAGE);
      assertEquals(populatedLogMessage.getAdditionalInformation(),
           DEFAULT_ADDITIONAL_INFO_MESSAGE);
      assertEquals(populatedLogMessage.getMatchedDN(),
           DEFAULT_MATCHED_DN);
      assertEquals(populatedLogMessage.getReferralURLs(),
           DEFAULT_REFERRAL_URLS);
      assertEquals(populatedLogMessage.getServersAccessed(),
           DEFAULT_SERVERS_ACCESSED);
      assertEquals(populatedLogMessage.getUncachedDataAccessed(),
           DEFAULT_UNCACHED_DATA_ACCESSED);
      assertEquals(
           populatedLogMessage.getWorkQueueWaitTimeMillis().doubleValue(),
           DEFAULT_WORK_QUEUE_WAIT_TIME_MILLIS);
      assertEquals(populatedLogMessage.getProcessingTimeMillis().doubleValue(),
           DEFAULT_PROCESSING_TIME_MILLIS);
      assertEquals(
           populatedLogMessage.getIntermediateResponsesReturned().longValue(),
           DEFAULT_INTERMEDIATE_RESPONSES_RETURNED);
      assertEquals(populatedLogMessage.getResponseControlOIDs(),
           DEFAULT_RESPONSE_CONTROL_OIDS);
      assertEquals(populatedLogMessage.getUsedPrivileges(),
           DEFAULT_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getPreAuthorizationUsedPrivileges(),
           DEFAULT_PRE_AUTHZ_USED_PRIVILEGES);
      assertEquals(populatedLogMessage.getMissingPrivileges(),
           DEFAULT_MISSING_PRIVILEGES);
      assertEquals(populatedLogMessage.getAlternateAuthorizationDN(),
           DEFAULT_AUTHZ_DN);
      assertEquals(
           populatedLogMessage.getIndexesWithKeysAccessedNearEntryLimit(),
           DEFAULT_INDEXES_NEAR_ENTRY_LIMIT);
      assertEquals(
           populatedLogMessage.getIndexesWithKeysAccessedExceedingEntryLimit(),
           DEFAULT_INDEXES_EXCEEDING_ENTRY_LIMIT);

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());

      final JSONIntermediateClientResponseControl intermediateClientResponse =
           populatedLogMessage.getIntermediateClientResponseControl();
      assertNotNull(intermediateClientResponse);
      assertNotNull(intermediateClientResponse.getControlObject());
      assertEquals(intermediateClientResponse.getUpstreamServerAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerAddress());
      assertEquals(intermediateClientResponse.getUpstreamServerSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getUpstreamServerSecure());
      assertEquals(intermediateClientResponse.getServerName(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getServerName());
      assertEquals(intermediateClientResponse.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getSessionID());
      assertEquals(intermediateClientResponse.getResponseID(),
           DEFAULT_INTERMEDIATE_CLIENT_RESPONSE.getResponseID());
      assertNotNull(intermediateClientResponse.getUpstreamResponse());
      assertNotNull(intermediateClientResponse.toString());

      // Message-specific fields.
      assertEquals(populatedLogMessage.getBaseDN(), "cn=base,cn=dn");
      assertEquals(populatedLogMessage.getScope(), SearchScope.SUB);
      assertEquals(populatedLogMessage.getFilter(), "(filter=value)");
      assertEquals(populatedLogMessage.getSizeLimit().intValue(), 2345);
      assertEquals(populatedLogMessage.getTimeLimitSeconds().intValue(), 3456);
      assertEquals(populatedLogMessage.getDereferencePolicy(),
           DereferencePolicy.NEVER);
      assertEquals(populatedLogMessage.getTypesOnly(), Boolean.FALSE);
      assertEquals(populatedLogMessage.getRequestedAttributes(),
           Arrays.asList("requested-attr-1", "requested-attr-2"));
      assertEquals(populatedLogMessage.getUnindexed(), Boolean.FALSE);


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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         REQUEST, UNBIND);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         REQUEST, UNBIND);

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONUnbindRequestAccessLogMessage minimalLogMessage =
           (JSONUnbindRequestAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(minimalLogMessage.getMessageType(), REQUEST);
      assertEquals(minimalLogMessage.getOperationType(), UNBIND);
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
      assertNull(minimalLogMessage.getIntermediateClientRequestControl());
      assertNull(minimalLogMessage.getOperationPurposeRequestControl());


      // Read the fully-populated log message.
      final JSONUnbindRequestAccessLogMessage populatedLogMessage =
           (JSONUnbindRequestAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
      assertEquals(populatedLogMessage.getMessageType(), REQUEST);
      assertEquals(populatedLogMessage.getOperationType(), UNBIND);
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

      final JSONIntermediateClientRequestControl intermediateClientRequest =
           populatedLogMessage.getIntermediateClientRequestControl();
      assertNotNull(intermediateClientRequest);
      assertNotNull(intermediateClientRequest.getControlObject());
      assertEquals(intermediateClientRequest.getDownstreamClientAddress(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientAddress());
      assertEquals(intermediateClientRequest.getDownstreamClientSecure(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getDownstreamClientSecure());
      assertEquals(intermediateClientRequest.getClientIdentity(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientIdentity());
      assertEquals(intermediateClientRequest.getClientName(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getClientName());
      assertEquals(intermediateClientRequest.getSessionID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getSessionID());
      assertEquals(intermediateClientRequest.getRequestID(),
           DEFAULT_INTERMEDIATE_CLIENT_REQUEST.getRequestID());
      assertNotNull(intermediateClientRequest.getDownstreamRequest());
      assertNotNull(intermediateClientRequest.toString());

      final JSONOperationPurposeRequestControl operationPurpose =
           populatedLogMessage.getOperationPurposeRequestControl();
      assertNotNull(operationPurpose);
      assertNotNull(operationPurpose.getControlObject());
      assertEquals(operationPurpose.getApplicationName(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationName());
      assertEquals(operationPurpose.getApplicationVersion(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getApplicationVersion());
      assertEquals(operationPurpose.getCodeLocation(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getCodeLocation());
      assertEquals(operationPurpose.getRequestPurpose(),
           DEFAULT_OPERATION_PURPOSE_REQUEST.getRequestPurpose());
      assertNotNull(operationPurpose.toString());


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
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         INTERMEDIATE_RESPONSE, EXTENDED);

    final JSONObject populatedMessageObject = createPopulatedMessageObject(
         INTERMEDIATE_RESPONSE, EXTENDED,
         createField(EXTENDED_REQUEST_OID, "1.2.3.4.5"),
         createField(EXTENDED_REQUEST_TYPE, "extended-request-type"),
         createField(INTERMEDIATE_RESPONSE_OID, "1.2.3.4.5.6"),
         createField(INTERMEDIATE_RESPONSE_NAME, "intermediate-response-name"),
         createField(INTERMEDIATE_RESPONSE_VALUE,
              "intermediate-response-value"));

    final File logFile = createTempFile(
         minimalMessageObject.toSingleLineString(),
         populatedMessageObject.toSingleLineString());

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      assertNotNull(reader);


      // Read the minimal log message.
      final JSONIntermediateResponseAccessLogMessage minimalLogMessage =
           (JSONIntermediateResponseAccessLogMessage) reader.readMessage();
      assertNotNull(minimalLogMessage);

      // Common fields.
      assertEquals(minimalLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(minimalLogMessage.getLogType(), ACCESS_LOG_TYPE);
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
      final JSONIntermediateResponseAccessLogMessage populatedLogMessage =
           (JSONIntermediateResponseAccessLogMessage) reader.readMessage();
      assertNotNull(populatedLogMessage);

      // Common fields.
      assertEquals(populatedLogMessage.getTimestamp(), DEFAULT_TIMESTAMP_DATE);
      assertEquals(populatedLogMessage.getLogType(), ACCESS_LOG_TYPE);
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

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
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
   * JSON data.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFileNotJSON()
         throws Exception
  {
    final File logFile = createTempFile("This is not valid JSON data");

    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for a file that contains invalid JSON.");
    }
    catch(final IOException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read a file containing a JSON object
   * that doesn't include a timestamp.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadObjectWithoutTimestamp()
         throws Exception
  {
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         CONNECT, null);

    final Map<String,JSONValue> fieldsWithoutTimestamp =
         new LinkedHashMap<>(minimalMessageObject.getFields());
    assertNotNull(fieldsWithoutTimestamp.remove(TIMESTAMP.getFieldName()));
    final JSONObject objectWithoutTimestamp =
         new JSONObject(fieldsWithoutTimestamp);

    final File logFile =
         createTempFile(objectWithoutTimestamp.toSingleLineString());
    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for a file that contains a JSON object " +
           "without a timestamp");
    }
    catch(final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read a file containing a JSON object
   * that doesn't include a message type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadObjectWithoutMessageType()
         throws Exception
  {
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         CONNECT, null);

    final Map<String,JSONValue> fieldsWithoutMessageType =
         new LinkedHashMap<>(minimalMessageObject.getFields());
    assertNotNull(fieldsWithoutMessageType.remove(MESSAGE_TYPE.getFieldName()));
    final JSONObject objectWithoutMessageType =
         new JSONObject(fieldsWithoutMessageType);

    final File logFile =
         createTempFile(objectWithoutMessageType.toSingleLineString());
    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for a file that contains a JSON object " +
           "without a message type");
    }
    catch(final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read a file containing a JSON object
   * that includes an invalid message type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadObjectWithInvalidMessageType()
         throws Exception
  {
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         CONNECT, null);

    final Map<String,JSONValue> fieldsWithInvalidMessageType =
         new LinkedHashMap<>(minimalMessageObject.getFields());
    assertNotNull(fieldsWithInvalidMessageType.put(MESSAGE_TYPE.getFieldName(),
         new JSONString("invalid")));
    final JSONObject objectWithoutMessageType =
         new JSONObject(fieldsWithInvalidMessageType);

    final File logFile =
         createTempFile(objectWithoutMessageType.toSingleLineString());
    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for a file that contains a JSON object " +
           "with an invalid message type");
    }
    catch(final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read a file containing a JSON object
   * for an operation message that doesn't include an operation type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadObjectWithoutOperationType()
         throws Exception
  {
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         REQUEST, ABANDON);

    final Map<String,JSONValue> fieldsWithoutOperationType =
         new LinkedHashMap<>(minimalMessageObject.getFields());
    assertNotNull(fieldsWithoutOperationType.remove(
         OPERATION_TYPE.getFieldName()));
    final JSONObject objectWithoutMessageType =
         new JSONObject(fieldsWithoutOperationType);

    final File logFile =
         createTempFile(objectWithoutMessageType.toSingleLineString());
    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for a file that contains a JSON object " +
           "without an operation type");
    }
    catch(final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read a file containing a JSON object
   * for an operation message that has an invalid operation type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadObjectWithInvalidOperationType()
         throws Exception
  {
    final JSONObject minimalMessageObject = createMinimalMessageObject(
         REQUEST, ABANDON);

    final Map<String,JSONValue> fieldsWithInvalidOperationType =
         new LinkedHashMap<>(minimalMessageObject.getFields());
    assertNotNull(fieldsWithInvalidOperationType.put(
         OPERATION_TYPE.getFieldName(), new JSONString("invalid")));
    final JSONObject objectWithoutMessageType =
         new JSONObject(fieldsWithInvalidOperationType);

    final File logFile =
         createTempFile(objectWithoutMessageType.toSingleLineString());
    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for a file that contains a JSON object " +
           "with an invalid operation type");
    }
    catch(final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read a file containing a JSON object for
   * a forward log message for an unbind operation (which can't be forwarded).
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadUnbindForwardMessage()
         throws Exception
  {
    final JSONObject messageObject = createMinimalMessageObject(
         FORWARD, UNBIND);

    final File logFile =
         createTempFile(messageObject.toSingleLineString());
    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for a forward message with an operation " +
           "type of unbind.");
    }
    catch(final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read a file containing a JSON object for
   * a forward failed log message for an unbind operation (which can't be
   * forwarded).
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadUnbindForwardFailedMessage()
         throws Exception
  {
    final JSONObject messageObject = createMinimalMessageObject(
         FORWARD_FAILED, UNBIND);

    final File logFile =
         createTempFile(messageObject.toSingleLineString());
    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for a forward failed message with an " +
           "operation type of unbind.");
    }
    catch(final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read a file containing a JSON object for
   * a result log message for an unbind operation (which doesn't have a result).
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadUnbindResultMessage()
         throws Exception
  {
    final JSONObject messageObject = createMinimalMessageObject(
         RESULT, UNBIND);

    final File logFile =
         createTempFile(messageObject.toSingleLineString());
    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for a result message with an operation " +
           "type of unbind.");
    }
    catch(final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read a file containing a JSON object for
   * an assurance complete log message for an unbind operation (for which
   * assurance isn't available).
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadUnbindAssuranceCompleteMessage()
         throws Exception
  {
    final JSONObject messageObject = createMinimalMessageObject(
         ASSURANCE_COMPLETE, UNBIND);

    final File logFile =
         createTempFile(messageObject.toSingleLineString());
    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for a result message with an operation " +
           "type of unbind.");
    }
    catch(final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read a file containing a JSON object for
   * an intermediate response log message that doesn't have an operation type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadIntermediateResponseWithoutOperationType()
         throws Exception
  {
    final JSONObject messageObject = createMinimalMessageObject(
         INTERMEDIATE_RESPONSE, null);

    final File logFile =
         createTempFile(messageObject.toSingleLineString());
    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for an intermediate response message " +
           "without an operation type.");
    }
    catch(final LogException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read a file containing a JSON object for
   * an intermediate response log message that has an invalid operation type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadIntermediateResponseWithInvalidOperationType()
         throws Exception
  {
    final JSONObject messageObject = createMinimalMessageObject(
         INTERMEDIATE_RESPONSE, null,
         createField(OPERATION_TYPE, "invalid"));

    final File logFile =
         createTempFile(messageObject.toSingleLineString());
    try (JSONAccessLogReader reader = new JSONAccessLogReader(logFile))
    {
      reader.readMessage();
      fail("Expected an exception for an intermediate response message with " +
           "an invalid operation type.");
    }
    catch(final LogException e)
    {
      // This was expected.
    }
  }
}
