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
package com.unboundid.ldap.sdk.unboundidds.logs;



import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Iterator;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.unboundidds.controls.AssuredReplicationLocalLevel;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationRemoteLevel;



/**
 * This class provides a set of test cases for the {@code AccessLogReader}
 * class.
 */
public class AccessLogReaderTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the ability to read from a file containing only a comment and an
   * empty line using a {@code File} object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyCommentUsingFile()
         throws Exception
  {
    File file = createTempFile(
         "# This is a comment and the next line is empty",
         "");

    AccessLogReader reader = new AccessLogReader(file);

    assertNull(reader.read());
    reader.close();
  }



  /**
   * Tests the ability to read from a file containing only a comment and an
   * empty line using a path.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyCommentUsingPath()
         throws Exception
  {
    File file = createTempFile(
         "# This is a comment and the next line is empty",
         "");

    AccessLogReader reader = new AccessLogReader(file.getAbsolutePath());

    assertNull(reader.read());
    reader.close();
  }



  /**
   * Tests the ability to read from a file containing only a comment and an
   * empty line using a buffered reader.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyCommentUsingBufferedReader()
         throws Exception
  {
    File file = createTempFile(
         "# This is a comment and the next line is empty",
         "");

    AccessLogReader reader =
         new AccessLogReader(new BufferedReader(new FileReader(file)));

    assertNull(reader.read());
    reader.close();
  }



  /**
   * Tests the ability to read from a file containing only a comment and an
   * empty line using a non-buffered reader.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyCommentUsingNonBufferedReader()
         throws Exception
  {
    File file = createTempFile(
         "# This is a comment and the next line is empty",
         "");

    AccessLogReader reader = new AccessLogReader(new FileReader(file));

    assertNull(reader.read());
    reader.close();
  }



  /**
   * Tests the behavior when reading an invalid log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidMessage()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " INVALID";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    try
    {
      reader.read();
      fail("Expected an exception when reading an invalid message");
    }
    catch (LogException le)
    {
      // This was expected.
    }

    reader.close();
  }



  /**
   * Tests the behavior when reading a request message with an invalid operation
   * type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidRequestMessage()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " INVALID REQUEST";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    try
    {
      reader.read();
      fail("Expected an exception when reading an invalid request message");
    }
    catch (LogException le)
    {
      // This was expected.
    }

    reader.close();
  }



  /**
   * Tests the behavior when reading a forward message with an invalid operation
   * type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidForwardMessage()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " INVALID FORWARD";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    try
    {
      reader.read();
      fail("Expected an exception when reading an invalid forward message");
    }
    catch (LogException le)
    {
      // This was expected.
    }

    reader.close();
  }



  /**
   * Tests the behavior when reading a forward failed message with an invalid
   * operation type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidForwardFailedMessage()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " INVALID FORWARD-FAILED";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    try
    {
      reader.read();
      fail("Expected an exception when reading an invalid forward failed " +
           "message");
    }
    catch (LogException le)
    {
      // This was expected.
    }

    reader.close();
  }



  /**
   * Tests the behavior when reading a result message with an invalid operation
   * type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidResultMessage()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " INVALID RESULT";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    try
    {
      reader.read();
      fail("Expected an exception when reading an invalid result message");
    }
    catch (LogException le)
    {
      // This was expected.
    }

    reader.close();
  }



  /**
   * Tests the behavior when reading an assurance completed message with an
   * invalid operation type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidAssuranceCompletedMessage()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " INVALID ASSURANCE-COMPLETE";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    try
    {
      reader.read();
      fail("Expected an exception when reading an invalid assurance " +
           "completed message");
    }
    catch (LogException le)
    {
      // This was expected.
    }

    reader.close();
  }



  /**
   * Provides test coverage for the {@code AccessLogMessage.parse} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAccessLogMessageParse()
         throws Exception
  {
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " CONNECT " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 from=\"1.2.3.4\" to=\"5.6.7.8\" " +
               "protocol=\"LDAP\"";

    ConnectAccessLogMessage m =
         (ConnectAccessLogMessage) AccessLogMessage.parse(s);

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.CONNECT);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getSourceAddress());
    assertEquals(m.getSourceAddress(), "1.2.3.4");

    assertNotNull(m.getTargetAddress());
    assertEquals(m.getTargetAddress(), "5.6.7.8");

    assertNotNull(m.getProtocolName());
    assertEquals(m.getProtocolName(), "LDAP");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);
  }



  /**
   * Tests the ability to read a connect message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadConnect()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " CONNECT " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 from=\"1.2.3.4\" to=\"5.6.7.8\" " +
               "protocol=\"LDAP\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    ConnectAccessLogMessage m = (ConnectAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.CONNECT);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getSourceAddress());
    assertEquals(m.getSourceAddress(), "1.2.3.4");

    assertNotNull(m.getTargetAddress());
    assertEquals(m.getTargetAddress(), "5.6.7.8");

    assertNotNull(m.getProtocolName());
    assertEquals(m.getProtocolName(), "LDAP");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a disconnect message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadDisonnect()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " DISCONNECT " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 reason=\"Client Unbind\" " +
               "msg=\"The client has closed the connection\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    DisconnectAccessLogMessage m = (DisconnectAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.DISCONNECT);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getDisconnectReason());
    assertEquals(m.getDisconnectReason(), "Client Unbind");

    assertNotNull(m.getMessage());
    assertEquals(m.getMessage(), "The client has closed the connection");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a client certificate message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadClientCertificate()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " CLIENT-CERTIFICATE " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 " +
               "peerSubject=\"CN=Peer,O=Test\" " +
               "issuerSubject=\"CN=Issuer,O=Test\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    ClientCertificateAccessLogMessage m =
         (ClientCertificateAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.CLIENT_CERTIFICATE);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getPeerSubject());
    assertEquals(new DN(m.getPeerSubject()), new DN("CN=Peer,O=Test"));

    assertNotNull(m.getIssuerSubject());
    assertEquals(new DN(m.getIssuerSubject()), new DN("CN=Issuer,O=Test"));

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a security negotiation message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadSecurityNegotiation()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " SECURITY-NEGOTIATION " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 " +
               "protocol=\"TLSv1.2\" " +
               "cipher=\"TLS_DHE_RSA_WITH_AES_128_CBC_SHA\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    SecurityNegotiationAccessLogMessage m =
         (SecurityNegotiationAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.SECURITY_NEGOTIATION);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getProtocol());
    assertEquals(m.getProtocol(), "TLSv1.2");

    assertNotNull(m.getCipher());
    assertEquals(m.getCipher(), "TLS_DHE_RSA_WITH_AES_128_CBC_SHA");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a entry-rebalancing request message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadEntryRebalancingRequest()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " ENTRY-REBALANCING-REQUEST " +
         "product=\"Directory Server\" " +
         "instanceName=\"server.example.com:389\" startupID=\"ABCDEFG\" " +
         "rebalancingOp=1 triggeredByConn=2 triggeredByOp=3 " +
         "base=\"ou=subtree,dc=example,dc=com\" sizeLimit=4 " +
         "sourceBackendSet=\"source set\" " +
         "sourceServer=\"source.example.com:1389\" " +
         "targetBackendSet=\"target set\" " +
         "targetServer=\"target.example.com:2389\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    EntryRebalancingRequestAccessLogMessage m =
         (EntryRebalancingRequestAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(),
         AccessLogMessageType.ENTRY_REBALANCING_REQUEST);

    assertNotNull(m.getProductName());
    assertEquals(m.getProductName(), "Directory Server");

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNull(m.getConnectionID());

    assertNotNull(m.getRebalancingOperationID());
    assertEquals(m.getRebalancingOperationID(), Long.valueOf(1L));

    assertNotNull(m.getTriggeringConnectionID());
    assertEquals(m.getTriggeringConnectionID(), Long.valueOf(2L));

    assertNotNull(m.getTriggeringOperationID());
    assertEquals(m.getTriggeringOperationID(), Long.valueOf(3L));

    assertNotNull(m.getSubtreeBaseDN());
    assertEquals(new DN(m.getSubtreeBaseDN()),
         new DN("ou=subtree,dc=example,dc=com"));

    assertNotNull(m.getSizeLimit());
    assertEquals(m.getSizeLimit(), Integer.valueOf(4));

    assertNotNull(m.getSourceBackendSetName());
    assertEquals(m.getSourceBackendSetName(), "source set");

    assertNotNull(m.getSourceBackendServer());
    assertEquals(m.getSourceBackendServer(), "source.example.com:1389");

    assertNotNull(m.getTargetBackendSetName());
    assertEquals(m.getTargetBackendSetName(), "target set");

    assertNotNull(m.getTargetBackendServer());
    assertEquals(m.getTargetBackendServer(), "target.example.com:2389");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a entry-rebalancing result message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadEntryRebalancingResult()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " ENTRY-REBALANCING-RESULT " +
         "product=\"Directory Server\" " +
         "instanceName=\"server.example.com:389\" startupID=\"ABCDEFG\" " +
         "rebalancingOp=1 triggeredByConn=2 triggeredByOp=3 " +
         "base=\"ou=subtree,dc=example,dc=com\" sizeLimit=4 " +
         "sourceBackendSet=\"source set\" " +
         "sourceServer=\"source.example.com:1389\" " +
         "targetBackendSet=\"target set\" " +
         "targetServer=\"target.example.com:2389\" resultCode=80 " +
         "errorMessage=\"error message\" " +
         "adminActionRequired=\"admin action\" sourceAltered=false " +
         "targetAltered=true entriesReadFromSource=5 entriesAddedToTarget=4 " +
         "entriesDeletedFromSource=0";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    EntryRebalancingResultAccessLogMessage m =
         (EntryRebalancingResultAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(),
         AccessLogMessageType.ENTRY_REBALANCING_RESULT);

    assertNotNull(m.getProductName());
    assertEquals(m.getProductName(), "Directory Server");

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNull(m.getConnectionID());

    assertNotNull(m.getRebalancingOperationID());
    assertEquals(m.getRebalancingOperationID(), Long.valueOf(1L));

    assertNotNull(m.getTriggeringConnectionID());
    assertEquals(m.getTriggeringConnectionID(), Long.valueOf(2L));

    assertNotNull(m.getTriggeringOperationID());
    assertEquals(m.getTriggeringOperationID(), Long.valueOf(3L));

    assertNotNull(m.getSubtreeBaseDN());
    assertEquals(new DN(m.getSubtreeBaseDN()),
         new DN("ou=subtree,dc=example,dc=com"));

    assertNotNull(m.getSizeLimit());
    assertEquals(m.getSizeLimit(), Integer.valueOf(4));

    assertNotNull(m.getSourceBackendSetName());
    assertEquals(m.getSourceBackendSetName(), "source set");

    assertNotNull(m.getSourceBackendServer());
    assertEquals(m.getSourceBackendServer(), "source.example.com:1389");

    assertNotNull(m.getTargetBackendSetName());
    assertEquals(m.getTargetBackendSetName(), "target set");

    assertNotNull(m.getTargetBackendServer());
    assertEquals(m.getTargetBackendServer(), "target.example.com:2389");

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), ResultCode.OTHER);

    assertNotNull(m.getErrorMessage());
    assertEquals(m.getErrorMessage(), "error message");

    assertNotNull(m.getAdminActionRequired());
    assertEquals(m.getAdminActionRequired(), "admin action");

    assertNotNull(m.sourceAltered());
    assertFalse(m.sourceAltered());

    assertNotNull(m.targetAltered());
    assertTrue(m.targetAltered());

    assertNotNull(m.getEntriesReadFromSource());
    assertEquals(m.getEntriesReadFromSource(), Integer.valueOf(5));

    assertNotNull(m.getEntriesAddedToTarget());
    assertEquals(m.getEntriesAddedToTarget(), Integer.valueOf(4));

    assertNotNull(m.getEntriesDeletedFromSource());
    assertEquals(m.getEntriesDeletedFromSource(), Integer.valueOf(0));

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read an abandon request message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadAbandonRequest()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " ABANDON REQUEST " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "idToAbandon=4";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    AbandonRequestAccessLogMessage m =
         (AbandonRequestAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.REQUEST);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.ABANDON);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getMessageIDToAbandon());
    assertEquals(m.getMessageIDToAbandon(), Integer.valueOf(4));

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read an abandon forward message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadAbandonForward()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " ABANDON FORWARD " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "idToAbandon=4 targetHost=\"5.6.7.8\" targetPort=389 " +
               "targetProtocol=\"LDAP\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    AbandonForwardAccessLogMessage m =
         (AbandonForwardAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.FORWARD);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.ABANDON);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getMessageIDToAbandon());
    assertEquals(m.getMessageIDToAbandon(), Integer.valueOf(4));

    assertNotNull(m.getTargetHost());
    assertEquals(m.getTargetHost(), "5.6.7.8");

    assertNotNull(m.getTargetPort());
    assertEquals(m.getTargetPort(), Integer.valueOf(389));

    assertNotNull(m.getTargetProtocol());
    assertEquals(m.getTargetProtocol(), "LDAP");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read an abandon result message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadAbandonResult()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " ABANDON RESULT " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "idToAbandon=4 resultCode=121 " +
               "message=\"This request cannot be canceled\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 qtime=4 " +
               "referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    AbandonResultAccessLogMessage m =
         (AbandonResultAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.RESULT);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.ABANDON);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getMessageIDToAbandon());
    assertEquals(m.getMessageIDToAbandon(), Integer.valueOf(4));

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), ResultCode.CANNOT_CANCEL);

    assertNotNull(m.getDiagnosticMessage());
    assertEquals(m.getDiagnosticMessage(), "This request cannot be canceled");

    assertNotNull(m.getAdditionalInformation());
    assertEquals(m.getAdditionalInformation(), "foo");

    assertNotNull(m.getMatchedDN());
    assertEquals(m.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(m.getProcessingTimeMillis());
    assertEquals(m.getProcessingTimeMillis(), Double.valueOf("0.123"));

    assertNotNull(m.getQueueTimeMillis());
    assertEquals(m.getQueueTimeMillis(), Double.valueOf("4"));

    assertNotNull(m.getIntermediateClientResult());
    assertEquals(m.getIntermediateClientResult(),
                 "app='UnboundID Directory Server'");

    assertNotNull(m.getReferralURLs());
    assertEquals(m.getReferralURLs().size(), 2);
    assertTrue(m.getReferralURLs().contains("ldap://server1.example.com:389/"));
    assertTrue(m.getReferralURLs().contains("ldap://server2.example.com:389/"));

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read an add request message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadAddRequest()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " ADD REQUEST " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"dc=example,dc=com\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    AddRequestAccessLogMessage m = (AddRequestAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.REQUEST);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.ADD);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "dc=example,dc=com");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read an add forward message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadAddForward()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " ADD FORWARD " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"dc=example,dc=com\" targetHost=\"5.6.7.8\" " +
               "targetPort=389 targetProtocol=\"LDAP\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    AddForwardAccessLogMessage m = (AddForwardAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.FORWARD);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.ADD);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "dc=example,dc=com");

    assertNotNull(m.getTargetHost());
    assertEquals(m.getTargetHost(), "5.6.7.8");

    assertNotNull(m.getTargetPort());
    assertEquals(m.getTargetPort(), Integer.valueOf(389));

    assertNotNull(m.getTargetProtocol());
    assertEquals(m.getTargetProtocol(), "LDAP");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read an add forward failed message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadAddForwardFailed()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " ADD FORWARD-FAILED " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"dc=example,dc=com\" targetHost=\"5.6.7.8\" " +
               "targetPort=389 targetProtocol=\"LDAP\" resultCode=80 " +
               "message=\"oops\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    AddForwardFailedAccessLogMessage m =
         (AddForwardFailedAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.FORWARD_FAILED);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.ADD);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "dc=example,dc=com");

    assertNotNull(m.getTargetHost());
    assertEquals(m.getTargetHost(), "5.6.7.8");

    assertNotNull(m.getTargetPort());
    assertEquals(m.getTargetPort(), Integer.valueOf(389));

    assertNotNull(m.getTargetProtocol());
    assertEquals(m.getTargetProtocol(), "LDAP");

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), Integer.valueOf(80));

    assertNotNull(m.getDiagnosticMessage());
    assertEquals(m.getDiagnosticMessage(), "oops");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read an add result message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadAddResult()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " ADD RESULT " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"ou=People,dc=example,dc=com\" resultCode=32 " +
               "message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 qtime=4 " +
               "referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "authzDN=\"uid=someone,ou=People,dc=example,dc=com\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    AddResultAccessLogMessage m = (AddResultAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.RESULT);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.ADD);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(m.getDiagnosticMessage());
    assertEquals(m.getDiagnosticMessage(), "The entry doesn't exist");

    assertNotNull(m.getAdditionalInformation());
    assertEquals(m.getAdditionalInformation(), "foo");

    assertNotNull(m.getMatchedDN());
    assertEquals(m.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(m.getProcessingTimeMillis());
    assertEquals(m.getProcessingTimeMillis(), Double.valueOf("0.123"));

    assertNotNull(m.getQueueTimeMillis());
    assertEquals(m.getQueueTimeMillis(), Double.valueOf("4"));

    assertNotNull(m.getIntermediateClientResult());
    assertEquals(m.getIntermediateClientResult(),
                 "app='UnboundID Directory Server'");

    assertNotNull(m.getReferralURLs());
    assertEquals(m.getReferralURLs().size(), 2);
    assertTrue(m.getReferralURLs().contains("ldap://server1.example.com:389/"));
    assertTrue(m.getReferralURLs().contains("ldap://server2.example.com:389/"));

    assertNotNull(m.getAlternateAuthorizationDN());
    assertEquals(m.getAlternateAuthorizationDN(),
                 "uid=someone,ou=People,dc=example,dc=com");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read an add assurance completed message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadAddAssuranceCompleted()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " ADD ASSURANCE-COMPLETE " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"ou=People,dc=example,dc=com\" resultCode=32 " +
               "message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 qtime=4 " +
               "referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "authzDN=\"uid=someone,ou=People,dc=example,dc=com\" " +
               "localAssuranceLevel=\"PROCESSED_ALL_SERVERS\" " +
               "remoteAssuranceLevel=\"PROCESSED_ALL_REMOTE_SERVERS\" " +
               "assuranceTimeoutMillis=5000 responseDelayedByAssurance=false " +
               "localAssuranceSatisfied=true remoteAssuranceSatisfied=false " +
               "serverAssuranceResults=\"assurance-results\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    AddAssuranceCompletedAccessLogMessage m =
         (AddAssuranceCompletedAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.ASSURANCE_COMPLETE);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.ADD);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(m.getDiagnosticMessage());
    assertEquals(m.getDiagnosticMessage(), "The entry doesn't exist");

    assertNotNull(m.getAdditionalInformation());
    assertEquals(m.getAdditionalInformation(), "foo");

    assertNotNull(m.getMatchedDN());
    assertEquals(m.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(m.getProcessingTimeMillis());
    assertEquals(m.getProcessingTimeMillis(), Double.valueOf("0.123"));

    assertNotNull(m.getQueueTimeMillis());
    assertEquals(m.getQueueTimeMillis(), Double.valueOf("4"));

    assertNotNull(m.getIntermediateClientResult());
    assertEquals(m.getIntermediateClientResult(),
                 "app='UnboundID Directory Server'");

    assertNotNull(m.getReferralURLs());
    assertEquals(m.getReferralURLs().size(), 2);
    assertTrue(m.getReferralURLs().contains("ldap://server1.example.com:389/"));
    assertTrue(m.getReferralURLs().contains("ldap://server2.example.com:389/"));

    assertNotNull(m.getAlternateAuthorizationDN());
    assertEquals(m.getAlternateAuthorizationDN(),
                 "uid=someone,ou=People,dc=example,dc=com");

    assertNotNull(m.getAssuredReplicationLocalLevel());
    assertEquals(m.getAssuredReplicationLocalLevel(),
         AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS);

    assertNotNull(m.getAssuredReplicationRemoteLevel());
    assertEquals(m.getAssuredReplicationRemoteLevel(),
         AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS);

    assertNotNull(m.getAssuredReplicationTimeoutMillis());
    assertEquals(m.getAssuredReplicationTimeoutMillis().longValue(), 5000L);

    assertNotNull(m.getResponseDelayedByAssurance());
    assertFalse(m.getResponseDelayedByAssurance().booleanValue());

    assertNotNull(m.getLocalAssuranceSatisfied());
    assertTrue(m.getLocalAssuranceSatisfied().booleanValue());

    assertNotNull(m.getRemoteAssuranceSatisfied());
    assertFalse(m.getRemoteAssuranceSatisfied().booleanValue());

    assertNotNull(m.getServerAssuranceResults());
    assertEquals(m.getServerAssuranceResults(), "assurance-results");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a bind request message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadBindRequest()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " BIND REQUEST " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" version=3 " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "authType=\"INTERNAL\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    BindRequestAccessLogMessage m = (BindRequestAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.REQUEST);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.BIND);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNull(m.getRequesterDN());

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getProtocolVersion());
    assertEquals(m.getProtocolVersion(), "3");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getAuthenticationType());
    assertEquals(m.getAuthenticationType(),
                 BindRequestAuthenticationType.INTERNAL);

    assertNull(m.getSASLMechanismName());

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a bind forward message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadBindForward()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " BIND FORWARD " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" version=3 " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "authType=\"INTERNAL\" targetHost=\"5.6.7.8\" targetPort=389 " +
               "targetProtocol=\"LDAP\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    BindForwardAccessLogMessage m = (BindForwardAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.FORWARD);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.BIND);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNull(m.getRequesterDN());

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getProtocolVersion());
    assertEquals(m.getProtocolVersion(), "3");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getAuthenticationType());
    assertEquals(m.getAuthenticationType(),
                 BindRequestAuthenticationType.INTERNAL);

    assertNull(m.getSASLMechanismName());

    assertNotNull(m.getTargetHost());
    assertEquals(m.getTargetHost(), "5.6.7.8");

    assertNotNull(m.getTargetPort());
    assertEquals(m.getTargetPort(), Integer.valueOf(389));

    assertNotNull(m.getTargetProtocol());
    assertEquals(m.getTargetProtocol(), "LDAP");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a bind forward failed message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadBindForwardFailed()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " BIND FORWARD-FAILED " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" version=3 " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "authType=\"INTERNAL\" targetHost=\"5.6.7.8\" targetPort=389 " +
               "targetProtocol=\"LDAP\" resultCode=80 message=\"oops\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    BindForwardFailedAccessLogMessage m =
         (BindForwardFailedAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.FORWARD_FAILED);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.BIND);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNull(m.getRequesterDN());

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getProtocolVersion());
    assertEquals(m.getProtocolVersion(), "3");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getAuthenticationType());
    assertEquals(m.getAuthenticationType(),
                 BindRequestAuthenticationType.INTERNAL);

    assertNull(m.getSASLMechanismName());

    assertNotNull(m.getTargetHost());
    assertEquals(m.getTargetHost(), "5.6.7.8");

    assertNotNull(m.getTargetPort());
    assertEquals(m.getTargetPort(), Integer.valueOf(389));

    assertNotNull(m.getTargetProtocol());
    assertEquals(m.getTargetProtocol(), "LDAP");

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), Integer.valueOf(80));

    assertNotNull(m.getDiagnosticMessage());
    assertEquals(m.getDiagnosticMessage(), "oops");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a bind result message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadBindResult()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " BIND RESULT " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" version=3 " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "authType=\"SIMPLE\" resultCode=49 " +
               "message=\"Invalid credentials\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 qtime=4 " +
               "referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "authFailureID=1234 authFailureReason=\"Wrong password\" " +
               "authDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "authzDN=\"uid=someone,ou=People,dc=example,dc=com\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    BindResultAccessLogMessage m = (BindResultAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.RESULT);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.BIND);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getProtocolVersion());
    assertEquals(m.getProtocolVersion(), "3");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getAuthenticationType());
    assertEquals(m.getAuthenticationType(),
                 BindRequestAuthenticationType.SIMPLE);

    assertNull(m.getSASLMechanismName());

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), ResultCode.INVALID_CREDENTIALS);

    assertNotNull(m.getDiagnosticMessage());
    assertEquals(m.getDiagnosticMessage(), "Invalid credentials");

    assertNotNull(m.getAdditionalInformation());
    assertEquals(m.getAdditionalInformation(), "foo");

    assertNotNull(m.getMatchedDN());
    assertEquals(m.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(m.getProcessingTimeMillis());
    assertEquals(m.getProcessingTimeMillis(), Double.valueOf("0.123"));

    assertNotNull(m.getQueueTimeMillis());
    assertEquals(m.getQueueTimeMillis(), Double.valueOf("4"));

    assertNotNull(m.getIntermediateClientResult());
    assertEquals(m.getIntermediateClientResult(),
                 "app='UnboundID Directory Server'");

    assertNotNull(m.getReferralURLs());
    assertFalse(m.getReferralURLs().isEmpty());
    assertTrue(m.getReferralURLs().contains("ldap://server1.example.com:389/"));
    assertTrue(m.getReferralURLs().contains("ldap://server2.example.com:389/"));

    assertNotNull(m.getAuthenticationDN());
    assertEquals(m.getAuthenticationDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getAuthorizationDN());
    assertEquals(m.getAuthorizationDN(),
                 "uid=someone,ou=People,dc=example,dc=com");

    assertNotNull(m.getAuthenticationFailureID());
    assertEquals(m.getAuthenticationFailureID(), Long.valueOf(1234));

    assertNotNull(m.getAuthenticationFailureReason());
    assertEquals(m.getAuthenticationFailureReason(), "Wrong password");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a compare request message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadCompareRequest()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " COMPARE REQUEST " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"dc=example,dc=com\" attr=\"description\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    CompareRequestAccessLogMessage m =
         (CompareRequestAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.REQUEST);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.COMPARE);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "dc=example,dc=com");

    assertNotNull(m.getAttributeName());
    assertEquals(m.getAttributeName(), "description");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a compare forward message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadCompareForward()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " COMPARE FORWARD " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"dc=example,dc=com\" attr=\"description\" " +
               "targetHost=\"5.6.7.8\" targetPort=389 targetProtocol=\"LDAP\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    CompareForwardAccessLogMessage m =
         (CompareForwardAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.FORWARD);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.COMPARE);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "dc=example,dc=com");

    assertNotNull(m.getAttributeName());
    assertEquals(m.getAttributeName(), "description");

    assertNotNull(m.getTargetHost());
    assertEquals(m.getTargetHost(), "5.6.7.8");

    assertNotNull(m.getTargetPort());
    assertEquals(m.getTargetPort(), Integer.valueOf(389));

    assertNotNull(m.getTargetProtocol());
    assertEquals(m.getTargetProtocol(), "LDAP");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a compare forward failed message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadCompareForwardFailed()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " COMPARE FORWARD-FAILED " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"dc=example,dc=com\" attr=\"description\" " +
               "targetHost=\"5.6.7.8\" targetPort=389 " +
               "targetProtocol=\"LDAP\" resultCode=80 message=\"oops\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    CompareForwardFailedAccessLogMessage m =
         (CompareForwardFailedAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.FORWARD_FAILED);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.COMPARE);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "dc=example,dc=com");

    assertNotNull(m.getAttributeName());
    assertEquals(m.getAttributeName(), "description");

    assertNotNull(m.getTargetHost());
    assertEquals(m.getTargetHost(), "5.6.7.8");

    assertNotNull(m.getTargetPort());
    assertEquals(m.getTargetPort(), Integer.valueOf(389));

    assertNotNull(m.getTargetProtocol());
    assertEquals(m.getTargetProtocol(), "LDAP");

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), Integer.valueOf(80));

    assertNotNull(m.getDiagnosticMessage());
    assertEquals(m.getDiagnosticMessage(), "oops");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a compare result message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadCompareResult()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " COMPARE RESULT " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"ou=People,dc=example,dc=com\" attr=\"description\" " +
               "resultCode=32 message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 qtime=4 " +
               "referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "authzDN=\"uid=someone,ou=People,dc=example,dc=com\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    CompareResultAccessLogMessage m =
         (CompareResultAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.RESULT);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.COMPARE);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(m.getAttributeName());
    assertEquals(m.getAttributeName(), "description");

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(m.getDiagnosticMessage());
    assertEquals(m.getDiagnosticMessage(), "The entry doesn't exist");

    assertNotNull(m.getAdditionalInformation());
    assertEquals(m.getAdditionalInformation(), "foo");

    assertNotNull(m.getMatchedDN());
    assertEquals(m.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(m.getProcessingTimeMillis());
    assertEquals(m.getProcessingTimeMillis(), Double.valueOf("0.123"));

    assertNotNull(m.getQueueTimeMillis());
    assertEquals(m.getQueueTimeMillis(), Double.valueOf("4"));

    assertNotNull(m.getIntermediateClientResult());
    assertEquals(m.getIntermediateClientResult(),
                 "app='UnboundID Directory Server'");

    assertNotNull(m.getReferralURLs());
    assertEquals(m.getReferralURLs().size(), 2);
    assertTrue(m.getReferralURLs().contains("ldap://server1.example.com:389/"));
    assertTrue(m.getReferralURLs().contains("ldap://server2.example.com:389/"));

    assertNotNull(m.getAlternateAuthorizationDN());
    assertEquals(m.getAlternateAuthorizationDN(),
                 "uid=someone,ou=People,dc=example,dc=com");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a delete request message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadDeleteRequest()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " DELETE REQUEST " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"dc=example,dc=com\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    DeleteRequestAccessLogMessage m =
         (DeleteRequestAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.REQUEST);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.DELETE);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "dc=example,dc=com");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a delete forward message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadDeleteForward()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " DELETE FORWARD " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"dc=example,dc=com\" targetHost=\"5.6.7.8\" " +
               "targetPort=389 targetProtocol=\"LDAP\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    DeleteForwardAccessLogMessage m =
         (DeleteForwardAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.FORWARD);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.DELETE);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "dc=example,dc=com");

    assertNotNull(m.getTargetHost());
    assertEquals(m.getTargetHost(), "5.6.7.8");

    assertNotNull(m.getTargetPort());
    assertEquals(m.getTargetPort(), Integer.valueOf(389));

    assertNotNull(m.getTargetProtocol());
    assertEquals(m.getTargetProtocol(), "LDAP");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a delete forward failed message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadDeleteForwardFailed()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " DELETE FORWARD-FAILED " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"dc=example,dc=com\" targetHost=\"5.6.7.8\" " +
               "targetPort=389 targetProtocol=\"LDAP\" resultCode=80 " +
               "message=\"oops\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    DeleteForwardFailedAccessLogMessage m =
         (DeleteForwardFailedAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.FORWARD_FAILED);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.DELETE);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "dc=example,dc=com");

    assertNotNull(m.getTargetHost());
    assertEquals(m.getTargetHost(), "5.6.7.8");

    assertNotNull(m.getTargetPort());
    assertEquals(m.getTargetPort(), Integer.valueOf(389));

    assertNotNull(m.getTargetProtocol());
    assertEquals(m.getTargetProtocol(), "LDAP");

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), Integer.valueOf(80));

    assertNotNull(m.getDiagnosticMessage());
    assertEquals(m.getDiagnosticMessage(), "oops");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a delete result message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadDeleteResult()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " DELETE RESULT " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"ou=People,dc=example,dc=com\" resultCode=32 " +
               "message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 qtime=4 " +
               "referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "authzDN=\"uid=someone,ou=People,dc=example,dc=com\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    DeleteResultAccessLogMessage m =
         (DeleteResultAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.RESULT);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.DELETE);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(m.getDiagnosticMessage());
    assertEquals(m.getDiagnosticMessage(), "The entry doesn't exist");

    assertNotNull(m.getAdditionalInformation());
    assertEquals(m.getAdditionalInformation(), "foo");

    assertNotNull(m.getMatchedDN());
    assertEquals(m.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(m.getProcessingTimeMillis());
    assertEquals(m.getProcessingTimeMillis(), Double.valueOf("0.123"));

    assertNotNull(m.getQueueTimeMillis());
    assertEquals(m.getQueueTimeMillis(), Double.valueOf("4"));

    assertNotNull(m.getIntermediateClientResult());
    assertEquals(m.getIntermediateClientResult(),
                 "app='UnboundID Directory Server'");

    assertNotNull(m.getReferralURLs());
    assertEquals(m.getReferralURLs().size(), 2);
    assertTrue(m.getReferralURLs().contains("ldap://server1.example.com:389/"));
    assertTrue(m.getReferralURLs().contains("ldap://server2.example.com:389/"));

    assertNotNull(m.getAlternateAuthorizationDN());
    assertEquals(m.getAlternateAuthorizationDN(),
                 "uid=someone,ou=People,dc=example,dc=com");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a delete assurance completed message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadDeleteAssuranceCompleted()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " DELETE ASSURANCE-COMPLETE " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"ou=People,dc=example,dc=com\" resultCode=32 " +
               "message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 qtime=4 " +
               "referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "authzDN=\"uid=someone,ou=People,dc=example,dc=com\" " +
               "localAssuranceLevel=\"PROCESSED_ALL_SERVERS\" " +
               "remoteAssuranceLevel=\"PROCESSED_ALL_REMOTE_SERVERS\" " +
               "assuranceTimeoutMillis=5000 responseDelayedByAssurance=false " +
               "localAssuranceSatisfied=true remoteAssuranceSatisfied=false " +
               "serverAssuranceResults=\"assurance-results\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    DeleteAssuranceCompletedAccessLogMessage m =
         (DeleteAssuranceCompletedAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.ASSURANCE_COMPLETE);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.DELETE);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(m.getDiagnosticMessage());
    assertEquals(m.getDiagnosticMessage(), "The entry doesn't exist");

    assertNotNull(m.getAdditionalInformation());
    assertEquals(m.getAdditionalInformation(), "foo");

    assertNotNull(m.getMatchedDN());
    assertEquals(m.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(m.getProcessingTimeMillis());
    assertEquals(m.getProcessingTimeMillis(), Double.valueOf("0.123"));

    assertNotNull(m.getQueueTimeMillis());
    assertEquals(m.getQueueTimeMillis(), Double.valueOf("4"));

    assertNotNull(m.getIntermediateClientResult());
    assertEquals(m.getIntermediateClientResult(),
                 "app='UnboundID Directory Server'");

    assertNotNull(m.getReferralURLs());
    assertEquals(m.getReferralURLs().size(), 2);
    assertTrue(m.getReferralURLs().contains("ldap://server1.example.com:389/"));
    assertTrue(m.getReferralURLs().contains("ldap://server2.example.com:389/"));

    assertNotNull(m.getAlternateAuthorizationDN());
    assertEquals(m.getAlternateAuthorizationDN(),
                 "uid=someone,ou=People,dc=example,dc=com");

    assertNotNull(m.getAssuredReplicationLocalLevel());
    assertEquals(m.getAssuredReplicationLocalLevel(),
         AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS);

    assertNotNull(m.getAssuredReplicationRemoteLevel());
    assertEquals(m.getAssuredReplicationRemoteLevel(),
         AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS);

    assertNotNull(m.getAssuredReplicationTimeoutMillis());
    assertEquals(m.getAssuredReplicationTimeoutMillis().longValue(), 5000L);

    assertNotNull(m.getResponseDelayedByAssurance());
    assertFalse(m.getResponseDelayedByAssurance().booleanValue());

    assertNotNull(m.getLocalAssuranceSatisfied());
    assertTrue(m.getLocalAssuranceSatisfied().booleanValue());

    assertNotNull(m.getRemoteAssuranceSatisfied());
    assertFalse(m.getRemoteAssuranceSatisfied().booleanValue());

    assertNotNull(m.getServerAssuranceResults());
    assertEquals(m.getServerAssuranceResults(), "assurance-results");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read an extended request message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadExtendedRequest()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " EXTENDED REQUEST " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "requestOID=\"5.6.7.8\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    ExtendedRequestAccessLogMessage m =
         (ExtendedRequestAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.REQUEST);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.EXTENDED);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getRequestOID());
    assertEquals(m.getRequestOID(), "5.6.7.8");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read an extended forward message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadExtendedForward()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " EXTENDED FORWARD " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "requestOID=\"4.3.2.1\" targetHost=\"5.6.7.8\" " +
               "targetPort=389 targetProtocol=\"LDAP\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    ExtendedForwardAccessLogMessage m =
         (ExtendedForwardAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.FORWARD);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.EXTENDED);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getRequestOID());
    assertEquals(m.getRequestOID(), "4.3.2.1");

    assertNotNull(m.getTargetHost());
    assertEquals(m.getTargetHost(), "5.6.7.8");

    assertNotNull(m.getTargetPort());
    assertEquals(m.getTargetPort(), Integer.valueOf(389));

    assertNotNull(m.getTargetProtocol());
    assertEquals(m.getTargetProtocol(), "LDAP");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read an extended forward failed message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadExtendedForwardFailed()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " EXTENDED FORWARD-FAILED " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "requestOID=\"4.3.2.1\" targetHost=\"5.6.7.8\" " +
               "targetPort=389 targetProtocol=\"LDAP\" resultCode=80 " +
               "message=\"oops\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    ExtendedForwardFailedAccessLogMessage m =
         (ExtendedForwardFailedAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.FORWARD_FAILED);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.EXTENDED);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getRequestOID());
    assertEquals(m.getRequestOID(), "4.3.2.1");

    assertNotNull(m.getTargetHost());
    assertEquals(m.getTargetHost(), "5.6.7.8");

    assertNotNull(m.getTargetPort());
    assertEquals(m.getTargetPort(), Integer.valueOf(389));

    assertNotNull(m.getTargetProtocol());
    assertEquals(m.getTargetProtocol(), "LDAP");

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), Integer.valueOf(80));

    assertNotNull(m.getDiagnosticMessage());
    assertEquals(m.getDiagnosticMessage(), "oops");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read an extended result message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadExtendedResult()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " EXTENDED RESULT " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "requestOID=\"5.6.7.8\" resultCode=32 " +
               "message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 qtime=4 " +
               "referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "responseOID=\"8.7.6.5\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    ExtendedResultAccessLogMessage m =
         (ExtendedResultAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.RESULT);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.EXTENDED);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getRequestOID());
    assertEquals(m.getRequestOID(), "5.6.7.8");

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(m.getDiagnosticMessage());
    assertEquals(m.getDiagnosticMessage(), "The entry doesn't exist");

    assertNotNull(m.getAdditionalInformation());
    assertEquals(m.getAdditionalInformation(), "foo");

    assertNotNull(m.getMatchedDN());
    assertEquals(m.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(m.getProcessingTimeMillis());
    assertEquals(m.getProcessingTimeMillis(), Double.valueOf("0.123"));

    assertNotNull(m.getQueueTimeMillis());
    assertEquals(m.getQueueTimeMillis(), Double.valueOf("4"));

    assertNotNull(m.getIntermediateClientResult());
    assertEquals(m.getIntermediateClientResult(),
                 "app='UnboundID Directory Server'");

    assertNotNull(m.getReferralURLs());
    assertEquals(m.getReferralURLs().size(), 2);
    assertTrue(m.getReferralURLs().contains("ldap://server1.example.com:389/"));
    assertTrue(m.getReferralURLs().contains("ldap://server2.example.com:389/"));

    assertNotNull(m.getResponseOID());
    assertEquals(m.getResponseOID(), "8.7.6.5");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a modify request message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadModifyRequest()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " MODIFY REQUEST " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"dc=example,dc=com\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    ModifyRequestAccessLogMessage m =
         (ModifyRequestAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.REQUEST);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.MODIFY);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "dc=example,dc=com");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a modify forward message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadModifyForward()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " MODIFY FORWARD " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"dc=example,dc=com\" targetHost=\"5.6.7.8\" " +
               "targetPort=389 targetProtocol=\"LDAP\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    ModifyForwardAccessLogMessage m =
         (ModifyForwardAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.FORWARD);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.MODIFY);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "dc=example,dc=com");

    assertNotNull(m.getTargetHost());
    assertEquals(m.getTargetHost(), "5.6.7.8");

    assertNotNull(m.getTargetPort());
    assertEquals(m.getTargetPort(), Integer.valueOf(389));

    assertNotNull(m.getTargetProtocol());
    assertEquals(m.getTargetProtocol(), "LDAP");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a modify forward failed message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadModifyForwardFailed()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " MODIFY FORWARD-FAILED " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"dc=example,dc=com\" targetHost=\"5.6.7.8\" " +
               "targetPort=389 targetProtocol=\"LDAP\" resultCode=80 " +
               "message=\"oops\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    ModifyForwardFailedAccessLogMessage m =
         (ModifyForwardFailedAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.FORWARD_FAILED);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.MODIFY);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "dc=example,dc=com");

    assertNotNull(m.getTargetHost());
    assertEquals(m.getTargetHost(), "5.6.7.8");

    assertNotNull(m.getTargetPort());
    assertEquals(m.getTargetPort(), Integer.valueOf(389));

    assertNotNull(m.getTargetProtocol());
    assertEquals(m.getTargetProtocol(), "LDAP");

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), Integer.valueOf(80));

    assertNotNull(m.getDiagnosticMessage());
    assertEquals(m.getDiagnosticMessage(), "oops");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a modify result message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadModifyResult()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " MODIFY RESULT " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"ou=People,dc=example,dc=com\" resultCode=32 " +
               "message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 qtime=4 " +
               "referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "authzDN=\"uid=someone,ou=People,dc=example,dc=com\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    ModifyResultAccessLogMessage m =
         (ModifyResultAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.RESULT);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.MODIFY);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(m.getDiagnosticMessage());
    assertEquals(m.getDiagnosticMessage(), "The entry doesn't exist");

    assertNotNull(m.getAdditionalInformation());
    assertEquals(m.getAdditionalInformation(), "foo");

    assertNotNull(m.getMatchedDN());
    assertEquals(m.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(m.getProcessingTimeMillis());
    assertEquals(m.getProcessingTimeMillis(), Double.valueOf("0.123"));

    assertNotNull(m.getQueueTimeMillis());
    assertEquals(m.getQueueTimeMillis(), Double.valueOf("4"));

    assertNotNull(m.getIntermediateClientResult());
    assertEquals(m.getIntermediateClientResult(),
                 "app='UnboundID Directory Server'");

    assertNotNull(m.getReferralURLs());
    assertEquals(m.getReferralURLs().size(), 2);
    assertTrue(m.getReferralURLs().contains("ldap://server1.example.com:389/"));
    assertTrue(m.getReferralURLs().contains("ldap://server2.example.com:389/"));

    assertNotNull(m.getAlternateAuthorizationDN());
    assertEquals(m.getAlternateAuthorizationDN(),
                 "uid=someone,ou=People,dc=example,dc=com");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a modify assurance completed message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadModifyAssuranceCompleted()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " MODIFY ASSURANCE-COMPLETE " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"ou=People,dc=example,dc=com\" resultCode=32 " +
               "message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 qtime=4 " +
               "referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "authzDN=\"uid=someone,ou=People,dc=example,dc=com\" " +
               "localAssuranceLevel=\"PROCESSED_ALL_SERVERS\" " +
               "remoteAssuranceLevel=\"PROCESSED_ALL_REMOTE_SERVERS\" " +
               "assuranceTimeoutMillis=5000 responseDelayedByAssurance=false " +
               "localAssuranceSatisfied=true remoteAssuranceSatisfied=false " +
               "serverAssuranceResults=\"assurance-results\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    ModifyAssuranceCompletedAccessLogMessage m =
         (ModifyAssuranceCompletedAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.ASSURANCE_COMPLETE);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.MODIFY);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(m.getDiagnosticMessage());
    assertEquals(m.getDiagnosticMessage(), "The entry doesn't exist");

    assertNotNull(m.getAdditionalInformation());
    assertEquals(m.getAdditionalInformation(), "foo");

    assertNotNull(m.getMatchedDN());
    assertEquals(m.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(m.getProcessingTimeMillis());
    assertEquals(m.getProcessingTimeMillis(), Double.valueOf("0.123"));

    assertNotNull(m.getQueueTimeMillis());
    assertEquals(m.getQueueTimeMillis(), Double.valueOf("4"));

    assertNotNull(m.getIntermediateClientResult());
    assertEquals(m.getIntermediateClientResult(),
                 "app='UnboundID Directory Server'");

    assertNotNull(m.getReferralURLs());
    assertEquals(m.getReferralURLs().size(), 2);
    assertTrue(m.getReferralURLs().contains("ldap://server1.example.com:389/"));
    assertTrue(m.getReferralURLs().contains("ldap://server2.example.com:389/"));

    assertNotNull(m.getAlternateAuthorizationDN());
    assertEquals(m.getAlternateAuthorizationDN(),
                 "uid=someone,ou=People,dc=example,dc=com");

    assertNotNull(m.getAssuredReplicationLocalLevel());
    assertEquals(m.getAssuredReplicationLocalLevel(),
         AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS);

    assertNotNull(m.getAssuredReplicationRemoteLevel());
    assertEquals(m.getAssuredReplicationRemoteLevel(),
         AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS);

    assertNotNull(m.getAssuredReplicationTimeoutMillis());
    assertEquals(m.getAssuredReplicationTimeoutMillis().longValue(), 5000L);

    assertNotNull(m.getResponseDelayedByAssurance());
    assertFalse(m.getResponseDelayedByAssurance().booleanValue());

    assertNotNull(m.getLocalAssuranceSatisfied());
    assertTrue(m.getLocalAssuranceSatisfied().booleanValue());

    assertNotNull(m.getRemoteAssuranceSatisfied());
    assertFalse(m.getRemoteAssuranceSatisfied().booleanValue());

    assertNotNull(m.getServerAssuranceResults());
    assertEquals(m.getServerAssuranceResults(), "assurance-results");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a modify DN request message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadModifyDNRequest()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " MODDN REQUEST " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "newRDN=\"uid=test.user\" deleteOldRDN=false " +
               "newSuperior=\"ou=Users,dc=example,dc=com\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    ModifyDNRequestAccessLogMessage m =
         (ModifyDNRequestAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.REQUEST);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.MODDN);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getNewRDN());
    assertEquals(m.getNewRDN(), "uid=test.user");

    assertNotNull(m.deleteOldRDN());
    assertEquals(m.deleteOldRDN(), Boolean.FALSE);

    assertNotNull(m.getNewSuperiorDN());
    assertEquals(m.getNewSuperiorDN(), "ou=Users,dc=example,dc=com");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a modify DN forward message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadModifyDNForward()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " MODDN FORWARD " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "newRDN=\"uid=test.user\" deleteOldRDN=false " +
               "newSuperior=\"ou=Users,dc=example,dc=com\" " +
               "targetHost=\"5.6.7.8\" targetPort=389 targetProtocol=\"LDAP\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    ModifyDNForwardAccessLogMessage m =
         (ModifyDNForwardAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.FORWARD);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.MODDN);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getNewRDN());
    assertEquals(m.getNewRDN(), "uid=test.user");

    assertNotNull(m.deleteOldRDN());
    assertEquals(m.deleteOldRDN(), Boolean.FALSE);

    assertNotNull(m.getNewSuperiorDN());
    assertEquals(m.getNewSuperiorDN(), "ou=Users,dc=example,dc=com");

    assertNotNull(m.getTargetHost());
    assertEquals(m.getTargetHost(), "5.6.7.8");

    assertNotNull(m.getTargetPort());
    assertEquals(m.getTargetPort(), Integer.valueOf(389));

    assertNotNull(m.getTargetProtocol());
    assertEquals(m.getTargetProtocol(), "LDAP");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a modify DN forward failed message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadModifyDNForwardFailed()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " MODDN FORWARD-FAILED " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "newRDN=\"uid=test.user\" deleteOldRDN=false " +
               "newSuperior=\"ou=Users,dc=example,dc=com\" " +
               "targetHost=\"5.6.7.8\" targetPort=389 " +
               "targetProtocol=\"LDAP\" resultCode=80 message=\"oops\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    ModifyDNForwardFailedAccessLogMessage m =
         (ModifyDNForwardFailedAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.FORWARD_FAILED);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.MODDN);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getNewRDN());
    assertEquals(m.getNewRDN(), "uid=test.user");

    assertNotNull(m.deleteOldRDN());
    assertEquals(m.deleteOldRDN(), Boolean.FALSE);

    assertNotNull(m.getNewSuperiorDN());
    assertEquals(m.getNewSuperiorDN(), "ou=Users,dc=example,dc=com");

    assertNotNull(m.getTargetHost());
    assertEquals(m.getTargetHost(), "5.6.7.8");

    assertNotNull(m.getTargetPort());
    assertEquals(m.getTargetPort(), Integer.valueOf(389));

    assertNotNull(m.getTargetProtocol());
    assertEquals(m.getTargetProtocol(), "LDAP");

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), Integer.valueOf(80));

    assertNotNull(m.getDiagnosticMessage());
    assertEquals(m.getDiagnosticMessage(), "oops");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a modify DN result message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadModifyDNResult()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " MODDN RESULT " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"ou=People,dc=example,dc=com\" newRDN=\"ou=Users\" " +
               "deleteOldRDN=true newSuperior=\"o=example.com\" " +
               "resultCode=32 message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 qtime=4 " +
               "referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "authzDN=\"uid=someone,ou=People,dc=example,dc=com\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    ModifyDNResultAccessLogMessage m =
         (ModifyDNResultAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.RESULT);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.MODDN);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(m.getNewRDN());
    assertEquals(m.getNewRDN(), "ou=Users");

    assertNotNull(m.deleteOldRDN());
    assertEquals(m.deleteOldRDN(), Boolean.TRUE);

    assertNotNull(m.getNewSuperiorDN());
    assertEquals(m.getNewSuperiorDN(), "o=example.com");

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(m.getDiagnosticMessage());
    assertEquals(m.getDiagnosticMessage(), "The entry doesn't exist");

    assertNotNull(m.getAdditionalInformation());
    assertEquals(m.getAdditionalInformation(), "foo");

    assertNotNull(m.getMatchedDN());
    assertEquals(m.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(m.getProcessingTimeMillis());
    assertEquals(m.getProcessingTimeMillis(), Double.valueOf("0.123"));

    assertNotNull(m.getQueueTimeMillis());
    assertEquals(m.getQueueTimeMillis(), Double.valueOf("4"));

    assertNotNull(m.getIntermediateClientResult());
    assertEquals(m.getIntermediateClientResult(),
                 "app='UnboundID Directory Server'");

    assertNotNull(m.getReferralURLs());
    assertEquals(m.getReferralURLs().size(), 2);
    assertTrue(m.getReferralURLs().contains("ldap://server1.example.com:389/"));
    assertTrue(m.getReferralURLs().contains("ldap://server2.example.com:389/"));

    assertNotNull(m.getAlternateAuthorizationDN());
    assertEquals(m.getAlternateAuthorizationDN(),
                 "uid=someone,ou=People,dc=example,dc=com");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a modify DN assurance completed message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadModifyDNAssuranceCompleted()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " MODDN ASSURANCE-COMPLETE " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"ou=People,dc=example,dc=com\" newRDN=\"ou=Users\" " +
               "deleteOldRDN=true newSuperior=\"o=example.com\" " +
               "resultCode=32 message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 qtime=4 " +
               "referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "authzDN=\"uid=someone,ou=People,dc=example,dc=com\" " +
               "localAssuranceLevel=\"PROCESSED_ALL_SERVERS\" " +
               "remoteAssuranceLevel=\"PROCESSED_ALL_REMOTE_SERVERS\" " +
               "assuranceTimeoutMillis=5000 responseDelayedByAssurance=false " +
               "localAssuranceSatisfied=true remoteAssuranceSatisfied=false " +
               "serverAssuranceResults=\"assurance-results\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    ModifyDNAssuranceCompletedAccessLogMessage m =
         (ModifyDNAssuranceCompletedAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.ASSURANCE_COMPLETE);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.MODDN);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(m.getNewRDN());
    assertEquals(m.getNewRDN(), "ou=Users");

    assertNotNull(m.deleteOldRDN());
    assertEquals(m.deleteOldRDN(), Boolean.TRUE);

    assertNotNull(m.getNewSuperiorDN());
    assertEquals(m.getNewSuperiorDN(), "o=example.com");

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(m.getDiagnosticMessage());
    assertEquals(m.getDiagnosticMessage(), "The entry doesn't exist");

    assertNotNull(m.getAdditionalInformation());
    assertEquals(m.getAdditionalInformation(), "foo");

    assertNotNull(m.getMatchedDN());
    assertEquals(m.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(m.getProcessingTimeMillis());
    assertEquals(m.getProcessingTimeMillis(), Double.valueOf("0.123"));

    assertNotNull(m.getQueueTimeMillis());
    assertEquals(m.getQueueTimeMillis(), Double.valueOf("4"));

    assertNotNull(m.getIntermediateClientResult());
    assertEquals(m.getIntermediateClientResult(),
                 "app='UnboundID Directory Server'");

    assertNotNull(m.getReferralURLs());
    assertEquals(m.getReferralURLs().size(), 2);
    assertTrue(m.getReferralURLs().contains("ldap://server1.example.com:389/"));
    assertTrue(m.getReferralURLs().contains("ldap://server2.example.com:389/"));

    assertNotNull(m.getAlternateAuthorizationDN());
    assertEquals(m.getAlternateAuthorizationDN(),
                 "uid=someone,ou=People,dc=example,dc=com");

    assertNotNull(m.getAssuredReplicationLocalLevel());
    assertEquals(m.getAssuredReplicationLocalLevel(),
         AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS);

    assertNotNull(m.getAssuredReplicationRemoteLevel());
    assertEquals(m.getAssuredReplicationRemoteLevel(),
         AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS);

    assertNotNull(m.getAssuredReplicationTimeoutMillis());
    assertEquals(m.getAssuredReplicationTimeoutMillis().longValue(), 5000L);

    assertNotNull(m.getResponseDelayedByAssurance());
    assertFalse(m.getResponseDelayedByAssurance().booleanValue());

    assertNotNull(m.getLocalAssuranceSatisfied());
    assertTrue(m.getLocalAssuranceSatisfied().booleanValue());

    assertNotNull(m.getRemoteAssuranceSatisfied());
    assertFalse(m.getRemoteAssuranceSatisfied().booleanValue());

    assertNotNull(m.getServerAssuranceResults());
    assertEquals(m.getServerAssuranceResults(), "assurance-results");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a search request message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadSearchRequest()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " SEARCH REQUEST " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "base=\"dc=example,dc=com\" scope=2 " +
               "filter=\"(uid=test.user)\" attrs=\"givenName,sn\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    SearchRequestAccessLogMessage m =
         (SearchRequestAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.REQUEST);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.SEARCH);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getBaseDN());
    assertEquals(m.getBaseDN(), "dc=example,dc=com");

    assertNotNull(m.getScope());
    assertEquals(m.getScope(), SearchScope.SUB);

    assertNotNull(m.getFilter());
    assertEquals(m.getFilter(), "(uid=test.user)");

    assertNotNull(m.getRequestedAttributes());
    assertEquals(m.getRequestedAttributes().size(), 2);

    Iterator<String> iterator = m.getRequestedAttributes().iterator();
    assertEquals(iterator.next(), "givenName");
    assertEquals(iterator.next(), "sn");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a search forward message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadSearchForward()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " SEARCH FORWARD " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "base=\"dc=example,dc=com\" scope=2 " +
               "filter=\"(uid=test.user)\" attrs=\"cn\" " +
               "targetHost=\"5.6.7.8\" targetPort=389 targetProtocol=\"LDAP\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    SearchForwardAccessLogMessage m =
         (SearchForwardAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.FORWARD);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.SEARCH);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getBaseDN());
    assertEquals(m.getBaseDN(), "dc=example,dc=com");

    assertNotNull(m.getScope());
    assertEquals(m.getScope(), SearchScope.SUB);

    assertNotNull(m.getFilter());
    assertEquals(m.getFilter(), "(uid=test.user)");

    assertNotNull(m.getRequestedAttributes());
    assertEquals(m.getRequestedAttributes().size(), 1);
    assertEquals(m.getRequestedAttributes().iterator().next(), "cn");

    assertNotNull(m.getTargetHost());
    assertEquals(m.getTargetHost(), "5.6.7.8");

    assertNotNull(m.getTargetPort());
    assertEquals(m.getTargetPort(), Integer.valueOf(389));

    assertNotNull(m.getTargetProtocol());
    assertEquals(m.getTargetProtocol(), "LDAP");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a search forward failed message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadSearchForwardFailed()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " SEARCH FORWARD-FAILED " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "base=\"dc=example,dc=com\" scope=2 " +
               "filter=\"(uid=test.user)\" attrs=\"cn\" " +
               "targetHost=\"5.6.7.8\" targetPort=389 " +
               "targetProtocol=\"LDAP\" resultCode=80 message=\"oops\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    SearchForwardFailedAccessLogMessage m =
         (SearchForwardFailedAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.FORWARD_FAILED);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.SEARCH);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getBaseDN());
    assertEquals(m.getBaseDN(), "dc=example,dc=com");

    assertNotNull(m.getScope());
    assertEquals(m.getScope(), SearchScope.SUB);

    assertNotNull(m.getFilter());
    assertEquals(m.getFilter(), "(uid=test.user)");

    assertNotNull(m.getRequestedAttributes());
    assertEquals(m.getRequestedAttributes().size(), 1);
    assertEquals(m.getRequestedAttributes().iterator().next(), "cn");

    assertNotNull(m.getTargetHost());
    assertEquals(m.getTargetHost(), "5.6.7.8");

    assertNotNull(m.getTargetPort());
    assertEquals(m.getTargetPort(), Integer.valueOf(389));

    assertNotNull(m.getTargetProtocol());
    assertEquals(m.getTargetProtocol(), "LDAP");

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), Integer.valueOf(80));

    assertNotNull(m.getDiagnosticMessage());
    assertEquals(m.getDiagnosticMessage(), "oops");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a search entry message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadSearchEntry()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " SEARCH ENTRY " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" dn=\"dc=example,dc=com\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    SearchEntryAccessLogMessage m =
         (SearchEntryAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.ENTRY);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.SEARCH);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getDN());
    assertEquals(m.getDN(), "dc=example,dc=com");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a search reference message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadSearchReference()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " SEARCH REFERENCE " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" " +
               "referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    SearchReferenceAccessLogMessage m =
         (SearchReferenceAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.REFERENCE);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.SEARCH);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getReferralURLs());
    assertEquals(m.getReferralURLs().size(), 2);
    assertTrue(m.getReferralURLs().contains("ldap://server1.example.com:389/"));
    assertTrue(m.getReferralURLs().contains("ldap://server2.example.com:389/"));

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read a search result message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadSearchResult()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " SEARCH RESULT " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "base=\"ou=People,dc=example,dc=com\" scope=0 " +
               "filter=\"(objectClass=*)\" attrs=\"ALL\" resultCode=32 " +
               "message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 qtime=4 " +
               "referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" entriesReturned=1 " +
               "unindexed=true " +
               "authzDN=\"uid=someone,ou=People,dc=example,dc=com\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    SearchResultAccessLogMessage m =
         (SearchResultAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.RESULT);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.SEARCH);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getBaseDN());
    assertEquals(m.getBaseDN(), "ou=People,dc=example,dc=com");

    assertNotNull(m.getScope());
    assertEquals(m.getScope(), SearchScope.BASE);

    assertNotNull(m.getFilter());
    assertEquals(m.getFilter(), "(objectClass=*)");

    assertNotNull(m.getRequestedAttributes());
    assertTrue(m.getRequestedAttributes().isEmpty());

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(m.getDiagnosticMessage());
    assertEquals(m.getDiagnosticMessage(), "The entry doesn't exist");

    assertNotNull(m.getAdditionalInformation());
    assertEquals(m.getAdditionalInformation(), "foo");

    assertNotNull(m.getMatchedDN());
    assertEquals(m.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(m.getProcessingTimeMillis());
    assertEquals(m.getProcessingTimeMillis(), Double.valueOf("0.123"));

    assertNotNull(m.getQueueTimeMillis());
    assertEquals(m.getQueueTimeMillis(), Double.valueOf("4"));

    assertNotNull(m.getIntermediateClientResult());
    assertEquals(m.getIntermediateClientResult(),
                 "app='UnboundID Directory Server'");

    assertNotNull(m.getReferralURLs());
    assertEquals(m.getReferralURLs().size(), 2);
    assertTrue(m.getReferralURLs().contains("ldap://server1.example.com:389/"));
    assertTrue(m.getReferralURLs().contains("ldap://server2.example.com:389/"));

    assertNotNull(m.getEntriesReturned());
    assertEquals(m.getEntriesReturned(), Long.valueOf(1));

    assertNotNull(m.isUnindexed());
    assertEquals(m.isUnindexed(), Boolean.TRUE);

    assertNotNull(m.getAlternateAuthorizationDN());
    assertEquals(m.getAlternateAuthorizationDN(),
                 "uid=someone,ou=People,dc=example,dc=com");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read an unbind request message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadUnbindRequest()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " UNBIND REQUEST " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"dc=example,dc=com\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    UnbindRequestAccessLogMessage m =
         (UnbindRequestAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.REQUEST);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.UNBIND);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }



  /**
   * Tests the ability to read an intermediate response message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadIntermediateResponse()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " EXTENDED INTERMEDIATE-RESPONSE " +
         "product=\"Directory Server\" " +
         "instanceName=\"server.example.com:389\" " +
         "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
         "origin=\"internal\" " +
         "oid=\"1.3.6.1.4.1.30221.2.6.7\" " +
         "name=\"Stream Directory Values Intermediate Response\" " +
         "value=\"result='more values to return' valueCount='1000'\" " +
         "responseControls=\"8.7.6.5\"";

    File file = createTempFile(s);

    AccessLogReader reader = new AccessLogReader(file);

    IntermediateResponseAccessLogMessage m =
         (IntermediateResponseAccessLogMessage) reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(),
         AccessLogMessageType.INTERMEDIATE_RESPONSE);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.EXTENDED);

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getOID());
    assertEquals(m.getOID(), "1.3.6.1.4.1.30221.2.6.7");

    assertNotNull(m.getIntermediateResponseName());
    assertEquals(m.getIntermediateResponseName(),
         "Stream Directory Values Intermediate Response");

    assertNotNull(m.getValueString());
    assertEquals(m.getValueString(),
         "result='more values to return' valueCount='1000'");

    assertNotNull(m.getResponseControlOIDs());
    assertEquals(m.getResponseControlOIDs().size(), 1);
    assertTrue(m.getResponseControlOIDs().contains("8.7.6.5"));

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    reader.close();
  }
}
