/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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



import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;



/**
 * This class provides a set of test cases for audit log messages.
 */
public final class AuditLogMessageTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a minimal audit log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalLogMessage()
         throws Exception
  {
    final AddAuditLogMessage m = new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40 -0500",
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "createTimestamp: 20180823190240.967Z",
         "creatorsName: cn=Directory Manager,cn=Root DNs,cn=config",
         "modifyTimestamp: 20180823190240.967Z",
         "modifiersName: cn=Directory Manager,cn=Root DNs,cn=config",
         "entryUUID: b58849bd-2032-4077-ba10-2cd9be8166e0");

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertTrue(
         m.getCommentedHeaderLine().equals("# 23/Aug/2018:14:02:40 -0500"));

    assertNotNull(m.getUncommentedHeaderLine());
    assertEquals(m.getUncommentedHeaderLine(), "23/Aug/2018:14:02:40 -0500");

    assertNotNull(m.getTimestamp());
    final Calendar calendar = new GregorianCalendar();
    calendar.setTime(m.getTimestamp());
    assertEquals(calendar.get(Calendar.YEAR), 2018);
    assertEquals(calendar.get(Calendar.MONTH), Calendar.AUGUST);

    assertNotNull(m.getHeaderNamedValues());
    assertTrue(m.getHeaderNamedValues().isEmpty());

    assertNull(m.getProductName());

    assertNull(m.getInstanceName());

    assertNull(m.getStartupID());

    assertNull(m.getThreadID());

    assertNull(m.getRequesterDN());

    assertNull(m.getRequesterIPAddress());

    assertNull(m.getConnectionID());

    assertNull(m.getOperationID());

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

    assertNull(m.getReplicationChangeID());

    assertNull(m.getAlternateAuthorizationDN());

    assertNull(m.getTransactionID());

    assertNull(m.getOrigin());

    assertNull(m.getUsingAdminSessionWorkerThread());

    assertNull(m.getRequestControlOIDs());

    assertNull(m.getOperationPurposeRequestControl());

    assertNull(m.getIntermediateClientRequestControl());

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.ADD);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFAddChangeRecord);

    assertTrue(m.isRevertible());

    assertNotNull(m.getRevertChangeRecords());
    assertFalse(m.getRevertChangeRecords().isEmpty());
    assertEquals(m.getRevertChangeRecords().size(), 1);
    assertTrue(
         m.getRevertChangeRecords().get(0) instanceof LDIFDeleteChangeRecord);

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a complete audit log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompleteLogMessage()
         throws Exception
  {
    final AddAuditLogMessage m = new AddAuditLogMessage(
         "# 23/Aug/2018:15:05:51.615 -0500; conn=25; op=1; " +
              "origin=\"replication\"; productName=\"Directory Server\"; " +
              "instanceName=\"ReplicaOne\"; startupID=W38TQw==; threadID=8; " +
              "clientIP=127.0.0.1; " +
              "requesterDN=\"cn=Proxy User,cn=Root DNs,cn=config\"; " +
              "replicationChangeID=\"000001656864A77520DB00000001\"; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"; " +
              "txnID=1234; usingAdminSessionWorkerThread=true; " +
              "isUndelete=false; " +
              "requestControlOIDs=\"2.16.840.1.113730.3.4.2," +
              "1.3.6.1.1.12,1.3.6.1.4.1.30221.2.5.19," +
              "1.3.6.1.4.1.30221.2.5.2\"; operationPurpose={ " +
              "\"applicationName\":\"Test Application\", " +
              "\"applicationVersion\":\"1.2.3\", " +
              "\"codeLocation\":\"Somewhere in the code\", " +
              "\"requestPurpose\":\"Just testing\" }; " +
              "intermediateClientRequestControl={ " +
              "\"clientIdentity\":\"dn:cn=Directory " +
              "Manager,cn=Root DNs,cn=config\", " +
              "\"downstreamClientAddress\":\"127.0.0.1\", " +
              "\"downstreamClientSecure\":false, " +
              "\"clientName\":\"PingDirectory\", " +
              "\"clientSessionID\":\"conn=8\", " +
              "\"clientRequestID\":\"op=1\", " +
              "\"downstreamRequest\":{ " +
              "\"clientName\":\"Unidentified Directory Application\" } }; " +
              "propertyNameAndValueSeparatedBySpaces = value ; " +
              "propertyWithValueContainingEscapedCharacters=a#22b\\;c; " +
              "propertyWithUnquotedValueContainingQuote=a\"b; " +
              "propertyWithQuotedValueContainingSpacesAndSemicolon=\" ; \" ; " +
              "propertyWithEmptyValue=; anotherPropertyWithEmptyValue=",
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "createTimestamp: 20180823190240.967Z",
         "creatorsName: cn=Directory Manager,cn=Root DNs,cn=config",
         "modifyTimestamp: 20180823190240.967Z",
         "modifiersName: cn=Directory Manager,cn=Root DNs,cn=config",
         "entryUUID: b58849bd-2032-4077-ba10-2cd9be8166e0");

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertTrue(m.getCommentedHeaderLine().startsWith("# "));

    assertNotNull(m.getUncommentedHeaderLine());
    assertFalse(m.getUncommentedHeaderLine().isEmpty());
    assertFalse(m.getUncommentedHeaderLine().startsWith("# "));
    assertEquals(m.getUncommentedHeaderLine(),
         m.getCommentedHeaderLine().substring(2));

    assertNotNull(m.getTimestamp());
    final Calendar calendar = new GregorianCalendar();
    calendar.setTime(m.getTimestamp());
    assertEquals(calendar.get(Calendar.YEAR), 2018);
    assertEquals(calendar.get(Calendar.MONTH), Calendar.AUGUST);

    assertNotNull(m.getHeaderNamedValues());
    assertFalse(m.getHeaderNamedValues().isEmpty());
    assertTrue(m.getHeaderNamedValues().containsKey("conn"));

    assertTrue(m.getHeaderNamedValues().containsKey(
         "propertyNameAndValueSeparatedBySpaces"));
    assertEquals(
         m.getHeaderNamedValues().get("propertyNameAndValueSeparatedBySpaces"),
         "value");

    assertTrue(m.getHeaderNamedValues().containsKey(
         "propertyWithValueContainingEscapedCharacters"));
    assertEquals(
         m.getHeaderNamedValues().get(
              "propertyWithValueContainingEscapedCharacters"),
         "a\"b;c");

    assertTrue(m.getHeaderNamedValues().containsKey(
         "propertyWithUnquotedValueContainingQuote"));
    assertEquals(
         m.getHeaderNamedValues().get(
              "propertyWithUnquotedValueContainingQuote"),
         "a\"b");

    assertTrue(m.getHeaderNamedValues().containsKey(
         "propertyWithQuotedValueContainingSpacesAndSemicolon"));
    assertEquals(
         m.getHeaderNamedValues().get(
              "propertyWithQuotedValueContainingSpacesAndSemicolon"),
         " ; ");

    assertTrue(m.getHeaderNamedValues().containsKey("propertyWithEmptyValue"));
    assertEquals(m.getHeaderNamedValues().get("propertyWithEmptyValue"), "");

    assertTrue(
         m.getHeaderNamedValues().containsKey("anotherPropertyWithEmptyValue"));
    assertEquals(
         m.getHeaderNamedValues().get("anotherPropertyWithEmptyValue"), "");

    assertNotNull(m.getProductName());
    assertEquals(m.getProductName(), "Directory Server");

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "ReplicaOne");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "W38TQw==");

    assertNotNull(m.getThreadID());
    assertEquals(m.getThreadID().longValue(), 8);

    assertNotNull(m.getRequesterDN());
    assertDNsEqual(m.getRequesterDN(), "cn=Proxy User,cn=Root DNs,cn=config");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "127.0.0.1");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID().longValue(), 25L);

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID().longValue(), 1L);

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

    assertNotNull(m.getReplicationChangeID());
    assertEquals(m.getReplicationChangeID(), "000001656864A77520DB00000001");

    assertNotNull(m.getAlternateAuthorizationDN());
    assertDNsEqual(m.getAlternateAuthorizationDN(),
         "cn=Directory Manager,cn=Root DNs,cn=config");

    assertNotNull(m.getTransactionID());
    assertEquals(m.getTransactionID(), "1234");

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "replication");

    assertNotNull(m.getUsingAdminSessionWorkerThread());
    assertEquals(m.getUsingAdminSessionWorkerThread().booleanValue(), true);

    assertNotNull(m.getRequestControlOIDs());
    assertFalse(m.getRequestControlOIDs().isEmpty());
    assertEquals(m.getRequestControlOIDs(),
         Arrays.asList("2.16.840.1.113730.3.4.2", "1.3.6.1.1.12",
              "1.3.6.1.4.1.30221.2.5.19", "1.3.6.1.4.1.30221.2.5.2"));

    assertNotNull(m.getOperationPurposeRequestControl());
    assertEquals(m.getOperationPurposeRequestControl().getApplicationName(),
         "Test Application");
    assertEquals(m.getOperationPurposeRequestControl().getApplicationVersion(),
         "1.2.3");
    assertEquals(m.getOperationPurposeRequestControl().getCodeLocation(),
         "Somewhere in the code");
    assertEquals(m.getOperationPurposeRequestControl().getRequestPurpose(),
         "Just testing");

    assertNotNull(m.getIntermediateClientRequestControl());
    assertEquals(m.getIntermediateClientRequestControl().getClientIdentity(),
         "dn:cn=Directory Manager,cn=Root DNs,cn=config");
    assertEquals(
         m.getIntermediateClientRequestControl().getDownstreamClientAddress(),
         "127.0.0.1");
    assertEquals(
         m.getIntermediateClientRequestControl().downstreamClientSecure(),
         Boolean.FALSE);
    assertEquals(m.getIntermediateClientRequestControl().getClientName(),
         "PingDirectory");
    assertEquals(m.getIntermediateClientRequestControl().getClientSessionID(),
         "conn=8");
    assertEquals(m.getIntermediateClientRequestControl().getClientRequestID(),
         "op=1");
    assertNotNull(
         m.getIntermediateClientRequestControl().getDownstreamRequest());
    assertEquals(
         m.getIntermediateClientRequestControl().getDownstreamRequest().
              getClientName(),
         "Unidentified Directory Application");

    assertNotNull(m.getDN());
    assertDNsEqual(m.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(m.getEntry());

    assertNotNull(m.getIsUndelete());
    assertEquals(m.getIsUndelete(), Boolean.FALSE);

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.ADD);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFAddChangeRecord);

    assertTrue(m.isRevertible());

    assertNotNull(m.getRevertChangeRecords());
    assertFalse(m.getRevertChangeRecords().isEmpty());
    assertEquals(m.getRevertChangeRecords().size(), 1);
    assertTrue(
         m.getRevertChangeRecords().get(0) instanceof LDIFDeleteChangeRecord);

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior when trying to create an audit log message from a null
   * set of lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testLogMessageFromNullLines()
         throws Exception
  {
    final List<String> nullList = null;
    new AddAuditLogMessage(nullList);
  }



  /**
   * Tests the behavior when trying to create an audit log message from an empty
   * set of lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testLogMessageFromEmptyLines()
         throws Exception
  {
    new AddAuditLogMessage(Collections.<String>emptyList());
  }



  /**
   * Tests the behavior when trying to create an audit log message from a set of
   * lines that includes a line with zero characters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testLogMessageFromLinesWithZeroLengthLine()
         throws Exception
  {
    new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.123 -0500",
         "",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the behavior when trying to create an audit log message from a set of
   * lines that don't contain any comments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testLogMessageFromLinesWithoutComments()
         throws Exception
  {
    new AddAuditLogMessage(
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the behavior when trying to create an audit log message from a set of
   * lines that includes comments but not a valid header line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testLogMessageFromLinesWithCommentsButWithoutHeader()
         throws Exception
  {
    new AddAuditLogMessage(
         "# This is a comment but isn't a valid header.",
         "# This is also not a valid header comment.",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the behavior when trying to create an audit log message from a set of
   * lines that includes comments including one that matches the header regex
   * but that has a timestamp with an invalid length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testLogMessageFromLinesWithBadHeaderInvalidTimestampLength()
         throws Exception
  {
    new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.12345 -0500",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the behavior when trying to create an audit log message from a set of
   * lines that includes comments including one that matches the header regex
   * but that has a timestamp that can't be parsed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testLogMessageFromLinesWithBadHeaderNonParseableTimestamp()
         throws Exception
  {
    new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.bad -0500",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the behavior when trying to create an audit log message from a set of
   * lines that includes comments including one that matches the header regex
   * but that has a property name that isn't followed by an equal sign.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testLogMessageHeaderHasPropertyNameWithoutEqual()
         throws Exception
  {
    new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.123 -0500; missingEqual",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the behavior when trying to create an audit log message from a set of
   * lines that includes comments including one that matches the header regex
   * but that has a property with a zero-length name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testLogMessageHeaderHasPropertyWithEmptyName()
         throws Exception
  {
    new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.123 -0500; =emptyPropertyName",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the behavior when trying to create an audit log message from a set of
   * lines that includes comments including one that matches the header regex
   * but that has a property with a quoted value that isn't closed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testLogMessageHeaderHasPropertyWithUnclosedQuotedValue()
         throws Exception
  {
    new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.123 -0500; quotedValue=\"unclosed",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the behavior when trying to create an audit log message from a set of
   * lines that includes comments including one that matches the header regex
   * but that has a value that looks like JSON but can't be parsed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testLogMessageHeaderHasPropertyWithMalformedJSONValue()
         throws Exception
  {
    new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.123 -0500; malformedJSONValue={ \"malformed\"",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the behavior when trying to create an audit log message from a set of
   * lines that includes comments including one that matches the header regex
   * but that has an unquoted string value that includes a backslash that isn't
   * followed by any more characters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testLogMessageHeaderHasUnquotedValueWithTrailingBackslash()
         throws Exception
  {
    new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.123 -0500; trailingBackslash=test\\",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the behavior when trying to create an audit log message from a set of
   * lines that includes comments including one that matches the header regex
   * but that has a quoted string value that includes a backslash that isn't
   * followed by any more characters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testLogMessageHeaderHasQuotedValueWithTrailingBackslash()
         throws Exception
  {
    new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.123 -0500; trailingBackslash=\"test\\\"",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the behavior when trying to create an audit log message from a set of
   * lines that includes comments including one that matches the header regex
   * but that has a string value that contains an octothorpe at the end (not
   * followed by any nex digits).
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testLogMessageHeaderValueWithTrailingOctothorpe()
         throws Exception
  {
    new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.123 -0500; trailingOctothorpe=test#",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the behavior when trying to create an audit log message from a set of
   * lines that includes comments including one that matches the header regex
   * but that has a string value that contains an octothorpe followed by only
   * one hex digit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testLogMessageHeaderValueWithOctothorpeFollowedByOneHexDigit()
         throws Exception
  {
    new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.123 -0500; trailingOctothorpe=test#a",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the behavior when trying to create an audit log message from a set of
   * lines that includes comments including one that matches the header regex
   * but that has a string value that contains an octothorpe followed by
   * characters that aren't hex digits.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testLogMessageHeaderValueWithOctothorpeFollowedByNonHex()
         throws Exception
  {
    new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.123 -0500; trailingOctothorpe=test#nonhex",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the behavior when trying to create an audit log message from a set of
   * lines that includes comments including one that matches the header regex
   * but that has an unquoted string value that includes an unescaped space.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testLogMessageHeaderUnquotedValueWithUnescapedSpace()
         throws Exception
  {
    new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.123 -0500; value=unescaped space",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Tests the behavior for a property value that ends with a quoted string not
   * followed by a semicolon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHeaderLineEndsWithQuotedStringNotFollowedBySemicolon()
         throws Exception
  {
    final AuditLogMessage m = new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.123 -0500; quotedString=\"foo\"",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    assertNotNull(m.getHeaderNamedValues());
    assertFalse(m.getHeaderNamedValues().isEmpty());
    assertEquals(m.getHeaderNamedValues().size(), 1);

    assertTrue(m.getHeaderNamedValues().containsKey("quotedString"));
    assertEquals(m.getHeaderNamedValues().get("quotedString"), "foo");
  }



  /**
   * Tests the behavior for a property value that ends with a quoted string that
   * is followed by a semicolon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHeaderLineEndsWithQuotedStringFollowedBySemicolon()
         throws Exception
  {
    final AuditLogMessage m = new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.123 -0500; quotedString=\"foo\";",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    assertNotNull(m.getHeaderNamedValues());
    assertFalse(m.getHeaderNamedValues().isEmpty());
    assertEquals(m.getHeaderNamedValues().size(), 1);

    assertTrue(m.getHeaderNamedValues().containsKey("quotedString"));
    assertEquals(m.getHeaderNamedValues().get("quotedString"), "foo");
  }



  /**
   * Tests the behavior for a property value that ends with an unquoted string
   * not followed by a semicolon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHeaderLineEndsWithUnquotedStringNotFollowedBySemicolon()
         throws Exception
  {
    final AuditLogMessage m = new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.123 -0500; unquotedString=foo",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    assertNotNull(m.getHeaderNamedValues());
    assertFalse(m.getHeaderNamedValues().isEmpty());
    assertEquals(m.getHeaderNamedValues().size(), 1);

    assertTrue(m.getHeaderNamedValues().containsKey("unquotedString"));
    assertEquals(m.getHeaderNamedValues().get("unquotedString"), "foo");
  }



  /**
   * Tests the behavior for a property value that ends with an unquoted string
   * that is followed by a semicolon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHeaderLineEndsWithUnquotedStringFollowedBySemicolon()
         throws Exception
  {
    final AuditLogMessage m = new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.123 -0500; unquotedString=foo;",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    assertNotNull(m.getHeaderNamedValues());
    assertFalse(m.getHeaderNamedValues().isEmpty());
    assertEquals(m.getHeaderNamedValues().size(), 1);

    assertTrue(m.getHeaderNamedValues().containsKey("unquotedString"));
    assertEquals(m.getHeaderNamedValues().get("unquotedString"), "foo");
  }



  /**
   * Tests the behavior of the readHexDigit method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadHexDigit()
         throws Exception
  {
    final AuditLogMessage m = new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.123 -0500; value=#30#31#32#33#34#35#36#37" +
              "#38#39#3a#3A#3b#3B#3c#3C#3d#3D#3e#3E#3f#3f",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    assertNotNull(m.getHeaderNamedValues());
    assertFalse(m.getHeaderNamedValues().isEmpty());
    assertEquals(m.getHeaderNamedValues().size(), 1);

    assertTrue(m.getHeaderNamedValues().containsKey("value"));
    assertEquals(m.getHeaderNamedValues().get("value"),
         "0123456789::;;<<==>>??");
  }



  /**
   * Tests the behavior of the getNamedValueAsBoolean method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetNamedValueAsBoolean()
         throws Exception
  {
    final AuditLogMessage m = new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.123 -0500; trueValue=true; tValue=t; " +
              "yesValue=yes; yValue=y; onValue=on; 1value=1; " +
              "falseValue=false; fValue=f; noValue=no; nValue=n; " +
              "offValue=off; 0value=0; nonBooleanValue=nonBoolean",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    assertNotNull(m.getHeaderNamedValues());
    assertFalse(m.getHeaderNamedValues().isEmpty());
    assertEquals(m.getHeaderNamedValues().size(), 13);

    assertTrue(AuditLogMessage.getNamedValueAsBoolean("trueValue",
         m.getHeaderNamedValues()));
    assertTrue(AuditLogMessage.getNamedValueAsBoolean("tValue",
         m.getHeaderNamedValues()));
    assertTrue(AuditLogMessage.getNamedValueAsBoolean("yesValue",
         m.getHeaderNamedValues()));
    assertTrue(AuditLogMessage.getNamedValueAsBoolean("yValue",
         m.getHeaderNamedValues()));
    assertTrue(AuditLogMessage.getNamedValueAsBoolean("onValue",
         m.getHeaderNamedValues()));
    assertTrue(AuditLogMessage.getNamedValueAsBoolean("1value",
         m.getHeaderNamedValues()));

    assertFalse(AuditLogMessage.getNamedValueAsBoolean("falseValue",
         m.getHeaderNamedValues()));
    assertFalse(AuditLogMessage.getNamedValueAsBoolean("fValue",
         m.getHeaderNamedValues()));
    assertFalse(AuditLogMessage.getNamedValueAsBoolean("noValue",
         m.getHeaderNamedValues()));
    assertFalse(AuditLogMessage.getNamedValueAsBoolean("nValue",
         m.getHeaderNamedValues()));
    assertFalse(AuditLogMessage.getNamedValueAsBoolean("offValue",
         m.getHeaderNamedValues()));
    assertFalse(AuditLogMessage.getNamedValueAsBoolean("0value",
         m.getHeaderNamedValues()));

    assertNull(AuditLogMessage.getNamedValueAsBoolean("nonBooleanValue",
         m.getHeaderNamedValues()));

    assertNull(AuditLogMessage.getNamedValueAsBoolean("missingValue",
         m.getHeaderNamedValues()));
  }



  /**
   * Tests the behavior of the getNamedValueAsLong method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetNamedValueAsLong()
         throws Exception
  {
    final AuditLogMessage m = new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.123 -0500; positiveValue=1234; " +
              "negativeValue=-5678; zeroValue=0; nonLongValue=nonLong",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    assertNotNull(m.getHeaderNamedValues());
    assertFalse(m.getHeaderNamedValues().isEmpty());
    assertEquals(m.getHeaderNamedValues().size(), 4);

    assertEquals(
         AuditLogMessage.getNamedValueAsLong("positiveValue",
              m.getHeaderNamedValues()).longValue(),
         1234L);

    assertEquals(
         AuditLogMessage.getNamedValueAsLong("negativeValue",
              m.getHeaderNamedValues()).longValue(),
         -5678L);

    assertEquals(
         AuditLogMessage.getNamedValueAsLong("zeroValue",
              m.getHeaderNamedValues()).longValue(),
         0L);

    assertNull(AuditLogMessage.getNamedValueAsLong("nonLongValue",
         m.getHeaderNamedValues()));

    assertNull(AuditLogMessage.getNamedValueAsLong("missingValue",
         m.getHeaderNamedValues()));
  }



  /**
   * Tests the behavior with a malformed operation purpose request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedOperationPurposeRequestControl()
         throws Exception
  {
    final AuditLogMessage m = new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.123 -0500; operationPurpose=\"not JSON\"",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    assertNull(m.getOperationPurposeRequestControl());
  }



  /**
   * Tests the behavior with a malformed intermediate client request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedIntermediateClientRequestControl()
         throws Exception
  {
    final AuditLogMessage m = new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40.123 -0500; " +
              "intermediateClientRequestControl=\"not JSON\"",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    assertNull(m.getOperationPurposeRequestControl());
  }



  /**
   * Tests the behavior of the {@code decodeCommentedEntry} method for a valid
   * entry that has a DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeCommentedEntryWithDN()
         throws Exception
  {
    final List<String> lines = Arrays.asList(
         "# This is a test line that isn't part of the entry",
         "# The entry starts below this",
         "# dn: dc=example,dc=com",
         "# objectClass: top",
         "# objectClass: domain",
         "# dc: example",
         "dn: dc=example,dc=com",
         "changetype: delete");

    final ReadOnlyEntry e = AuditLogMessage.decodeCommentedEntry(
         "The entry starts below this", lines, null);
    assertNotNull(e);
    assertEquals(e,
         new ReadOnlyEntry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
  }



  /**
   * Tests the behavior of the {@code decodeCommentedEntry} method for a valid
   * entry that does not have a DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeCommentedEntryWithoutDN()
         throws Exception
  {
    final List<String> lines = Arrays.asList(
         "# This is a test line that isn't part of the entry",
         "# The list of attributes starts below",
         "# objectClass: top",
         "# objectClass: organizationalUnit",
         "# ou: People",
         "# More attributes start below this",
         "# description: foo",
         "# description: bar",
         "dn: dc=example,dc=com",
         "changetype: delete");

    final ReadOnlyEntry e = AuditLogMessage.decodeCommentedEntry(
         "The list of attributes starts below", lines,
         "ou=People,dc=example,dc=com");
    assertNotNull(e);
    assertEquals(e,
         new ReadOnlyEntry(
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));
  }



  /**
   * Tests the behavior of the {@code decodeCommentedEntry} method for a header
   * that doesn't include the expected header line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeCommentedEntryWithoutHeaderLine()
         throws Exception
  {
    final List<String> lines = Arrays.asList(
         "# This is a test line that isn't part of the entry",
         "# There is an entry, but not the expected header line",
         "# dn: dc=example,dc=com",
         "# objectClass: top",
         "# objectClass: domain",
         "# dc: example",
         "dn: dc=example,dc=com",
         "changetype: delete");

    assertNull(AuditLogMessage.decodeCommentedEntry(
         "A line that isn't in the header", lines, null));
  }



  /**
   * Tests the behavior of the {@code decodeCommentedEntry} method for a header
   * that has a malformed entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeCommentedEntryMalformed()
         throws Exception
  {
    final List<String> lines = Arrays.asList(
         "# This is a test line that isn't part of the entry",
         "# The entry starts below this",
         "# dn: dc=example,dc=com",
         "# objectClass: top",
         "# objectClass: domain",
         "# dc: example",
         "# description:: This is not valid base64",
         "dn: dc=example,dc=com",
         "changetype: delete");

    assertNull(AuditLogMessage.decodeCommentedEntry(
         "The entry starts below this", lines, null));
  }
}
