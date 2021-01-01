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
import java.util.GregorianCalendar;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.unboundidds.controls.SoftDeleteRequestControl;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;



/**
 * This class provides a set of test cases for add audit log messages.
 */
public final class AddAuditLogMessageTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a basic add audit log message read from an array of
   * strings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicLogMessageFromArray()
         throws Exception
  {
    final AddAuditLogMessage m = new AddAuditLogMessage(
         "# 23/Aug/2018:14:02:40 -0500; conn=28; op=1; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"",
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
    assertEquals(m.getCommentedHeaderLine(),
         "# 23/Aug/2018:14:02:40 -0500; conn=28; op=1; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"");

    assertNotNull(m.getUncommentedHeaderLine());
    assertEquals(m.getUncommentedHeaderLine(),
         "23/Aug/2018:14:02:40 -0500; conn=28; op=1; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"");

    assertNotNull(m.getTimestamp());
    final Calendar calendar = new GregorianCalendar();
    calendar.setTime(m.getTimestamp());
    assertEquals(calendar.get(Calendar.YEAR), 2018);
    assertEquals(calendar.get(Calendar.MONTH), Calendar.AUGUST);

    assertNotNull(m.getHeaderNamedValues());
    assertFalse(m.getHeaderNamedValues().isEmpty());
    assertTrue(m.getHeaderNamedValues().containsKey("conn"));

    assertNull(m.getProductName());

    assertNull(m.getInstanceName());

    assertNull(m.getStartupID());

    assertNull(m.getThreadID());

    assertNull(m.getRequesterDN());

    assertNull(m.getRequesterIPAddress());

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID().longValue(), 28L);

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID().longValue(), 1L);

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

    assertNull(m.getReplicationChangeID());

    assertNotNull(m.getAlternateAuthorizationDN());
    assertDNsEqual(m.getAlternateAuthorizationDN(),
         "cn=Directory Manager,cn=Root DNs,cn=config");

    assertNull(m.getTransactionID());

    assertNull(m.getOrigin());

    assertNull(m.getUsingAdminSessionWorkerThread());

    assertNull(m.getRequestControlOIDs());

    assertNull(m.getOperationPurposeRequestControl());

    assertNull(m.getIntermediateClientRequestControl());

    assertNotNull(m.getDN());
    assertDNsEqual(m.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(m.getEntry());

    assertNull(m.getIsUndelete());

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

    final LDIFDeleteChangeRecord revertChangeRecord =
         (LDIFDeleteChangeRecord) m.getRevertChangeRecords().get(0);
    assertDNsEqual(revertChangeRecord.getDN(), "ou=People,dc=example,dc=com");
    assertNotNull(revertChangeRecord.getControls());
    assertTrue(revertChangeRecord.getControls().isEmpty());

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a basic add audit log message read from a list of
   * strings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicLogMessageFromList()
         throws Exception
  {
    final AddAuditLogMessage m = new AddAuditLogMessage(Arrays.asList(
         "# 23/Aug/2018:14:02:40 -0500; conn=28; op=1; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"",
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "createTimestamp: 20180823190240.967Z",
         "creatorsName: cn=Directory Manager,cn=Root DNs,cn=config",
         "modifyTimestamp: 20180823190240.967Z",
         "modifiersName: cn=Directory Manager,cn=Root DNs,cn=config",
         "entryUUID: b58849bd-2032-4077-ba10-2cd9be8166e0"));

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

    assertNull(m.getProductName());

    assertNull(m.getInstanceName());

    assertNull(m.getStartupID());

    assertNull(m.getThreadID());

    assertNull(m.getRequesterDN());

    assertNull(m.getRequesterIPAddress());

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID().longValue(), 28L);

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID().longValue(), 1L);

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

    assertNull(m.getReplicationChangeID());

    assertNotNull(m.getAlternateAuthorizationDN());
    assertDNsEqual(m.getAlternateAuthorizationDN(),
         "cn=Directory Manager,cn=Root DNs,cn=config");

    assertNull(m.getTransactionID());

    assertNull(m.getOrigin());

    assertNull(m.getUsingAdminSessionWorkerThread());

    assertNull(m.getRequestControlOIDs());

    assertNull(m.getOperationPurposeRequestControl());

    assertNull(m.getIntermediateClientRequestControl());

    assertNotNull(m.getDN());
    assertDNsEqual(m.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(m.getEntry());

    assertNull(m.getIsUndelete());

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

    final LDIFDeleteChangeRecord revertChangeRecord =
         (LDIFDeleteChangeRecord) m.getRevertChangeRecords().get(0);
    assertDNsEqual(revertChangeRecord.getDN(), "ou=People,dc=example,dc=com");
    assertNotNull(revertChangeRecord.getControls());
    assertTrue(revertChangeRecord.getControls().isEmpty());

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a basic add audit log message read from a list of
   * strings and an already-provided change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicLogMessageFromListAndChangeRecord()
         throws Exception
  {
    final AddAuditLogMessage m = new AddAuditLogMessage(
         Arrays.asList(
              "# 23/Aug/2018:14:02:40 -0500; conn=28; op=1; " +
                   "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"",
              "dn: ou=People,dc=example,dc=com",
              "changetype: add",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People",
              "createTimestamp: 20180823190240.967Z",
              "creatorsName: cn=Directory Manager,cn=Root DNs,cn=config",
              "modifyTimestamp: 20180823190240.967Z",
              "modifiersName: cn=Directory Manager,cn=Root DNs,cn=config",
              "entryUUID: b58849bd-2032-4077-ba10-2cd9be8166e0"),
         new LDIFAddChangeRecord(new AddRequest(
              "dn: ou=People,dc=example,dc=com",
              "changetype: add",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People",
              "createTimestamp: 20180823190240.967Z",
              "creatorsName: cn=Directory Manager,cn=Root DNs,cn=config",
              "modifyTimestamp: 20180823190240.967Z",
              "modifiersName: cn=Directory Manager,cn=Root DNs,cn=config",
              "entryUUID: b58849bd-2032-4077-ba10-2cd9be8166e0")));

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

    assertNull(m.getProductName());

    assertNull(m.getInstanceName());

    assertNull(m.getStartupID());

    assertNull(m.getThreadID());

    assertNull(m.getRequesterDN());

    assertNull(m.getRequesterIPAddress());

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID().longValue(), 28L);

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID().longValue(), 1L);

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

    assertNull(m.getReplicationChangeID());

    assertNotNull(m.getAlternateAuthorizationDN());
    assertDNsEqual(m.getAlternateAuthorizationDN(),
         "cn=Directory Manager,cn=Root DNs,cn=config");

    assertNull(m.getTransactionID());

    assertNull(m.getOrigin());

    assertNull(m.getUsingAdminSessionWorkerThread());

    assertNull(m.getRequestControlOIDs());

    assertNull(m.getOperationPurposeRequestControl());

    assertNull(m.getIntermediateClientRequestControl());

    assertNotNull(m.getDN());
    assertDNsEqual(m.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(m.getEntry());

    assertNull(m.getIsUndelete());

    assertNull(m.getUndeleteRequestEntry());

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
   * Tests the behavior for an add audit log message that describes an undelete
   * operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUndeleteAuditLogMessage()
         throws Exception
  {
    final AddAuditLogMessage m = new AddAuditLogMessage(
         "# 24/Aug/2018:12:11:51.006 -0500; conn=56; op=1; " +
              "productName=\"Directory Server\"; " +
              "instanceName=\"ReplicaOne\"; startupID=W4A77w==; threadID=14; " +
              "clientIP=127.0.0.1; " +
              "requesterDN=\"cn=Proxy User,cn=Root DNs,cn=config\"; " +
              "replicationChangeID=\"000001656CEBB3D55DE30000000D\"; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"; " +
              "isUndelete=true; " +
              "requestControlOIDs=\"1.3.6.1.4.1.30221.2.5.23," +
              "1.3.6.1.4.1.30221.2.5.2\"; intermediateClientRequestControl={ " +
              "\"clientIdentity\":\"dn:cn=Directory Manager,cn=Root " +
              "DNs,cn=config\", \"downstreamClientAddress\":\"127.0.0.1\", " +
              "\"downstreamClientSecure\":false, " +
              "\"clientName\":\"PingDirectory\", " +
              "\"clientSessionID\":\"conn=9\", \"clientRequestID\":\"op=3\", " +
              "\"downstreamRequest\":{ " +
              "\"clientName\":\"Unidentified Directory Application\" } }",
              "# Undelete request entry",
              "# dn: ou=People,dc=example,dc=com",
              "# ds-undelete-from-dn: " +
                   "entryUUID=b4004999-f0cf-4b6b-9d9d-1b2ee06a0b38+ou=People," +
                   "dc=example,dc=com",
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "createTimestamp: 20180824171150.975Z",
         "creatorsName: cn=Directory Manager,cn=Root DNs,cn=config",
         "modifyTimestamp: 20180824171150.975Z",
         "modifiersName: cn=Directory Manager,cn=Root DNs,cn=config",
         "entryUUID: d7fc4a73-3338-4a99-b26e-9e971297445e");
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

    assertNotNull(m.getProductName());
    assertEquals(m.getProductName(), "Directory Server");

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "ReplicaOne");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "W4A77w==");

    assertNotNull(m.getThreadID());
    assertEquals(m.getThreadID().longValue(), 14L);

    assertNotNull(m.getRequesterDN());
    assertDNsEqual(m.getRequesterDN(), "cn=Proxy User,cn=Root DNs,cn=config");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "127.0.0.1");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID().longValue(), 56L);

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID().longValue(), 1L);

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

    assertNotNull(m.getReplicationChangeID());
    assertEquals(m.getReplicationChangeID(), "000001656CEBB3D55DE30000000D");

    assertNotNull(m.getAlternateAuthorizationDN());
    assertDNsEqual(m.getAlternateAuthorizationDN(),
         "cn=Directory Manager,cn=Root DNs,cn=config");

    assertNull(m.getTransactionID());

    assertNull(m.getOrigin());

    assertNull(m.getUsingAdminSessionWorkerThread());

    assertNotNull(m.getRequestControlOIDs());
    assertFalse(m.getRequestControlOIDs().isEmpty());
    assertEquals(m.getRequestControlOIDs(),
         Arrays.asList("1.3.6.1.4.1.30221.2.5.23", "1.3.6.1.4.1.30221.2.5.2"));

    assertNull(m.getOperationPurposeRequestControl());

    assertNotNull(m.getIntermediateClientRequestControl());

    assertNotNull(m.getDN());
    assertDNsEqual(m.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(m.getEntry());

    assertNotNull(m.getIsUndelete());
    assertTrue(m.getIsUndelete());

    assertNotNull(m.getUndeleteRequestEntry());
    assertEquals(m.getUndeleteRequestEntry(),
         new ReadOnlyEntry(
              "dn: ou=People,dc=example,dc=com",
              "ds-undelete-from-dn: " +
                   "entryUUID=b4004999-f0cf-4b6b-9d9d-1b2ee06a0b38+ou=People," +
                   "dc=example,dc=com"));

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

    final LDIFDeleteChangeRecord revertChangeRecord =
         (LDIFDeleteChangeRecord) m.getRevertChangeRecords().get(0);
    assertDNsEqual(revertChangeRecord.getDN(), "ou=People,dc=example,dc=com");
    assertNotNull(revertChangeRecord.getControls());
    assertFalse(revertChangeRecord.getControls().isEmpty());

    final SoftDeleteRequestControl softDeleteRequestControl =
         (SoftDeleteRequestControl)
         revertChangeRecord.toDeleteRequest().getControl(
              SoftDeleteRequestControl.SOFT_DELETE_REQUEST_OID);
    assertNotNull(softDeleteRequestControl);

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior when trying to create an add audit log message from a
   * set of lines that don't include an add change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testNotAddChangeRecord()
         throws Exception
  {
    final AddAuditLogMessage m = new AddAuditLogMessage(Arrays.asList(
         "# 23/Aug/2018:14:02:40 -0500; conn=28; op=1; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"",
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete"));
  }



  /**
   * Tests the behavior when trying to create an add audit log message from a
   * set of lines that represent a valid change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testNotValidChangeRecord()
         throws Exception
  {
    final AddAuditLogMessage m = new AddAuditLogMessage(Arrays.asList(
         "# 23/Aug/2018:14:02:40 -0500; conn=28; op=1; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"",
         "This is not a valid change record"));
  }
}
