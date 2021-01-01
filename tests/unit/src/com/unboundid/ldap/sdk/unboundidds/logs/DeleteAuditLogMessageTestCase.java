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

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.unboundidds.controls.UndeleteRequestControl;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;



/**
 * This class provides a set of test cases for delete audit log messages.
 */
public final class DeleteAuditLogMessageTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a basic, non-reversible delete audit log message
   * read from an array of strings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicNonReversibleDeleteLogMessageFromArray()
         throws Exception
  {
    final DeleteAuditLogMessage m = new DeleteAuditLogMessage(
         "# 24/Aug/2018:12:11:50 -0500; conn=33; op=1; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"",
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete");

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertEquals(m.getCommentedHeaderLine(),
         "# 24/Aug/2018:12:11:50 -0500; conn=33; op=1; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"");

    assertNotNull(m.getUncommentedHeaderLine());
    assertEquals(m.getUncommentedHeaderLine(),
         "24/Aug/2018:12:11:50 -0500; conn=33; op=1; " +
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
    assertEquals(m.getConnectionID().longValue(), 33L);

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

    assertNull(m.getIsSubtreeDelete());

    assertNull(m.getDeletedAsPartOfSubtreeDelete());

    assertNull(m.getIsSoftDelete());

    assertNull(m.getSoftDeletedEntryDN());

    assertNull(m.getIsSoftDeletedEntry());

    assertNull(m.getDeletedEntry());

    assertNull(m.getDeletedEntryVirtualAttributes());

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.DELETE);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFDeleteChangeRecord);

    assertFalse(m.isRevertible());

    try
    {
      m.getRevertChangeRecords();
      fail("Expected an exception when trying to revert a non-revertible " +
           "delete audit log message");
    }
    catch (final AuditLogException e)
    {
      // This was expected.
    }

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a basic, reversible delete audit log message read
   * from a list of strings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicReversibleDeleteLogMessageFromList()
         throws Exception
  {
    final DeleteAuditLogMessage m = new DeleteAuditLogMessage(Arrays.asList(
         "# --- INCREMENTAL SIGNED CONTENT ---  " +
              "signature='p1WyKjniyWSaZVmuhNRhPI3v/wpzLmTTr04bnW4Drs4='",
         "# 24/Aug/2018:12:11:50.949 -0500; conn=-18; op=757; " +
              "origin=\"replication\"; productName=\"Directory Server\"; " +
              "instanceName=\"ReplicaTwo\"; startupID=W4A8Ew==; " +
              "threadID=232; clientIP=internal; " +
              "requesterDN=\"cn=Internal Client,cn=Internal,cn=Root " +
              "DNs,cn=config\"; " +
              "replicationChangeID=\"000001656CEBB3525DE300000007\"",
         "# Deleted entry real attributes",
         "# objectClass: top",
         "# objectClass: organizationalUnit",
         "# ou: People",
         "# createTimestamp: 20180824200759.380Z",
         "# creatorsName: cn=Directory Manager,cn=Root DNs,cn=config",
         "# modifyTimestamp: 20180824200759.380Z",
         "# modifiersName: cn=Directory Manager,cn=Root DNs,cn=config",
         "# entryUUID: 5f06efca-2796-4d2a-9b14-a543dbd322e0",
         "# Deleted entry virtual attributes",
         "# ds-entry-checksum: 419234829",
         "# subschemaSubentry: cn=schema",
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete"));

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertTrue(m.getCommentedHeaderLine().startsWith(
         "# 24/Aug/2018:12:11:50.949 -0500; conn=-18; op=757; "));

    assertNotNull(m.getUncommentedHeaderLine());
    assertTrue(m.getUncommentedHeaderLine().startsWith(
         "24/Aug/2018:12:11:50.949 -0500; conn=-18; op=757; "));

    assertNotNull(m.getTimestamp());
    final Calendar calendar = new GregorianCalendar();
    calendar.setTime(m.getTimestamp());
    assertEquals(calendar.get(Calendar.YEAR), 2018);
    assertEquals(calendar.get(Calendar.MONTH), Calendar.AUGUST);

    assertNotNull(m.getHeaderNamedValues());
    assertFalse(m.getHeaderNamedValues().isEmpty());
    assertTrue(m.getHeaderNamedValues().containsKey("conn"));

    assertNotNull(m.getProductName());
    assertEquals(m.getProductName(), "Directory Server");

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "ReplicaTwo");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "W4A8Ew==");

    assertNotNull(m.getThreadID());
    assertEquals(m.getThreadID().longValue(), 232L);

    assertNotNull(m.getRequesterDN());
    assertDNsEqual(m.getRequesterDN(),
         "cn=Internal Client,cn=Internal,cn=Root DNs,cn=config");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "internal");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID().longValue(), -18L);

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID().longValue(), 757L);

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

    assertNotNull(m.getReplicationChangeID());
    assertEquals(m.getReplicationChangeID(), "000001656CEBB3525DE300000007");

    assertNull(m.getAlternateAuthorizationDN());

    assertNull(m.getTransactionID());

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "replication");

    assertNull(m.getUsingAdminSessionWorkerThread());

    assertNull(m.getRequestControlOIDs());

    assertNull(m.getOperationPurposeRequestControl());

    assertNull(m.getIntermediateClientRequestControl());

    assertNotNull(m.getDN());
    assertDNsEqual(m.getDN(), "ou=People,dc=example,dc=com");

    assertNull(m.getIsSubtreeDelete());

    assertNull(m.getDeletedAsPartOfSubtreeDelete());

    assertNull(m.getIsSoftDelete());

    assertNull(m.getSoftDeletedEntryDN());

    assertNull(m.getIsSoftDeletedEntry());

    assertNotNull(m.getDeletedEntry());
    assertEquals(m.getDeletedEntry(),
         new ReadOnlyEntry(
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People",
              "createTimestamp: 20180824200759.380Z",
              "creatorsName: cn=Directory Manager,cn=Root DNs,cn=config",
              "modifyTimestamp: 20180824200759.380Z",
              "modifiersName: cn=Directory Manager,cn=Root DNs,cn=config",
              "entryUUID: 5f06efca-2796-4d2a-9b14-a543dbd322e0"));

    assertNotNull(m.getDeletedEntryVirtualAttributes());
    assertFalse(m.getDeletedEntryVirtualAttributes().isEmpty());
    assertEquals(m.getDeletedEntryVirtualAttributes(),
         Arrays.asList(
              new Attribute("ds-entry-checksum", "419234829"),
              new Attribute("subschemaSubentry", "cn=schema")));

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.DELETE);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFDeleteChangeRecord);

    assertTrue(m.isRevertible());

    final List<LDIFChangeRecord> revertChangeRecords =
         m.getRevertChangeRecords();
    assertNotNull(revertChangeRecords);
    assertFalse(revertChangeRecords.isEmpty());
    assertEquals(revertChangeRecords.size(), 1);
    assertTrue(revertChangeRecords.get(0) instanceof LDIFAddChangeRecord);

    final LDIFAddChangeRecord revertChangeRecord =
         (LDIFAddChangeRecord) revertChangeRecords.get(0);
    assertEquals(revertChangeRecord.getEntryToAdd(),
         m.getDeletedEntry());

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a reversible delete audit log message that reflects
   * the deletion of the base entry for a subtree delete operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBaseOfSubtreeDeleteWithDeletedEntry()
         throws Exception
  {
    final DeleteAuditLogMessage m = new DeleteAuditLogMessage(
         "# 24/Aug/2018:15:07:59.457 -0500; conn=59; op=1; " +
              "productName=\"Directory Server\"; " +
              "instanceName=\"ReplicaOne\"; startupID=W4BlNw==; " +
              "threadID=13; clientIP=127.0.0.1; " +
              "requesterDN=\"cn=Proxy User,cn=Root DNs,cn=config\"; " +
              "replicationChangeID=\"000001656D8CF6C70D3F00000016\"; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"; " +
              "isSubtreeDelete=true; " +
              "requestControlOIDs=\"1.2.840.113556.1.4.805," +
              "1.3.6.1.4.1.30221.2.5.2\"; intermediateClientRequestControl={ " +
              "\"clientIdentity\":\"dn:cn=Directory Manager,cn=Root " +
              "DNs,cn=config\", \"downstreamClientAddress\":\"127.0.0.1\", " +
              "\"downstreamClientSecure\":false, " +
              "\"clientName\":\"PingDirectory\", " +
              "\"clientSessionID\":\"conn=10\", " +
              "\"clientRequestID\":\"op=7\", \"downstreamRequest\":{ " +
              "\"clientName\":\"Unidentified Directory Application\" } }",
         "# Deleted entry real attributes",
         "# objectClass: top",
         "# objectClass: organizationalUnit",
         "# ou: People",
         "# createTimestamp: 20180824200759.380Z",
         "# creatorsName: cn=Directory Manager,cn=Root DNs,cn=config",
         "# modifyTimestamp: 20180824200759.380Z",
         "# modifiersName: cn=Directory Manager,cn=Root DNs,cn=config",
         "# entryUUID: 5f06efca-2796-4d2a-9b14-a543dbd322e0",
         "# Deleted entry virtual attributes",
         "# ds-entry-checksum: 419234829",
         "# subschemaSubentry: cn=schema",
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete");

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertTrue(m.getCommentedHeaderLine().startsWith(
         "# 24/Aug/2018:15:07:59.457 -0500; conn=59; op=1; "));

    assertNotNull(m.getUncommentedHeaderLine());
    assertTrue(m.getUncommentedHeaderLine().startsWith(
         "24/Aug/2018:15:07:59.457 -0500; conn=59; op=1; "));

    assertNotNull(m.getTimestamp());
    final Calendar calendar = new GregorianCalendar();
    calendar.setTime(m.getTimestamp());
    assertEquals(calendar.get(Calendar.YEAR), 2018);
    assertEquals(calendar.get(Calendar.MONTH), Calendar.AUGUST);

    assertNotNull(m.getHeaderNamedValues());
    assertFalse(m.getHeaderNamedValues().isEmpty());
    assertTrue(m.getHeaderNamedValues().containsKey("conn"));

    assertNotNull(m.getProductName());
    assertEquals(m.getProductName(), "Directory Server");

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "ReplicaOne");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "W4BlNw==");

    assertNotNull(m.getThreadID());
    assertEquals(m.getThreadID().longValue(), 13L);

    assertNotNull(m.getRequesterDN());
    assertDNsEqual(m.getRequesterDN(), "cn=Proxy User,cn=Root DNs,cn=config");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "127.0.0.1");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID().longValue(), 59L);

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID().longValue(), 1L);

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

    assertNotNull(m.getReplicationChangeID());
    assertEquals(m.getReplicationChangeID(), "000001656D8CF6C70D3F00000016");

    assertNotNull(m.getAlternateAuthorizationDN());
    assertDNsEqual(m.getAlternateAuthorizationDN(),
         "cn=Directory Manager,cn=Root DNs,cn=config");

    assertNull(m.getTransactionID());

    assertNull(m.getOrigin());

    assertNull(m.getUsingAdminSessionWorkerThread());

    assertNotNull(m.getRequestControlOIDs());
    assertEquals(m.getRequestControlOIDs(),
         Arrays.asList("1.2.840.113556.1.4.805", "1.3.6.1.4.1.30221.2.5.2"));

    assertNull(m.getOperationPurposeRequestControl());

    assertNotNull(m.getIntermediateClientRequestControl());

    assertNotNull(m.getDN());
    assertDNsEqual(m.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(m.getIsSubtreeDelete());
    assertTrue(m.getIsSubtreeDelete());

    assertNull(m.getDeletedAsPartOfSubtreeDelete());

    assertNull(m.getIsSoftDelete());

    assertNull(m.getSoftDeletedEntryDN());

    assertNull(m.getIsSoftDeletedEntry());

    assertNotNull(m.getDeletedEntry());
    assertEquals(m.getDeletedEntry(),
         new ReadOnlyEntry(
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People",
              "createTimestamp: 20180824200759.380Z",
              "creatorsName: cn=Directory Manager,cn=Root DNs,cn=config",
              "modifyTimestamp: 20180824200759.380Z",
              "modifiersName: cn=Directory Manager,cn=Root DNs,cn=config",
              "entryUUID: 5f06efca-2796-4d2a-9b14-a543dbd322e0"));

    assertNotNull(m.getDeletedEntryVirtualAttributes());
    assertFalse(m.getDeletedEntryVirtualAttributes().isEmpty());
    assertEquals(m.getDeletedEntryVirtualAttributes(),
         Arrays.asList(
              new Attribute("ds-entry-checksum", "419234829"),
              new Attribute("subschemaSubentry", "cn=schema")));

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.DELETE);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFDeleteChangeRecord);

    assertFalse(m.isRevertible());

    try
    {
      m.getRevertChangeRecords();
      fail("Expected an exception because a subtree delete base entry is not " +
           "revertible.");
    }
    catch (final AuditLogException e)
    {
      // This was expected.
    }

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a reversible delete audit log message that reflects
   * the deletion of the base entry for a subtree delete operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBaseOfSubtreeDeleteWithoutDeletedEntry()
         throws Exception
  {
    final DeleteAuditLogMessage m = new DeleteAuditLogMessage(
         "# 24/Aug/2018:15:07:59.457 -0500; conn=59; op=1; " +
              "productName=\"Directory Server\"; " +
              "instanceName=\"ReplicaOne\"; startupID=W4BlNw==; " +
              "threadID=13; clientIP=127.0.0.1; " +
              "requesterDN=\"cn=Proxy User,cn=Root DNs,cn=config\"; " +
              "replicationChangeID=\"000001656D8CF6C70D3F00000016\"; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"; " +
              "isSubtreeDelete=true; " +
              "requestControlOIDs=\"1.2.840.113556.1.4.805," +
              "1.3.6.1.4.1.30221.2.5.2\"; intermediateClientRequestControl={ " +
              "\"clientIdentity\":\"dn:cn=Directory Manager,cn=Root " +
              "DNs,cn=config\", \"downstreamClientAddress\":\"127.0.0.1\", " +
              "\"downstreamClientSecure\":false, " +
              "\"clientName\":\"PingDirectory\", " +
              "\"clientSessionID\":\"conn=10\", " +
              "\"clientRequestID\":\"op=7\", \"downstreamRequest\":{ " +
              "\"clientName\":\"Unidentified Directory Application\" } }",
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete");

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertTrue(m.getCommentedHeaderLine().startsWith(
         "# 24/Aug/2018:15:07:59.457 -0500; conn=59; op=1; "));

    assertNotNull(m.getUncommentedHeaderLine());
    assertTrue(m.getUncommentedHeaderLine().startsWith(
         "24/Aug/2018:15:07:59.457 -0500; conn=59; op=1; "));

    assertNotNull(m.getTimestamp());
    final Calendar calendar = new GregorianCalendar();
    calendar.setTime(m.getTimestamp());
    assertEquals(calendar.get(Calendar.YEAR), 2018);
    assertEquals(calendar.get(Calendar.MONTH), Calendar.AUGUST);

    assertNotNull(m.getHeaderNamedValues());
    assertFalse(m.getHeaderNamedValues().isEmpty());
    assertTrue(m.getHeaderNamedValues().containsKey("conn"));

    assertNotNull(m.getProductName());
    assertEquals(m.getProductName(), "Directory Server");

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "ReplicaOne");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "W4BlNw==");

    assertNotNull(m.getThreadID());
    assertEquals(m.getThreadID().longValue(), 13L);

    assertNotNull(m.getRequesterDN());
    assertDNsEqual(m.getRequesterDN(), "cn=Proxy User,cn=Root DNs,cn=config");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "127.0.0.1");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID().longValue(), 59L);

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID().longValue(), 1L);

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

    assertNotNull(m.getReplicationChangeID());
    assertEquals(m.getReplicationChangeID(), "000001656D8CF6C70D3F00000016");

    assertNotNull(m.getAlternateAuthorizationDN());
    assertDNsEqual(m.getAlternateAuthorizationDN(),
         "cn=Directory Manager,cn=Root DNs,cn=config");

    assertNull(m.getTransactionID());

    assertNull(m.getOrigin());

    assertNull(m.getUsingAdminSessionWorkerThread());

    assertNotNull(m.getRequestControlOIDs());
    assertEquals(m.getRequestControlOIDs(),
         Arrays.asList("1.2.840.113556.1.4.805", "1.3.6.1.4.1.30221.2.5.2"));

    assertNull(m.getOperationPurposeRequestControl());

    assertNotNull(m.getIntermediateClientRequestControl());

    assertNotNull(m.getDN());
    assertDNsEqual(m.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(m.getIsSubtreeDelete());
    assertTrue(m.getIsSubtreeDelete());

    assertNull(m.getDeletedAsPartOfSubtreeDelete());

    assertNull(m.getIsSoftDelete());

    assertNull(m.getSoftDeletedEntryDN());

    assertNull(m.getIsSoftDeletedEntry());

    assertNull(m.getDeletedEntry());

    assertNull(m.getDeletedEntryVirtualAttributes());

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.DELETE);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFDeleteChangeRecord);

    assertFalse(m.isRevertible());

    try
    {
      m.getRevertChangeRecords();
      fail("Expected an exception because a subtree delete base entry is not " +
           "revertible.");
    }
    catch (final AuditLogException e)
    {
      // This was expected.
    }

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a reversible delete audit log message that reflects
   * the deletion of a subordinate (non-base) entry for a subtree delete
   * operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicReversibleSubordinateOfSubtreeDelete()
         throws Exception
  {
    final DeleteAuditLogMessage m = new DeleteAuditLogMessage(
         "# --- INCREMENTAL SIGNED CONTENT ---  " +
              "signature='C007Rb525K46wqbg1dw5EwDHOxFEhi8Uiw/8pXZcxXU='",
         "# 27/Aug/2018:13:56:04.386 -0500; conn=-27; op=1195; " +
              "triggeredByConn=43; triggeredByOp=1; origin=\"internal\"; " +
              "productName=\"Directory Server\"; " +
              "instanceName=\"ReplicaOne\"; startupID=W4RIvA==; threadID=10; " +
              "clientIP=internal; requesterDN=\"cn=Directory " +
              "Manager,cn=Root DNs,cn=config\"; " +
              "replicationChangeID=\"000001657CBE331B1DD500000016\"; " +
              "deletedAsPartOfSubtreeDelete=true; " +
              "requestControlOIDs=\"2.16.840.1.113730.3.4.2\"",
         "# Deleted entry real attributes",
         "# objectClass: top",
         "# objectClass: person",
         "# objectClass: organizationalPerson",
         "# objectClass: inetOrgPerson",
         "# sn: 4",
         "# cn: User 4",
         "# givenName: User",
         "# uid: user.4",
         "# createTimestamp: 20180827185604.369Z",
         "# creatorsName: cn=Directory Manager,cn=Root DNs,cn=config",
         "# modifyTimestamp: 20180827185604.369Z",
         "# modifiersName: cn=Directory Manager,cn=Root DNs,cn=config",
         "# entryUUID: ce51184a-67a0-49ac-99a8-1b856c10d057",
         "# Deleted entry virtual attributes",
         "# ds-entry-checksum: 2457931569",
         "# subschemaSubentry: cn=schema",
         "dn: uid=user.4,ou=people,dc=example,dc=com",
         "changetype: delete");

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertTrue(m.getCommentedHeaderLine().startsWith(
         "# 27/Aug/2018:13:56:04.386 -0500; conn=-27; op=1195; "));

    assertNotNull(m.getUncommentedHeaderLine());
    assertTrue(m.getUncommentedHeaderLine().startsWith(
         "27/Aug/2018:13:56:04.386 -0500; conn=-27; op=1195; "));

    assertNotNull(m.getTimestamp());
    final Calendar calendar = new GregorianCalendar();
    calendar.setTime(m.getTimestamp());
    assertEquals(calendar.get(Calendar.YEAR), 2018);
    assertEquals(calendar.get(Calendar.MONTH), Calendar.AUGUST);

    assertNotNull(m.getHeaderNamedValues());
    assertFalse(m.getHeaderNamedValues().isEmpty());
    assertTrue(m.getHeaderNamedValues().containsKey("conn"));

    assertNotNull(m.getProductName());
    assertEquals(m.getProductName(), "Directory Server");

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "ReplicaOne");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "W4RIvA==");

    assertNotNull(m.getThreadID());
    assertEquals(m.getThreadID().longValue(), 10L);

    assertNotNull(m.getRequesterDN());
    assertDNsEqual(m.getRequesterDN(),
         "cn=Directory Manager,cn=Root DNs,cn=config");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "internal");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID().longValue(), -27L);

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID().longValue(), 1195L);

    assertNotNull(m.getTriggeredByConnectionID());
    assertEquals(m.getTriggeredByConnectionID().longValue(), 43L);

    assertNotNull(m.getTriggeredByOperationID());
    assertEquals(m.getTriggeredByOperationID().longValue(), 1L);

    assertNotNull(m.getReplicationChangeID());
    assertEquals(m.getReplicationChangeID(), "000001657CBE331B1DD500000016");

    assertNull(m.getAlternateAuthorizationDN());

    assertNull(m.getTransactionID());

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNull(m.getUsingAdminSessionWorkerThread());

    assertNotNull(m.getRequestControlOIDs());
    assertEquals(m.getRequestControlOIDs(),
         Collections.singletonList("2.16.840.1.113730.3.4.2"));

    assertNull(m.getOperationPurposeRequestControl());

    assertNull(m.getIntermediateClientRequestControl());

    assertNotNull(m.getDN());
    assertDNsEqual(m.getDN(), "uid=user.4,ou=People,dc=example,dc=com");

    assertNull(m.getIsSubtreeDelete());

    assertNotNull(m.getDeletedAsPartOfSubtreeDelete());
    assertEquals(m.getDeletedAsPartOfSubtreeDelete(), Boolean.TRUE);

    assertNull(m.getIsSoftDelete());

    assertNull(m.getSoftDeletedEntryDN());

    assertNull(m.getIsSoftDeletedEntry());

    assertNotNull(m.getDeletedEntry());
    assertEquals(m.getDeletedEntry(),
         new ReadOnlyEntry(
              "dn: uid=user.4,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "sn: 4",
              "cn: User 4",
              "givenName: User",
              "uid: user.4",
              "createTimestamp: 20180827185604.369Z",
              "creatorsName: cn=Directory Manager,cn=Root DNs,cn=config",
              "modifyTimestamp: 20180827185604.369Z",
              "modifiersName: cn=Directory Manager,cn=Root DNs,cn=config",
              "entryUUID: ce51184a-67a0-49ac-99a8-1b856c10d057"));

    assertNotNull(m.getDeletedEntryVirtualAttributes());
    assertFalse(m.getDeletedEntryVirtualAttributes().isEmpty());
    assertEquals(m.getDeletedEntryVirtualAttributes(),
         Arrays.asList(
              new Attribute("ds-entry-checksum", "2457931569"),
              new Attribute("subschemaSubentry", "cn=schema")));

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.DELETE);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFDeleteChangeRecord);

    assertTrue(m.isRevertible());

    final List<LDIFChangeRecord> revertChangeRecords =
         m.getRevertChangeRecords();
    assertNotNull(revertChangeRecords);
    assertFalse(revertChangeRecords.isEmpty());
    assertEquals(revertChangeRecords.size(), 1);
    assertTrue(revertChangeRecords.get(0) instanceof LDIFAddChangeRecord);

    final LDIFAddChangeRecord revertChangeRecord =
         (LDIFAddChangeRecord) revertChangeRecords.get(0);
    assertEquals(revertChangeRecord.getEntryToAdd(),
         m.getDeletedEntry());

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a revertible delete audit log message that reflects
   * a soft delete operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRevertibleSoftDelete()
         throws Exception
  {
    final DeleteAuditLogMessage m = new DeleteAuditLogMessage(
         "# 27/Aug/2018:13:55:32.217 -0500; conn=41; op=1; " +
              "productName=\"Directory Server\"; " +
              "instanceName=\"ReplicaOne\"; startupID=W4RIvA==; threadID=8; " +
              "clientIP=127.0.0.1; " +
              "requesterDN=\"cn=Proxy User,cn=Root DNs,cn=config\"; " +
              "replicationChangeID=\"000001657CBDB56B1DD50000000C\"; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"; " +
              "isSoftDelete=true; softDeletedEntryDN=\"entryUUID=b4004999-" +
              "f0cf-4b6b-9d9d-1b2ee06a0b38+ou=People,dc=example,dc=com\"; " +
              "requestControlOIDs=\"1.3.6.1.4.1.30221.2.5.20," +
              "1.3.6.1.4.1.30221.2.5.2\"; intermediateClientRequestControl={ " +
              "\"clientIdentity\":\"dn:cn=Directory Manager,cn=Root " +
              "DNs,cn=config\", \"downstreamClientAddress\":\"127.0.0.1\", " +
              "\"downstreamClientSecure\":false, " +
              "\"clientName\":\"PingDirectory\", " +
              "\"clientSessionID\":\"conn=9\", \"clientRequestID\":\"op=2\", " +
              "\"downstreamRequest\":{ " +
              "\"clientName\":\"Unidentified Directory Application\" } }",
         "# Deleted entry real attributes",
         "# objectClass: top",
         "# objectClass: organizationalUnit",
         "# ou: People",
         "# createTimestamp: 20180827185532.195Z",
         "# creatorsName: cn=Directory Manager,cn=Root DNs,cn=config",
         "# modifyTimestamp: 20180827185532.195Z",
         "# modifiersName: cn=Directory Manager,cn=Root DNs,cn=config",
         "# entryUUID: b4004999-f0cf-4b6b-9d9d-1b2ee06a0b38",
         "# Deleted entry virtual attributes",
         "# ds-entry-checksum: 419234829",
         "# subschemaSubentry: cn=schema",
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete");

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertTrue(m.getCommentedHeaderLine().startsWith(
         "# 27/Aug/2018:13:55:32.217 -0500; conn=41; op=1; "));

    assertNotNull(m.getUncommentedHeaderLine());
    assertTrue(m.getUncommentedHeaderLine().startsWith(
         "27/Aug/2018:13:55:32.217 -0500; conn=41; op=1; "));

    assertNotNull(m.getTimestamp());
    final Calendar calendar = new GregorianCalendar();
    calendar.setTime(m.getTimestamp());
    assertEquals(calendar.get(Calendar.YEAR), 2018);
    assertEquals(calendar.get(Calendar.MONTH), Calendar.AUGUST);

    assertNotNull(m.getHeaderNamedValues());
    assertFalse(m.getHeaderNamedValues().isEmpty());
    assertTrue(m.getHeaderNamedValues().containsKey("conn"));

    assertNotNull(m.getProductName());
    assertEquals(m.getProductName(), "Directory Server");

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "ReplicaOne");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "W4RIvA==");

    assertNotNull(m.getThreadID());
    assertEquals(m.getThreadID().longValue(), 8L);

    assertNotNull(m.getRequesterDN());
    assertDNsEqual(m.getRequesterDN(), "cn=Proxy User,cn=Root DNs,cn=config");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "127.0.0.1");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID().longValue(), 41L);

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID().longValue(), 1L);

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

    assertNotNull(m.getReplicationChangeID());
    assertEquals(m.getReplicationChangeID(), "000001657CBDB56B1DD50000000C");

    assertNotNull(m.getAlternateAuthorizationDN());
    assertDNsEqual(m.getAlternateAuthorizationDN(),
         "cn=Directory Manager,cn=Root DNs,cn=config");

    assertNull(m.getTransactionID());

    assertNull(m.getOrigin());

    assertNull(m.getUsingAdminSessionWorkerThread());

    assertNotNull(m.getRequestControlOIDs());
    assertEquals(m.getRequestControlOIDs(),
         Arrays.asList("1.3.6.1.4.1.30221.2.5.20", "1.3.6.1.4.1.30221.2.5.2"));

    assertNull(m.getOperationPurposeRequestControl());

    assertNotNull(m.getIntermediateClientRequestControl());

    assertNotNull(m.getDN());
    assertDNsEqual(m.getDN(), "ou=People,dc=example,dc=com");

    assertNull(m.getIsSubtreeDelete());

    assertNull(m.getDeletedAsPartOfSubtreeDelete());

    assertNotNull(m.getIsSoftDelete());
    assertTrue(m.getIsSoftDelete());

    assertNotNull(m.getSoftDeletedEntryDN());
    assertDNsEqual(m.getSoftDeletedEntryDN(),
         "entryUUID=b4004999-f0cf-4b6b-9d9d-1b2ee06a0b38+ou=People," +
              "dc=example,dc=com");

    assertNull(m.getIsSoftDeletedEntry());

    assertNotNull(m.getDeletedEntry());
    assertEquals(m.getDeletedEntry(),
         new ReadOnlyEntry(
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People",
              "createTimestamp: 20180827185532.195Z",
              "creatorsName: cn=Directory Manager,cn=Root DNs,cn=config",
              "modifyTimestamp: 20180827185532.195Z",
              "modifiersName: cn=Directory Manager,cn=Root DNs,cn=config",
              "entryUUID: b4004999-f0cf-4b6b-9d9d-1b2ee06a0b38"));

    assertNotNull(m.getDeletedEntryVirtualAttributes());
    assertFalse(m.getDeletedEntryVirtualAttributes().isEmpty());
    assertEquals(m.getDeletedEntryVirtualAttributes(),
         Arrays.asList(
              new Attribute("ds-entry-checksum", "419234829"),
              new Attribute("subschemaSubentry", "cn=schema")));

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.DELETE);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFDeleteChangeRecord);

    assertTrue(m.isRevertible());

    final List<LDIFChangeRecord> revertChangeRecords =
         m.getRevertChangeRecords();
    assertNotNull(revertChangeRecords);
    assertFalse(revertChangeRecords.isEmpty());
    assertEquals(revertChangeRecords.size(), 1);
    assertTrue(revertChangeRecords.get(0) instanceof LDIFAddChangeRecord);

    final LDIFAddChangeRecord revertChangeRecord =
         (LDIFAddChangeRecord) revertChangeRecords.get(0);
    assertEquals(revertChangeRecord.toLDIFString(),
         UndeleteRequestControl.createUndeleteRequest(
              "ou=People,dc=example,dc=com",
              "entryUUID=b4004999-f0cf-4b6b-9d9d-1b2ee06a0b38+ou=People," +
                   "dc=example,dc=com").toLDIFString());

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a non-revertible delete audit log message that
   * reflects a soft delete operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonRevertibleSoftDelete()
         throws Exception
  {
    final DeleteAuditLogMessage m = new DeleteAuditLogMessage(
         "# 27/Aug/2018:13:55:32.217 -0500; conn=41; op=1; " +
              "productName=\"Directory Server\"; " +
              "instanceName=\"ReplicaOne\"; startupID=W4RIvA==; threadID=8; " +
              "clientIP=127.0.0.1; " +
              "requesterDN=\"cn=Proxy User,cn=Root DNs,cn=config\"; " +
              "replicationChangeID=\"000001657CBDB56B1DD50000000C\"; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"; " +
              "isSoftDelete=true; " +
              "requestControlOIDs=\"1.3.6.1.4.1.30221.2.5.20," +
              "1.3.6.1.4.1.30221.2.5.2\"; intermediateClientRequestControl={ " +
              "\"clientIdentity\":\"dn:cn=Directory Manager,cn=Root " +
              "DNs,cn=config\", \"downstreamClientAddress\":\"127.0.0.1\", " +
              "\"downstreamClientSecure\":false, " +
              "\"clientName\":\"PingDirectory\", " +
              "\"clientSessionID\":\"conn=9\", \"clientRequestID\":\"op=2\", " +
              "\"downstreamRequest\":{ " +
              "\"clientName\":\"Unidentified Directory Application\" } }",
         "# Deleted entry real attributes",
         "# objectClass: top",
         "# objectClass: organizationalUnit",
         "# ou: People",
         "# createTimestamp: 20180827185532.195Z",
         "# creatorsName: cn=Directory Manager,cn=Root DNs,cn=config",
         "# modifyTimestamp: 20180827185532.195Z",
         "# modifiersName: cn=Directory Manager,cn=Root DNs,cn=config",
         "# entryUUID: b4004999-f0cf-4b6b-9d9d-1b2ee06a0b38",
         "# Deleted entry virtual attributes",
         "# ds-entry-checksum: 419234829",
         "# subschemaSubentry: cn=schema",
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete");

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertTrue(m.getCommentedHeaderLine().startsWith(
         "# 27/Aug/2018:13:55:32.217 -0500; conn=41; op=1; "));

    assertNotNull(m.getUncommentedHeaderLine());
    assertTrue(m.getUncommentedHeaderLine().startsWith(
         "27/Aug/2018:13:55:32.217 -0500; conn=41; op=1; "));

    assertNotNull(m.getTimestamp());
    final Calendar calendar = new GregorianCalendar();
    calendar.setTime(m.getTimestamp());
    assertEquals(calendar.get(Calendar.YEAR), 2018);
    assertEquals(calendar.get(Calendar.MONTH), Calendar.AUGUST);

    assertNotNull(m.getHeaderNamedValues());
    assertFalse(m.getHeaderNamedValues().isEmpty());
    assertTrue(m.getHeaderNamedValues().containsKey("conn"));

    assertNotNull(m.getProductName());
    assertEquals(m.getProductName(), "Directory Server");

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "ReplicaOne");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "W4RIvA==");

    assertNotNull(m.getThreadID());
    assertEquals(m.getThreadID().longValue(), 8L);

    assertNotNull(m.getRequesterDN());
    assertDNsEqual(m.getRequesterDN(), "cn=Proxy User,cn=Root DNs,cn=config");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "127.0.0.1");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID().longValue(), 41);

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID().longValue(), 1L);

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

    assertNotNull(m.getReplicationChangeID());
    assertEquals(m.getReplicationChangeID(), "000001657CBDB56B1DD50000000C");

    assertNotNull(m.getAlternateAuthorizationDN());
    assertDNsEqual(m.getAlternateAuthorizationDN(),
         "cn=Directory Manager,cn=Root DNs,cn=config");

    assertNull(m.getTransactionID());

    assertNull(m.getOrigin());

    assertNull(m.getUsingAdminSessionWorkerThread());

    assertNotNull(m.getRequestControlOIDs());
    assertEquals(m.getRequestControlOIDs(),
         Arrays.asList("1.3.6.1.4.1.30221.2.5.20", "1.3.6.1.4.1.30221.2.5.2"));

    assertNull(m.getOperationPurposeRequestControl());

    assertNotNull(m.getIntermediateClientRequestControl());

    assertNotNull(m.getDN());
    assertDNsEqual(m.getDN(), "ou=People,dc=example,dc=com");

    assertNull(m.getIsSubtreeDelete());

    assertNull(m.getDeletedAsPartOfSubtreeDelete());

    assertNotNull(m.getIsSoftDelete());
    assertTrue(m.getIsSoftDelete());

    assertNull(m.getSoftDeletedEntryDN());

    assertNull(m.getIsSoftDeletedEntry());

    assertNotNull(m.getDeletedEntry());
    assertEquals(m.getDeletedEntry(),
         new ReadOnlyEntry(
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People",
              "createTimestamp: 20180827185532.195Z",
              "creatorsName: cn=Directory Manager,cn=Root DNs,cn=config",
              "modifyTimestamp: 20180827185532.195Z",
              "modifiersName: cn=Directory Manager,cn=Root DNs,cn=config",
              "entryUUID: b4004999-f0cf-4b6b-9d9d-1b2ee06a0b38"));

    assertNotNull(m.getDeletedEntryVirtualAttributes());
    assertFalse(m.getDeletedEntryVirtualAttributes().isEmpty());
    assertEquals(m.getDeletedEntryVirtualAttributes(),
         Arrays.asList(
              new Attribute("ds-entry-checksum", "419234829"),
              new Attribute("subschemaSubentry", "cn=schema")));

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.DELETE);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFDeleteChangeRecord);

    assertFalse(m.isRevertible());

    try
    {
      m.getRevertChangeRecords();
      fail("Expected an exception when trying to revert a non-revertible " +
           "soft delete audit log message");
    }
    catch (final AuditLogException e)
    {
      // This was expected.
    }

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a hard delete of a soft-deleted entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHardDeleteOfSoftDeletedEntry()
         throws Exception
  {
    final DeleteAuditLogMessage m = new DeleteAuditLogMessage(
         "# 27/Aug/2018:15:09:11.624 -0500; conn=58; op=1; " +
              "productName=\"Directory Server\"; " +
              "instanceName=\"ReplicaOne\"; startupID=W4RZ/w==; " +
              "threadID=14; clientIP=127.0.0.1; " +
              "requesterDN=\"cn=Proxy User,cn=Root DNs,cn=config\"; " +
              "replicationChangeID=\"000001657D0124C47A0D0000000F\"; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"; " +
              "isSoftDeletedEntry=true; " +
              "requestControlOIDs=\"1.3.6.1.4.1.30221.2.5.2\"; " +
              "intermediateClientRequestControl={ " +
              "\"clientIdentity\":\"dn:cn=Directory Manager,cn=Root " +
              "DNs,cn=config\", \"downstreamClientAddress\":\"127.0.0.1\", " +
              "\"downstreamClientSecure\":false, " +
              "\"clientName\":\"PingDirectory\", " +
              "\"clientSessionID\":\"conn=9\", \"clientRequestID\":\"op=5\", " +
              "\"downstreamRequest\":{ " +
              "\"clientName\":\"Unidentified Directory Application\" } }",
         "# Deleted entry real attributes",
         "# objectClass: top",
         "# objectClass: organizationalUnit",
         "# objectClass: ds-soft-delete-entry",
         "# ou: People",
         "# createTimestamp: 20180827200911.586Z",
         "# creatorsName: cn=Directory Manager,cn=Root DNs,cn=config",
         "# modifyTimestamp: 20180827200911.586Z",
         "# modifiersName: cn=Directory Manager,cn=Root DNs,cn=config",
         "# entryUUID: f7e0fa1e-03e5-4a81-9b2f-f909b6531a80",
         "# ds-soft-delete-from-dn: ou=People,dc=example,dc=com",
         "# ds-soft-delete-timestamp: 20180827200911.614Z",
         "# Deleted entry virtual attributes",
         "# ds-entry-checksum: 419234829",
         "# subschemaSubentry: cn=schema",
         "dn: entryUUID=f7e0fa1e-03e5-4a81-9b2f-f909b6531a80+ou=People," +
              "dc=example,dc=com",
         "changetype: delete");

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertTrue(m.getCommentedHeaderLine().startsWith(
         "# 27/Aug/2018:15:09:11.624 -0500; conn=58; op=1; "));

    assertNotNull(m.getUncommentedHeaderLine());
    assertTrue(m.getUncommentedHeaderLine().startsWith(
         "27/Aug/2018:15:09:11.624 -0500; conn=58; op=1; "));

    assertNotNull(m.getTimestamp());
    final Calendar calendar = new GregorianCalendar();
    calendar.setTime(m.getTimestamp());
    assertEquals(calendar.get(Calendar.YEAR), 2018);
    assertEquals(calendar.get(Calendar.MONTH), Calendar.AUGUST);

    assertNotNull(m.getHeaderNamedValues());
    assertFalse(m.getHeaderNamedValues().isEmpty());
    assertTrue(m.getHeaderNamedValues().containsKey("conn"));

    assertNotNull(m.getProductName());
    assertEquals(m.getProductName(), "Directory Server");

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "ReplicaOne");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "W4RZ/w==");

    assertNotNull(m.getThreadID());
    assertEquals(m.getThreadID().longValue(), 14L);

    assertNotNull(m.getRequesterDN());
    assertDNsEqual(m.getRequesterDN(), "cn=Proxy User,cn=Root DNs,cn=config");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "127.0.0.1");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID().longValue(), 58L);

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID().longValue(), 1L);

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

    assertNotNull(m.getReplicationChangeID());
    assertEquals(m.getReplicationChangeID(), "000001657D0124C47A0D0000000F");

    assertNotNull(m.getAlternateAuthorizationDN());
    assertDNsEqual(m.getAlternateAuthorizationDN(),
         "cn=Directory Manager,cn=Root DNs,cn=config");

    assertNull(m.getTransactionID());

    assertNull(m.getOrigin());

    assertNull(m.getUsingAdminSessionWorkerThread());

    assertNotNull(m.getRequestControlOIDs());
    assertEquals(m.getRequestControlOIDs(),
         Collections.singletonList("1.3.6.1.4.1.30221.2.5.2"));

    assertNull(m.getOperationPurposeRequestControl());

    assertNotNull(m.getIntermediateClientRequestControl());

    assertNotNull(m.getDN());
    assertDNsEqual(m.getDN(),
         "entryUUID=f7e0fa1e-03e5-4a81-9b2f-f909b6531a80+ou=People," +
              "dc=example,dc=com");

    assertNull(m.getIsSubtreeDelete());

    assertNull(m.getDeletedAsPartOfSubtreeDelete());

    assertNull(m.getIsSoftDelete());

    assertNull(m.getSoftDeletedEntryDN());

    assertNotNull(m.getIsSoftDeletedEntry());
    assertTrue(m.getIsSoftDeletedEntry());

    assertNotNull(m.getDeletedEntry());
    assertEquals(m.getDeletedEntry(),
         new ReadOnlyEntry(
              "dn: entryUUID=f7e0fa1e-03e5-4a81-9b2f-f909b6531a80+ou=People," +
                   "dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "objectClass: ds-soft-delete-entry",
              "ou: People",
              "createTimestamp: 20180827200911.586Z",
              "creatorsName: cn=Directory Manager,cn=Root DNs,cn=config",
              "modifyTimestamp: 20180827200911.586Z",
              "modifiersName: cn=Directory Manager,cn=Root DNs,cn=config",
              "entryUUID: f7e0fa1e-03e5-4a81-9b2f-f909b6531a80",
              "ds-soft-delete-from-dn: ou=People,dc=example,dc=com",
              "ds-soft-delete-timestamp: 20180827200911.614Z"));

    assertNotNull(m.getDeletedEntryVirtualAttributes());
    assertFalse(m.getDeletedEntryVirtualAttributes().isEmpty());
    assertEquals(m.getDeletedEntryVirtualAttributes(),
         Arrays.asList(
              new Attribute("ds-entry-checksum", "419234829"),
              new Attribute("subschemaSubentry", "cn=schema")));

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.DELETE);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFDeleteChangeRecord);

    assertTrue(m.isRevertible());

    final List<LDIFChangeRecord> revertChangeRecords =
         m.getRevertChangeRecords();
    assertNotNull(revertChangeRecords);
    assertFalse(revertChangeRecords.isEmpty());
    assertEquals(revertChangeRecords.size(), 1);
    assertTrue(revertChangeRecords.get(0) instanceof LDIFAddChangeRecord);

    final LDIFAddChangeRecord revertChangeRecord =
         (LDIFAddChangeRecord) revertChangeRecords.get(0);
    assertEquals(revertChangeRecord.getEntryToAdd(),
         m.getDeletedEntry());

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a non-revertible delete audit log message created
   * from a string list and a change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteNonRevertibleLogMessageFromListAndChangeRecord()
         throws Exception
  {
    final DeleteAuditLogMessage m = new DeleteAuditLogMessage(
         Arrays.asList(
              "# 24/Aug/2018:12:11:50 -0500; conn=33; op=1; " +
                   "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"",
              "dn: ou=People,dc=example,dc=com",
              "changetype: delete"),
         new LDIFDeleteChangeRecord("ou=People,dc=example,dc=com"));

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertEquals(m.getCommentedHeaderLine(),
         "# 24/Aug/2018:12:11:50 -0500; conn=33; op=1; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"");

    assertNotNull(m.getUncommentedHeaderLine());
    assertEquals(m.getUncommentedHeaderLine(),
         "24/Aug/2018:12:11:50 -0500; conn=33; op=1; " +
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
    assertEquals(m.getConnectionID().longValue(), 33L);

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

    assertNull(m.getIsSubtreeDelete());

    assertNull(m.getDeletedAsPartOfSubtreeDelete());

    assertNull(m.getIsSoftDelete());

    assertNull(m.getSoftDeletedEntryDN());

    assertNull(m.getIsSoftDeletedEntry());

    assertNull(m.getDeletedEntry());

    assertNull(m.getDeletedEntryVirtualAttributes());

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.DELETE);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFDeleteChangeRecord);

    assertFalse(m.isRevertible());

    try
    {
      m.getRevertChangeRecords();
      fail("Expected an exception when trying to revert a non-revertible " +
           "delete audit log message");
    }
    catch (final AuditLogException e)
    {
      // This was expected.
    }

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a revertible delete audit log message created from a
   * string list and a change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteRevertibleLogMessageFromListAndChangeRecord()
         throws Exception
  {
    final DeleteAuditLogMessage m = new DeleteAuditLogMessage(
         Arrays.asList(
              "# 24/Aug/2018:12:11:50 -0500; conn=33; op=1; " +
                   "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"",
              "# Deleted entry real attributes",
              "# objectClass: top",
              "# objectClass: organizationalUnit",
              "# ou: People",
              "# createTimestamp: 20180827185604.369Z",
              "# creatorsName: cn=Directory Manager,cn=Root DNs,cn=config",
              "# modifyTimestamp: 20180827185604.369Z",
              "# modifiersName: cn=Directory Manager,cn=Root DNs,cn=config",
              "# entryUUID: ce51184a-67a0-49ac-99a8-1b856c10d057",
              "# Deleted entry virtual attributes",
              "# ds-entry-checksum: 2457931569",
              "# subschemaSubentry: cn=schema",
              "dn: ou=People,dc=example,dc=com",
              "changetype: delete"),
         new LDIFDeleteChangeRecord("ou=People,dc=example,dc=com"));

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertEquals(m.getCommentedHeaderLine(),
         "# 24/Aug/2018:12:11:50 -0500; conn=33; op=1; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"");

    assertNotNull(m.getUncommentedHeaderLine());
    assertEquals(m.getUncommentedHeaderLine(),
         "24/Aug/2018:12:11:50 -0500; conn=33; op=1; " +
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
    assertEquals(m.getConnectionID().longValue(), 33L);

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

    assertNull(m.getIsSubtreeDelete());

    assertNull(m.getDeletedAsPartOfSubtreeDelete());

    assertNull(m.getIsSoftDelete());

    assertNull(m.getSoftDeletedEntryDN());

    assertNull(m.getIsSoftDeletedEntry());

    assertNotNull(m.getDeletedEntry());
    assertEquals(m.getDeletedEntry(),
         new ReadOnlyEntry(
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People",
              "createTimestamp: 20180827185604.369Z",
              "creatorsName: cn=Directory Manager,cn=Root DNs,cn=config",
              "modifyTimestamp: 20180827185604.369Z",
              "modifiersName: cn=Directory Manager,cn=Root DNs,cn=config",
              "entryUUID: ce51184a-67a0-49ac-99a8-1b856c10d057"));

    assertNotNull(m.getDeletedEntryVirtualAttributes());
    assertEquals(m.getDeletedEntryVirtualAttributes(),
         Arrays.asList(
              new Attribute("ds-entry-checksum", "2457931569"),
              new Attribute("subschemaSubentry", "cn=schema")));

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.DELETE);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFDeleteChangeRecord);

    assertTrue(m.isRevertible());

    final List<LDIFChangeRecord> revertChangeRecords =
         m.getRevertChangeRecords();
    assertNotNull(revertChangeRecords);
    assertFalse(revertChangeRecords.isEmpty());
    assertEquals(revertChangeRecords.size(), 1);
    assertTrue(revertChangeRecords.get(0) instanceof LDIFAddChangeRecord);

    final LDIFAddChangeRecord revertChangeRecord =
         (LDIFAddChangeRecord) revertChangeRecords.get(0);
    assertEquals(revertChangeRecord.getEntryToAdd(),
         m.getDeletedEntry());

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior when trying to create a delete audit log message from
   * a set of lines that comprise a valid change record but not a delete change
   * record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testCreateFromMessageWithNonDeleteChangeType()
         throws Exception
  {

    new DeleteAuditLogMessage(
         "# 24/Aug/2018:12:11:50 -0500; conn=33; op=1; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"",
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");
  }



  /**
   * Tests the behavior when trying to create a delete audit log message from
   * a set of lines that do not comprise a valid LDIF change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testCreateFromMessageWithInvalidChangeRecordLines()
         throws Exception
  {

    new DeleteAuditLogMessage(
         "# 24/Aug/2018:12:11:50 -0500; conn=33; op=1; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"",
         "not a valid change record");
  }
}
