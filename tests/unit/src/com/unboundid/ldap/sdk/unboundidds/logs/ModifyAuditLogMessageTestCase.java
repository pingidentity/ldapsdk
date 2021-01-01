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
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFChangeRecord;



/**
 * This class provides a set of test cases for modify audit log messages.
 */
public final class ModifyAuditLogMessageTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a revertible modify audit log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRevertibleModifyAuditLogMessage()
         throws Exception
  {
    final ModifyAuditLogMessage m = new ModifyAuditLogMessage(
         "# 27/Aug/2018:15:09:11.476 -0500; conn=18; op=1; " +
              "productName=\"Directory Server\"; " +
              "instanceName=\"ReplicaOne\"; startupID=W4RZ/w==; threadID=7; " +
              "clientIP=127.0.0.1; " +
              "requesterDN=\"cn=Proxy User,cn=Root DNs,cn=config\"; " +
              "replicationChangeID=\"000001657D01242C7A0D00000004\"; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"; " +
              "requestControlOIDs=\"1.3.6.1.4.1.30221.2.5.2\"; " +
              "intermediateClientRequestControl={ " +
              "\"clientIdentity\":\"dn:cn=Directory Manager,cn=Root " +
              "DNs,cn=config\", \"downstreamClientAddress\":\"127.0.0.1\", " +
              "\"downstreamClientSecure\":false, " +
              "\"clientName\":\"PingDirectory\", " +
              "\"clientSessionID\":\"conn=8\", \"clientRequestID\":\"op=4\", " +
              "\"downstreamRequest\":{ " +
              "\"clientName\":\"Unidentified Directory Application\" } }",
         "dn: uid=jdoe,ou=People,dc=example,dc=com",
         "changetype: modify",
         "delete: displayName",
         "displayName: Johnny Doe",
         "-",
         "add: givenName",
         "givenName: Jonathan",
         "-",
         "delete: description",
         "description: Initial description",
         "-",
         "add: description",
         "description: Replaced description",
         "-",
         "increment: intAttr1",
         "intAttr1: 123",
         "-",
         "increment: intAttr2",
         "intAttr2: -456",
         "-",
         "delete: modifyTimestamp",
         "modifyTimestamp: 20180827200911.455Z",
         "-",
         "add: modifyTimestamp",
         "modifyTimestamp: 20180827200911.470Z");

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertTrue(m.getCommentedHeaderLine().startsWith(
         "# 27/Aug/2018:15:09:11.476 -0500; conn=18; op=1; "));

    assertNotNull(m.getUncommentedHeaderLine());
    assertTrue(m.getUncommentedHeaderLine().startsWith(
         "27/Aug/2018:15:09:11.476 -0500; conn=18; op=1; "));

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
    assertEquals(m.getThreadID().longValue(), 7L);

    assertNotNull(m.getRequesterDN());
    assertDNsEqual(m.getRequesterDN(), "cn=Proxy User,cn=Root DNs,cn=config");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "127.0.0.1");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID().longValue(), 18L);

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID().longValue(), 1L);

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

    assertNotNull(m.getReplicationChangeID());
    assertEquals(m.getReplicationChangeID(), "000001657D01242C7A0D00000004");

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
    assertDNsEqual(m.getDN(), "uid=jdoe,ou=People,dc=example,dc=com");

    assertNotNull(m.getModifications());
    assertFalse(m.getModifications().isEmpty());
    assertEquals(m.getModifications(),
         Arrays.asList(
              new Modification(ModificationType.DELETE, "displayName",
                   "Johnny Doe"),
              new Modification(ModificationType.ADD, "givenName", "Jonathan"),
              new Modification(ModificationType.DELETE, "description",
                   "Initial description"),
              new Modification(ModificationType.ADD, "description",
                   "Replaced description"),
              new Modification(ModificationType.INCREMENT, "intAttr1",
                   "123"),
              new Modification(ModificationType.INCREMENT, "intAttr2",
                   "-456"),
              new Modification(ModificationType.DELETE, "modifyTimestamp",
                   "20180827200911.455Z"),
              new Modification(ModificationType.ADD, "modifyTimestamp",
                   "20180827200911.470Z")));

    assertNull(m.getIsSoftDeletedEntry());

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.MODIFY);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFModifyChangeRecord);

    assertTrue(m.isRevertible());

    final List<LDIFChangeRecord> revertChangeRecords =
         m.getRevertChangeRecords();
    assertNotNull(revertChangeRecords);
    assertFalse(revertChangeRecords.isEmpty());
    assertEquals(revertChangeRecords.size(), 1);
    assertTrue(revertChangeRecords.get(0) instanceof LDIFModifyChangeRecord);

    final LDIFModifyChangeRecord revertChangeRecord =
         (LDIFModifyChangeRecord) revertChangeRecords.get(0);
    assertEquals(revertChangeRecord.getModifications(),
         new Modification[]
         {
           new Modification(ModificationType.DELETE, "modifyTimestamp",
                "20180827200911.470Z"),
           new Modification(ModificationType.ADD, "modifyTimestamp",
                "20180827200911.455Z"),
           new Modification(ModificationType.INCREMENT, "intAttr2", "456"),
           new Modification(ModificationType.INCREMENT, "intAttr1", "-123"),
           new Modification(ModificationType.DELETE, "description",
                "Replaced description"),
           new Modification(ModificationType.ADD, "description",
                "Initial description"),
           new Modification(ModificationType.DELETE, "givenName", "Jonathan"),
           new Modification(ModificationType.ADD, "displayName", "Johnny Doe")
         });

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a modify audit log message that is not revertible
   * because it includes a replace modification.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonRevertibleBecauseOfReplaceModifyAuditLogMessage()
         throws Exception
  {
    final ModifyAuditLogMessage m = new ModifyAuditLogMessage(Arrays.asList(
         "# 27/Aug/2018:15:09:11.476 -0500; conn=18; op=1; " +
              "productName=\"Directory Server\"; " +
              "instanceName=\"ReplicaOne\"; startupID=W4RZ/w==; threadID=7; " +
              "clientIP=127.0.0.1; " +
              "requesterDN=\"cn=Proxy User,cn=Root DNs,cn=config\"; " +
              "replicationChangeID=\"000001657D01242C7A0D00000004\"; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"; " +
              "requestControlOIDs=\"1.3.6.1.4.1.30221.2.5.2\"; " +
              "intermediateClientRequestControl={ " +
              "\"clientIdentity\":\"dn:cn=Directory Manager,cn=Root " +
              "DNs,cn=config\", \"downstreamClientAddress\":\"127.0.0.1\", " +
              "\"downstreamClientSecure\":false, " +
              "\"clientName\":\"PingDirectory\", " +
              "\"clientSessionID\":\"conn=8\", \"clientRequestID\":\"op=4\", " +
              "\"downstreamRequest\":{ " +
              "\"clientName\":\"Unidentified Directory Application\" } }",
         "dn: uid=jdoe,ou=People,dc=example,dc=com",
         "changetype: modify",
         "add: givenName",
         "givenName: Jonathan",
         "-",
         "replace: description",
         "description: Replaced description",
         "-",
         "replace: modifyTimestamp",
         "modifyTimestamp: 20180827200911.470Z"));

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertTrue(m.getCommentedHeaderLine().startsWith(
         "# 27/Aug/2018:15:09:11.476 -0500; conn=18; op=1; "));

    assertNotNull(m.getUncommentedHeaderLine());
    assertTrue(m.getUncommentedHeaderLine().startsWith(
         "27/Aug/2018:15:09:11.476 -0500; conn=18; op=1; "));

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
    assertEquals(m.getThreadID().longValue(), 7L);

    assertNotNull(m.getRequesterDN());
    assertDNsEqual(m.getRequesterDN(), "cn=Proxy User,cn=Root DNs,cn=config");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "127.0.0.1");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID().longValue(), 18L);

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID().longValue(), 1L);

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

    assertNotNull(m.getReplicationChangeID());
    assertEquals(m.getReplicationChangeID(), "000001657D01242C7A0D00000004");

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
    assertDNsEqual(m.getDN(), "uid=jdoe,ou=People,dc=example,dc=com");

    assertNotNull(m.getModifications());
    assertFalse(m.getModifications().isEmpty());
    assertEquals(m.getModifications(),
         Arrays.asList(
              new Modification(ModificationType.ADD, "givenName", "Jonathan"),
              new Modification(ModificationType.REPLACE, "description",
                   "Replaced description"),
              new Modification(ModificationType.REPLACE, "modifyTimestamp",
                   "20180827200911.470Z")));

    assertNull(m.getIsSoftDeletedEntry());

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.MODIFY);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFModifyChangeRecord);

    assertFalse(m.isRevertible());

    try
    {
      m.getRevertChangeRecords();
      fail("Expected an exception when trying to revert a non-revertible " +
           "modify audit log message");
    }
    catch (final AuditLogException e)
    {
      // This was expected.
    }

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a modify audit log message that is not revertible
   * because it includes a delete modification that doesn't have any values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonRevertibleBecauseOfNoValueDeleteModifyAuditLogMessage()
         throws Exception
  {
    final ModifyAuditLogMessage m = new ModifyAuditLogMessage(Arrays.asList(
         "# 27/Aug/2018:15:09:11.476 -0500; conn=18; op=1; " +
              "productName=\"Directory Server\"; " +
              "instanceName=\"ReplicaOne\"; startupID=W4RZ/w==; threadID=7; " +
              "clientIP=127.0.0.1; " +
              "requesterDN=\"cn=Proxy User,cn=Root DNs,cn=config\"; " +
              "replicationChangeID=\"000001657D01242C7A0D00000004\"; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"; " +
              "requestControlOIDs=\"1.3.6.1.4.1.30221.2.5.2\"; " +
              "intermediateClientRequestControl={ " +
              "\"clientIdentity\":\"dn:cn=Directory Manager,cn=Root " +
              "DNs,cn=config\", \"downstreamClientAddress\":\"127.0.0.1\", " +
              "\"downstreamClientSecure\":false, " +
              "\"clientName\":\"PingDirectory\", " +
              "\"clientSessionID\":\"conn=8\", \"clientRequestID\":\"op=4\", " +
              "\"downstreamRequest\":{ " +
              "\"clientName\":\"Unidentified Directory Application\" } }",
         "dn: uid=jdoe,ou=People,dc=example,dc=com",
         "changetype: modify",
         "delete: displayName",
         "-",
         "add: givenName",
         "givenName: Jonathan",
         "-",
         "replace: description",
         "description: Replaced description",
         "-",
         "replace: modifyTimestamp",
         "modifyTimestamp: 20180827200911.470Z"));

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertTrue(m.getCommentedHeaderLine().startsWith(
         "# 27/Aug/2018:15:09:11.476 -0500; conn=18; op=1; "));

    assertNotNull(m.getUncommentedHeaderLine());
    assertTrue(m.getUncommentedHeaderLine().startsWith(
         "27/Aug/2018:15:09:11.476 -0500; conn=18; op=1; "));

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
    assertEquals(m.getThreadID().longValue(), 7L);

    assertNotNull(m.getRequesterDN());
    assertDNsEqual(m.getRequesterDN(), "cn=Proxy User,cn=Root DNs,cn=config");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "127.0.0.1");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID().longValue(), 18L);

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID().longValue(), 1L);

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

    assertNotNull(m.getReplicationChangeID());
    assertEquals(m.getReplicationChangeID(), "000001657D01242C7A0D00000004");

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
    assertDNsEqual(m.getDN(), "uid=jdoe,ou=People,dc=example,dc=com");

    assertNotNull(m.getModifications());
    assertFalse(m.getModifications().isEmpty());
    assertEquals(m.getModifications(),
         Arrays.asList(
              new Modification(ModificationType.DELETE, "displayName"),
              new Modification(ModificationType.ADD, "givenName", "Jonathan"),
              new Modification(ModificationType.REPLACE, "description",
                   "Replaced description"),
              new Modification(ModificationType.REPLACE, "modifyTimestamp",
                   "20180827200911.470Z")));

    assertNull(m.getIsSoftDeletedEntry());

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.MODIFY);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFModifyChangeRecord);

    assertFalse(m.isRevertible());

    try
    {
      m.getRevertChangeRecords();
      fail("Expected an exception when trying to revert a non-revertible " +
           "modify audit log message");
    }
    catch (final AuditLogException e)
    {
      // This was expected.
    }

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a revertible modify of a soft-deleted entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRevertibleModifyOfSoftDeletedEntry()
         throws Exception
  {
    final ModifyAuditLogMessage m = new ModifyAuditLogMessage(
         "# 27/Aug/2018:16:33:47.160 -0500; conn=38; op=1; " +
              "productName=\"Directory Server\"; " +
              "instanceName=\"ReplicaOne\"; startupID=W4Rt1g==; threadID=10; " +
              "clientIP=127.0.0.1; " +
              "requesterDN=\"cn=Proxy User,cn=Root DNs,cn=config\"; " +
              "replicationChangeID=\"000001657D4E9715214B0000000F\"; " +
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
         "dn: entryUUID=2e51e2ab-2a4f-4f55-b4bb-2b9bef1b1f8f+ou=People," +
              "dc=example,dc=com",
         "changetype: modify",
         "add: description",
         "description: foo",
         "-",
         "delete: modifyTimestamp",
         "modifyTimestamp: 20180827213347.110Z",
         "-",
         "add: modifyTimestamp",
         "modifyTimestamp: 20180827213347.157Z");

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertTrue(m.getCommentedHeaderLine().startsWith(
         "# 27/Aug/2018:16:33:47.160 -0500; conn=38; op=1; "));

    assertNotNull(m.getUncommentedHeaderLine());
    assertTrue(m.getUncommentedHeaderLine().startsWith(
         "27/Aug/2018:16:33:47.160 -0500; conn=38; op=1; "));

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
    assertEquals(m.getStartupID(), "W4Rt1g==");

    assertNotNull(m.getThreadID());
    assertEquals(m.getThreadID().longValue(), 10L);

    assertNotNull(m.getRequesterDN());
    assertDNsEqual(m.getRequesterDN(), "cn=Proxy User,cn=Root DNs,cn=config");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "127.0.0.1");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID().longValue(), 38L);

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID().longValue(), 1L);

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

    assertNotNull(m.getReplicationChangeID());
    assertEquals(m.getReplicationChangeID(), "000001657D4E9715214B0000000F");

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
         "entryUUID=2e51e2ab-2a4f-4f55-b4bb-2b9bef1b1f8f+ou=People," +
              "dc=example,dc=com");

    assertNotNull(m.getModifications());
    assertFalse(m.getModifications().isEmpty());
    assertEquals(m.getModifications(),
         Arrays.asList(
              new Modification(ModificationType.ADD, "description", "foo"),
              new Modification(ModificationType.DELETE, "modifyTimestamp",
                   "20180827213347.110Z"),
              new Modification(ModificationType.ADD, "modifyTimestamp",
                   "20180827213347.157Z")));

    assertNotNull(m.getIsSoftDeletedEntry());
    assertTrue(m.getIsSoftDeletedEntry());

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.MODIFY);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFModifyChangeRecord);

    assertTrue(m.isRevertible());

    final List<LDIFChangeRecord> revertChangeRecords =
         m.getRevertChangeRecords();
    assertNotNull(revertChangeRecords);
    assertFalse(revertChangeRecords.isEmpty());
    assertEquals(revertChangeRecords.size(), 1);
    assertTrue(revertChangeRecords.get(0) instanceof LDIFModifyChangeRecord);

    final LDIFModifyChangeRecord revertChangeRecord =
         (LDIFModifyChangeRecord) revertChangeRecords.get(0);
    assertEquals(revertChangeRecord.getModifications(),
         new Modification[]
         {
           new Modification(ModificationType.DELETE, "modifyTimestamp",
                "20180827213347.157Z"),
           new Modification(ModificationType.ADD, "modifyTimestamp",
                "20180827213347.110Z"),
           new Modification(ModificationType.DELETE, "description", "foo")
         });

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a non-revertible modify audit log message with a
   * minimal set of content.  The message will be created from a list of lines
   * and a change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonRevertibleMessageWithLinesAndChangeRecord()
         throws Exception
  {
    final ModifyAuditLogMessage m = new ModifyAuditLogMessage(
         Arrays.asList(
              "# 27/Aug/2018:15:09:11.476 -0500; conn=18; op=1",
              "dn: uid=jdoe,ou=People,dc=example,dc=com",
              "changetype: modify",
              "delete: displayName"),
         new LDIFModifyChangeRecord(new ModifyRequest(
              "dn: uid=jdoe,ou=People,dc=example,dc=com",
              "changetype: modify",
              "delete: displayName")));

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertEquals(m.getCommentedHeaderLine(),
         "# 27/Aug/2018:15:09:11.476 -0500; conn=18; op=1");

    assertNotNull(m.getUncommentedHeaderLine());
    assertEquals(m.getUncommentedHeaderLine(),
         "27/Aug/2018:15:09:11.476 -0500; conn=18; op=1");

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
    assertEquals(m.getConnectionID().longValue(), 18L);

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID().longValue(), 1L);

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

    assertNotNull(m.getDN());
    assertDNsEqual(m.getDN(), "uid=jdoe,ou=People,dc=example,dc=com");

    assertNotNull(m.getModifications());
    assertFalse(m.getModifications().isEmpty());
    assertEquals(m.getModifications(),
         Collections.singletonList(
              new Modification(ModificationType.DELETE, "displayName")));

    assertNull(m.getIsSoftDeletedEntry());

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.MODIFY);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFModifyChangeRecord);

    assertFalse(m.isRevertible());

    try
    {
      m.getRevertChangeRecords();
      fail("Expected an exception when trying to revert a non-revertible " +
           "modify audit log message");
    }
    catch (final AuditLogException e)
    {
      // This was expected.
    }

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior when trying to create a modify audit log message from
   * a set of lines that comprise a valid change record but not a modify change
   * record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testCreateFromMessageWithNonModifyChangeType()
         throws Exception
  {

    new ModifyAuditLogMessage(
         "# 24/Aug/2018:12:11:50 -0500; conn=33; op=1; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"",
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");
  }



  /**
   * Tests the behavior when trying to create a modify audit log message from
   * a set of lines that do not comprise a valid LDIF change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testCreateFromMessageWithInvalidChangeRecordLines()
         throws Exception
  {

    new ModifyAuditLogMessage(
         "# 24/Aug/2018:12:11:50 -0500; conn=33; op=1; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"",
         "not a valid change record");
  }
}
