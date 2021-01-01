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



import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.List;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFModifyDNChangeRecord;



/**
 * This class provides a set of test cases for the audit log reader.
 */
public final class AuditLogReaderTestCase
       extends LDAPSDKTestCase
{
  // A file to use for testing.
  private File testBasicAuditLogFile = null;



  /**
   * Creates a sample log file to use for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    testBasicAuditLogFile = createTempFile(
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
         "entryUUID: b58849bd-2032-4077-ba10-2cd9be8166e0",
         "",
         "",
         "# 24/Aug/2018:12:11:50 -0500; conn=33; op=1; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"",
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete",
         "",
         "# This is just a comment",
         "",
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
         "modifyTimestamp: 20180827200911.470Z",
         "",
         "# 27/Aug/2018:16:33:47.019 -0500; conn=31; op=1; " +
              "productName=\"Directory Server\"; " +
              "instanceName=\"ReplicaOne\"; startupID=W4Rt1g==; threadID=8; " +
              "clientIP=127.0.0.1; " +
              "requesterDN=\"cn=Proxy User,cn=Root DNs,cn=config\"; " +
              "replicationChangeID=\"000001657D4E9677214B00000005\"; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"; " +
              "requestControlOIDs=\"1.3.6.1.4.1.30221.2.5.2\"; " +
              "intermediateClientRequestControl={ " +
              "\"clientIdentity\":\"dn:cn=Directory Manager,cn=Root " +
              "DNs,cn=config\", \"downstreamClientAddress\":\"127.0.0.1\", " +
              "\"downstreamClientSecure\":false, " +
              "\"clientName\":\"PingDirectory\", " +
              "\"clientSessionID\":\"conn=8\", \"clientRequestID\":\"op=5\", " +
              "\"downstreamRequest\":{ " +
              "\"clientName\":\"Unidentified Directory Application\" } }",
         "# ModifyDN attribute modifications (count=2)",
         "# delete: uid",
         "# uid: jdoe",
         "# -",
         "# add: uid",
         "# uid: john.doe",
         "dn: uid=jdoe,ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newrdn: uid=john.doe",
         "deleteoldrdn: 1",
         "",
         "# 27/Aug/2018:16:33:47.019 -0500; conn=31; op=2",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: unrecognized");

  }



  /**
   * Tests the behavior when trying to read the basic audit log file.
   *
   * @param  reader  The reader to use for testing.
   * @param  origin  The origin of the provided reader.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "basicAuditLogReaders")
  public void testBasicAuditLogFile(final AuditLogReader reader,
                                    final String origin)
         throws Exception
  {
    AuditLogMessage m = reader.read();
    assertNotNull(m);
    assertTrue(m instanceof AddAuditLogMessage);

    final AddAuditLogMessage addMessage = (AddAuditLogMessage) m;
    assertNotNull(addMessage.getLogMessageLines());
    assertFalse(addMessage.getLogMessageLines().isEmpty());

    assertNotNull(addMessage.getCommentedHeaderLine());
    assertEquals(addMessage.getCommentedHeaderLine(),
         "# 23/Aug/2018:14:02:40 -0500; conn=28; op=1; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"");

    assertNotNull(addMessage.getUncommentedHeaderLine());
    assertEquals(addMessage.getUncommentedHeaderLine(),
         "23/Aug/2018:14:02:40 -0500; conn=28; op=1; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"");

    assertNotNull(addMessage.getTimestamp());
    final Calendar calendar = new GregorianCalendar();
    calendar.setTime(addMessage.getTimestamp());
    assertEquals(calendar.get(Calendar.YEAR), 2018);
    assertEquals(calendar.get(Calendar.MONTH), Calendar.AUGUST);

    assertNotNull(addMessage.getHeaderNamedValues());
    assertFalse(addMessage.getHeaderNamedValues().isEmpty());
    assertTrue(addMessage.getHeaderNamedValues().containsKey("conn"));

    assertNull(addMessage.getProductName());

    assertNull(addMessage.getInstanceName());

    assertNull(addMessage.getStartupID());

    assertNull(addMessage.getThreadID());

    assertNull(addMessage.getRequesterDN());

    assertNull(addMessage.getRequesterIPAddress());

    assertNotNull(addMessage.getConnectionID());
    assertEquals(addMessage.getConnectionID().longValue(), 28L);

    assertNotNull(addMessage.getOperationID());
    assertEquals(addMessage.getOperationID().longValue(), 1L);

    assertNull(addMessage.getTriggeredByConnectionID());

    assertNull(addMessage.getTriggeredByOperationID());

    assertNull(addMessage.getReplicationChangeID());

    assertNotNull(addMessage.getAlternateAuthorizationDN());
    assertDNsEqual(addMessage.getAlternateAuthorizationDN(),
         "cn=Directory Manager,cn=Root DNs,cn=config");

    assertNull(addMessage.getTransactionID());

    assertNull(addMessage.getOrigin());

    assertNull(addMessage.getUsingAdminSessionWorkerThread());

    assertNull(addMessage.getRequestControlOIDs());

    assertNull(addMessage.getOperationPurposeRequestControl());

    assertNull(addMessage.getIntermediateClientRequestControl());

    assertNotNull(addMessage.getDN());
    assertDNsEqual(addMessage.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(addMessage.getEntry());

    assertNull(addMessage.getIsUndelete());

    assertNotNull(addMessage.getChangeType());
    assertEquals(addMessage.getChangeType(), ChangeType.ADD);

    assertNotNull(addMessage.getChangeRecord());
    assertTrue(addMessage.getChangeRecord() instanceof LDIFAddChangeRecord);

    assertTrue(addMessage.isRevertible());

    assertNotNull(addMessage.getRevertChangeRecords());
    assertFalse(addMessage.getRevertChangeRecords().isEmpty());
    assertEquals(addMessage.getRevertChangeRecords().size(), 1);
    assertTrue(addMessage.getRevertChangeRecords().get(0) instanceof
         LDIFDeleteChangeRecord);

    final LDIFDeleteChangeRecord revertDeleteChangeRecord =
         (LDIFDeleteChangeRecord) addMessage.getRevertChangeRecords().get(0);
    assertDNsEqual(revertDeleteChangeRecord.getDN(),
         "ou=People,dc=example,dc=com");
    assertNotNull(revertDeleteChangeRecord.getControls());
    assertTrue(revertDeleteChangeRecord.getControls().isEmpty());

    assertNotNull(addMessage.toString());

    assertNotNull(addMessage.toMultiLineString());


    m = reader.read();
    assertNotNull(m);
    assertTrue(m instanceof DeleteAuditLogMessage);

    final DeleteAuditLogMessage deleteMessage = (DeleteAuditLogMessage) m;
    assertNotNull(deleteMessage.getLogMessageLines());
    assertFalse(deleteMessage.getLogMessageLines().isEmpty());

    assertNotNull(deleteMessage.getCommentedHeaderLine());
    assertEquals(deleteMessage.getCommentedHeaderLine(),
         "# 24/Aug/2018:12:11:50 -0500; conn=33; op=1; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"");

    assertNotNull(deleteMessage.getUncommentedHeaderLine());
    assertEquals(deleteMessage.getUncommentedHeaderLine(),
         "24/Aug/2018:12:11:50 -0500; conn=33; op=1; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"");

    assertNotNull(deleteMessage.getTimestamp());
    calendar.setTime(deleteMessage.getTimestamp());
    assertEquals(calendar.get(Calendar.YEAR), 2018);
    assertEquals(calendar.get(Calendar.MONTH), Calendar.AUGUST);

    assertNotNull(deleteMessage.getHeaderNamedValues());
    assertFalse(deleteMessage.getHeaderNamedValues().isEmpty());
    assertTrue(deleteMessage.getHeaderNamedValues().containsKey("conn"));

    assertNull(deleteMessage.getProductName());

    assertNull(deleteMessage.getInstanceName());

    assertNull(deleteMessage.getStartupID());

    assertNull(deleteMessage.getThreadID());

    assertNull(deleteMessage.getRequesterDN());

    assertNull(deleteMessage.getRequesterIPAddress());

    assertNotNull(deleteMessage.getConnectionID());
    assertEquals(deleteMessage.getConnectionID().longValue(), 33L);

    assertNotNull(deleteMessage.getOperationID());
    assertEquals(deleteMessage.getOperationID().longValue(), 1L);

    assertNull(deleteMessage.getTriggeredByConnectionID());

    assertNull(deleteMessage.getTriggeredByOperationID());

    assertNull(deleteMessage.getReplicationChangeID());

    assertNotNull(deleteMessage.getAlternateAuthorizationDN());
    assertDNsEqual(deleteMessage.getAlternateAuthorizationDN(),
         "cn=Directory Manager,cn=Root DNs,cn=config");

    assertNull(deleteMessage.getTransactionID());

    assertNull(deleteMessage.getOrigin());

    assertNull(deleteMessage.getUsingAdminSessionWorkerThread());

    assertNull(deleteMessage.getRequestControlOIDs());

    assertNull(deleteMessage.getOperationPurposeRequestControl());

    assertNull(deleteMessage.getIntermediateClientRequestControl());

    assertNotNull(deleteMessage.getDN());
    assertDNsEqual(deleteMessage.getDN(), "ou=People,dc=example,dc=com");

    assertNull(deleteMessage.getIsSubtreeDelete());

    assertNull(deleteMessage.getDeletedAsPartOfSubtreeDelete());

    assertNull(deleteMessage.getIsSoftDelete());

    assertNull(deleteMessage.getSoftDeletedEntryDN());

    assertNull(deleteMessage.getIsSoftDeletedEntry());

    assertNull(deleteMessage.getDeletedEntry());

    assertNull(deleteMessage.getDeletedEntryVirtualAttributes());

    assertNotNull(deleteMessage.getChangeType());
    assertEquals(deleteMessage.getChangeType(), ChangeType.DELETE);

    assertNotNull(deleteMessage.getChangeRecord());
    assertTrue(
         deleteMessage.getChangeRecord() instanceof LDIFDeleteChangeRecord);

    assertFalse(deleteMessage.isRevertible());

    try
    {
      deleteMessage.getRevertChangeRecords();
      fail("Expected an exception when trying to revert a non-revertible " +
           "delete audit log message");
    }
    catch (final AuditLogException e)
    {
      // This was expected.
    }

    assertNotNull(deleteMessage.toString());

    assertNotNull(deleteMessage.toMultiLineString());


    m = reader.read();
    assertNotNull(m);
    assertTrue(m instanceof ModifyAuditLogMessage);

    final ModifyAuditLogMessage modifyMessage = (ModifyAuditLogMessage) m;

    assertNotNull(modifyMessage.getLogMessageLines());
    assertFalse(modifyMessage.getLogMessageLines().isEmpty());

    assertNotNull(modifyMessage.getCommentedHeaderLine());
    assertTrue(modifyMessage.getCommentedHeaderLine().startsWith(
         "# 27/Aug/2018:15:09:11.476 -0500; conn=18; op=1; "));

    assertNotNull(modifyMessage.getUncommentedHeaderLine());
    assertTrue(modifyMessage.getUncommentedHeaderLine().startsWith(
         "27/Aug/2018:15:09:11.476 -0500; conn=18; op=1; "));

    assertNotNull(modifyMessage.getTimestamp());
    calendar.setTime(modifyMessage.getTimestamp());
    assertEquals(calendar.get(Calendar.YEAR), 2018);
    assertEquals(calendar.get(Calendar.MONTH), Calendar.AUGUST);

    assertNotNull(modifyMessage.getHeaderNamedValues());
    assertFalse(modifyMessage.getHeaderNamedValues().isEmpty());
    assertTrue(modifyMessage.getHeaderNamedValues().containsKey("conn"));

    assertNotNull(modifyMessage.getProductName());
    assertEquals(modifyMessage.getProductName(), "Directory Server");

    assertNotNull(modifyMessage.getInstanceName());
    assertEquals(modifyMessage.getInstanceName(), "ReplicaOne");

    assertNotNull(modifyMessage.getStartupID());
    assertEquals(modifyMessage.getStartupID(), "W4RZ/w==");

    assertNotNull(modifyMessage.getThreadID());
    assertEquals(modifyMessage.getThreadID().longValue(), 7L);

    assertNotNull(modifyMessage.getRequesterDN());
    assertDNsEqual(modifyMessage.getRequesterDN(),
         "cn=Proxy User,cn=Root DNs,cn=config");

    assertNotNull(modifyMessage.getRequesterIPAddress());
    assertEquals(modifyMessage.getRequesterIPAddress(), "127.0.0.1");

    assertNotNull(modifyMessage.getConnectionID());
    assertEquals(modifyMessage.getConnectionID().longValue(), 18L);

    assertNotNull(modifyMessage.getOperationID());
    assertEquals(modifyMessage.getOperationID().longValue(), 1L);

    assertNull(modifyMessage.getTriggeredByConnectionID());

    assertNull(modifyMessage.getTriggeredByOperationID());

    assertNotNull(modifyMessage.getReplicationChangeID());
    assertEquals(modifyMessage.getReplicationChangeID(),
         "000001657D01242C7A0D00000004");

    assertNotNull(modifyMessage.getAlternateAuthorizationDN());
    assertDNsEqual(modifyMessage.getAlternateAuthorizationDN(),
         "cn=Directory Manager,cn=Root DNs,cn=config");

    assertNull(modifyMessage.getTransactionID());

    assertNull(modifyMessage.getOrigin());

    assertNull(modifyMessage.getUsingAdminSessionWorkerThread());

    assertNotNull(modifyMessage.getRequestControlOIDs());
    assertEquals(modifyMessage.getRequestControlOIDs(),
         Collections.singletonList("1.3.6.1.4.1.30221.2.5.2"));

    assertNull(modifyMessage.getOperationPurposeRequestControl());

    assertNotNull(modifyMessage.getIntermediateClientRequestControl());

    assertNotNull(modifyMessage.getDN());
    assertDNsEqual(modifyMessage.getDN(),
         "uid=jdoe,ou=People,dc=example,dc=com");

    assertNotNull(modifyMessage.getModifications());
    assertFalse(modifyMessage.getModifications().isEmpty());
    assertEquals(modifyMessage.getModifications(),
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

    assertNull(modifyMessage.getIsSoftDeletedEntry());

    assertNotNull(modifyMessage.getChangeType());
    assertEquals(modifyMessage.getChangeType(), ChangeType.MODIFY);

    assertNotNull(modifyMessage.getChangeRecord());
    assertTrue(
         modifyMessage.getChangeRecord() instanceof LDIFModifyChangeRecord);

    assertTrue(modifyMessage.isRevertible());

    List<LDIFChangeRecord> revertChangeRecords =
         modifyMessage.getRevertChangeRecords();
    assertNotNull(revertChangeRecords);
    assertFalse(revertChangeRecords.isEmpty());
    assertEquals(revertChangeRecords.size(), 1);
    assertTrue(revertChangeRecords.get(0) instanceof LDIFModifyChangeRecord);

    final LDIFModifyChangeRecord revertModifyChangeRecord =
         (LDIFModifyChangeRecord) revertChangeRecords.get(0);
    assertEquals(revertModifyChangeRecord.getModifications(),
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

    assertNotNull(modifyMessage.toString());

    assertNotNull(modifyMessage.toMultiLineString());


    m = reader.read();
    assertNotNull(m);
    assertTrue(m instanceof ModifyDNAuditLogMessage);

    final ModifyDNAuditLogMessage modifyDNMessage = (ModifyDNAuditLogMessage) m;

    assertNotNull(modifyDNMessage.getLogMessageLines());
    assertFalse(modifyDNMessage.getLogMessageLines().isEmpty());

    assertNotNull(modifyDNMessage.getCommentedHeaderLine());
    assertTrue(modifyDNMessage.getCommentedHeaderLine().startsWith(
         "# 27/Aug/2018:16:33:47.019 -0500; conn=31; op=1; "));

    assertNotNull(modifyDNMessage.getUncommentedHeaderLine());
    assertTrue(modifyDNMessage.getUncommentedHeaderLine().startsWith(
         "27/Aug/2018:16:33:47.019 -0500; conn=31; op=1; "));

    assertNotNull(modifyDNMessage.getTimestamp());
    calendar.setTime(modifyDNMessage.getTimestamp());
    assertEquals(calendar.get(Calendar.YEAR), 2018);
    assertEquals(calendar.get(Calendar.MONTH), Calendar.AUGUST);

    assertNotNull(modifyDNMessage.getHeaderNamedValues());
    assertFalse(modifyDNMessage.getHeaderNamedValues().isEmpty());
    assertTrue(modifyDNMessage.getHeaderNamedValues().containsKey("conn"));

    assertNotNull(modifyDNMessage.getProductName());
    assertEquals(modifyDNMessage.getProductName(), "Directory Server");

    assertNotNull(modifyDNMessage.getInstanceName());
    assertEquals(modifyDNMessage.getInstanceName(), "ReplicaOne");

    assertNotNull(modifyDNMessage.getStartupID());
    assertEquals(modifyDNMessage.getStartupID(), "W4Rt1g==");

    assertNotNull(modifyDNMessage.getThreadID());
    assertEquals(modifyDNMessage.getThreadID().longValue(), 8L);

    assertNotNull(modifyDNMessage.getRequesterDN());
    assertDNsEqual(modifyDNMessage.getRequesterDN(),
         "cn=Proxy User,cn=Root DNs,cn=config");

    assertNotNull(modifyDNMessage.getRequesterIPAddress());
    assertEquals(modifyDNMessage.getRequesterIPAddress(), "127.0.0.1");

    assertNotNull(modifyDNMessage.getConnectionID());
    assertEquals(modifyDNMessage.getConnectionID().longValue(), 31L);

    assertNotNull(modifyDNMessage.getOperationID());
    assertEquals(modifyDNMessage.getOperationID().longValue(), 1L);

    assertNull(modifyDNMessage.getTriggeredByConnectionID());

    assertNull(modifyDNMessage.getTriggeredByOperationID());

    assertNotNull(modifyDNMessage.getReplicationChangeID());
    assertEquals(modifyDNMessage.getReplicationChangeID(),
         "000001657D4E9677214B00000005");

    assertNotNull(modifyDNMessage.getAlternateAuthorizationDN());
    assertDNsEqual(modifyDNMessage.getAlternateAuthorizationDN(),
         "cn=Directory Manager,cn=Root DNs,cn=config");

    assertNull(modifyDNMessage.getTransactionID());

    assertNull(modifyDNMessage.getOrigin());

    assertNull(modifyDNMessage.getUsingAdminSessionWorkerThread());

    assertNotNull(modifyDNMessage.getRequestControlOIDs());
    assertEquals(modifyDNMessage.getRequestControlOIDs(),
         Collections.singletonList("1.3.6.1.4.1.30221.2.5.2"));

    assertNull(modifyDNMessage.getOperationPurposeRequestControl());

    assertNotNull(modifyDNMessage.getIntermediateClientRequestControl());

    assertNotNull(modifyDNMessage.getDN());
    assertDNsEqual(modifyDNMessage.getDN(),
         "uid=jdoe,ou=People,dc=example,dc=com");

    assertNotNull(modifyDNMessage.getNewRDN());
    assertDNsEqual(modifyDNMessage.getNewRDN(), "uid=john.doe");

    assertTrue(modifyDNMessage.deleteOldRDN());

    assertNull(modifyDNMessage.getNewSuperiorDN());

    assertNotNull(modifyDNMessage.getAttributeModifications());
    assertEquals(modifyDNMessage.getAttributeModifications(),
         Arrays.asList(
              new Modification(ModificationType.DELETE, "uid", "jdoe"),
              new Modification(ModificationType.ADD, "uid", "john.doe")));

    assertNotNull(modifyDNMessage.getChangeType());
    assertEquals(modifyDNMessage.getChangeType(), ChangeType.MODIFY_DN);

    assertNotNull(modifyDNMessage.getChangeRecord());
    assertTrue(
         modifyDNMessage.getChangeRecord() instanceof LDIFModifyDNChangeRecord);

    assertTrue(modifyDNMessage.isRevertible());

    revertChangeRecords = modifyDNMessage.getRevertChangeRecords();
    assertNotNull(revertChangeRecords);
    assertFalse(revertChangeRecords.isEmpty());
    assertEquals(revertChangeRecords.size(), 1);
    assertTrue(revertChangeRecords.get(0) instanceof LDIFModifyDNChangeRecord);

    final LDIFModifyDNChangeRecord revertModifyDNChangeRecord =
         (LDIFModifyDNChangeRecord) revertChangeRecords.get(0);
    assertDNsEqual(revertModifyDNChangeRecord.getDN(),
         "uid=john.doe,ou=People,dc=example,dc=com");
    assertDNsEqual(revertModifyDNChangeRecord.getNewRDN(), "uid=jdoe");
    assertTrue(revertModifyDNChangeRecord.deleteOldRDN());
    assertNull(revertModifyDNChangeRecord.getNewSuperiorDN());

    assertNotNull(modifyDNMessage.toString());

    assertNotNull(modifyDNMessage.toMultiLineString());


    try
    {
      m = reader.read();
      fail("Expected an exception when trying to read message " + m);
    }
    catch (final AuditLogException e)
    {
      // This was expected.
    }


    assertNull(reader.read());

    reader.close();
  }



  /**
   * Gets a set of audit log readers to use for testing.
   *
   * @return  A set of audit log readers to use for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name = "basicAuditLogReaders")
  public Object[][] getBasicAuditLogReaders()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        new AuditLogReader(testBasicAuditLogFile.getAbsolutePath()),
        "Reader created from string path",
      },

      new Object[]
      {
        new AuditLogReader(testBasicAuditLogFile),
        "Reader created from file",
      },

      new Object[]
      {
        new AuditLogReader(new FileReader(testBasicAuditLogFile)),
        "Reader created from non-buffered reader",
      },

      new Object[]
      {
        new AuditLogReader(new BufferedReader(new FileReader(
             testBasicAuditLogFile))),
        "Reader created from buffered reader",
      },

      new Object[]
      {
        new AuditLogReader(new FileInputStream(testBasicAuditLogFile)),
        "Reader created from input stream",
      }
    };
  }
}
