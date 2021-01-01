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
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFModifyDNChangeRecord;
import com.unboundid.ldif.LDIFChangeRecord;



/**
 * This class provides a set of test cases for modify DN audit log messages.
 */
public final class ModifyDNAuditLogMessageTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a revertible modify DN audit log message that does
   * not have a new superior DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyAuditLogMessageWithoutNewSuperior()
         throws Exception
  {
    final ModifyDNAuditLogMessage m = new ModifyDNAuditLogMessage(
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
         "deleteoldrdn: 1");

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertTrue(m.getCommentedHeaderLine().startsWith(
         "# 27/Aug/2018:16:33:47.019 -0500; conn=31; op=1; "));

    assertNotNull(m.getUncommentedHeaderLine());
    assertTrue(m.getUncommentedHeaderLine().startsWith(
         "27/Aug/2018:16:33:47.019 -0500; conn=31; op=1; "));

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
    assertEquals(m.getThreadID().longValue(), 8L);

    assertNotNull(m.getRequesterDN());
    assertDNsEqual(m.getRequesterDN(), "cn=Proxy User,cn=Root DNs,cn=config");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "127.0.0.1");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID().longValue(), 31L);

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID().longValue(), 1L);

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

    assertNotNull(m.getReplicationChangeID());
    assertEquals(m.getReplicationChangeID(), "000001657D4E9677214B00000005");

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

    assertNotNull(m.getNewRDN());
    assertDNsEqual(m.getNewRDN(), "uid=john.doe");

    assertTrue(m.deleteOldRDN());

    assertNull(m.getNewSuperiorDN());

    assertNotNull(m.getAttributeModifications());
    assertEquals(m.getAttributeModifications(),
         Arrays.asList(
              new Modification(ModificationType.DELETE, "uid", "jdoe"),
              new Modification(ModificationType.ADD, "uid", "john.doe")));

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.MODIFY_DN);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFModifyDNChangeRecord);

    assertTrue(m.isRevertible());

    final List<LDIFChangeRecord> revertChangeRecords =
         m.getRevertChangeRecords();
    assertNotNull(revertChangeRecords);
    assertFalse(revertChangeRecords.isEmpty());
    assertEquals(revertChangeRecords.size(), 1);
    assertTrue(revertChangeRecords.get(0) instanceof LDIFModifyDNChangeRecord);

    final LDIFModifyDNChangeRecord revertChangeRecord =
         (LDIFModifyDNChangeRecord) revertChangeRecords.get(0);
    assertDNsEqual(revertChangeRecord.getDN(),
         "uid=john.doe,ou=People,dc=example,dc=com");
    assertDNsEqual(revertChangeRecord.getNewRDN(), "uid=jdoe");
    assertTrue(revertChangeRecord.deleteOldRDN());
    assertNull(revertChangeRecord.getNewSuperiorDN());

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a revertible modify DN audit log message that does
   * not have a new superior DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyAuditLogMessageWithNewSuperior()
         throws Exception
  {
    final ModifyDNAuditLogMessage m = new ModifyDNAuditLogMessage(Arrays.asList(
         "# 27/Aug/2018:16:33:47.033 -0500; conn=32; op=1; " +
              "productName=\"Directory Server\"; " +
              "instanceName=\"ReplicaOne\"; startupID=W4Rt1g==; threadID=9; " +
              "clientIP=127.0.0.1; " +
              "requesterDN=\"cn=Proxy User,cn=Root DNs,cn=config\"; " +
              "replicationChangeID=\"000001657D4E968C214B00000006\"; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"; " +
              "requestControlOIDs=\"1.3.6.1.4.1.30221.2.5.2\"; " +
              "intermediateClientRequestControl={ " +
              "\"clientIdentity\":\"dn:cn=Directory Manager,cn=Root " +
              "DNs,cn=config\", \"downstreamClientAddress\":\"127.0.0.1\", " +
              "\"downstreamClientSecure\":false, " +
              "\"clientName\":\"PingDirectory\", " +
              "\"clientSessionID\":\"conn=8\", \"clientRequestID\":\"op=6\", " +
              "\"downstreamRequest\":{ " +
              "\"clientName\":\"Unidentified Directory Application\" } }",
         "# ModifyDN attribute modifications (count=0)",
         "dn: uid=john.doe,ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newrdn: uid=john.doe",
         "deleteoldrdn: 1",
         "newsuperior: ou=Users,dc=example,dc=com"));

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertTrue(m.getCommentedHeaderLine().startsWith(
         "# 27/Aug/2018:16:33:47.033 -0500; conn=32; op=1; "));

    assertNotNull(m.getUncommentedHeaderLine());
    assertTrue(m.getUncommentedHeaderLine().startsWith(
         "27/Aug/2018:16:33:47.033 -0500; conn=32; op=1; "));

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
    assertEquals(m.getThreadID().longValue(), 9L);

    assertNotNull(m.getRequesterDN());
    assertDNsEqual(m.getRequesterDN(), "cn=Proxy User,cn=Root DNs,cn=config");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "127.0.0.1");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID().longValue(), 32L);

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID().longValue(), 1L);

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

    assertNotNull(m.getReplicationChangeID());
    assertEquals(m.getReplicationChangeID(), "000001657D4E968C214B00000006");

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
    assertDNsEqual(m.getDN(), "uid=john.doe,ou=People,dc=example,dc=com");

    assertNotNull(m.getNewRDN());
    assertDNsEqual(m.getNewRDN(), "uid=john.doe");

    assertTrue(m.deleteOldRDN());

    assertNotNull(m.getNewSuperiorDN());
    assertDNsEqual(m.getNewSuperiorDN(), "ou=Users,dc=example,dc=com");

    assertNotNull(m.getAttributeModifications());
    assertTrue(m.getAttributeModifications().isEmpty());

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.MODIFY_DN);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFModifyDNChangeRecord);

    assertTrue(m.isRevertible());

    final List<LDIFChangeRecord> revertChangeRecords =
         m.getRevertChangeRecords();
    assertNotNull(revertChangeRecords);
    assertFalse(revertChangeRecords.isEmpty());
    assertEquals(revertChangeRecords.size(), 1);
    assertTrue(revertChangeRecords.get(0) instanceof LDIFModifyDNChangeRecord);

    final LDIFModifyDNChangeRecord revertChangeRecord =
         (LDIFModifyDNChangeRecord) revertChangeRecords.get(0);
    assertDNsEqual(revertChangeRecord.getDN(),
         "uid=john.doe,ou=Users,dc=example,dc=com");
    assertDNsEqual(revertChangeRecord.getNewRDN(), "uid=john.doe");
    assertFalse(revertChangeRecord.deleteOldRDN());
    assertDNsEqual(revertChangeRecord.getNewSuperiorDN(),
         "ou=People,dc=Example,dc=com");

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a revertible modify DN audit log message that has
   * multiple components in the new RDN, one of which is already present in the
   * entry and one that is not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyAuditLogMessageMultipleNewRDNComponentsOneAlreadyThere()
         throws Exception
  {
    final ModifyDNAuditLogMessage m = new ModifyDNAuditLogMessage(
         "# 27/Aug/2018:22:42:11.929 -0500; conn=33; op=1; " +
              "productName=\"Directory Server\"; " +
              "instanceName=\"ReplicaOne\"; startupID=W4TELw==; threadID=13; " +
              "clientIP=127.0.0.1; " +
              "requesterDN=\"cn=Proxy User,cn=Root DNs,cn=config\"; " +
              "replicationChangeID=\"000001657E9FE1D473A700000007\"; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"; " +
              "requestControlOIDs=\"1.3.6.1.4.1.30221.2.5.2\"; " +
              "intermediateClientRequestControl={ " +
              "\"clientIdentity\":\"dn:cn=Directory Manager,cn=Root " +
              "DNs,cn=config\", \"downstreamClientAddress\":\"127.0.0.1\", " +
              "\"downstreamClientSecure\":false, " +
              "\"clientName\":\"PingDirectory\", " +
              "\"clientSessionID\":\"conn=8\", \"clientRequestID\":\"op=7\", " +
              "\"downstreamRequest\":{ " +
              "\"clientName\":\"Unidentified Directory Application\" } }",
         "# ModifyDN attribute modifications (count=1)",
         "# add: sn",
         "# sn: Smith",
         "dn: uid=jane.doe,ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newrdn: givenName=Jane+sn=Smith",
         "deleteoldrdn: 0");

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertTrue(m.getCommentedHeaderLine().startsWith(
         "# 27/Aug/2018:22:42:11.929 -0500; conn=33; op=1; "));

    assertNotNull(m.getUncommentedHeaderLine());
    assertTrue(m.getUncommentedHeaderLine().startsWith(
         "27/Aug/2018:22:42:11.929 -0500; conn=33; op=1; "));

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
    assertEquals(m.getStartupID(), "W4TELw==");

    assertNotNull(m.getThreadID());
    assertEquals(m.getThreadID().longValue(), 13L);

    assertNotNull(m.getRequesterDN());
    assertDNsEqual(m.getRequesterDN(), "cn=Proxy User,cn=Root DNs,cn=config");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "127.0.0.1");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID().longValue(), 33L);

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID().longValue(), 1L);

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

    assertNotNull(m.getReplicationChangeID());
    assertEquals(m.getReplicationChangeID(), "000001657E9FE1D473A700000007");

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
    assertDNsEqual(m.getDN(), "uid=jane.doe,ou=People,dc=example,dc=com");

    assertNotNull(m.getNewRDN());
    assertDNsEqual(m.getNewRDN(), "givenName=Jane+sn=Smith");

    assertFalse(m.deleteOldRDN());

    assertNull(m.getNewSuperiorDN());

    assertNotNull(m.getAttributeModifications());
    assertEquals(m.getAttributeModifications(),
         Collections.singletonList(
              new Modification(ModificationType.ADD, "sn", "Smith")));

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.MODIFY_DN);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFModifyDNChangeRecord);

    assertTrue(m.isRevertible());

    final List<LDIFChangeRecord> revertChangeRecords =
         m.getRevertChangeRecords();
    assertNotNull(revertChangeRecords);
    assertFalse(revertChangeRecords.isEmpty());
    assertEquals(revertChangeRecords.size(), 2);
    assertTrue(revertChangeRecords.get(0) instanceof LDIFModifyDNChangeRecord);
    assertTrue(revertChangeRecords.get(1) instanceof LDIFModifyChangeRecord);

    final LDIFModifyDNChangeRecord revertModifyDNChangeRecord =
         (LDIFModifyDNChangeRecord) revertChangeRecords.get(0);
    assertDNsEqual(revertModifyDNChangeRecord.getDN(),
         "givenName=Jane+sn=Smith,ou=People,dc=example,dc=com");
    assertDNsEqual(revertModifyDNChangeRecord.getNewRDN(), "uid=jane.doe");
    assertFalse(revertModifyDNChangeRecord.deleteOldRDN());
    assertNull(revertModifyDNChangeRecord.getNewSuperiorDN());

    final LDIFModifyChangeRecord revertModifyChangeRecord =
         (LDIFModifyChangeRecord) revertChangeRecords.get(1);
    assertDNsEqual(revertModifyChangeRecord.getDN(),
         "uid=jane.doe,ou=People,dc=example,dc=com");
    assertEquals(revertModifyChangeRecord.getModifications(),
         new Modification[]
         {
           new Modification(ModificationType.DELETE, "sn", "Smith")
         });

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a revertible modify DN audit log message that has
   * additional modifications not related to the RDN change.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyAuditLogMessageWithAdditionalMods()
         throws Exception
  {
    final ModifyDNAuditLogMessage m = new ModifyDNAuditLogMessage(
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
         "# ModifyDN attribute modifications (count=6)",
         "# delete: givenName",
         "# givenName: John",
         "# givenName: Johnny",
         "# -",
         "# delete: sn",
         "# sn: Doe",
         "# sn: A Female Deer",
         "# -",
         "# add: uid",
         "# uid: jdoe",
         "# uid: john.doe",
         "# -",
         "# delete: displayName",
         "# displayName: foo",
         "# -",
         "# add: description",
         "# description: bar",
         "# -",
         "# increment: intAttr",
         "# intAttr: 1",
         "dn: givenName=John+sn=Doe,ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newrdn: uid=jdoe",
         "deleteoldrdn: 1");

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertTrue(m.getCommentedHeaderLine().startsWith(
         "# 27/Aug/2018:16:33:47.019 -0500; conn=31; op=1; "));

    assertNotNull(m.getUncommentedHeaderLine());
    assertTrue(m.getUncommentedHeaderLine().startsWith(
         "27/Aug/2018:16:33:47.019 -0500; conn=31; op=1; "));

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
    assertEquals(m.getThreadID().longValue(), 8L);

    assertNotNull(m.getRequesterDN());
    assertDNsEqual(m.getRequesterDN(), "cn=Proxy User,cn=Root DNs,cn=config");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "127.0.0.1");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID().longValue(), 31L);

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID().longValue(), 1L);

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

    assertNotNull(m.getReplicationChangeID());
    assertEquals(m.getReplicationChangeID(), "000001657D4E9677214B00000005");

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
         "givenName=John+sn=Doe,ou=People,dc=example,dc=com");

    assertNotNull(m.getNewRDN());
    assertDNsEqual(m.getNewRDN(), "uid=jdoe");

    assertTrue(m.deleteOldRDN());

    assertNull(m.getNewSuperiorDN());

    assertNotNull(m.getAttributeModifications());
    assertEquals(m.getAttributeModifications(),
         Arrays.asList(
              new Modification(ModificationType.DELETE, "givenName", "John",
                   "Johnny"),
              new Modification(ModificationType.DELETE, "sn", "Doe",
                   "A Female Deer"),
              new Modification(ModificationType.ADD, "uid", "jdoe", "john.doe"),
              new Modification(ModificationType.DELETE, "displayName", "foo"),
              new Modification(ModificationType.ADD, "description", "bar"),
              new Modification(ModificationType.INCREMENT, "intAttr", "1")));

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.MODIFY_DN);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFModifyDNChangeRecord);

    assertTrue(m.isRevertible());

    final List<LDIFChangeRecord> revertChangeRecords =
         m.getRevertChangeRecords();
    assertNotNull(revertChangeRecords);
    assertFalse(revertChangeRecords.isEmpty());
    assertEquals(revertChangeRecords.size(), 2);
    assertTrue(revertChangeRecords.get(0) instanceof LDIFModifyDNChangeRecord);
    assertTrue(revertChangeRecords.get(1) instanceof LDIFModifyChangeRecord);

    final LDIFModifyDNChangeRecord revertModifyDNChangeRecord =
         (LDIFModifyDNChangeRecord) revertChangeRecords.get(0);
    assertDNsEqual(revertModifyDNChangeRecord.getDN(),
         "uid=jdoe,ou=People,dc=example,dc=com");
    assertDNsEqual(revertModifyDNChangeRecord.getNewRDN(),
         "givenName=John+sn=Doe");
    assertTrue(revertModifyDNChangeRecord.deleteOldRDN());
    assertNull(revertModifyDNChangeRecord.getNewSuperiorDN());

    final LDIFModifyChangeRecord revertModifyChangeRecord =
         (LDIFModifyChangeRecord) revertChangeRecords.get(1);
    assertDNsEqual(revertModifyChangeRecord.getDN(),
         "givenName=John+sn=Doe,ou=People,dc=example,dc=com");
    assertEquals(revertModifyChangeRecord.getModifications(),
         new Modification[]
         {
           new Modification(ModificationType.INCREMENT, "intAttr", "-1"),
           new Modification(ModificationType.DELETE, "description", "bar"),
           new Modification(ModificationType.ADD, "displayName", "foo"),
           new Modification(ModificationType.DELETE, "uid", "john.doe"),
           new Modification(ModificationType.ADD, "sn", "A Female Deer"),
           new Modification(ModificationType.ADD, "givenName", "Johnny")
         });

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a modify DN audit log message that is not revertible
   * because there are no modifications and deleteOldRDN is true.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyAuditLogMessageNotRevertibleMissingMods()
         throws Exception
  {
    final ModifyDNAuditLogMessage m = new ModifyDNAuditLogMessage(
         Arrays.asList(
              "# 27/Aug/2018:16:33:47.019 -0500; conn=31; op=1",
              "dn: uid=jdoe,ou=People,dc=example,dc=com",
              "changetype: moddn",
              "newrdn: uid=john.doe",
              "deleteoldrdn: 1"),
         new LDIFModifyDNChangeRecord("uid=jdoe,ou=People,dc=example,dc=com",
              "uid=john.doe", true, null));

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertEquals(m.getCommentedHeaderLine(),
         "# 27/Aug/2018:16:33:47.019 -0500; conn=31; op=1");

    assertNotNull(m.getUncommentedHeaderLine());
    assertEquals(m.getUncommentedHeaderLine(),
         "27/Aug/2018:16:33:47.019 -0500; conn=31; op=1");

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
    assertEquals(m.getConnectionID().longValue(), 31L);

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

    assertNotNull(m.getNewRDN());
    assertDNsEqual(m.getNewRDN(), "uid=john.doe");

    assertTrue(m.deleteOldRDN());

    assertNull(m.getNewSuperiorDN());

    assertNull(m.getAttributeModifications());

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.MODIFY_DN);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFModifyDNChangeRecord);

    assertFalse(m.isRevertible());

    try
    {
      m.getRevertChangeRecords();
      fail("Expected an exception when trying to revert a non-revertible " +
           "modify DN audit log message");
    }
    catch (final AuditLogException e)
    {
      // This was expected.
    }

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior when trying to create a modify DN audit log message from
   * a set of lines that comprise a valid change record but not a modify DN
   * change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testCreateFromMessageWithNonModifyDNChangeType()
         throws Exception
  {

    new ModifyDNAuditLogMessage(
         "# 24/Aug/2018:12:11:50 -0500; conn=33; op=1; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"",
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");
  }



  /**
   * Tests the behavior when trying to create a modify DN audit log message from
   * a set of lines that do not comprise a valid LDIF change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AuditLogException.class })
  public void testCreateFromMessageWithInvalidChangeRecordLines()
         throws Exception
  {

    new ModifyDNAuditLogMessage(
         "# 24/Aug/2018:12:11:50 -0500; conn=33; op=1; " +
              "authzDN=\"cn=Directory Manager,cn=Root DNs,cn=config\"",
         "not a valid change record");
  }



  /**
   * Tests the behavior for a modify DN audit log message that cannot be
   * reverted because the current DN is the null DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyAuditLogMessageWithCurrentDNIsNullDN()
         throws Exception
  {
    final ModifyDNAuditLogMessage m = new ModifyDNAuditLogMessage(
         "# 27/Aug/2018:16:33:47.019 -0500; conn=31; op=1",
         "# ModifyDN attribute modifications (count=0)",
         "dn: ",
         "changetype: moddn",
         "newrdn: uid=john.doe",
         "deleteoldrdn: 0",
         "newsuperior: ou=People,dc=example,dc=com");

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertEquals(m.getCommentedHeaderLine(),
         "# 27/Aug/2018:16:33:47.019 -0500; conn=31; op=1");

    assertNotNull(m.getUncommentedHeaderLine());
    assertEquals(m.getUncommentedHeaderLine(),
         "27/Aug/2018:16:33:47.019 -0500; conn=31; op=1");

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
    assertEquals(m.getConnectionID().longValue(), 31L);

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
    assertEquals(m.getDN(), "");

    assertNotNull(m.getNewRDN());
    assertDNsEqual(m.getNewRDN(), "uid=john.doe");

    assertFalse(m.deleteOldRDN());

    assertNotNull(m.getNewSuperiorDN());
    assertDNsEqual(m.getNewSuperiorDN(), "ou=People,dc=example,dc=com");

    assertNotNull(m.getAttributeModifications());
    assertTrue(m.getAttributeModifications().isEmpty());

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.MODIFY_DN);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFModifyDNChangeRecord);

    assertFalse(m.isRevertible());

    try
    {
      m.getRevertChangeRecords();
      fail("Expected an exception when trying to revert a non-revertible " +
           "modify DN audit log message");
    }
    catch (final AuditLogException e)
    {
      // This was expected.
    }

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a modify DN audit log message that cannot be
   * reverted because the message doesn't include modifications, delete old RDN
   * is true, and the new RDN is not the same as the old RDN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyAuditLogMessageWithoutNecessaryModifications()
         throws Exception
  {
    final ModifyDNAuditLogMessage m = new ModifyDNAuditLogMessage(
         "# 27/Aug/2018:16:33:47.019 -0500; conn=31; op=1",
         "# ModifyDN attribute modifications (count=0)",
         "dn: uid=jdoe,ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newrdn: uid=john.doe",
         "deleteoldrdn: 1");

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertEquals(m.getCommentedHeaderLine(),
         "# 27/Aug/2018:16:33:47.019 -0500; conn=31; op=1");

    assertNotNull(m.getUncommentedHeaderLine());
    assertEquals(m.getUncommentedHeaderLine(),
         "27/Aug/2018:16:33:47.019 -0500; conn=31; op=1");

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
    assertEquals(m.getConnectionID().longValue(), 31L);

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
    assertEquals(m.getDN(), "uid=jdoe,ou=People,dc=example,dc=com");

    assertNotNull(m.getNewRDN());
    assertDNsEqual(m.getNewRDN(), "uid=john.doe");

    assertTrue(m.deleteOldRDN());

    assertNull(m.getNewSuperiorDN());

    assertNotNull(m.getAttributeModifications());
    assertTrue(m.getAttributeModifications().isEmpty());

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.MODIFY_DN);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFModifyDNChangeRecord);

    assertFalse(m.isRevertible());

    try
    {
      m.getRevertChangeRecords();
      fail("Expected an exception when trying to revert a non-revertible " +
           "modify DN audit log message");
    }
    catch (final AuditLogException e)
    {
      // This was expected.
    }

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a modify DN audit log message that cannot be
   * reverted because the message includes non-revertible modifications.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyAuditLogMessageWithNonRevertibleModifications()
         throws Exception
  {
    final ModifyDNAuditLogMessage m = new ModifyDNAuditLogMessage(
         "# 27/Aug/2018:16:33:47.019 -0500; conn=31; op=1",
         "# ModifyDN attribute modifications (count=1)",
         "# replace: uid",
         "# uid: john.doe",
         "dn: uid=jdoe,ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newrdn: uid=john.doe",
         "deleteoldrdn: 1");

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertEquals(m.getCommentedHeaderLine(),
         "# 27/Aug/2018:16:33:47.019 -0500; conn=31; op=1");

    assertNotNull(m.getUncommentedHeaderLine());
    assertEquals(m.getUncommentedHeaderLine(),
         "27/Aug/2018:16:33:47.019 -0500; conn=31; op=1");

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
    assertEquals(m.getConnectionID().longValue(), 31L);

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
    assertEquals(m.getDN(), "uid=jdoe,ou=People,dc=example,dc=com");

    assertNotNull(m.getNewRDN());
    assertDNsEqual(m.getNewRDN(), "uid=john.doe");

    assertTrue(m.deleteOldRDN());

    assertNull(m.getNewSuperiorDN());

    assertNotNull(m.getAttributeModifications());
    assertEquals(m.getAttributeModifications(),
         Collections.singletonList(
              new Modification(ModificationType.REPLACE, "uid", "john.doe")));

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.MODIFY_DN);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFModifyDNChangeRecord);

    assertFalse(m.isRevertible());

    try
    {
      m.getRevertChangeRecords();
      fail("Expected an exception when trying to revert a non-revertible " +
           "modify DN audit log message");
    }
    catch (final AuditLogException e)
    {
      // This was expected.
    }

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a modify DN audit log message that cannot be
   * reverted because it has a malformed current DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyAuditLogMessageWithMalformedCurrentDN()
         throws Exception
  {
    final ModifyDNAuditLogMessage m = new ModifyDNAuditLogMessage(
         "# 27/Aug/2018:16:33:47.019 -0500; conn=31; op=1",
         "# ModifyDN attribute modifications (count=0)",
         "dn: malformed",
         "changetype: moddn",
         "newrdn: uid=john.doe",
         "deleteoldrdn: 0");

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertEquals(m.getCommentedHeaderLine(),
         "# 27/Aug/2018:16:33:47.019 -0500; conn=31; op=1");

    assertNotNull(m.getUncommentedHeaderLine());
    assertEquals(m.getUncommentedHeaderLine(),
         "27/Aug/2018:16:33:47.019 -0500; conn=31; op=1");

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
    assertEquals(m.getConnectionID().longValue(), 31L);

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
    assertEquals(m.getDN(), "malformed");

    assertNotNull(m.getNewRDN());
    assertDNsEqual(m.getNewRDN(), "uid=john.doe");

    assertFalse(m.deleteOldRDN());

    assertNull(m.getNewSuperiorDN());

    assertNotNull(m.getAttributeModifications());
    assertTrue(m.getAttributeModifications().isEmpty());

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.MODIFY_DN);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFModifyDNChangeRecord);

    assertFalse(m.isRevertible());

    try
    {
      m.getRevertChangeRecords();
      fail("Expected an exception when trying to revert a non-revertible " +
           "modify DN audit log message");
    }
    catch (final AuditLogException e)
    {
      // This was expected.
    }

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a modify DN audit log message that cannot be
   * reverted because it has a malformed new RDN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyAuditLogMessageWithMalformedNewRDN()
         throws Exception
  {
    final ModifyDNAuditLogMessage m = new ModifyDNAuditLogMessage(
         "# 27/Aug/2018:16:33:47.019 -0500; conn=31; op=1",
         "# ModifyDN attribute modifications (count=0)",
         "dn: uid=jdoe,ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newrdn: malformed",
         "deleteoldrdn: 0");

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertEquals(m.getCommentedHeaderLine(),
         "# 27/Aug/2018:16:33:47.019 -0500; conn=31; op=1");

    assertNotNull(m.getUncommentedHeaderLine());
    assertEquals(m.getUncommentedHeaderLine(),
         "27/Aug/2018:16:33:47.019 -0500; conn=31; op=1");

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
    assertEquals(m.getConnectionID().longValue(), 31L);

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

    assertNotNull(m.getNewRDN());
    assertEquals(m.getNewRDN(), "malformed");

    assertFalse(m.deleteOldRDN());

    assertNull(m.getNewSuperiorDN());

    assertNotNull(m.getAttributeModifications());
    assertTrue(m.getAttributeModifications().isEmpty());

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.MODIFY_DN);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFModifyDNChangeRecord);

    assertFalse(m.isRevertible());

    try
    {
      m.getRevertChangeRecords();
      fail("Expected an exception when trying to revert a non-revertible " +
           "modify DN audit log message");
    }
    catch (final AuditLogException e)
    {
      // This was expected.
    }

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a modify DN audit log message that cannot be
   * reverted because it has a malformed new superior DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyAuditLogMessageWithMalformedNewSuperior()
         throws Exception
  {
    final ModifyDNAuditLogMessage m = new ModifyDNAuditLogMessage(
         "# 27/Aug/2018:16:33:47.019 -0500; conn=31; op=1",
         "# ModifyDN attribute modifications (count=0)",
         "dn: uid=jdoe,ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newrdn: uid=jdoe",
         "deleteoldrdn: 0",
         "newsuperior: malformed");

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertEquals(m.getCommentedHeaderLine(),
         "# 27/Aug/2018:16:33:47.019 -0500; conn=31; op=1");

    assertNotNull(m.getUncommentedHeaderLine());
    assertEquals(m.getUncommentedHeaderLine(),
         "27/Aug/2018:16:33:47.019 -0500; conn=31; op=1");

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
    assertEquals(m.getConnectionID().longValue(), 31L);

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

    assertNotNull(m.getNewRDN());
    assertDNsEqual(m.getNewRDN(), "uid=jdoe");

    assertFalse(m.deleteOldRDN());

    assertNotNull(m.getNewSuperiorDN());
    assertEquals(m.getNewSuperiorDN(), "malformed");

    assertNotNull(m.getAttributeModifications());
    assertTrue(m.getAttributeModifications().isEmpty());

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.MODIFY_DN);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFModifyDNChangeRecord);

    assertFalse(m.isRevertible());

    try
    {
      m.getRevertChangeRecords();
      fail("Expected an exception when trying to revert a non-revertible " +
           "modify DN audit log message");
    }
    catch (final AuditLogException e)
    {
      // This was expected.
    }

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }



  /**
   * Tests the behavior for a modify DN audit log message that cannot be
   * reverted because it has a malformed new RDN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyAuditLogMessageWithMalformedModifications()
         throws Exception
  {
    final ModifyDNAuditLogMessage m = new ModifyDNAuditLogMessage(
         "# 27/Aug/2018:16:33:47.019 -0500; conn=31; op=1",
         "# ModifyDN attribute modifications (count=1)",
         "# malformed",
         "dn: uid=jdoe,ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newrdn: uid=john.doe",
         "deleteoldrdn: 0");

    assertNotNull(m.getLogMessageLines());
    assertFalse(m.getLogMessageLines().isEmpty());

    assertNotNull(m.getCommentedHeaderLine());
    assertEquals(m.getCommentedHeaderLine(),
         "# 27/Aug/2018:16:33:47.019 -0500; conn=31; op=1");

    assertNotNull(m.getUncommentedHeaderLine());
    assertEquals(m.getUncommentedHeaderLine(),
         "27/Aug/2018:16:33:47.019 -0500; conn=31; op=1");

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
    assertEquals(m.getConnectionID().longValue(), 31L);

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

    assertNotNull(m.getNewRDN());
    assertDNsEqual(m.getNewRDN(), "uid=john.doe");

    assertFalse(m.deleteOldRDN());

    assertNull(m.getNewSuperiorDN());

    assertNull(m.getAttributeModifications());

    assertNotNull(m.getChangeType());
    assertEquals(m.getChangeType(), ChangeType.MODIFY_DN);

    assertNotNull(m.getChangeRecord());
    assertTrue(m.getChangeRecord() instanceof LDIFModifyDNChangeRecord);

    assertFalse(m.isRevertible());

    try
    {
      m.getRevertChangeRecords();
      fail("Expected an exception when trying to revert a non-revertible " +
           "modify DN audit log message");
    }
    catch (final AuditLogException e)
    {
      // This was expected.
    }

    assertNotNull(m.toString());

    assertNotNull(m.toMultiLineString());
  }
}
