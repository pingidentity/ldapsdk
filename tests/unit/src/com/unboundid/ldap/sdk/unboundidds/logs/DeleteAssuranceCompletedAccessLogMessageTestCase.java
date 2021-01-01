/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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



import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.GregorianCalendar;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.controls.AssuredReplicationLocalLevel;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationRemoteLevel;



/**
 * This class provides test coverage for the
 * {@code DeleteAssuranceCompletedAccessLogMessage} class.
 */
public class DeleteAssuranceCompletedAccessLogMessageTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the ability to create a log message from a string containing only a
   * timestamp.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyTimestamp()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d);

    DeleteAssuranceCompletedAccessLogMessage m =
         new DeleteAssuranceCompletedAccessLogMessage(s);
    m = new DeleteAssuranceCompletedAccessLogMessage(m);

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertTrue(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertTrue(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.ASSURANCE_COMPLETE);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.DELETE);

    assertNull(m.getProductName());

    assertNull(m.getInstanceName());

    assertNull(m.getStartupID());

    assertNull(m.getConnectionID());

    assertNull(m.getOperationID());

    assertNull(m.getMessageID());

    assertNull(m.getOrigin());

    assertNull(m.getRequesterDN());

    assertNull(m.getRequesterIPAddress());

    assertNull(m.getIntermediateClientRequest());

    assertNull(m.getOperationPurpose());

    assertNull(m.getDN());

    assertNull(m.getResultCode());

    assertNull(m.getDiagnosticMessage());

    assertNull(m.getAdditionalInformation());

    assertNull(m.getMatchedDN());

    assertNull(m.getIntermediateResponsesReturned());

    assertNull(m.getProcessingTimeMillis());

    assertNull(m.getIntermediateClientResult());

    assertNotNull(m.getReferralURLs());
    assertTrue(m.getReferralURLs().isEmpty());

    assertNotNull(m.getServersAccessed());
    assertTrue(m.getServersAccessed().isEmpty());

    assertNull(m.getUncachedDataAccessed());

    assertNull(m.getAlternateAuthorizationDN());

    assertNull(m.getReplicationChangeID());

    assertNull(m.getSoftDeletedEntryDN());

    assertNull(m.getChangeToSoftDeletedEntry());

    assertNull(m.getTargetHost());

    assertNull(m.getTargetPort());

    assertNull(m.getTargetProtocol());

    assertNull(m.getAssuredReplicationLocalLevel());

    assertNull(m.getAssuredReplicationRemoteLevel());

    assertNull(m.getAssuredReplicationTimeoutMillis());

    assertNull(m.getResponseDelayedByAssurance());

    assertNull(m.getLocalAssuranceSatisfied());

    assertNull(m.getRemoteAssuranceSatisfied());

    assertNull(m.getServerAssuranceResults());

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);
  }



  /**
   * Tests the ability to create a log message from a string containing only a
   * basic set of information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicContents()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " DELETE ASSURANCE-COMPLETE conn=1 op=2 msgID=3 " +
               "resultCode=0 etime=0.123 serversAccessed=\"1.2.3.4:389\" " +
               "uncachedDataAccessed=true";

    DeleteAssuranceCompletedAccessLogMessage m =
         new DeleteAssuranceCompletedAccessLogMessage(s);
    m = new DeleteAssuranceCompletedAccessLogMessage(m);

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

    assertNull(m.getProductName());

    assertNull(m.getInstanceName());

    assertNull(m.getStartupID());

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNull(m.getOrigin());

    assertNull(m.getRequesterDN());

    assertNull(m.getRequesterIPAddress());

    assertNull(m.getIntermediateClientRequest());

    assertNull(m.getOperationPurpose());

    assertNull(m.getDN());

    assertNotNull(m.getResultCode());
    assertEquals(m.getResultCode(), ResultCode.SUCCESS);

    assertNull(m.getDiagnosticMessage());

    assertNull(m.getAdditionalInformation());

    assertNull(m.getMatchedDN());

    assertNull(m.getIntermediateResponsesReturned());

    assertNotNull(m.getProcessingTimeMillis());
    assertEquals(m.getProcessingTimeMillis(), Double.valueOf("0.123"));

    assertNull(m.getQueueTimeMillis());

    assertNull(m.getIntermediateClientResult());

    assertNotNull(m.getReferralURLs());
    assertTrue(m.getReferralURLs().isEmpty());

    assertNotNull(m.getServersAccessed());
    assertFalse(m.getServersAccessed().isEmpty());
    assertTrue(m.getServersAccessed().contains("1.2.3.4:389"));

    assertTrue(m.getUncachedDataAccessed());

    assertNull(m.getAlternateAuthorizationDN());

    assertNull(m.getReplicationChangeID());

    assertNull(m.getSoftDeletedEntryDN());

    assertNull(m.getChangeToSoftDeletedEntry());

    assertNull(m.getTargetHost());

    assertNull(m.getTargetPort());

    assertNull(m.getTargetProtocol());

    assertNull(m.getAssuredReplicationLocalLevel());

    assertNull(m.getAssuredReplicationRemoteLevel());

    assertNull(m.getAssuredReplicationTimeoutMillis());

    assertNull(m.getResponseDelayedByAssurance());

    assertNull(m.getLocalAssuranceSatisfied());

    assertNull(m.getRemoteAssuranceSatisfied());

    assertNull(m.getServerAssuranceResults());

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);
  }



  /**
   * Tests the ability to create a log message from a string containing a
   * complete set of information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompleteContents()
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
               "product=\"Directory Server\" " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "requestControls=\"5.6.7.8,9.10.11.12\" " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "dn=\"ou=People,dc=example,dc=com\" resultCode=32 " +
               "message=\"The entry doesn't exist\" " +
               "additionalInfo=\"foo\" matchedDN=\"dc=example,dc=com\" " +
               "etime=0.123 qtime=4 responseControls=\"8.7.6.5\" " +
               "referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" " +
               "from=\"app='UnboundID Directory Server'\" " +
               "authzDN=\"uid=someone,ou=People,dc=example,dc=com\" " +
               "serversAccessed=\"1.2.3.4:389,5.6.7.8:389\" " +
               "uncachedDataAccessed=true intermediateResponsesReturned=5 " +
               "replicationChangeID=\"0000012EBB009C9F726B0000138B\" " +
               "softDeleteEntryDN=\"entryUUID=12345+ou=People,dc=example," +
                    "dc=com\" " +
               "changeToSoftDeletedEntry=false " +
               "targetHost=\"4.3.2.1\" targetPort=8765 " +
               "targetProtocol=\"LDAP\" " +
               "localAssuranceLevel=\"PROCESSED_ALL_SERVERS\" " +
               "remoteAssuranceLevel=\"PROCESSED_ALL_REMOTE_SERVERS\" " +
               "assuranceTimeoutMillis=5000 responseDelayedByAssurance=false " +
               "localAssuranceSatisfied=true remoteAssuranceSatisfied=false " +
               "serverAssuranceResults=\"assurance-results\"";

    DeleteAssuranceCompletedAccessLogMessage m =
         new DeleteAssuranceCompletedAccessLogMessage(s);
    m = new DeleteAssuranceCompletedAccessLogMessage(m);

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

    assertNotNull(m.getProductName());
    assertEquals(m.getProductName(), "Directory Server");

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

    assertNotNull(m.getRequestControlOIDs());
    assertEquals(m.getRequestControlOIDs().size(), 2);
    assertTrue(m.getRequestControlOIDs().contains("5.6.7.8"));
    assertTrue(m.getRequestControlOIDs().contains("9.10.11.12"));

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

    assertNotNull(m.getIntermediateResponsesReturned());
    assertEquals(m.getIntermediateResponsesReturned(), Long.valueOf(5L));

    assertNotNull(m.getProcessingTimeMillis());
    assertEquals(m.getProcessingTimeMillis(), Double.valueOf("0.123"));

    assertNotNull(m.getQueueTimeMillis());
    assertEquals(m.getQueueTimeMillis(), Double.valueOf("4"));

    assertNotNull(m.getIntermediateClientResult());
    assertEquals(m.getIntermediateClientResult(),
                 "app='UnboundID Directory Server'");

    assertNotNull(m.getResponseControlOIDs());
    assertEquals(m.getResponseControlOIDs().size(), 1);
    assertTrue(m.getResponseControlOIDs().contains("8.7.6.5"));

    assertNotNull(m.getReferralURLs());
    assertEquals(m.getReferralURLs().size(), 2);
    assertTrue(m.getReferralURLs().contains("ldap://server1.example.com:389/"));
    assertTrue(m.getReferralURLs().contains("ldap://server2.example.com:389/"));

    assertNotNull(m.getServersAccessed());
    assertFalse(m.getServersAccessed().isEmpty());
    assertTrue(m.getServersAccessed().contains("1.2.3.4:389"));
    assertTrue(m.getServersAccessed().contains("5.6.7.8:389"));

    assertTrue(m.getUncachedDataAccessed());

    assertNotNull(m.getAlternateAuthorizationDN());
    assertEquals(m.getAlternateAuthorizationDN(),
                 "uid=someone,ou=People,dc=example,dc=com");

    assertNotNull(m.getReplicationChangeID());
    assertEquals(m.getReplicationChangeID(), "0000012EBB009C9F726B0000138B");

    assertNotNull(m.getSoftDeletedEntryDN());

    assertNotNull(m.getChangeToSoftDeletedEntry());
    assertFalse(m.getChangeToSoftDeletedEntry());

    assertNotNull(m.getTargetHost());
    assertEquals(m.getTargetHost(), "4.3.2.1");

    assertNotNull(m.getTargetPort());
    assertEquals(m.getTargetPort(), Integer.valueOf(8765));

    assertNotNull(m.getTargetProtocol());
    assertEquals(m.getTargetProtocol(), "LDAP");

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
  }
}
