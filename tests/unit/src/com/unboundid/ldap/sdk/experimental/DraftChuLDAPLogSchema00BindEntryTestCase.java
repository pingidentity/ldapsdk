/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.experimental;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the
 * {@code DraftChuLDAPLogSchema00BindEntry} class.
 */
public final class DraftChuLDAPLogSchema00BindEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with an entry that represents a valid, successful simple
   * bind operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeValidSuccessfulSimpleBind()
         throws Exception
  {
    final DraftChuLDAPLogSchema00BindEntry e =
         (DraftChuLDAPLogSchema00BindEntry)
         DraftChuLDAPLogSchema00Entry.decode(new Entry(
              "dn: reqStart=20160102030406.789012Z,cn=log",
              "objectClass: auditBind",
              "reqStart: 20160102030406.789012Z",
              "reqType: bind",
              "reqSession: 1234",
              "reqVersion: 3",
              "reqMethod: SIMPLE",
              "reqDN: uid=test.user,ou=People,dc=example,dc=com",
              "reqResult: 0",
              "reqAuthzID: "));

    assertNotNull(e);

    assertNotNull(e.getOperationType());
    assertEquals(e.getOperationType(), OperationType.BIND);

    assertNotNull(e.getTargetEntryDN());
    assertDNsEqual(e.getTargetEntryDN(),
         "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(e.getProcessingStartTimeString());
    assertEquals(e.getProcessingStartTimeString(), "20160102030406.789012Z");

    assertNotNull(e.getProcessingStartTimeDate());
    assertEquals(e.getProcessingStartTimeDate(),
         StaticUtils.decodeGeneralizedTime("20160102030406.789Z"));

    assertNull(e.getProcessingEndTimeString());

    assertNull(e.getProcessingEndTimeDate());

    assertNotNull(e.getSessionID());
    assertEquals(e.getSessionID(), "1234");

    assertNotNull(e.getRequestControls());
    assertTrue(e.getRequestControls().isEmpty());

    assertNotNull(e.getRequestControlArray());
    assertEquals(e.getRequestControlArray().length, 0);

    assertNotNull(e.getResultCode());
    assertEquals(e.getResultCode(), ResultCode.SUCCESS);

    assertNull(e.getDiagnosticMessage());

    assertNotNull(e.getReferralURLs());
    assertTrue(e.getReferralURLs().isEmpty());

    assertNotNull(e.getResponseControls());
    assertTrue(e.getResponseControls().isEmpty());

    assertNotNull(e.getAuthorizationIdentityDN());
    assertDNsEqual(e.getAuthorizationIdentityDN(), "");

    assertNotNull(e.toLDAPResult());

    assertEquals(e.getProtocolVersion(), 3);

    assertNotNull(e.getBindMethod());
    assertEquals(e.getBindMethod(), "SIMPLE");

    assertNull(e.getSASLMechanism());
  }



  /**
   * Tests the behavior with an entry that represents a valid, failed SASL
   * EXTERNAL bind operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeValidFailedEXTERNALBind()
         throws Exception
  {
    final DraftChuLDAPLogSchema00BindEntry e =
         (DraftChuLDAPLogSchema00BindEntry)
         DraftChuLDAPLogSchema00Entry.decode(new Entry(
              "dn: reqStart=20160102030406.789012Z,cn=log",
              "objectClass: auditBind",
              "reqStart: 20160102030406.789012Z",
              "reqType: bind",
              "reqSession: 1234",
              "reqVersion: 3",
              "reqMethod: SASL/EXTERNAL",
              "reqDN: ",
              "reqResult: 49",
              "reqMessage: I don't trust your certificate",
              "reqAuthzID: "));

    assertNotNull(e);

    assertNotNull(e.getOperationType());
    assertEquals(e.getOperationType(), OperationType.BIND);

    assertNotNull(e.getTargetEntryDN());
    assertDNsEqual(e.getTargetEntryDN(), "");

    assertNotNull(e.getProcessingStartTimeString());
    assertEquals(e.getProcessingStartTimeString(), "20160102030406.789012Z");

    assertNotNull(e.getProcessingStartTimeDate());
    assertEquals(e.getProcessingStartTimeDate(),
         StaticUtils.decodeGeneralizedTime("20160102030406.789Z"));

    assertNull(e.getProcessingEndTimeString());

    assertNull(e.getProcessingEndTimeDate());

    assertNotNull(e.getSessionID());
    assertEquals(e.getSessionID(), "1234");

    assertNotNull(e.getRequestControls());
    assertTrue(e.getRequestControls().isEmpty());

    assertNotNull(e.getRequestControlArray());
    assertEquals(e.getRequestControlArray().length, 0);

    assertNotNull(e.getResultCode());
    assertEquals(e.getResultCode(), ResultCode.INVALID_CREDENTIALS);

    assertNotNull(e.getDiagnosticMessage());
    assertEquals(e.getDiagnosticMessage(), "I don't trust your certificate");

    assertNotNull(e.getReferralURLs());
    assertTrue(e.getReferralURLs().isEmpty());

    assertNotNull(e.getResponseControls());
    assertTrue(e.getResponseControls().isEmpty());

    assertNotNull(e.getAuthorizationIdentityDN());
    assertDNsEqual(e.getAuthorizationIdentityDN(), "");

    assertNotNull(e.toLDAPResult());

    assertEquals(e.getProtocolVersion(), 3);

    assertNotNull(e.getBindMethod());
    assertEquals(e.getBindMethod(), "SASL");

    assertNotNull(e.getSASLMechanism());
    assertEquals(e.getSASLMechanism(), "EXTERNAL");
  }



  /**
   * Tests the behavior with an entry that represents a bind operation with some
   * other method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeBindWithOtherMethod()
         throws Exception
  {
    final DraftChuLDAPLogSchema00BindEntry e =
         (DraftChuLDAPLogSchema00BindEntry)
         DraftChuLDAPLogSchema00Entry.decode(new Entry(
              "dn: reqStart=20160102030406.789012Z,cn=log",
              "objectClass: auditBind",
              "reqStart: 20160102030406.789012Z",
              "reqType: bind",
              "reqSession: 1234",
              "reqVersion: 3",
              "reqMethod: OTHER",
              "reqDN: ",
              "reqResult: 49",
              "reqMessage: I don't support that method",
              "reqAuthzID: "));

    assertNotNull(e);

    assertNotNull(e.getOperationType());
    assertEquals(e.getOperationType(), OperationType.BIND);

    assertNotNull(e.getTargetEntryDN());
    assertDNsEqual(e.getTargetEntryDN(), "");

    assertNotNull(e.getProcessingStartTimeString());
    assertEquals(e.getProcessingStartTimeString(), "20160102030406.789012Z");

    assertNotNull(e.getProcessingStartTimeDate());
    assertEquals(e.getProcessingStartTimeDate(),
         StaticUtils.decodeGeneralizedTime("20160102030406.789Z"));

    assertNull(e.getProcessingEndTimeString());

    assertNull(e.getProcessingEndTimeDate());

    assertNotNull(e.getSessionID());
    assertEquals(e.getSessionID(), "1234");

    assertNotNull(e.getRequestControls());
    assertTrue(e.getRequestControls().isEmpty());

    assertNotNull(e.getRequestControlArray());
    assertEquals(e.getRequestControlArray().length, 0);

    assertNotNull(e.getResultCode());
    assertEquals(e.getResultCode(), ResultCode.INVALID_CREDENTIALS);

    assertNotNull(e.getDiagnosticMessage());
    assertEquals(e.getDiagnosticMessage(), "I don't support that method");

    assertNotNull(e.getReferralURLs());
    assertTrue(e.getReferralURLs().isEmpty());

    assertNotNull(e.getResponseControls());
    assertTrue(e.getResponseControls().isEmpty());

    assertNotNull(e.getAuthorizationIdentityDN());
    assertDNsEqual(e.getAuthorizationIdentityDN(), "");

    assertNotNull(e.toLDAPResult());

    assertEquals(e.getProtocolVersion(), 3);

    assertNotNull(e.getBindMethod());
    assertEquals(e.getBindMethod(), "OTHER");

    assertNull(e.getSASLMechanism());
  }



  /**
   * Tests the behavior with a bind operation entry that is missing the target
   * DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeBindWithoutTargetDN()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditBind",
         "reqStart: 20160102030406.789012Z",
         "reqType: bind",
         "reqSession: 1234",
         "reqVersion: 3",
         "reqMethod: SIMPLE"));
  }



  /**
   * Tests the behavior with a bind operation entry that is missing the protocol
   * version.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeBindWithoutProtocolVersion()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditBind",
         "reqStart: 20160102030406.789012Z",
         "reqType: bind",
         "reqSession: 1234",
         "reqMethod: SIMPLE",
         "reqDN: "));
  }



  /**
   * Tests the behavior with a bind operation entry that has an invalid
   * protocol version.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeBindWithInvalidProtocolVersion()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditBind",
         "reqStart: 20160102030406.789012Z",
         "reqType: bind",
         "reqSession: 1234",
         "reqVersion: invalid",
         "reqMethod: SIMPLE",
         "reqDN: "));
  }



  /**
   * Tests the behavior with a bind operation entry that is missing the bind
   * method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeBindWithoutBindMethod()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditBind",
         "reqStart: 20160102030406.789012Z",
         "reqType: bind",
         "reqSession: 1234",
         "reqVersion: 3",
         "reqDN: "));
  }
}
