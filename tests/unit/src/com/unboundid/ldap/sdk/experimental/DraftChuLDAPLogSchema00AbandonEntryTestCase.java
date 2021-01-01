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



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.util.Base64;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the
 * {@code DraftChuLDAPLogSchema00AbandonEntry} class.
 */
public final class DraftChuLDAPLogSchema00AbandonEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with an entry that represents a valid abandon operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeValidEntry()
         throws Exception
  {
    final Control c1 = new Control("1.2.3.4", false, null);
    final Control c2 = new Control("5.6.7.8", true, new ASN1OctetString("foo"));

    final DraftChuLDAPLogSchema00AbandonEntry e =
         (DraftChuLDAPLogSchema00AbandonEntry)
         DraftChuLDAPLogSchema00Entry.decode(new Entry(
              "dn: reqStart=20160102030406.789012Z,cn=log",
              "objectClass: auditAbandon",
              "reqStart: 20160102030406.789012Z",
              "reqType: abandon",
              "reqSession: 1234",
              "reqAuthzID: cn=manager,dc=example,dc=com",
              "reqId: 5678",
              "reqControls:: " + Base64.encode(c1.encode().encode()),
              "reqControls:: " + Base64.encode(c2.encode().encode())));
    assertNotNull(e);

    assertNotNull(e.getOperationType());
    assertEquals(e.getOperationType(), OperationType.ABANDON);

    assertNull(e.getTargetEntryDN());

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
    assertEquals(e.getRequestControls(), Arrays.asList(c1, c2));

    assertNotNull(e.getRequestControlArray());
    assertEquals(e.getRequestControlArray(), new Control[] { c1, c2 });

    assertNull(e.getResultCode());

    assertNull(e.getDiagnosticMessage());

    assertNotNull(e.getReferralURLs());
    assertTrue(e.getReferralURLs().isEmpty());

    assertNotNull(e.getResponseControls());
    assertTrue(e.getResponseControls().isEmpty());


    assertNotNull(e.getAuthorizationIdentityDN());
    assertDNsEqual(e.getAuthorizationIdentityDN(),
         "cn=manager,dc=example,dc=com");

    assertNull(e.toLDAPResult());

    assertEquals(e.getIDToAbandon(), 5678);
  }



  /**
   * Tests the behavior with an entry that is missing the required request ID
   * element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeEntryWithoutRequestID()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditAbandon",
         "reqStart: 20160102030406.789012Z",
         "reqType: abandon",
         "reqSession: 1234",
         "reqAuthzID: cn=manager,dc=example,dc=com"));
  }



  /**
   * Tests the behavior with an entry that has a malformed request ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeEntryMalformedRequestID()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditAbandon",
         "reqStart: 20160102030406.789012Z",
         "reqType: abandon",
         "reqSession: 1234",
         "reqAuthzID: cn=manager,dc=example,dc=com",
         "reqId: malformed"));
  }
}
