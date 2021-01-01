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

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the
 * {@code DraftChuLDAPLogSchema00CompareEntry} class.
 */
public final class DraftChuLDAPLogSchema00CompareEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with an entry that represents a valid compare operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeValidCompare()
         throws Exception
  {
    final ASN1Sequence avaSequence = new ASN1Sequence(
         new ASN1OctetString("dc"),
         new ASN1OctetString("example"));

    final DraftChuLDAPLogSchema00CompareEntry e =
         (DraftChuLDAPLogSchema00CompareEntry)
         DraftChuLDAPLogSchema00Entry.decode(new Entry(
              "dn: reqStart=20160102030406.789012Z,cn=log",
              "objectClass: auditCompare",
              "reqStart: 20160102030406.789012Z",
              "reqType: compare",
              "reqSession: 1234",
              "reqDN: dc=example,dc=com",
              "reqAssertion:: " + Base64.encode(avaSequence.encode()),
              "reqResult: 6",
              "reqAuthzID: cn=manager,dc=example,dc=com"));

    assertNotNull(e);

    assertNotNull(e.getOperationType());
    assertEquals(e.getOperationType(), OperationType.COMPARE);

    assertNotNull(e.getTargetEntryDN());
    assertDNsEqual(e.getTargetEntryDN(),
         "dc=example,dc=com");

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
    assertEquals(e.getResultCode(), ResultCode.COMPARE_TRUE);

    assertNull(e.getDiagnosticMessage());

    assertNotNull(e.getReferralURLs());
    assertTrue(e.getReferralURLs().isEmpty());

    assertNotNull(e.getResponseControls());
    assertTrue(e.getResponseControls().isEmpty());

    assertNotNull(e.getAuthorizationIdentityDN());
    assertDNsEqual(e.getAuthorizationIdentityDN(),
         "cn=manager,dc=example,dc=com");

    assertNotNull(e.toLDAPResult());

    assertNotNull(e.getAttributeName());
    assertEquals(e.getAttributeName(), "dc");

    assertNotNull(e.getAssertionValueString());
    assertEquals(e.getAssertionValueString(), "example");

    assertNotNull(e.getAssertionValueBytes());
    assertEquals(e.getAssertionValueBytes(), "example".getBytes("UTF-8"));

    assertNotNull(e.toCompareRequest());
    assertDNsEqual(e.toCompareRequest().getDN(), "dc=example,dc=com");
    assertEquals(e.toCompareRequest().getAttributeName(), "dc");
    assertEquals(e.toCompareRequest().getAssertionValue(), "example");
  }



  /**
   * Tests the behavior with a compare operation entry that is missing the
   * target entry DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeCompareWithoutTargetDN()
         throws Exception
  {
    final ASN1Sequence avaSequence = new ASN1Sequence(
         new ASN1OctetString("dc"),
         new ASN1OctetString("example"));

    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditCompare",
         "reqStart: 20160102030406.789012Z",
         "reqType: compare",
         "reqSession: 1234",
         "reqMethod: SIMPLE",
         "reqAssertion:: " + Base64.encode(avaSequence.encode())));
  }



  /**
   * Tests the behavior with a compare operation entry that is missing the
   * attribute value assertion.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeCompareWithoutAVA()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditCompare",
         "reqStart: 20160102030406.789012Z",
         "reqType: compare",
         "reqSession: 1234",
         "reqMethod: SIMPLE",
         "reqDN: dc=example,dc=com"));
  }



  /**
   * Tests the behavior with a compare operation entry that has a malformed
   * attribute value assertion.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeCompareMalformedAVA()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditCompare",
         "reqStart: 20160102030406.789012Z",
         "reqType: compare",
         "reqSession: 1234",
         "reqMethod: SIMPLE",
         "reqDN: dc=example,dc=com",
         "reqAssertion: malformed"));
  }
}
