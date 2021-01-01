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
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the
 * {@code DraftChuLDAPLogSchema00AddEntry} class.
 */
public final class DraftChuLDAPLogSchema00AddEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with an entry that represents a valid add operation with
   * only request information provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeValidEntryRequestOnly()
         throws Exception
  {
    final Control c1 = new Control("1.2.3.4", false, null);
    final Control c2 = new Control("5.6.7.8", true, new ASN1OctetString("foo"));

    final DraftChuLDAPLogSchema00AddEntry e =
         (DraftChuLDAPLogSchema00AddEntry)
         DraftChuLDAPLogSchema00Entry.decode(new Entry(
              "dn: reqStart=20160102030406.789012Z,cn=log",
              "objectClass: auditAdd",
              "reqStart: 20160102030406.789012Z",
              "reqType: add",
              "reqSession: 1234",
              "reqDN: dc=example,dc=com",
              "reqMod: objectClass:+ domain",
              "reqMod: dc:+ example",
              "reqMod:: " + Base64.encode("description:+ "),
              "reqControls:: " + Base64.encode(c1.encode().encode()),
              "reqControls:: " + Base64.encode(c2.encode().encode())));

    assertNotNull(e);

    assertNotNull(e.getOperationType());
    assertEquals(e.getOperationType(), OperationType.ADD);

    assertNotNull(e.getTargetEntryDN());
    assertDNsEqual(e.getTargetEntryDN(), "dc=example,dc=com");

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

    assertNull(e.getAuthorizationIdentityDN());

    assertNull(e.toLDAPResult());

    assertNotNull(e.getAddAttributes());
    assertEquals(e.getAddAttributes(),
         Arrays.asList(new Attribute("objectClass", "domain"),
              new Attribute("dc", "example"),
              new Attribute("description", "")));

    assertNotNull(e.toAddRequest());
  }



  /**
   * Tests the behavior with an entry that represents a valid add operation with
   * request and response information for a successful operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeValidEntryRequestAndResponseSuccess()
         throws Exception
  {
    final DraftChuLDAPLogSchema00AddEntry e =
         (DraftChuLDAPLogSchema00AddEntry)
         DraftChuLDAPLogSchema00Entry.decode(new Entry(
              "dn: reqStart=20160102030406.789012Z,cn=log",
              "objectClass: auditAdd",
              "reqStart: 20160102030406.789012Z",
              "reqEnd: 20160102030407.123456Z",
              "reqType: add",
              "reqSession: 1234",
              "reqDN: dc=example,dc=com",
              "reqMod: objectClass:+ top",
              "reqMod: objectClass:+ domain",
              "reqMod: dc:+ example",
              "reqResult: 0",
              "reqAuthzID: cn=manager,dc=example,dc=com"));

    assertNotNull(e);

    assertNotNull(e.getOperationType());
    assertEquals(e.getOperationType(), OperationType.ADD);

    assertNotNull(e.getTargetEntryDN());
    assertDNsEqual(e.getTargetEntryDN(), "dc=example,dc=com");

    assertNotNull(e.getProcessingStartTimeString());
    assertEquals(e.getProcessingStartTimeString(), "20160102030406.789012Z");

    assertNotNull(e.getProcessingStartTimeDate());
    assertEquals(e.getProcessingStartTimeDate(),
         StaticUtils.decodeGeneralizedTime("20160102030406.789Z"));

    assertNotNull(e.getProcessingEndTimeString());
    assertEquals(e.getProcessingEndTimeString(), "20160102030407.123456Z");

    assertNotNull(e.getProcessingEndTimeDate());
    assertEquals(e.getProcessingEndTimeDate(),
         StaticUtils.decodeGeneralizedTime("20160102030407.123Z"));

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
    assertDNsEqual(e.getAuthorizationIdentityDN(),
         "cn=manager,dc=example,dc=com");

    assertNotNull(e.toLDAPResult());

    assertNotNull(e.getAddAttributes());
    assertEquals(e.getAddAttributes(),
         Arrays.asList(new Attribute("objectClass", "top", "domain"),
              new Attribute("dc", "example")));

    assertNotNull(e.toAddRequest());
  }



  /**
   * Tests the behavior with an entry that represents a valid add operation with
   * request and response information for a failed operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeValidEntryRequestAndResponseFailure()
         throws Exception
  {
    final Control c1 = new Control("1.2.3.4", false, null);
    final Control c2 = new Control("5.6.7.8", true, new ASN1OctetString("foo"));

    final DraftChuLDAPLogSchema00AddEntry e =
         (DraftChuLDAPLogSchema00AddEntry)
         DraftChuLDAPLogSchema00Entry.decode(new Entry(
              "dn: reqStart=20160102030406.789012Z,cn=log",
              "objectClass: auditAdd",
              "reqStart: 20160102030406.789012Z",
              "reqEnd: 20160102030407.123456Z",
              "reqType: add",
              "reqSession: 1234",
              "reqDN: dc=example,dc=com",
              "reqMod: objectClass:+ top",
              "reqMod: objectClass:+ domain",
              "reqMod: dc:+ example",
              "reqResult: 10",
              "reqMessage: Go somewhere else",
              "reqReferral: ldap://ds1.example.com/dc=example,dc=com",
              "reqReferral: ldap://ds2.example.com/dc=example,dc=com",
              "reqAuthzID: cn=manager,dc=example,dc=com",
              "reqRespControls:: " + Base64.encode(c1.encode().encode()),
              "reqRespControls:: " + Base64.encode(c2.encode().encode())));

    assertNotNull(e);

    assertNotNull(e.getOperationType());
    assertEquals(e.getOperationType(), OperationType.ADD);

    assertNotNull(e.getTargetEntryDN());
    assertDNsEqual(e.getTargetEntryDN(), "dc=example,dc=com");

    assertNotNull(e.getProcessingStartTimeString());
    assertEquals(e.getProcessingStartTimeString(), "20160102030406.789012Z");

    assertNotNull(e.getProcessingStartTimeDate());
    assertEquals(e.getProcessingStartTimeDate(),
         StaticUtils.decodeGeneralizedTime("20160102030406.789Z"));

    assertNotNull(e.getProcessingEndTimeString());
    assertEquals(e.getProcessingEndTimeString(), "20160102030407.123456Z");

    assertNotNull(e.getProcessingEndTimeDate());
    assertEquals(e.getProcessingEndTimeDate(),
         StaticUtils.decodeGeneralizedTime("20160102030407.123Z"));

    assertNotNull(e.getSessionID());
    assertEquals(e.getSessionID(), "1234");

    assertNotNull(e.getRequestControls());
    assertTrue(e.getRequestControls().isEmpty());

    assertNotNull(e.getRequestControlArray());
    assertEquals(e.getRequestControlArray().length, 0);

    assertNotNull(e.getResultCode());
    assertEquals(e.getResultCode(), ResultCode.REFERRAL);

    assertNotNull(e.getDiagnosticMessage());
    assertEquals(e.getDiagnosticMessage(), "Go somewhere else");

    assertNotNull(e.getReferralURLs());
    assertEquals(e.getReferralURLs(),
         Arrays.asList("ldap://ds1.example.com/dc=example,dc=com",
                       "ldap://ds2.example.com/dc=example,dc=com"));

    assertNotNull(e.getResponseControls());
    assertEquals(e.getResponseControls(), Arrays.asList(c1, c2));

    assertNotNull(e.getAuthorizationIdentityDN());
    assertDNsEqual(e.getAuthorizationIdentityDN(),
         "cn=manager,dc=example,dc=com");

    assertNotNull(e.toLDAPResult());

    assertNotNull(e.getAddAttributes());
    assertEquals(e.getAddAttributes(),
         Arrays.asList(new Attribute("objectClass", "top", "domain"),
              new Attribute("dc", "example")));

    assertNotNull(e.toAddRequest());
  }



  /**
   * Tests the behavior when trying to decode a request entry that doesn't
   * include a DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeRequestWithoutDN()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditAdd",
         "reqStart: 20160102030406.789012Z",
         "reqType: add",
         "reqSession: 1234",
         "reqMod: objectClass:+ domain",
         "reqMod: dc:+ example"));
  }



  /**
   * Tests the behavior when trying to decode a request entry that doesn't
   * include any attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeRequestWithoutAttributes()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditAdd",
         "reqStart: 20160102030406.789012Z",
         "reqType: add",
         "reqSession: 1234",
         "reqDN: dc=example,dc=com"));
  }



  /**
   * Tests the behavior when trying to decode a request entry that has an
   * attribute definition that is missing a colon to separate the name from the
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeRequestAttributeWithoutColon()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditAdd",
         "reqStart: 20160102030406.789012Z",
         "reqType: add",
         "reqSession: 1234",
         "reqDN: dc=example,dc=com",
         "reqMod: objectClass+ domain",
         "reqMod: dc:+ example"));
  }



  /**
   * Tests the behavior when trying to decode a request entry that has an
   * attribute definition that starts with a colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeRequestAttributeStartsWithColon()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditAdd",
         "reqStart: 20160102030406.789012Z",
         "reqType: add",
         "reqSession: 1234",
         "reqDN: dc=example,dc=com",
         "reqMod: :+ domain",
         "reqMod: dc:+ example"));
  }



  /**
   * Tests the behavior when trying to decode a request entry that has an
   * attribute definition that does not have a plus sign immediately after the
   * colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeRequestAttributeWithoutPlus()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditAdd",
         "reqStart: 20160102030406.789012Z",
         "reqType: add",
         "reqSession: 1234",
         "reqDN: dc=example,dc=com",
         "reqMod: objectClass:= domain",
         "reqMod: dc:+ example"));
  }



  /**
   * Tests the behavior when trying to decode a request entry that has an
   * attribute definition that does not have a space immediately after the plus
   * sign.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeRequestAttributeNoSpaceAfterPlus()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditAdd",
         "reqStart: 20160102030406.789012Z",
         "reqType: add",
         "reqSession: 1234",
         "reqDN: dc=example,dc=com",
         "reqMod: objectClass:+domain",
         "reqMod: dc:+ example"));
  }
}
