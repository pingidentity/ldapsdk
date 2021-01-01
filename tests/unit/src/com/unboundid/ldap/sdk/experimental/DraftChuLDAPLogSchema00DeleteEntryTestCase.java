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

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the
 * {@code DraftChuLDAPLogSchema00DeleteEntry} class.
 */
public final class DraftChuLDAPLogSchema00DeleteEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with an entry that represents a valid delete operation
   * without any former attribute values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeValidDeleteNoFormerAttributes()
         throws Exception
  {
    final DraftChuLDAPLogSchema00DeleteEntry e =
         (DraftChuLDAPLogSchema00DeleteEntry)
         DraftChuLDAPLogSchema00Entry.decode(new Entry(
              "dn: reqStart=20160102030406.789012Z,cn=log",
              "objectClass: auditDelete",
              "reqStart: 20160102030406.789012Z",
              "reqType: delete",
              "reqSession: 1234",
              "reqDN: dc=example,dc=com",
              "reqResult: 0",
              "reqAuthzID: cn=manager,dc=example,dc=com"));

    assertNotNull(e);

    assertNotNull(e.getOperationType());
    assertEquals(e.getOperationType(), OperationType.DELETE);

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

    assertNotNull(e.getDeletedAttributes());
    assertTrue(e.getDeletedAttributes().isEmpty());

    assertNotNull(e.toDeleteRequest());
    assertDNsEqual(e.toDeleteRequest().getDN(), "dc=example,dc=com");
  }



  /**
   * Tests the behavior with an entry that represents a valid delete operation
   * that includes former attribute values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeValidDeleteWithFormerAttributes()
         throws Exception
  {
    final DraftChuLDAPLogSchema00DeleteEntry e =
         (DraftChuLDAPLogSchema00DeleteEntry)
         DraftChuLDAPLogSchema00Entry.decode(new Entry(
              "dn: reqStart=20160102030406.789012Z,cn=log",
              "objectClass: auditDelete",
              "reqStart: 20160102030406.789012Z",
              "reqType: delete",
              "reqSession: 1234",
              "reqDN: dc=example,dc=com",
              "reqOld: objectClass: top",
              "reqOld: objectClass: domain",
              "reqOld: dc: example",
              "reqOld:: " + Base64.encode("description: "),
              "reqResult: 0",
              "reqAuthzID: cn=manager,dc=example,dc=com"));

    assertNotNull(e);

    assertNotNull(e.getOperationType());
    assertEquals(e.getOperationType(), OperationType.DELETE);

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

    assertNotNull(e.getDeletedAttributes());
    assertEquals(e.getDeletedAttributes(),
         Arrays.asList(
              new Attribute("objectClass" , "top", "domain"),
              new Attribute("dc", "example"),
              new Attribute("description", "")));

    assertNotNull(e.toDeleteRequest());
    assertDNsEqual(e.toDeleteRequest().getDN(), "dc=example,dc=com");
  }



  /**
   * Tests the behavior with a delete operation entry that is missing the
   * target entry DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeDeleteWithoutTargetDN()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditDelete",
         "reqStart: 20160102030406.789012Z",
         "reqType: delete",
         "reqSession: 1234"));
  }



  /**
   * Tests the behavior with a delete operation entry that is missing a colon in
   * a former attribute descriptor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeDeleteFormerAttributeWithoutColon()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditDelete",
         "reqStart: 20160102030406.789012Z",
         "reqType: delete",
         "reqSession: 1234",
         "reqDN: dc=example,dc=com",
         "reqOld: objectClass: top",
         "reqOld: objectClass domain",
         "reqOld: dc: example"));
  }



  /**
   * Tests the behavior with a delete operation entry in which a former
   * attribute descriptor starts with a colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeDeleteFormerAttributeStartsWithColon()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditDelete",
         "reqStart: 20160102030406.789012Z",
         "reqType: delete",
         "reqSession: 1234",
         "reqDN: dc=example,dc=com",
         "reqOld: objectClass: top",
         "reqOld: objectClass: domain",
         "reqOld: dc: example",
         "reqOld: : foo"));
  }



  /**
   * Tests the behavior with a delete operation entry in which a former
   * attribute descriptor is missing the space between the colon and value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeDeleteFormerAttributeMissingSpace()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditDelete",
         "reqStart: 20160102030406.789012Z",
         "reqType: delete",
         "reqSession: 1234",
         "reqDN: dc=example,dc=com",
         "reqOld: objectClass: top",
         "reqOld: objectClass: domain",
         "reqOld: dc: example",
         "reqOld: description:foo"));
  }
}
