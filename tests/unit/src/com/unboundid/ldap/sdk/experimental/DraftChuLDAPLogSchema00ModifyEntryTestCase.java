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
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the
 * {@code DraftChuLDAPLogSchema00ModifyEntry} class.
 */
public final class DraftChuLDAPLogSchema00ModifyEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with an entry that represents a valid modify operation
   * without any former attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeValidModifyWithoutFormerAttributes()
         throws Exception
  {
    final DraftChuLDAPLogSchema00ModifyEntry e =
         (DraftChuLDAPLogSchema00ModifyEntry)
         DraftChuLDAPLogSchema00Entry.decode(new Entry(
              "dn: reqStart=20160102030406.789012Z,cn=log",
              "objectClass: auditModify",
              "reqStart: 20160102030406.789012Z",
              "reqType: modify",
              "reqSession: 1234",
              "reqDN: uid=test.user,ou=People,dc=example,dc=com",
              "reqMod: attrA:+ valueA1",
              "reqMod: attrA:+ valueA2",
              "reqMod: attrB:+ valueB",
              "reqMod: attrC:-",
              "reqMod: attrD:- valueD1",
              "reqMod: attrD:- valueD2",
              "reqMod: attrE:- valueE",
              "reqMod: attrF:=",
              "reqMod: attrG:= valueG1",
              "reqMod: attrG:= valueG2",
              "reqMod: attrH:= valueH",
              "reqMod: attrI:# 1",
              "reqResult: 0",
              "reqAuthzID: cn=manager,dc=example,dc=com"));

    assertNotNull(e);

    assertNotNull(e.getOperationType());
    assertEquals(e.getOperationType(), OperationType.MODIFY);

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
    assertDNsEqual(e.getAuthorizationIdentityDN(),
         "cn=manager,dc=example,dc=com");

    assertNotNull(e.toLDAPResult());

    assertNotNull(e.getModifications());
    assertEquals(e.getModifications(),
         Arrays.asList(
              new Modification(ModificationType.ADD, "attrA", "valueA1",
                   "valueA2"),
              new Modification(ModificationType.ADD, "attrB", "valueB"),
              new Modification(ModificationType.DELETE, "attrC"),
              new Modification(ModificationType.DELETE, "attrD", "valueD1",
                   "valueD2"),
              new Modification(ModificationType.DELETE, "attrE", "valueE"),
              new Modification(ModificationType.REPLACE, "attrF"),
              new Modification(ModificationType.REPLACE, "attrG", "valueG1",
                   "valueG2"),
              new Modification(ModificationType.REPLACE, "attrH", "valueH"),
              new Modification(ModificationType.INCREMENT, "attrI", "1")));

    assertNotNull(e.getFormerAttributes());
    assertTrue(e.getFormerAttributes().isEmpty());

    assertNotNull(e.toModifyRequest());
    assertDNsEqual(e.toModifyRequest().getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(e.toModifyRequest().getModifications(),
         Arrays.asList(
              new Modification(ModificationType.ADD, "attrA", "valueA1",
                   "valueA2"),
              new Modification(ModificationType.ADD, "attrB", "valueB"),
              new Modification(ModificationType.DELETE, "attrC"),
              new Modification(ModificationType.DELETE, "attrD", "valueD1",
                   "valueD2"),
              new Modification(ModificationType.DELETE, "attrE", "valueE"),
              new Modification(ModificationType.REPLACE, "attrF"),
              new Modification(ModificationType.REPLACE, "attrG", "valueG1",
                   "valueG2"),
              new Modification(ModificationType.REPLACE, "attrH", "valueH"),
              new Modification(ModificationType.INCREMENT, "attrI", "1")));
  }



  /**
   * Tests the behavior with an entry that represents a valid modify operation
   * with former attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeValidModifyWithFormerAttributes()
         throws Exception
  {
    final DraftChuLDAPLogSchema00ModifyEntry e =
         (DraftChuLDAPLogSchema00ModifyEntry)
         DraftChuLDAPLogSchema00Entry.decode(new Entry(
              "dn: reqStart=20160102030406.789012Z,cn=log",
              "objectClass: auditModify",
              "reqStart: 20160102030406.789012Z",
              "reqType: modify",
              "reqSession: 1234",
              "reqDN: uid=test.user,ou=People,dc=example,dc=com",
              "reqMod: attrA:+ valueA1",
              "reqMod: attrA:+ valueA2",
              "reqMod: attrB:+ valueB",
              "reqMod: attrC:-",
              "reqMod: attrD:- valueD1",
              "reqMod: attrD:- valueD2",
              "reqMod: attrE:- valueE",
              "reqMod: attrF:=",
              "reqMod: attrG:= valueG1",
              "reqMod: attrG:= valueG2",
              "reqMod: attrH:= valueH",
              "reqMod: attrI:# 1",
              "reqOld: attrC: valueC1",
              "reqOld: attrC: valueC2",
              "reqOld: attrE: valueE",
              "reqOld: attrF: valueF",
              "reqOld: attrG: valueG",
              "reqOld: attrH: valueH1",
              "reqOld: attrH: valueH2",
              "reqOld: attrI: 123",
              "reqResult: 0",
              "reqAuthzID: cn=manager,dc=example,dc=com"));

    assertNotNull(e);

    assertNotNull(e.getOperationType());
    assertEquals(e.getOperationType(), OperationType.MODIFY);

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
    assertDNsEqual(e.getAuthorizationIdentityDN(),
         "cn=manager,dc=example,dc=com");

    assertNotNull(e.toLDAPResult());

    assertNotNull(e.getModifications());
    assertEquals(e.getModifications(),
         Arrays.asList(
              new Modification(ModificationType.ADD, "attrA", "valueA1",
                   "valueA2"),
              new Modification(ModificationType.ADD, "attrB", "valueB"),
              new Modification(ModificationType.DELETE, "attrC"),
              new Modification(ModificationType.DELETE, "attrD", "valueD1",
                   "valueD2"),
              new Modification(ModificationType.DELETE, "attrE", "valueE"),
              new Modification(ModificationType.REPLACE, "attrF"),
              new Modification(ModificationType.REPLACE, "attrG", "valueG1",
                   "valueG2"),
              new Modification(ModificationType.REPLACE, "attrH", "valueH"),
              new Modification(ModificationType.INCREMENT, "attrI", "1")));

    assertNotNull(e.getFormerAttributes());
    assertEquals(e.getFormerAttributes(),
         Arrays.asList(
              new Attribute("attrC", "valueC1", "valueC2"),
              new Attribute("attrE", "valueE"),
              new Attribute("attrF", "valueF"),
              new Attribute("attrG", "valueG"),
              new Attribute("attrH", "valueH1", "valueH2"),
              new Attribute("attrI", "123")));

    assertNotNull(e.toModifyRequest());
    assertDNsEqual(e.toModifyRequest().getDN(),
         "uid=test.user,ou=People,dc=example,dc=com");
    assertEquals(e.toModifyRequest().getModifications(),
         Arrays.asList(
              new Modification(ModificationType.ADD, "attrA", "valueA1",
                   "valueA2"),
              new Modification(ModificationType.ADD, "attrB", "valueB"),
              new Modification(ModificationType.DELETE, "attrC"),
              new Modification(ModificationType.DELETE, "attrD", "valueD1",
                   "valueD2"),
              new Modification(ModificationType.DELETE, "attrE", "valueE"),
              new Modification(ModificationType.REPLACE, "attrF"),
              new Modification(ModificationType.REPLACE, "attrG", "valueG1",
                   "valueG2"),
              new Modification(ModificationType.REPLACE, "attrH", "valueH"),
              new Modification(ModificationType.INCREMENT, "attrI", "1")));
  }



  /**
   * Tests the behavior with a modify operation entry that is missing the
   * target entry DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeModifyWithoutTargetDN()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditModify",
         "reqStart: 20160102030406.789012Z",
         "reqType: modify",
         "reqSession: 1234",
         "reqMod: description:= foo",
         "reqOld: description: bar"));
  }



  /**
   * Tests the behavior with a modify operation entry that is missing the
   * set of modifications.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeModifyWithoutModifications()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditModify",
         "reqStart: 20160102030406.789012Z",
         "reqType: modify",
         "reqSession: 1234",
         "reqDN: uid=test.user,ou=People,dc=example,dc=com",
         "reqOld: description: bar"));
  }



  /**
   * Tests the behavior with a modify operation entry that has a modification
   * descriptor without a colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeModifyModificationWithoutColon()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditModify",
         "reqStart: 20160102030406.789012Z",
         "reqType: modify",
         "reqSession: 1234",
         "reqDN: uid=test.user,ou=People,dc=example,dc=com",
         "reqMod: description= foo",
         "reqOld: description: bar"));
  }



  /**
   * Tests the behavior with a modify operation entry that has a modification
   * descriptor that starts with a colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeModifyModificationEndsWithColon()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditModify",
         "reqStart: 20160102030406.789012Z",
         "reqType: modify",
         "reqSession: 1234",
         "reqDN: uid=test.user,ou=People,dc=example,dc=com",
         "reqMod: := foo",
         "reqOld: description: bar"));
  }



  /**
   * Tests the behavior with a modify operation entry that has a modification
   * descriptor that ends with the colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeModifyEndsWithColon()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditModify",
         "reqStart: 20160102030406.789012Z",
         "reqType: modify",
         "reqSession: 1234",
         "reqDN: uid=test.user,ou=People,dc=example,dc=com",
         "reqMod: description:",
         "reqOld: description: bar"));
  }



  /**
   * Tests the behavior with a modify operation entry that has a modification
   * descriptor that has an invalid change type indicator.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeModifyInvalidChangeType()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditModify",
         "reqStart: 20160102030406.789012Z",
         "reqType: modify",
         "reqSession: 1234",
         "reqDN: uid=test.user,ou=People,dc=example,dc=com",
         "reqMod: description:X foo",
         "reqOld: description: bar"));
  }



  /**
   * Tests the behavior with a modify operation entry that is missing the space
   * between the change type indicator and the value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeModifyMissingSpaceAfterChangeType()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditModify",
         "reqStart: 20160102030406.789012Z",
         "reqType: modify",
         "reqSession: 1234",
         "reqDN: uid=test.user,ou=People,dc=example,dc=com",
         "reqMod: description:=foo",
         "reqOld: description: bar"));
  }



  /**
   * Tests the behavior with a modify operation entry that is missing a required
   * modification value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeModifyMissingModificationValue()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditModify",
         "reqStart: 20160102030406.789012Z",
         "reqType: modify",
         "reqSession: 1234",
         "reqDN: uid=test.user,ou=People,dc=example,dc=com",
         "reqMod: description:+",
         "reqOld: description: bar"));
  }



  /**
   * Tests the behavior with a modify operation entry in which a former
   * attribute is missing a colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeModifyFormerAttributeWithoutColon()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditModify",
         "reqStart: 20160102030406.789012Z",
         "reqType: modify",
         "reqSession: 1234",
         "reqDN: uid=test.user,ou=People,dc=example,dc=com",
         "reqMod: description:= foo",
         "reqOld: description"));
  }



  /**
   * Tests the behavior with a modify operation entry in which a former
   * attribute starts with a colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeModifyFormerAttributeStartsWithColon()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditModify",
         "reqStart: 20160102030406.789012Z",
         "reqType: modify",
         "reqSession: 1234",
         "reqDN: uid=test.user,ou=People,dc=example,dc=com",
         "reqMod: description:= foo",
         "reqOld: : bar"));
  }



  /**
   * Tests the behavior with a modify operation entry in which a former
   * attribute ends with the colon.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeModifyFormerAttributeEndsWithColon()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditModify",
         "reqStart: 20160102030406.789012Z",
         "reqType: modify",
         "reqSession: 1234",
         "reqDN: uid=test.user,ou=People,dc=example,dc=com",
         "reqMod: description:= foo",
         "reqOld: description:"));
  }



  /**
   * Tests the behavior with a modify operation entry in which a former
   * attribute is missing the space between the colon and the value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeModifyFormerAttributeMissingSpace()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditModify",
         "reqStart: 20160102030406.789012Z",
         "reqType: modify",
         "reqSession: 1234",
         "reqDN: uid=test.user,ou=People,dc=example,dc=com",
         "reqMod: description:= foo",
         "reqOld: description:bar"));
  }
}
