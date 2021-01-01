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

import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the
 * {@code DraftChuLDAPLogSchema00SearchEntry} class.
 */
public final class DraftChuLDAPLogSchema00SearchEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with an entry that represents a valid search operation
   * with the minimal set of content.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeMinimalSearch()
         throws Exception
  {
    final DraftChuLDAPLogSchema00SearchEntry e =
         (DraftChuLDAPLogSchema00SearchEntry)
         DraftChuLDAPLogSchema00Entry.decode(new Entry(
              "dn: reqStart=20160102030406.789012Z,cn=log",
              "objectClass: auditSearch",
              "reqStart: 20160102030406.789012Z",
              "reqType: search",
              "reqSession: 1234",
              "reqDN: dc=example,dc=com",
              "reqScope: base",
              "reqDerefAliases: never",
              "reqAttrsOnly: false"));

    assertNotNull(e);

    assertNotNull(e.getOperationType());
    assertEquals(e.getOperationType(), OperationType.SEARCH);

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

    assertNull(e.getResultCode());

    assertNull(e.getDiagnosticMessage());

    assertNotNull(e.getReferralURLs());
    assertTrue(e.getReferralURLs().isEmpty());

    assertNotNull(e.getResponseControls());
    assertTrue(e.getResponseControls().isEmpty());

    assertNull(e.getAuthorizationIdentityDN());

    assertNull(e.toLDAPResult());

    assertNotNull(e.getScope());
    assertEquals(e.getScope(), SearchScope.BASE);

    assertNotNull(e.getDereferencePolicy());
    assertEquals(e.getDereferencePolicy(), DereferencePolicy.NEVER);

    assertFalse(e.typesOnly());

    assertNull(e.getFilter());

    assertNull(e.getRequestedSizeLimit());

    assertNull(e.getRequestedTimeLimitSeconds());

    assertNotNull(e.getRequestedAttributes());
    assertTrue(e.getRequestedAttributes().isEmpty());

    assertNull(e.getEntriesReturned());

    assertNotNull(e.toSearchRequest());
    assertDNsEqual(e.toSearchRequest().getBaseDN(), "dc=example,dc=com");
    assertEquals(e.toSearchRequest().getScope(), SearchScope.BASE);
    assertEquals(e.toSearchRequest().getDereferencePolicy(),
         DereferencePolicy.NEVER);
    assertEquals(e.toSearchRequest().getSizeLimit(), 0);
    assertEquals(e.toSearchRequest().getTimeLimitSeconds(), 0);
    assertEquals(e.toSearchRequest().typesOnly(), false);
    assertEquals(e.toSearchRequest().getFilter(),
         Filter.createPresenceFilter("objectClass"));
    assertTrue(e.toSearchRequest().getAttributeList().isEmpty());
  }



  /**
   * Tests the behavior with an entry that represents a valid search operation
   * with a full set of content and a successful result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeFullSearchSuccess()
         throws Exception
  {
    final DraftChuLDAPLogSchema00SearchEntry e =
         (DraftChuLDAPLogSchema00SearchEntry)
         DraftChuLDAPLogSchema00Entry.decode(new Entry(
              "dn: reqStart=20160102030406.789012Z,cn=log",
              "objectClass: auditSearch",
              "reqStart: 20160102030406.789012Z",
              "reqType: search",
              "reqSession: 1234",
              "reqDN: dc=example,dc=com",
              "reqScope: one",
              "reqDerefAliases: searching",
              "reqAttrsOnly: true",
              "reqFilter: (objectClass=organizationalUnit)",
              "reqSizeLimit: 123",
              "reqTimeLimit: 456",
              "reqAttr: cn",
              "reqEntries: 789",
              "reqResult: 0"));

    assertNotNull(e);

    assertNotNull(e.getOperationType());
    assertEquals(e.getOperationType(), OperationType.SEARCH);

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

    assertNull(e.getAuthorizationIdentityDN());

    assertNotNull(e.toLDAPResult());

    assertNotNull(e.getScope());
    assertEquals(e.getScope(), SearchScope.ONE);

    assertNotNull(e.getDereferencePolicy());
    assertEquals(e.getDereferencePolicy(), DereferencePolicy.SEARCHING);

    assertTrue(e.typesOnly());

    assertNotNull(e.getFilter());
    assertEquals(e.getFilter(),
         Filter.createEqualityFilter("objectClass", "organizationalUnit"));

    assertNotNull(e.getRequestedSizeLimit());
    assertEquals(e.getRequestedSizeLimit().intValue(), 123);

    assertNotNull(e.getRequestedTimeLimitSeconds());
    assertEquals(e.getRequestedTimeLimitSeconds().intValue(), 456);

    assertNotNull(e.getRequestedAttributes());
    assertEquals(e.getRequestedAttributes(), Arrays.asList("cn"));

    assertNotNull(e.getEntriesReturned());
    assertEquals(e.getEntriesReturned().intValue(), 789);

    assertNotNull(e.toSearchRequest());
    assertDNsEqual(e.toSearchRequest().getBaseDN(), "dc=example,dc=com");
    assertEquals(e.toSearchRequest().getScope(), SearchScope.ONE);
    assertEquals(e.toSearchRequest().getDereferencePolicy(),
         DereferencePolicy.SEARCHING);
    assertEquals(e.toSearchRequest().getSizeLimit(), 123);
    assertEquals(e.toSearchRequest().getTimeLimitSeconds(), 456);
    assertEquals(e.toSearchRequest().typesOnly(), true);
    assertEquals(e.toSearchRequest().getFilter(),
         Filter.createEqualityFilter("objectClass", "organizationalUnit"));
    assertEquals(e.toSearchRequest().getAttributeList(), Arrays.asList("cn"));
  }



  /**
   * Tests the behavior with an entry that represents a valid search operation
   * with a full set of content and a failure result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeFullSearchFailure()
         throws Exception
  {
    final DraftChuLDAPLogSchema00SearchEntry e =
         (DraftChuLDAPLogSchema00SearchEntry)
         DraftChuLDAPLogSchema00Entry.decode(new Entry(
              "dn: reqStart=20160102030406.789012Z,cn=log",
              "objectClass: auditSearch",
              "reqStart: 20160102030406.789012Z",
              "reqType: search",
              "reqSession: 1234",
              "reqDN: ou=missing,dc=example,dc=com",
              "reqScope: sub",
              "reqDerefAliases: finding",
              "reqAttrsOnly: false",
              "reqFilter: (objectClass=organizationalUnit)",
              "reqSizeLimit: 123",
              "reqTimeLimit: 456",
              "reqAttr: cn",
              "reqAttr: givenName",
              "reqAttr: sn",
              "reqAttr: uid",
              "reqEntries: 0",
              "reqResult: 32",
              "reqMessage: The base DN doesn't exist",
              "reqAuthzID: cn=manager,dc=example,dc=com"));

    assertNotNull(e);

    assertNotNull(e.getOperationType());
    assertEquals(e.getOperationType(), OperationType.SEARCH);

    assertNotNull(e.getTargetEntryDN());
    assertDNsEqual(e.getTargetEntryDN(),
         "ou=missing,dc=example,dc=com");

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
    assertEquals(e.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(e.getDiagnosticMessage());
    assertEquals(e.getDiagnosticMessage(), "The base DN doesn't exist");

    assertNotNull(e.getReferralURLs());
    assertTrue(e.getReferralURLs().isEmpty());

    assertNotNull(e.getResponseControls());
    assertTrue(e.getResponseControls().isEmpty());

    assertNotNull(e.getAuthorizationIdentityDN());
    assertDNsEqual(e.getAuthorizationIdentityDN(),
         "cn=manager,dc=example,dc=com");

    assertNotNull(e.toLDAPResult());

    assertNotNull(e.getScope());
    assertEquals(e.getScope(), SearchScope.SUB);

    assertNotNull(e.getDereferencePolicy());
    assertEquals(e.getDereferencePolicy(), DereferencePolicy.FINDING);

    assertFalse(e.typesOnly());

    assertNotNull(e.getFilter());
    assertEquals(e.getFilter(),
         Filter.createEqualityFilter("objectClass", "organizationalUnit"));

    assertNotNull(e.getRequestedSizeLimit());
    assertEquals(e.getRequestedSizeLimit().intValue(), 123);

    assertNotNull(e.getRequestedTimeLimitSeconds());
    assertEquals(e.getRequestedTimeLimitSeconds().intValue(), 456);

    assertNotNull(e.getRequestedAttributes());
    assertEquals(e.getRequestedAttributes(),
         Arrays.asList("cn", "givenName", "sn", "uid"));

    assertNotNull(e.getEntriesReturned());
    assertEquals(e.getEntriesReturned().intValue(), 0);

    assertNotNull(e.toSearchRequest());
    assertDNsEqual(e.toSearchRequest().getBaseDN(),
         "ou=missing,dc=example,dc=com");
    assertEquals(e.toSearchRequest().getScope(), SearchScope.SUB);
    assertEquals(e.toSearchRequest().getDereferencePolicy(),
         DereferencePolicy.FINDING);
    assertEquals(e.toSearchRequest().getSizeLimit(), 123);
    assertEquals(e.toSearchRequest().getTimeLimitSeconds(), 456);
    assertEquals(e.toSearchRequest().typesOnly(), false);
    assertEquals(e.toSearchRequest().getFilter(),
         Filter.createEqualityFilter("objectClass", "organizationalUnit"));
    assertEquals(e.toSearchRequest().getAttributeList(),
         Arrays.asList("cn", "givenName", "sn", "uid"));
  }



  /**
   * Tests the behavior with an entry that represents a valid search operation
   * with a full set of content and a failure result.  This is just intended to
   * cover the remaining valid scope and dereference policy values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeFullSearchFailureRemainingScopeAndDerefValues()
         throws Exception
  {
    final DraftChuLDAPLogSchema00SearchEntry e =
         (DraftChuLDAPLogSchema00SearchEntry)
         DraftChuLDAPLogSchema00Entry.decode(new Entry(
              "dn: reqStart=20160102030406.789012Z,cn=log",
              "objectClass: auditSearch",
              "reqStart: 20160102030406.789012Z",
              "reqType: search",
              "reqSession: 1234",
              "reqDN: ou=missing,dc=example,dc=com",
              "reqScope: subord",
              "reqDerefAliases: always",
              "reqAttrsOnly: false",
              "reqFilter: (objectClass=organizationalUnit)",
              "reqSizeLimit: 123",
              "reqTimeLimit: 456",
              "reqAttr: cn",
              "reqAttr: givenName",
              "reqAttr: sn",
              "reqAttr: uid",
              "reqEntries: 0",
              "reqResult: 32",
              "reqMessage: The base DN doesn't exist",
              "reqAuthzID: cn=manager,dc=example,dc=com"));

    assertNotNull(e);

    assertNotNull(e.getOperationType());
    assertEquals(e.getOperationType(), OperationType.SEARCH);

    assertNotNull(e.getTargetEntryDN());
    assertDNsEqual(e.getTargetEntryDN(),
         "ou=missing,dc=example,dc=com");

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
    assertEquals(e.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(e.getDiagnosticMessage());
    assertEquals(e.getDiagnosticMessage(), "The base DN doesn't exist");

    assertNotNull(e.getReferralURLs());
    assertTrue(e.getReferralURLs().isEmpty());

    assertNotNull(e.getResponseControls());
    assertTrue(e.getResponseControls().isEmpty());

    assertNotNull(e.getAuthorizationIdentityDN());
    assertDNsEqual(e.getAuthorizationIdentityDN(),
         "cn=manager,dc=example,dc=com");

    assertNotNull(e.toLDAPResult());

    assertNotNull(e.getScope());
    assertEquals(e.getScope(), SearchScope.SUBORDINATE_SUBTREE);

    assertNotNull(e.getDereferencePolicy());
    assertEquals(e.getDereferencePolicy(), DereferencePolicy.ALWAYS);

    assertFalse(e.typesOnly());

    assertNotNull(e.getFilter());
    assertEquals(e.getFilter(),
         Filter.createEqualityFilter("objectClass", "organizationalUnit"));

    assertNotNull(e.getRequestedSizeLimit());
    assertEquals(e.getRequestedSizeLimit().intValue(), 123);

    assertNotNull(e.getRequestedTimeLimitSeconds());
    assertEquals(e.getRequestedTimeLimitSeconds().intValue(), 456);

    assertNotNull(e.getRequestedAttributes());
    assertEquals(e.getRequestedAttributes(),
         Arrays.asList("cn", "givenName", "sn", "uid"));

    assertNotNull(e.getEntriesReturned());
    assertEquals(e.getEntriesReturned().intValue(), 0);

    assertNotNull(e.toSearchRequest());
    assertDNsEqual(e.toSearchRequest().getBaseDN(),
         "ou=missing,dc=example,dc=com");
    assertEquals(e.toSearchRequest().getScope(),
         SearchScope.SUBORDINATE_SUBTREE);
    assertEquals(e.toSearchRequest().getDereferencePolicy(),
         DereferencePolicy.ALWAYS);
    assertEquals(e.toSearchRequest().getSizeLimit(), 123);
    assertEquals(e.toSearchRequest().getTimeLimitSeconds(), 456);
    assertEquals(e.toSearchRequest().typesOnly(), false);
    assertEquals(e.toSearchRequest().getFilter(),
         Filter.createEqualityFilter("objectClass", "organizationalUnit"));
    assertEquals(e.toSearchRequest().getAttributeList(),
         Arrays.asList("cn", "givenName", "sn", "uid"));
  }



  /**
   * Tests the behavior with a search operation entry that is missing the
   * target entry DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSearchWithoutTargetDN()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditSearch",
         "reqStart: 20160102030406.789012Z",
         "reqType: search",
         "reqSession: 1234",
         "reqScope: base",
         "reqDerefAliases: never",
         "reqAttrsOnly: false"));
  }



  /**
   * Tests the behavior with a search operation entry that is missing the scope.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSearchWithoutScope()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditSearch",
         "reqStart: 20160102030406.789012Z",
         "reqType: search",
         "reqSession: 1234",
         "reqDN: dc=example,dc=com",
         "reqDerefAliases: never",
         "reqAttrsOnly: false"));
  }



  /**
   * Tests the behavior with a search operation entry with an invalid scope.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSearchInvalidScope()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditSearch",
         "reqStart: 20160102030406.789012Z",
         "reqType: search",
         "reqSession: 1234",
         "reqDN: dc=example,dc=com",
         "reqScope: invalid",
         "reqDerefAliases: never",
         "reqAttrsOnly: false"));
  }



  /**
   * Tests the behavior with a search operation entry that is missing the
   * dereference policy.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSearchWithoutDeref()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditSearch",
         "reqStart: 20160102030406.789012Z",
         "reqType: search",
         "reqSession: 1234",
         "reqDN: dc=example,dc=com",
         "reqScope: base",
         "reqAttrsOnly: false"));
  }



  /**
   * Tests the behavior with a search operation entry that has an invalid
   * dereference policy.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSearchInvalidDeref()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditSearch",
         "reqStart: 20160102030406.789012Z",
         "reqType: search",
         "reqSession: 1234",
         "reqDN: dc=example,dc=com",
         "reqScope: base",
         "reqDerefAliases: invalid",
         "reqAttrsOnly: false"));
  }



  /**
   * Tests the behavior with a search operation entry that is missing the types
   * only flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSearchMissingTypesOnly()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditSearch",
         "reqStart: 20160102030406.789012Z",
         "reqType: search",
         "reqSession: 1234",
         "reqDN: dc=example,dc=com",
         "reqScope: base",
         "reqDerefAliases: never"));
  }



  /**
   * Tests the behavior with a search operation entry that has an invalid value
   * for the types only flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSearchInvalidTypesOnly()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditSearch",
         "reqStart: 20160102030406.789012Z",
         "reqType: search",
         "reqSession: 1234",
         "reqDN: dc=example,dc=com",
         "reqScope: base",
         "reqDerefAliases: never",
         "reqAttrsOnly: invalid"));
  }



  /**
   * Tests the behavior with a search operation entry that has an invalid
   * filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSearchInvalidFilter()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditSearch",
         "reqStart: 20160102030406.789012Z",
         "reqType: search",
         "reqSession: 1234",
         "reqDN: dc=example,dc=com",
         "reqScope: base",
         "reqDerefAliases: never",
         "reqAttrsOnly: false",
         "reqFilter: invalid"));
  }



  /**
   * Tests the behavior with a search operation entry that has an invalid size
   * limit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSearchInvalidSizeLimit()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditSearch",
         "reqStart: 20160102030406.789012Z",
         "reqType: search",
         "reqSession: 1234",
         "reqDN: dc=example,dc=com",
         "reqScope: base",
         "reqDerefAliases: never",
         "reqAttrsOnly: false",
         "reqSizeLimit: invalid"));
  }



  /**
   * Tests the behavior with a search operation entry that has an invalid time
   * limit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSearchInvalidTimeLimit()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditSearch",
         "reqStart: 20160102030406.789012Z",
         "reqType: search",
         "reqSession: 1234",
         "reqDN: dc=example,dc=com",
         "reqScope: base",
         "reqDerefAliases: never",
         "reqAttrsOnly: false",
         "reqTimeLimit: invalid"));
  }



  /**
   * Tests the behavior with a search operation entry that has an invalid
   * entries returned.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSearchInvalidEntriesReturned()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditSearch",
         "reqStart: 20160102030406.789012Z",
         "reqType: search",
         "reqSession: 1234",
         "reqDN: dc=example,dc=com",
         "reqScope: base",
         "reqDerefAliases: never",
         "reqAttrsOnly: false",
         "reqEntries: invalid"));
  }
}
