/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.CompareResult;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.LDAPURL;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.PLAINBindRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.controls.AssertionRequestControl;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityRequestControl;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityResponseControl;
import com.unboundid.ldap.sdk.controls.DraftLDUPSubentriesRequestControl;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.controls.PermissiveModifyRequestControl;
import com.unboundid.ldap.sdk.controls.PostReadRequestControl;
import com.unboundid.ldap.sdk.controls.PostReadResponseControl;
import com.unboundid.ldap.sdk.controls.PreReadRequestControl;
import com.unboundid.ldap.sdk.controls.PreReadResponseControl;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV1RequestControl;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV2RequestControl;
import com.unboundid.ldap.sdk.controls.RFC3672SubentriesRequestControl;
import com.unboundid.ldap.sdk.controls.ServerSideSortRequestControl;
import com.unboundid.ldap.sdk.controls.ServerSideSortResponseControl;
import com.unboundid.ldap.sdk.controls.SimplePagedResultsControl;
import com.unboundid.ldap.sdk.controls.SortKey;
import com.unboundid.ldap.sdk.controls.SubtreeDeleteRequestControl;
import com.unboundid.ldap.sdk.controls.VirtualListViewRequestControl;
import com.unboundid.ldap.sdk.controls.VirtualListViewResponseControl;
import com.unboundid.ldap.sdk.experimental.
            DraftZeilengaLDAPNoOp12RequestControl;



/**
 * This class provides a set of test cases to cover the in-memory directory
 * server's support for controls.
 */
public final class InMemoryDirectoryControlsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the assertion request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAssertionControl()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();


    // Test an add with a filter that doesn't match.
    final AddRequest addRequest = new AddRequest(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test");
    addRequest.setControls(new AssertionRequestControl("(description=*)"));

    try
    {
      conn.add(addRequest);
      fail("Expected an exception from an add with a non-matching assertion " +
           "filter");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.ASSERTION_FAILED);
    }

    // Test the add again with a matching filter.
    addRequest.setControls(new AssertionRequestControl("(ou=test)"));

    final LDAPResult addResult = conn.add(addRequest);
    assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);


    // Test a compare with a filter that doesn't match.
    final CompareRequest compareRequest = new CompareRequest(
         "uid=test.user,ou=People,dc=example,dc=com", "givenName", "Test");
    compareRequest.setControls(new AssertionRequestControl("(description=*)"));

    try
    {
      conn.compare(compareRequest);
      fail("Expected an exception from a compare with a non-matching " +
           "assertion filter");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.ASSERTION_FAILED);
    }

    // Test the compare again with a matching filter.
    compareRequest.setControls(new AssertionRequestControl("(uid=test.user)"));

    final CompareResult compareResult = conn.compare(compareRequest);
    assertTrue(compareResult.compareMatched());


    // Test a modify request with a filter that doesn't match.
    final ModifyRequest modifyRequest = new ModifyRequest(
         "dn: ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");
    modifyRequest.setControls(new AssertionRequestControl("(description=*)"));

    try
    {
      conn.modify(modifyRequest);
      fail("Expected an exception from a modify with a non-matching " +
           "assertion filter");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.ASSERTION_FAILED);
    }

    // Test the modify again with a matching filter.
    modifyRequest.setControls(new AssertionRequestControl("(objectClass=top)"));

    final LDAPResult modifyResult = conn.modify(modifyRequest);
    assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);


    // Test a modify DN request with a filter that doesn't match.
    final ModifyDNRequest modifyDNRequest = new ModifyDNRequest(
         "ou=test,dc=example,dc=com", "ou=test2", true);
    modifyDNRequest.setControls(new AssertionRequestControl("(description=*)"));

    try
    {
      conn.modifyDN(modifyDNRequest);
      fail("Expected an exception from a modify DN with a non-matching " +
           "assertion filter");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.ASSERTION_FAILED);
    }

    // Test the modify DN again with a matching filter.
    modifyDNRequest.setControls(new AssertionRequestControl("(ou=test)"));

    final LDAPResult modifyDNResult = conn.modifyDN(modifyDNRequest);
    assertEquals(modifyDNResult.getResultCode(), ResultCode.SUCCESS);


    // Test a search request with a filter that doesn't match the base entry but
    // does match an entry matching the search criteria.
    final SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, "(uid=test.user)");
    searchRequest.setControls(
         new AssertionRequestControl("(objectClass=person)"));

    try
    {
      conn.search(searchRequest);
      fail("Expected an exception from a search with a non-matching " +
           "assertion filter");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.ASSERTION_FAILED);
    }

    // Test the search again with an assertion filter that matches the base
    // entry but not the entry that matches the search criteria.
    searchRequest.setControls(
         new AssertionRequestControl("(objectClass=domain)"));

    final SearchResult searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);
    assertEquals(new DN(searchResult.getSearchEntries().get(0).getDN()),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));


    // Test a delete request with a filter that doesn't match.
    final DeleteRequest deleteRequest =
         new DeleteRequest("ou=test2,dc=example,dc=com");
    deleteRequest.setControls(new AssertionRequestControl("(ou=test)"));

    try
    {
      conn.delete(deleteRequest);
      fail("Expected an exception from a delete with a non-matching " +
           "assertion filter");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.ASSERTION_FAILED);
    }

    // Test the delete again with a matching filter.
    deleteRequest.setControls(new AssertionRequestControl("(ou=test2)"));

    final LDAPResult deleteResult = conn.delete(deleteRequest);
    assertEquals(deleteResult.getResultCode(), ResultCode.SUCCESS);


    conn.close();
  }



  /**
   * Provides test coverage for the authorization identity request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthorizationIdentityControl()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();

    final AuthorizationIdentityRequestControl authzIDRequest =
         new AuthorizationIdentityRequestControl();

    conn.add(generateUserEntry("another.user",
         "ou=People,dc=example,dc=com", "Another", "User", "password"));


    // Test a simple bind without the authorization identity request control.
    BindResult bindResult = conn.bind(new SimpleBindRequest(
         "uid=test.user,ou=People,dc=example,dc=com", "password"));
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);
    assertFalse(bindResult.hasResponseControl(
         AuthorizationIdentityResponseControl.
              AUTHORIZATION_IDENTITY_RESPONSE_OID));


    // Test an anonymous simple bind.
    bindResult = conn.bind(new SimpleBindRequest("", "", authzIDRequest));
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);
    AuthorizationIdentityResponseControl authzIDResponse =
         AuthorizationIdentityResponseControl.get(bindResult);
    assertNotNull(authzIDResponse);
    assertEquals(authzIDResponse.getAuthorizationID(), "");


    // Test a valid simple bind as a normal user.
    bindResult = conn.bind(new SimpleBindRequest(
         "uid=test.user,ou=People,dc=example,dc=com", "password",
         authzIDRequest));
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);
    authzIDResponse = AuthorizationIdentityResponseControl.get(bindResult);
    assertNotNull(authzIDResponse);
    assertTrue(authzIDResponse.getAuthorizationID().startsWith("dn:"));
    assertEquals(new DN(authzIDResponse.getAuthorizationID().substring(3)),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));


    // Test a valid simple bind as an additional bind user.
    bindResult = conn.bind(new SimpleBindRequest("cn=Directory Manager",
         "password", authzIDRequest));
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);
    authzIDResponse = AuthorizationIdentityResponseControl.get(bindResult);
    assertNotNull(authzIDResponse);
    assertTrue(authzIDResponse.getAuthorizationID().startsWith("dn:"));
    assertEquals(new DN(authzIDResponse.getAuthorizationID().substring(3)),
         new DN("cn=Directory Manager"));


    // Test a failed simple bind as a normal user.
    try
    {
      conn.bind(new SimpleBindRequest(
           "uid=test.user,ou=People,dc=example,dc=com", "wrongPassword",
           authzIDRequest));
      fail("Expected an exception from a failed simple bind as a normal user.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_CREDENTIALS);
      assertFalse(le.hasResponseControl(AuthorizationIdentityResponseControl.
           AUTHORIZATION_IDENTITY_RESPONSE_OID));
    }


    // Test a failed simple bind as an additional bind user.
    try
    {
      conn.bind(new SimpleBindRequest("cn=Directory Manager", "wrongPassword",
           authzIDRequest));
      fail("Expected an exception from a failed simple bind as an additional " +
           "bind user.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_CREDENTIALS);
      assertFalse(le.hasResponseControl(AuthorizationIdentityResponseControl.
           AUTHORIZATION_IDENTITY_RESPONSE_OID));
    }


    // Test a SASL PLAIN bind without the authorization identity request
    // control.
    bindResult = conn.bind(new PLAINBindRequest(
         "dn:uid=test.user,ou=People,dc=example,dc=com", "password"));
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);
    assertFalse(bindResult.hasResponseControl(
         AuthorizationIdentityResponseControl.
              AUTHORIZATION_IDENTITY_RESPONSE_OID));


    // Test a valid SASL PLAIN bind as an anonymous user.
    bindResult = conn.bind(new PLAINBindRequest("dn:", "", authzIDRequest));
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);
    authzIDResponse = AuthorizationIdentityResponseControl.get(bindResult);
    assertNotNull(authzIDResponse);
    assertEquals(authzIDResponse.getAuthorizationID(), "dn:");


    // Test a valid SASL PLAIN bind as a normal user with a dn-style auth ID and
    // no authz ID.
    bindResult = conn.bind(new PLAINBindRequest(
         "dn:uid=test.user,ou=People,dc=example,dc=com", "password",
         authzIDRequest));
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);
    authzIDResponse = AuthorizationIdentityResponseControl.get(bindResult);
    assertNotNull(authzIDResponse);
    assertTrue(authzIDResponse.getAuthorizationID().startsWith("dn:"));
    assertEquals(new DN(authzIDResponse.getAuthorizationID().substring(3)),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));


    // Test a valid SASL PLAIN bind as an additional bind user with a dn-style
    // auth ID and no authz ID.
    bindResult = conn.bind(new PLAINBindRequest("dn:cn=Directory Manager",
         "password", authzIDRequest));
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);
    authzIDResponse = AuthorizationIdentityResponseControl.get(bindResult);
    assertNotNull(authzIDResponse);
    assertTrue(authzIDResponse.getAuthorizationID().startsWith("dn:"));
    assertEquals(new DN(authzIDResponse.getAuthorizationID().substring(3)),
         new DN("cn=Directory Manager"));


    // Test a valid SASL PLAIN bind as a normal user with a u-style auth ID and
    // no authz ID.
    bindResult = conn.bind(new PLAINBindRequest("u:test.user", "password",
         authzIDRequest));
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);
    authzIDResponse = AuthorizationIdentityResponseControl.get(bindResult);
    assertNotNull(authzIDResponse);
    assertTrue(authzIDResponse.getAuthorizationID().startsWith("dn:"));
    assertEquals(new DN(authzIDResponse.getAuthorizationID().substring(3)),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));


    // Test a valid SASL PLAIN bind as a normal user with a dn-style authz ID.
    bindResult = conn.bind(new PLAINBindRequest(
         "dn:uid=test.user,ou=People,dc=example,dc=com",
         "dn:uid=another.user,ou=People,dc=example,dc=com", "password",
         authzIDRequest));
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);
    authzIDResponse = AuthorizationIdentityResponseControl.get(bindResult);
    assertNotNull(authzIDResponse);
    assertTrue(authzIDResponse.getAuthorizationID().startsWith("dn:"));
    assertEquals(new DN(authzIDResponse.getAuthorizationID().substring(3)),
         new DN("uid=another.user,ou=People,dc=example,dc=com"));


    // Test a valid SASL PLAIN bind as an additional bind user with a dn-style
    // authz ID.
    bindResult = conn.bind(new PLAINBindRequest("dn:cn=Directory Manager",
         "dn:cn=Manager", "password", authzIDRequest));
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);
    authzIDResponse = AuthorizationIdentityResponseControl.get(bindResult);
    assertNotNull(authzIDResponse);
    assertTrue(authzIDResponse.getAuthorizationID().startsWith("dn:"));
    assertEquals(new DN(authzIDResponse.getAuthorizationID().substring(3)),
         new DN("cn=Manager"));


    // Test a valid SASL PLAIN bind as a normal user with a u-style authz ID.
    bindResult = conn.bind(new PLAINBindRequest("u:test.user", "u:another.user",
         "password", authzIDRequest));
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);
    authzIDResponse = AuthorizationIdentityResponseControl.get(bindResult);
    assertNotNull(authzIDResponse);
    assertTrue(authzIDResponse.getAuthorizationID().startsWith("dn:"));
    assertEquals(new DN(authzIDResponse.getAuthorizationID().substring(3)),
         new DN("uid=another.user,ou=People,dc=example,dc=com"));


    // Test a failed SASL PLAIN bind as a normal user.
    try
    {
      conn.bind(new PLAINBindRequest(
           "dn:uid=test.user,ou=People,dc=example,dc=com", "wrongPassword",
           authzIDRequest));
      fail("Expected an exception from a failed PLAIN bind as a normal user.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_CREDENTIALS);
      assertFalse(le.hasResponseControl(AuthorizationIdentityResponseControl.
           AUTHORIZATION_IDENTITY_RESPONSE_OID));
    }


    // Test a failed SASL PLAIN bind as an additional bind user.
    try
    {
      conn.bind(new PLAINBindRequest("dn:cn=Directory Manager", "wrongPassword",
           authzIDRequest));
      fail("Expected an exception from a failed PLAIN bind as an additional " +
           "bind user.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_CREDENTIALS);
      assertFalse(le.hasResponseControl(AuthorizationIdentityResponseControl.
           AUTHORIZATION_IDENTITY_RESPONSE_OID));
    }


    conn.close();
  }



  /**
   * Provides test coverage for the manage DSA IT request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testManageDsaITControl()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();

    final ManageDsaITRequestControl c = new ManageDsaITRequestControl();

    conn.add(
         "dn: ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ou: Users",
         "ref: ldap://127.0.0.1:" + ds.getListenPort() +
              "/ou=People,dc=example,dc=com");


    // Try to add an entry with a DN equal to the referral entry without the
    // control and verify that we get the correct referral.
    AddRequest addRequest = new AddRequest(
         "dn: ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Users");
    try
    {
      conn.add(addRequest);
      fail("Expected an exception when trying to add an entry with the same " +
           "DN as the referral entry and without the manage DSA IT control");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.REFERRAL);
      assertNotNull(le.getReferralURLs());
      assertEquals(le.getReferralURLs().length, 1);
      assertEquals(new LDAPURL(le.getReferralURLs()[0]),
           new LDAPURL("ldap://127.0.0.1:" + ds.getListenPort() +
                "/ou=People,dc=example,dc=com"));
    }

    // Try the same add with a DN equal to the referral entry with the control
    // and verify that we get an entry already exists error.
    try
    {
      addRequest.setControls(c);
      conn.add(addRequest);
      fail("Expected an exception when trying to add an entry with the same " +
           "DN as the referral entry and with the manage DSA IT control");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.ENTRY_ALREADY_EXISTS);
    }


    // Try to add an entry below the referral without the control and verify
    // that we get the correct referral.
    addRequest = new AddRequest(
         "dn: ou=Test,ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Test");

    try
    {
      conn.add(addRequest);
      fail("Expected an exception when trying to add an entry below the " +
           "referral entry and without the manage DSA IT control");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.REFERRAL);
      assertNotNull(le.getReferralURLs());
      assertEquals(le.getReferralURLs().length, 1);
      assertEquals(new LDAPURL(le.getReferralURLs()[0]),
           new LDAPURL("ldap://127.0.0.1:" + ds.getListenPort() +
                "/ou=Test,ou=People,dc=example,dc=com"));
    }


    // Try a compare at the referral entry without the control and verify that
    // we get the correct referral.
    CompareRequest compareRequest =
         new CompareRequest("ou=Users,dc=example,dc=com", "objectClass", "top");

    try
    {
      conn.compare(compareRequest);
      fail("Expected an exception when trying to perform a compare targeting " +
           "the referral entry and without the manage DSA IT control");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.REFERRAL);
      assertNotNull(le.getReferralURLs());
      assertEquals(le.getReferralURLs().length, 1);
      assertEquals(new LDAPURL(le.getReferralURLs()[0]),
           new LDAPURL("ldap://127.0.0.1:" + ds.getListenPort() +
                "/ou=People,dc=example,dc=com"));
    }

    // Add the control and verify that the compare succeeds.
    compareRequest.setControls(c);

    final CompareResult compareResult = conn.compare(compareRequest);
    assertTrue(compareResult.compareMatched());
    assertEquals(compareResult.getReferralURLs().length, 0,
         Arrays.toString(compareResult.getReferralURLs()));


    // Try a compare below the referral entry without the control and verify
    // that we get the correct referral.
    compareRequest = new CompareRequest(
         "uid=test.user,ou=Users,dc=example,dc=com", "objectClass", "top");

    try
    {
      conn.compare(compareRequest);
      fail("Expected an exception when trying to perform a compare below " +
           "the referral entry and without the manage DSA IT control");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.REFERRAL);
      assertNotNull(le.getReferralURLs());
      assertEquals(le.getReferralURLs().length, 1);
      assertEquals(new LDAPURL(le.getReferralURLs()[0]),
           new LDAPURL("ldap://127.0.0.1:" + ds.getListenPort() +
                "/uid=test.user,ou=People,dc=example,dc=com"));
    }

    // Add the control and verify that the compare fails because the entry
    // doesn't exist.
    try
    {
      compareRequest.setControls(c);
      conn.compare(compareRequest);
      fail("Expected an exception when trying to perform a compare below " +
           "the referral entry and with the manage DSA IT control");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
      assertNotNull(le.getMatchedDN());
      assertEquals(le.getReferralURLs().length, 0,
           Arrays.toString(le.getReferralURLs()));
    }


    // Try to modify the referral entry without the control and verify that it
    // returns the expected referral.
    ModifyRequest modifyRequest = new ModifyRequest(
         "dn: ou=Users,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");

    try
    {
      conn.modify(modifyRequest);
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.REFERRAL);
      assertNotNull(le.getReferralURLs());
      assertEquals(le.getReferralURLs().length, 1);
      assertEquals(new LDAPURL(le.getReferralURLs()[0]),
           new LDAPURL("ldap://127.0.0.1:" + ds.getListenPort() +
                "/ou=People,dc=example,dc=com"));
    }

    // Add the control and verify that the modify succeeds.
    modifyRequest.setControls(c);

    final LDAPResult modifyResult = conn.modify(modifyRequest);
    assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(modifyResult.getReferralURLs().length, 0,
         Arrays.toString(modifyResult.getReferralURLs()));


    // Try to modify an entry below the referral entry without the control and
    // verify that it returns the expected referral.
    modifyRequest = new ModifyRequest(
         "dn: uid=test.user,ou=Users,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");

    try
    {
      conn.modify(modifyRequest);
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.REFERRAL);
      assertNotNull(le.getReferralURLs());
      assertEquals(le.getReferralURLs().length, 1);
      assertEquals(new LDAPURL(le.getReferralURLs()[0]),
           new LDAPURL("ldap://127.0.0.1:" + ds.getListenPort() +
                "/uid=test.user,ou=People,dc=example,dc=com"));
    }

    // Add the control and verify that the attempt fails with a no such object
    // result.
    try
    {
      modifyRequest.setControls(c);
      conn.modify(modifyRequest);
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
      assertNotNull(le.getMatchedDN());
      assertEquals(le.getReferralURLs().length, 0,
           Arrays.toString(le.getReferralURLs()));
    }


    // Perform a search based at the referral entry without the control.
    SearchRequest searchRequest = new SearchRequest(
         "ou=Users,dc=example,dc=com", SearchScope.SUB, "(objectClass=*)");

    try
    {
      conn.search(searchRequest);
      fail("Expected an exception when trying to search based at the " +
           "referral entry without the control");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.REFERRAL);
      assertNotNull(le.getReferralURLs());
      assertEquals(le.getReferralURLs().length, 1);
      assertEquals(new LDAPURL(le.getReferralURLs()[0]),
           new LDAPURL("ldap://127.0.0.1:" + ds.getListenPort() +
                "/ou=People,dc=example,dc=com"));
    }

    // Add the control and verify that the search succeeds.
    searchRequest.setControls(c);

    SearchResult searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getReferralURLs().length, 0,
         Arrays.toString(searchResult.getReferralURLs()));
    assertEquals(searchResult.getEntryCount(), 1);
    assertEquals(searchResult.getReferenceCount(), 0);


    // Perform a search based below the referral entry without the control.
    searchRequest = new SearchRequest(
         "uid=test.user,ou=Users,dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");

    try
    {
      conn.search(searchRequest);
      fail("Expected an exception when trying to search below the referral " +
           "entry without the control");
    }
    catch (final LDAPSearchException lse)
    {
      assertEquals(lse.getResultCode(), ResultCode.REFERRAL);
      assertNotNull(lse.getReferralURLs());
      assertEquals(lse.getReferralURLs().length, 1);
      assertEquals(new LDAPURL(lse.getReferralURLs()[0]),
           new LDAPURL("ldap://127.0.0.1:" + ds.getListenPort() +
                "/uid=test.user,ou=People,dc=example,dc=com"));
      assertEquals(lse.getEntryCount(), 0);
      assertEquals(lse.getReferenceCount(), 0);
    }

    // Add the control and verify that the search fails with no such object.
    try
    {
      searchRequest.setControls(c);
      conn.search(searchRequest);
      fail("Expected an exception when trying to search below the referral " +
           "entry with the control");
    }
    catch (final LDAPSearchException lse)
    {
      assertEquals(lse.getResultCode(), ResultCode.NO_SUCH_OBJECT);
      assertNotNull(lse.getMatchedDN());
      assertEquals(lse.getReferralURLs().length, 0,
           Arrays.toString(lse.getReferralURLs()));
      assertEquals(lse.getEntryCount(), 0);
      assertEquals(lse.getReferenceCount(), 0);
    }


    // Perform a search based above the referral entry without the control and
    // verify that a reference is returned, along with other entries.
    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getReferralURLs().length, 0,
         Arrays.toString(searchResult.getReferralURLs()));
    assertEquals(searchResult.getEntryCount(), 3);
    assertEquals(searchResult.getReferenceCount(), 1);

    // Add the control and verify that the search returns only entries and no
    // references.
    searchRequest.setControls(c);

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getReferralURLs().length, 0,
         Arrays.toString(searchResult.getReferralURLs()));
    assertEquals(searchResult.getEntryCount(), 4);
    assertEquals(searchResult.getReferenceCount(), 0);


    // Attempt a modify DN at the referral entry without the control.
    ModifyDNRequest modifyDNRequest = new ModifyDNRequest(
         "ou=Users,dc=example,dc=com", "ou=Persons", true);

    try
    {
      conn.modifyDN(modifyDNRequest);
      fail("Expected an exception when trying to perform a modify DN at the " +
           "referral entry without the control.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.REFERRAL);
      assertNotNull(le.getReferralURLs());
      assertEquals(le.getReferralURLs().length, 1);
      assertEquals(new LDAPURL(le.getReferralURLs()[0]),
           new LDAPURL("ldap://127.0.0.1:" + ds.getListenPort() +
                "/ou=People,dc=example,dc=com"));
    }


    // Attempt a modify DN below the referral entry without the control.
    modifyDNRequest = new ModifyDNRequest(
         "uid=test.user,ou=Users,dc=example,dc=com", "ou=Persons", true);

    try
    {
      conn.modifyDN(modifyDNRequest);
      fail("Expected an exception when trying to perform a modify DN below " +
           "the referral entry without the control.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.REFERRAL);
      assertNotNull(le.getReferralURLs());
      assertEquals(le.getReferralURLs().length, 1);
      assertEquals(new LDAPURL(le.getReferralURLs()[0]),
           new LDAPURL("ldap://127.0.0.1:" + ds.getListenPort() +
                "/uid=test.user,ou=People,dc=example,dc=com"));
    }

    // Add the control and verify that the operation fails with no such object.
    try
    {
      modifyDNRequest.setControls(c);
      conn.modifyDN(modifyDNRequest);
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
      assertNotNull(le.getMatchedDN());
      assertEquals(le.getReferralURLs().length, 0,
           Arrays.toString(le.getReferralURLs()));
    }


    // Attempt a modify DN with the new DN below a referral entry.
    modifyDNRequest = new ModifyDNRequest(
         "uid=test.user,ou=People,dc=example,dc=com", "cn=Test User", false,
         "ou=Users,dc=example,dc=com");

    try
    {
      conn.modifyDN(modifyDNRequest);
      fail("Expected an exception when trying to move an entry below a " +
           "referral.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }


    // Attempt to delete an entry below the referral entry without the control.
    DeleteRequest deleteRequest =
         new DeleteRequest("uid=test.user,ou=Users,dc=example,dc=com");

    try
    {
      conn.delete(deleteRequest);
      fail("Expected an exception when trying to delete an entry below the " +
           "referral without the control.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.REFERRAL);
      assertNotNull(le.getReferralURLs());
      assertEquals(le.getReferralURLs().length, 1);
      assertEquals(new LDAPURL(le.getReferralURLs()[0]),
           new LDAPURL("ldap://127.0.0.1:" + ds.getListenPort() +
                "/uid=test.user,ou=People,dc=example,dc=com"));
    }

    // Add the control and verify that the operation fails with no such object.
    try
    {
      deleteRequest.setControls(c);
      conn.delete(deleteRequest);
      fail("Expected an exception when trying to delete an entry below the " +
           "referral with the control.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
      assertNotNull(le.getMatchedDN());
      assertEquals(le.getReferralURLs().length, 0,
           Arrays.toString(le.getReferralURLs()));
    }


    // Attempt to delete the referral entry without the control.
    deleteRequest = new DeleteRequest("ou=Users,dc=example,dc=com");

    try
    {
      conn.delete(deleteRequest);
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.REFERRAL);
      assertNotNull(le.getReferralURLs());
      assertEquals(le.getReferralURLs().length, 1);
      assertEquals(new LDAPURL(le.getReferralURLs()[0]),
           new LDAPURL("ldap://127.0.0.1:" + ds.getListenPort() +
                "/ou=People,dc=example,dc=com"));
    }

    // Add the control and verify that the delete is successful.
    deleteRequest.setControls(c);

    final LDAPResult deleteResult = conn.delete(deleteRequest);
    assertEquals(deleteResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(deleteResult.getReferralURLs().length, 0,
         Arrays.toString(modifyResult.getReferralURLs()));


    // Perform a search and verify that no references are returned.
    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getReferralURLs().length, 0,
         Arrays.toString(searchResult.getReferralURLs()));
    assertEquals(searchResult.getEntryCount(), 3);
    assertEquals(searchResult.getReferenceCount(), 0);

    // Add the control and verify that the search result is the same.
    searchRequest.setControls(c);

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getReferralURLs().length, 0,
         Arrays.toString(searchResult.getReferralURLs()));
    assertEquals(searchResult.getEntryCount(), 3);
    assertEquals(searchResult.getReferenceCount(), 0);


    conn.close();
  }



  /**
   * Provides test coverage for the no-operation request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoOperationControl()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();


    // Test an add with a no-operation control.
    final AddRequest addRequest = new AddRequest(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test");
    addRequest.setControls(new DraftZeilengaLDAPNoOp12RequestControl());
    assertResultCodeEquals(conn, addRequest, ResultCode.NO_OPERATION);


    // Test a delete with a no-operation control.
    final DeleteRequest deleteRequest =
         new DeleteRequest("uid=test.user,ou=People,dc=example,dc=com");
    deleteRequest.setControls(new DraftZeilengaLDAPNoOp12RequestControl());
    assertResultCodeEquals(conn, deleteRequest, ResultCode.NO_OPERATION);


    // Test a modify with a no-operation control.
    final ModifyRequest modifyRequest = new ModifyRequest(
         "dn: ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");
    modifyRequest.setControls(new DraftZeilengaLDAPNoOp12RequestControl());
    assertResultCodeEquals(conn, modifyRequest, ResultCode.NO_OPERATION);


    // Test a modify DN with a no-operation control.
    final ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("uid=test.user,ou=People,dc=example,dc=com",
              "cn=Test User", false);
    modifyDNRequest.setControls(new DraftZeilengaLDAPNoOp12RequestControl());
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.NO_OPERATION);


    // Test a search with a no-operation control.
    final SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, "(objectClass=*)");
    searchRequest.setControls(new DraftZeilengaLDAPNoOp12RequestControl());
    assertResultCodeEquals(conn, searchRequest,
         ResultCode.UNAVAILABLE_CRITICAL_EXTENSION);


    conn.close();
  }



  /**
   * Provides test coverage for the permissive modify request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPermissiveModifyControl()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();

    final PermissiveModifyRequestControl c =
         new PermissiveModifyRequestControl();


    // Try to remove a value that doesn't exist without the control.
    ModifyRequest modifyRequest = new ModifyRequest(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: modify",
         "delete: description",
         "description: foo");

    try
    {
      conn.modify(modifyRequest);
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_ATTRIBUTE);
    }

    // Try the same modification with the control.
    modifyRequest.setControls(c);

    LDAPResult modifyResult = conn.modify(modifyRequest);
    assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);


    // Try to add a value that already exists without the control.
    modifyRequest = new ModifyRequest(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: modify",
         "add: givenName",
         "givenName: Test");

    try
    {
      conn.modify(modifyRequest);
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.ATTRIBUTE_OR_VALUE_EXISTS);
    }

    // Try the same modification with the control.
    modifyRequest.setControls(c);

    modifyResult = conn.modify(modifyRequest);
    assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);


    conn.close();
  }



  /**
   * Provides test coverage for the pre-read and post-read controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadEntryControls()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();

    conn.add(
         "dn: ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Users");

    final PreReadRequestControl preReadUserAttrs =
         new PreReadRequestControl();
    final PreReadRequestControl preReadAllAttrs =
         new PreReadRequestControl("*", "+");
    final PreReadRequestControl preReadSpecifiedAttrs =
         new PreReadRequestControl("objectClass", "cn", "entryUUID");

    final PostReadRequestControl postReadUserAttrs =
         new PostReadRequestControl();
    final PostReadRequestControl postReadAllAttrs =
         new PostReadRequestControl("*", "+");
    final PostReadRequestControl postReadSpecifiedAttrs =
         new PostReadRequestControl("objectClass", "cn", "entryUUID");


    // Test an add with a post-read control that should return all user
    // attributes.
    AddRequest addRequest = new AddRequest(generateUserEntry("test.1",
         "ou=People,dc=example,dc=com", "Test", "1", "password",
         new Attribute("description", "foo")));
    addRequest.setControls(postReadUserAttrs);

    LDAPResult addResult = conn.add(addRequest);
    assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);

    PostReadResponseControl postReadResponse =
         PostReadResponseControl.get(addResult);
    assertNotNull(postReadResponse);

    Entry postReadEntry = postReadResponse.getEntry();
    assertEquals(postReadEntry.getParsedDN(),
         new DN("uid=test.1,ou=People,dc=example,dc=com"));
    assertTrue(postReadEntry.hasAttributeValue("objectClass", "top"));
    assertTrue(postReadEntry.hasAttributeValue("objectClass", "inetOrgPerson"));
    assertTrue(postReadEntry.hasAttributeValue("cn", "Test 1"));
    assertTrue(postReadEntry.hasAttributeValue("uid", "test.1"));
    assertTrue(postReadEntry.hasAttributeValue("givenName", "Test"));
    assertTrue(postReadEntry.hasAttributeValue("sn", "1"));
    assertTrue(postReadEntry.hasAttributeValue("userPassword", "password"));
    assertTrue(postReadEntry.hasAttributeValue("description", "foo"));
    assertFalse(postReadEntry.hasAttribute("entryDN"));
    assertFalse(postReadEntry.hasAttribute("entryUUID"));
    assertFalse(postReadEntry.hasAttribute("creatorsName"));
    assertFalse(postReadEntry.hasAttribute("createTimestamp"));
    assertFalse(postReadEntry.hasAttribute("modifiersName"));
    assertFalse(postReadEntry.hasAttribute("modifyTimestamp"));
    assertFalse(postReadEntry.hasAttribute("subschemaSubentry"));


    // Test an add with a post-read control that should return all user and
    // operational attributes.
    addRequest = new AddRequest(generateUserEntry("test.2",
         "ou=People,dc=example,dc=com", "Test", "2", "password",
         new Attribute("description", "foo")));
    addRequest.setControls(postReadAllAttrs);

    addResult = conn.add(addRequest);
    assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);

    postReadResponse = PostReadResponseControl.get(addResult);
    assertNotNull(postReadResponse);

    postReadEntry = postReadResponse.getEntry();
    assertEquals(postReadEntry.getParsedDN(),
         new DN("uid=test.2,ou=People,dc=example,dc=com"));
    assertTrue(postReadEntry.hasAttributeValue("objectClass", "top"));
    assertTrue(postReadEntry.hasAttributeValue("objectClass", "inetOrgPerson"));
    assertTrue(postReadEntry.hasAttributeValue("cn", "Test 2"));
    assertTrue(postReadEntry.hasAttributeValue("uid", "test.2"));
    assertTrue(postReadEntry.hasAttributeValue("givenName", "Test"));
    assertTrue(postReadEntry.hasAttributeValue("sn", "2"));
    assertTrue(postReadEntry.hasAttributeValue("userPassword", "password"));
    assertTrue(postReadEntry.hasAttributeValue("description", "foo"));
    assertTrue(postReadEntry.hasAttribute("entryDN"));
    assertTrue(postReadEntry.hasAttribute("entryUUID"));
    assertTrue(postReadEntry.hasAttribute("creatorsName"));
    assertTrue(postReadEntry.hasAttribute("createTimestamp"));
    assertTrue(postReadEntry.hasAttribute("modifiersName"));
    assertTrue(postReadEntry.hasAttribute("modifyTimestamp"));
    assertTrue(postReadEntry.hasAttribute("subschemaSubentry"));


    // Test an add with a post-read control that should return only a specified
    // set of attributes.
    addRequest = new AddRequest(generateUserEntry("test.3",
         "ou=People,dc=example,dc=com", "Test", "3", "password",
         new Attribute("description", "foo")));
    addRequest.setControls(postReadSpecifiedAttrs);

    addResult = conn.add(addRequest);
    assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);

    postReadResponse = PostReadResponseControl.get(addResult);
    assertNotNull(postReadResponse);

    postReadEntry = postReadResponse.getEntry();
    assertEquals(postReadEntry.getParsedDN(),
         new DN("uid=test.3,ou=People,dc=example,dc=com"));
    assertTrue(postReadEntry.hasAttributeValue("objectClass", "top"));
    assertTrue(postReadEntry.hasAttributeValue("objectClass", "inetOrgPerson"));
    assertTrue(postReadEntry.hasAttributeValue("cn", "Test 3"));
    assertFalse(postReadEntry.hasAttribute("uid"));
    assertFalse(postReadEntry.hasAttribute("givenName"));
    assertFalse(postReadEntry.hasAttribute("sn"));
    assertFalse(postReadEntry.hasAttribute("userPassword"));
    assertFalse(postReadEntry.hasAttribute("description"));
    assertFalse(postReadEntry.hasAttribute("entryDN"));
    assertTrue(postReadEntry.hasAttribute("entryUUID"));
    assertFalse(postReadEntry.hasAttribute("creatorsName"));
    assertFalse(postReadEntry.hasAttribute("createTimestamp"));
    assertFalse(postReadEntry.hasAttribute("modifiersName"));
    assertFalse(postReadEntry.hasAttribute("modifyTimestamp"));
    assertFalse(postReadEntry.hasAttribute("subschemaSubentry"));


    // Test a modify with pre-read and post-read controls that should return all
    // user attributes.
    ModifyRequest modifyRequest = new ModifyRequest(
         "dn: uid=test.1,ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: bar");
    modifyRequest.setControls(preReadUserAttrs, postReadUserAttrs);

    LDAPResult modifyResult = conn.modify(modifyRequest);
    assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);

    PreReadResponseControl preReadResponse =
         PreReadResponseControl.get(modifyResult);
    assertNotNull(preReadResponse);

    Entry preReadEntry = preReadResponse.getEntry();
    assertEquals(preReadEntry.getParsedDN(),
         new DN("uid=test.1,ou=People,dc=example,dc=com"));
    assertTrue(preReadEntry.hasAttributeValue("objectClass", "top"));
    assertTrue(preReadEntry.hasAttributeValue("objectClass", "inetOrgPerson"));
    assertTrue(preReadEntry.hasAttributeValue("cn", "Test 1"));
    assertTrue(preReadEntry.hasAttributeValue("uid", "test.1"));
    assertTrue(preReadEntry.hasAttributeValue("givenName", "Test"));
    assertTrue(preReadEntry.hasAttributeValue("sn", "1"));
    assertTrue(preReadEntry.hasAttributeValue("userPassword", "password"));
    assertTrue(preReadEntry.hasAttributeValue("description", "foo"));
    assertFalse(preReadEntry.hasAttribute("entryDN"));
    assertFalse(preReadEntry.hasAttribute("entryUUID"));
    assertFalse(preReadEntry.hasAttribute("creatorsName"));
    assertFalse(preReadEntry.hasAttribute("createTimestamp"));
    assertFalse(preReadEntry.hasAttribute("modifiersName"));
    assertFalse(preReadEntry.hasAttribute("modifyTimestamp"));
    assertFalse(preReadEntry.hasAttribute("subschemaSubentry"));

    postReadResponse = PostReadResponseControl.get(modifyResult);
    assertNotNull(postReadResponse);

    postReadEntry = postReadResponse.getEntry();
    assertEquals(postReadEntry.getParsedDN(),
         new DN("uid=test.1,ou=People,dc=example,dc=com"));
    assertTrue(postReadEntry.hasAttributeValue("objectClass", "top"));
    assertTrue(postReadEntry.hasAttributeValue("objectClass", "inetOrgPerson"));
    assertTrue(postReadEntry.hasAttributeValue("cn", "Test 1"));
    assertTrue(postReadEntry.hasAttributeValue("uid", "test.1"));
    assertTrue(postReadEntry.hasAttributeValue("givenName", "Test"));
    assertTrue(postReadEntry.hasAttributeValue("sn", "1"));
    assertTrue(postReadEntry.hasAttributeValue("userPassword", "password"));
    assertTrue(postReadEntry.hasAttributeValue("description", "bar"));
    assertFalse(postReadEntry.hasAttribute("entryDN"));
    assertFalse(postReadEntry.hasAttribute("entryUUID"));
    assertFalse(postReadEntry.hasAttribute("creatorsName"));
    assertFalse(postReadEntry.hasAttribute("createTimestamp"));
    assertFalse(postReadEntry.hasAttribute("modifiersName"));
    assertFalse(postReadEntry.hasAttribute("modifyTimestamp"));
    assertFalse(postReadEntry.hasAttribute("subschemaSubentry"));


    // Test a modify with pre-read and post-read controls that should return all
    // user and operational attributes.  Sleep before processing the modify so
    // that we can ensure that the pre-read and post-read versions of the entry
    // will have different modifyTimestamp values.
    Thread.sleep(20L);
    modifyRequest = new ModifyRequest(
         "dn: uid=test.2,ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: bar");
    modifyRequest.setControls(preReadAllAttrs, postReadAllAttrs);

    modifyResult = conn.modify(modifyRequest);
    assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);

    preReadResponse = PreReadResponseControl.get(modifyResult);
    assertNotNull(preReadResponse);

    preReadEntry = preReadResponse.getEntry();
    assertEquals(preReadEntry.getParsedDN(),
         new DN("uid=test.2,ou=People,dc=example,dc=com"));
    assertTrue(preReadEntry.hasAttributeValue("objectClass", "top"));
    assertTrue(preReadEntry.hasAttributeValue("objectClass", "inetOrgPerson"));
    assertTrue(preReadEntry.hasAttributeValue("cn", "Test 2"));
    assertTrue(preReadEntry.hasAttributeValue("uid", "test.2"));
    assertTrue(preReadEntry.hasAttributeValue("givenName", "Test"));
    assertTrue(preReadEntry.hasAttributeValue("sn", "2"));
    assertTrue(preReadEntry.hasAttributeValue("userPassword", "password"));
    assertTrue(preReadEntry.hasAttributeValue("description", "foo"));
    assertTrue(preReadEntry.hasAttribute("entryDN"));
    assertTrue(preReadEntry.hasAttribute("entryUUID"));
    assertTrue(preReadEntry.hasAttribute("creatorsName"));
    assertTrue(preReadEntry.hasAttribute("createTimestamp"));
    assertTrue(preReadEntry.hasAttribute("modifiersName"));
    assertTrue(preReadEntry.hasAttribute("modifyTimestamp"));
    assertTrue(preReadEntry.hasAttribute("subschemaSubentry"));

    postReadResponse = PostReadResponseControl.get(modifyResult);
    assertNotNull(postReadResponse);

    postReadEntry = postReadResponse.getEntry();
    assertEquals(postReadEntry.getParsedDN(),
         new DN("uid=test.2,ou=People,dc=example,dc=com"));
    assertTrue(postReadEntry.hasAttributeValue("objectClass", "top"));
    assertTrue(postReadEntry.hasAttributeValue("objectClass", "inetOrgPerson"));
    assertTrue(postReadEntry.hasAttributeValue("cn", "Test 2"));
    assertTrue(postReadEntry.hasAttributeValue("uid", "test.2"));
    assertTrue(postReadEntry.hasAttributeValue("givenName", "Test"));
    assertTrue(postReadEntry.hasAttributeValue("sn", "2"));
    assertTrue(postReadEntry.hasAttributeValue("userPassword", "password"));
    assertTrue(postReadEntry.hasAttributeValue("description", "bar"));
    assertTrue(postReadEntry.hasAttribute("entryDN"));
    assertTrue(postReadEntry.hasAttribute("entryUUID"));
    assertTrue(postReadEntry.hasAttribute("creatorsName"));
    assertTrue(postReadEntry.hasAttribute("createTimestamp"));
    assertTrue(postReadEntry.hasAttribute("modifiersName"));
    assertTrue(postReadEntry.hasAttribute("modifyTimestamp"));
    assertTrue(postReadEntry.hasAttribute("subschemaSubentry"));

    final Date preReadModifyTimestamp =
         preReadEntry.getAttributeValueAsDate("modifyTimestamp");
    final Date postReadModifyTimestamp =
         postReadEntry.getAttributeValueAsDate("modifyTimestamp");
    assertNotNull(preReadModifyTimestamp);
    assertNotNull(postReadModifyTimestamp);
    assertFalse(preReadModifyTimestamp.equals(postReadModifyTimestamp));


    // Test a modify with pre-read and post-read controls that should return
    // only a specified set of attributes.
    modifyRequest = new ModifyRequest(
         "dn: uid=test.3,ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: bar");
    modifyRequest.setControls(preReadSpecifiedAttrs, postReadSpecifiedAttrs);

    modifyResult = conn.modify(modifyRequest);
    assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);

    preReadResponse = PreReadResponseControl.get(modifyResult);
    assertNotNull(preReadResponse);

    preReadEntry = preReadResponse.getEntry();
    assertEquals(preReadEntry.getParsedDN(),
         new DN("uid=test.3,ou=People,dc=example,dc=com"));
    assertTrue(preReadEntry.hasAttributeValue("objectClass", "top"));
    assertTrue(preReadEntry.hasAttributeValue("objectClass", "inetOrgPerson"));
    assertTrue(preReadEntry.hasAttributeValue("cn", "Test 3"));
    assertFalse(preReadEntry.hasAttributeValue("uid", "test.3"));
    assertFalse(preReadEntry.hasAttributeValue("givenName", "Test"));
    assertFalse(preReadEntry.hasAttributeValue("sn", "3"));
    assertFalse(preReadEntry.hasAttributeValue("userPassword", "password"));
    assertFalse(preReadEntry.hasAttributeValue("description", "foo"));
    assertFalse(preReadEntry.hasAttribute("entryDN"));
    assertTrue(preReadEntry.hasAttribute("entryUUID"));
    assertFalse(preReadEntry.hasAttribute("creatorsName"));
    assertFalse(preReadEntry.hasAttribute("createTimestamp"));
    assertFalse(preReadEntry.hasAttribute("modifiersName"));
    assertFalse(preReadEntry.hasAttribute("modifyTimestamp"));
    assertFalse(preReadEntry.hasAttribute("subschemaSubentry"));

    postReadResponse = PostReadResponseControl.get(modifyResult);
    assertNotNull(postReadResponse);

    postReadEntry = postReadResponse.getEntry();
    assertEquals(postReadEntry.getParsedDN(),
         new DN("uid=test.3,ou=People,dc=example,dc=com"));
    assertTrue(postReadEntry.hasAttributeValue("objectClass", "top"));
    assertTrue(postReadEntry.hasAttributeValue("objectClass", "inetOrgPerson"));
    assertTrue(postReadEntry.hasAttributeValue("cn", "Test 3"));
    assertFalse(postReadEntry.hasAttributeValue("uid", "test.3"));
    assertFalse(postReadEntry.hasAttributeValue("givenName", "Test"));
    assertFalse(postReadEntry.hasAttributeValue("sn", "3"));
    assertFalse(postReadEntry.hasAttributeValue("userPassword", "password"));
    assertFalse(postReadEntry.hasAttributeValue("description", "bar"));
    assertFalse(postReadEntry.hasAttribute("entryDN"));
    assertTrue(postReadEntry.hasAttribute("entryUUID"));
    assertFalse(postReadEntry.hasAttribute("creatorsName"));
    assertFalse(postReadEntry.hasAttribute("createTimestamp"));
    assertFalse(postReadEntry.hasAttribute("modifiersName"));
    assertFalse(postReadEntry.hasAttribute("modifyTimestamp"));
    assertFalse(postReadEntry.hasAttribute("subschemaSubentry"));


    // Test a modify DN with pre-read and post-read controls that should return
    // all user attributes.
    ModifyDNRequest modifyDNRequest = new ModifyDNRequest(
         "uid=test.1,ou=People,dc=example,dc=com", "cn=Test 1", false);
    modifyDNRequest.setControls(preReadUserAttrs, postReadUserAttrs);

    LDAPResult modifyDNResult = conn.modifyDN(modifyDNRequest);
    assertEquals(modifyDNResult.getResultCode(), ResultCode.SUCCESS);

    preReadResponse = PreReadResponseControl.get(modifyDNResult);
    assertNotNull(preReadResponse);

    preReadEntry = preReadResponse.getEntry();
    assertEquals(preReadEntry.getParsedDN(),
         new DN("uid=test.1,ou=People,dc=example,dc=com"));
    assertTrue(preReadEntry.hasAttributeValue("objectClass", "top"));
    assertTrue(preReadEntry.hasAttributeValue("objectClass", "inetOrgPerson"));
    assertTrue(preReadEntry.hasAttributeValue("cn", "Test 1"));
    assertTrue(preReadEntry.hasAttributeValue("uid", "test.1"));
    assertTrue(preReadEntry.hasAttributeValue("givenName", "Test"));
    assertTrue(preReadEntry.hasAttributeValue("sn", "1"));
    assertTrue(preReadEntry.hasAttributeValue("userPassword", "password"));
    assertTrue(preReadEntry.hasAttributeValue("description", "bar"));
    assertFalse(preReadEntry.hasAttribute("entryDN"));
    assertFalse(preReadEntry.hasAttribute("entryUUID"));
    assertFalse(preReadEntry.hasAttribute("creatorsName"));
    assertFalse(preReadEntry.hasAttribute("createTimestamp"));
    assertFalse(preReadEntry.hasAttribute("modifiersName"));
    assertFalse(preReadEntry.hasAttribute("modifyTimestamp"));
    assertFalse(preReadEntry.hasAttribute("subschemaSubentry"));

    postReadResponse = PostReadResponseControl.get(modifyDNResult);
    assertNotNull(postReadResponse);

    postReadEntry = postReadResponse.getEntry();
    assertEquals(postReadEntry.getParsedDN(),
         new DN("cn=Test 1,ou=People,dc=example,dc=com"));
    assertTrue(postReadEntry.hasAttributeValue("objectClass", "top"));
    assertTrue(postReadEntry.hasAttributeValue("objectClass", "inetOrgPerson"));
    assertTrue(postReadEntry.hasAttributeValue("cn", "Test 1"));
    assertTrue(postReadEntry.hasAttributeValue("uid", "test.1"));
    assertTrue(postReadEntry.hasAttributeValue("givenName", "Test"));
    assertTrue(postReadEntry.hasAttributeValue("sn", "1"));
    assertTrue(postReadEntry.hasAttributeValue("userPassword", "password"));
    assertTrue(postReadEntry.hasAttributeValue("description", "bar"));
    assertFalse(postReadEntry.hasAttribute("entryDN"));
    assertFalse(postReadEntry.hasAttribute("entryUUID"));
    assertFalse(postReadEntry.hasAttribute("creatorsName"));
    assertFalse(postReadEntry.hasAttribute("createTimestamp"));
    assertFalse(postReadEntry.hasAttribute("modifiersName"));
    assertFalse(postReadEntry.hasAttribute("modifyTimestamp"));
    assertFalse(postReadEntry.hasAttribute("subschemaSubentry"));


    // Test a modify DN with pre-read and post-read controls that should return
    // all user and operational attributes.
    modifyDNRequest = new ModifyDNRequest(
         "uid=test.2,ou=People,dc=example,dc=com", "uid=test.two", true);
    modifyDNRequest.setControls(preReadAllAttrs, postReadAllAttrs);

    modifyDNResult = conn.modifyDN(modifyDNRequest);
    assertEquals(modifyDNResult.getResultCode(), ResultCode.SUCCESS);

    preReadResponse = PreReadResponseControl.get(modifyDNResult);
    assertNotNull(preReadResponse);

    preReadEntry = preReadResponse.getEntry();
    assertEquals(preReadEntry.getParsedDN(),
         new DN("uid=test.2,ou=People,dc=example,dc=com"));
    assertTrue(preReadEntry.hasAttributeValue("objectClass", "top"));
    assertTrue(preReadEntry.hasAttributeValue("objectClass", "inetOrgPerson"));
    assertTrue(preReadEntry.hasAttributeValue("cn", "Test 2"));
    assertTrue(preReadEntry.hasAttributeValue("uid", "test.2"));
    assertFalse(preReadEntry.hasAttributeValue("uid", "test.two"));
    assertTrue(preReadEntry.hasAttributeValue("givenName", "Test"));
    assertTrue(preReadEntry.hasAttributeValue("sn", "2"));
    assertTrue(preReadEntry.hasAttributeValue("userPassword", "password"));
    assertTrue(preReadEntry.hasAttributeValue("description", "bar"));
    assertTrue(preReadEntry.hasAttribute("entryDN"));
    assertTrue(preReadEntry.hasAttribute("entryUUID"));
    assertTrue(preReadEntry.hasAttribute("creatorsName"));
    assertTrue(preReadEntry.hasAttribute("createTimestamp"));
    assertTrue(preReadEntry.hasAttribute("modifiersName"));
    assertTrue(preReadEntry.hasAttribute("modifyTimestamp"));
    assertTrue(preReadEntry.hasAttribute("subschemaSubentry"));

    postReadResponse = PostReadResponseControl.get(modifyDNResult);
    assertNotNull(postReadResponse);

    postReadEntry = postReadResponse.getEntry();
    assertEquals(postReadEntry.getParsedDN(),
         new DN("uid=test.two,ou=People,dc=example,dc=com"));
    assertTrue(postReadEntry.hasAttributeValue("objectClass", "top"));
    assertTrue(postReadEntry.hasAttributeValue("objectClass", "inetOrgPerson"));
    assertTrue(postReadEntry.hasAttributeValue("cn", "Test 2"));
    assertFalse(postReadEntry.hasAttributeValue("uid", "test.2"));
    assertTrue(postReadEntry.hasAttributeValue("uid", "test.two"));
    assertTrue(postReadEntry.hasAttributeValue("givenName", "Test"));
    assertTrue(postReadEntry.hasAttributeValue("sn", "2"));
    assertTrue(postReadEntry.hasAttributeValue("userPassword", "password"));
    assertTrue(postReadEntry.hasAttributeValue("description", "bar"));
    assertTrue(postReadEntry.hasAttribute("entryDN"));
    assertTrue(postReadEntry.hasAttribute("entryUUID"));
    assertTrue(postReadEntry.hasAttribute("creatorsName"));
    assertTrue(postReadEntry.hasAttribute("createTimestamp"));
    assertTrue(postReadEntry.hasAttribute("modifiersName"));
    assertTrue(postReadEntry.hasAttribute("modifyTimestamp"));
    assertTrue(postReadEntry.hasAttribute("subschemaSubentry"));


    // Test a modify DN with pre-read and post-read controls that should return
    // only a specified set of attributes.
    modifyDNRequest = new ModifyDNRequest(
         "uid=test.3,ou=People,dc=example,dc=com", "uid=test.3", true,
         "ou=Users,dc=example,dc=com");
    modifyDNRequest.setControls(preReadSpecifiedAttrs, postReadSpecifiedAttrs);

    modifyDNResult = conn.modifyDN(modifyDNRequest);
    assertEquals(modifyDNResult.getResultCode(), ResultCode.SUCCESS);

    preReadResponse = PreReadResponseControl.get(modifyDNResult);
    assertNotNull(preReadResponse);

    preReadEntry = preReadResponse.getEntry();
    assertEquals(preReadEntry.getParsedDN(),
         new DN("uid=test.3,ou=People,dc=example,dc=com"));
    assertTrue(preReadEntry.hasAttributeValue("objectClass", "top"));
    assertTrue(preReadEntry.hasAttributeValue("objectClass", "inetOrgPerson"));
    assertTrue(preReadEntry.hasAttributeValue("cn", "Test 3"));
    assertFalse(preReadEntry.hasAttribute("uid"));
    assertFalse(preReadEntry.hasAttribute("givenName"));
    assertFalse(preReadEntry.hasAttribute("sn"));
    assertFalse(preReadEntry.hasAttribute("userPassword"));
    assertFalse(preReadEntry.hasAttribute("description"));
    assertFalse(preReadEntry.hasAttribute("entryDN"));
    assertTrue(preReadEntry.hasAttribute("entryUUID"));
    assertFalse(preReadEntry.hasAttribute("creatorsName"));
    assertFalse(preReadEntry.hasAttribute("createTimestamp"));
    assertFalse(preReadEntry.hasAttribute("modifiersName"));
    assertFalse(preReadEntry.hasAttribute("modifyTimestamp"));
    assertFalse(preReadEntry.hasAttribute("subschemaSubentry"));

    postReadResponse = PostReadResponseControl.get(modifyDNResult);
    assertNotNull(postReadResponse);

    postReadEntry = postReadResponse.getEntry();
    assertEquals(postReadEntry.getParsedDN(),
         new DN("uid=test.3,ou=Users,dc=example,dc=com"));
    assertTrue(postReadEntry.hasAttributeValue("objectClass", "top"));
    assertTrue(postReadEntry.hasAttributeValue("objectClass", "inetOrgPerson"));
    assertTrue(postReadEntry.hasAttributeValue("cn", "Test 3"));
    assertFalse(postReadEntry.hasAttribute("uid"));
    assertFalse(postReadEntry.hasAttribute("givenName"));
    assertFalse(postReadEntry.hasAttribute("sn"));
    assertFalse(postReadEntry.hasAttribute("userPassword"));
    assertFalse(postReadEntry.hasAttribute("description"));
    assertFalse(postReadEntry.hasAttribute("entryDN"));
    assertTrue(postReadEntry.hasAttribute("entryUUID"));
    assertFalse(postReadEntry.hasAttribute("creatorsName"));
    assertFalse(postReadEntry.hasAttribute("createTimestamp"));
    assertFalse(postReadEntry.hasAttribute("modifiersName"));
    assertFalse(postReadEntry.hasAttribute("modifyTimestamp"));
    assertFalse(postReadEntry.hasAttribute("subschemaSubentry"));


    // Test a delete with a pre-read control that should return all user
    // attributes.
    DeleteRequest deleteRequest =
         new DeleteRequest("cn=Test 1,ou=People,dc=example,dc=com");
    deleteRequest.setControls(preReadUserAttrs);

    LDAPResult deleteResult = conn.delete(deleteRequest);
    assertEquals(deleteResult.getResultCode(), ResultCode.SUCCESS);

    preReadResponse = PreReadResponseControl.get(deleteResult);
    assertNotNull(preReadResponse);

    preReadEntry = preReadResponse.getEntry();
    assertEquals(preReadEntry.getParsedDN(),
         new DN("cn=Test 1,ou=People,dc=example,dc=com"));
    assertTrue(preReadEntry.hasAttributeValue("objectClass", "top"));
    assertTrue(preReadEntry.hasAttributeValue("objectClass", "inetOrgPerson"));
    assertTrue(preReadEntry.hasAttributeValue("cn", "Test 1"));
    assertTrue(preReadEntry.hasAttributeValue("uid", "test.1"));
    assertTrue(preReadEntry.hasAttributeValue("givenName", "Test"));
    assertTrue(preReadEntry.hasAttributeValue("sn", "1"));
    assertTrue(preReadEntry.hasAttributeValue("userPassword", "password"));
    assertTrue(preReadEntry.hasAttributeValue("description", "bar"));
    assertFalse(preReadEntry.hasAttribute("entryDN"));
    assertFalse(preReadEntry.hasAttribute("entryUUID"));
    assertFalse(preReadEntry.hasAttribute("creatorsName"));
    assertFalse(preReadEntry.hasAttribute("createTimestamp"));
    assertFalse(preReadEntry.hasAttribute("modifiersName"));
    assertFalse(preReadEntry.hasAttribute("modifyTimestamp"));
    assertFalse(preReadEntry.hasAttribute("subschemaSubentry"));


    // Test a delete with a pre-read control that should return all user and
    // operational attributes.
    deleteRequest =
         new DeleteRequest("uid=test.two,ou=People,dc=example,dc=com");
    deleteRequest.setControls(preReadAllAttrs);

    deleteResult = conn.delete(deleteRequest);
    assertEquals(deleteResult.getResultCode(), ResultCode.SUCCESS);

    preReadResponse = PreReadResponseControl.get(deleteResult);
    assertNotNull(preReadResponse);

    preReadEntry = preReadResponse.getEntry();
    assertEquals(preReadEntry.getParsedDN(),
         new DN("uid=test.two,ou=People,dc=example,dc=com"));
    assertTrue(preReadEntry.hasAttributeValue("objectClass", "top"));
    assertTrue(preReadEntry.hasAttributeValue("objectClass", "inetOrgPerson"));
    assertTrue(preReadEntry.hasAttributeValue("cn", "Test 2"));
    assertFalse(preReadEntry.hasAttributeValue("uid", "test.2"));
    assertTrue(preReadEntry.hasAttributeValue("uid", "test.two"));
    assertTrue(preReadEntry.hasAttributeValue("givenName", "Test"));
    assertTrue(preReadEntry.hasAttributeValue("sn", "2"));
    assertTrue(preReadEntry.hasAttributeValue("userPassword", "password"));
    assertTrue(preReadEntry.hasAttributeValue("description", "bar"));
    assertTrue(preReadEntry.hasAttribute("entryDN"));
    assertTrue(preReadEntry.hasAttribute("entryUUID"));
    assertTrue(preReadEntry.hasAttribute("creatorsName"));
    assertTrue(preReadEntry.hasAttribute("createTimestamp"));
    assertTrue(preReadEntry.hasAttribute("modifiersName"));
    assertTrue(preReadEntry.hasAttribute("modifyTimestamp"));
    assertTrue(preReadEntry.hasAttribute("subschemaSubentry"));


    // Test a delete with a pre-read control that should return only a specified
    // set of attributes.
    deleteRequest = new DeleteRequest("uid=test.3,ou=Users,dc=example,dc=com");
    deleteRequest.setControls(preReadSpecifiedAttrs);

    deleteResult = conn.delete(deleteRequest);
    assertEquals(deleteResult.getResultCode(), ResultCode.SUCCESS);

    preReadResponse = PreReadResponseControl.get(deleteResult);
    assertNotNull(preReadResponse);

    preReadEntry = preReadResponse.getEntry();
    assertEquals(preReadEntry.getParsedDN(),
         new DN("uid=test.3,ou=Users,dc=example,dc=com"));
    assertTrue(preReadEntry.hasAttributeValue("objectClass", "top"));
    assertTrue(preReadEntry.hasAttributeValue("objectClass", "inetOrgPerson"));
    assertTrue(preReadEntry.hasAttributeValue("cn", "Test 3"));
    assertFalse(preReadEntry.hasAttribute("uid"));
    assertFalse(preReadEntry.hasAttribute("givenName"));
    assertFalse(preReadEntry.hasAttribute("sn"));
    assertFalse(preReadEntry.hasAttribute("userPassword"));
    assertFalse(preReadEntry.hasAttribute("description"));
    assertFalse(preReadEntry.hasAttribute("entryDN"));
    assertTrue(preReadEntry.hasAttribute("entryUUID"));
    assertFalse(preReadEntry.hasAttribute("creatorsName"));
    assertFalse(preReadEntry.hasAttribute("createTimestamp"));
    assertFalse(preReadEntry.hasAttribute("modifiersName"));
    assertFalse(preReadEntry.hasAttribute("modifyTimestamp"));
    assertFalse(preReadEntry.hasAttribute("subschemaSubentry"));


    conn.close();
  }



  /**
   * Provides test coverage for the proxied auth v1 request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProxiedAuthV1Control()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();

    conn.add(generateUserEntry("bound.user",
         "ou=People,dc=example,dc=com", "Bound", "User", "password"));
    ds.assertEntryExists("uid=bound.user,ou=People,dc=example,dc=com");

    conn.add(generateUserEntry("another.user",
         "ou=People,dc=example,dc=com", "Another", "User", "password"));
    ds.assertEntryExists("uid=another.user,ou=People,dc=example,dc=com");

    conn.bind("uid=bound.user,ou=People,dc=example,dc=com", "password");


    // Test without proxied auth.
    AddRequest addRequest = new AddRequest(
         "dn: ou=test1,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test1");

    LDAPResult addResult = conn.add(addRequest);
    assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);

    ds.assertValueExists("ou=test1,dc=example,dc=com", "creatorsName",
         "uid=bound.user,ou=People,dc=example,dc=com");


    // Test proxied as anonymous.
    addRequest = new AddRequest(
         "dn: ou=test2,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test2");
    addRequest.setControls(new ProxiedAuthorizationV1RequestControl(""));

    addResult = conn.add(addRequest);
    assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);

    ds.assertValueExists("ou=test2,dc=example,dc=com", "creatorsName",
         "");


    // Test proxied as a regular user.
    addRequest = new AddRequest(
         "dn: ou=test3,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test3");
    addRequest.setControls(new ProxiedAuthorizationV1RequestControl(
         "uid=another.user,ou=People,dc=example,dc=com"));

    addResult = conn.add(addRequest);
    assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);

    ds.assertValueExists("ou=test3,dc=example,dc=com", "creatorsName",
         "uid=another.user,ou=People,dc=example,dc=com");


    // Test proxied as an additional bind user.
    addRequest = new AddRequest(
         "dn: ou=test4,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test4");
    addRequest.setControls(new ProxiedAuthorizationV1RequestControl(
         "cn=Directory Manager"));

    addResult = conn.add(addRequest);
    assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);

    ds.assertValueExists("ou=test4,dc=example,dc=com", "creatorsName",
         "cn=Directory Manager");


    // Test proxied as a nonexistent user.
    addRequest = new AddRequest(
         "dn: ou=test5,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test5");
    addRequest.setControls(new ProxiedAuthorizationV1RequestControl(
         "uid=nonexistent,dc=example,dc=com"));

    try
    {
      conn.add(addRequest);
      fail("Expected an exception when trying to proxy as a nonexistent user");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.AUTHORIZATION_DENIED);
    }


    // Test proxied as a malformed DN.
    addRequest = new AddRequest(
         "dn: ou=test6,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test6");
    addRequest.setControls(new ProxiedAuthorizationV1RequestControl(
         "malformed-dn"));

    try
    {
      conn.add(addRequest);
      fail("Expected an exception when trying to proxy as a malformed DN");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }


    conn.close();
  }



  /**
   * Provides test coverage for the proxied auth v2 request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProxiedAuthV2Control()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();

    conn.add(generateUserEntry("bound.user",
         "ou=People,dc=example,dc=com", "Bound", "User", "password"));
    ds.assertEntryExists("uid=bound.user,ou=People,dc=example,dc=com");

    conn.add(generateUserEntry("another.user",
         "ou=People,dc=example,dc=com", "Another", "User", "password"));
    ds.assertEntryExists("uid=another.user,ou=People,dc=example,dc=com");

    conn.bind("uid=bound.user,ou=People,dc=example,dc=com", "password");

    conn.add(
         "dn: cn=duplicate uid 1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: duplicate.uid",
         "givenName: Duplicate",
         "sn: uid",
         "cn: duplicate uid 1",
         "userPassword: password");

    conn.add(
         "dn: cn=duplicate uid 2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: duplicate.uid",
         "givenName: Duplicate",
         "sn: uid",
         "cn: duplicate uid 2",
         "userPassword: password");


    // Test without proxied auth.
    AddRequest addRequest = new AddRequest(
         "dn: ou=test1,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test1");

    LDAPResult addResult = conn.add(addRequest);
    assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);

    ds.assertValueExists("ou=test1,dc=example,dc=com", "creatorsName",
         "uid=bound.user,ou=People,dc=example,dc=com");


    // Test proxied as anonymous.
    addRequest = new AddRequest(
         "dn: ou=test2,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test2");
    addRequest.setControls(new ProxiedAuthorizationV2RequestControl("dn:"));

    addResult = conn.add(addRequest);
    assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);

    ds.assertValueExists("ou=test2,dc=example,dc=com", "creatorsName",
         "");


    // Test proxied as a regular user with a dn-style authzID.
    addRequest = new AddRequest(
         "dn: ou=test3,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test3");
    addRequest.setControls(new ProxiedAuthorizationV2RequestControl(
         "dn:uid=another.user,ou=People,dc=example,dc=com"));


    // Test proxied as a regular user with a u-style authzID.
    addRequest = new AddRequest(
         "dn: ou=test4,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test4");
    addRequest.setControls(new ProxiedAuthorizationV2RequestControl(
         "u:another.user"));

    addResult = conn.add(addRequest);
    assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);

    ds.assertValueExists("ou=test4,dc=example,dc=com", "creatorsName",
         "uid=another.user,ou=People,dc=example,dc=com");


    // Test proxied as an additional bind user with a dn-style authzID.
    addRequest = new AddRequest(
         "dn: ou=test5,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test5");
    addRequest.setControls(new ProxiedAuthorizationV2RequestControl(
         "dn:cn=Directory Manager"));

    addResult = conn.add(addRequest);
    assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);

    ds.assertValueExists("ou=test5,dc=example,dc=com", "creatorsName",
         "cn=Directory Manager");


    // Test proxied as a nonexistent user with a dn-style authzID.
    addRequest = new AddRequest(
         "dn: ou=test6,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test6");
    addRequest.setControls(new ProxiedAuthorizationV2RequestControl(
         "dn:uid=nonexistent,dc=example,dc=com"));

    try
    {
      conn.add(addRequest);
      fail("Expected an exception when trying to proxy as a nonexistent user");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.AUTHORIZATION_DENIED);
    }


    // Test proxied as a nonexistent user with a u-style authzID.
    addRequest = new AddRequest(
         "dn: ou=test7,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test7");
    addRequest.setControls(new ProxiedAuthorizationV2RequestControl(
         "u:nonexistent"));

    try
    {
      conn.add(addRequest);
      fail("Expected an exception when trying to proxy as a nonexistent user");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.AUTHORIZATION_DENIED);
    }


    // Test proxied as a malformed DN.
    addRequest = new AddRequest(
         "dn: ou=test8,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test8");
    addRequest.setControls(new ProxiedAuthorizationV2RequestControl(
         "dn:malformed-dn"));

    try
    {
      conn.add(addRequest);
      fail("Expected an exception when trying to proxy as a malformed DN");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }


    // Test proxied as a malformed authorization ID.
    addRequest = new AddRequest(
         "dn: ou=test9,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test9");
    addRequest.setControls(new ProxiedAuthorizationV2RequestControl(
         "malformed-authzID"));

    try
    {
      conn.add(addRequest);
      fail("Expected an exception when trying to proxy as a malformed authzID");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.AUTHORIZATION_DENIED);
    }


    // Test proxied with a non-unique u-style authorization ID.
    addRequest = new AddRequest(
         "dn: ou=test10,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test10");
    addRequest.setControls(new ProxiedAuthorizationV2RequestControl(
         "u:duplicate-uid"));

    try
    {
      conn.add(addRequest);
      fail("Expected an exception when trying to proxy as a malformed authzID");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.AUTHORIZATION_DENIED);
    }


    conn.close();
  }



  /**
   * Provides test coverage for the server-side sort request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testServerSideSortControl()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, false);

    ds.addEntries(
         generateOrgUnitEntry("People", "dc=example,dc=com"),
         generateUserEntry("aaron.asparagus", "ou=People,dc=example,dc=com",
              "Aaron", "Asparagus", "password"),
         generateUserEntry("andrea.asparagus", "ou=People,dc=example,dc=com",
              "Andrea", "Asparagus", "password"),
         generateUserEntry("barbara.beet", "ou=People,dc=example,dc=com",
              "Barbara", "Beet", "password"),
         generateUserEntry("barney.beet", "ou=People,dc=example,dc=com",
              "Barney", "Beet", "password"),
         generateUserEntry("carol.cabbage", "ou=People,dc=example,dc=com",
              "Carol", "Cabbage", "password"),
         generateUserEntry("charlie.cabbage", "ou=People,dc=example,dc=com",
              "Charlie", "Cabbage", "password"));

    final LDAPConnection conn = ds.getConnection();


    // Test without the sort control and verify that no response control is
    // returned.  Although the order in which entries are returned will be
    // predictable (based on DN ordering), we don't really care about that.
    final SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, "(objectClass=person)");

    SearchResult searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 6);
    assertNotNull(searchResult.getSearchEntries());
    assertEquals(searchResult.getSearchEntries().size(), 6);
    assertFalse(searchResult.hasResponseControl(
         ServerSideSortResponseControl.SERVER_SIDE_SORT_RESPONSE_OID));


    // Test with a sort control that will sort first based on last name
    // (ascending), then based on first name (ascending).
    searchRequest.setControls(new ServerSideSortRequestControl(true,
         new SortKey("sn"), new SortKey("givenName")));

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 6);

    ServerSideSortResponseControl sortResponse =
         ServerSideSortResponseControl.get(searchResult);
    assertNotNull(sortResponse);
    assertEquals(sortResponse.getResultCode(), ResultCode.SUCCESS);
    assertNull(sortResponse.getAttributeName());

    List<SearchResultEntry> entryList = searchResult.getSearchEntries();
    assertNotNull(entryList);
    assertEquals(entryList.size(), 6);

    assertEquals(entryList.get(0).getParsedDN(),
         new DN("uid=aaron.asparagus,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(1).getParsedDN(),
         new DN("uid=andrea.asparagus,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(2).getParsedDN(),
         new DN("uid=barbara.beet,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(3).getParsedDN(),
         new DN("uid=barney.beet,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(4).getParsedDN(),
         new DN("uid=carol.cabbage,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(5).getParsedDN(),
         new DN("uid=charlie.cabbage,ou=People,dc=example,dc=com"));


    // Test with a sort control that will sort first based on last name
    // (descending), then based on first name (descending).
    searchRequest.setControls(new ServerSideSortRequestControl(true,
         new SortKey("sn", true), new SortKey("givenName", true)));

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 6);

    sortResponse = ServerSideSortResponseControl.get(searchResult);
    assertNotNull(sortResponse);
    assertEquals(sortResponse.getResultCode(), ResultCode.SUCCESS);
    assertNull(sortResponse.getAttributeName());

    entryList = searchResult.getSearchEntries();
    assertNotNull(entryList);
    assertEquals(entryList.size(), 6);

    assertEquals(entryList.get(0).getParsedDN(),
         new DN("uid=charlie.cabbage,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(1).getParsedDN(),
         new DN("uid=carol.cabbage,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(2).getParsedDN(),
         new DN("uid=barney.beet,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(3).getParsedDN(),
         new DN("uid=barbara.beet,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(4).getParsedDN(),
         new DN("uid=andrea.asparagus,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(5).getParsedDN(),
         new DN("uid=aaron.asparagus,ou=People,dc=example,dc=com"));


    // Test with a sort control that will sort first based on last name
    // (ascending), then based on first name (descending).
    searchRequest.setControls(new ServerSideSortRequestControl(true,
         new SortKey("sn", false), new SortKey("givenName", true)));

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 6);

    sortResponse = ServerSideSortResponseControl.get(searchResult);
    assertNotNull(sortResponse);
    assertEquals(sortResponse.getResultCode(), ResultCode.SUCCESS);
    assertNull(sortResponse.getAttributeName());

    entryList = searchResult.getSearchEntries();
    assertNotNull(entryList);
    assertEquals(entryList.size(), 6);

    assertEquals(entryList.get(0).getParsedDN(),
         new DN("uid=andrea.asparagus,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(1).getParsedDN(),
         new DN("uid=aaron.asparagus,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(2).getParsedDN(),
         new DN("uid=barney.beet,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(3).getParsedDN(),
         new DN("uid=barbara.beet,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(4).getParsedDN(),
         new DN("uid=charlie.cabbage,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(5).getParsedDN(),
         new DN("uid=carol.cabbage,ou=People,dc=example,dc=com"));


    conn.close();
  }



  /**
   * Provides test coverage for the simple paged results control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimplePagedResultsControl()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final LDAPConnection conn = ds.getConnection();

    for (int i=0; i < 100; i++)
    {
      conn.add(generateUserEntry("test." + i, "ou=People,dc=example,dc=com",
           "Test", String.valueOf(i), "password"));
    }

    final int totalEntries = ds.countEntries();
    final HashSet<DN> returnedEntries = new HashSet<DN>(totalEntries);


    // Use the simple paged results control to iterate across all the entries
    // in batches of 10.
    final SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, "(objectClass=*)");
    searchRequest.addControl(new SimplePagedResultsControl(10, true));

    boolean sawTen         = false;
    boolean sawLessThanTen = false;
    while (true)
    {
      final SearchResult searchResult = conn.search(searchRequest);

      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

      if (searchResult.getEntryCount() == 10)
      {
        sawTen = true;
        assertFalse(sawLessThanTen);
      }
      else
      {
        assertTrue(searchResult.getEntryCount() < 10);
        assertFalse(sawLessThanTen);
        sawLessThanTen = true;
      }

      for (final SearchResultEntry e : searchResult.getSearchEntries())
      {
        final DN dn = e.getParsedDN();
        assertFalse(returnedEntries.contains(dn));
        returnedEntries.add(dn);
      }

      final SimplePagedResultsControl pagedResultsResponse =
           SimplePagedResultsControl.get(searchResult);
      assertNotNull(pagedResultsResponse);

      assertEquals(pagedResultsResponse.getSize(), totalEntries);

      final ASN1OctetString cookie = pagedResultsResponse.getCookie();
      assertNotNull(cookie);
      if (cookie.getValueLength() == 0)
      {
        break;
      }
      else
      {
        searchRequest.setControls(
             new SimplePagedResultsControl(10, cookie, true));
      }
    }

    assertTrue(sawTen);
    assertTrue(sawLessThanTen);

    assertEquals(returnedEntries.size(), totalEntries);


    // Provide coverage for a request with a malformed cookie value.
    searchRequest.setControls(new SimplePagedResultsControl(10,
         new ASN1OctetString("this is a malformed cookie"), true));

    try
    {
      conn.search(searchRequest);
      fail("Expected an exception when trying to search with a malformed " +
           "simple paged results cookie");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.PROTOCOL_ERROR);
    }

    conn.close();
  }



  /**
   * Provides test coverage for the subentries request control as described in
   * draft-ietf-ldup-subentry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDraftLDUPSubentriesControl()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();

    final DraftLDUPSubentriesRequestControl c =
         new DraftLDUPSubentriesRequestControl();

    conn.add(
         "dn: cn=subentry test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "cn: subentry test");


    // Ensure that the subentry is returned for a base-level search even if the
    // control is not present.
    SearchRequest searchRequest = new SearchRequest(
         "cn=subentry test,dc=example,dc=com", SearchScope.BASE,
         "(objectClass=*)");

    SearchResult searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);
    assertNotNull(searchResult.getSearchEntry(
         "cn=subentry test,dc=example,dc=com"));


    // Ensure that the entry is also returned for a base-level search if the
    // control is provided.
    searchRequest.setControls(c);

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);
    assertNotNull(searchResult.getSearchEntry(
         "cn=subentry test,dc=example,dc=com"));


    // Ensure that the subentry is not returned for a non-base search without
    // the control.
    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 3);
    assertNotNull(searchResult.getSearchEntry("dc=example,dc=com"));
    assertNotNull(searchResult.getSearchEntry("ou=People,dc=example,dc=com"));
    assertNotNull(searchResult.getSearchEntry(
         "uid=test.user,ou=People,dc=example,dc=com"));
    assertNull(searchResult.getSearchEntry(
         "cn=subentry test,dc=example,dc=com"));


    // Ensure that only the subentry is returned for the same non-base search if
    // the subentries control is provided.
    searchRequest.setControls(c);

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);
    assertNotNull(searchResult.getSearchEntry(
         "cn=subentry test,dc=example,dc=com"));


    // Ensure that the subentry is returned for a non-base search without the
    // control if the base entry is a subentry.
    searchRequest = new SearchRequest("cn=subentry test,dc=example,dc=com",
         SearchScope.SUB, "(objectClass=*)");

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);
    assertNotNull(searchResult.getSearchEntry(
         "cn=subentry test,dc=example,dc=com"));


    // Ensure that the subentry is still returned for the same non-base search
    // if the subentries control is provided.
    searchRequest.setControls(c);

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);
    assertNotNull(searchResult.getSearchEntry(
         "cn=subentry test,dc=example,dc=com"));


    // Ensure that only the subentry is returned for a subtree search from the
    // naming context with a filter of "(objectClass=ldapSubEntry)".
    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         Filter.createEqualityFilter("objectClass", "ldapSubEntry"));

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);
    assertNull(searchResult.getSearchEntry(
         "dc=example,dc=com"));
    assertNull(searchResult.getSearchEntry(
         "ou=People,dc=example,dc=com"));
    assertNull(searchResult.getSearchEntry(
         "uid=test.user,ou=People,dc=example,dc=com"));
    assertNotNull(searchResult.getSearchEntry(
         "cn=subentry test,dc=example,dc=com"));


    // Ensure that all entries, including subentry are returned for a subtree
    // search from the naming context with a filter of
    // "(|(objectClass=*)(objectClass=ldapSubEntry))".
    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         Filter.createORFilter(
              Filter.createPresenceFilter("objectClass"),
              Filter.createEqualityFilter("objectClass", "ldapSubEntry")));

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 4);
    assertNotNull(searchResult.getSearchEntry(
         "dc=example,dc=com"));
    assertNotNull(searchResult.getSearchEntry(
         "ou=People,dc=example,dc=com"));
    assertNotNull(searchResult.getSearchEntry(
         "uid=test.user,ou=People,dc=example,dc=com"));
    assertNotNull(searchResult.getSearchEntry(
         "cn=subentry test,dc=example,dc=com"));


    conn.close();
  }



  /**
   * Provides test coverage for the subentries request control as described in
   * RFC 3672.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRFC3672SubentriesControl()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();

    RFC3672SubentriesRequestControl returnOnlySubentriesControl =
         new RFC3672SubentriesRequestControl(true);
    RFC3672SubentriesRequestControl returnRegularAndSubentriesControl =
         new RFC3672SubentriesRequestControl(false);

    conn.add(
         "dn: cn=subentry test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "cn: subentry test");


    // Ensure that the subentry is returned for a base-level search even if the
    // control is not present.
    SearchRequest searchRequest = new SearchRequest(
         "cn=subentry test,dc=example,dc=com", SearchScope.BASE,
         "(objectClass=*)");

    SearchResult searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);
    assertNotNull(searchResult.getSearchEntry(
         "cn=subentry test,dc=example,dc=com"));


    // Ensure that the entry is also returned for a base-level search if the
    // control is provided, regardless of whether regular entries are to be
    // returned.
    searchRequest.setControls(returnOnlySubentriesControl);

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);
    assertNotNull(searchResult.getSearchEntry(
         "cn=subentry test,dc=example,dc=com"));

    searchRequest.setControls(returnRegularAndSubentriesControl);

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);
    assertNotNull(searchResult.getSearchEntry(
         "cn=subentry test,dc=example,dc=com"));


    // Ensure that the subentry is not returned for a non-base search without
    // the control.
    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 3);
    assertNotNull(searchResult.getSearchEntry("dc=example,dc=com"));
    assertNotNull(searchResult.getSearchEntry("ou=People,dc=example,dc=com"));
    assertNotNull(searchResult.getSearchEntry(
         "uid=test.user,ou=People,dc=example,dc=com"));
    assertNull(searchResult.getSearchEntry(
         "cn=subentry test,dc=example,dc=com"));


    // Ensure that only the subentry is returned for the same non-base search if
    // the subentries control is provided with returnOnlySubnetries flag set to
    // true.
    searchRequest.setControls(returnOnlySubentriesControl);

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);
    assertNotNull(searchResult.getSearchEntry(
         "cn=subentry test,dc=example,dc=com"));


    // Ensure that all entries, including subentry are returned for a subtree
    // search from the naming context with a filter of
    // "(|(objectClass=*)(objectClass=ldapSubEntry))".
    searchRequest.setControls(returnRegularAndSubentriesControl);

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 4);
    assertNotNull(searchResult.getSearchEntry(
         "dc=example,dc=com"));
    assertNotNull(searchResult.getSearchEntry(
         "ou=People,dc=example,dc=com"));
    assertNotNull(searchResult.getSearchEntry(
         "uid=test.user,ou=People,dc=example,dc=com"));
    assertNotNull(searchResult.getSearchEntry(
         "cn=subentry test,dc=example,dc=com"));


    conn.close();
  }



  /**
   * Provides test coverage for the subtree delete request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSubtreeDeleteControl()
         throws Exception
  {
    // We'll use a changelog so that we can verify the order in which the
    // entries were deleted.  Also, we'll use short base DNs.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("o=a");
    cfg.setMaxChangeLogEntries(1000);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();


    try
    {
      final SubtreeDeleteRequestControl c = new SubtreeDeleteRequestControl();
      final LDAPConnection conn = ds.getConnection();


      // Create the test hierarchy.  It will look like the following:
      // o=a
      //   o=b1,o=a
      //     o=c1,b1,o=a
      //       o=d1,o=c1,o=b1,o=a
      //       o=d2,o=c1,o=b1,o=a
      //     o=c2,b1,o=a
      //       o=d1,o=c2,o=b1,o=a
      //       o=d2,o=c2,o=b1,o=a
      //   o=b2,o=a
      //     o=c1,b2,o=a
      //       o=d1,o=c1,o=b2,o=a
      //       o=d2,o=c1,o=b2,o=a
      //     o=c2,b2,o=a
      //       o=d1,o=c2,o=b2,o=a
      //       o=d2,o=c2,o=b2,o=a
      conn.add(generateOrgEntry("a", null));
      conn.add(generateOrgEntry("b1", "o=a"));
      conn.add(generateOrgEntry("b2", "o=a"));
      conn.add(generateOrgEntry("c1", "o=b1,o=a"));
      conn.add(generateOrgEntry("c2", "o=b1,o=a"));
      conn.add(generateOrgEntry("c1", "o=b2,o=a"));
      conn.add(generateOrgEntry("c2", "o=b2,o=a"));
      conn.add(generateOrgEntry("d1", "o=c1,o=b1,o=a"));
      conn.add(generateOrgEntry("d2", "o=c1,o=b1,o=a"));
      conn.add(generateOrgEntry("d1", "o=c2,o=b1,o=a"));
      conn.add(generateOrgEntry("d2", "o=c2,o=b1,o=a"));
      conn.add(generateOrgEntry("d1", "o=c1,o=b2,o=a"));
      conn.add(generateOrgEntry("d2", "o=c1,o=b2,o=a"));
      conn.add(generateOrgEntry("d1", "o=c2,o=b2,o=a"));
      conn.add(generateOrgEntry("d2", "o=c2,o=b2,o=a"));


      // Get the last number.  It should be 15.
      ds.assertValueExists("", "lastChangeNumber", "15");


      // Delete a leaf entry with the subtree delete control.
      final DeleteRequest deleteRequest =
           new DeleteRequest("o=d2,o=c2,o=b2,o=a");
      deleteRequest.setControls(c);

      LDAPResult deleteResult = conn.delete(deleteRequest);
      assertEquals(deleteResult.getResultCode(), ResultCode.SUCCESS);

      ds.assertValueExists("", "lastChangeNumber", "16");
      ds.assertValueExists("changeNumber=16,cn=changelog", "targetDN",
           "o=d2,o=c2,o=b2,o=a");


      // Delete an entry with a single level of subordinates with the subtree
      // delete control.  It should delete entries in the following order:
      // * o=d2,o=c1,o=b2,o=a
      // * o=d1,o=c1,o=b2,o=a
      // * o=c1,o=b2,o=a
      deleteRequest.setDN("o=c1,o=b2,o=a");

      deleteResult = conn.delete(deleteRequest);
      assertEquals(deleteResult.getResultCode(), ResultCode.SUCCESS);

      ds.assertValueExists("", "lastChangeNumber", "19");
      ds.assertValueExists("changeNumber=17,cn=changelog", "targetDN",
           "o=d2,o=c1,o=b2,o=a");
      ds.assertValueExists("changeNumber=18,cn=changelog", "targetDN",
           "o=d1,o=c1,o=b2,o=a");
      ds.assertValueExists("changeNumber=19,cn=changelog", "targetDN",
           "o=c1,o=b2,o=a");


      // Delete all remaining entries from the base DN.  It should delete
      // entries in the following order:
      // * o=d1,o=c2,o=b2,o=a
      // * o=c2,b2,o=a
      // * o=b2,o=a
      // * o=d2,o=c2,o=b1,o=a
      // * o=d1,o=c2,o=b1,o=a
      // * o=c2,b1,o=a
      // * o=d2,o=c1,o=b1,o=a
      // * o=d1,o=c1,o=b1,o=a
      // * o=c1,b1,o=a
      // * o=b1,o=a
      // * o=a
      deleteRequest.setDN("o=a");

      deleteResult = conn.delete(deleteRequest);
      assertEquals(deleteResult.getResultCode(), ResultCode.SUCCESS);

      ds.assertValueExists("", "lastChangeNumber", "30");
      ds.assertValueExists("changeNumber=20,cn=changelog", "targetDN",
           "o=d1,o=c2,o=b2,o=a");
      ds.assertValueExists("changeNumber=21,cn=changelog", "targetDN",
           "o=c2,o=b2,o=a");
      ds.assertValueExists("changeNumber=22,cn=changelog", "targetDN",
           "o=b2,o=a");
      ds.assertValueExists("changeNumber=23,cn=changelog", "targetDN",
           "o=d2,o=c2,o=b1,o=a");
      ds.assertValueExists("changeNumber=24,cn=changelog", "targetDN",
           "o=d1,o=c2,o=b1,o=a");
      ds.assertValueExists("changeNumber=25,cn=changelog", "targetDN",
           "o=c2,o=b1,o=a");
      ds.assertValueExists("changeNumber=26,cn=changelog", "targetDN",
           "o=d2,o=c1,o=b1,o=a");
      ds.assertValueExists("changeNumber=27,cn=changelog", "targetDN",
           "o=d1,o=c1,o=b1,o=a");
      ds.assertValueExists("changeNumber=28,cn=changelog", "targetDN",
           "o=c1,o=b1,o=a");
      ds.assertValueExists("changeNumber=29,cn=changelog", "targetDN",
           "o=b1,o=a");
      ds.assertValueExists("changeNumber=30,cn=changelog", "targetDN",
           "o=a");


      conn.close();
    }
    finally
    {
      ds.shutDown(true);
    }
  }



  /**
   * Provides test coverage for the virtual list view request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testVirtualListViewControl()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final LDAPConnection conn = ds.getConnection();

    conn.delete("uid=test.user,ou=People,dc=example,dc=com");

    for (int i=0; i < 100; i++)
    {
      final String snValue;
      if (i < 10)
      {
        snValue = "0" + i;
      }
      else
      {
        snValue = String.valueOf(i);
      }

      conn.add(generateUserEntry("test." + snValue,
           "ou=People,dc=example,dc=com", "Test", snValue, "password"));
    }


    // Create a search request that will match all users.  Don't include any
    // controls in the request.
    final SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, "(objectClass=person)");

    SearchResult searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 100);
    assertFalse(searchResult.hasResponseControl(
         VirtualListViewResponseControl.VIRTUAL_LIST_VIEW_RESPONSE_OID));


    // Use VLV to retrieve the first 10 entries of the set by offset, sorted
    // by sn.
    final ServerSideSortRequestControl sortControl =
         new ServerSideSortRequestControl(true, new SortKey("sn"));
    searchRequest.setControls(sortControl,
         new VirtualListViewRequestControl(1, 0, 9, 0, null));

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 10);

    List<SearchResultEntry> entryList = searchResult.getSearchEntries();
    assertEquals(entryList.size(), 10);
    assertEquals(entryList.get(0).getParsedDN(),
         new DN("uid=test.00,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(1).getParsedDN(),
         new DN("uid=test.01,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(2).getParsedDN(),
         new DN("uid=test.02,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(3).getParsedDN(),
         new DN("uid=test.03,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(4).getParsedDN(),
         new DN("uid=test.04,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(5).getParsedDN(),
         new DN("uid=test.05,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(6).getParsedDN(),
         new DN("uid=test.06,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(7).getParsedDN(),
         new DN("uid=test.07,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(8).getParsedDN(),
         new DN("uid=test.08,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(9).getParsedDN(),
         new DN("uid=test.09,ou=People,dc=example,dc=com"));

    VirtualListViewResponseControl vlvResponse =
         VirtualListViewResponseControl.get(searchResult);
    assertNotNull(vlvResponse);
    assertEquals(vlvResponse.getResultCode(), ResultCode.SUCCESS);
    assertEquals(vlvResponse.getContentCount(), 100);
    assertEquals(vlvResponse.getTargetPosition(), 1);
    assertNull(vlvResponse.getContextID());


    // Use VLV to retrieve entries from the beginning of the list, with the
    // before count beyond the beginning of the list.
    searchRequest.setControls(sortControl,
         new VirtualListViewRequestControl(3, 5, 4, 0, null));

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 7);

    entryList = searchResult.getSearchEntries();
    assertEquals(entryList.size(), 7);
    assertEquals(entryList.get(0).getParsedDN(),
         new DN("uid=test.00,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(1).getParsedDN(),
         new DN("uid=test.01,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(2).getParsedDN(),
         new DN("uid=test.02,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(3).getParsedDN(),
         new DN("uid=test.03,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(4).getParsedDN(),
         new DN("uid=test.04,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(5).getParsedDN(),
         new DN("uid=test.05,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(6).getParsedDN(),
         new DN("uid=test.06,ou=People,dc=example,dc=com"));

    vlvResponse = VirtualListViewResponseControl.get(searchResult);
    assertNotNull(vlvResponse);
    assertEquals(vlvResponse.getResultCode(), ResultCode.SUCCESS);
    assertEquals(vlvResponse.getContentCount(), 100);
    assertEquals(vlvResponse.getTargetPosition(), 3);
    assertNull(vlvResponse.getContextID());


    // Use VLV to retrieve entries from near the end of the list, with the after
    // count beyond the end of the list.
    searchRequest.setControls(sortControl,
         new VirtualListViewRequestControl(95, 2, 10, 0, null));

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 8);

    entryList = searchResult.getSearchEntries();
    assertEquals(entryList.size(), 8);
    assertEquals(entryList.get(0).getParsedDN(),
         new DN("uid=test.92,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(1).getParsedDN(),
         new DN("uid=test.93,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(2).getParsedDN(),
         new DN("uid=test.94,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(3).getParsedDN(),
         new DN("uid=test.95,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(4).getParsedDN(),
         new DN("uid=test.96,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(5).getParsedDN(),
         new DN("uid=test.97,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(6).getParsedDN(),
         new DN("uid=test.98,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(7).getParsedDN(),
         new DN("uid=test.99,ou=People,dc=example,dc=com"));

    vlvResponse = VirtualListViewResponseControl.get(searchResult);
    assertNotNull(vlvResponse);
    assertEquals(vlvResponse.getResultCode(), ResultCode.SUCCESS);
    assertEquals(vlvResponse.getContentCount(), 100);
    assertEquals(vlvResponse.getTargetPosition(), 95);
    assertNull(vlvResponse.getContextID());


    // Use VLV with an offset beyond the end of the list and no before count.
    searchRequest.setControls(sortControl,
         new VirtualListViewRequestControl(200, 0, 9, 0, null));

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 0);

    entryList = searchResult.getSearchEntries();
    assertEquals(entryList.size(), 0);

    vlvResponse = VirtualListViewResponseControl.get(searchResult);
    assertNotNull(vlvResponse);
    assertEquals(vlvResponse.getResultCode(), ResultCode.SUCCESS);
    assertEquals(vlvResponse.getContentCount(), 100);
    assertEquals(vlvResponse.getTargetPosition(), 101);
    assertNull(vlvResponse.getContextID());


    // Use VLV with an assertion value in the middle of the list and the entire
    // result set inside the list.
    searchRequest.setControls(sortControl,
         new VirtualListViewRequestControl("45", 5, 4, null));

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 10);

    entryList = searchResult.getSearchEntries();
    assertEquals(entryList.size(), 10);
    assertEquals(entryList.get(0).getParsedDN(),
         new DN("uid=test.40,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(1).getParsedDN(),
         new DN("uid=test.41,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(2).getParsedDN(),
         new DN("uid=test.42,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(3).getParsedDN(),
         new DN("uid=test.43,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(4).getParsedDN(),
         new DN("uid=test.44,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(5).getParsedDN(),
         new DN("uid=test.45,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(6).getParsedDN(),
         new DN("uid=test.46,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(7).getParsedDN(),
         new DN("uid=test.47,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(8).getParsedDN(),
         new DN("uid=test.48,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(9).getParsedDN(),
         new DN("uid=test.49,ou=People,dc=example,dc=com"));

    vlvResponse = VirtualListViewResponseControl.get(searchResult);
    assertNotNull(vlvResponse);
    assertEquals(vlvResponse.getResultCode(), ResultCode.SUCCESS);
    assertEquals(vlvResponse.getContentCount(), 100);
    assertEquals(vlvResponse.getTargetPosition(), 46);
    assertNull(vlvResponse.getContextID());


    // Use VLV with an assertion value in the middle of the list and the before
    // count beyond the beginning of the list.
    searchRequest.setControls(sortControl,
         new VirtualListViewRequestControl("03", 10, 3, null));

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 7);

    entryList = searchResult.getSearchEntries();
    assertEquals(entryList.size(), 7);
    assertEquals(entryList.get(0).getParsedDN(),
         new DN("uid=test.00,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(1).getParsedDN(),
         new DN("uid=test.01,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(2).getParsedDN(),
         new DN("uid=test.02,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(3).getParsedDN(),
         new DN("uid=test.03,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(4).getParsedDN(),
         new DN("uid=test.04,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(5).getParsedDN(),
         new DN("uid=test.05,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(6).getParsedDN(),
         new DN("uid=test.06,ou=People,dc=example,dc=com"));

    vlvResponse = VirtualListViewResponseControl.get(searchResult);
    assertNotNull(vlvResponse);
    assertEquals(vlvResponse.getResultCode(), ResultCode.SUCCESS);
    assertEquals(vlvResponse.getContentCount(), 100);
    assertEquals(vlvResponse.getTargetPosition(), 4);
    assertNull(vlvResponse.getContextID());


    // Use VLV with an assertion value before the beginning of the list.
    searchRequest.setControls(sortControl,
         new VirtualListViewRequestControl(".", 0, 5, null));

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 6);

    entryList = searchResult.getSearchEntries();
    assertEquals(entryList.size(), 6);
    assertEquals(entryList.get(0).getParsedDN(),
         new DN("uid=test.00,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(1).getParsedDN(),
         new DN("uid=test.01,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(2).getParsedDN(),
         new DN("uid=test.02,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(3).getParsedDN(),
         new DN("uid=test.03,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(4).getParsedDN(),
         new DN("uid=test.04,ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(5).getParsedDN(),
         new DN("uid=test.05,ou=People,dc=example,dc=com"));

    vlvResponse = VirtualListViewResponseControl.get(searchResult);
    assertNotNull(vlvResponse);
    assertEquals(vlvResponse.getResultCode(), ResultCode.SUCCESS);
    assertEquals(vlvResponse.getContentCount(), 100);
    assertEquals(vlvResponse.getTargetPosition(), 1);
    assertNull(vlvResponse.getContextID());


    // Use VLV with an assertion value beyond the end of the list.
    searchRequest.setControls(sortControl,
         new VirtualListViewRequestControl(":", 0, 5, null));

    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 0);

    entryList = searchResult.getSearchEntries();
    assertEquals(entryList.size(), 0);

    vlvResponse = VirtualListViewResponseControl.get(searchResult);
    assertNotNull(vlvResponse);
    assertEquals(vlvResponse.getResultCode(), ResultCode.SUCCESS);
    assertEquals(vlvResponse.getContentCount(), 100);
    assertEquals(vlvResponse.getTargetPosition(), 101);
    assertNull(vlvResponse.getContextID());


    conn.close();
  }
}
