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
package com.unboundid.ldap.sdk.controls;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.AsyncRequestID;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.BindRequest;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.TestAsyncListener;
import com.unboundid.util.LDAPTestUtils;



/**
 * This class is primarily intended to ensure that code provided in javadoc
 * examples is valid.
 */
public final class ExampleUsagesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the example in the {@code AssertionRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAssertionRequestControlExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServerConfig dsConfig =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsConfig.setSchema(null);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsConfig);
    ds.startListening();
    final LDAPConnection connection = ds.getConnection();
    connection.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    connection.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");
    connection.add(
         "dn: uid=john.doe,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "objectClass: extensibleObject",
         "uid: john.doe",
         "givenName: John",
         "sn: Doe",
         "cn: John Doe",
         "accountBalance: 1234.56");


    /* ----- BEGIN EXAMPLE CODE ----- */
    Modification mod = new Modification(ModificationType.REPLACE,
         "accountBalance", "543.21");
    ModifyRequest modifyRequest =
         new ModifyRequest("uid=john.doe,ou=People,dc=example,dc=com", mod);
    modifyRequest.addControl(
         new AssertionRequestControl("(accountBalance=1234.56)"));

    LDAPResult modifyResult;
    try
    {
      modifyResult = connection.modify(modifyRequest);
      // If we've gotten here, then the modification was successful.
    }
    catch (LDAPException le)
    {
      modifyResult = le.toLDAPResult();
      ResultCode resultCode = le.getResultCode();
      String errorMessageFromServer = le.getDiagnosticMessage();
      if (resultCode == ResultCode.ASSERTION_FAILED)
      {
        // The modification failed because the account balance value wasn't
        // what we thought it was.
      }
      else
      {
        // The modification failed for some other reason.
      }
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    ds.shutDown(true);
    assertResultCodeEquals(modifyResult, ResultCode.SUCCESS);
  }



  /**
   * Tests the example in the {@code AuthorizationIdentityRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthorizationIdentityRequestControlExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection connection = ds.getConnection();


    /* ----- BEGIN EXAMPLE CODE ----- */
    String authzID = null;
    BindRequest bindRequest =
         new SimpleBindRequest("uid=test.user,ou=People,dc=example,dc=com",
              "password", new AuthorizationIdentityRequestControl());

    BindResult bindResult = connection.bind(bindRequest);
    AuthorizationIdentityResponseControl authzIdentityResponse =
         AuthorizationIdentityResponseControl.get(bindResult);
    if (authzIdentityResponse != null)
    {
      authzID = authzIdentityResponse.getAuthorizationID();
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertResultCodeEquals(bindResult, ResultCode.SUCCESS);
    assertNotNull(authzIdentityResponse);
    assertNotNull(authzID);
    if (authzID.startsWith("dn:"))
    {
      assertTrue(authzID.equalsIgnoreCase(
           "dn:uid=test.user,ou=People,dc=example,dc=com"));
    }
    else if (authzID.startsWith("u:"))
    {
      assertTrue(authzID.equalsIgnoreCase("u:test.user"));
    }
    else
    {
      fail("Unexpected authorization ID '" + authzID + '\'');
    }
  }



  /**
   * Tests the example in the {@code ManageDsaITRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testManageDsaITRequestControl()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    ds.add(
         "dn: ou=referral entry,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ou: this is a referral entry",
         "ref: ldap://ds.example.com:389/ou=referral entry,dc=example,dc=com");

    final String serverAddress = "localhost";
    final int serverPort = ds.getListenPort();
    final String bindDN = "cn=Directory Manager";
    final String bindPassword = "password";


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Establish a connection to the directory server.  Even though it's the
    // default behavior, we'll explicitly configure the connection to not follow
    // referrals.
    LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setFollowReferrals(false);
    LDAPConnection connection = new LDAPConnection(connectionOptions,
         serverAddress, serverPort, bindDN, bindPassword);

    // Try to delete an entry that will result in a referral.  Without the
    // ManageDsaIT request control, we should get an exception.
    DeleteRequest deleteRequest =
         new DeleteRequest("ou=referral entry,dc=example,dc=com");
    LDAPResult deleteResult;
    try
    {
      deleteResult = connection.delete(deleteRequest);
    }
    catch (LDAPException le)
    {
      // This exception is expected because we should get a referral, and
      // the connection is configured to not follow referrals.
      deleteResult = le.toLDAPResult();
      ResultCode resultCode = le.getResultCode();
      String errorMessageFromServer = le.getDiagnosticMessage();
      String[] referralURLs = le.getReferralURLs();
    }
    LDAPTestUtils.assertResultCodeEquals(deleteResult, ResultCode.REFERRAL);
    LDAPTestUtils.assertHasReferral(deleteResult);

    // Update the delete request to include the ManageDsaIT request control,
    // which will cause the server to try to delete the referral entry instead
    // of returning a referral response.  We'll assume that the delete is
    // successful.
    deleteRequest.addControl(new ManageDsaITRequestControl());
    try
    {
      deleteResult = connection.delete(deleteRequest);
    }
    catch (LDAPException le)
    {
      // The delete shouldn't trigger a referral, but it's possible that the
      // operation failed for some other reason (e.g., entry doesn't exist, the
      // user doesn't have permission to delete it, etc.).
      deleteResult = le.toLDAPResult();
    }
    LDAPTestUtils.assertResultCodeEquals(deleteResult, ResultCode.SUCCESS);
    LDAPTestUtils.assertMissingReferral(deleteResult);

    connection.close();
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code MatchedValuesRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchedValuesRequestControlExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection connection = ds.getConnection();


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Ensure that a test user has multiple description values.
    LDAPResult modifyResult = connection.modify(
         "uid=test.user,ou=People,dc=example,dc=com",
         new Modification(ModificationType.REPLACE,
              "description", // Attribute name
              "first", "second", "third", "fourth")); // Attribute values.
    assertResultCodeEquals(modifyResult, ResultCode.SUCCESS);

    // Perform a search to retrieve the test user entry without using the
    // matched values request control.  This should return all four description
    // values.
    SearchRequest searchRequest = new SearchRequest(
         "uid=test.user,ou=People,dc=example,dc=com", // Base DN
         SearchScope.BASE, // Scope
         Filter.createPresenceFilter("objectClass"), // Filter
         "description"); // Attributes to return.
    SearchResultEntry entryRetrievedWithoutControl =
         connection.searchForEntry(searchRequest);
    Attribute fullDescriptionAttribute =
         entryRetrievedWithoutControl.getAttribute("description");
    int numFullDescriptionValues = fullDescriptionAttribute.size();

    // Update the search request to include a matched values control that will
    // only return values that start with the letter "f".  In our test entry,
    // this should just match two values ("first" and "fourth").
    searchRequest.addControl(new MatchedValuesRequestControl(
         MatchedValuesFilter.createSubstringFilter("description", // Attribute
              "f", // subInitial component
              null, // subAny components
              null))); // subFinal component
    SearchResultEntry entryRetrievedWithControl =
         connection.searchForEntry(searchRequest);
    Attribute partialDescriptionAttribute =
         entryRetrievedWithControl.getAttribute("description");
    int numPartialDescriptionValues = partialDescriptionAttribute.size();
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertEquals(numFullDescriptionValues, 4);

    // NOTE:  At present, the in-memory directory server doesn't support the
    // matched values control.  However, since the control is non-critical, it
    // will be ignored and therefore the entry will just be returned with all
    // four values as if the control had not been provided.
    assertEquals(numPartialDescriptionValues, 4);
  }



  /**
   * Tests the example in the {@code PasswordExpiredControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordExpiredControlExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection connection = ds.getConnection();


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Send a simple bind request to the directory server.
    BindRequest bindRequest =
         new SimpleBindRequest("uid=test.user,ou=People,dc=example,dc=com",
              "password");
    BindResult bindResult;
    boolean bindSuccessful;
    boolean passwordExpired;
    boolean passwordAboutToExpire;
    try
    {
      bindResult = connection.bind(bindRequest);

      // If we got here, the bind was successful and we know the password was
      // not expired.  However, we shouldn't ignore the result because the
      // password might be about to expire.  To determine whether that is the
      // case, we should see if the bind result included a password expiring
      // control.
      bindSuccessful = true;
      passwordExpired = false;

      PasswordExpiringControl expiringControl =
           PasswordExpiringControl.get(bindResult);
      if (expiringControl != null)
      {
        passwordAboutToExpire = true;
        int secondsToExpiration = expiringControl.getSecondsUntilExpiration();
      }
      else
      {
        passwordAboutToExpire = false;
      }
    }
    catch (LDAPException le)
    {
      // If we got here, then the bind failed.  The failure may or may not have
      // been due to an expired password.  To determine that, we should see if
      // the bind result included a password expired control.
      bindSuccessful = false;
      passwordAboutToExpire = false;
      bindResult = new BindResult(le);
      ResultCode resultCode = le.getResultCode();
      String errorMessageFromServer = le.getDiagnosticMessage();

      PasswordExpiredControl expiredControl =
           PasswordExpiredControl.get(le);
      if (expiredControl != null)
      {
        passwordExpired = true;
      }
      else
      {
        passwordExpired = false;
      }
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();

    // The in-memory directory sever doesn't currently support password
    // expiration, so the bind should be successful with no hint of expiration.
    assertResultCodeEquals(bindResult, ResultCode.SUCCESS);
    assertTrue(bindSuccessful);
    assertFalse(passwordExpired);
    assertFalse(passwordAboutToExpire);
  }



  /**
   * Tests the example in the {@code PermissiveModifyRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPermissiveModifyRequestControlExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection connection = ds.getConnection();


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Ensure that we start with a known description value in the test entry
    // by using a replace to overwrite any existing value(s).
    ModifyRequest replaceRequest = new ModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com",
         new Modification(ModificationType.REPLACE, "description", "value"));
    LDAPResult replaceResult = connection.modify(replaceRequest);

    // Create a modify request that will attempt to add the value that already
    // exists.  If we attempt to do this without the permissive modify control,
    // the attempt should fail.
    ModifyRequest addExistingValueRequest = new ModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com",
         new Modification(ModificationType.ADD, "description", "value"));
    LDAPResult addExistingValueResultWithoutControl;
    try
    {
      addExistingValueResultWithoutControl =
           connection.modify(addExistingValueRequest);
      // We shouldn't get here because the attempt to add the existing value
      // should fail.
    }
    catch (LDAPException le)
    {
      // We expected this failure because the value we're trying to add already
      // exists in the entry.
      addExistingValueResultWithoutControl = le.toLDAPResult();
      ResultCode resultCode = le.getResultCode();
      String errorMessageFromServer = le.getDiagnosticMessage();
    }

    // Update the modify request to include the permissive modify request
    // control, and re-send the request.  The operation should now succeed.
    addExistingValueRequest.addControl(new PermissiveModifyRequestControl());
    LDAPResult addExistingValueResultWithControl;
    try
    {
      addExistingValueResultWithControl =
           connection.modify(addExistingValueRequest);
      // If we've gotten here, then the modification was successful.
    }
    catch (LDAPException le)
    {
      // If we've gotten here, then the modification failed for some reason.
      addExistingValueResultWithControl = le.toLDAPResult();
      ResultCode resultCode = le.getResultCode();
      String errorMessageFromServer = le.getDiagnosticMessage();
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertResultCodeEquals(replaceResult, ResultCode.SUCCESS);
    assertResultCodeEquals(addExistingValueResultWithoutControl,
         ResultCode.ATTRIBUTE_OR_VALUE_EXISTS);
    assertResultCodeEquals(addExistingValueResultWithControl,
         ResultCode.SUCCESS);
  }



  /**
   * Tests the example in the {@code PersistentSearchRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testPersistentSearchRequestControlExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support the use
    // of the persistent search control, so this test won't actually do anything
    // except verify that the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection connection = ds.getConnection();
    final TestAsyncListener asyncSearchListener = new TestAsyncListener();


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Create a persistent search request that will be notified when there are
    // any writes to any entries at or below "dc=example,dc=com".  The
    // search request should have an asynchronous search result listener so that
    // this thread won't block once the search has started, but results will be
    // handled as soon as they are received.
    SearchRequest persistentSearchRequest = new SearchRequest(
         asyncSearchListener, "dc=example,dc=com", SearchScope.SUB,
         Filter.createPresenceFilter("objectClass"));
    persistentSearchRequest.addControl(new PersistentSearchRequestControl(
         PersistentSearchChangeType.allChangeTypes(), // Notify change types.
         true, // Only return new changes, don't match existing entries.
         true)); // Include change notification controls in search entries.

    // Launch the persistent search as an asynchronous operation.
    AsyncRequestID persistentSearchRequestID =
         connection.asyncSearch(persistentSearchRequest);

    // Modify an entry that matches the persistent search criteria.  This
    // should cause the persistent search listener to be notified.
    LDAPResult modifyResult = connection.modify(
         "uid=test.user,ou=People,dc=example,dc=com",
         new Modification(ModificationType.REPLACE, "description", "test"));

    // Verify that the persistent search listener was notified....

    // Since persistent search operations don't end on their own, we need to
    // abandon the search when we don't need it anymore.
    connection.abandon(persistentSearchRequestID);
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
  }



  /**
   * Tests the example in the {@code PostReadRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPostReadRequestControlExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServerConfig dsConfig =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsConfig);
    ds.startListening();
    final LDAPConnection connection = ds.getConnection();

    connection.modify(
         "dn: cn=schema",
         "changetype: modify",
         "add: attributeTypes",
         "attributeTypes: ( test-counter-oid NAME 'test-counter' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 EQUALITY integerMatch " +
              "ORDERING integerOrderingMatch SINGLE-VALUE )");
    connection.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    connection.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");
    connection.add(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "objectClass: extensibleObject",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "test-counter: 123");


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Create a modify request that we can use to increment the value of a
    // custom attribute named "test-counter".
    ModifyRequest modifyRequest = new ModifyRequest(
         "uid=test.user,ou=People,dc=example,dc=com",
         new Modification(ModificationType.INCREMENT,
              "test-counter", // The attribute to increment.
              "1")); // The amount by which to increment the value.

    // Update the modify request to add both pre-read and post-read request
    // controls to see what the entry value was before and after the change.
    // We only care about getting the test-counter attribute.
    modifyRequest.setControls(
         new PreReadRequestControl("test-counter"),
         new PostReadRequestControl("test-counter"));

    // Process the modify operation in the server.
    LDAPResult modifyResult;
    try
    {
      modifyResult = connection.modify(modifyRequest);
      // If we got here, then the modification should have been successful.
    }
    catch (LDAPException le)
    {
      // This indicates that the operation did not complete successfully.
      modifyResult = le.toLDAPResult();
      ResultCode resultCode = le.getResultCode();
      String errorMessageFromServer = le.getDiagnosticMessage();
    }
    LDAPTestUtils.assertResultCodeEquals(modifyResult, ResultCode.SUCCESS);

    // Get the pre-read and post-read response controls from the server and
    // retrieve the before and after values for the test-counter attribute.
    LDAPTestUtils.assertHasControl(modifyResult,
         PreReadResponseControl.PRE_READ_RESPONSE_OID);
    PreReadResponseControl preReadResponse =
         PreReadResponseControl.get(modifyResult);
    Integer beforeValue =
         preReadResponse.getEntry().getAttributeValueAsInteger("test-counter");

    LDAPTestUtils.assertHasControl(modifyResult,
         PostReadResponseControl.POST_READ_RESPONSE_OID);
    PostReadResponseControl postReadResponse =
         PostReadResponseControl.get(modifyResult);
    Integer afterValue =
         postReadResponse.getEntry().getAttributeValueAsInteger("test-counter");
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    ds.shutDown(true);

    assertNotNull(beforeValue);
    assertEquals(beforeValue, Integer.valueOf(123));

    assertNotNull(afterValue);
    assertEquals(afterValue, Integer.valueOf(124));
  }



  /**
   * Tests the example in the {@code ProxiedAuthorizationV1RequestControl}
   * class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProxiedAuthorizationV1RequestControlExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection connection = ds.getConnection();

    connection.add(
         "dn: uid=alternate.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: alternate.user",
         "givenName: Alternate",
         "sn: User",
         "cn: Alternate User");


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Create a delete request to delete an entry.  Include the proxied
    // authorization v1 request control in the delete request so that the
    // delete will be processed as user
    // "uid=alternate.user,ou=People,dc=example,dc=com" instead of the user
    // that's actually authenticated on the connection.
    DeleteRequest deleteRequest =
         new DeleteRequest("uid=test.user,ou=People,dc=example,dc=com");
    deleteRequest.addControl(new ProxiedAuthorizationV1RequestControl(
         "uid=alternate.user,ou=People,dc=example,dc=com"));

    LDAPResult deleteResult;
    try
    {
      deleteResult = connection.delete(deleteRequest);
      // If we got here, then the delete was successful.
    }
    catch (LDAPException le)
    {
      // The delete failed for some reason.  In addition to all of the normal
      // reasons a delete could fail (e.g., the entry doesn't exist, or has one
      // or more subordinates), proxied-authorization specific failures may
      // include that the authenticated user doesn't have permission to use the
      // proxied authorization control to impersonate the alternate user, that
      // the alternate user doesn't exist, or that the alternate user doesn't
      // have permission to perform the requested operation.
      deleteResult = le.toLDAPResult();
      ResultCode resultCode = le.getResultCode();
      String errorMessageFromServer = le.getDiagnosticMessage();
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertResultCodeEquals(deleteResult, ResultCode.SUCCESS);
  }



  /**
   * Tests the example in the {@code ProxiedAuthorizationV2RequestControl}
   * class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProxiedAuthorizationV2RequestControlExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection connection = ds.getConnection();

    connection.add(
         "dn: uid=alternate.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: alternate.user",
         "givenName: Alternate",
         "sn: User",
         "cn: Alternate User");


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Create a delete request to delete an entry.  Include the proxied
    // authorization v2 request control in the delete request so that the
    // delete will be processed as the user with username "alternate.user"
    // instead of the user that's actually authenticated on the connection.
    DeleteRequest deleteRequest =
         new DeleteRequest("uid=test.user,ou=People,dc=example,dc=com");
    deleteRequest.addControl(new ProxiedAuthorizationV2RequestControl(
         "u:alternate.user"));

    LDAPResult deleteResult;
    try
    {
      deleteResult = connection.delete(deleteRequest);
      // If we got here, then the delete was successful.
    }
    catch (LDAPException le)
    {
      // The delete failed for some reason.  In addition to all of the normal
      // reasons a delete could fail (e.g., the entry doesn't exist, or has one
      // or more subordinates), proxied-authorization specific failures may
      // include that the authenticated user doesn't have permission to use the
      // proxied authorization control to impersonate the alternate user, that
      // the alternate user doesn't exist, or that the alternate user doesn't
      // have permission to perform the requested operation.
      deleteResult = le.toLDAPResult();
      ResultCode resultCode = le.getResultCode();
      String errorMessageFromServer = le.getDiagnosticMessage();
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertResultCodeEquals(deleteResult, ResultCode.SUCCESS);
  }



  /**
   * Tests the example in the {@code ServerSideSortRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testServerSideSortRequestControlExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final LDAPConnection connection = ds.getConnection();
    connection.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");
    connection.add(
         "dn: uid=aaron.baker,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: aaron.baker",
         "givenName: Aaron",
         "sn: Baker",
         "cn: Aaron Baker");
    connection.add(
         "dn: uid=charles.dunn,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: charles.dunn",
         "givenName: Charles",
         "sn: Dunn",
         "cn: Charles Dunn");
    connection.add(
         "dn: uid=erica.finn,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: erica.finn",
         "givenName: Erica",
         "sn: Finn",
         "cn: Erica Finn");
    connection.add(
         "dn: uid=grace.hamill,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: grace.hamill",
         "givenName: Grace",
         "sn: Hamill",
         "cn: Grace Hamill");


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Perform a search to get all user entries sorted by last name, then by
    // first name, both in ascending order.
    SearchRequest searchRequest = new SearchRequest(
         "ou=People,dc=example,dc=com", SearchScope.SUB,
         Filter.createEqualityFilter("objectClass", "person"));
    searchRequest.addControl(new ServerSideSortRequestControl(
         new SortKey("sn"), new SortKey("givenName")));
    SearchResult lastNameAscendingResult;
    try
    {
      lastNameAscendingResult = connection.search(searchRequest);
      // If we got here, then the search was successful.
    }
    catch (LDAPSearchException lse)
    {
      // The search failed for some reason.
      lastNameAscendingResult = lse.getSearchResult();
      ResultCode resultCode = lse.getResultCode();
      String errorMessageFromServer = lse.getDiagnosticMessage();
    }

    // Get the response control and retrieve the result code for the sort
    // processing.
    LDAPTestUtils.assertHasControl(lastNameAscendingResult,
         ServerSideSortResponseControl.SERVER_SIDE_SORT_RESPONSE_OID);
    ServerSideSortResponseControl lastNameAscendingResponseControl =
         ServerSideSortResponseControl.get(lastNameAscendingResult);
    ResultCode lastNameSortResult =
         lastNameAscendingResponseControl.getResultCode();


    // Perform the same search, but this time request the results to be sorted
    // in descending order by first name, then last name.
    searchRequest.setControls(new ServerSideSortRequestControl(
         new SortKey("givenName", true), new SortKey("sn", true)));
    SearchResult firstNameDescendingResult;
    try
    {
      firstNameDescendingResult = connection.search(searchRequest);
      // If we got here, then the search was successful.
    }
    catch (LDAPSearchException lse)
    {
      // The search failed for some reason.
      firstNameDescendingResult = lse.getSearchResult();
      ResultCode resultCode = lse.getResultCode();
      String errorMessageFromServer = lse.getDiagnosticMessage();
    }

    // Get the response control and retrieve the result code for the sort
    // processing.
    LDAPTestUtils.assertHasControl(firstNameDescendingResult,
         ServerSideSortResponseControl.SERVER_SIDE_SORT_RESPONSE_OID);
    ServerSideSortResponseControl firstNameDescendingResponseControl =
         ServerSideSortResponseControl.get(firstNameDescendingResult);
    ResultCode firstNameSortResult =
         firstNameDescendingResponseControl.getResultCode();
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();

    assertResultCodeEquals(lastNameAscendingResult, ResultCode.SUCCESS);
    assertEquals(lastNameSortResult, ResultCode.SUCCESS);
    assertEquals(lastNameAscendingResult.getEntryCount(), 4);
    assertTrue(lastNameAscendingResult.getSearchEntries().get(0).
         hasAttributeValue("sn", "Baker"));
    assertTrue(lastNameAscendingResult.getSearchEntries().get(1).
         hasAttributeValue("sn", "Dunn"));
    assertTrue(lastNameAscendingResult.getSearchEntries().get(2).
         hasAttributeValue("sn", "Finn"));
    assertTrue(lastNameAscendingResult.getSearchEntries().get(3).
         hasAttributeValue("sn", "Hamill"));

    assertResultCodeEquals(firstNameDescendingResult, ResultCode.SUCCESS);
    assertEquals(firstNameSortResult, ResultCode.SUCCESS);
    assertEquals(firstNameDescendingResult.getEntryCount(), 4);
    assertTrue(firstNameDescendingResult.getSearchEntries().get(0).
         hasAttributeValue("givenName", "Grace"));
    assertTrue(firstNameDescendingResult.getSearchEntries().get(1).
         hasAttributeValue("givenName", "Erica"));
    assertTrue(firstNameDescendingResult.getSearchEntries().get(2).
         hasAttributeValue("givenName", "Charles"));
    assertTrue(firstNameDescendingResult.getSearchEntries().get(3).
         hasAttributeValue("givenName", "Aaron"));
  }



  /**
   * Tests the example in the {@code SimplePagedResultsControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimplePagedResultsControlExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final LDAPConnection connection = ds.getConnection();
    connection.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");
    for (int i=0; i < 50; i++)
    {
      connection.add(
           "dn: uid=user." + i + ",ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: user." + i,
           "givenName: User",
           "sn: " + i,
           "cn: User " + i);
    }


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Perform a search to retrieve all users in the server, but only retrieving
    // ten at a time.
    int numSearches = 0;
    int totalEntriesReturned = 0;
    SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, Filter.createEqualityFilter("objectClass", "person"));
    ASN1OctetString resumeCookie = null;
    while (true)
    {
      searchRequest.setControls(
           new SimplePagedResultsControl(10, resumeCookie));
      SearchResult searchResult = connection.search(searchRequest);
      numSearches++;
      totalEntriesReturned += searchResult.getEntryCount();
      for (SearchResultEntry e : searchResult.getSearchEntries())
      {
        // Do something with each entry...
      }

      LDAPTestUtils.assertHasControl(searchResult,
           SimplePagedResultsControl.PAGED_RESULTS_OID);
      SimplePagedResultsControl responseControl =
           SimplePagedResultsControl.get(searchResult);
      if (responseControl.moreResultsToReturn())
      {
        // The resume cookie can be included in the simple paged results
        // control included in the next search to get the next page of results.
        resumeCookie = responseControl.getCookie();
      }
      else
      {
        break;
      }
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertEquals(numSearches, 5);
    assertEquals(totalEntriesReturned, 50);
  }



  /**
   * Tests the example in the {@code DraftLDUPSubentriesRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSubentriesRequestControlExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final LDAPConnection connection = ds.getConnection();
    connection.add(
         "dn: cn=test subentry,dc=example,dc=com",
         "objectClass: top",
         "objectClass: ldapSubentry",
         "cn: test subentry");


    /* ----- BEGIN EXAMPLE CODE ----- */
    // First, perform a search to retrieve an entry with a cn of "test subentry"
    // but without including the subentries request control.  This should not
    // return any matching entries.
    SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, Filter.createEqualityFilter("cn", "test subentry"));
    SearchResult resultWithoutControl = connection.search(searchRequest);
    LDAPTestUtils.assertResultCodeEquals(resultWithoutControl,
         ResultCode.SUCCESS);
    LDAPTestUtils.assertEntriesReturnedEquals(resultWithoutControl, 0);

    // Update the search request to add a subentries request control so that
    // subentries should be included in search results.  This should cause the
    // subentry to be returned.
    searchRequest.addControl(new DraftLDUPSubentriesRequestControl());
    SearchResult resultWithControl = connection.search(searchRequest);
    LDAPTestUtils.assertResultCodeEquals(resultWithControl, ResultCode.SUCCESS);
    LDAPTestUtils.assertEntriesReturnedEquals(resultWithControl, 1);
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
  }



  /**
   * Tests the example in the {@code SubtreeDeleteRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSubtreeDeleteRequestControlExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final LDAPConnection connection = ds.getConnection();
    connection.add(
         "dn: ou=entry with children,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: entry with children");
    connection.add(
         "dn: ou=child,ou=entry with children,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: child");


    /* ----- BEGIN EXAMPLE CODE ----- */
    // First, try to delete an entry that has children, but don't include the
    // subtree delete control.  This delete attempt should fail, and the
    // "NOT_ALLOWED_ON_NONLEAF" result is most appropriate if the failure reason
    // is that the entry has subordinates.
    DeleteRequest deleteRequest =
         new DeleteRequest("ou=entry with children,dc=example,dc=com");
    LDAPResult resultWithoutControl;
    try
    {
      resultWithoutControl = connection.delete(deleteRequest);
      // We shouldn't get here because the delete should fail.
    }
    catch (LDAPException le)
    {
      // This is expected because the entry has children.
      resultWithoutControl = le.toLDAPResult();
      ResultCode resultCode = le.getResultCode();
      String errorMessageFromServer = le.getDiagnosticMessage();
    }
    LDAPTestUtils.assertResultCodeEquals(resultWithoutControl,
         ResultCode.NOT_ALLOWED_ON_NONLEAF);

    // Update the delete request to include the subtree delete request control
    // and try again.
    deleteRequest.addControl(new SubtreeDeleteRequestControl());
    LDAPResult resultWithControl;
    try
    {
      resultWithControl = connection.delete(deleteRequest);
      // The delete should no longer be rejected just because the target entry
      // has children.
    }
    catch (LDAPException le)
    {
      // The delete still failed for some other reason.
      resultWithControl = le.toLDAPResult();
      ResultCode resultCode = le.getResultCode();
      String errorMessageFromServer = le.getDiagnosticMessage();
    }
    LDAPTestUtils.assertResultCodeEquals(resultWithControl, ResultCode.SUCCESS);
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
  }



  /**
   * Tests the example in the {@code VirtualListViewRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testVirtualListViewRequestControlExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final LDAPConnection connection = ds.getConnection();
    connection.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");
    for (int i=0; i < 50; i++)
    {
      connection.add(
           "dn: uid=user." + i + ",ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: user." + i,
           "givenName: User",
           "sn: " + i,
           "cn: User " + i);
    }


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Perform a search to retrieve all users in the server, but only retrieving
    // ten at a time.  Ensure that the users are sorted in ascending order by
    // last name, then first name.
    int numSearches = 0;
    int totalEntriesReturned = 0;
    SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, Filter.createEqualityFilter("objectClass", "person"));
    int vlvOffset = 1;
    int vlvContentCount = 0;
    ASN1OctetString vlvContextID = null;
    while (true)
    {
      // Note that the VLV control always requires the server-side sort
      // control.
      searchRequest.setControls(
           new ServerSideSortRequestControl(new SortKey("sn"),
                new SortKey("givenName")),
           new VirtualListViewRequestControl(vlvOffset, 0, 9, vlvContentCount,
                vlvContextID));
      SearchResult searchResult = connection.search(searchRequest);
      numSearches++;
      totalEntriesReturned += searchResult.getEntryCount();
      for (SearchResultEntry e : searchResult.getSearchEntries())
      {
        // Do something with each entry...
      }

      LDAPTestUtils.assertHasControl(searchResult,
           VirtualListViewResponseControl.VIRTUAL_LIST_VIEW_RESPONSE_OID);
      VirtualListViewResponseControl vlvResponseControl =
           VirtualListViewResponseControl.get(searchResult);
      vlvContentCount = vlvResponseControl.getContentCount();
      vlvOffset += 10;
      vlvContextID = vlvResponseControl.getContextID();
      if (vlvOffset > vlvContentCount)
      {
        break;
      }
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertEquals(numSearches, 5);
    assertEquals(totalEntriesReturned, 50);
  }
}
