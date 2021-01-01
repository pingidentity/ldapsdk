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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.BindRequest;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedRequest;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedResult;
import com.unboundid.util.LDAPTestUtils;



/**
 * This class is primarily intended to ensure that code provided in javadoc
 * examples is valid.
 */
public final class ExampleUsagesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the example in the {@code AccountUsableRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testAccountUsableRequestControlExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    SearchRequest searchRequest =
         new SearchRequest("dc=example,dc=com", SearchScope.SUB,
              Filter.createEqualityFilter("uid", "john.doe"));
    searchRequest.addControl(new AccountUsableRequestControl());
    SearchResult searchResult = connection.search(searchRequest);

    boolean isUsable = false;
    for (SearchResultEntry entry : searchResult.getSearchEntries())
    {
      AccountUsableResponseControl c =
           AccountUsableResponseControl.get(entry);
      isUsable = c.isUsable();
      if (isUsable)
      {
        // The account is usable.
      }
      else
      {
        // The account is not usable.
        List<String> unusableReasons = c.getUnusableReasons();
      }
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code AssuredReplicationRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testAssuredReplicationRequestControlExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    DeleteRequest deleteRequest = new DeleteRequest(
         "uid=test.user,ou=People,dc=example,dc=com");
    deleteRequest.addControl(new AssuredReplicationRequestControl(
         AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS,
         AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION,
         5000L));
     LDAPResult deleteResult = connection.delete(deleteRequest);

    if (deleteResult.getResultCode() == ResultCode.SUCCESS)
    {
      AssuredReplicationResponseControl assuredReplicationResponse =
           AssuredReplicationResponseControl.get(deleteResult);
      if (assuredReplicationResponse == null)
      {
        // The entry was deleted, but its replication could not be confirmed in
        // either the local or remote data centers.
      }
      else
      {
        if (assuredReplicationResponse.localAssuranceSatisfied())
        {
          if (assuredReplicationResponse.remoteAssuranceSatisfied())
          {
            // The entry was deleted.  The delete has been applied across all
            // available local servers, and has been replicated to at least one
            // remote data center.
          }
          else
          {
            // The entry was deleted.  The delete has been applied across all
            // available local servers, but cannot be confirmed to have yet
            // been replicated to any remote data centers.
          }
        }
        else if (assuredReplicationResponse.remoteAssuranceSatisfied())
        {
          // The entry was deleted.  The delete has been confirmed to have been
          // replicated to at least one remote data center, but cannot be
          // confirmed to have yet been applied to all available local servers.
        }
        else
        {
          // The entry was deleted, but its replication could not be confirmed
          // to either local servers or remote data centers.
        }
      }
    }
    else
    {
      // The entry could not be deleted.
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code ExtendedSchemaInfoRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testExtendedSchemaInfoRequestControlExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    String schemaDN = Schema.getSubschemaSubentryDN(connection, "");
    SearchRequest searchRequest = new SearchRequest(schemaDN, SearchScope.BASE,
         Filter.createPresenceFilter("objectClass"), "*", "+");
    searchRequest.addControl(new ExtendedSchemaInfoRequestControl());
    SearchResult searchResult = connection.search(searchRequest);

    Schema schema = null;
    if (searchResult.getEntryCount() == 1)
    {
      schema = new Schema(searchResult.getSearchEntries().get(0));
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code GetAuthorizationEntryRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testGetAuthorizationEntryRequestControlExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    ReadOnlyEntry authNEntry = null;
    ReadOnlyEntry authZEntry = null;

    BindRequest bindRequest = new SimpleBindRequest(
         "uid=john.doe,ou=People,dc=example,dc=com", "password",
         new GetAuthorizationEntryRequestControl());

    BindResult bindResult = connection.bind(bindRequest);
    GetAuthorizationEntryResponseControl c =
         GetAuthorizationEntryResponseControl.get(bindResult);
    if (c != null)
    {
      authNEntry = c.getAuthNEntry();
      authZEntry = c.getAuthZEntry();
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code GetEffectiveRightsRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testGetEffectiveRightsRequestControlExample()
         throws Exception
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, Filter.createEqualityFilter("uid", "john.doe"),
         "userPassword", "aclRights");
    searchRequest.addControl(new GetEffectiveRightsRequestControl(
         "dn:uid=admin,dc=example,dc=com"));
    SearchResult searchResult = connection.search(searchRequest);

    for (SearchResultEntry entry : searchResult.getSearchEntries())
    {
      EffectiveRightsEntry effectiveRightsEntry =
           new EffectiveRightsEntry(entry);
      if (effectiveRightsEntry.rightsInformationAvailable())
      {
        if (effectiveRightsEntry.hasAttributeRight(AttributeRight.WRITE,
             "userPassword"))
        {
          // The admin user has permission to change the target user's password.
        }
        else
        {
          // The admin user does not have permission to change the target user's
          // password.
        }
      }
      else
      {
        // No effective rights information was returned.
      }
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code IgnoreNoUserModificationRequestControl}
   * class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testIgnoreNoUserModificationRequestControlExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    AddRequest addRequest = new AddRequest("dc=example,dc=com",
         new Attribute("objectClass", "top", "domain"),
         new Attribute("dc", "example"),
         new Attribute("creatorsName", "cn=Admin User DN"),
         new Attribute("createTimestamp", "20080101000000Z"));
    addRequest.addControl(new IgnoreNoUserModificationRequestControl());

    try
    {
      LDAPResult result = connection.add(addRequest);
      // The entry was added successfully.
    }
    catch (LDAPException le)
    {
      // The attempt to add the entry failed.
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code IntermediateClientRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testIntermediateClientRequestControlExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, Filter.createEqualityFilter("uid", "john.doe"));
    searchRequest.addControl(new IntermediateClientRequestControl(null, null,
         null, null, "my client", "session123", "request456"));
    SearchResult searchResult = connection.search(searchRequest);

    IntermediateClientResponseControl c =
         IntermediateClientResponseControl.get(searchResult);
    if (c != null)
    {
      // There was an intermediate client response control.
      IntermediateClientResponseValue responseValue = c.getResponseValue();
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code JoinRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testJoinRequestControlExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;
    final String userID = "john.doe";


    /* ----- BEGIN EXAMPLE CODE ----- */
    SearchRequest searchRequest = new SearchRequest(
         "ou=People,dc=example,dc=com", SearchScope.SUB,
         Filter.createEqualityFilter("uid", userID));
    searchRequest.addControl(new JoinRequestControl(new JoinRequestValue(
         JoinRule.createEqualityJoin("accountNumber", "accountNumber", false),
         JoinBaseDN.createUseCustomBaseDN("ou=Accounts,dc=example,dc=com"),
         SearchScope.SUB, DereferencePolicy.NEVER, null,
         Filter.createEqualityFilter("objectClass", "accountEntry"),
         new String[0], false, null)));
    SearchResult searchResult = connection.search(searchRequest);

    for (SearchResultEntry userEntry : searchResult.getSearchEntries())
    {
      JoinResultControl c = JoinResultControl.get(userEntry);
      for (JoinedEntry accountEntry : c.getJoinResults())
      {
        // User userEntry was joined with account accountEntry
      }
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code NoOpRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testNoOpRequestControlExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    ModifyRequest modifyRequest = new ModifyRequest("dc=example,dc=com",
         new Modification(ModificationType.REPLACE, "description",
              "new value"));
    modifyRequest.addControl(new NoOpRequestControl());

    try
    {
      LDAPResult result = connection.modify(modifyRequest);
      if (result.getResultCode() == ResultCode.NO_OPERATION)
      {
        // The modify would likely have succeeded.
      }
      else
      {
        // The modify would likely have failed.
      }
    }
    catch (LDAPException le)
    {
      // The modify attempt failed even with the no-op control.
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code OperationPurposeRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testOperationPurposeRequestControlExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;
    final String uidValue = "john.doe";
    final String appName = "Test App";
    final String appVersion = "1.0";
    final String password = "password";


    /* ----- BEGIN EXAMPLE CODE ----- */
    SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, Filter.createEqualityFilter("uid", uidValue),
         "1.1");
    searchRequest.addControl(new OperationPurposeRequestControl(appName,
         appVersion, 0,  "Retrieve the entry for a user with a given uid"));
    Entry userEntry = connection.searchForEntry(searchRequest);

    SimpleBindRequest bindRequest = new SimpleBindRequest(userEntry.getDN(),
         password, new OperationPurposeRequestControl(appName, appVersion, 0,
         "Bind as a user to verify the provided credentials."));
    BindResult bindResult = connection.bind(bindRequest);
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code PasswordPolicyRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testPasswordPolicyRequestControlExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    SimpleBindRequest bindRequest = new SimpleBindRequest(
         "uid=john.doe,ou=People,dc=example,dc=com", "password",
         new PasswordPolicyRequestControl());

    BindResult bindResult;
    try
    {
      bindResult = connection.bind(bindRequest);
    }
    catch (LDAPException le)
    {
      // The bind failed.  There may be a password policy response control to
      // help tell us why.
      bindResult = new BindResult(le);
    }

    PasswordPolicyResponseControl pwpResponse =
         PasswordPolicyResponseControl.get(bindResult);
    if (pwpResponse != null)
    {
      PasswordPolicyErrorType errorType = pwpResponse.getErrorType();
      if (errorType != null)
      {
        // There was a password policy-related error.
      }

      PasswordPolicyWarningType warningType = pwpResponse.getWarningType();
      if (warningType != null)
      {
        // There was a password policy-related warning.
        int value = pwpResponse.getWarningValue();
        switch (warningType)
        {
          case TIME_BEFORE_EXPIRATION:
            // The warning value is the number of seconds until the user's
            // password expires.
            break;
          case GRACE_LOGINS_REMAINING:
            // The warning value is the number of grace logins remaining for
            // the user.
        }
      }
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code PurgePasswordRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testPurgePasswordRequestControlExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    Control[] requestControls =
    {
      new PurgePasswordRequestControl(true)
    };

    PasswordModifyExtendedRequest passwordModifyRequest =
         new PasswordModifyExtendedRequest(
              "uid=test.user,ou=People,dc=example,dc=com", // The user to update
              null, // The current password -- we don't know it.
              "newPassword", // The new password to assign to the user.
              requestControls); // The controls to include in the request.
    PasswordModifyExtendedResult passwordModifyResult =
         (PasswordModifyExtendedResult)
         connection.processExtendedOperation(passwordModifyRequest);
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code RealAttributesOnlyRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testRealAttributesOnlyRequestControlExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, Filter.createEqualityFilter("uid", "john.doe"));

    searchRequest.addControl(new RealAttributesOnlyRequestControl());
    SearchResult searchResult = connection.search(searchRequest);
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code ReplicationRepairRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testReplicationRepairRequestControlExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    ModifyRequest modifyRequest = new ModifyRequest("dc=example,dc=com",
         new Modification(ModificationType.REPLACE, "attrName", "attrValue"));
    modifyRequest.addControl(new ReplicationRepairRequestControl());
    LDAPResult modifyResult = connection.modify(modifyRequest);
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code RetainIdentityRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testRetainIdentityRequestControlExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    SimpleBindRequest bindRequest = new SimpleBindRequest(
         "uid=john.doe,ou=People,dc=example,dc=com", "password",
         new RetainIdentityRequestControl());

    BindResult bindResult;
    try
    {
      bindResult = connection.bind(bindRequest);
      // The bind was successful and the account is usable, but the identity
      // associated with the client connection hasn't changed.
    }
    catch (LDAPException le)
    {
      bindResult = new BindResult(le);
      // The bind was unsuccessful, potentially because the credentials were
      // invalid or the account is unusable for some reason (e.g., disabled,
      // locked, expired password, etc.).  The identity associated with the
      // client connection hasn't changed.
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code RetirePasswordRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testRetirePasswordRequestControlExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    Control[] requestControls =
    {
      new RetirePasswordRequestControl(true)
    };

    PasswordModifyExtendedRequest passwordModifyRequest =
         new PasswordModifyExtendedRequest(
              "uid=test.user,ou=People,dc=example,dc=com", // The user to update
              null, // The current password -- we don't know it.
              "newPassword", // The new password to assign to the user.
              requestControls); // The controls to include in the request.
    PasswordModifyExtendedResult passwordModifyResult =
         (PasswordModifyExtendedResult)
         connection.processExtendedOperation(passwordModifyRequest);
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code RouteToServerRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testRouteToServerRequestControlExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Perform a search to find an entry, and use the get server ID request
    // control to figure out which server actually processed the request.
    SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.BASE, Filter.createPresenceFilter("objectClass"),
         "description");
    searchRequest.addControl(new GetServerIDRequestControl());

    SearchResultEntry entry = connection.searchForEntry(searchRequest);
    GetServerIDResponseControl serverIDControl =
         GetServerIDResponseControl.get(entry);
    String serverID = serverIDControl.getServerID();

    // Send a modify request to update the target entry, and include the route
    // to server request control to request that the change be processed on the
    // same server that processed the request.
    ModifyRequest modifyRequest = new ModifyRequest("dc=example,dc=com",
         new Modification(ModificationType.REPLACE, "description",
              "new description value"));
    modifyRequest.addControl(new RouteToServerRequestControl(false, serverID,
         true, true, true));
    LDAPResult modifyResult = connection.modify(modifyRequest);
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code SoftDeleteRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testSoftDeleteRequestControlExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Perform a search to verify that the test entry exists.
    SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, Filter.createEqualityFilter("uid", "test"));
    SearchResult searchResult = connection.search(searchRequest);
    LDAPTestUtils.assertEntriesReturnedEquals(searchResult, 1);
    String originalDN = searchResult.getSearchEntries().get(0).getDN();

    // Perform a soft delete against the entry.
    DeleteRequest softDeleteRequest = new DeleteRequest(originalDN);
    softDeleteRequest.addControl(new SoftDeleteRequestControl());
    LDAPResult softDeleteResult = connection.delete(softDeleteRequest);

    // Verify that a soft delete response control was included in the result.
    SoftDeleteResponseControl softDeleteResponseControl =
         SoftDeleteResponseControl.get(softDeleteResult);
    String softDeletedDN = softDeleteResponseControl.getSoftDeletedEntryDN();

    // Verify that the original entry no longer exists.
    LDAPTestUtils.assertEntryMissing(connection, originalDN);

    // Verify that the original search no longer returns any entries.
    searchResult = connection.search(searchRequest);
    LDAPTestUtils.assertNoEntriesReturned(searchResult);

    // Verify that the search will return an entry if we include the
    // soft-deleted entry access control in the request.
    searchRequest.addControl(new SoftDeletedEntryAccessRequestControl());
    searchResult = connection.search(searchRequest);
    LDAPTestUtils.assertEntriesReturnedEquals(searchResult, 1);

    // Perform an undelete operation to restore the entry.
    AddRequest undeleteRequest = UndeleteRequestControl.createUndeleteRequest(
         originalDN, softDeletedDN);
    LDAPResult undeleteResult = connection.add(undeleteRequest);

    // Verify that the original entry is back.
    LDAPTestUtils.assertEntryExists(connection, originalDN);

    // Permanently remove the original entry with a hard delete.
    DeleteRequest hardDeleteRequest = new DeleteRequest(originalDN);
    hardDeleteRequest.addControl(new HardDeleteRequestControl());
    LDAPResult hardDeleteResult = connection.delete(hardDeleteRequest);
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code VirtualAttributesOnlyRequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testVirtualAttributesOnlyRequestControlExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, Filter.createEqualityFilter("uid", "john.doe"));

    searchRequest.addControl(new VirtualAttributesOnlyRequestControl());
    SearchResult searchResult = connection.search(searchRequest);
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }
}
