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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.io.InputStream;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.unboundidds.controls.
            BatchedTransactionSpecificationRequestControl;
import com.unboundid.ldap.sdk.unboundidds.monitors.MonitorEntry;
import com.unboundid.ldap.sdk.unboundidds.monitors.MonitorManager;
import com.unboundid.util.LDAPTestUtils;



/**
 * This class is primarily intended to ensure that code provided in javadoc
 * examples is valid.
 */
public final class ExampleUsagesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the example in the {@code GetChangelogBatchExtendedRequest} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testGetChangelogBatchExtendedRequestExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    ChangelogBatchStartingPoint startingPoint =
         new BeginningOfChangelogStartingPoint();
    while (true)
    {
      GetChangelogBatchExtendedRequest request =
           new GetChangelogBatchExtendedRequest(startingPoint, 1000, 5000L);

      GetChangelogBatchExtendedResult result =
           (GetChangelogBatchExtendedResult)
           connection.processExtendedOperation(request);
      List<ChangelogEntryIntermediateResponse> changelogEntries =
           result.getChangelogEntries();

      startingPoint = new ResumeWithTokenStartingPoint(result.getResumeToken());
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code GetConnectionIDExtendedRequest} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testGetConnectionIDExtendedRequestExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    GetConnectionIDExtendedResult result =
         (GetConnectionIDExtendedResult) connection.processExtendedOperation(
              new GetConnectionIDExtendedRequest());

    // NOTE:  The processExtendedOperation method will generally only throw an
    // exception if a problem occurs while trying to send the request or read
    // the response.  It will not throw an exception because of a non-success
    // response.

    if (result.getResultCode() == ResultCode.SUCCESS)
    {
      long connectionID = result.getConnectionID();
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code ListConfigurationsExtendedRequest} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testListConfigurationsExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Get a list of the available configurations from the server.
    ListConfigurationsExtendedResult listConfigsResult =
         (ListConfigurationsExtendedResult)
         connection.processExtendedOperation(
              new ListConfigurationsExtendedRequest());
    String archivedConfigFileName =
         listConfigsResult.getArchivedFileNames().get(0);

    // Retrieve the first archived configuration from the list configurations
    // result.
    GetConfigurationExtendedResult getConfigResult =
         (GetConfigurationExtendedResult)
         connection.processExtendedOperation(GetConfigurationExtendedRequest.
              createGetArchivedConfigurationRequest(archivedConfigFileName));

    InputStream fileDataStream = getConfigResult.getFileDataInputStream();
    // Read data from the file.
    fileDataStream.close();
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code MultiUpdateExtendedRequest} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testMultiUpdateExtendedRequestExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    MultiUpdateExtendedRequest multiUpdateRequest =
         new MultiUpdateExtendedRequest(
              MultiUpdateErrorBehavior.ABORT_ON_ERROR,
              new AddRequest(
                   "dn: uid=new.user,ou=People,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: person",
                   "objectClass: organizationalPerson",
                   "objectClass: inetOrgPerson",
                   "uid: new.user",
                   "givenName: New",
                   "sn: User",
                   "cn: New User"),
              new ModifyRequest(
                   "dn: cn=Test Group,ou=Groups,dc=example,dc=com",
                   "changetype: modify",
                   "add: member",
                   "member: uid=new.user,ou=People,dc=example,dc=com"));

    MultiUpdateExtendedResult multiUpdateResult =
         (MultiUpdateExtendedResult)
         connection.processExtendedOperation(multiUpdateRequest);
    if (multiUpdateResult.getResultCode() == ResultCode.SUCCESS)
    {
      // The server successfully processed the multi-update request, although
      // this does not necessarily mean that any or all of the changes
      // contained in it were successful.  For that, we should look at the
      // changes applied and/or results element of the response.
      switch (multiUpdateResult.getChangesApplied())
      {
        case NONE:
          // There were no changes applied.  Based on the configuration of the
          // request, this means that the attempt to create the user failed
          // and there was no subsequent attempt to add that user to a group.
          break;
        case ALL:
          // Both parts of the update succeeded.  The user was created and
          // successfully added to a group.
          break;
        case PARTIAL:
          // At least one update succeeded, and at least one failed.  Based on
          // the configuration of the request, this means that the user was
          // successfully created but not added to the target group.
          break;
      }
    }
    else
    {
      // The server encountered a failure while attempting to parse or process
      // the multi-update operation itself and did not attempt to process any
      // of the changes contained in the request.
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code PasswordPolicyStateExtendedRequest} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testPasswordPolicyStateExtendedRequestExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    PasswordPolicyStateOperation disableOp =
         PasswordPolicyStateOperation.createSetAccountDisabledStateOperation(
              true);
    PasswordPolicyStateExtendedRequest pwpStateRequest =
         new PasswordPolicyStateExtendedRequest(
                  "uid=john.doe,ou=People,dc=example,dc=com", disableOp);
    PasswordPolicyStateExtendedResult pwpStateResult =
         (PasswordPolicyStateExtendedResult)
         connection.processExtendedOperation(pwpStateRequest);

    // NOTE:  The processExtendedOperation method will generally only throw an
    // exception if a problem occurs while trying to send the request or read
    // the response.  It will not throw an exception because of a non-success
    // response.

    if (pwpStateResult.getResultCode() == ResultCode.SUCCESS)
    {
      boolean isDisabled = pwpStateResult.getBooleanValue(
           PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_DISABLED_STATE);
      if (isDisabled)
      {
        // The user account has been disabled.
      }
      else
      {
        // The user account is not disabled.
      }
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code StartAdministrativeSessionExtendedRequest}
   * class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testStartAdministrativeSessionExtendedRequestExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS();
    final String host = "localhost";
    final int port = ds.getListenPort();
    final String userDN = "cn=Directory Manager";
    final String password = "password";


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Establish a connection to the server.
    LDAPConnection connection = new LDAPConnection(host, port);

    // Use the start administrative session operation to begin an administrative
    // session and request that operations in the session use the dedicated
    // thread pool.
    ExtendedResult extendedResult = connection.processExtendedOperation(
         new StartAdministrativeSessionExtendedRequest("Test Client", true));

    // Authenticate the connection.  It is strongly recommended that the
    // administrative session be created before the connection is authenticated.
    // Attempting to authenticate the connection before creating the
    // administrative session may result in the bind using a "regular" worker
    // thread rather than an administrative session worker thread, and if all
    // normal worker threads are busy or stuck, then the bind request may be
    // blocked.
    BindResult bindResult = connection.bind(userDN, password);

    // Use the connection to perform operations that may benefit from using an
    // administrative session (e.g., operations that troubleshoot and attempt to
    // correct some problem with the server).  In this example, we'll just
    // request all monitor entries from the server.
    List<MonitorEntry> monitorEntries =
         MonitorManager.getMonitorEntries(connection);

    // Use the end administrative session operation to end the administrative
    // session and resume using normal worker threads for subsequent operations.
    // This isn't strictly needed if we just want to close the connection.
    extendedResult = connection.processExtendedOperation(
         new EndAdministrativeSessionExtendedRequest());

    // Do other operations that don't need an administrative session.

    connection.close();
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code StartBatchedTransactionExtendedRequest}
   * class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testStartBatchedTransactionExtendedRequestExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Use the start transaction extended operation to begin a transaction.
    StartBatchedTransactionExtendedResult startTxnResult;
    try
    {
      startTxnResult = (StartBatchedTransactionExtendedResult)
           connection.processExtendedOperation(
                new StartBatchedTransactionExtendedRequest());
      // This doesn't necessarily mean that the operation was successful, since
      // some kinds of extended operations return non-success results under
      // normal conditions.
    }
    catch (LDAPException le)
    {
      // For an extended operation, this generally means that a problem was
      // encountered while trying to send the request or read the result.
      startTxnResult = new StartBatchedTransactionExtendedResult(
           new ExtendedResult(le));
    }
    LDAPTestUtils.assertResultCodeEquals(startTxnResult, ResultCode.SUCCESS);
    ASN1OctetString txnID = startTxnResult.getTransactionID();


    // At this point, we have a transaction available for use.  If any problem
    // arises, we want to ensure that the transaction is aborted, so create a
    // try block to process the operations and a finally block to commit or
    // abort the transaction.
    boolean commit = false;
    try
    {
      // Create and process a modify operation to update a first entry as part
      // of the transaction.  Make sure to include the transaction specification
      // control in the request to indicate that it should be part of the
      // transaction.
      ModifyRequest firstModifyRequest = new ModifyRequest(
           "cn=first,dc=example,dc=com",
           new Modification(ModificationType.REPLACE, "description", "first"));
      firstModifyRequest.addControl(
           new BatchedTransactionSpecificationRequestControl(txnID));
      LDAPResult firstModifyResult;
      try
      {
        firstModifyResult = connection.modify(firstModifyRequest);
      }
      catch (LDAPException le)
      {
        firstModifyResult = le.toLDAPResult();
      }
      LDAPTestUtils.assertResultCodeEquals(firstModifyResult,
           ResultCode.SUCCESS);

      // Perform a second modify operation as part of the transaction.
      ModifyRequest secondModifyRequest = new ModifyRequest(
           "cn=second,dc=example,dc=com",
           new Modification(ModificationType.REPLACE, "description", "second"));
      secondModifyRequest.addControl(
           new BatchedTransactionSpecificationRequestControl(txnID));
      LDAPResult secondModifyResult;
      try
      {
        secondModifyResult = connection.modify(secondModifyRequest);
      }
      catch (LDAPException le)
      {
        secondModifyResult = le.toLDAPResult();
      }
      LDAPTestUtils.assertResultCodeEquals(secondModifyResult,
           ResultCode.SUCCESS);

      // If we've gotten here, then all writes have been processed successfully
      // and we can indicate that the transaction should be committed rather
      // than aborted.
      commit = true;
    }
    finally
    {
      // Commit or abort the transaction.
      EndBatchedTransactionExtendedResult endTxnResult;
      try
      {
        endTxnResult = (EndBatchedTransactionExtendedResult)
             connection.processExtendedOperation(
                  new EndBatchedTransactionExtendedRequest(txnID, commit));
      }
      catch (LDAPException le)
      {
        endTxnResult = new EndBatchedTransactionExtendedResult(
             new ExtendedResult(le));
      }
      LDAPTestUtils.assertResultCodeEquals(endTxnResult, ResultCode.SUCCESS);
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code StartInteractiveTransactionExtendedRequest}
   * class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  @SuppressWarnings("deprecation")
  public void testStartInteractiveTransactionExtendedRequestExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Start the interactive transaction and get the transaction ID.
    StartInteractiveTransactionExtendedRequest startTxnRequest =
         new StartInteractiveTransactionExtendedRequest("dc=example,dc=com");
    StartInteractiveTransactionExtendedResult startTxnResult =
         (StartInteractiveTransactionExtendedResult)
         connection.processExtendedOperation(startTxnRequest);
    if (startTxnResult.getResultCode() != ResultCode.SUCCESS)
    {
      throw new LDAPException(startTxnResult);
    }
    ASN1OctetString txnID = startTxnResult.getTransactionID();

    // At this point, we have a valid transaction.  We want to ensure that the
    // transaction is aborted if any failure occurs, so do that in a
    // try-finally block.
    boolean txnFailed = true;
    try
    {
      // Perform a search to find all users in the "Sales" department.
      SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
           SearchScope.SUB, Filter.createEqualityFilter("ou", "Sales"));
      searchRequest.addControl(new com.unboundid.ldap.sdk.unboundidds.controls.
           InteractiveTransactionSpecificationRequestControl(txnID, true,
                true));

      SearchResult searchResult = connection.search(searchRequest);
      if (searchResult.getResultCode() != ResultCode.SUCCESS)
      {
        throw new LDAPException(searchResult);
      }

      // Iterate through all of the users and assign a new fax number to each
      // of them.
      for (SearchResultEntry e : searchResult.getSearchEntries())
      {
        ModifyRequest modifyRequest = new ModifyRequest(e.getDN(),
             new Modification(ModificationType.REPLACE,
                  "facsimileTelephoneNumber", "+1 123 456 7890"));
        modifyRequest.addControl(new com.unboundid.ldap.sdk.unboundidds.
             controls.InteractiveTransactionSpecificationRequestControl(txnID,
                  true, true));
        connection.modify(modifyRequest);
      }

      // Commit the transaction.
      ExtendedResult endTxnResult = connection.processExtendedOperation(
           new EndInteractiveTransactionExtendedRequest(txnID, true));
      if (endTxnResult.getResultCode() == ResultCode.SUCCESS)
      {
        txnFailed = false;
      }
    }
    finally
    {
      if (txnFailed)
      {
        connection.processExtendedOperation(
             new EndInteractiveTransactionExtendedRequest(txnID, false));
      }
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }
}
