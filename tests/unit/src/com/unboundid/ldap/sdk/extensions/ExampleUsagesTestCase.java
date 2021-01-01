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
package com.unboundid.ldap.sdk.extensions;



import java.io.File;
import javax.net.ssl.SSLContext;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.AsyncRequestID;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.ldap.sdk.TestAsyncListener;
import com.unboundid.ldap.sdk.controls.TransactionSpecificationRequestControl;
import com.unboundid.util.LDAPTestUtils;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustStoreTrustManager;
import com.unboundid.util.ssl.TrustAllTrustManager;



/**
 * This class is primarily intended to ensure that code provided in javadoc
 * examples is valid.
 */
public final class ExampleUsagesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the example in the {@code CancelExtendedRequest} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCancelExtendedRequestExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection connection = ds.getConnection();
    final TestAsyncListener myAsyncResultListener = new TestAsyncListener();


    /* ----- BEGIN EXAMPLE CODE ----- */
    Modification mod = new Modification(ModificationType.REPLACE,
         "description", "This is the new description.");
    ModifyRequest modifyRequest =
         new ModifyRequest("dc=example,dc=com", mod);

    AsyncRequestID asyncRequestID =
         connection.asyncModify(modifyRequest, myAsyncResultListener);

    // Assume that we've waited a reasonable amount of time but the modify
    // hasn't completed yet so we'll try to cancel it.

    ExtendedResult cancelResult;
    try
    {
      cancelResult = connection.processExtendedOperation(
           new CancelExtendedRequest(asyncRequestID));
      // This doesn't necessarily mean that the operation was successful, since
      // some kinds of extended operations (like cancel) return non-success
      // results under normal conditions.
    }
    catch (LDAPException le)
    {
      // For an extended operation, this generally means that a problem was
      // encountered while trying to send the request or read the result.
      cancelResult = new ExtendedResult(le);
    }

    switch (cancelResult.getResultCode().intValue())
    {
      case ResultCode.CANCELED_INT_VALUE:
        // The modify operation was successfully canceled.
        break;
      case ResultCode.CANNOT_CANCEL_INT_VALUE:
        // This indicates that the server isn't capable of canceling that
        // type of operation.  This probably won't happen for  this kind of
        // modify operation, but it could happen for other kinds of operations.
        break;
      case ResultCode.TOO_LATE_INT_VALUE:
        // This indicates that the cancel request was received too late and the
        // server is intending to process the operation.
        break;
      case ResultCode.NO_SUCH_OPERATION_INT_VALUE:
        // This indicates that the server doesn't know anything about the
        // operation, most likely because it has already completed.
        break;
      default:
        // This suggests that the operation failed for some other reason.
        break;
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();

    // Since the in-memory directory server doesn't support the cancel
    // operation, we expect an "unwilling to perform" result.
    assertResultCodeEquals(cancelResult, ResultCode.UNWILLING_TO_PERFORM);
  }



  /**
   * Tests the example in the {@code PasswordModifyExtendedRequest} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordModifyExtendedRequestExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection connection = ds.getConnection();
    connection.bind("cn=Directory Manager", "password");


    /* ----- BEGIN EXAMPLE CODE ----- */
    PasswordModifyExtendedRequest passwordModifyRequest =
         new PasswordModifyExtendedRequest(
              "uid=test.user,ou=People,dc=example,dc=com", // The user to update
              (String) null, // The current password for the user.
              (String) null); // The new password.  null = server will generate

    PasswordModifyExtendedResult passwordModifyResult;
    try
    {
      passwordModifyResult = (PasswordModifyExtendedResult)
           connection.processExtendedOperation(passwordModifyRequest);
      // This doesn't necessarily mean that the operation was successful, since
      // some kinds of extended operations return non-success results under
      // normal conditions.
    }
    catch (LDAPException le)
    {
      // For an extended operation, this generally means that a problem was
      // encountered while trying to send the request or read the result.
      passwordModifyResult = new PasswordModifyExtendedResult(
           new ExtendedResult(le));
    }

    LDAPTestUtils.assertResultCodeEquals(passwordModifyResult,
         ResultCode.SUCCESS);
    String serverGeneratedNewPassword =
         passwordModifyResult.getGeneratedPassword();
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertNotNull(serverGeneratedNewPassword);
  }



  /**
   * Tests the example in the {@code StartTLSExtendedRequest} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStartTLSExtendedRequestExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "server.keystore");
    assertTrue(serverKeyStore.exists());

    // The client trust store will be the same as the server key store.
    final String trustStorePath = serverKeyStore.getAbsolutePath();

    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray(), "JKS",
              "server-cert"),
         new TrustAllTrustManager());

    InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.setListenerConfigs(
         InMemoryListenerConfig.createLDAPConfig("LDAP", // Listener name
              null, // Listen address. (null = listen on all interfaces)
              0, // Listen port (0 = automatically choose an available port)
              serverSSLUtil.createSSLSocketFactory())); // StartTLS factory

    InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
    ds.startListening();
    LDAPConnection connection = ds.getConnection();


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Create an SSLContext that will be used to perform the cryptographic
    // processing.
    SSLUtil sslUtil = new SSLUtil(new TrustStoreTrustManager(trustStorePath));
    SSLContext sslContext = sslUtil.createSSLContext();

     // Create and process the extended request to secure a connection.
    StartTLSExtendedRequest startTLSRequest =
         new StartTLSExtendedRequest(sslContext);
    ExtendedResult startTLSResult;
    try
    {
      startTLSResult = connection.processExtendedOperation(startTLSRequest);
      // This doesn't necessarily mean that the operation was successful, since
      // some kinds of extended operations return non-success results under
      // normal conditions.
    }
    catch (LDAPException le)
    {
      // For an extended operation, this generally means that a problem was
      // encountered while trying to send the request or read the result.
      startTLSResult = new ExtendedResult(le);
    }

    // Make sure that we can use the connection to interact with the server.
    RootDSE rootDSE = connection.getRootDSE();
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    ds.shutDown(true);

    assertResultCodeEquals(startTLSResult, ResultCode.SUCCESS);
    assertNotNull(rootDSE);
  }



  /**
   * Tests the example in the {@code StartTransactionExtendedRequest} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStartTransactionExtendedRequestExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final LDAPConnection connection = ds.getConnection();
    connection.add(
         "dn: cn=first,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "cn: first",
         "sn: first");
    connection.add(
         "dn: cn=second,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "cn: second",
         "sn: second");


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Use the start transaction extended operation to begin a transaction.
    StartTransactionExtendedResult startTxnResult;
    try
    {
      startTxnResult = (StartTransactionExtendedResult)
           connection.processExtendedOperation(
                new StartTransactionExtendedRequest());
      // This doesn't necessarily mean that the operation was successful, since
      // some kinds of extended operations return non-success results under
      // normal conditions.
    }
    catch (LDAPException le)
    {
      // For an extended operation, this generally means that a problem was
      // encountered while trying to send the request or read the result.
      startTxnResult = new StartTransactionExtendedResult(
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
           new TransactionSpecificationRequestControl(txnID));
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
           new TransactionSpecificationRequestControl(txnID));
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
      EndTransactionExtendedResult endTxnResult;
      try
      {
        endTxnResult = (EndTransactionExtendedResult)
             connection.processExtendedOperation(
                  new EndTransactionExtendedRequest(txnID, commit));
      }
      catch (LDAPException le)
      {
        endTxnResult = new EndTransactionExtendedResult(new ExtendedResult(le));
      }
      LDAPTestUtils.assertResultCodeEquals(endTxnResult, ResultCode.SUCCESS);
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertTrue(commit);
  }



  /**
   * Tests the example in the {@code WhoAmIExtendedRequest} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWhoAmIExtendedRequestExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final LDAPConnection connection = ds.getConnection();
    connection.bind("cn=Directory Manager", "password");


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Use the "Who Am I?" extended request to determine the identity of the
    // currently-authenticated user.
    WhoAmIExtendedResult whoAmIResult;
    try
    {
      whoAmIResult = (WhoAmIExtendedResult)
           connection.processExtendedOperation(new WhoAmIExtendedRequest());
      // This doesn't necessarily mean that the operation was successful, since
      // some kinds of extended operations return non-success results under
      // normal conditions.
    }
    catch (LDAPException le)
    {
      // For an extended operation, this generally means that a problem was
      // encountered while trying to send the request or read the result.
      whoAmIResult = new WhoAmIExtendedResult(new ExtendedResult(le));
    }

    LDAPTestUtils.assertResultCodeEquals(whoAmIResult, ResultCode.SUCCESS);
    String authzID = whoAmIResult.getAuthorizationID();
    if (authzID.equals("") || authzID.equals("dn:"))
    {
      // The user is authenticated anonymously.
    }
    else if (authzID.startsWith("dn:"))
    {
      // The DN of the authenticated user should be authzID.substring(3)
    }
    else if (authzID.startsWith("u:"))
    {
      // The username of the authenticated user should be authzID.substring(2)
    }
    else
    {
      // The authorization ID isn't in any recognizable format.  Perhaps it's
      // a raw DN or a username?
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertEquals(authzID, "dn:cn=Directory Manager");
  }
}
