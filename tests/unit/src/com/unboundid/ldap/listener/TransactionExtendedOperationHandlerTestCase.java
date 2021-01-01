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



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.TestUnsolicitedNotificationHandler;
import com.unboundid.ldap.sdk.controls.PostReadRequestControl;
import com.unboundid.ldap.sdk.controls.PostReadResponseControl;
import com.unboundid.ldap.sdk.controls.PreReadRequestControl;
import com.unboundid.ldap.sdk.controls.PreReadResponseControl;
import com.unboundid.ldap.sdk.controls.TransactionSpecificationRequestControl;
import com.unboundid.ldap.sdk.extensions.EndTransactionExtendedRequest;
import com.unboundid.ldap.sdk.extensions.EndTransactionExtendedResult;
import com.unboundid.ldap.sdk.extensions.StartTransactionExtendedRequest;
import com.unboundid.ldap.sdk.extensions.StartTransactionExtendedResult;



/**
 * This class provides a set of test cases for the in-memory directory server's
 * support for standard LDAP transactions as defined in RFC 5805.
 */
public final class TransactionExtendedOperationHandlerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides a test case for a completely successful transaction.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessfulTransaction()
         throws Exception
  {
    final TestUnsolicitedNotificationHandler unsolicitedNotificationHandler =
         new TestUnsolicitedNotificationHandler();
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setUnsolicitedNotificationHandler(
         unsolicitedNotificationHandler);

    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection(connectionOptions);
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final StartTransactionExtendedResult startTxnResult =
         (StartTransactionExtendedResult)
         conn.processExtendedOperation(new StartTransactionExtendedRequest());
    assertResultCodeEquals(startTxnResult, ResultCode.SUCCESS);

    final ASN1OctetString txnID = startTxnResult.getTransactionID();
    assertNotNull(txnID);
    final TransactionSpecificationRequestControl txnControl =
         new TransactionSpecificationRequestControl(txnID);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final AddRequest addRequest = new AddRequest(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test");
    addRequest.setControls(txnControl);
    assertResultCodeEquals(conn, addRequest, ResultCode.SUCCESS);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final ModifyRequest modifyRequest = new ModifyRequest(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo");
    modifyRequest.setControls(txnControl);
    assertResultCodeEquals(conn, modifyRequest, ResultCode.SUCCESS);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("uid=test.user,ou=People,dc=example,dc=com",
              "uid=test.user", false, "ou=test,dc=example,dc=com");
    modifyDNRequest.setControls(txnControl);
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.SUCCESS);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final DeleteRequest deleteRequest =
         new DeleteRequest("ou=People,dc=example,dc=com");
    deleteRequest.setControls(txnControl);
    assertResultCodeEquals(conn, deleteRequest, ResultCode.SUCCESS);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final EndTransactionExtendedResult endTxnResult =
         (EndTransactionExtendedResult) conn.processExtendedOperation(
              new EndTransactionExtendedRequest(txnID, true));
    assertResultCodeEquals(endTxnResult, ResultCode.SUCCESS);
    assertTrue(endTxnResult.getFailedOpMessageID() < 0);
    assertNotNull(endTxnResult.getOperationResponseControls());
    assertTrue(endTxnResult.getOperationResponseControls().isEmpty());


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=test,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=test,dc=example,dc=com");
    ds.assertEntryMissing("ou=People,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=People,dc=example,dc=com");


    conn.close();
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);
  }



  /**
   * Provides a test case for a transaction that is aborted rather than
   * committed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAbortedTransaction()
         throws Exception
  {
    final TestUnsolicitedNotificationHandler unsolicitedNotificationHandler =
         new TestUnsolicitedNotificationHandler();
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setUnsolicitedNotificationHandler(
         unsolicitedNotificationHandler);

    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection(connectionOptions);
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final StartTransactionExtendedResult startTxnResult =
         (StartTransactionExtendedResult)
         conn.processExtendedOperation(new StartTransactionExtendedRequest());
    assertResultCodeEquals(startTxnResult, ResultCode.SUCCESS);

    final ASN1OctetString txnID = startTxnResult.getTransactionID();
    assertNotNull(txnID);
    final TransactionSpecificationRequestControl txnControl =
         new TransactionSpecificationRequestControl(txnID);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final AddRequest addRequest = new AddRequest(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test");
    addRequest.setControls(txnControl);
    assertResultCodeEquals(conn, addRequest, ResultCode.SUCCESS);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final ModifyRequest modifyRequest = new ModifyRequest(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo");
    modifyRequest.setControls(txnControl);
    assertResultCodeEquals(conn, modifyRequest, ResultCode.SUCCESS);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("uid=test.user,ou=People,dc=example,dc=com",
              "uid=test.user", false, "ou=test,dc=example,dc=com");
    modifyDNRequest.setControls(txnControl);
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.SUCCESS);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final DeleteRequest deleteRequest =
         new DeleteRequest("ou=People,dc=example,dc=com");
    deleteRequest.setControls(txnControl);
    assertResultCodeEquals(conn, deleteRequest, ResultCode.SUCCESS);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final EndTransactionExtendedResult endTxnResult =
         (EndTransactionExtendedResult) conn.processExtendedOperation(
              new EndTransactionExtendedRequest(txnID, false));
    assertResultCodeEquals(endTxnResult, ResultCode.SUCCESS);
    assertTrue(endTxnResult.getFailedOpMessageID() < 0);
    assertNotNull(endTxnResult.getOperationResponseControls());
    assertTrue(endTxnResult.getOperationResponseControls().isEmpty());


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    conn.close();
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);
  }



  /**
   * Provides a test case for a transaction in which one of the operations
   * fails after other operations that should have succeeded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailedTransaction()
         throws Exception
  {
    final TestUnsolicitedNotificationHandler unsolicitedNotificationHandler =
         new TestUnsolicitedNotificationHandler();
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setUnsolicitedNotificationHandler(
         unsolicitedNotificationHandler);

    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection(connectionOptions);
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final StartTransactionExtendedResult startTxnResult =
         (StartTransactionExtendedResult)
         conn.processExtendedOperation(new StartTransactionExtendedRequest());
    assertResultCodeEquals(startTxnResult, ResultCode.SUCCESS);

    final ASN1OctetString txnID = startTxnResult.getTransactionID();
    assertNotNull(txnID);
    final TransactionSpecificationRequestControl txnControl =
         new TransactionSpecificationRequestControl(txnID);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final AddRequest addRequest = new AddRequest(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test");
    addRequest.setControls(txnControl);
    assertResultCodeEquals(conn, addRequest, ResultCode.SUCCESS);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final ModifyRequest modifyRequest = new ModifyRequest(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo");
    modifyRequest.setControls(txnControl);
    assertResultCodeEquals(conn, modifyRequest, ResultCode.SUCCESS);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("uid=test.user,ou=People,dc=example,dc=com",
              "uid=test.user", false, "ou=test,dc=example,dc=com");
    modifyDNRequest.setControls(txnControl);
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.SUCCESS);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final DeleteRequest deleteRequest =
         new DeleteRequest("ou=missing,dc=example,dc=com");
    deleteRequest.setControls(txnControl);
    assertResultCodeEquals(conn, deleteRequest, ResultCode.SUCCESS);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final EndTransactionExtendedResult endTxnResult =
         (EndTransactionExtendedResult) conn.processExtendedOperation(
              new EndTransactionExtendedRequest(txnID, true));
    assertResultCodeEquals(endTxnResult, ResultCode.NO_SUCH_OBJECT);
    assertTrue(endTxnResult.getFailedOpMessageID() > 0);
    assertEquals(endTxnResult.getFailedOpMessageID(),
         deleteRequest.getLastMessageID());
    assertNotNull(endTxnResult.getOperationResponseControls());
    assertTrue(endTxnResult.getOperationResponseControls().isEmpty());


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    conn.close();
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);
  }



  /**
   * Provides a test case for a completely successful transaction that includes
   * request and response controls for the associated operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransactionWithControls()
         throws Exception
  {
    final TestUnsolicitedNotificationHandler unsolicitedNotificationHandler =
         new TestUnsolicitedNotificationHandler();
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setUnsolicitedNotificationHandler(
         unsolicitedNotificationHandler);

    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection(connectionOptions);
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final StartTransactionExtendedResult startTxnResult =
         (StartTransactionExtendedResult)
         conn.processExtendedOperation(new StartTransactionExtendedRequest());
    assertResultCodeEquals(startTxnResult, ResultCode.SUCCESS);

    final ASN1OctetString txnID = startTxnResult.getTransactionID();
    assertNotNull(txnID);
    final TransactionSpecificationRequestControl txnControl =
         new TransactionSpecificationRequestControl(txnID);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final AddRequest addRequest = new AddRequest(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test");
    final PostReadRequestControl postReadRequestControl =
         new PostReadRequestControl("*", "+");
    addRequest.setControls(txnControl, postReadRequestControl);
    assertResultCodeEquals(conn, addRequest, ResultCode.SUCCESS);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final ModifyRequest modifyRequest = new ModifyRequest(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo");
    final PreReadRequestControl preReadRequestControl =
         new PreReadRequestControl("*", "+");
    modifyRequest.setControls(txnControl, preReadRequestControl,
         postReadRequestControl);
    assertResultCodeEquals(conn, modifyRequest, ResultCode.SUCCESS);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("uid=test.user,ou=People,dc=example,dc=com",
              "uid=test.user", false, "ou=test,dc=example,dc=com");
    modifyDNRequest.setControls(txnControl, preReadRequestControl,
         postReadRequestControl);
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.SUCCESS);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final DeleteRequest deleteRequest =
         new DeleteRequest("ou=People,dc=example,dc=com");
    deleteRequest.setControls(txnControl, preReadRequestControl);
    assertResultCodeEquals(conn, deleteRequest, ResultCode.SUCCESS);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final EndTransactionExtendedResult endTxnResult =
         (EndTransactionExtendedResult) conn.processExtendedOperation(
              new EndTransactionExtendedRequest(txnID, true));
    assertResultCodeEquals(endTxnResult, ResultCode.SUCCESS);
    assertTrue(endTxnResult.getFailedOpMessageID() < 0);
    assertNotNull(endTxnResult.getOperationResponseControls());
    assertFalse(endTxnResult.getOperationResponseControls().isEmpty());


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=test,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=test,dc=example,dc=com");
    ds.assertEntryMissing("ou=People,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=People,dc=example,dc=com");


    final Control[] addControls = endTxnResult.getOperationResponseControls(
         addRequest.getLastMessageID());
    assertNotNull(addControls);
    assertEquals(addControls.length, 1);
    assertTrue(addControls[0] instanceof PostReadResponseControl);

    final Control[] modifyControls = endTxnResult.getOperationResponseControls(
         modifyRequest.getLastMessageID());
    assertNotNull(modifyControls);
    assertEquals(modifyControls.length, 2);
    assertTrue(modifyControls[0] instanceof PreReadResponseControl);
    assertTrue(modifyControls[1] instanceof PostReadResponseControl);

    final Control[] modifyDNControls =
         endTxnResult.getOperationResponseControls(
              modifyDNRequest.getLastMessageID());
    assertNotNull(modifyDNControls);
    assertEquals(modifyDNControls.length, 2);
    assertTrue(modifyDNControls[0] instanceof PreReadResponseControl);
    assertTrue(modifyDNControls[1] instanceof PostReadResponseControl);

    final Control[] deleteControls = endTxnResult.getOperationResponseControls(
         deleteRequest.getLastMessageID());
    assertNotNull(deleteControls);
    assertEquals(deleteControls.length, 1);
    assertTrue(deleteControls[0] instanceof PreReadResponseControl);


    conn.close();
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);
  }



  /**
   * Tests the behavior when trying to use the transaction specification request
   * control when no transaction has been started.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransactionControlWithoutTransaction()
         throws Exception
  {
    final TestUnsolicitedNotificationHandler unsolicitedNotificationHandler =
         new TestUnsolicitedNotificationHandler();
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setUnsolicitedNotificationHandler(
         unsolicitedNotificationHandler);

    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection(connectionOptions);
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);


    final TransactionSpecificationRequestControl txnControl =
         new TransactionSpecificationRequestControl(
              new ASN1OctetString("nonexistent"));


    final AddRequest addRequest = new AddRequest(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test");
    addRequest.setControls(txnControl);
    assertResultCodeEquals(conn, addRequest,
         ResultCode.UNAVAILABLE_CRITICAL_EXTENSION);


    final DeleteRequest deleteRequest = new DeleteRequest("dc=example,dc=com");
    deleteRequest.setControls(txnControl);
    assertResultCodeEquals(conn, deleteRequest,
         ResultCode.UNAVAILABLE_CRITICAL_EXTENSION);


    final ModifyRequest modifyRequest = new ModifyRequest(
         "dn: dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo");
    modifyRequest.setControls(txnControl);
    assertResultCodeEquals(conn, modifyRequest,
         ResultCode.UNAVAILABLE_CRITICAL_EXTENSION);


    final ModifyDNRequest modifyDNRequest = new ModifyDNRequest(
         "ou=People,dc=example,dc=com", "ou=Users", true);
    modifyDNRequest.setControls(txnControl);
    assertResultCodeEquals(conn, modifyDNRequest,
         ResultCode.UNAVAILABLE_CRITICAL_EXTENSION);


    conn.close();
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);
  }



  /**
   * Tests the behavior when trying to use the transaction specification request
   * control with a transaction ID that differs from the ID of the associated
   * transaction.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransactionControlWithMismatchedTransactionID()
         throws Exception
  {
    final TestUnsolicitedNotificationHandler unsolicitedNotificationHandler =
         new TestUnsolicitedNotificationHandler();
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setUnsolicitedNotificationHandler(
         unsolicitedNotificationHandler);

    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection(connectionOptions);
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);


    final StartTransactionExtendedResult startTxnResult =
         (StartTransactionExtendedResult)
         conn.processExtendedOperation(new StartTransactionExtendedRequest());
    assertResultCodeEquals(startTxnResult, ResultCode.SUCCESS);

    final ASN1OctetString txnID = startTxnResult.getTransactionID();
    assertNotNull(txnID);

    final ASN1OctetString wrongTxnID = new ASN1OctetString(
         txnID.stringValue() + "-wrong");
    final TransactionSpecificationRequestControl wrongTxnControl =
         new TransactionSpecificationRequestControl(wrongTxnID);


    final AddRequest addRequest = new AddRequest(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test");
    addRequest.setControls(wrongTxnControl);
    assertResultCodeEquals(conn, addRequest,
         ResultCode.UNAVAILABLE_CRITICAL_EXTENSION);


    conn.close();
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 1);
  }



  /**
   * Tests the behavior when trying to use the end transaction extended request
   * with a transaction ID that differs from the ID of the associated
   * transaction.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEndTransactionWithMismatchedTransactionID()
         throws Exception
  {
    final TestUnsolicitedNotificationHandler unsolicitedNotificationHandler =
         new TestUnsolicitedNotificationHandler();
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setUnsolicitedNotificationHandler(
         unsolicitedNotificationHandler);

    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection(connectionOptions);
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);


    final StartTransactionExtendedResult startTxnResult =
         (StartTransactionExtendedResult)
         conn.processExtendedOperation(new StartTransactionExtendedRequest());
    assertResultCodeEquals(startTxnResult, ResultCode.SUCCESS);

    final ASN1OctetString txnID = startTxnResult.getTransactionID();
    assertNotNull(txnID);

    final ASN1OctetString wrongTxnID = new ASN1OctetString(
         txnID.stringValue() + "-wrong");
    final EndTransactionExtendedResult endTxnResult =
         (EndTransactionExtendedResult)
         conn.processExtendedOperation(new EndTransactionExtendedRequest(
              wrongTxnID, true));
    assertResultCodeEquals(endTxnResult, ResultCode.CONSTRAINT_VIOLATION);


    conn.close();
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 1);
  }



  /**
   * Tests the behavior when trying to start a transaction when another
   * transaction is already in progress on the connection.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStartTransactionWithAnotherActive()
         throws Exception
  {
    final TestUnsolicitedNotificationHandler unsolicitedNotificationHandler =
         new TestUnsolicitedNotificationHandler();
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setUnsolicitedNotificationHandler(
         unsolicitedNotificationHandler);

    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection(connectionOptions);
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);


    final StartTransactionExtendedResult startTxn1Result =
         (StartTransactionExtendedResult)
         conn.processExtendedOperation(new StartTransactionExtendedRequest());
    assertResultCodeEquals(startTxn1Result, ResultCode.SUCCESS);

    final ASN1OctetString txnID1 = startTxn1Result.getTransactionID();
    assertNotNull(txnID1);


    final StartTransactionExtendedResult startTxn2Result =
         (StartTransactionExtendedResult)
         conn.processExtendedOperation(new StartTransactionExtendedRequest());
    assertResultCodeEquals(startTxn2Result, ResultCode.SUCCESS);

    final ASN1OctetString txnID2 = startTxn2Result.getTransactionID();
    assertNotNull(txnID2);
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 1);


    final EndTransactionExtendedResult endTxn2Result =
         (EndTransactionExtendedResult)
         conn.processExtendedOperation(new EndTransactionExtendedRequest(
              txnID2, true));
    assertResultCodeEquals(endTxn2Result, ResultCode.SUCCESS);

    final EndTransactionExtendedResult endTxn1Result =
         (EndTransactionExtendedResult)
         conn.processExtendedOperation(new EndTransactionExtendedRequest(
              txnID1, true));
    assertResultCodeEquals(endTxn1Result, ResultCode.CONSTRAINT_VIOLATION);


    conn.close();
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 1);
  }



  /**
   * Tests the behavior when including controls with the start transaction
   * extended request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStartTransactionWithControls()
         throws Exception
  {
    final TestUnsolicitedNotificationHandler unsolicitedNotificationHandler =
         new TestUnsolicitedNotificationHandler();
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setUnsolicitedNotificationHandler(
         unsolicitedNotificationHandler);

    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection(connectionOptions);
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);


    final Control[] controls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", true)
    };
    final StartTransactionExtendedResult startTxnResult =
         (StartTransactionExtendedResult)
         conn.processExtendedOperation(new StartTransactionExtendedRequest(
              controls));
    assertResultCodeEquals(startTxnResult,
         ResultCode.UNAVAILABLE_CRITICAL_EXTENSION);


    conn.close();
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);
  }



  /**
   * Tests the behavior when including controls with the end transaction
   * extended request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEndTransactionWithControls()
         throws Exception
  {
    final TestUnsolicitedNotificationHandler unsolicitedNotificationHandler =
         new TestUnsolicitedNotificationHandler();
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setUnsolicitedNotificationHandler(
         unsolicitedNotificationHandler);

    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection(connectionOptions);
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);


    final StartTransactionExtendedResult startTxnResult =
         (StartTransactionExtendedResult)
         conn.processExtendedOperation(new StartTransactionExtendedRequest());
    assertResultCodeEquals(startTxnResult, ResultCode.SUCCESS);

    final ASN1OctetString txnID = startTxnResult.getTransactionID();
    assertNotNull(txnID);


    final Control[] controls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", true)
    };
    final EndTransactionExtendedResult endTxnResult =
         (EndTransactionExtendedResult) conn.processExtendedOperation(
              new EndTransactionExtendedRequest(txnID, true, controls));
    assertResultCodeEquals(endTxnResult,
         ResultCode.UNAVAILABLE_CRITICAL_EXTENSION);


    conn.close();
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 1);
  }



  /**
   * Tests the behavior when provided with a malformed start transaction
   * request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedStartTransactionRequest()
         throws Exception
  {
    final TestUnsolicitedNotificationHandler unsolicitedNotificationHandler =
         new TestUnsolicitedNotificationHandler();
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setUnsolicitedNotificationHandler(
         unsolicitedNotificationHandler);

    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection(connectionOptions);
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);


    try
    {
      final StartTransactionExtendedResult startTxnResult =
           (StartTransactionExtendedResult)
                conn.processExtendedOperation(new ExtendedRequest(
                     StartTransactionExtendedRequest.
                          START_TRANSACTION_REQUEST_OID,
                     new ASN1OctetString("foo")));
      assertResultCodeEquals(startTxnResult,
           ResultCode.PROTOCOL_ERROR);
    }
    catch (final LDAPException le)
    {
      assertResultCodeEquals(le, ResultCode.PROTOCOL_ERROR);
    }


    conn.close();
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);
  }



  /**
   * Tests the behavior when provided with a malformed end transaction request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedEndTransactionRequest()
         throws Exception
  {
    final TestUnsolicitedNotificationHandler unsolicitedNotificationHandler =
         new TestUnsolicitedNotificationHandler();
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setUnsolicitedNotificationHandler(
         unsolicitedNotificationHandler);

    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection(connectionOptions);
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);


    final StartTransactionExtendedResult startTxnResult =
         (StartTransactionExtendedResult)
         conn.processExtendedOperation(new StartTransactionExtendedRequest());
    assertResultCodeEquals(startTxnResult, ResultCode.SUCCESS);

    final ASN1OctetString txnID = startTxnResult.getTransactionID();
    assertNotNull(txnID);


    try
    {
      final EndTransactionExtendedResult endTxnResult =
           (EndTransactionExtendedResult) conn.processExtendedOperation(
                EndTransactionExtendedRequest.END_TRANSACTION_REQUEST_OID);
      assertResultCodeEquals(endTxnResult, ResultCode.PROTOCOL_ERROR);
    }
    catch (final LDAPException le)
    {
      assertResultCodeEquals(le, ResultCode.PROTOCOL_ERROR);
    }


    conn.close();
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 1);
  }



  /**
   * Provides a test case for a transaction in which an add operation fails
   * after other operations that should have succeeded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailedAddInTransaction()
         throws Exception
  {
    final TestUnsolicitedNotificationHandler unsolicitedNotificationHandler =
         new TestUnsolicitedNotificationHandler();
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setUnsolicitedNotificationHandler(
         unsolicitedNotificationHandler);

    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection(connectionOptions);
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final StartTransactionExtendedResult startTxnResult =
         (StartTransactionExtendedResult)
         conn.processExtendedOperation(new StartTransactionExtendedRequest());
    assertResultCodeEquals(startTxnResult, ResultCode.SUCCESS);

    final ASN1OctetString txnID = startTxnResult.getTransactionID();
    assertNotNull(txnID);
    final TransactionSpecificationRequestControl txnControl =
         new TransactionSpecificationRequestControl(txnID);

    final AddRequest addRequest1 = new AddRequest(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test");
    addRequest1.setControls(txnControl);
    assertResultCodeEquals(conn, addRequest1, ResultCode.SUCCESS);

    final AddRequest addRequest2 = new AddRequest(
         "dn: ou=test2,ou=missing,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test");
    addRequest2.setControls(txnControl);
    assertResultCodeEquals(conn, addRequest2, ResultCode.SUCCESS);


    final EndTransactionExtendedResult endTxnResult =
         (EndTransactionExtendedResult) conn.processExtendedOperation(
              new EndTransactionExtendedRequest(txnID, true));
    assertResultCodeEquals(endTxnResult, ResultCode.NO_SUCH_OBJECT);
    assertTrue(endTxnResult.getFailedOpMessageID() > 0);
    assertEquals(endTxnResult.getFailedOpMessageID(),
         addRequest2.getLastMessageID());
    assertNotNull(endTxnResult.getOperationResponseControls());
    assertTrue(endTxnResult.getOperationResponseControls().isEmpty());


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    conn.close();
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);
  }



  /**
   * Provides a test case for a transaction in which a delete operation fails
   * after other operations that should have succeeded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailedDeleteInTransaction()
         throws Exception
  {
    final TestUnsolicitedNotificationHandler unsolicitedNotificationHandler =
         new TestUnsolicitedNotificationHandler();
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setUnsolicitedNotificationHandler(
         unsolicitedNotificationHandler);

    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection(connectionOptions);
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final StartTransactionExtendedResult startTxnResult =
         (StartTransactionExtendedResult)
         conn.processExtendedOperation(new StartTransactionExtendedRequest());
    assertResultCodeEquals(startTxnResult, ResultCode.SUCCESS);

    final ASN1OctetString txnID = startTxnResult.getTransactionID();
    assertNotNull(txnID);
    final TransactionSpecificationRequestControl txnControl =
         new TransactionSpecificationRequestControl(txnID);

    final AddRequest addRequest = new AddRequest(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test");
    addRequest.setControls(txnControl);
    assertResultCodeEquals(conn, addRequest, ResultCode.SUCCESS);

    final DeleteRequest deleteRequest =
         new DeleteRequest("ou=People,dc=example,dc=com");
    deleteRequest.setControls(txnControl);
    assertResultCodeEquals(conn, deleteRequest, ResultCode.SUCCESS);


    final EndTransactionExtendedResult endTxnResult =
         (EndTransactionExtendedResult) conn.processExtendedOperation(
              new EndTransactionExtendedRequest(txnID, true));
    assertResultCodeEquals(endTxnResult, ResultCode.NOT_ALLOWED_ON_NONLEAF);
    assertTrue(endTxnResult.getFailedOpMessageID() > 0);
    assertEquals(endTxnResult.getFailedOpMessageID(),
         deleteRequest.getLastMessageID());
    assertNotNull(endTxnResult.getOperationResponseControls());
    assertTrue(endTxnResult.getOperationResponseControls().isEmpty());


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    conn.close();
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);
  }



  /**
   * Provides a test case for a transaction in which a modify operation fails
   * after other operations that should have succeeded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailedModifyInTransaction()
         throws Exception
  {
    final TestUnsolicitedNotificationHandler unsolicitedNotificationHandler =
         new TestUnsolicitedNotificationHandler();
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setUnsolicitedNotificationHandler(
         unsolicitedNotificationHandler);

    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection(connectionOptions);
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final StartTransactionExtendedResult startTxnResult =
         (StartTransactionExtendedResult)
         conn.processExtendedOperation(new StartTransactionExtendedRequest());
    assertResultCodeEquals(startTxnResult, ResultCode.SUCCESS);

    final ASN1OctetString txnID = startTxnResult.getTransactionID();
    assertNotNull(txnID);
    final TransactionSpecificationRequestControl txnControl =
         new TransactionSpecificationRequestControl(txnID);

    final AddRequest addRequest = new AddRequest(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test");
    addRequest.setControls(txnControl);
    assertResultCodeEquals(conn, addRequest, ResultCode.SUCCESS);

    final ModifyRequest modifyRequest = new ModifyRequest(
         "dn: ou=Missing,dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo");
    modifyRequest.setControls(txnControl);
    assertResultCodeEquals(conn, modifyRequest, ResultCode.SUCCESS);


    final EndTransactionExtendedResult endTxnResult =
         (EndTransactionExtendedResult) conn.processExtendedOperation(
              new EndTransactionExtendedRequest(txnID, true));
    assertResultCodeEquals(endTxnResult, ResultCode.NO_SUCH_OBJECT);
    assertTrue(endTxnResult.getFailedOpMessageID() > 0);
    assertEquals(endTxnResult.getFailedOpMessageID(),
         modifyRequest.getLastMessageID());
    assertNotNull(endTxnResult.getOperationResponseControls());
    assertTrue(endTxnResult.getOperationResponseControls().isEmpty());


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    conn.close();
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);
  }



  /**
   * Provides a test case for a transaction in which a modify DN operation fails
   * after other operations that should have succeeded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailedModifyDNInTransaction()
         throws Exception
  {
    final TestUnsolicitedNotificationHandler unsolicitedNotificationHandler =
         new TestUnsolicitedNotificationHandler();
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setUnsolicitedNotificationHandler(
         unsolicitedNotificationHandler);

    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection(connectionOptions);
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    final StartTransactionExtendedResult startTxnResult =
         (StartTransactionExtendedResult)
         conn.processExtendedOperation(new StartTransactionExtendedRequest());
    assertResultCodeEquals(startTxnResult, ResultCode.SUCCESS);

    final ASN1OctetString txnID = startTxnResult.getTransactionID();
    assertNotNull(txnID);
    final TransactionSpecificationRequestControl txnControl =
         new TransactionSpecificationRequestControl(txnID);

    final AddRequest addRequest = new AddRequest(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test");
    addRequest.setControls(txnControl);
    assertResultCodeEquals(conn, addRequest, ResultCode.SUCCESS);

    final ModifyDNRequest modifyDNRequest = new ModifyDNRequest(
         "ou=Missing,dc=example,dc=com", "ou=Still Missing", true);
    modifyDNRequest.setControls(txnControl);
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.SUCCESS);


    final EndTransactionExtendedResult endTxnResult =
         (EndTransactionExtendedResult) conn.processExtendedOperation(
              new EndTransactionExtendedRequest(txnID, true));
    assertResultCodeEquals(endTxnResult, ResultCode.NO_SUCH_OBJECT);
    assertTrue(endTxnResult.getFailedOpMessageID() > 0);
    assertEquals(endTxnResult.getFailedOpMessageID(),
         modifyDNRequest.getLastMessageID());
    assertNotNull(endTxnResult.getOperationResponseControls());
    assertTrue(endTxnResult.getOperationResponseControls().isEmpty());


    ds.assertEntryExists("dc=example,dc=com");
    ds.assertEntryExists("ou=People,dc=example,dc=com");
    ds.assertEntryExists("uid=test.user,ou=People,dc=example,dc=com");
    ds.assertEntryMissing("ou=test,dc=example,dc=com");
    ds.assertEntryMissing("uid=test.user,ou=test,dc=example,dc=com");


    conn.close();
    assertEquals(unsolicitedNotificationHandler.getNotificationCount(), 0);
  }
}
