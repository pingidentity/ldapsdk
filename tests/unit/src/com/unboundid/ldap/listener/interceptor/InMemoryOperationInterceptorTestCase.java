/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener.interceptor;



import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.PLAINBindRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.TestIntermediateResponseListener;
import com.unboundid.ldap.sdk.TestUnsolicitedNotificationHandler;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedResult;



/**
 * This class provides a set of test cases for the in-memory operation
 * interceptor API.
 */
public final class InMemoryOperationInterceptorTestCase
       extends LDAPSDKTestCase
{
  // The in-memory directory server instance that can be used for testing.
  private InMemoryDirectoryServer ds = null;



  /**
   * Creates an in-memory directory server instance that can be used for
   * testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");

    assertNotNull(cfg.getOperationInterceptors());
    assertTrue(cfg.getOperationInterceptors().isEmpty());

    cfg.addInMemoryOperationInterceptor(
         new ControlBasedOperationInterceptor());
    assertNotNull(cfg.getOperationInterceptors());
    assertEquals(cfg.getOperationInterceptors().size(), 1);

    cfg.addInMemoryOperationInterceptor(
         new DoNothingOperationInterceptor());
    assertNotNull(cfg.getOperationInterceptors());
    assertEquals(cfg.getOperationInterceptors().size(), 2);

    ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();
    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
  }



  /**
   * Cleans up after testing has completed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void cleanUp()
         throws Exception
  {
    ds.shutDown(true);
  }



  /**
   * Tests to ensure that everything works properly without any transformations
   * in place.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutTransformations()
         throws Exception
  {
    final LDAPConnection conn = ds.getConnection();

    final SimpleBindRequest simpleBind =
         new SimpleBindRequest("cn=Directory Manager", "password");
    assertResultCodeEquals(conn, simpleBind, ResultCode.SUCCESS);

    final PLAINBindRequest plainBind =
         new PLAINBindRequest("dn:cn=Directory Manager", "password");
    assertResultCodeEquals(conn, plainBind, ResultCode.SUCCESS);


    final WhoAmIExtendedResult whoAmIResult =
         (WhoAmIExtendedResult)
         conn.processExtendedOperation(new WhoAmIExtendedRequest());
    assertResultCodeEquals(whoAmIResult, ResultCode.SUCCESS);
    assertTrue(whoAmIResult.getAuthorizationID().startsWith("dn:"));
    assertDNsEqual(whoAmIResult.getAuthorizationID().substring(3),
         "cn=Directory Manager");

    final AddRequest addRequest = new AddRequest(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test");
    assertResultCodeEquals(conn, addRequest, ResultCode.SUCCESS);

    final SearchResult searchResult = conn.search("ou=test,dc=example,dc=com",
         SearchScope.SUB, "(objectClass=*)");
    assertResultCodeEquals(searchResult, ResultCode.SUCCESS);
    assertEntriesReturnedEquals(searchResult, 1);
    assertDNsEqual(searchResult.getSearchEntries().get(0).getDN(),
         "ou=test,dc=example,dc=com");

    final CompareRequest compareRequest =
         new CompareRequest("ou=test,dc=example,dc=com", "ou", "test");
    assertResultCodeEquals(conn, compareRequest, ResultCode.COMPARE_TRUE);

    final ModifyRequest modifyRequest = new ModifyRequest(
         "dn: ou=test,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");
    assertResultCodeEquals(conn, modifyRequest, ResultCode.SUCCESS);

    final ModifyDNRequest modifyDNRequest = new ModifyDNRequest(
         "ou=test,dc=example,dc=com", "ou=renamed test", true);
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.SUCCESS);

    final DeleteRequest deleteRequest =
         new DeleteRequest("ou=renamed test,dc=example,dc=com");
    assertResultCodeEquals(conn, deleteRequest, ResultCode.SUCCESS);

    conn.close();
  }



  /**
   * Tests to ensure that processing works correctly for add operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddWithTransformations()
         throws Exception
  {
    final LDAPConnection conn = ds.getConnection();

    AddRequest addRequest = new AddRequest(
         "dn: ou=no transforms,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: no transforms");
    assertResultCodeEquals(conn, addRequest, ResultCode.SUCCESS);
    assertEntryExists(conn, "ou=no transforms,dc=example,dc=com");

    addRequest = new AddRequest(
         "dn: ou=with alter DN transform,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: no transforms");
    addRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.ALTER_DN));
    assertResultCodeEquals(conn, addRequest, ResultCode.SUCCESS);
    assertEntryMissing(conn, "ou=with alter DN transform,dc=example,dc=com");
    assertEntryExists(conn, "ou=altered,dc=example,dc=com");

    addRequest = new AddRequest(
         "dn: ou=with inject IR transform,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: with inject IR transform");
    addRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.
              INJECT_INTERMEDIATE_RESPONSE
    ));
    final TestIntermediateResponseListener testIRListener =
         new TestIntermediateResponseListener();
    addRequest.setIntermediateResponseListener(testIRListener);
    assertResultCodeEquals(conn, addRequest, ResultCode.SUCCESS);
    assertEntryExists(conn, "ou=with inject IR transform,dc=example,dc=com");
    assertEquals(testIRListener.getCount(), 2);

    addRequest = new AddRequest(
         "dn: ou=with reject request transform,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: with reject request transform");
    addRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.REJECT_REQUEST));
    assertResultCodeEquals(conn, addRequest, ResultCode.UNWILLING_TO_PERFORM);
    assertEntryMissing(conn,
         "ou=with reject request transform,dc=example,dc=com");

    addRequest = new AddRequest(
         "dn: ou=with request RTE transform,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: with request RTE transform");
    addRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.
              REQUEST_RUNTIME_EXCEPTION));
    assertResultCodeEquals(conn, addRequest, ResultCode.OTHER);
    assertEntryMissing(conn,
         "ou=with request RTE transform,dc=example,dc=com");

    addRequest = new AddRequest(
         "dn: ou=with error result transform,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: with error result transform");
    addRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.ERROR_RESULT));
    assertResultCodeEquals(conn, addRequest, ResultCode.UNWILLING_TO_PERFORM);
    assertEntryExists(conn, "ou=with error result transform,dc=example,dc=com");

    addRequest = new AddRequest(
         "dn: ou=with result RTE transform,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: with result RTE transform");
    addRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.
              RESULT_RUNTIME_EXCEPTION));
    assertResultCodeEquals(conn, addRequest, ResultCode.OTHER);
    assertEntryExists(conn, "ou=with result RTE transform,dc=example,dc=com");

    conn.delete("ou=no transforms,dc=example,dc=com");
    conn.delete("ou=altered,dc=example,dc=com");
    conn.delete("ou=with inject IR transform,dc=example,dc=com");
    conn.delete("ou=with error result transform,dc=example,dc=com");
    conn.delete("ou=with result RTE transform,dc=example,dc=com");

    conn.close();
  }



  /**
   * Tests to ensure that processing works correctly for simple bind operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimpleBindWithTransformations()
         throws Exception
  {
    final LDAPConnection conn = ds.getConnection();

    SimpleBindRequest bindRequest =
         new SimpleBindRequest("cn=Directory Manager", "password");
    assertResultCodeEquals(conn, bindRequest, ResultCode.SUCCESS);

    bindRequest = new SimpleBindRequest("cn=Directory Manager", "password",
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.ALTER_DN));
    assertResultCodeEquals(conn, bindRequest, ResultCode.INVALID_CREDENTIALS);

    bindRequest = new SimpleBindRequest("cn=Directory Manager", "password",
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.REJECT_REQUEST));
    assertResultCodeEquals(conn, bindRequest, ResultCode.UNWILLING_TO_PERFORM);

    bindRequest = new SimpleBindRequest("cn=Directory Manager", "password",
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.
                   REQUEST_RUNTIME_EXCEPTION));
    assertResultCodeEquals(conn, bindRequest, ResultCode.OTHER);

    bindRequest = new SimpleBindRequest("cn=Directory Manager", "password",
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.ERROR_RESULT));
    assertResultCodeEquals(conn, bindRequest, ResultCode.UNWILLING_TO_PERFORM);

    bindRequest = new SimpleBindRequest("cn=Directory Manager", "password",
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.
                   RESULT_RUNTIME_EXCEPTION));
    assertResultCodeEquals(conn, bindRequest, ResultCode.OTHER);

    bindRequest = new SimpleBindRequest("cn=Directory Manager", "password",
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.
                   INJECT_INTERMEDIATE_RESPONSE));
    final TestIntermediateResponseListener testIRListener =
         new TestIntermediateResponseListener();
    bindRequest.setIntermediateResponseListener(testIRListener);
    assertResultCodeEquals(conn, bindRequest, ResultCode.SUCCESS);
    assertEquals(testIRListener.getCount(), 2);

    conn.close();
  }



  /**
   * Tests to ensure that processing works correctly for SASL bind operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSASLBindWithTransformations()
         throws Exception
  {
    final LDAPConnection conn = ds.getConnection();

    PLAINBindRequest bindRequest =
         new PLAINBindRequest("dn:cn=Directory Manager", "password");
    assertResultCodeEquals(conn, bindRequest, ResultCode.SUCCESS);

    bindRequest = new PLAINBindRequest("dn:cn=Directory Manager", "password",
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.ALTER_DN));
    assertResultCodeEquals(conn, bindRequest, ResultCode.SUCCESS);

    bindRequest = new PLAINBindRequest("dn:cn=Directory Manager", "password",
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.REJECT_REQUEST));
    assertResultCodeEquals(conn, bindRequest, ResultCode.UNWILLING_TO_PERFORM);

    bindRequest = new PLAINBindRequest("dn:cn=Directory Manager", "password",
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.
                   REQUEST_RUNTIME_EXCEPTION));
    assertResultCodeEquals(conn, bindRequest, ResultCode.OTHER);

    bindRequest = new PLAINBindRequest("dn:cn=Directory Manager", "password",
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.ERROR_RESULT));
    assertResultCodeEquals(conn, bindRequest, ResultCode.UNWILLING_TO_PERFORM);

    bindRequest = new PLAINBindRequest("dn:cn=Directory Manager", "password",
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.
                   RESULT_RUNTIME_EXCEPTION));
    assertResultCodeEquals(conn, bindRequest, ResultCode.OTHER);

    bindRequest = new PLAINBindRequest("dn:cn=Directory Manager", "password",
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.
                   INJECT_INTERMEDIATE_RESPONSE));
    final TestIntermediateResponseListener testIRListener =
         new TestIntermediateResponseListener();
    bindRequest.setIntermediateResponseListener(testIRListener);
    assertResultCodeEquals(conn, bindRequest, ResultCode.SUCCESS);
    assertEquals(testIRListener.getCount(), 2);

    conn.close();
  }



  /**
   * Tests to ensure that processing works correctly for compare operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareWithTransformations()
         throws Exception
  {
    final LDAPConnection conn = ds.getConnection();

    CompareRequest compareRequest = new CompareRequest(
         "dc=example,dc=com", "dc", "example");
    assertResultCodeEquals(conn, compareRequest, ResultCode.COMPARE_TRUE);

    compareRequest = new CompareRequest("dc=example,dc=com", "dc", "example");
    compareRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.ALTER_DN));
    assertResultCodeEquals(conn, compareRequest, ResultCode.NO_SUCH_OBJECT);

    compareRequest = new CompareRequest("dc=example,dc=com", "dc", "example");
    compareRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.REJECT_REQUEST));
    assertResultCodeEquals(conn, compareRequest,
         ResultCode.UNWILLING_TO_PERFORM);

    compareRequest = new CompareRequest("dc=example,dc=com", "dc", "example");
    compareRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.
              REQUEST_RUNTIME_EXCEPTION
    ));
    assertResultCodeEquals(conn, compareRequest, ResultCode.OTHER);

    compareRequest = new CompareRequest("dc=example,dc=com", "dc", "example");
    compareRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.ERROR_RESULT));
    assertResultCodeEquals(conn, compareRequest,
         ResultCode.UNWILLING_TO_PERFORM);

    compareRequest = new CompareRequest("dc=example,dc=com", "dc", "example");
    compareRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.
              RESULT_RUNTIME_EXCEPTION));
    assertResultCodeEquals(conn, compareRequest, ResultCode.OTHER);

    compareRequest = new CompareRequest("dc=example,dc=com", "dc", "example");
    compareRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.
              INJECT_INTERMEDIATE_RESPONSE));
    final TestIntermediateResponseListener testIRListener =
         new TestIntermediateResponseListener();
    compareRequest.setIntermediateResponseListener(testIRListener);
    assertResultCodeEquals(conn, compareRequest, ResultCode.COMPARE_TRUE);
    assertEquals(testIRListener.getCount(), 2);

    conn.close();
  }



  /**
   * Tests to ensure that processing works correctly for delete operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteWithTransformations()
         throws Exception
  {
    final LDAPConnection conn = ds.getConnection();

    conn.add(
         "dn: ou=test1,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test1");
    conn.add(
         "dn: ou=test2,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test2");
    conn.add(
         "dn: ou=test3,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test3");
    conn.add(
         "dn: ou=test4,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test4");
    conn.add(
         "dn: ou=altered,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: altered");

    DeleteRequest deleteRequest =
         new DeleteRequest("ou=test1,dc=example,dc=com");
    assertResultCodeEquals(conn, deleteRequest, ResultCode.SUCCESS);
    assertEntryMissing(conn, "ou=test1,dc=example,dc=com");

    deleteRequest = new DeleteRequest("ou=test2,dc=example,dc=com");
    deleteRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.ALTER_DN));
    assertResultCodeEquals(conn, deleteRequest, ResultCode.SUCCESS);
    assertEntryExists(conn, "ou=test2,dc=example,dc=com");
    assertEntryMissing(conn, "ou=altered,dc=example,dc=com");

    deleteRequest = new DeleteRequest("ou=test2,dc=example,dc=com");
    deleteRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.REJECT_REQUEST));
    assertResultCodeEquals(conn, deleteRequest,
         ResultCode.UNWILLING_TO_PERFORM);
    assertEntryExists(conn, "ou=test2,dc=example,dc=com");

    deleteRequest = new DeleteRequest("ou=test2,dc=example,dc=com");
    deleteRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.
              REQUEST_RUNTIME_EXCEPTION));
    assertResultCodeEquals(conn, deleteRequest, ResultCode.OTHER);
    assertEntryExists(conn, "ou=test2,dc=example,dc=com");

    deleteRequest = new DeleteRequest("ou=test2,dc=example,dc=com");
    deleteRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.ERROR_RESULT));
    assertResultCodeEquals(conn, deleteRequest,
         ResultCode.UNWILLING_TO_PERFORM);
    assertEntryMissing(conn, "ou=test2,dc=example,dc=com");

    deleteRequest = new DeleteRequest("ou=test3,dc=example,dc=com");
    deleteRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.
              RESULT_RUNTIME_EXCEPTION));
    assertResultCodeEquals(conn, deleteRequest, ResultCode.OTHER);
    assertEntryMissing(conn, "ou=test3,dc=example,dc=com");

    deleteRequest = new DeleteRequest("ou=test4,dc=example,dc=com");
    deleteRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.
              INJECT_INTERMEDIATE_RESPONSE));
    final TestIntermediateResponseListener testIRListener =
         new TestIntermediateResponseListener();
    deleteRequest.setIntermediateResponseListener(testIRListener);
    assertResultCodeEquals(conn, deleteRequest, ResultCode.SUCCESS);
    assertEntryMissing(conn, "ou=test4,dc=example,dc=com");
    assertEquals(testIRListener.getCount(), 2);

    conn.close();
  }



  /**
   * Tests to ensure that processing works correctly for extended operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedWithTransformations()
         throws Exception
  {
    final LDAPConnection conn = ds.getConnection();

    WhoAmIExtendedRequest whoAmIRequest = new WhoAmIExtendedRequest();
    assertResultCodeEquals(conn, whoAmIRequest, ResultCode.SUCCESS);

    whoAmIRequest = new WhoAmIExtendedRequest(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.ALTER_DN));
    assertResultCodeEquals(conn, whoAmIRequest, ResultCode.SUCCESS);

    whoAmIRequest = new WhoAmIExtendedRequest(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.REJECT_REQUEST));
    assertResultCodeEquals(conn, whoAmIRequest,
         ResultCode.UNWILLING_TO_PERFORM);

    whoAmIRequest = new WhoAmIExtendedRequest(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.
                   REQUEST_RUNTIME_EXCEPTION));
    assertResultCodeEquals(conn, whoAmIRequest, ResultCode.OTHER);

    whoAmIRequest = new WhoAmIExtendedRequest(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.ERROR_RESULT));
    assertResultCodeEquals(conn, whoAmIRequest,
         ResultCode.UNWILLING_TO_PERFORM);

    whoAmIRequest = new WhoAmIExtendedRequest(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.
                   RESULT_RUNTIME_EXCEPTION));
    assertResultCodeEquals(conn, whoAmIRequest, ResultCode.OTHER);

    whoAmIRequest = new WhoAmIExtendedRequest(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.
                   INJECT_INTERMEDIATE_RESPONSE));
    final TestIntermediateResponseListener testIRListener =
         new TestIntermediateResponseListener();
    whoAmIRequest.setIntermediateResponseListener(testIRListener);
    assertResultCodeEquals(conn, whoAmIRequest, ResultCode.SUCCESS);
    assertEquals(testIRListener.getCount(), 2);

    conn.close();
  }



  /**
   * Tests to ensure that processing works correctly for modify operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyWithTransformations()
         throws Exception
  {
    final LDAPConnection conn = ds.getConnection();

    ModifyRequest modifyRequest = new ModifyRequest(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: test1");
    assertResultCodeEquals(conn, modifyRequest, ResultCode.SUCCESS);
    assertValueExists(conn, "dc=example,dc=com", "description", "test1");

    modifyRequest = new ModifyRequest(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: test2");
    modifyRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.ALTER_DN));
    assertResultCodeEquals(conn, modifyRequest, ResultCode.NO_SUCH_OBJECT);
    assertValueExists(conn, "dc=example,dc=com", "description", "test1");

    modifyRequest = new ModifyRequest(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: test2");
    modifyRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.REJECT_REQUEST));
    assertResultCodeEquals(conn, modifyRequest,
         ResultCode.UNWILLING_TO_PERFORM);
    assertValueExists(conn, "dc=example,dc=com", "description", "test1");

    modifyRequest = new ModifyRequest(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: test2");
    modifyRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.
              REQUEST_RUNTIME_EXCEPTION));
    assertResultCodeEquals(conn, modifyRequest, ResultCode.OTHER);
    assertValueExists(conn, "dc=example,dc=com", "description", "test1");

    modifyRequest = new ModifyRequest(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: test2");
    modifyRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.ERROR_RESULT));
    assertResultCodeEquals(conn, modifyRequest,
         ResultCode.UNWILLING_TO_PERFORM);
    assertValueExists(conn, "dc=example,dc=com", "description", "test2");

    modifyRequest = new ModifyRequest(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: test3");
    modifyRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.
              RESULT_RUNTIME_EXCEPTION));
    assertResultCodeEquals(conn, modifyRequest, ResultCode.OTHER);
    assertValueExists(conn, "dc=example,dc=com", "description", "test3");

    modifyRequest = new ModifyRequest(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: test4");
    modifyRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.
              INJECT_INTERMEDIATE_RESPONSE));
    final TestIntermediateResponseListener testIRListener =
         new TestIntermediateResponseListener();
    modifyRequest.setIntermediateResponseListener(testIRListener);
    assertResultCodeEquals(conn, modifyRequest, ResultCode.SUCCESS);
    assertValueExists(conn, "dc=example,dc=com", "description", "test4");

    modifyRequest = new ModifyRequest(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description");
    assertResultCodeEquals(conn, modifyRequest, ResultCode.SUCCESS);
    assertAttributeMissing(conn, "dc=example,dc=com", "description");

    conn.close();
  }



  /**
   * Tests to ensure that processing works correctly for modify DN operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNWithTransformations()
         throws Exception
  {
    final LDAPConnection conn = ds.getConnection();

    conn.add(
         "dn: ou=test1,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test1");
    conn.add(
         "dn: ou=test2,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test2");
    conn.add(
         "dn: ou=test3,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test3");
    conn.add(
         "dn: ou=test4,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test4");
    conn.add(
         "dn: ou=altered,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: altered");

    ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("ou=test1,dc=example,dc=com", "ou=renamed1", true);
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.SUCCESS);
    assertEntryMissing(conn, "ou=test1,dc=example,dc=com");
    assertEntryExists(conn, "ou=renamed1,dc=example,dc=com");

    modifyDNRequest =
         new ModifyDNRequest("ou=test2,dc=example,dc=com", "ou=renamed2", true);
    modifyDNRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.ALTER_DN));
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.SUCCESS);
    assertEntryExists(conn, "ou=test2,dc=example,dc=com");
    assertEntryMissing(conn, "ou=altered,dc=example,dc=com");
    assertEntryExists(conn, "ou=renamed2,dc=example,dc=com");

    modifyDNRequest =
         new ModifyDNRequest("ou=test2,dc=example,dc=com", "ou=renamed3", true);
    modifyDNRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.REJECT_REQUEST));
    assertResultCodeEquals(conn, modifyDNRequest,
         ResultCode.UNWILLING_TO_PERFORM);
    assertEntryExists(conn, "ou=test2,dc=example,dc=com");
    assertEntryMissing(conn, "ou=renamed3,dc=example,dc=com");

    modifyDNRequest =
         new ModifyDNRequest("ou=test2,dc=example,dc=com", "ou=renamed3", true);
    modifyDNRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.
              REQUEST_RUNTIME_EXCEPTION));
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.OTHER);
    assertEntryExists(conn, "ou=test2,dc=example,dc=com");
    assertEntryMissing(conn, "ou=renamed3,dc=example,dc=com");

    modifyDNRequest =
         new ModifyDNRequest("ou=test2,dc=example,dc=com", "ou=renamed3", true);
    modifyDNRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.ERROR_RESULT));
    assertResultCodeEquals(conn, modifyDNRequest,
         ResultCode.UNWILLING_TO_PERFORM);
    assertEntryMissing(conn, "ou=test2,dc=example,dc=com");
    assertEntryExists(conn, "ou=renamed3,dc=example,dc=com");

    modifyDNRequest =
         new ModifyDNRequest("ou=test3,dc=example,dc=com", "ou=renamed4", true);
    modifyDNRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.
              RESULT_RUNTIME_EXCEPTION));
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.OTHER);
    assertEntryMissing(conn, "ou=test3,dc=example,dc=com");
    assertEntryExists(conn, "ou=renamed4,dc=example,dc=com");

    modifyDNRequest =
         new ModifyDNRequest("ou=test4,dc=example,dc=com", "ou=renamed5", true);
    modifyDNRequest.setControls(ControlBasedOperationInterceptor.createControls(
         ControlBasedOperationInterceptor.TransformType.
              INJECT_INTERMEDIATE_RESPONSE));
    final TestIntermediateResponseListener testIRListener =
         new TestIntermediateResponseListener();
    modifyDNRequest.setIntermediateResponseListener(testIRListener);
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.SUCCESS);
    assertEntryMissing(conn, "ou=test4,dc=example,dc=com");
    assertEntryExists(conn, "ou=renamed5,dc=example,dc=com");
    assertEquals(testIRListener.getCount(), 2);

    conn.delete("ou=renamed1,dc=example,dc=com");
    conn.delete("ou=renamed2,dc=example,dc=com");
    conn.delete("ou=renamed3,dc=example,dc=com");
    conn.delete("ou=renamed4,dc=example,dc=com");
    conn.delete("ou=renamed5,dc=example,dc=com");

    conn.close();
  }



  /**
   * Tests to ensure that processing works correctly for search operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchWithTransformations()
         throws Exception
  {
    final LDAPConnection conn = ds.getConnection();

    SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, "(objectClass=*)");
    SearchResult searchResult = (SearchResult)
         assertResultCodeEquals(conn, searchRequest, ResultCode.SUCCESS);
    assertEntriesReturnedEquals(searchResult, 1);
    assertReferencesReturnedEquals(searchResult, 0);

    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");
    searchRequest.setControls(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.ALTER_DN));
    searchResult = (SearchResult)
         assertResultCodeEquals(conn, searchRequest, ResultCode.NO_SUCH_OBJECT);
    assertEntriesReturnedEquals(searchResult, 0);
    assertReferencesReturnedEquals(searchResult, 0);

    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");
    searchRequest.setControls(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.REJECT_REQUEST));
    searchResult = (SearchResult)
         assertResultCodeEquals(conn, searchRequest,
              ResultCode.UNWILLING_TO_PERFORM);
    assertEntriesReturnedEquals(searchResult, 0);
    assertReferencesReturnedEquals(searchResult, 0);

    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");
    searchRequest.setControls(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.
                   REQUEST_RUNTIME_EXCEPTION));
    searchResult = (SearchResult)
         assertResultCodeEquals(conn, searchRequest, ResultCode.OTHER);
    assertEntriesReturnedEquals(searchResult, 0);
    assertReferencesReturnedEquals(searchResult, 0);

    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");
    searchRequest.setControls(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.ERROR_RESULT));
    searchResult = (SearchResult)
         assertResultCodeEquals(conn, searchRequest,
              ResultCode.UNWILLING_TO_PERFORM);
    assertEntriesReturnedEquals(searchResult, 1);
    assertReferencesReturnedEquals(searchResult, 0);

    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");
    searchRequest.setControls(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.
                   RESULT_RUNTIME_EXCEPTION));
    searchResult = (SearchResult)
         assertResultCodeEquals(conn, searchRequest, ResultCode.OTHER);
    assertEntriesReturnedEquals(searchResult, 1);
    assertReferencesReturnedEquals(searchResult, 0);

    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");
    searchRequest.setControls(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.INJECT_ENTRY));
    searchResult = (SearchResult)
         assertResultCodeEquals(conn, searchRequest, ResultCode.SUCCESS);
    assertEntriesReturnedEquals(searchResult, 3);
    assertReferencesReturnedEquals(searchResult, 0);

    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");
    searchRequest.setControls(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.
                   ENTRY_RUNTIME_EXCEPTION));
    searchResult = (SearchResult)
         assertResultCodeEquals(conn, searchRequest, ResultCode.SUCCESS);
    assertEntriesReturnedEquals(searchResult, 0);
    assertReferencesReturnedEquals(searchResult, 0);

    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");
    searchRequest.setControls(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.ALTER_ENTRY));
    searchResult = (SearchResult)
         assertResultCodeEquals(conn, searchRequest, ResultCode.SUCCESS);
    assertEntriesReturnedEquals(searchResult, 1);
    assertReferencesReturnedEquals(searchResult, 0);

    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");
    searchRequest.setControls(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.SUPPRESS_ENTRY));
    searchResult = (SearchResult)
         assertResultCodeEquals(conn, searchRequest, ResultCode.SUCCESS);
    assertEntriesReturnedEquals(searchResult, 0);
    assertReferencesReturnedEquals(searchResult, 0);

    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");
    searchRequest.setControls(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.INJECT_ENTRY,
              ControlBasedOperationInterceptor.TransformType.SUPPRESS_ENTRY));
    searchResult = (SearchResult)
         assertResultCodeEquals(conn, searchRequest, ResultCode.SUCCESS);
    assertEntriesReturnedEquals(searchResult, 0);
    assertReferencesReturnedEquals(searchResult, 0);

    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");
    searchRequest.setControls(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.INJECT_ENTRY,
              ControlBasedOperationInterceptor.TransformType.ALTER_ENTRY));
    searchResult = (SearchResult)
         assertResultCodeEquals(conn, searchRequest, ResultCode.SUCCESS);
    assertEntriesReturnedEquals(searchResult, 3);
    assertReferencesReturnedEquals(searchResult, 0);

    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");
    searchRequest.setControls(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.INJECT_REFERENCE));
    searchResult = (SearchResult)
         assertResultCodeEquals(conn, searchRequest, ResultCode.SUCCESS);
    assertEntriesReturnedEquals(searchResult, 1);
    assertReferencesReturnedEquals(searchResult, 2);

    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");
    searchRequest.setControls(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.INJECT_REFERENCE,
              ControlBasedOperationInterceptor.TransformType.
                   SUPPRESS_REFERENCE));
    searchResult = (SearchResult)
         assertResultCodeEquals(conn, searchRequest, ResultCode.SUCCESS);
    assertEntriesReturnedEquals(searchResult, 1);
    assertReferencesReturnedEquals(searchResult, 0);

    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");
    searchRequest.setControls(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.INJECT_REFERENCE,
              ControlBasedOperationInterceptor.TransformType.ALTER_REFERENCE));
    searchResult = (SearchResult)
         assertResultCodeEquals(conn, searchRequest, ResultCode.SUCCESS);
    assertEntriesReturnedEquals(searchResult, 1);
    assertReferencesReturnedEquals(searchResult, 2);

    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");
    searchRequest.setControls(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.INJECT_REFERENCE,
              ControlBasedOperationInterceptor.TransformType.
                   REFERENCE_RUNTIME_EXCEPTION));
    searchResult = (SearchResult)
         assertResultCodeEquals(conn, searchRequest, ResultCode.SUCCESS);
    assertEntriesReturnedEquals(searchResult, 1);
    assertReferencesReturnedEquals(searchResult, 0);

    searchRequest = new SearchRequest("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");
    searchRequest.setControls(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.
                   INJECT_INTERMEDIATE_RESPONSE));
    final TestIntermediateResponseListener testIRListener =
         new TestIntermediateResponseListener();
    searchRequest.setIntermediateResponseListener(testIRListener);
    searchResult = (SearchResult)
         assertResultCodeEquals(conn, searchRequest, ResultCode.SUCCESS);
    assertEntriesReturnedEquals(searchResult, 1);
    assertReferencesReturnedEquals(searchResult, 0);
    assertEquals(testIRListener.getCount(), 2);

    conn.close();
  }



  /**
   * Tests to ensure that processing works correctly for intermediate responses.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntermediateResponseWithTransformations()
         throws Exception
  {
    final LDAPConnection conn = ds.getConnection();

    WhoAmIExtendedRequest whoAmIRequest = new WhoAmIExtendedRequest(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.
                   INJECT_INTERMEDIATE_RESPONSE));
    TestIntermediateResponseListener testIRListener =
         new TestIntermediateResponseListener();
    whoAmIRequest.setIntermediateResponseListener(testIRListener);
    assertResultCodeEquals(conn, whoAmIRequest, ResultCode.SUCCESS);
    assertEquals(testIRListener.getCount(), 2);

    whoAmIRequest = new WhoAmIExtendedRequest(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.
                   INJECT_INTERMEDIATE_RESPONSE,
              ControlBasedOperationInterceptor.TransformType.
                   SUPPRESS_INTERMEDIATE_RESPONSE));
    testIRListener = new TestIntermediateResponseListener();
    whoAmIRequest.setIntermediateResponseListener(testIRListener);
    assertResultCodeEquals(conn, whoAmIRequest, ResultCode.SUCCESS);
    assertEquals(testIRListener.getCount(), 0);

    whoAmIRequest = new WhoAmIExtendedRequest(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.
                   INJECT_INTERMEDIATE_RESPONSE,
              ControlBasedOperationInterceptor.TransformType.
                   ALTER_INTERMEDIATE_RESPONSE));
    testIRListener = new TestIntermediateResponseListener();
    whoAmIRequest.setIntermediateResponseListener(testIRListener);
    assertResultCodeEquals(conn, whoAmIRequest, ResultCode.SUCCESS);
    assertEquals(testIRListener.getCount(), 2);

    whoAmIRequest = new WhoAmIExtendedRequest(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.
                   INJECT_INTERMEDIATE_RESPONSE,
              ControlBasedOperationInterceptor.TransformType.
                   INTERMEDIATE_RESPONSE_RUNTIME_EXCEPTION));
    testIRListener = new TestIntermediateResponseListener();
    whoAmIRequest.setIntermediateResponseListener(testIRListener);
    assertResultCodeEquals(conn, whoAmIRequest, ResultCode.SUCCESS);
    assertEquals(testIRListener.getCount(), 0);

    conn.close();
  }



  /**
   * Tests to ensure that unsolicited responses are handled properly.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnsolicitedResponse()
         throws Exception
  {
    final LDAPConnection conn = ds.getConnection();

    final TestUnsolicitedNotificationHandler testNotificationHandler =
         new TestUnsolicitedNotificationHandler();
    final LDAPConnectionOptions options = conn.getConnectionOptions();
    options.setUnsolicitedNotificationHandler(testNotificationHandler);
    conn.setConnectionOptions(options);

    WhoAmIExtendedRequest whoAmIRequest = new WhoAmIExtendedRequest(
         ControlBasedOperationInterceptor.createControls(
              ControlBasedOperationInterceptor.TransformType.
                   INJECT_UNSOLICITED_NOTIFICATION));
    assertResultCodeEquals(conn, whoAmIRequest, ResultCode.SUCCESS);

    assertEquals(testNotificationHandler.getNotificationCount(), 2);

    conn.close();
  }
}
