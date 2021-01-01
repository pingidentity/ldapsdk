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

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.CompareResult;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.ReadOnlyAddRequest;
import com.unboundid.ldap.sdk.ReadOnlyCompareRequest;
import com.unboundid.ldap.sdk.ReadOnlyDeleteRequest;
import com.unboundid.ldap.sdk.ReadOnlyModifyRequest;
import com.unboundid.ldap.sdk.ReadOnlyModifyDNRequest;
import com.unboundid.ldap.sdk.ReadOnlySearchRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.TestSearchResultListener;
import com.unboundid.ldap.sdk.controls.AssertionRequestControl;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityRequestControl;
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
import com.unboundid.ldap.sdk.controls.SimplePagedResultsControl;
import com.unboundid.ldap.sdk.controls.SubtreeDeleteRequestControl;
import com.unboundid.ldap.sdk.controls.TransactionSpecificationRequestControl;
import com.unboundid.ldap.sdk.controls.VirtualListViewRequestControl;
import com.unboundid.ldap.sdk.extensions.EndTransactionExtendedRequest;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedRequest;
import com.unboundid.ldap.sdk.extensions.StartTransactionExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedResult;
import com.unboundid.ldap.sdk.schema.Schema;



/**
 * This class provides a set of test cases for the functionality that allows the
 * in-memory directory server to behave according to the {@code LDAPInterface}
 * interface.
 */
public final class InMemoryDirectoryServerLDAPInterfaceTestCase
       extends LDAPSDKTestCase
{
  // The in-memory directory server instance that will be used for the tests
  // in this class.  It will not be started.
  private InMemoryDirectoryServer ds = null;

  // An initial snapshot of the in-memory directory server instance.
  private InMemoryDirectoryServerSnapshot snapshot = null;



  /**
   * Creates but does not start the in-memory directory server instance and
   * creates a snapshot of that instance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void createDS()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com",
              "o=example.com");
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    cfg.addAdditionalBindCredentials("cn=Manager", "password");
    cfg.setSchema(Schema.getDefaultStandardSchema());

    ds = new InMemoryDirectoryServer(cfg);

    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    ds.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    ds.add(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password");

    snapshot = ds.createSnapshot();
  }



  /**
   * Tests the {@code getRootDSE} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetRootDSE()
         throws Exception
  {
    ds.restoreSnapshot(snapshot);


    final RootDSE rootDSE = ds.getRootDSE();

    assertNotNull(rootDSE);

    assertNotNull(rootDSE.getNamingContextDNs());
    assertEquals(rootDSE.getNamingContextDNs().length, 2);
    assertEquals(new DN(rootDSE.getNamingContextDNs()[0]),
         new DN("dc=example,dc=com"));
    assertEquals(new DN(rootDSE.getNamingContextDNs()[1]),
         new DN("o=example.com"));

    assertNotNull(rootDSE.getSubschemaSubentryDN());
    assertEquals(new DN(rootDSE.getSubschemaSubentryDN()),
         new DN("cn=schema"));

    assertNotNull(rootDSE.getSupportedControlOIDs());
    assertTrue(rootDSE.supportsControl(
         AssertionRequestControl.ASSERTION_REQUEST_OID));
    assertTrue(rootDSE.supportsControl(AuthorizationIdentityRequestControl.
         AUTHORIZATION_IDENTITY_REQUEST_OID));
    assertTrue(rootDSE.supportsControl(
         DraftLDUPSubentriesRequestControl.SUBENTRIES_REQUEST_OID));
    assertTrue(rootDSE.supportsControl(
         ManageDsaITRequestControl.MANAGE_DSA_IT_REQUEST_OID));
    assertTrue(rootDSE.supportsControl(
         PermissiveModifyRequestControl.PERMISSIVE_MODIFY_REQUEST_OID));
    assertTrue(rootDSE.supportsControl(
         PostReadRequestControl.POST_READ_REQUEST_OID));
    assertTrue(rootDSE.supportsControl(
         PreReadRequestControl.PRE_READ_REQUEST_OID));
    assertTrue(rootDSE.supportsControl(ProxiedAuthorizationV1RequestControl.
         PROXIED_AUTHORIZATION_V1_REQUEST_OID));
    assertTrue(rootDSE.supportsControl(ProxiedAuthorizationV2RequestControl.
         PROXIED_AUTHORIZATION_V2_REQUEST_OID));
    assertTrue(rootDSE.supportsControl(
         RFC3672SubentriesRequestControl.SUBENTRIES_REQUEST_OID));
    assertTrue(rootDSE.supportsControl(
         ServerSideSortRequestControl.SERVER_SIDE_SORT_REQUEST_OID));
    assertTrue(rootDSE.supportsControl(
         SimplePagedResultsControl.PAGED_RESULTS_OID));
    assertTrue(rootDSE.supportsControl(
         SubtreeDeleteRequestControl.SUBTREE_DELETE_REQUEST_OID));
    assertTrue(rootDSE.supportsControl(TransactionSpecificationRequestControl.
         TRANSACTION_SPECIFICATION_REQUEST_OID));
    assertTrue(rootDSE.supportsControl(
         VirtualListViewRequestControl.VIRTUAL_LIST_VIEW_REQUEST_OID));

    assertNotNull(rootDSE.getSupportedExtendedOperationOIDs());
    assertTrue(rootDSE.supportsExtendedOperation(
         EndTransactionExtendedRequest.END_TRANSACTION_REQUEST_OID));
    assertTrue(rootDSE.supportsExtendedOperation(
         PasswordModifyExtendedRequest.PASSWORD_MODIFY_REQUEST_OID));
    assertTrue(rootDSE.supportsExtendedOperation(
         StartTransactionExtendedRequest.START_TRANSACTION_REQUEST_OID));
    assertTrue(rootDSE.supportsExtendedOperation(
         WhoAmIExtendedRequest.WHO_AM_I_REQUEST_OID));

    assertNotNull(rootDSE.getSupportedFeatureOIDs());
    assertTrue(rootDSE.supportsFeature("1.3.6.1.4.1.4203.1.5.1"));
    assertTrue(rootDSE.supportsFeature("1.3.6.1.4.1.4203.1.5.2"));
    assertTrue(rootDSE.supportsFeature("1.3.6.1.4.1.4203.1.5.3"));
    assertTrue(rootDSE.supportsFeature("1.3.6.1.1.14"));

    assertNotNull(rootDSE.getSupportedLDAPVersions());
    assertEquals(rootDSE.getSupportedLDAPVersions().length, 1);
    assertEquals(rootDSE.getSupportedLDAPVersions()[0], 3);

    assertTrue(rootDSE.supportsLDAPVersion(3));

    assertNotNull(rootDSE.getSupportedSASLMechanismNames());
    assertTrue(rootDSE.supportsSASLMechanism("PLAIN"));

    assertNotNull(rootDSE.getVendorName());

    assertNotNull(rootDSE.getVendorVersion());
  }



  /**
   * Tests the {@code getSchema} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSchema()
         throws Exception
  {
    ds.restoreSnapshot(snapshot);


    // Test without an explicit DN provided.
    Schema schema = ds.getSchema();

    assertNotNull(schema);

    assertNotNull(schema.getAttributeType("uid"));

    assertNotNull(schema.getObjectClass("inetOrgPerson"));


    // Test with an explicit DN.
    schema = ds.getSchema("dc=example,dc=com");

    assertNotNull(schema);

    assertNotNull(schema.getAttributeType("uid"));

    assertNotNull(schema.getObjectClass("inetOrgPerson"));
  }



  /**
   * Tests the {@code getEntry} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetEntry()
         throws Exception
  {
    ds.restoreSnapshot(snapshot);


    // Test the version without any requested attributes.
    SearchResultEntry entry = ds.getEntry("dc=example,dc=com");

    assertNotNull(entry);

    assertTrue(entry.hasAttribute("dc"));
    assertTrue(entry.hasAttribute("objectClass"));
    assertFalse(entry.hasAttribute("missing"));
    assertFalse(entry.hasAttribute("entryDN"));
    assertFalse(entry.hasAttribute("entryUUID"));
    assertFalse(entry.hasAttribute("creatorsName"));
    assertFalse(entry.hasAttribute("createTimestamp"));
    assertFalse(entry.hasAttribute("modifiersName"));
    assertFalse(entry.hasAttribute("modifyTimestamp"));
    assertFalse(entry.hasAttribute("subschemaSubentry"));


    // Test with a request for all user and operational attributes.
    entry = ds.getEntry("dc=example,dc=com", "*", "+");

    assertNotNull(entry);

    assertTrue(entry.hasAttribute("dc"));
    assertTrue(entry.hasAttribute("objectClass"));
    assertFalse(entry.hasAttribute("missing"));
    assertTrue(entry.hasAttribute("entryDN"));
    assertTrue(entry.hasAttribute("entryUUID"));
    assertTrue(entry.hasAttribute("creatorsName"));
    assertTrue(entry.hasAttribute("createTimestamp"));
    assertTrue(entry.hasAttribute("modifiersName"));
    assertTrue(entry.hasAttribute("modifyTimestamp"));
    assertTrue(entry.hasAttribute("subschemaSubentry"));


    // Test with an explicit set of requested attributes.
    entry = ds.getEntry("dc=example,dc=com", "dc", "entryUUID");

    assertNotNull(entry);

    assertTrue(entry.hasAttribute("dc"));
    assertFalse(entry.hasAttribute("objectClass"));
    assertFalse(entry.hasAttribute("missing"));
    assertFalse(entry.hasAttribute("entryDN"));
    assertTrue(entry.hasAttribute("entryUUID"));
    assertFalse(entry.hasAttribute("creatorsName"));
    assertFalse(entry.hasAttribute("createTimestamp"));
    assertFalse(entry.hasAttribute("modifiersName"));
    assertFalse(entry.hasAttribute("modifyTimestamp"));
    assertFalse(entry.hasAttribute("subschemaSubentry"));


    // Test with the DN of an entry that does not exist.
    entry = ds.getEntry("cn=missing,dc=example,dc=com");

    assertNull(entry);
  }



  /**
   * Provides test coverage for the methods that can be used to process add
   * operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAdd()
         throws Exception
  {
    ds.restoreSnapshot(snapshot);


    // Test the method that takes a DN and array of attributes.
    LDAPResult result = ds.add("ou=test 1,dc=example,dc=com",
         new Attribute("objectClass", "top", "organizationalUnit"),
         new Attribute("ou", "test 1"));

    assertNotNull(result);

    assertEquals(result.getResultCode(), ResultCode.SUCCESS);


    // Test the method that takes a DN and list of attributes.
    result = ds.add("ou=test 2,dc=example,dc=com", Arrays.asList(
         new Attribute("objectClass", "top", "organizationalUnit"),
         new Attribute("ou", "test 2")));

    assertNotNull(result);

    assertEquals(result.getResultCode(), ResultCode.SUCCESS);


    // Test the method that takes an entry.
    result = ds.add(new Entry(
         "dn: ou=test 3,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test 3"));

    assertNotNull(result);

    assertEquals(result.getResultCode(), ResultCode.SUCCESS);


    // Test the method that takes an LDIF representation of the entry.
    result = ds.add(
         "dn: ou=test 4,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test 4");

    assertNotNull(result);

    assertEquals(result.getResultCode(), ResultCode.SUCCESS);


    // Test the method that takes an add request, and include a request control.
    AddRequest addRequest = new AddRequest(
         "dn: ou=test 5,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test 5");
    addRequest.addControl(new AssertionRequestControl("(objectClass=top)"));
    addRequest.addControl(new PostReadRequestControl("*", "+"));

    result = ds.add(addRequest);

    assertNotNull(result);

    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    assertTrue(result.hasResponseControl(
         PostReadResponseControl.POST_READ_RESPONSE_OID));

    final PostReadResponseControl postReadResponse =
         PostReadResponseControl.get(result);
    assertNotNull(postReadResponse);

    assertTrue(postReadResponse.getEntry().hasAttribute("ou"));
    assertTrue(postReadResponse.getEntry().hasAttribute("objectClass"));
    assertTrue(postReadResponse.getEntry().hasAttribute("entryDN"));
    assertTrue(postReadResponse.getEntry().hasAttribute("entryUUID"));


    // Test the method that takes an add request with a request that will not
    // be successful.
    addRequest = new AddRequest(
         "dn: ou=test 6,ou=missing,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test 6");

    try
    {
      ds.add(addRequest);
      fail("Expected an exception when trying to add an entry below a " +
           "missing parent");
    }
    catch (final LDAPException le)
    {
      // This was expected.
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
    }


    // Test the method that takes a read-only add request.
    final ReadOnlyAddRequest readOnlyAddRequest = new AddRequest(
         "dn: ou=test 7,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test 7");

    result = ds.add(readOnlyAddRequest);

    assertNotNull(result);

    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
  }



  /**
   * Provides test coverage for the methods that can be used to process compare
   * operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompare()
         throws Exception
  {
    ds.restoreSnapshot(snapshot);


    // Test the method that takes a DN, attribute type, and assertion value.
    CompareResult compareResult =
         ds.compare("dc=example,dc=com", "objectClass", "top");

    assertNotNull(compareResult);

    assertTrue(compareResult.compareMatched());


    // Test the method that takes a compare request object, including controls.
    final CompareRequest compareRequest =
         new CompareRequest("dc=example,dc=com", "objectClass" , "missing");
    compareRequest.addControl(new AssertionRequestControl(
         "(objectClass=missing)"));

    try
    {
      ds.compare(compareRequest);
      fail("Expected an exception when processing a compare request with a " +
           "non-matching assertion control filter");
    }
    catch (final LDAPException le)
    {
      // This was expected
      assertEquals(le.getResultCode(), ResultCode.ASSERTION_FAILED);
    }


    // Test the method that takes a read-only compare request object with a
    // failed request.
    ReadOnlyCompareRequest readOnlyCompareRequest =
         new CompareRequest("ou=missing,dc=example,dc=com", "objectClass",
              "top");

    try
    {
      ds.compare(readOnlyCompareRequest);
      fail("Expected an exception when trying to process a compare request " +
           "targeting a nonexistent entry.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
    }


    // Test the method that takes a read-only compare request object with a
    // non-matching request.
    readOnlyCompareRequest =
         new CompareRequest("dc=example,dc=com", "objectClass", "missing");

    compareResult = ds.compare(readOnlyCompareRequest);

    assertNotNull(compareResult);

    assertFalse(compareResult.compareMatched());
  }



  /**
   * Provides test coverage for the methods that can be used to process delete
   * operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDelete()
         throws Exception
  {
    ds.restoreSnapshot(snapshot);


    // Test the method that takes a DN.
    LDAPResult deleteResult =
         ds.delete("uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(deleteResult);

    assertEquals(deleteResult.getResultCode(), ResultCode.SUCCESS);


    // Test the method that takes a delete request object, including controls.
    final DeleteRequest deleteRequest =
         new DeleteRequest("ou=People,dc=example,dc=com");
    deleteRequest.addControl(new AssertionRequestControl(
         "(objectClass=top)"));
    deleteRequest.addControl(new PreReadRequestControl("*", "+"));

    deleteResult = ds.delete(deleteRequest);

    assertNotNull(deleteResult);

    assertEquals(deleteResult.getResultCode(), ResultCode.SUCCESS);

    assertTrue(deleteResult.hasResponseControl(
         PreReadResponseControl.PRE_READ_RESPONSE_OID));

    final PreReadResponseControl preReadResponse =
         PreReadResponseControl.get(deleteResult);
    assertNotNull(preReadResponse);

    assertTrue(preReadResponse.getEntry().hasAttribute("ou"));
    assertTrue(preReadResponse.getEntry().hasAttribute("objectClass"));
    assertTrue(preReadResponse.getEntry().hasAttribute("entryDN"));
    assertTrue(preReadResponse.getEntry().hasAttribute("entryUUID"));


    // Test the method that takes a read-only delete request object with a
    // failed request.
    ReadOnlyDeleteRequest readOnlyDeleteRequest =
         new DeleteRequest("ou=missing,dc=example,dc=com");

    try
    {
      ds.delete(readOnlyDeleteRequest);
      fail("Expected an exception when trying to process a delete request " +
           "targeting a nonexistent entry.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
    }


    // Test the method that takes a read-only delete request object with a
    // successful request.
    readOnlyDeleteRequest = new DeleteRequest("dc=example,dc=com");

    deleteResult = ds.delete(readOnlyDeleteRequest);

    assertNotNull(deleteResult);

    assertEquals(deleteResult.getResultCode(), ResultCode.SUCCESS);
  }



  /**
   * Provides test coverage for the methods that can be used to process extended
   * operations.  This isn't really part of LDAPInterface, but it's close enough
   * to be tested here.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtended()
         throws Exception
  {
    ds.restoreSnapshot(snapshot);


    // Test the method that takes just an OID.
    ExtendedResult extendedResult = ds.processExtendedOperation("1.2.3.4");

    assertNotNull(extendedResult);

    assertEquals(extendedResult.getResultCode(),
         ResultCode.UNWILLING_TO_PERFORM);


    // Test the method that takes an OID and value.
    extendedResult = ds.processExtendedOperation("1.2.3.4",
         new ASN1OctetString());

    assertNotNull(extendedResult);

    assertEquals(extendedResult.getResultCode(),
         ResultCode.UNWILLING_TO_PERFORM);


    // Test the method that takes a generic extended request.
    extendedResult =
         ds.processExtendedOperation(new ExtendedRequest("1.2.3.4"));

    assertNotNull(extendedResult);

    assertEquals(extendedResult.getResultCode(),
         ResultCode.UNWILLING_TO_PERFORM);


    // Test the method that takes a specific extended request.
    extendedResult = ds.processExtendedOperation(new WhoAmIExtendedRequest());

    final WhoAmIExtendedResult whoAmIResult =
         new WhoAmIExtendedResult(extendedResult);

    assertNotNull(whoAmIResult);

    assertEquals(whoAmIResult.getResultCode(), ResultCode.SUCCESS);

    assertNotNull(whoAmIResult.getAuthorizationID());
  }



  /**
   * Provides test coverage for the methods that can be used to process modify
   * operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModify()
         throws Exception
  {
    ds.restoreSnapshot(snapshot);


    // Test the method that takes a DN and a single modification.
    LDAPResult modifyResult = ds.modify("dc=example,dc=com",
         new Modification(ModificationType.REPLACE, "description", "mod 1"));

    assertNotNull(modifyResult);

    assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);


    // Test the method that takes a DN and an array of modifications.
    modifyResult = ds.modify("dc=example,dc=com",
         new Modification(ModificationType.DELETE, "description", "mod 1"),
         new Modification(ModificationType.ADD, "description", "mod 2"));

    assertNotNull(modifyResult);

    assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);


    // Test the method that takes a DN and a list of modifications.
    modifyResult = ds.modify("dc=example,dc=com", Arrays.asList(
         new Modification(ModificationType.DELETE, "description", "mod 2"),
         new Modification(ModificationType.ADD, "description", "mod 3")));

    assertNotNull(modifyResult);

    assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);


    // Test the method that takes an LDIF representation of the modification.
    modifyResult = ds.modify(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: mod 4");

    assertNotNull(modifyResult);

    assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);


    // Test the method that takes a modify request, with controls.
    final ModifyRequest modifyRequest = new ModifyRequest(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: mod 5");
    modifyRequest.addControl(new PreReadRequestControl("*", "+"));
    modifyRequest.addControl(new PostReadRequestControl("*", "+"));

    modifyResult = ds.modify(modifyRequest);

    assertNotNull(modifyResult);

    assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);

    assertTrue(modifyResult.hasResponseControl(
         PreReadResponseControl.PRE_READ_RESPONSE_OID));

    final PreReadResponseControl preReadResponse =
         PreReadResponseControl.get(modifyResult);
    assertNotNull(preReadResponse);

    assertTrue(preReadResponse.getEntry().hasAttributeValue("description",
         "mod 4"));

    assertTrue(modifyResult.hasResponseControl(
         PostReadResponseControl.POST_READ_RESPONSE_OID));

    final PostReadResponseControl postReadResponse =
         PostReadResponseControl.get(modifyResult);
    assertNotNull(postReadResponse);

    assertTrue(postReadResponse.getEntry().hasAttributeValue("description",
         "mod 5"));


    // Test the method that takes a read-only modify request, with controls.
    final ReadOnlyModifyRequest readOnlyModifyRequest = new ModifyRequest(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: mod 6");

    modifyResult = ds.modify(readOnlyModifyRequest);

    assertNotNull(modifyResult);

    assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);
  }



  /**
   * Provides test coverage for the methods that can be used to process modify
   * DN operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDN()
         throws Exception
  {
    ds.restoreSnapshot(snapshot);

    ds.add(
         "dn: ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Users");


    // Test the method that takes a DN, new RDN, and deleteOldRDN flag.
    LDAPResult modifyDNResult = ds.modifyDN(
         "uid=test.user,ou=People,dc=example,dc=com", "uid=test.2", true);

    assertNotNull(modifyDNResult);

    assertEquals(modifyDNResult.getResultCode(), ResultCode.SUCCESS);


    // Test the method that takes a DN, new RDN, deleteOldRDN flag and a new
    // superior DN.
    modifyDNResult = ds.modifyDN("uid=test.2,ou=People,dc=example,dc=com",
         "uid=test.2", false, "ou=Users,dc=example,dc=com");

    assertNotNull(modifyDNResult);

    assertEquals(modifyDNResult.getResultCode(), ResultCode.SUCCESS);


    // Test the method that takes a modify DN request, with controls.
    final ModifyDNRequest modifyDNRequest = new ModifyDNRequest(
         "uid=test.2,ou=Users,dc=example,dc=com", "uid=test.3", true);
    modifyDNRequest.addControl(new PreReadRequestControl("*", "+"));
    modifyDNRequest.addControl(new PostReadRequestControl("*", "+"));

    modifyDNResult = ds.modifyDN(modifyDNRequest);

    assertNotNull(modifyDNResult);

    assertEquals(modifyDNResult.getResultCode(), ResultCode.SUCCESS);

    assertTrue(modifyDNResult.hasResponseControl(
         PreReadResponseControl.PRE_READ_RESPONSE_OID));

    final PreReadResponseControl preReadResponse =
         PreReadResponseControl.get(modifyDNResult);
    assertNotNull(preReadResponse);

    assertTrue(preReadResponse.getEntry().hasAttributeValue("uid", "test.2"));

    assertTrue(modifyDNResult.hasResponseControl(
         PostReadResponseControl.POST_READ_RESPONSE_OID));

    final PostReadResponseControl postReadResponse =
         PostReadResponseControl.get(modifyDNResult);
    assertNotNull(postReadResponse);

    assertTrue(postReadResponse.getEntry().hasAttributeValue("uid", "test.3"));


    // Test the method that takes a read-only modify DN request.
    final ReadOnlyModifyDNRequest readOnlyModifyDNRequest = new ModifyDNRequest(
         "uid=test.3,ou=Users,dc=example,dc=com", "uid=test.4", true);

    modifyDNResult = ds.modifyDN(readOnlyModifyDNRequest);

    assertNotNull(modifyDNResult);

    assertEquals(modifyDNResult.getResultCode(), ResultCode.SUCCESS);
  }



  /**
   * Provides test coverage for the methods that can be used to process search
   * operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearch()
         throws Exception
  {
    ds.restoreSnapshot(snapshot);

    ds.add(
         "dn: ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ou: Users",
         "ref: ldap://directory.example.com/ou=Users,dc=example,dc=com");


    // Test the method that takes a base, scope, string filter, and attributes,
    // with no explicitly-requested attributes.
    SearchResult searchResult = ds.search("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");

    assertNotNull(searchResult);

    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 3);

    assertNotNull(searchResult.getSearchEntries());

    assertEquals(searchResult.getSearchEntries().size(), 3);

    for (final SearchResultEntry e : searchResult.getSearchEntries())
    {
      assertTrue(e.hasAttribute("objectClass"));
      assertFalse(e.hasAttribute("entryDN"));
      assertFalse(e.hasAttribute("entryUUID"));
      assertFalse(e.hasAttribute("creatorsName"));
      assertFalse(e.hasAttribute("createTimestamp"));
      assertFalse(e.hasAttribute("modifiersName"));
      assertFalse(e.hasAttribute("modifyTimestamp"));
      assertFalse(e.hasAttribute("subschemaSubentry"));
    }

    assertEquals(searchResult.getReferenceCount(), 1);

    assertNotNull(searchResult.getSearchReferences());

    assertEquals(searchResult.getSearchReferences().size(), 1);


    // Test the method that takes a base, scope, filter object, and attributes,
    // with all user and operational attributes.
    searchResult = ds.search("dc=example,dc=com", SearchScope.SUB,
         Filter.createPresenceFilter("objectClass"), "*", "+");

    assertNotNull(searchResult);

    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 3);

    assertNotNull(searchResult.getSearchEntries());

    assertEquals(searchResult.getSearchEntries().size(), 3);

    for (final SearchResultEntry e : searchResult.getSearchEntries())
    {
      assertTrue(e.hasAttribute("objectClass"));
      assertTrue(e.hasAttribute("entryDN"));
      assertTrue(e.hasAttribute("entryUUID"));
      assertTrue(e.hasAttribute("creatorsName"));
      assertTrue(e.hasAttribute("createTimestamp"));
      assertTrue(e.hasAttribute("modifiersName"));
      assertTrue(e.hasAttribute("modifyTimestamp"));
      assertTrue(e.hasAttribute("subschemaSubentry"));
    }

    assertEquals(searchResult.getReferenceCount(), 1);

    assertNotNull(searchResult.getSearchReferences());

    assertEquals(searchResult.getSearchReferences().size(), 1);


    // Test the method that takes a search result listener, base, scope,
    // string filter, and attributes.
    final TestSearchResultListener searchListener =
         new TestSearchResultListener();

    searchResult = ds.search(searchListener, "dc=example,dc=com",
         SearchScope.SUB, "(objectClass=*)");

    assertNotNull(searchResult);

    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 3);

    assertNull(searchResult.getSearchEntries());

    assertEquals(searchResult.getReferenceCount(), 1);

    assertNull(searchResult.getSearchReferences());


    // Test the method that takes a search result listener, base, scope,
    // object filter, and attributes.
    searchResult = ds.search(searchListener, "dc=example,dc=com",
         SearchScope.SUB, Filter.createPresenceFilter("objectClass"));

    assertNotNull(searchResult);

    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 3);

    assertNull(searchResult.getSearchEntries());

    assertEquals(searchResult.getReferenceCount(), 1);

    assertNull(searchResult.getSearchReferences());


    // Test the method that takes all search elements with a string filter and
    // no listener.
    searchResult = ds.search("dc=example,dc=com", SearchScope.SUB,
         DereferencePolicy.NEVER, 0, 0, false, "(objectClass=*)", "objectClass",
         "entryUUID");

    assertNotNull(searchResult);

    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 3);

    assertNotNull(searchResult.getSearchEntries());

    assertEquals(searchResult.getSearchEntries().size(), 3);

    for (final SearchResultEntry e : searchResult.getSearchEntries())
    {
      assertTrue(e.hasAttribute("objectClass"));
      assertFalse(e.hasAttribute("entryDN"));
      assertTrue(e.hasAttribute("entryUUID"));
      assertFalse(e.hasAttribute("creatorsName"));
      assertFalse(e.hasAttribute("createTimestamp"));
      assertFalse(e.hasAttribute("modifiersName"));
      assertFalse(e.hasAttribute("modifyTimestamp"));
      assertFalse(e.hasAttribute("subschemaSubentry"));
    }

    assertEquals(searchResult.getReferenceCount(), 1);

    assertNotNull(searchResult.getSearchReferences());

    assertEquals(searchResult.getSearchReferences().size(), 1);


    // Test the method that takes all search elements with a filter object and
    // no listener.
    searchResult = ds.search("dc=example,dc=com", SearchScope.SUB,
         DereferencePolicy.NEVER, 0, 0, false,
         Filter.createPresenceFilter("objectClass"), "entryUUID");

    assertNotNull(searchResult);

    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 3);

    assertNotNull(searchResult.getSearchEntries());

    assertEquals(searchResult.getSearchEntries().size(), 3);

    for (final SearchResultEntry e : searchResult.getSearchEntries())
    {
      assertFalse(e.hasAttribute("objectClass"));
      assertFalse(e.hasAttribute("entryDN"));
      assertTrue(e.hasAttribute("entryUUID"));
      assertFalse(e.hasAttribute("creatorsName"));
      assertFalse(e.hasAttribute("createTimestamp"));
      assertFalse(e.hasAttribute("modifiersName"));
      assertFalse(e.hasAttribute("modifyTimestamp"));
      assertFalse(e.hasAttribute("subschemaSubentry"));
    }

    assertEquals(searchResult.getReferenceCount(), 1);

    assertNotNull(searchResult.getSearchReferences());

    assertEquals(searchResult.getSearchReferences().size(), 1);


    // Test the method that takes all search elements with a string filter and a
    // search listener.
    searchResult = ds.search(searchListener, "dc=example,dc=com",
         SearchScope.SUB, DereferencePolicy.NEVER, 0, 0, false,
         "(objectClass=*)");

    assertNotNull(searchResult);

    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 3);

    assertNull(searchResult.getSearchEntries());

    assertEquals(searchResult.getReferenceCount(), 1);

    assertNull(searchResult.getSearchReferences());


    // Test the method that takes all search elements with a filter object and a
    // search listener.
    searchResult = ds.search(searchListener, "dc=example,dc=com",
         SearchScope.SUB, DereferencePolicy.NEVER, 0, 0, false,
         Filter.createPresenceFilter("objectClass"));

    assertNotNull(searchResult);

    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 3);

    assertNull(searchResult.getSearchEntries());

    assertEquals(searchResult.getReferenceCount(), 1);

    assertNull(searchResult.getSearchReferences());


    // Test the method that takes a search request, including controls.
    final SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, "(objectClass=*)", "1.1");
    searchRequest.addControl(new ManageDsaITRequestControl());

    searchResult = ds.search(searchRequest);

    assertNotNull(searchResult);

    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 4);

    assertNotNull(searchResult.getSearchEntries());

    assertEquals(searchResult.getSearchEntries().size(), 4);

    for (final SearchResultEntry e : searchResult.getSearchEntries())
    {
      assertFalse(e.hasAttribute("objectClass"));
      assertFalse(e.hasAttribute("entryDN"));
      assertFalse(e.hasAttribute("entryUUID"));
      assertFalse(e.hasAttribute("creatorsName"));
      assertFalse(e.hasAttribute("createTimestamp"));
      assertFalse(e.hasAttribute("modifiersName"));
      assertFalse(e.hasAttribute("modifyTimestamp"));
      assertFalse(e.hasAttribute("subschemaSubentry"));
    }

    assertEquals(searchResult.getReferenceCount(), 0);

    assertNotNull(searchResult.getSearchReferences());

    assertEquals(searchResult.getSearchReferences().size(), 0);


    // Test the method that takes a read-only search request.
    final ReadOnlySearchRequest readOnlySearchRequest = new SearchRequest(
         searchListener, "dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");

    searchResult = ds.search(readOnlySearchRequest);

    assertNotNull(searchResult);

    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 3);

    assertNull(searchResult.getSearchEntries());

    assertEquals(searchResult.getReferenceCount(), 1);

    assertNull(searchResult.getSearchReferences());
  }



  /**
   * Provides test coverage for the methods that can be used to process search
   * operations that are only expected to return a single entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchForEntry()
         throws Exception
  {
    ds.restoreSnapshot(snapshot);


    // Test the method that takes a base, scope, string filter, and attributes,
    // with no explicitly-requested attributes.
    SearchResultEntry entry = ds.searchForEntry("dc=example,dc=com",
         SearchScope.SUB, "(uid=test.user)");

    assertNotNull(entry);

    assertTrue(entry.hasAttribute("objectClass"));
    assertTrue(entry.hasAttribute("uid"));
    assertTrue(entry.hasAttribute("givenName"));
    assertTrue(entry.hasAttribute("sn"));
    assertTrue(entry.hasAttribute("cn"));
    assertFalse(entry.hasAttribute("entryDN"));
    assertFalse(entry.hasAttribute("entryUUID"));
    assertFalse(entry.hasAttribute("creatorsName"));
    assertFalse(entry.hasAttribute("createTimestamp"));
    assertFalse(entry.hasAttribute("modifiersName"));
    assertFalse(entry.hasAttribute("modifyTimestamp"));
    assertFalse(entry.hasAttribute("subschemaSubentry"));


    // Test the method that takes a base, scope, string filter, and attributes,
    // with all user and operational attributes.
    entry = ds.searchForEntry("dc=example,dc=com", SearchScope.SUB,
         Filter.createEqualityFilter("uid", "test.user"), "*", "+");

    assertNotNull(entry);

    assertTrue(entry.hasAttribute("objectClass"));
    assertTrue(entry.hasAttribute("uid"));
    assertTrue(entry.hasAttribute("givenName"));
    assertTrue(entry.hasAttribute("sn"));
    assertTrue(entry.hasAttribute("cn"));
    assertTrue(entry.hasAttribute("entryDN"));
    assertTrue(entry.hasAttribute("entryUUID"));
    assertTrue(entry.hasAttribute("creatorsName"));
    assertTrue(entry.hasAttribute("createTimestamp"));
    assertTrue(entry.hasAttribute("modifiersName"));
    assertTrue(entry.hasAttribute("modifyTimestamp"));
    assertTrue(entry.hasAttribute("subschemaSubentry"));


    // Test the method that takes all elements and a string filter with a
    // filter that doesn't match any entry.
    entry = ds.searchForEntry("dc=example,dc=com", SearchScope.SUB,
         DereferencePolicy.NEVER, 0, false, "(uid=does.not.match)");

    assertNull(entry);


    // Test the method that takes all elements and a filter object with a base
    // DN that targets a nonexistent entry.
    entry = ds.searchForEntry("cn=missing,dc=example,dc=com", SearchScope.SUB,
         DereferencePolicy.NEVER, 0, false,
         Filter.createPresenceFilter("objectClass"));

    assertNull(entry);


    // Test the method that takes a search request with criteria that matches a
    // single entry.
    entry = ds.searchForEntry(new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, "(uid=test.user)", "objectClass", "cn", "entryUUID"));

    assertNotNull(entry);

    assertTrue(entry.hasAttribute("objectClass"));
    assertFalse(entry.hasAttribute("uid"));
    assertFalse(entry.hasAttribute("givenName"));
    assertFalse(entry.hasAttribute("sn"));
    assertTrue(entry.hasAttribute("cn"));
    assertFalse(entry.hasAttribute("entryDN"));
    assertTrue(entry.hasAttribute("entryUUID"));
    assertFalse(entry.hasAttribute("creatorsName"));
    assertFalse(entry.hasAttribute("createTimestamp"));
    assertFalse(entry.hasAttribute("modifiersName"));
    assertFalse(entry.hasAttribute("modifyTimestamp"));
    assertFalse(entry.hasAttribute("subschemaSubentry"));


    // Test the method that takes a search request with criteria that matches
    // multiple entries.
    try
    {
      final SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
           SearchScope.SUB, "(objectClass=*)");
      searchRequest.addControl(new ManageDsaITRequestControl());

      ds.searchForEntry(searchRequest);
      fail("Expected an exception from searchForEntry with criteria that " +
           "matches multiple entries");
    }
    catch (final LDAPSearchException lse)
    {
      // This was expected.
      assertEquals(lse.getResultCode(), ResultCode.SIZE_LIMIT_EXCEEDED);
    }


    // Test the method that takes a read-only search request that matches only a
    // single entry, including a search result listener.
    final TestSearchResultListener searchListener =
         new TestSearchResultListener();

    final ReadOnlySearchRequest readOnlySearchRequest = new SearchRequest(
         searchListener, "dc=example,dc=com", SearchScope.SUB,
         "(uid=test.user)", "1.1");

    entry = ds.searchForEntry(readOnlySearchRequest);

    assertNotNull(entry);

    assertFalse(entry.hasAttribute("objectClass"));
    assertFalse(entry.hasAttribute("uid"));
    assertFalse(entry.hasAttribute("givenName"));
    assertFalse(entry.hasAttribute("sn"));
    assertFalse(entry.hasAttribute("cn"));
    assertFalse(entry.hasAttribute("entryDN"));
    assertFalse(entry.hasAttribute("entryDN"));
    assertFalse(entry.hasAttribute("creatorsName"));
    assertFalse(entry.hasAttribute("createTimestamp"));
    assertFalse(entry.hasAttribute("modifiersName"));
    assertFalse(entry.hasAttribute("modifyTimestamp"));
    assertFalse(entry.hasAttribute("subschemaSubentry"));
  }
}
