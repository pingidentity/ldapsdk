/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.CompareResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;



/**
 * Provides a set of test cases for the start interactive transaction extended
 * request.
 */
@SuppressWarnings("deprecation")
public class StartInteractiveTransactionExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    StartInteractiveTransactionExtendedRequest r =
         new StartInteractiveTransactionExtendedRequest();
    r = new StartInteractiveTransactionExtendedRequest(r.duplicate());

    assertNotNull(r);

    assertNull(r.getBaseDN());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.3");

    assertNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the second constructor with a base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2WithBaseDN()
         throws Exception
  {
    StartInteractiveTransactionExtendedRequest r =
         new StartInteractiveTransactionExtendedRequest("dc=example,dc=com");
    r = new StartInteractiveTransactionExtendedRequest(r.duplicate());

    assertNotNull(r);

    assertNotNull(r.getBaseDN());
    assertEquals(new DN(r.getBaseDN()), new DN("dc=example,dc=com"));

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.3");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the second constructor without a base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NoBaseDN()
         throws Exception
  {
    StartInteractiveTransactionExtendedRequest r =
         new StartInteractiveTransactionExtendedRequest((String) null);
    r = new StartInteractiveTransactionExtendedRequest(r.duplicate());

    assertNotNull(r);

    assertNull(r.getBaseDN());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.3");

    assertNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the third constructor with a base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3WithBaseDN()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString())
    };

    StartInteractiveTransactionExtendedRequest r =
         new StartInteractiveTransactionExtendedRequest("dc=example,dc=com",
                                                        controls);
    r = new StartInteractiveTransactionExtendedRequest(r.duplicate());

    assertNotNull(r);

    assertNotNull(r.getBaseDN());
    assertEquals(new DN(r.getBaseDN()), new DN("dc=example,dc=com"));

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.3");

    assertNotNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the third constructor without a base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NoBaseDN()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString())
    };

    StartInteractiveTransactionExtendedRequest r =
         new StartInteractiveTransactionExtendedRequest(null, controls);
    r = new StartInteractiveTransactionExtendedRequest(r.duplicate());

    assertNotNull(r);

    assertNull(r.getBaseDN());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.3");

    assertNull(r.getValue());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the fourth constructor with a value that is not a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor4ValueNotSequence()
         throws Exception
  {
    ExtendedRequest r = new ExtendedRequest("1.3.6.1.4.1.30221.2.6.3",
                                            new ASN1OctetString("x"));
    new StartInteractiveTransactionExtendedRequest(r);
  }



  /**
   * Tests the fourth constructor with a value sequence containing an invalid
   * element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor4ValueSequenceInvalidType()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1OctetString((byte) 0x01, "Invalid BER type")
    };

    ExtendedRequest r = new ExtendedRequest("1.3.6.1.4.1.30221.2.6.3",
         new ASN1OctetString(new ASN1Sequence(elements).encode()));
    new StartInteractiveTransactionExtendedRequest(r);
  }



  /**
   * Tests the process of creating a transaction, including multiple operations
   * as part of that transaction, and then committing it.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCommitTransaction()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    RootDSE rootDSE = conn.getRootDSE();
    if ((rootDSE == null) ||
        (! rootDSE.supportsExtendedOperation(
                StartInteractiveTransactionExtendedRequest.
                     START_INTERACTIVE_TRANSACTION_REQUEST_OID)))
    {
      conn.close();
      return;
    }


    // Start the interactive transaction.
    StartInteractiveTransactionExtendedResult startTxnResult =
         (StartInteractiveTransactionExtendedResult)
         conn.processExtendedOperation(
              new StartInteractiveTransactionExtendedRequest(getTestBaseDN()));

    assertEquals(startTxnResult.getResultCode(), ResultCode.SUCCESS);

    ASN1OctetString txnID = startTxnResult.getTransactionID();
    assertNotNull(txnID);

    assertNotNull(startTxnResult.toString());

    Control[] controls =
    {
      new com.unboundid.ldap.sdk.unboundidds.controls.
           InteractiveTransactionSpecificationRequestControl(txnID, true, true)
    };


    // Add the base entry.
    AddRequest addRequest =
         new AddRequest(getTestBaseDN(), getBaseEntryAttributes(), controls);
    LDAPResult addResult = conn.add(addRequest);
    assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);

    Control c = addResult.getResponseControl(com.unboundid.ldap.sdk.unboundidds.
         controls.InteractiveTransactionSpecificationResponseControl.
              INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID);
    assertNotNull(c);
    assertTrue(c instanceof com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl);
    com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl itsrc =
         (com.unboundid.ldap.sdk.unboundidds.controls.
              InteractiveTransactionSpecificationResponseControl) c;
    assertTrue(itsrc.transactionValid());


    // Ensure that we can retrieve the base entry as part of the transaction.
    // Note that the search needs to be indexed, since unindexed searches won't
    // be allowed as part of a transaction.
    SearchRequest searchRequest = new SearchRequest(getTestBaseDN(),
         SearchScope.SUB, "(objectClass=top)");
    searchRequest.setControls(controls);
    SearchResult searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1,
                 searchResult.getSearchEntries().toString());

    c = searchResult.getResponseControl(com.unboundid.ldap.sdk.unboundidds.
         controls.InteractiveTransactionSpecificationResponseControl.
              INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID);
    assertNotNull(c);
    assertTrue(c instanceof com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl);
    itsrc = (com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl) c;
    assertTrue(itsrc.transactionValid());


    // Add an "ou=People" entry.
    addRequest = new AddRequest(
         "dn: ou=People," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: foo");
    addRequest.setControls(controls);
    addResult = conn.add(addRequest);
    assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);

    c = addResult.getResponseControl(com.unboundid.ldap.sdk.unboundidds.
         controls.InteractiveTransactionSpecificationResponseControl.
              INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID);
    assertNotNull(c);
    assertTrue(c instanceof com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl);
    itsrc = (com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl) c;
    assertTrue(itsrc.transactionValid());


    // Ensure that we can now retrieve the both entries as part of the
    // transaction.
    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 2,
                 searchResult.getSearchEntries().toString());

    c = searchResult.getResponseControl(com.unboundid.ldap.sdk.unboundidds.
         controls.InteractiveTransactionSpecificationResponseControl.
              INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID);
    assertNotNull(c);
    assertTrue(c instanceof com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl);
    itsrc = (com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl) c;
    assertTrue(itsrc.transactionValid());


    // Perform a compare against the entry.
    CompareRequest compareRequest = new CompareRequest(
         "ou=People," + getTestBaseDN(), "description", "foo", controls);
    CompareResult compareResult = conn.compare(compareRequest);
    assertTrue(compareResult.compareMatched());

    c = compareResult.getResponseControl(com.unboundid.ldap.sdk.unboundidds.
         controls.InteractiveTransactionSpecificationResponseControl.
              INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID);
    assertNotNull(c);
    assertTrue(c instanceof com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl);
    itsrc = (com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl) c;
    assertTrue(itsrc.transactionValid());


    // Modify the entry.
    ModifyRequest modifyRequest = new ModifyRequest(
         "dn: ou=People," + getTestBaseDN(),
         "changetype: modify",
         "replace: description",
         "description: bar");
    modifyRequest.setControls(controls);
    LDAPResult modifyResult = conn.modify(modifyRequest);
    assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);

    c = modifyResult.getResponseControl(com.unboundid.ldap.sdk.unboundidds.
         controls.InteractiveTransactionSpecificationResponseControl.
              INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID);
    assertNotNull(c);
    assertTrue(c instanceof com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl);
    itsrc = (com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl) c;
    assertTrue(itsrc.transactionValid());


    // Perform another compare against the entry to verify the change.
    compareRequest = new CompareRequest(
         "ou=People," + getTestBaseDN(), "description", "bar", controls);
    compareResult = conn.compare(compareRequest);
    assertTrue(compareResult.compareMatched());

    c = compareResult.getResponseControl(com.unboundid.ldap.sdk.unboundidds.
         controls.InteractiveTransactionSpecificationResponseControl.
              INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID);
    assertNotNull(c);
    assertTrue(c instanceof com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl);
    itsrc = (com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl) c;
    assertTrue(itsrc.transactionValid());


    // Rename the target entry.
    ModifyDNRequest modifyDNRequest = new ModifyDNRequest(
         "ou=People," + getTestBaseDN(), "ou=Users", true, controls);
    LDAPResult modifyDNResult = conn.modifyDN(modifyDNRequest);
    assertEquals(modifyDNResult.getResultCode(), ResultCode.SUCCESS);

    c = modifyDNResult.getResponseControl(com.unboundid.ldap.sdk.unboundidds.
         controls.InteractiveTransactionSpecificationResponseControl.
              INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID);
    assertNotNull(c);
    assertTrue(c instanceof com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl);
    itsrc = (com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl) c;
    assertTrue(itsrc.transactionValid());


    // Perform a search below the base entry and verify that we still get two
    // entries returned.
    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 2,
                 searchResult.getSearchEntries().toString());

    c = searchResult.getResponseControl(com.unboundid.ldap.sdk.unboundidds.
         controls.InteractiveTransactionSpecificationResponseControl.
              INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID);
    assertNotNull(c);
    assertTrue(c instanceof com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl);
    itsrc = (com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl) c;
    assertTrue(itsrc.transactionValid());


    // Delete the "ou=Users" entry.
    DeleteRequest deleteRequest = new DeleteRequest(
         "ou=Users," + getTestBaseDN(), controls);
    LDAPResult deleteResult = conn.delete(deleteRequest);
    assertEquals(deleteResult.getResultCode(), ResultCode.SUCCESS);

    c = deleteResult.getResponseControl(com.unboundid.ldap.sdk.unboundidds.
         controls.InteractiveTransactionSpecificationResponseControl.
              INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID);
    assertNotNull(c);
    assertTrue(c instanceof com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl);
    itsrc = (com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl) c;
    assertTrue(itsrc.transactionValid());


    // Commit the transaction.
    ExtendedResult endTxnResult =
         conn.processExtendedOperation(
              new EndInteractiveTransactionExtendedRequest(txnID, true));
    assertEquals(endTxnResult.getResultCode(), ResultCode.SUCCESS);


    // Re-perform the search below the base entry and verify that only a single
    // entry is returned.
    searchRequest.clearControls();
    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);


    // Delete the base entry and close the connection.
    conn.delete(getTestBaseDN());
    conn.close();
  }



  /**
   * Tests the process of creating a transaction, including multiple operations
   * as part of that transaction, and then aborting it.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAbortTransaction()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    RootDSE rootDSE = conn.getRootDSE();
    if ((rootDSE == null) ||
        (! rootDSE.supportsExtendedOperation(
                StartInteractiveTransactionExtendedRequest.
                     START_INTERACTIVE_TRANSACTION_REQUEST_OID)))
    {
      conn.close();
      return;
    }


    // Start the interactive transaction.
    StartInteractiveTransactionExtendedResult startTxnResult =
         (StartInteractiveTransactionExtendedResult)
         conn.processExtendedOperation(
              new StartInteractiveTransactionExtendedRequest(getTestBaseDN()));

    assertEquals(startTxnResult.getResultCode(), ResultCode.SUCCESS);

    ASN1OctetString txnID = startTxnResult.getTransactionID();
    assertNotNull(txnID);

    assertNotNull(startTxnResult.toString());

    Control[] controls =
    {
      new com.unboundid.ldap.sdk.unboundidds.controls.
           InteractiveTransactionSpecificationRequestControl(txnID, true, true)
    };


    // Add the base entry.
    AddRequest addRequest =
         new AddRequest(getTestBaseDN(), getBaseEntryAttributes(), controls);
    LDAPResult addResult = conn.add(addRequest);
    assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);

    Control c = addResult.getResponseControl(com.unboundid.ldap.sdk.unboundidds.
         controls.InteractiveTransactionSpecificationResponseControl.
              INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID);
    assertNotNull(c);
    assertTrue(c instanceof com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl);
    com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl itsrc =
         (com.unboundid.ldap.sdk.unboundidds.controls.
              InteractiveTransactionSpecificationResponseControl) c;
    assertTrue(itsrc.transactionValid());


    // Ensure that we can retrieve the base entry as part of the transaction.
    // Note that the search needs to be indexed, since unindexed searches won't
    // be allowed as part of a transaction.
    SearchRequest searchRequest = new SearchRequest(getTestBaseDN(),
         SearchScope.SUB, "(objectClass=top)");
    searchRequest.setControls(controls);
    SearchResult searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1,
                 searchResult.getSearchEntries().toString());

    c = searchResult.getResponseControl(com.unboundid.ldap.sdk.unboundidds.
         controls.InteractiveTransactionSpecificationResponseControl.
              INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID);
    assertNotNull(c);
    assertTrue(c instanceof com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl);
    itsrc = (com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl) c;
    assertTrue(itsrc.transactionValid());


    // Add an "ou=People" entry.
    addRequest = new AddRequest(
         "dn: ou=People," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: foo");
    addRequest.setControls(controls);
    addResult = conn.add(addRequest);
    assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);

    c = addResult.getResponseControl(com.unboundid.ldap.sdk.unboundidds.
         controls.InteractiveTransactionSpecificationResponseControl.
              INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID);
    assertNotNull(c);
    assertTrue(c instanceof com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl);
    itsrc = (com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl) c;
    assertTrue(itsrc.transactionValid());


    // Ensure that we can now retrieve the both entries as part of the
    // transaction.
    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 2,
                 searchResult.getSearchEntries().toString());

    c = searchResult.getResponseControl(com.unboundid.ldap.sdk.unboundidds.
         controls.InteractiveTransactionSpecificationResponseControl.
              INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID);
    assertNotNull(c);
    assertTrue(c instanceof com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl);
    itsrc = (com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl) c;
    assertTrue(itsrc.transactionValid());


    // Perform a compare against the entry.
    CompareRequest compareRequest = new CompareRequest(
         "ou=People," + getTestBaseDN(), "description", "foo", controls);
    CompareResult compareResult = conn.compare(compareRequest);
    assertTrue(compareResult.compareMatched());

    c = compareResult.getResponseControl(com.unboundid.ldap.sdk.unboundidds.
         controls.InteractiveTransactionSpecificationResponseControl.
              INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID);
    assertNotNull(c);
    assertTrue(c instanceof com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl);
    itsrc = (com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl) c;
    assertTrue(itsrc.transactionValid());


    // Modify the entry.
    ModifyRequest modifyRequest = new ModifyRequest(
         "dn: ou=People," + getTestBaseDN(),
         "changetype: modify",
         "replace: description",
         "description: bar");
    modifyRequest.setControls(controls);
    LDAPResult modifyResult = conn.modify(modifyRequest);
    assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);

    c = modifyResult.getResponseControl(com.unboundid.ldap.sdk.unboundidds.
         controls.InteractiveTransactionSpecificationResponseControl.
              INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID);
    assertNotNull(c);
    assertTrue(c instanceof com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl);
    itsrc = (com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl) c;
    assertTrue(itsrc.transactionValid());


    // Perform another compare against the entry to verify the change.
    compareRequest = new CompareRequest(
         "ou=People," + getTestBaseDN(), "description", "bar", controls);
    compareResult = conn.compare(compareRequest);
    assertTrue(compareResult.compareMatched());

    c = compareResult.getResponseControl(com.unboundid.ldap.sdk.unboundidds.
         controls.InteractiveTransactionSpecificationResponseControl.
              INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID);
    assertNotNull(c);
    assertTrue(c instanceof com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl);
    itsrc = (com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl) c;
    assertTrue(itsrc.transactionValid());


    // Rename the target entry.
    ModifyDNRequest modifyDNRequest = new ModifyDNRequest(
         "ou=People," + getTestBaseDN(), "ou=Users", true, controls);
    LDAPResult modifyDNResult = conn.modifyDN(modifyDNRequest);
    assertEquals(modifyDNResult.getResultCode(), ResultCode.SUCCESS);

    c = modifyDNResult.getResponseControl(com.unboundid.ldap.sdk.unboundidds.
         controls.InteractiveTransactionSpecificationResponseControl.
              INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID);
    assertNotNull(c);
    assertTrue(c instanceof com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl);
    itsrc = (com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl) c;
    assertTrue(itsrc.transactionValid());


    // Perform a search below the base entry and verify that we still get two
    // entries returned.
    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 2,
                 searchResult.getSearchEntries().toString());

    c = searchResult.getResponseControl(com.unboundid.ldap.sdk.unboundidds.
         controls.InteractiveTransactionSpecificationResponseControl.
              INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID);
    assertNotNull(c);
    assertTrue(c instanceof com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl);
    itsrc = (com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl) c;
    assertTrue(itsrc.transactionValid());


    // Delete the "ou=Users" entry.
    DeleteRequest deleteRequest = new DeleteRequest(
         "ou=Users," + getTestBaseDN(), controls);
    LDAPResult deleteResult = conn.delete(deleteRequest);
    assertEquals(deleteResult.getResultCode(), ResultCode.SUCCESS);

    c = deleteResult.getResponseControl(com.unboundid.ldap.sdk.unboundidds.
         controls.InteractiveTransactionSpecificationResponseControl.
              INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID);
    assertNotNull(c);
    assertTrue(c instanceof com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl);
    itsrc = (com.unboundid.ldap.sdk.unboundidds.controls.
         InteractiveTransactionSpecificationResponseControl) c;
    assertTrue(itsrc.transactionValid());


    // Abort the transaction.
    ExtendedResult endTxnResult =
         conn.processExtendedOperation(
              new EndInteractiveTransactionExtendedRequest(txnID, false));
    assertEquals(endTxnResult.getResultCode(),
                 ResultCode.INTERACTIVE_TRANSACTION_ABORTED);


    // Verify that the base entry does not exist.
    try
    {
      assertNull(conn.getEntry(getTestBaseDN()));
    }
    finally
    {
      conn.close();
    }
  }
}
