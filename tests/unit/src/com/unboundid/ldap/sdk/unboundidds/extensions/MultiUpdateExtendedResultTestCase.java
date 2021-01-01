/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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



import java.util.ArrayList;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedResult;
import com.unboundid.util.ObjectPair;



/**
 * This class provides a set of test cases for the multi-update extended result.
 */
public final class MultiUpdateExtendedResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when creating a success result that contains multiple
   * operation results.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessWithResults()
         throws Exception
  {
    final Control[] opControls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true)
    };

    final ArrayList<ObjectPair<OperationType,LDAPResult>> results =
         new ArrayList<ObjectPair<OperationType,LDAPResult>>(5);
    results.add(new ObjectPair<OperationType,LDAPResult>(
         OperationType.ADD,
         new LDAPResult(-1, ResultCode.ADMIN_LIMIT_EXCEEDED, null, null, null,
              opControls)));
    results.add(new ObjectPair<OperationType,LDAPResult>(
         OperationType.DELETE,
         new LDAPResult(-1, ResultCode.ASSERTION_FAILED)));
    results.add(new ObjectPair<OperationType,LDAPResult>(
         OperationType.EXTENDED,
         new PasswordModifyExtendedResult(-1, ResultCode.INVALID_CREDENTIALS,
              null, null, null, null, null)));
    results.add(new ObjectPair<OperationType,LDAPResult>(
         OperationType.MODIFY,
         new LDAPResult(-1, ResultCode.ATTRIBUTE_OR_VALUE_EXISTS)));
    results.add(new ObjectPair<OperationType,LDAPResult>(
         OperationType.MODIFY_DN,
         new LDAPResult(-1, ResultCode.UNWILLING_TO_PERFORM)));

    final Control[] controls =
    {
      new Control("1.2.3.6"),
      new Control("1.2.3.7", true)
    };

    MultiUpdateExtendedResult r = new MultiUpdateExtendedResult(1,
         ResultCode.SUCCESS, null, null, null,
         MultiUpdateChangesApplied.PARTIAL, results, controls);

    r = new MultiUpdateExtendedResult(r);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getChangesApplied());
    assertEquals(r.getChangesApplied(), MultiUpdateChangesApplied.PARTIAL);

    assertNotNull(r.getResults());
    assertEquals(r.getResults().size(), 5);

    assertEquals(r.getResults().get(0).getFirst(), OperationType.ADD);
    assertEquals(r.getResults().get(0).getSecond().getResultCode(),
         ResultCode.ADMIN_LIMIT_EXCEEDED);

    assertEquals(r.getResults().get(1).getFirst(), OperationType.DELETE);
    assertEquals(r.getResults().get(1).getSecond().getResultCode(),
         ResultCode.ASSERTION_FAILED);

    assertEquals(r.getResults().get(2).getFirst(), OperationType.EXTENDED);
    assertTrue(r.getResults().get(2).getSecond() instanceof ExtendedResult);
    assertEquals(r.getResults().get(2).getSecond().getResultCode(),
         ResultCode.INVALID_CREDENTIALS);

    assertEquals(r.getResults().get(3).getFirst(), OperationType.MODIFY);
    assertEquals(r.getResults().get(3).getSecond().getResultCode(),
         ResultCode.ATTRIBUTE_OR_VALUE_EXISTS);

    assertEquals(r.getResults().get(4).getFirst(), OperationType.MODIFY_DN);
    assertEquals(r.getResults().get(4).getSecond().getResultCode(),
         ResultCode.UNWILLING_TO_PERFORM);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 2);

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when creating a failure result in which the set of
   * operation results is null.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailureWithNullResults()
         throws Exception
  {
    final ArrayList<ObjectPair<OperationType,LDAPResult>> results = null;

    final String[] referralURLs =
    {
      "ldap://ds1.example.com:389/dc=example,dc=com",
      "ldap://ds2.example.com:389/dc=example,dc=com"
    };

    MultiUpdateExtendedResult r = new MultiUpdateExtendedResult(-1,
         ResultCode.UNWILLING_TO_PERFORM, "I don't know that operation",
         "cn=Matched DN", referralURLs, MultiUpdateChangesApplied.NONE,
         results);

    r = new MultiUpdateExtendedResult(r);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(), "I don't know that operation");

    assertNotNull(r.getMatchedDN());
    assertEquals(new DN(r.getMatchedDN()), new DN("cn=Matched DN"));

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);

    assertNotNull(r.getChangesApplied());
    assertEquals(r.getChangesApplied(), MultiUpdateChangesApplied.NONE);

    assertNotNull(r.getResults());
    assertTrue(r.getResults().isEmpty());

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when creating a failure result in which the set of
   * operation results is empty.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailureWithEmptyResults()
         throws Exception
  {
    final ArrayList<ObjectPair<OperationType,LDAPResult>> results =
         new ArrayList<ObjectPair<OperationType,LDAPResult>>(0);

    MultiUpdateExtendedResult r = new MultiUpdateExtendedResult(-1,
         ResultCode.UNWILLING_TO_PERFORM, "I don't know that operation", null,
         null, MultiUpdateChangesApplied.NONE, results);
    r = new MultiUpdateExtendedResult(r);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(), "I don't know that operation");

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getChangesApplied());
    assertEquals(r.getChangesApplied(), MultiUpdateChangesApplied.NONE);

    assertNotNull(r.getResults());
    assertTrue(r.getResults().isEmpty());

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when attempting to encode a result with an invalid
   * result type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testEncodeInvalidResultType()
         throws Exception
  {
    final ArrayList<ObjectPair<OperationType,LDAPResult>> results =
         new ArrayList<ObjectPair<OperationType,LDAPResult>>(1);
    results.add(new ObjectPair<OperationType,LDAPResult>(OperationType.BIND,
         new LDAPResult(-1, ResultCode.SUCCESS)));

    new MultiUpdateExtendedResult(-1, ResultCode.UNWILLING_TO_PERFORM,
         "I don't know that operation", null, null,
         MultiUpdateChangesApplied.NONE, results);
  }



  /**
   * Tests the behavior when attempting to decode a result in which the value is
   * not a valid ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new MultiUpdateExtendedResult(new ExtendedResult(-1, ResultCode.SUCCESS,
         null, null, null, MultiUpdateExtendedResult.MULTI_UPDATE_RESULT_OID,
         new ASN1OctetString("foo"), null));
  }



  /**
   * Tests the behavior when attempting to decode a result in which the value
   * contains an invalid changes applied value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidChangesApplied()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Enumerated(12345),
         new ASN1Sequence(
              new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_ADD_RESPONSE,
                   new ASN1Enumerated(0),
                   new ASN1OctetString(),
                   new ASN1OctetString())));


    new MultiUpdateExtendedResult(new ExtendedResult(-1, ResultCode.SUCCESS,
         null, null, null, MultiUpdateExtendedResult.MULTI_UPDATE_RESULT_OID,
         new ASN1OctetString(valueSequence.encode()), null));
  }



  /**
   * Tests the behavior when attempting to decode a result in which the value
   * contains information about an operation of an invalid type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidOperationType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Enumerated(1),
         new ASN1Sequence(
              new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_BIND_RESPONSE,
                   new ASN1Enumerated(49),
                   new ASN1OctetString(),
                   new ASN1OctetString())));


    new MultiUpdateExtendedResult(new ExtendedResult(-1, ResultCode.SUCCESS,
         null, null, null, MultiUpdateExtendedResult.MULTI_UPDATE_RESULT_OID,
         new ASN1OctetString(valueSequence.encode()), null));
  }
}
