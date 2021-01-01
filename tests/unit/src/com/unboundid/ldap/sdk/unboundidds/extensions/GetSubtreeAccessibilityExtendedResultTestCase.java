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
import java.util.Date;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the get subtree accessibility
 * extended result.
 */
public final class GetSubtreeAccessibilityExtendedResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides a basic set of tests for the get subtree accessibility result
   * that implies a successful operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAccessibilityResultSuccess()
         throws Exception
  {
    final ArrayList<SubtreeAccessibilityRestriction> restrictions =
         new ArrayList<SubtreeAccessibilityRestriction>(2);
    restrictions.add(new SubtreeAccessibilityRestriction(
         "ou=sub1,dc=example,dc=com",
         SubtreeAccessibilityState.READ_ONLY_BIND_ALLOWED,
         "uid=bypass,dc=example,dc=com", new Date()));
    restrictions.add(new SubtreeAccessibilityRestriction(
         "ou=sub2,dc=example,dc=com", SubtreeAccessibilityState.HIDDEN, null,
         new Date()));

    GetSubtreeAccessibilityExtendedResult r =
         new GetSubtreeAccessibilityExtendedResult(1234, ResultCode.SUCCESS,
              null, null, null, restrictions, new Control("1.2.3.4"),
              new Control("1.2.3.5"));
    r = new GetSubtreeAccessibilityExtendedResult(r);

    assertEquals(r.getMessageID(), 1234);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getAccessibilityRestrictions());
    assertEquals(r.getAccessibilityRestrictions().size(), 2);

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Provides a basic set of tests for the get subtree accessibility result
   * that implies a failed operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAccessibilityResultFailure()
         throws Exception
  {
    final String[] referralURLs =
    {
      "ldap://ds1.example.com:389/",
      "ldap://ds2.example.com:389/",
    };

    GetSubtreeAccessibilityExtendedResult r =
         new GetSubtreeAccessibilityExtendedResult(5678,
              ResultCode.UNWILLING_TO_PERFORM, "diagnostic message",
              "matched DN", referralURLs, null);
    r = new GetSubtreeAccessibilityExtendedResult(r);

    assertEquals(r.getMessageID(), 5678);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(), "diagnostic message");

    assertNotNull(r.getMatchedDN());
    assertEquals(r.getMatchedDN(), "matched DN");

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);

    assertNull(r.getAccessibilityRestrictions());

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode a result whose value is not an
   * ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetAccessibilityValueNotSequence()
         throws Exception
  {
    new GetSubtreeAccessibilityExtendedResult(new ExtendedResult(1234,
         ResultCode.OTHER, null, null, null,
         GetSubtreeAccessibilityExtendedResult.
              GET_SUBTREE_ACCESSIBILITY_RESULT_OID,
         new ASN1OctetString("foo"), null));
  }



  /**
   * Tests the behavior when trying to decode a result whose value sequence is
   * missing a base DN element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetAccessibilityValueSequenceMissingBaseDN()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Enumerated((byte) 0x81, 1),
         new ASN1OctetString((byte) 0x82, "uid=bypass,dc=example,dc=com"),
         new ASN1OctetString((byte) 0x83, "20120101012345.678Z"));

    new GetSubtreeAccessibilityExtendedResult(new ExtendedResult(1234,
         ResultCode.OTHER, null, null, null,
         GetSubtreeAccessibilityExtendedResult.
              GET_SUBTREE_ACCESSIBILITY_RESULT_OID,
         new ASN1OctetString(new ASN1Sequence(valueSequence).encode()), null));
  }



  /**
   * Tests the behavior when trying to decode a result whose value sequence is
   * missing an accessibility state element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetAccessibilityValueSequenceMissingState()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "ou=subtree,dc=example,dc=com"),
         new ASN1OctetString((byte) 0x82, "uid=bypass,dc=example,dc=com"),
         new ASN1OctetString((byte) 0x83, "20120101012345.678Z"));

    new GetSubtreeAccessibilityExtendedResult(new ExtendedResult(1234,
         ResultCode.OTHER, null, null, null,
         GetSubtreeAccessibilityExtendedResult.
              GET_SUBTREE_ACCESSIBILITY_RESULT_OID,
         new ASN1OctetString(new ASN1Sequence(valueSequence).encode()), null));
  }



  /**
   * Tests the behavior when trying to decode a result whose value sequence has
   * an invalid accessibility state element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetAccessibilityValueSequenceInvalidState()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "ou=subtree,dc=example,dc=com"),
         new ASN1Enumerated((byte) 0x81, 1234),
         new ASN1OctetString((byte) 0x82, "uid=bypass,dc=example,dc=com"),
         new ASN1OctetString((byte) 0x83, "20120101012345.678Z"));

    new GetSubtreeAccessibilityExtendedResult(new ExtendedResult(1234,
         ResultCode.OTHER, null, null, null,
         GetSubtreeAccessibilityExtendedResult.
              GET_SUBTREE_ACCESSIBILITY_RESULT_OID,
         new ASN1OctetString(new ASN1Sequence(valueSequence).encode()), null));
  }



  /**
   * Tests the behavior when trying to decode a result whose value sequence has
   * an invalid accessibility state element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetAccessibilityValueSequenceMissingEffectiveTime()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "ou=subtree,dc=example,dc=com"),
         new ASN1Enumerated((byte) 0x81, 1),
         new ASN1OctetString((byte) 0x82, "uid=bypass,dc=example,dc=com"));

    new GetSubtreeAccessibilityExtendedResult(new ExtendedResult(1234,
         ResultCode.OTHER, null, null, null,
         GetSubtreeAccessibilityExtendedResult.
              GET_SUBTREE_ACCESSIBILITY_RESULT_OID,
         new ASN1OctetString(new ASN1Sequence(valueSequence).encode()), null));
  }



  /**
   * Tests the behavior when trying to decode a result whose value sequence has
   * an invalid element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetAccessibilityValueSequenceInvalidElementType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString("invalid type"));

    new GetSubtreeAccessibilityExtendedResult(new ExtendedResult(1234,
         ResultCode.OTHER, null, null, null,
         GetSubtreeAccessibilityExtendedResult.
              GET_SUBTREE_ACCESSIBILITY_RESULT_OID,
         new ASN1OctetString(new ASN1Sequence(valueSequence).encode()), null));
  }
}
