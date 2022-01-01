/*
 * Copyright 2021-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021-2022 Ping Identity Corporation
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
 * Copyright (C) 2021-2022 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the purge retired listener
 * certificates extended result.
 */
public final class PurgeRetiredListenerCertificatesExtendedResultTestCase
     extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for an extended result object that does not contain
   * tool output.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutToolOutput()
         throws Exception
  {
    final String[] referralURLs =
    {
      "ldap://ds1.example.com:389/dc=example,dc=com",
      "ldap://ds2.example.com:389/dc=example,dc=com"
    };

    PurgeRetiredListenerCertificatesExtendedResult r =
         new PurgeRetiredListenerCertificatesExtendedResult(2,
              ResultCode.UNWILLING_TO_PERFORM, "Refusing the operation",
              "dc=example,dc=com", referralURLs, null,
              new Control("1.2.3.4"),
              new Control("1.2.3.5", true, new ASN1OctetString("foo")));

    r = new PurgeRetiredListenerCertificatesExtendedResult(r);

    assertEquals(r.getMessageID(), 2);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(), "Refusing the operation");

    assertNotNull(r.getMatchedDN());
    assertDNsEqual(r.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs(), referralURLs);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.70");

    assertNotNull(r.getValue());

    assertNull(r.getToolOutput());

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 2);

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior for an extended result object that contains tool
   * output.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithToolOutput()
         throws Exception
  {
    final String toolOutput =
         "tool output\r\n'\"\\requires escaping\nin toString";

    PurgeRetiredListenerCertificatesExtendedResult r =
         new PurgeRetiredListenerCertificatesExtendedResult(3,
              ResultCode.SUCCESS, null, null, null, toolOutput);

    r = new PurgeRetiredListenerCertificatesExtendedResult(r);

    assertEquals(r.getMessageID(), 3);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.70");

    assertNotNull(r.getValue());

    assertNotNull(r.getToolOutput());
    assertEquals(r.getToolOutput(), toolOutput);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode an extended result that does not
   * have an OID or value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeResultWithoutOIDOrValue()
         throws Exception
  {
    final PurgeRetiredListenerCertificatesExtendedResult r =
         new PurgeRetiredListenerCertificatesExtendedResult(new ExtendedResult(
              4, ResultCode.UNWILLING_TO_PERFORM, "Unrecognized operation",
              null, null, null, null, null));

    assertEquals(r.getMessageID(), 4);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(), "Unrecognized operation");

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNull(r.getOID());

    assertNull(r.getValue());

    assertNull(r.getToolOutput());

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode an extended result with a
   * malformed value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeResultWithoutMalformedValue()
         throws Exception
  {
    try
    {
      new PurgeRetiredListenerCertificatesExtendedResult(new ExtendedResult(4,
           ResultCode.UNWILLING_TO_PERFORM, "Unrecognized operation", null,
           null, "1.3.6.1.4.1.30221.2.6.70",
           new ASN1OctetString("malformed-value"), null));
      fail("Expected an exception when trying to decode an extended result " +
           "with a malformed value");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }
  }
}
