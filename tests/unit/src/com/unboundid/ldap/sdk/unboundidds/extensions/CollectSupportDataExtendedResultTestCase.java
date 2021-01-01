/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
 * This class provides a set of test cases for the collect support data extended
 * result.
 */
public final class CollectSupportDataExtendedResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a version of the extended result that failed without an exit code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidResponseWithMoreToReturn()
         throws Exception
  {
    final String[] referralURLs =
    {
      "ldap://ds1.example.com:636/",
      "ldap://ds2.example.com:636/"
    };

    CollectSupportDataExtendedResult r = new CollectSupportDataExtendedResult(
         2, ResultCode.UNWILLING_TO_PERFORM, "I don't want to do it",
         "dc=example,dc=com", referralURLs, null,
         new Control("1.2.3.4"));

    r = new CollectSupportDataExtendedResult(r);

    assertEquals(r.getMessageID(), 2);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(), "I don't want to do it");

    assertNotNull(r.getMatchedDN());
    assertEquals(r.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs(), referralURLs);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 1);

    assertNull(r.getOID());

    assertNull(r.getValue());

    assertNull(r.getExitCode());

    assertNotNull(r.getExtendedResultName());
    assertFalse(r.getExtendedResultName().isEmpty());

    assertNotNull(r.toString());
  }



  /**
   * Tests a version of the extended result that succeeded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessResult()
         throws Exception
  {
    CollectSupportDataExtendedResult r = new CollectSupportDataExtendedResult(
         2, ResultCode.SUCCESS, null, null, null, 0);

    r = new CollectSupportDataExtendedResult(r);

    assertEquals(r.getMessageID(), 2);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.67");

    assertNotNull(r.getValue());

    assertNotNull(r.getExitCode());
    assertEquals(r.getExitCode().intValue(), 0);

    assertNotNull(r.getExtendedResultName());
    assertFalse(r.getExtendedResultName().isEmpty());

    assertNotNull(r.toString());
  }



  /**
   * Tests a version of the extended result in which the tool execution failed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailedExecution()
         throws Exception
  {
    CollectSupportDataExtendedResult r = new CollectSupportDataExtendedResult(
         2, ResultCode.OTHER,
         "The collect-support-data tool exited with code 1", null, null, 1,
         new Control("1.2.3.4"), new Control("1.2.3.5"));

    r = new CollectSupportDataExtendedResult(r);

    assertEquals(r.getMessageID(), 2);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.OTHER);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(),
         "The collect-support-data tool exited with code 1");

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 2);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.67");

    assertNotNull(r.getValue());

    assertNotNull(r.getExitCode());
    assertEquals(r.getExitCode().intValue(), 1);

    assertNotNull(r.getExtendedResultName());
    assertFalse(r.getExtendedResultName().isEmpty());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode an extended result with a
   * malformed value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedValue()
         throws Exception
  {
    new CollectSupportDataExtendedResult(new ExtendedResult(2,
         ResultCode.SUCCESS, null, null, null, "1.3.6.1.4.1.30221.2.6.67",
         new ASN1OctetString("malformed"), null));
  }
}
