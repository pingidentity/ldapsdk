/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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



import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the get password quality
 * requirements extended result.
 */
public final class GetPasswordQualityRequirementsExtendedResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for a successful result but without any
   * requirements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessResultWithoutRequirements()
         throws Exception
  {
    GetPasswordQualityRequirementsExtendedResult r =
         new GetPasswordQualityRequirementsExtendedResult(1,
              ResultCode.SUCCESS, null, null, null, null, null, null, null);

    r = new GetPasswordQualityRequirementsExtendedResult(r);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.44");

    assertNotNull(r.getValue());

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(r.getPasswordRequirements());
    assertTrue(r.getPasswordRequirements().isEmpty());

    assertNull(r.getCurrentPasswordRequired());

    assertNull(r.getMustChangePassword());

    assertNull(r.getSecondsUntilExpiration());

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for a successful result that includes password
   * quality requirements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessResultWithRequirements()
         throws Exception
  {
    final List<PasswordQualityRequirement> requirements = Arrays.asList(
         new PasswordQualityRequirement(
              "Your password must be at least eight characters long.", "length",
              Collections.singletonMap("minimum-length", "8")),
         new PasswordQualityRequirement(
              "You cannot reuse a password you have used in the last year.",
              "history",
              Collections.singletonMap("history-duration-seconds",
                   "31536000")));

    GetPasswordQualityRequirementsExtendedResult r =
         new GetPasswordQualityRequirementsExtendedResult(1,
              ResultCode.SUCCESS, null, null, null, requirements, true, false,
              7776000);

    r = new GetPasswordQualityRequirementsExtendedResult(r);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.44");

    assertNotNull(r.getValue());

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(r.getPasswordRequirements());
    assertFalse(r.getPasswordRequirements().isEmpty());
    assertEquals(r.getPasswordRequirements().size(), 2);

    assertNotNull(r.getCurrentPasswordRequired());
    assertEquals(r.getCurrentPasswordRequired(), Boolean.TRUE);

    assertNotNull(r.getMustChangePassword());
    assertEquals(r.getMustChangePassword(), Boolean.FALSE);

    assertNotNull(r.getSecondsUntilExpiration());
    assertEquals(r.getSecondsUntilExpiration().intValue(), 7776000);

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for a result from an operation that did not
   * complete successfully.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonSuccessResult()
         throws Exception
  {
    final String[] referralURLs =
    {
      "ldap://ds1.example.com/",
      "ldap://ds2.example.com/"
    };

    GetPasswordQualityRequirementsExtendedResult r =
         new GetPasswordQualityRequirementsExtendedResult(1,
              ResultCode.INSUFFICIENT_ACCESS_RIGHTS,
              "You do not have permission to issue this request",
              "cn=matched,cn=dn", referralURLs, null, null, null, null,
              new Control("1.2.3.4"), new Control("1.2.3.5", true));

    r = new GetPasswordQualityRequirementsExtendedResult(r);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.INSUFFICIENT_ACCESS_RIGHTS);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(),
         "You do not have permission to issue this request");

    assertNotNull(r.getMatchedDN());
    assertDNsEqual(r.getMatchedDN(), "cn=matched,cn=dn");

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);

    assertNull(r.getOID());

    assertNull(r.getValue());

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 2);

    assertNotNull(r.getPasswordRequirements());
    assertTrue(r.getPasswordRequirements().isEmpty());

    assertNull(r.getCurrentPasswordRequired());

    assertNull(r.getMustChangePassword());

    assertNull(r.getSecondsUntilExpiration());

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to create a non-success response that
   * includes requirements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNonSuccessWithRequirements()
         throws Exception
  {
    final List<PasswordQualityRequirement> requirements = Arrays.asList(
         new PasswordQualityRequirement(
              "Your password must be at least eight characters long.", "length",
              Collections.singletonMap("minimum-length", "8")),
         new PasswordQualityRequirement(
              "You cannot reuse a password you have used in the last year.",
              "history",
              Collections.singletonMap("history-duration-seconds",
                   "31536000")));

    GetPasswordQualityRequirementsExtendedResult r =
         new GetPasswordQualityRequirementsExtendedResult(1,
              ResultCode.UNWILLING_TO_PERFORM, "I don't feel like it", null,
              null, requirements, null, null, null);
  }



  /**
   * Tests the behavior when trying to create a non-success response that
   * includes a current password required element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNonSuccessWithCurrentPasswordRequired()
         throws Exception
  {
    GetPasswordQualityRequirementsExtendedResult r =
         new GetPasswordQualityRequirementsExtendedResult(1,
              ResultCode.UNWILLING_TO_PERFORM, "I don't feel like it", null,
              null, null, true, null, null);
  }



  /**
   * Tests the behavior when trying to create a non-success response that
   * includes a must change password element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNonSuccessWithMustChangePassword()
         throws Exception
  {
    GetPasswordQualityRequirementsExtendedResult r =
         new GetPasswordQualityRequirementsExtendedResult(1,
              ResultCode.UNWILLING_TO_PERFORM, "I don't feel like it", null,
              null, null, null, true, null);
  }



  /**
   * Tests the behavior when trying to create a non-success response that
   * includes a seconds until expiration element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNonSuccessWithSecondsUntilExpiration()
         throws Exception
  {
    GetPasswordQualityRequirementsExtendedResult r =
         new GetPasswordQualityRequirementsExtendedResult(1,
              ResultCode.UNWILLING_TO_PERFORM, "I don't feel like it", null,
              null, null, null, null, 1234);
  }



  /**
   * Tests the behavior when trying to decode an extended result whose value is
   * not a valid ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new GetPasswordQualityRequirementsExtendedResult(new ExtendedResult(1,
         ResultCode.SUCCESS, null, null, null, "1.3.6.1.4.1.30221.2.6.44",
         new ASN1OctetString("not a valid sequence"), null));
  }
}
