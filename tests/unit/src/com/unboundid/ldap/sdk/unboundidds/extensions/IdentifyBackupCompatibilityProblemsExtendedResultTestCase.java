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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the identify backup compatibility
 * problems extended result.
 */
public final class IdentifyBackupCompatibilityProblemsExtendedResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a success result without any warnings or errors.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessResultWithoutWarningsOrErrors()
         throws Exception
  {
    IdentifyBackupCompatibilityProblemsExtendedResult r =
         new IdentifyBackupCompatibilityProblemsExtendedResult(-1,
              ResultCode.SUCCESS, null, null, null, null, null);

    r = new IdentifyBackupCompatibilityProblemsExtendedResult(r);
    assertNotNull(r);

    assertResultCodeEquals(r, ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.33");

    assertNotNull(r.getValue());

    assertNotNull(r.getErrorMessages());
    assertTrue(r.getErrorMessages().isEmpty());

    assertNotNull(r.getWarningMessages());
    assertTrue(r.getWarningMessages().isEmpty());

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior for a success result containing only warnings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessResultOnlyWarnings()
         throws Exception
  {
    IdentifyBackupCompatibilityProblemsExtendedResult r =
         new IdentifyBackupCompatibilityProblemsExtendedResult(-1,
              ResultCode.SUCCESS, null, null, null, null,
              Arrays.asList("warning1", "warning2"));

    r = new IdentifyBackupCompatibilityProblemsExtendedResult(r);
    assertNotNull(r);

    assertResultCodeEquals(r, ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.33");

    assertNotNull(r.getValue());

    assertNotNull(r.getErrorMessages());
    assertTrue(r.getErrorMessages().isEmpty());

    assertNotNull(r.getWarningMessages());
    assertFalse(r.getWarningMessages().isEmpty());
    assertEquals(r.getWarningMessages().size(), 2);
    assertTrue(r.getWarningMessages().contains("warning1"));
    assertTrue(r.getWarningMessages().contains("warning2"));

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior for a success result containing only errors.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessResultOnlyErrors()
         throws Exception
  {
    IdentifyBackupCompatibilityProblemsExtendedResult r =
         new IdentifyBackupCompatibilityProblemsExtendedResult(-1,
              ResultCode.SUCCESS, null, null, null,
              Arrays.asList("error1", "error2"), null);

    r = new IdentifyBackupCompatibilityProblemsExtendedResult(r);
    assertNotNull(r);

    assertResultCodeEquals(r, ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.33");

    assertNotNull(r.getValue());

    assertNotNull(r.getErrorMessages());
    assertFalse(r.getErrorMessages().isEmpty());
    assertEquals(r.getErrorMessages().size(), 2);
    assertTrue(r.getErrorMessages().contains("error1"));
    assertTrue(r.getErrorMessages().contains("error2"));

    assertNotNull(r.getWarningMessages());
    assertTrue(r.getWarningMessages().isEmpty());

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior for a success result containing both warnings and
   * errors.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessResultWarningsAndErrors()
         throws Exception
  {
    IdentifyBackupCompatibilityProblemsExtendedResult r =
         new IdentifyBackupCompatibilityProblemsExtendedResult(-1,
              ResultCode.SUCCESS, null, null, null,
              Arrays.asList("error1", "error2"),
              Arrays.asList("warning1", "warning2"));

    r = new IdentifyBackupCompatibilityProblemsExtendedResult(r);
    assertNotNull(r);

    assertResultCodeEquals(r, ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.33");

    assertNotNull(r.getValue());

    assertNotNull(r.getErrorMessages());
    assertFalse(r.getErrorMessages().isEmpty());
    assertEquals(r.getErrorMessages().size(), 2);
    assertTrue(r.getErrorMessages().contains("error1"));
    assertTrue(r.getErrorMessages().contains("error2"));

    assertNotNull(r.getWarningMessages());
    assertFalse(r.getWarningMessages().isEmpty());
    assertEquals(r.getWarningMessages().size(), 2);
    assertTrue(r.getWarningMessages().contains("warning1"));
    assertTrue(r.getWarningMessages().contains("warning2"));

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior for a failure result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailureResult()
         throws Exception
  {
    final String[] referralURLs =
    {
      "ldap://ds1.example.com:389/dc=example,dc=com",
      "ldap://ds2.example.com:389/dc=example,dc=com"
    };

    IdentifyBackupCompatibilityProblemsExtendedResult r =
         new IdentifyBackupCompatibilityProblemsExtendedResult(123,
              ResultCode.OTHER, "diag", "dc=matched,dc=dn", referralURLs,
              null, null, new Control("1.2.3.4"), new Control("1.2.3.5"));

    r = new IdentifyBackupCompatibilityProblemsExtendedResult(r);
    assertNotNull(r);

    assertResultCodeEquals(r, ResultCode.OTHER);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(), "diag");

    assertNotNull(r.getMatchedDN());
    assertDNsEqual(r.getMatchedDN(), "dc=matched,dc=dn");

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);

    assertNull(r.getOID());

    assertNull(r.getValue());

    assertNotNull(r.getErrorMessages());
    assertTrue(r.getErrorMessages().isEmpty());

    assertNotNull(r.getWarningMessages());
    assertTrue(r.getWarningMessages().isEmpty());

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
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
    final ExtendedResult r = new ExtendedResult(-1, ResultCode.SUCCESS, null,
         null, null, "1.3.6.1.4.1.30221.2.6.31", new ASN1OctetString("foo"),
         null);
    new IdentifyBackupCompatibilityProblemsExtendedResult(r);
  }



  /**
   * Tests the behavior when trying to decode an extended result in which the
   * value sequence has an element with an unexpected type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceUnexpectedType()
         throws Exception
  {
    final ASN1Sequence valueSequence =
         new ASN1Sequence(new ASN1OctetString((byte) 123, "foo"));

    final ExtendedResult r = new ExtendedResult(-1, ResultCode.SUCCESS, null,
         null, null, "1.3.6.1.4.1.30221.2.6.31",
         new ASN1OctetString(valueSequence.encode()), null);
    new IdentifyBackupCompatibilityProblemsExtendedResult(r);
  }
}
