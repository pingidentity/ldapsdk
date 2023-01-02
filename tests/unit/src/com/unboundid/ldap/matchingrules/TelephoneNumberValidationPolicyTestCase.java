/*
 * Copyright 2022-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2023 Ping Identity Corporation
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
 * Copyright (C) 2022-2023 Ping Identity Corporation
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
package com.unboundid.ldap.matchingrules;



import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the telephone number validation
 * policy.
 */
public final class TelephoneNumberValidationPolicyTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for the enum methods.
   */
  @Test()
  public void testEnumMethods()
  {
    for (final TelephoneNumberValidationPolicy p :
         TelephoneNumberValidationPolicy.values())
    {
      assertEquals(TelephoneNumberValidationPolicy.valueOf(p.name()), p);
    }

    try
    {
      TelephoneNumberValidationPolicy.valueOf("undefined-value");
      fail("Expected valueOf to throw an exception for an undefined value.");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior of the {@code validateValue} method with the provided
   * information.
   *
   * @param  value  The value to validate.
   * @param  acceptedByAllowNonEmptyWhole
   *              Indicates whether the value is acceptable when allowing any
   *              non-empty printable string when the value is used as a whole
   *              value.
   * @param  acceptedByAllowNonEmptySubstring
   *              Indicates whether the value is acceptable when allowing any
   *              non-empty printable string when the value is used as a
   *              substring component.
   * @param  acceptedByAllowNonEmptyWithDigitWhole
   *              Indicates whether the value is acceptable when allowing any
   *              non-empty printable string containing at least one digit when
   *              the value is used as a whole value.
   * @param  acceptedByAllowNonEmptyWithDigitSubstring
   *              Indicates whether the value is acceptable when allowing any
   *              non-empty printable string containing at least one digit when
   *              the value is used as a substring component.
   * @param  acceptedByStrictX520ComplianceWhole
   *              Indicates whether the value is acceptable when using strict
   *              X.520-compliant validation when the value is used as a whole
   *              value.
   * @param  acceptedByStrictX520ComplianceSubstring
   *              Indicates whether the value is acceptable when using strict
   *              X.520-compliant validation when the value is used as a
   *              substring component.
   */
  @Test(dataProvider = "validateValueTestData")
  public void testValidateValue(final String value,
                   final boolean acceptedByAllowNonEmptyWhole,
                   final boolean acceptedByAllowNonEmptySubstring,
                   final boolean acceptedByAllowNonEmptyWithDigitWhole,
                   final boolean acceptedByAllowNonEmptyWithDigitSubstring,
                   final boolean acceptedByStrictX520ComplianceWhole,
                   final boolean acceptedByStrictX520ComplianceSubstring)
  {
    final ASN1OctetString valueOctetString = new ASN1OctetString(value);

    try
    {
      TelephoneNumberValidationPolicy.ALLOW_NON_EMPTY_PRINTABLE_STRING.
           validateValue(valueOctetString, false);
      assertTrue(acceptedByAllowNonEmptyWhole);
    }
    catch (final LDAPException e)
    {
      assertFalse(acceptedByAllowNonEmptyWhole);
    }

    try
    {
      TelephoneNumberValidationPolicy.ALLOW_NON_EMPTY_PRINTABLE_STRING.
           validateValue(valueOctetString, true);
      assertTrue(acceptedByAllowNonEmptySubstring);
    }
    catch (final LDAPException e)
    {
      assertFalse(acceptedByAllowNonEmptySubstring);
    }

    try
    {
      TelephoneNumberValidationPolicy.
           ALLOW_NON_EMPTY_PRINTABLE_STRING_WITH_AT_LEAST_ONE_DIGIT.
                validateValue(valueOctetString, false);
      assertTrue(acceptedByAllowNonEmptyWithDigitWhole);
    }
    catch (final LDAPException e)
    {
      assertFalse(acceptedByAllowNonEmptyWithDigitWhole);
    }

    try
    {
      TelephoneNumberValidationPolicy.
           ALLOW_NON_EMPTY_PRINTABLE_STRING_WITH_AT_LEAST_ONE_DIGIT.
                validateValue(valueOctetString, true);
      assertTrue(acceptedByAllowNonEmptyWithDigitSubstring);
    }
    catch (final LDAPException e)
    {
      assertFalse(acceptedByAllowNonEmptyWithDigitSubstring);
    }

    try
    {
      TelephoneNumberValidationPolicy.ENFORCE_STRICT_X520_COMPLIANCE.
           validateValue(valueOctetString, false);
      assertTrue(acceptedByStrictX520ComplianceWhole);
    }
    catch (final LDAPException e)
    {
      assertFalse(acceptedByStrictX520ComplianceWhole);
    }

    try
    {
      TelephoneNumberValidationPolicy.ENFORCE_STRICT_X520_COMPLIANCE.
           validateValue(valueOctetString, true);
      assertTrue(acceptedByStrictX520ComplianceSubstring);
    }
    catch (final LDAPException e)
    {
      assertFalse(acceptedByStrictX520ComplianceSubstring);
    }
  }



  /**
   * Retrieves a set of data for testing the {@code validateValue} method.
   *
   * @return  A set of data for testing the {@code validateValue} method.
   */
  @DataProvider(name = "validateValueTestData")
  public Object[][] getValidateValueTestData()
  {
    return new Object[][]
    {
      // An empty value should never be accepted.
      new Object[]
      {
        "",
        false,
        false,
        false,
        false,
        false,
        false
      },

      // A strictly X.520-compliant value should always be accepted.
      new Object[]
      {
        "+1 123 456-7890",
        true,
        true,
        true,
        true,
        true,
        true
      },

      // A value without any digits should only be accepted if we don't require
      // digits, or if we do require digits but
      new Object[]
      {
        "no digits",
        true,
        true,
        false,
        true,
        false,
        false
      },

      // A value that would be X.520-compliant except that it's missing the
      // leading plus sign should be valid everywhere except for the strict
      // X.520 compliance with a whole value.
      new Object[]
      {
        "1 123 456-7890",
        true,
        true,
        true,
        true,
        false,
        true
      },

      // A value that includes a non-printable character will never be
      // acceptable.
      new Object[]
      {
        "+1 \"123 456-7890\"",
        false,
        false,
        false,
        false,
        false,
        false
      },

      // A value that would be X.520-compliant except that it's got a printable
      // character outside of the set of digits, plus sign, space, and dash.
      // This should be acceptable in all cases other than strict X.520
      // compliance, regardless of whole value versus substring.
      new Object[]
      {
        "+1 123 456-7890 x123",
        true,
        true,
        true,
        true,
        false,
        false
      },

      // A value that would be X.520-compliant except that it's got an extra
      // plus sign somewhere that isn't the first character should be acceptable
      // in all cases other than strict X.520 compliance, regardless of whole
      // value versus substring.
      new Object[]
      {
        "+1 +123 456-7890",
        true,
        true,
        true,
        true,
        false,
        false
      },

      // A value that's just a plus sign should be acceptable in cases where
      // we don't require a digit.
      new Object[]
      {
        "+",
        true,
        true,
        false,
        true,
        false,
        false
      }
    };
  }
}
