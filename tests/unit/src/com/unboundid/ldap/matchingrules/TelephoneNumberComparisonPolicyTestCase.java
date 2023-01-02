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
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the telephone number comparison
 * policy.
 */
public final class TelephoneNumberComparisonPolicyTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for the enum methods.
   */
  @Test()
  public void testEnumMethods()
  {
    for (final TelephoneNumberComparisonPolicy p :
         TelephoneNumberComparisonPolicy.values())
    {
      assertEquals(TelephoneNumberComparisonPolicy.valueOf(p.name()), p);
    }

    try
    {
      TelephoneNumberComparisonPolicy.valueOf("undefined-value");
      fail("Expected valueOf to throw an exception for an undefined value.");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior of the {@code normalizeValue} method with the provided
   * information.
   *
   * @param  value  The value to normalize.
   * @param  expectedNormalizedIgnoreAllNonNumeric
   *              The expected normalized representation of the value when
   *              ignoring all non-numeric characters.
   * @param  expectedNormalizedIgnoreOnlySpacesAndDashes
   *              The expected normalized representation of the value when
   *              ignoring only spaces and dashes.
   */
  @Test(dataProvider = "normalizeTestData")
  public void testNormalize(final String value,
                   final String expectedNormalizedIgnoreAllNonNumeric,
                   final String expectedNormalizedIgnoreOnlySpacesAndDashes)
  {
    final ASN1OctetString valueOctetString = new ASN1OctetString(value);

    assertEquals(
         TelephoneNumberComparisonPolicy.IGNORE_ALL_NON_NUMERIC_CHARACTERS.
              normalizeValue(valueOctetString).stringValue(),
         expectedNormalizedIgnoreAllNonNumeric);

    assertEquals(
         TelephoneNumberComparisonPolicy.IGNORE_ONLY_SPACES_AND_DASHES.
              normalizeValue(valueOctetString).stringValue(),
         expectedNormalizedIgnoreOnlySpacesAndDashes);
  }



  /**
   * Retrieves a set of data for testing the {@code normalizeValue} method.
   *
   * @return  A set of data for testing the {@code normalizeValue} method.
   */
  @DataProvider(name = "normalizeTestData")
  public Object[][] getNormalizeTestData()
  {
    return new Object[][]
    {
      new Object[]
      {
        "",
        "",
        ""
      },

      new Object[]
      {
        " ",
        "",
        ""
      },

      new Object[]
      {
        "-",
        "",
        ""
      },

      new Object[]
      {
        "+1 123 456 7890",
        "+11234567890",
        "+11234567890"
      },

      new Object[]
      {
        "+1 123-456-7890",
        "+11234567890",
        "+11234567890"
      },

      new Object[]
      {
        "+1 123-456-7890 Ext. 123",
        "+11234567890123",
        "+11234567890ext.123"
      }
    };
  }
}
