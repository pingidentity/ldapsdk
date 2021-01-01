/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.util.args;



import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the OID argument value validator.
 */
public final class OIDArgumentValueValidatorTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the default constructor.
   *
   * @throws Exception If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultConstructor()
       throws Exception
  {
    final OIDArgumentValueValidator v = new OIDArgumentValueValidator();

    assertTrue(v.isStrict());

    assertNotNull(v.toString());
  }



  /**
   * Tests the behavior of the non-default constructor when it is configured to
   * be strict.
   *
   * @throws Exception If an unexpected problem occurs.
   */
  @Test()
  public void testNonDefaultConstructorIsStrict()
       throws Exception
  {
    final OIDArgumentValueValidator v = new OIDArgumentValueValidator(true);

    assertTrue(v.isStrict());

    assertNotNull(v.toString());
  }



  /**
   * Tests the behavior of the non-default constructor when it is configured to
   * be non-strict.
   *
   * @throws Exception If an unexpected problem occurs.
   */
  @Test()
  public void testNonDefaultConstructorNotStrict()
       throws Exception
  {
    final OIDArgumentValueValidator v = new OIDArgumentValueValidator(false);

    assertFalse(v.isStrict());

    assertNotNull(v.toString());
  }



  /**
   * Tests validation with the provided information.
   *
   * @param valueString        The value string to test.
   * @param isNonStrictlyValid Indicates whether the provided string should be
   *                           considered valid when performing non-strict
   *                           validation.
   * @param isStrictlyValid    Indicates whether the provided string should be
   *                           considered valid when performing strict
   *                           validation.
   *
   * @throws Exception If an unexpected problem occurs.
   */
  @Test(dataProvider = "testData")
  public void testValidation(final String valueString,
                             final boolean isNonStrictlyValid,
                             final boolean isStrictlyValid)
       throws Exception
  {
    final StringArgument arg =
         new StringArgument(null, "oid", true, 1, "{oid}", "A test OID.");

    final OIDArgumentValueValidator nonStrictValidator =
         new OIDArgumentValueValidator(false);
    try
    {
      nonStrictValidator.validateArgumentValue(arg, valueString);
      assertTrue(isNonStrictlyValid);
    }
    catch (final ArgumentException ae)
    {
      assertFalse(isNonStrictlyValid);
    }

    final OIDArgumentValueValidator strictValidator =
         new OIDArgumentValueValidator(true);
    try
    {
      strictValidator.validateArgumentValue(arg, valueString);
      assertTrue(isStrictlyValid);
    }
    catch (final ArgumentException ae)
    {
      assertFalse(isStrictlyValid);
    }
  }



  /**
   * Retrieves a set of data to use for testing.
   *
   * @return  A set of data to use for testing.
   */
  @DataProvider(name = "testData")
  public Object[][] getTestData()
  {
    return new Object[][]
    {
      // An empty string is never valid.
      new Object[]
      {
        "",
        false,
        false
      },

      // A string with characters other than numbers and digits is never valid.
      new Object[]
      {
        "non-numeric",
        false,
        false
      },

      // A with just a period is never valid.
      new Object[]
      {
        ".",
        false,
        false
      },

      // This is strictly valid.
      new Object[]
      {
        "1.2.3.4",
        true,
        true
      },

      // The above valid OID becomes invalid if it has consecutive periods.
      new Object[]
      {
        "1.2..3.4",
        false,
        false
      },

      // The above valid OID becomes invalid if it starts with a period.
      new Object[]
      {
        ".1.2.3.4",
        false,
        false
      },

      // The above valid OID becomes invalid if it ends with a period.
      new Object[]
      {
        "1.2.3.4.",
        false,
        false
      },

      // This is also strictly valid.
      new Object[]
      {
        "1.2",
        true,
        true
      },

      // An OID containing only a single component is not strictly valid.
      new Object[]
      {
        "1",
        true,
        false
      },

      // An OID with a first component of 0 can be strictly valid.
      new Object[]
      {
        "0.1",
        true,
        true
      },

      // An OID with a first component of 2 can be strictly valid.
      new Object[]
      {
        "2.2",
        true,
        true
      },

      // An OID in which the first component is not 0, 1, or 2 is not strictly
      // valid.
      new Object[]
      {
        "3.2",
        true,
        false
      },

      // An OID in which the first component is not 0 or 1 and the second
      // component is greater than 39 is not strictly valid.
      new Object[]
      {
        "0.1234",
        true,
        false
      },

      // An OID with a first component of 2 can have a second component value
      // that is larger than 40.
      new Object[]
      {
        "2.1234",
        true,
        true
      },

      // An OID with a non-final component that has a leading zero.
      new Object[]
      {
        "1.2.3.04.5.6.7",
        false,
        false
      },

      // An OID with a final component that has a leading zero.
      new Object[]
      {
        "1.2.3.4.5.6.07",
        false,
        false
      },

      // An OID with a non-final component that is out of range.
      new Object[]
      {
        "1.2.3.123456789123456789.5.6.7",
        false,
        false
      },

      // An OID with a final component that is out of range.
      new Object[]
      {
        "1.2.3.4.5.6.123456789123456789",
        false,
        false
      }
    };
  }
}
