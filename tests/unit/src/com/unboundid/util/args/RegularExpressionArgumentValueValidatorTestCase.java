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
package com.unboundid.util.args;



import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the regular expression argument
 * value validator.
 */
public final class RegularExpressionArgumentValueValidatorTestCase
       extends LDAPSDKTestCase
{
  // The validator instance to use in testing.
  private RegularExpressionArgumentValueValidator validator;

  // The argument to use for testing.
  private StringArgument arg;



  /**
   * Sets up the necessary elements for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    validator = new RegularExpressionArgumentValueValidator();
    assertNotNull(validator.toString());

    arg = new StringArgument(null, "test", false, 1, "{value}", "Description");
  }




  /**
   * Tests the validator with the provided information.
   *
   * @param  value    The value to be tested.
   * @param  isValid  Indicates whether the provided value is valid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testData")
  public void testValidator(final String value, final boolean isValid)
         throws Exception
  {
    if (isValid)
    {
      assertValid(value);
    }
    else
    {
      assertInvalid(value);
    }
  }



  /**
   * Retrieves data that can be used for testing.
   *
   * @return  Data that can be used for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="testData")
  public Object[][] getTestData()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        "",
        true
      },

      new Object[]
      {
        "^[a-z]$",
        true
      },

      new Object[]
      {
        "[unclosed",
        false
      },
    };
  }



  /**
   * Ensures that the provided value is valid for the validator.
   *
   * @param  value  The value to validate.
   */
  private void assertValid(final String value)
  {
    try
    {
      validator.validateArgumentValue(arg, value);
    }
    catch (final ArgumentException ae)
    {
      fail("Expected value '" + value + "' to be accepted by validator " +
           validator);
    }
  }



  /**
   * Ensures that the provided value is not valid for the validator.
   *
   * @param  value  The value to validate.
   */
  private void assertInvalid(final String value)
  {
    try
    {
      validator.validateArgumentValue(arg, value);
      fail("Expected value '" + value + "' to be rejected by validator " +
           validator);
    }
    catch (final ArgumentException ae)
    {
      // This was expected.
    }
  }
}
