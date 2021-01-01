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
 * This class provides a set of test cases for the URL argument value validator.
 */
public final class URLArgumentValueValidatorTestCase
       extends LDAPSDKTestCase
{
  // A number of validator instances to use in testing.
  private URLArgumentValueValidator permitAny;
  private URLArgumentValueValidator permitSingle;
  private URLArgumentValueValidator permitMultiple;

  // An argument to use for testing.
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
    permitAny = new URLArgumentValueValidator((String[]) null);
    assertNotNull(permitAny.getAllowedSchemes());
    assertTrue(permitAny.getAllowedSchemes().isEmpty());
    assertNotNull(permitAny.toString());

    permitSingle = new URLArgumentValueValidator("http");
    assertNotNull(permitSingle.getAllowedSchemes());
    assertEquals(permitSingle.getAllowedSchemes().size(), 1);
    assertNotNull(permitSingle.toString());

    permitMultiple = new URLArgumentValueValidator("http", "https");
    assertNotNull(permitMultiple.getAllowedSchemes());
    assertEquals(permitMultiple.getAllowedSchemes().size(), 2);
    assertNotNull(permitMultiple.toString());

    arg = new StringArgument(null, "testString", false, 1, "{value}",
         "Description");
  }




  /**
   * Tests the validator with the provided information.
   *
   * @param  value     The value to be tested.
   * @param  isValid   Indicates whether the provided value is a valid URL.
   * @param  matches1  Indicates whether the provided value matches the first
   *                   allowed scheme.
   * @param  matches2  Indicates whether the provided value matches the second
   *                   allowed scheme.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testData")
  public void testValidator(final String value, final boolean isValid,
                            final boolean matches1, final boolean matches2)
         throws Exception
  {
    // See if the value is a valid URL.  If so, not, then it shouldn't match
    // any of the validators.  Otherwise, it should match at least the one that
    // doesn't care about which scheme is used.
    if (isValid)
    {
      assertValid(permitAny, value);
    }
    else
    {
      assertInvalid(permitAny, value);
      assertInvalid(permitSingle, value);
      assertInvalid(permitMultiple, value);
      return;
    }

    // If the value matches the first allowed scheme, then it should be
    // acceptable to both scheme-specific validators.  If it matches the
    // second, then it should only be acceptable to one.  If it doesn't match
    // either scheme, then it shouldn't be acceptable to either validator
    if (matches1)
    {
      assertValid(permitSingle, value);
      assertValid(permitMultiple, value);
    }
    else if (matches2)
    {
      assertInvalid(permitSingle, value);
      assertValid(permitMultiple, value);
    }
    else
    {
      assertInvalid(permitSingle, value);
      assertInvalid(permitMultiple, value);
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
        false,
        false,
        false
      },

      new Object[]
      {
        ":",
        false,
        false,
        false
      },

      new Object[]
      {
        ":/",
        false,
        false,
        false
      },

      new Object[]
      {
        "invalid",
        false,
        false,
        false
      },

      new Object[]
      {
        "http://www.example.com/test",
        true,
        true,
        false
      },

      new Object[]
      {
        "https://www.example.com/test",
        true,
        false,
        true
      },

      new Object[]
      {
        "ftp://ftp.example.com/test",
        true,
        false,
        false
      },

      new Object[]
      {
        "ldap://ldap.example.com/dc=example,dc=com??sub?(uid=john.doe)",
        true,
        false,
        false
      },

      new Object[]
      {
        "notarecognizedscheme://something.example.com/test",
        true,
        false,
        false
      },
    };
  }



  /**
   * Ensures that the provided value is valid for the provided validator.
   *
   * @param  validator  The validator to use.
   * @param  value      The value to validate.
   */
  private void assertValid(final URLArgumentValueValidator validator,
                           final String value)
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
   * Ensures that the provided value is not valid for the provided validator.
   *
   * @param  validator  The validator to use.
   * @param  value      The value to validate.
   */
  private void assertInvalid(final URLArgumentValueValidator validator,
                             final String value)
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
