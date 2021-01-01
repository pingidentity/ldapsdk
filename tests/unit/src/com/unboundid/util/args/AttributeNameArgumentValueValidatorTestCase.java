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
import com.unboundid.ldap.sdk.schema.Schema;



/**
 * This class provides a set of test cases for the attribute name argument value
 * validator.
 */
public final class AttributeNameArgumentValueValidatorTestCase
       extends LDAPSDKTestCase
{
  // A number of validator instances to use in testing.
  private AttributeNameArgumentValueValidator allowOptionsNoSchema;
  private AttributeNameArgumentValueValidator allowOptionsWithSchema;
  private AttributeNameArgumentValueValidator noOptionsNoSchema;
  private AttributeNameArgumentValueValidator noOptionsWithSchema;

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
    final Schema schema = Schema.getDefaultStandardSchema();

    noOptionsNoSchema = new AttributeNameArgumentValueValidator();
    assertFalse(noOptionsNoSchema.allowOptions());
    assertNull(noOptionsNoSchema.getSchema());
    assertNotNull(noOptionsNoSchema.toString());

    allowOptionsNoSchema = new AttributeNameArgumentValueValidator(true, null);
    assertTrue(allowOptionsNoSchema.allowOptions());
    assertNull(allowOptionsNoSchema.getSchema());
    assertNotNull(allowOptionsNoSchema.toString());

    noOptionsWithSchema =
         new AttributeNameArgumentValueValidator(false, schema);
    assertFalse(noOptionsWithSchema.allowOptions());
    assertNotNull(noOptionsWithSchema.getSchema());
    assertNotNull(noOptionsWithSchema.toString());

    allowOptionsWithSchema =
         new AttributeNameArgumentValueValidator(true, schema);
    assertTrue(allowOptionsWithSchema.allowOptions());
    assertNotNull(allowOptionsWithSchema.getSchema());
    assertNotNull(allowOptionsWithSchema.toString());

    arg = new StringArgument(null, "test", false, 1, "{value}", "Description");
  }




  /**
   * Tests the validator with the provided information.
   *
   * @param  value       The value to be tested.
   * @param  isValid     Indicates whether the provided value is a valid
   *                     attribute description.
   * @param  hasOptions  Indicates whether the provided value has one or more
   *                     attribute options.
   * @param  isDefined   Indicates whether the provided value is defined in the
   *                     schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testData")
  public void testValidator(final String value, final boolean isValid,
                            final boolean hasOptions, final boolean isDefined)
         throws Exception
  {
    // If the value isn't valid, then it'll always be rejected.
    if (! isValid)
    {
      assertInvalid(noOptionsNoSchema, value);
      assertInvalid(allowOptionsNoSchema, value);
      assertInvalid(noOptionsWithSchema, value);
      assertInvalid(allowOptionsWithSchema, value);
      return;
    }


    // If the value has options, then it should be rejected by the validators
    // that don't allow options.  Also consider whether the value is defined in
    // the schema.
    if (hasOptions)
    {
      assertInvalid(noOptionsNoSchema, value);
      assertInvalid(noOptionsWithSchema, value);

      assertValid(allowOptionsNoSchema, value);

      if (isDefined)
      {
        assertValid(allowOptionsWithSchema, value);
      }
      else
      {
        assertInvalid(allowOptionsWithSchema, value);
      }
    }
    else
    {
      assertValid(noOptionsNoSchema, value);
      assertValid(allowOptionsNoSchema, value);

      if (isDefined)
      {
        assertValid(noOptionsWithSchema, value);
        assertValid(allowOptionsWithSchema, value);
      }
      else
      {
        assertInvalid(noOptionsWithSchema, value);
        assertInvalid(allowOptionsWithSchema, value);
      }
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
        "cn",
        true,
        false,
        true
      },

      new Object[]
      {
        "cn;lang-EN-US",
        true,
        true,
        true
      },

      new Object[]
      {
        "2.5.4.3",
        true,
        false,
        true
      },

      new Object[]
      {
        "2.5.4.3;lang-EN-US",
        true,
        true,
        true
      },

      new Object[]
      {
        "undefined",
        true,
        false,
        false
      },

      new Object[]
      {
        "undefined;binary",
        true,
        true,
        false
      },

      new Object[]
      {
        "1.2.3.4",
        true,
        false,
        false
      },

      new Object[]
      {
        "1.2.3.4;binary",
        true,
        true,
        false
      },

      new Object[]
      {
        "not a valid name",
        false,
        false,
        false
      },

      new Object[]
      {
        "valid-name;not a valid option",
        false,
        true,
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
  private void assertValid(final AttributeNameArgumentValueValidator validator,
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
  private void assertInvalid(
       final AttributeNameArgumentValueValidator validator, final String value)
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
