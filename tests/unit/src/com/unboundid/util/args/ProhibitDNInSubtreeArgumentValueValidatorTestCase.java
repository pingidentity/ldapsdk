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

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the prohibit DN in subtree
 * argument value validator.
 */
public final class ProhibitDNInSubtreeArgumentValueValidatorTestCase
       extends LDAPSDKTestCase
{
  // A number of validator instances to use in testing.
  private ProhibitDNInSubtreeArgumentValueValidator prohibitSingle;
  private ProhibitDNInSubtreeArgumentValueValidator prohibitMultiple;

  // Arguments to use for testing.
  private DNArgument dnArg;
  private StringArgument stringArg;



  /**
   * Sets up the necessary elements for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    prohibitSingle = new ProhibitDNInSubtreeArgumentValueValidator(
         new DN("ou=Excluded1,dc=example,dc=com"));
    assertNotNull(prohibitSingle.getBaseDNs());
    assertEquals(prohibitSingle.getBaseDNs().size(), 1);
    assertNotNull(prohibitSingle.toString());

    prohibitMultiple = new ProhibitDNInSubtreeArgumentValueValidator(
         new DN("ou=Excluded1,dc=example,dc=com"),
         new DN("ou=Excluded2,dc=example,dc=com"));
    assertNotNull(prohibitMultiple.getBaseDNs());
    assertEquals(prohibitMultiple.getBaseDNs().size(), 2);
    assertNotNull(prohibitMultiple.toString());

    dnArg = new DNArgument(null, "testDN", false, 1, "{dn}", "Description");
    stringArg = new StringArgument(null, "testString", false, 1, "{value}",
         "Description");
  }




  /**
   * Tests the validator with the provided information.
   *
   * @param  value             The value to be tested.
   * @param  matchesExcluded1  Indicates whether the provided value is within
   *                           the first excluded branch.
   * @param  matchesExcluded2  Indicates whether the provided value is within
   *                           the second excluded branch.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testData")
  public void testValidator(final String value, final boolean matchesExcluded1,
                            final boolean matchesExcluded2)
         throws Exception
  {
    // See if the provided value is a valid DN.  If not, then it'll always be
    // rejected.
    if (! DN.isValidDN(value))
    {
      assertInvalid(prohibitSingle, value);
      assertInvalid(prohibitMultiple, value);
      return;
    }

    // See if the value matches the first prohibited DN.
    if (matchesExcluded1)
    {
      assertInvalid(prohibitSingle, value);
      assertInvalid(prohibitMultiple, value);
    }
    else
    {
      assertValid(prohibitSingle, value);
    }

    // See if the value matches the second prohibited DN.
    if (matchesExcluded2)
    {
      assertValid(prohibitSingle, value);
      assertInvalid(prohibitMultiple, value);
    }
    else if (! matchesExcluded1)
    {
      assertValid(prohibitSingle, value);
      assertValid(prohibitMultiple, value);
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
        false
      },

      new Object[]
      {
        "invalid",
        false,
        false
      },

      new Object[]
      {
        "dc=example,dc=com",
        false,
        false
      },

      new Object[]
      {
        "ou=Excluded1,dc=example,dc=com",
        true,
        false
      },

      new Object[]
      {
        "ou=Sub1,ou=Excluded1,dc=example,dc=com",
        true,
        false
      },

      new Object[]
      {
        "ou=Sub2,ou=Excluded1,dc=example,dc=com",
        true,
        false
      },

      new Object[]
      {
        "ou=Excluded2,dc=example,dc=com",
        false,
        true
      },

      new Object[]
      {
        "ou=Sub1,ou=Excluded2,dc=example,dc=com",
        false,
        true
      },

      new Object[]
      {
        "ou=Sub2,ou=Excluded2,dc=example,dc=com",
        false,
        true
      },
    };
  }



  /**
   * Ensures that the provided value is valid for the provided validator.
   *
   * @param  validator  The validator to use.
   * @param  value      The value to validate.
   */
  private void assertValid(
       final ProhibitDNInSubtreeArgumentValueValidator validator,
       final String value)
  {
    try
    {
      validator.validateArgumentValue(dnArg, value);
    }
    catch (final ArgumentException ae)
    {
      fail("Expected value '" + value + "' to be accepted by validator " +
           validator);
    }

    try
    {
      validator.validateArgumentValue(stringArg, value);
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
       final ProhibitDNInSubtreeArgumentValueValidator validator,
       final String value)
  {
    try
    {
      validator.validateArgumentValue(dnArg, value);
      fail("Expected value '" + value + "' to be rejected by validator " +
           validator);
    }
    catch (final ArgumentException ae)
    {
      // This was expected.
    }

    try
    {
      validator.validateArgumentValue(stringArg, value);
      fail("Expected value '" + value + "' to be rejected by validator " +
           validator);
    }
    catch (final ArgumentException ae)
    {
      // This was expected.
    }
  }
}
