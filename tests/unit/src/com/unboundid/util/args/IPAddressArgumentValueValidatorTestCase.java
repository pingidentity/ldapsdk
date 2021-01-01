/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the IP address argument value
 * validator.
 */
public final class IPAddressArgumentValueValidatorTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the default constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultConstructor()
         throws Exception
  {
    final IPAddressArgumentValueValidator v =
         new IPAddressArgumentValueValidator();

    assertTrue(v.acceptIPv4Addresses());

    assertTrue(v.acceptIPv6Addresses());

    assertNotNull(v.toString());
  }



  /**
   * Tests the behavior of the full constructor when only IPv4 addresses will
   * be accepted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFullConstructorAcceptOnlyIPv4()
         throws Exception
  {
    final IPAddressArgumentValueValidator v =
         new IPAddressArgumentValueValidator(true, false);

    assertTrue(v.acceptIPv4Addresses());

    assertFalse(v.acceptIPv6Addresses());

    assertNotNull(v.toString());
  }



  /**
   * Tests the behavior of the full constructor when only IPv6 addresses will
   * be accepted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFullConstructorAcceptOnlyIPv6()
         throws Exception
  {
    final IPAddressArgumentValueValidator v =
         new IPAddressArgumentValueValidator(false, true);

    assertFalse(v.acceptIPv4Addresses());

    assertTrue(v.acceptIPv6Addresses());

    assertNotNull(v.toString());
  }



  /**
   * Tests the behavior of the full constructor when neither IPv4 nor IPv6
   * addresses will be accepted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testFullConstructorAcceptNeither()
         throws Exception
  {
    new IPAddressArgumentValueValidator(false, false);
  }



  /**
   * Tests validation with the provided set of test data when both IPv4 and
   * IPv6 addresses are accepted.
   *
   * @param  valueString  The string to validate.
   * @param  isValid      Indicates whether the string represents a valid IP
   *                      address.
   * @param  isIPv6       Indicates whether the string represents an IPv6
   *                      address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testData")
  public void testValidateBothAccepted(final String valueString,
                                       final boolean isValid,
                                       final boolean isIPv6)
         throws Exception
  {
    final IPAddressArgumentValueValidator v =
         new IPAddressArgumentValueValidator(true, true);

    final StringArgument a = new StringArgument('a', "arg", "description");

    boolean exceptionCaught;
    try
    {
      v.validateArgumentValue(a, valueString);
      exceptionCaught = false;
    }
    catch (final ArgumentException ae)
    {
      exceptionCaught = true;
    }

    if (isValid)
    {
      assertFalse(exceptionCaught,
           "Failed to accept valid IP address '" + valueString + '\'');
    }
    else
    {
      assertTrue(exceptionCaught,
           "Accepted invalid IP address '" + valueString + '\'');
    }
  }



  /**
   * Tests validation with the provided set of test data when only IPv4
   * addresses are accepted.
   *
   * @param  valueString  The string to validate.
   * @param  isValid      Indicates whether the string represents a valid IP
   *                      address.
   * @param  isIPv6       Indicates whether the string represents an IPv6
   *                      address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testData")
  public void testValidateOnlyIPv4Accepted(final String valueString,
                                           final boolean isValid,
                                           final boolean isIPv6)
         throws Exception
  {
    final IPAddressArgumentValueValidator v =
         new IPAddressArgumentValueValidator(true, false);

    final StringArgument a = new StringArgument('a', "arg", "description");

    boolean exceptionCaught;
    try
    {
      v.validateArgumentValue(a, valueString);
      exceptionCaught = false;
    }
    catch (final ArgumentException ae)
    {
      exceptionCaught = true;
    }

    if (isValid)
    {
      if (isIPv6)
      {
        assertTrue(exceptionCaught,
             "Failed to reject IPv6 address '" + valueString + '\'');
      }
      else
      {
        assertFalse(exceptionCaught,
             "Failed to accept valid IPv4 address '" + valueString + '\'');
      }
    }
    else
    {
      assertTrue(exceptionCaught,
           "Failed to reject invalid IP address '" + valueString + '\'');
    }
  }



  /**
   * Tests validation with the provided set of test data when only IPv6
   * addresses are accepted.
   *
   * @param  valueString  The string to validate.
   * @param  isValid      Indicates whether the string represents a valid IP
   *                      address.
   * @param  isIPv6       Indicates whether the string represents an IPv6
   *                      address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testData")
  public void testValidateOnlyIPv6Accepted(final String valueString,
                                           final boolean isValid,
                                           final boolean isIPv6)
         throws Exception
  {
    final IPAddressArgumentValueValidator v =
         new IPAddressArgumentValueValidator(false, true);

    final StringArgument a = new StringArgument('a', "arg", "description");

    boolean exceptionCaught;
    try
    {
      v.validateArgumentValue(a, valueString);
      exceptionCaught = false;
    }
    catch (final ArgumentException ae)
    {
      exceptionCaught = true;
    }

    if (isValid)
    {
      if (! isIPv6)
      {
        assertTrue(exceptionCaught,
             "Failed to reject IPv4 address '" + valueString + '\'');
      }
      else
      {
        assertFalse(exceptionCaught,
             "Failed to accept valid IPv6 address '" + valueString + '\'');
      }
    }
    else
    {
      assertTrue(exceptionCaught,
           "Failed to reject invalid IP address '" + valueString + '\'');
    }
  }



  /**
   * Tests the {@code isValidNumericIPAddress} method.
   *
   * @param  valueString  The string to validate.
   * @param  isValid      Indicates whether the string represents a valid IP
   *                      address.
   * @param  isIPv6       Indicates whether the string represents an IPv6
   *                      address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testData")
  public void testIsValidNumericIPAddress(final String valueString,
                                          final boolean isValid,
                                          final boolean isIPv6)
         throws Exception
  {
    assertEquals(
         IPAddressArgumentValueValidator.isValidNumericIPAddress(valueString),
         isValid);

    if (isValid)
    {
      if (isIPv6)
      {
        assertFalse(IPAddressArgumentValueValidator.isValidNumericIPv4Address(
             valueString));
        assertTrue(IPAddressArgumentValueValidator.isValidNumericIPv6Address(
             valueString));
      }
      else
      {
        assertTrue(IPAddressArgumentValueValidator.isValidNumericIPv4Address(
             valueString));
        assertFalse(IPAddressArgumentValueValidator.isValidNumericIPv6Address(
             valueString));
      }
    }
    else
    {
      assertFalse(IPAddressArgumentValueValidator.isValidNumericIPv4Address(
           valueString));
      assertFalse(IPAddressArgumentValueValidator.isValidNumericIPv6Address(
           valueString));
    }
  }



  /**
   * Retrieves a set of test data.  Each element of the outer array will be an
   * array with the following three elements:
   * <OL>
   *   <LI>A string to validate</LI>
   *   <LI>A boolean indicating whether it's a valid IP address.</LI>
   *   <LI>A boolean indicating whether it's an IPv6 address.</LI>
   * </OL>
   *
   * @return  A set of test data.
   */
  @DataProvider(name = "testData")
  public Object[][] getTestData()
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
        "0.0.0.0",
        true,
        false
      },

      new Object[]
      {
        "1.2.3.4",
        true,
        false
      },

      new Object[]
      {
        "255.255.255.255",
        true,
        false
      },

      new Object[]
      {
        "123.456.789.101",
        false,
        false
      },

      new Object[]
      {
        "1..2..3..4",
        false,
        false
      },

      new Object[]
      {
        "1..23.4",
        false,
        false
      },

      new Object[]
      {
        "::",
        true,
        true
      },

      new Object[]
      {
        "::1",
        true,
        true
      },

      new Object[]
      {
        "ABCD:EF01:2345:6789:ABCD:EF01:2345:6789",
        true,
        true
      },

      new Object[]
      {
        "ABCD::EF01::2345::6789::ABCD::EF01::2345::6789",
        false,
        true
      },

      new Object[]
      {
        "0:0:0:0:0:0:0:1",
        true,
        true
      },

      new Object[]
      {
        "0:0:0:0:0:0:0:0",
        true,
        true
      },

      new Object[]
      {
        "FF01::101",
        true,
        true
      },

      new Object[]
      {
        "::13.1.68.3",
        true,
        true
      },

      new Object[]
      {
        "::1.2.3.4",
        true,
        true
      },

      new Object[]
      {
        "::1.2.3.4.5",
        false,
        true
      },

      new Object[]
      {
        "::123.456.789.101",
        false,
        true
      },

      new Object[]
      {
        "invalid",
        false,
        false
      },

      new Object[]
      {
        "i:n:v:a:l:i::d",
        false,
        false
      },

      new Object[]
      {
        "in.va.li.d",
        false,
        false
      },
    };
  }
}
