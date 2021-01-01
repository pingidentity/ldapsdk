/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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

import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the DNS host name argument value
 * validator.
 */
public final class DNSHostNameArgumentValueValidatorTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when testing host name validation with the default
   * settings when performing validation with an argument.
   *
   * @param  hostName          The host name to validate.
   * @param  isMinimallyValid  Indicates whether the provided host name is valid
   *                           when performing the default, minimal set of
   *                           validation.
   * @param  isIPAddress       Indicates whether the provided host name is
   *                           actually an IP address.
   * @param  isFullyQualified  Indicates whether the provided host name is
   *                           fully qualified.
   * @param  isResolvable      Indicates whether the provided host name is
   *                           expected to be resolvable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testHostNames")
  public void testDefaultValidationWithArgument(final String hostName,
                                                final boolean isMinimallyValid,
                                                final boolean isIPAddress,
                                                final boolean isFullyQualified,
                                                final boolean isResolvable)
         throws Exception
  {
    final DNSHostNameArgumentValueValidator validator =
         new DNSHostNameArgumentValueValidator();

    assertTrue(validator.allowIPAddresses());

    assertTrue(validator.allowUnqualifiedNames());

    assertTrue(validator.allowUnresolvableNames());

    assertNotNull(validator.getNameResolver());

    assertNotNull(validator.toString());

    final StringArgument argument =
         new StringArgument('h', "hostname", false, 1, "{hostname}",
              "A host name");
    argument.addValueValidator(validator);

    try
    {
      argument.addValue(hostName);
      assertTrue(isMinimallyValid);
    }
    catch (final ArgumentException e)
    {
      assertFalse(isMinimallyValid);
    }
  }



  /**
   * Tests the behavior when testing host name validation with the default
   * settings when performing validation without an argument.
   *
   * @param  hostName          The host name to validate.
   * @param  isMinimallyValid  Indicates whether the provided host name is valid
   *                           when performing the default, minimal set of
   *                           validation.
   * @param  isIPAddress       Indicates whether the provided host name is
   *                           actually an IP address.
   * @param  isFullyQualified  Indicates whether the provided host name is
   *                           fully qualified.
   * @param  isResolvable      Indicates whether the provided host name is
   *                           expected to be resolvable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testHostNames")
  public void testDefaultValidationWithoutArgument(final String hostName,
                   final boolean isMinimallyValid,
                   final boolean isIPAddress,
                   final boolean isFullyQualified,
                   final boolean isResolvable)
         throws Exception
  {
    try
    {
      DNSHostNameArgumentValueValidator.validateDNSHostName(hostName);
      assertTrue(isMinimallyValid);
    }
    catch (final ArgumentException e)
    {
      assertFalse(isMinimallyValid);
    }
  }



  /**
   * Tests the behavior when testing host name validation when IP addresses will
   * not be accepted.
   *
   * @param  hostName          The host name to validate.
   * @param  isMinimallyValid  Indicates whether the provided host name is valid
   *                           when performing the default, minimal set of
   *                           validation.
   * @param  isIPAddress       Indicates whether the provided host name is
   *                           actually an IP address.
   * @param  isFullyQualified  Indicates whether the provided host name is
   *                           fully qualified.
   * @param  isResolvable      Indicates whether the provided host name is
   *                           expected to be resolvable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testHostNames")
  public void testDoNotAcceptIPAddresses(final String hostName,
                                         final boolean isMinimallyValid,
                                         final boolean isIPAddress,
                                         final boolean isFullyQualified,
                                         final boolean isResolvable)
         throws Exception
  {
    final DNSHostNameArgumentValueValidator validator =
         new DNSHostNameArgumentValueValidator(false, true, true,
              LDAPConnectionOptions.DEFAULT_NAME_RESOLVER);

    assertFalse(validator.allowIPAddresses());

    assertTrue(validator.allowUnqualifiedNames());

    assertTrue(validator.allowUnresolvableNames());

    assertNotNull(validator.getNameResolver());

    assertNotNull(validator.toString());

    final StringArgument argument =
         new StringArgument('h', "hostname", false, 1, "{hostname}",
              "A host name");
    argument.addValueValidator(validator);

    try
    {
      argument.addValue(hostName);
      assertTrue(isMinimallyValid);
      assertFalse(isIPAddress);
    }
    catch (final ArgumentException e)
    {
      if (isMinimallyValid)
      {
        assertTrue(isIPAddress);
      }
    }
  }



  /**
   * Tests the behavior when testing host name validation when unqualified names
   * will not be accepted.
   *
   * @param  hostName          The host name to validate.
   * @param  isMinimallyValid  Indicates whether the provided host name is valid
   *                           when performing the default, minimal set of
   *                           validation.
   * @param  isIPAddress       Indicates whether the provided host name is
   *                           actually an IP address.
   * @param  isFullyQualified  Indicates whether the provided host name is
   *                           fully qualified.
   * @param  isResolvable      Indicates whether the provided host name is
   *                           expected to be resolvable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testHostNames")
  public void testDoNotAcceptUnqualifiedNames(final String hostName,
                                              final boolean isMinimallyValid,
                                              final boolean isIPAddress,
                                              final boolean isFullyQualified,
                                              final boolean isResolvable)
         throws Exception
  {
    final DNSHostNameArgumentValueValidator validator =
         new DNSHostNameArgumentValueValidator(true, false, true, null);

    assertTrue(validator.allowIPAddresses());

    assertFalse(validator.allowUnqualifiedNames());

    assertTrue(validator.allowUnresolvableNames());

    assertNotNull(validator.getNameResolver());

    assertNotNull(validator.toString());

    final StringArgument argument =
         new StringArgument('h', "hostname", false, 1, "{hostname}",
              "A host name");
    argument.addValueValidator(validator);

    try
    {
      argument.addValue(hostName);
      assertTrue(isMinimallyValid);
      assertTrue(isFullyQualified);
    }
    catch (final ArgumentException e)
    {
      if (isMinimallyValid)
      {
        assertFalse(isFullyQualified);
      }
    }
  }



  /**
   * Tests the behavior when testing host name validation when unresolvable
   * names will not be accepted.
   *
   * @param  hostName          The host name to validate.
   * @param  isMinimallyValid  Indicates whether the provided host name is valid
   *                           when performing the default, minimal set of
   *                           validation.
   * @param  isIPAddress       Indicates whether the provided host name is
   *                           actually an IP address.
   * @param  isFullyQualified  Indicates whether the provided host name is
   *                           fully qualified.
   * @param  isResolvable      Indicates whether the provided host name is
   *                           expected to be resolvable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testHostNames")
  public void testDoNotAcceptUnresolvableNames(final String hostName,
                                               final boolean isMinimallyValid,
                                               final boolean isIPAddress,
                                               final boolean isFullyQualified,
                                               final boolean isResolvable)
         throws Exception
  {
    final DNSHostNameArgumentValueValidator validator =
         new DNSHostNameArgumentValueValidator(true, true, false,
              LDAPConnectionOptions.DEFAULT_NAME_RESOLVER);

    assertTrue(validator.allowIPAddresses());

    assertTrue(validator.allowUnqualifiedNames());

    assertFalse(validator.allowUnresolvableNames());

    assertNotNull(validator.getNameResolver());

    assertNotNull(validator.toString());

    final StringArgument argument =
         new StringArgument('h', "hostname", false, 1, "{hostname}",
              "A host name");
    argument.addValueValidator(validator);

    try
    {
      argument.addValue(hostName);
      assertTrue(isMinimallyValid);
      assertTrue(isResolvable);
    }
    catch (final ArgumentException e)
    {
      if (isMinimallyValid)
      {
        assertFalse(isResolvable);
      }
    }
  }



  /**
   * Tests the behavior when testing host name validation when unresolvable
   * names will not be accepted and a {@code null} resolver is provided.
   *
   * @param  hostName          The host name to validate.
   * @param  isMinimallyValid  Indicates whether the provided host name is valid
   *                           when performing the default, minimal set of
   *                           validation.
   * @param  isIPAddress       Indicates whether the provided host name is
   *                           actually an IP address.
   * @param  isFullyQualified  Indicates whether the provided host name is
   *                           fully qualified.
   * @param  isResolvable      Indicates whether the provided host name is
   *                           expected to be resolvable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testHostNames")
  public void testDoNotAcceptUnresolvableNamesWithNullResolver(
                   final String hostName,
                   final boolean isMinimallyValid,
                   final boolean isIPAddress,
                   final boolean isFullyQualified,
                   final boolean isResolvable)
         throws Exception
  {
    try
    {
      DNSHostNameArgumentValueValidator.validateDNSHostName(hostName, true,
           true, false, null);
      assertTrue(isMinimallyValid);
      assertTrue(isResolvable);
    }
    catch (final ArgumentException e)
    {
      if (isMinimallyValid)
      {
        assertFalse(isResolvable);
      }
    }
  }



  /**
   * Retrieves a set of data that can be used for testing host name validation.
   *
   * @return  A set of data that can be used for testing host name validation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="testHostNames")
  public Object[][] getTestHostNames()
         throws Exception
  {
    return new Object[][]
    {
      // Null host names are never valid.
      new Object[]
      {
        null, // The host name
        false, // Is minimally valid
        false, // Is IP address
        false, // Is fully qualified
        false  // Is resolvable
      },

      // Empty host names are never valid.
      new Object[]
      {
        "", // The host name
        false, // Is minimally valid
        false, // Is IP address
        false, // Is fully qualified
        false  // Is resolvable
      },

      // A valid, fully qualified, resolvable host name.
      new Object[]
      {
        "www.pingidentity.com",  // The host name
        true, // Is minimally valid
        false, // Is IP address
        true, // Is fully qualified
        true  // Is resolvable
      },

      // A valid, fully qualified, resolvable host name that includes uppercase
      // letters.
      new Object[]
      {
        "WWW.PingIdentity.com",  // The host name
        true, // Is minimally valid
        false, // Is IP address
        true, // Is fully qualified
        true  // Is resolvable
      },

      // A valid, fully qualified, resolvable host name that ends with a period.
      new Object[]
      {
        "www.pingidentity.com.",  // The host name
        true, // Is minimally valid
        false, // Is IP address
        true, // Is fully qualified
        true  // Is resolvable
      },

      // A valid, fully qualified host name that represents the root label.
      new Object[]
      {
        ".",  // The host name
        true, // Is minimally valid
        false, // Is IP address
        true, // Is fully qualified
        false  // Is resolvable
      },

      // A valid, unqualified, resolvable host name.
      new Object[]
      {
        "localhost", // The host name
        true, // Is minimally valid
        false, // Is IP address
        false, // Is fully qualified
        true  // Is resolvable
      },

      // A valid IP address.
      new Object[]
      {
        "1.2.3.4", // The host name
        true, // Is minimally valid
        true, // Is IP address
        true, // Is fully qualified
        true  // Is resolvable
      },

      // A valid, fully qualified, unresolvable host name.
      new Object[]
      {
        "unresolvable.example.com", // The host name
        true, // Is minimally valid
        false, // Is IP address
        true, // Is fully qualified
        false  // Is resolvable
      },

      // A host name with an initial period.
      new Object[]
      {
        ".example.com", // The host name
        false, // Is minimally valid
        false, // Is IP address
        true, // Is fully qualified
        false  // Is resolvable
      },

      // A host name with consecutive periods.
      new Object[]
      {
        "www..example.com", // The host name
        false, // Is minimally valid
        false, // Is IP address
        true, // Is fully qualified
        false  // Is resolvable
      },

      // A valid (but unresolvable) host name with the longest allowed component
      // name.
      new Object[]
      {
        "a234567890b234567890c234567890d234567890e234567890f234567890g23." +
             "example.com", // The host name
        true, // Is minimally valid
        false, // Is IP address
        true, // Is fully qualified
        false  // Is resolvable
      },

      // A host name with a component that is too long.
      new Object[]
      {
        "a234567890b234567890c234567890d234567890e234567890f234567890g234." +
             "example.com", // The host name
        false, // Is minimally valid
        false, // Is IP address
        true, // Is fully qualified
        false  // Is resolvable
      },

      // A host name with the longest acceptable length.
      new Object[]
      {
        "a234567890b234567890c234567890d234567890e234567890." + // The host name
             "a234567890b234567890c234567890d234567890e234567890." +
             "a234567890b234567890c234567890d234567890e234567890." +
             "a234567890b234567890c234567890d234567890e234567890." +
             "a234567890b234567890c234567890d23456789.example.com",
        true, // Is minimally valid
        false, // Is IP address
        true, // Is fully qualified
        false  // Is resolvable
      },

      // A host name that is too long.
      new Object[]
      {
        "a234567890b234567890c234567890d234567890e234567890." + // The host name
             "a234567890b234567890c234567890d234567890e234567890." +
             "a234567890b234567890c234567890d234567890e234567890." +
             "a234567890b234567890c234567890d234567890e234567890." +
             "a234567890b234567890c234567890d234567890.example.com",
        false, // Is minimally valid
        false, // Is IP address
        true, // Is fully qualified
        false  // Is resolvable
      },

      // A host name with an initial component that starts with a dash.
      new Object[]
      {
        "-123.example.com",
        false, // Is minimally valid
        false, // Is IP address
        true, // Is fully qualified
        false  // Is resolvable
      },

      // A host name with a subsequent component that starts with a dash.
      new Object[]
      {
        "abc.-123.example.com",
        false, // Is minimally valid
        false, // Is IP address
        true, // Is fully qualified
        false  // Is resolvable
      },

      // A host name with a component that contains a dash as a subsequent
      // character.
      new Object[]
      {
        "abc-123.example.com",
        true, // Is minimally valid
        false, // Is IP address
        true, // Is fully qualified
        false  // Is resolvable
      },

      // A host name with a subsequent component that starts with a dash.
      new Object[]
      {
        "abc.-123.example.com",
        false, // Is minimally valid
        false, // Is IP address
        true, // Is fully qualified
        false  // Is resolvable
      },

      // A host name with an initial component that starts with a digit.
      new Object[]
      {
        "123.example.com",
        true, // Is minimally valid
        false, // Is IP address
        true, // Is fully qualified
        false  // Is resolvable
      },

      // A host name with a subsequent component that starts with a digit.
      new Object[]
      {
        "abc.123.example.com",
        true, // Is minimally valid
        false, // Is IP address
        true, // Is fully qualified
        false  // Is resolvable
      },

      // A host name that contains a space.
      new Object[]
      {
        "host name.example.com",
        false, // Is minimally valid
        false, // Is IP address
        true, // Is fully qualified
        false  // Is resolvable
      },

      // A host name that contains a non-ASCII character.
      new Object[]
      {
        "host\u00f1ame.example.com",
        false, // Is minimally valid
        false, // Is IP address
        true, // Is fully qualified
        false  // Is resolvable
      },
    };
  }
}
