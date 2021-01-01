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
import com.unboundid.ldap.sdk.LDAPURL;



/**
 * This class provides a set of test cases for the LDAP URL argument value
 * validator.
 */
public final class LDAPURLArgumentValueValidatorTestCase
       extends LDAPSDKTestCase
{
  // A number of validator instances to use in testing.
  private LDAPURLArgumentValueValidator requireNone;
  private LDAPURLArgumentValueValidator requireAll;
  private LDAPURLArgumentValueValidator requireHost;
  private LDAPURLArgumentValueValidator requirePort;
  private LDAPURLArgumentValueValidator requireBaseDN;
  private LDAPURLArgumentValueValidator requireAttributes;
  private LDAPURLArgumentValueValidator requireScope;
  private LDAPURLArgumentValueValidator requireFilter;

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
    requireNone = new LDAPURLArgumentValueValidator();
    assertFalse(requireNone.requireHost());
    assertFalse(requireNone.requirePort());
    assertFalse(requireNone.requireBaseDN());
    assertFalse(requireNone.requireAttributes());
    assertFalse(requireNone.requireScope());
    assertFalse(requireNone.requireFilter());
    assertNotNull(requireNone.toString());

    requireAll = new LDAPURLArgumentValueValidator(true, true, true, true, true,
         true);
    assertTrue(requireAll.requireHost());
    assertTrue(requireAll.requirePort());
    assertTrue(requireAll.requireBaseDN());
    assertTrue(requireAll.requireAttributes());
    assertTrue(requireAll.requireScope());
    assertTrue(requireAll.requireFilter());
    assertNotNull(requireAll.toString());

    requireHost = new LDAPURLArgumentValueValidator(true, false, false, false,
         false, false);
    assertTrue(requireHost.requireHost());
    assertFalse(requireHost.requirePort());
    assertFalse(requireHost.requireBaseDN());
    assertFalse(requireHost.requireAttributes());
    assertFalse(requireHost.requireScope());
    assertFalse(requireHost.requireFilter());
    assertNotNull(requireHost.toString());

    requirePort = new LDAPURLArgumentValueValidator(false, true, false, false,
         false, false);
    assertFalse(requirePort.requireHost());
    assertTrue(requirePort.requirePort());
    assertFalse(requirePort.requireBaseDN());
    assertFalse(requirePort.requireAttributes());
    assertFalse(requirePort.requireScope());
    assertFalse(requirePort.requireFilter());
    assertNotNull(requirePort.toString());

    requireBaseDN = new LDAPURLArgumentValueValidator(false, false, true, false,
         false, false);
    assertFalse(requireBaseDN.requireHost());
    assertFalse(requireBaseDN.requirePort());
    assertTrue(requireBaseDN.requireBaseDN());
    assertFalse(requireBaseDN.requireAttributes());
    assertFalse(requireBaseDN.requireScope());
    assertFalse(requireBaseDN.requireFilter());
    assertNotNull(requireBaseDN.toString());

    requireAttributes = new LDAPURLArgumentValueValidator(false, false, false,
         true, false, false);
    assertFalse(requireAttributes.requireHost());
    assertFalse(requireAttributes.requirePort());
    assertFalse(requireAttributes.requireBaseDN());
    assertTrue(requireAttributes.requireAttributes());
    assertFalse(requireAttributes.requireScope());
    assertFalse(requireAttributes.requireFilter());
    assertNotNull(requireAttributes.toString());

    requireScope = new LDAPURLArgumentValueValidator(false, false, false, false,
         true, false);
    assertFalse(requireScope.requireHost());
    assertFalse(requireScope.requirePort());
    assertFalse(requireScope.requireBaseDN());
    assertFalse(requireScope.requireAttributes());
    assertTrue(requireScope.requireScope());
    assertFalse(requireScope.requireFilter());
    assertNotNull(requireScope.toString());

    requireFilter = new LDAPURLArgumentValueValidator(false, false, false,
         false, false, true);
    assertFalse(requireFilter.requireHost());
    assertFalse(requireFilter.requirePort());
    assertFalse(requireFilter.requireBaseDN());
    assertFalse(requireFilter.requireAttributes());
    assertFalse(requireFilter.requireScope());
    assertTrue(requireFilter.requireFilter());
    assertNotNull(requireFilter.toString());

    arg = new StringArgument(null, "test", false, 1, "{value}", "Description");
  }




  /**
   * Tests the validator with the provided information.
   *
   * @param  value  The value to be tested.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testData")
  public void testValidator(final String value)
         throws Exception
  {
    // If the value isn't valid, then it'll always be rejected.
    final LDAPURL ldapURL;
    try
    {
      ldapURL = new LDAPURL(value);
      assertValid(requireNone, value);
    }
    catch (final Exception e)
    {
      assertInvalid(requireNone, value);
      assertInvalid(requireAll, value);
      assertInvalid(requireHost, value);
      assertInvalid(requirePort, value);
      assertInvalid(requireBaseDN, value);
      assertInvalid(requireAttributes, value);
      assertInvalid(requireScope, value);
      assertInvalid(requireFilter, value);
      return;
    }

    if (ldapURL.hostProvided())
    {
      assertValid(requireHost, value);
    }
    else
    {
      assertInvalid(requireHost, value);
    }

    if (ldapURL.portProvided())
    {
      assertValid(requirePort, value);
    }
    else
    {
      assertInvalid(requirePort, value);
    }

    if (ldapURL.baseDNProvided())
    {
      assertValid(requireBaseDN, value);
    }
    else
    {
      assertInvalid(requireBaseDN, value);
    }

    if (ldapURL.attributesProvided())
    {
      assertValid(requireAttributes, value);
    }
    else
    {
      assertInvalid(requireAttributes, value);
    }

    if (ldapURL.scopeProvided())
    {
      assertValid(requireScope, value);
    }
    else
    {
      assertInvalid(requireScope, value);
    }

    if (ldapURL.filterProvided())
    {
      assertValid(requireFilter, value);
    }
    else
    {
      assertInvalid(requireFilter, value);
    }

    if (ldapURL.hostProvided() && ldapURL.portProvided() &&
        ldapURL.baseDNProvided() && ldapURL.attributesProvided() &&
        ldapURL.scopeProvided() && ldapURL.filterProvided())
    {
      assertValid(requireAll, value);
    }
    else
    {
      assertInvalid(requireAll, value);
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
        ""
      },

      new Object[]
      {
        "invalid"
      },

      new Object[]
      {
        "invalid://"
      },

      new Object[]
      {
        "ldap://"
      },

      new Object[]
      {
        "ldap://ds.example.com"
      },

      new Object[]
      {
        "ldap://:389"
      },

      new Object[]
      {
        "ldap:///dc=example,dc=com"
      },

      new Object[]
      {
        "ldap:///?givenName"
      },

      new Object[]
      {
        "ldap:///?givenName,sn"
      },

      new Object[]
      {
        "ldap:///??base"
      },

      new Object[]
      {
        "ldap:///???(objectClass=*)"
      },

      new Object[]
      {
        "ldap://ds.example.com:389/dc=example,dc=com?givenName,sn?base?" +
             "(objectClass=*)"
      },
    };
  }



  /**
   * Ensures that the provided value is valid for the provided validator.
   *
   * @param  validator  The validator to use.
   * @param  value      The value to validate.
   */
  private void assertValid(final LDAPURLArgumentValueValidator validator,
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
  private void assertInvalid(final LDAPURLArgumentValueValidator validator,
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
