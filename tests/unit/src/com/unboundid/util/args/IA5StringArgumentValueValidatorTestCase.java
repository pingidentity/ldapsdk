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



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the IA5 string argument value
 * validator.
 */
public final class IA5StringArgumentValueValidatorTestCase
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
    final IA5StringArgumentValueValidator v =
         new IA5StringArgumentValueValidator();

    assertFalse(v.allowEmptyStrings());

    assertNotNull(v.toString());
    assertFalse(v.toString().isEmpty());


    final StringArgument arg =
         new StringArgument(null, "ia5String", true, 1, "{value}",
              "A test IA5 String.");

    try
    {
      v.validateArgumentValue(arg, "");
      fail("Expected an exception when validating an empty value.");
    }
    catch (final ArgumentException e)
    {
      // This is expected.
    }

    v.validateArgumentValue(arg, "this is a valid IA5 string");

    try
    {
      v.validateArgumentValue(arg, "jalape\u00f1o");
      fail("Expected an exception when validating a value with non-ASCII " +
           "characters.");
    }
    catch (final ArgumentException e)
    {
      // This is expected.
    }

    assertNotNull(v.toString());
  }



  /**
   * Tests the behavior of the non-default constructor that is configured to
   * allow empty strings.
   *
   * @throws Exception If an unexpected problem occurs.
   */
  @Test()
  public void testAllowEmptyStrings()
       throws Exception
  {
    final IA5StringArgumentValueValidator v =
         new IA5StringArgumentValueValidator(true);

    assertTrue(v.allowEmptyStrings());

    assertNotNull(v.toString());
    assertFalse(v.toString().isEmpty());


    final StringArgument arg =
         new StringArgument(null, "ia5String", true, 1, "{value}",
              "A test IA5 String.");

    v.validateArgumentValue(arg, "");

    v.validateArgumentValue(arg, "this is a valid IA5 string");

    try
    {
      v.validateArgumentValue(arg, "jalape\u00f1o");
      fail("Expected an exception when validating a value with non-ASCII " +
           "characters.");
    }
    catch (final ArgumentException e)
    {
      // This is expected.
    }

    assertNotNull(v.toString());
  }
}
