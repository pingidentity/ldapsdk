/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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

import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.UtilTestCase;



/**
 * This class provides test coverage for the ScopeArgument class.
 */
public class ScopeArgumentTestCase
       extends UtilTestCase
{
  /**
   * Tests the minimal constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalConstructor()
         throws Exception
  {
    ScopeArgument a = new ScopeArgument('s', "scopeArg", "foo");
    a = a.getCleanCopy();

    assertNotNull(a);

    assertNotNull(a.getShortIdentifier());
    assertEquals(a.getShortIdentifier(), Character.valueOf('s'));

    assertNotNull(a.getLongIdentifier());
    assertEquals(a.getLongIdentifier(), "scopeArg");

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{base|one|sub|subordinates}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertNull(a.getValue());

    assertNull(a.getDefaultValue());

    assertFalse(a.isRequired());

    assertFalse(a.isPresent());

    assertFalse(a.isHidden());

    assertFalse(a.isRegistered());

    assertFalse(a.isUsageArgument());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());

    final ArgumentParser newParser = new ArgumentParser("test", "test");
    newParser.addArgument(a);
    assertNotNull(newParser.getScopeArgument(a.getIdentifierString()));

    assertNull(newParser.getScopeArgument("--noSuchArgument"));
  }



  /**
   * Tests the constructor without a default value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithoutDefault()
         throws Exception
  {
    ScopeArgument a = new ScopeArgument('s', "scopeArg", true, "{scope}",
         "foo");
    a = a.getCleanCopy();

    assertNotNull(a);

    assertNotNull(a.getShortIdentifier());
    assertEquals(a.getShortIdentifier(), Character.valueOf('s'));

    assertNotNull(a.getLongIdentifier());
    assertEquals(a.getLongIdentifier(), "scopeArg");

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{scope}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertNull(a.getValue());

    assertNull(a.getDefaultValue());

    assertTrue(a.isRequired());

    assertFalse(a.isPresent());

    assertFalse(a.isHidden());

    assertFalse(a.isRegistered());

    assertFalse(a.isUsageArgument());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the constructor with a default value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithDefault()
         throws Exception
  {
    ScopeArgument a = new ScopeArgument('s', "scopeArg", true, "{scope}",
         "foo", SearchScope.BASE);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertNotNull(a.getShortIdentifier());
    assertEquals(a.getShortIdentifier(), Character.valueOf('s'));

    assertNotNull(a.getLongIdentifier());
    assertEquals(a.getLongIdentifier(), "scopeArg");

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{scope}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), SearchScope.BASE);

    assertNotNull(a.getDefaultValue());
    assertEquals(a.getDefaultValue(), SearchScope.BASE);

    assertTrue(a.isRequired());

    assertTrue(a.isPresent());

    assertFalse(a.isHidden());

    assertFalse(a.isRegistered());

    assertFalse(a.isUsageArgument());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the {@code addValue} method with valid scope strings.
   *
   * @param  stringValue    The string value to be parsed.
   * @param  expectedScope  The expected scope for the given string value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "validValues")
  public void testAddValueValid(final String stringValue,
                                final SearchScope expectedScope)
         throws Exception
  {
    ScopeArgument a = new ScopeArgument('s', "scopeArg", false, "{scope}",
         "foo");
    a = a.getCleanCopy();
    assertNull(a.getValue());

    a.addValue(stringValue);

    assertNotNull(a.getValue());
    assertEquals(a.getValue(),  expectedScope);

    try
    {
      // Verify that we can't add another value.
      a.addValue(stringValue);
      fail("Expected an exception when trying to add a second value.");
    }
    catch (final ArgumentException ae)
    {
      // This was expected.
    }

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the {@code addValue} method with an invalid value.
   *
   * @param  stringValue  The invalid string value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "invalidValues",
        expectedExceptions = { ArgumentException.class })
  public void testAddValueValid(final String stringValue)
         throws Exception
  {
    ScopeArgument a = new ScopeArgument('s', "scopeArg", false, "{scope}",
         "foo");
    a = a.getCleanCopy();
    assertNull(a.getValue());

    a.addValue(stringValue);
  }



  /**
   * Retrieves a set of valid values that may be used for testing.
   *
   * @return  A set of valid values that may be used for testing.
   */
  @DataProvider(name = "validValues")
  public Object[][] getValidValues()
  {
    return new Object[][]
    {
      new Object[] { "base", SearchScope.BASE },
      new Object[] { "baseObject", SearchScope.BASE },
      new Object[] { "baseobject", SearchScope.BASE },
      new Object[] { "base-object", SearchScope.BASE },
      new Object[] { "0", SearchScope.BASE },

      new Object[] { "one", SearchScope.ONE },
      new Object[] { "singleLevel", SearchScope.ONE },
      new Object[] { "singlelevel", SearchScope.ONE },
      new Object[] { "single-level", SearchScope.ONE },
      new Object[] { "oneLevel", SearchScope.ONE },
      new Object[] { "onelevel", SearchScope.ONE },
      new Object[] { "one-level", SearchScope.ONE },
      new Object[] { "1", SearchScope.ONE },

      new Object[] { "sub", SearchScope.SUB },
      new Object[] { "subtree", SearchScope.SUB },
      new Object[] { "wholeSubtree", SearchScope.SUB },
      new Object[] { "wholesubtree", SearchScope.SUB },
      new Object[] { "whole-subtree", SearchScope.SUB },
      new Object[] { "2", SearchScope.SUB },

      new Object[] { "subord", SearchScope.SUBORDINATE_SUBTREE },
      new Object[] { "subordinate", SearchScope.SUBORDINATE_SUBTREE },
      new Object[] { "subordinateSubtree", SearchScope.SUBORDINATE_SUBTREE },
      new Object[] { "subordinatesubtree", SearchScope.SUBORDINATE_SUBTREE },
      new Object[] { "subordinate-subtree", SearchScope.SUBORDINATE_SUBTREE },
      new Object[] { "3", SearchScope.SUBORDINATE_SUBTREE }
    };
  }



  /**
   * Retrieves a set of invalid values that may be used for testing.
   *
   * @return  A set of invalid values that may be used for testing.
   */
  @DataProvider(name = "invalidValues")
  public Object[][] getInvalidValues()
  {
    return new Object[][]
    {
      new Object[] { "" },
      new Object[] { " " },
      new Object[] { "foo" },
      new Object[] { " base" },
      new Object[] { "base " },
      new Object[] { " base " },
      new Object[] { "basea" }
    };
  }
}
