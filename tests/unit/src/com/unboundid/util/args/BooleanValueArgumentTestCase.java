/*
 * Copyright 2010-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2010-2017 UnboundID Corp.
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

import com.unboundid.util.UtilTestCase;



/**
 * This class provides test coverage for the BooleanValueArgument class.
 */
public class BooleanValueArgumentTestCase
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
    BooleanValueArgument a = new BooleanValueArgument('b',
         "booleanValueArg", "foo");
    a = a.getCleanCopy();

    assertNotNull(a);

    assertNotNull(a.getShortIdentifier());
    assertEquals(a.getShortIdentifier(), Character.valueOf('b'));

    assertNotNull(a.getLongIdentifier());
    assertEquals(a.getLongIdentifier(), "booleanValueArg");

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{true|false}");

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
    assertNotNull(newParser.getBooleanValueArgument(a.getIdentifierString()));

    assertNull(newParser.getBooleanValueArgument("--noSuchArgument"));
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
    BooleanValueArgument a = new BooleanValueArgument('b',
         "booleanValueArg", false, "{value}", "foo");
    a = a.getCleanCopy();

    assertNotNull(a);

    assertNotNull(a.getShortIdentifier());
    assertEquals(a.getShortIdentifier(), Character.valueOf('b'));

    assertNotNull(a.getLongIdentifier());
    assertEquals(a.getLongIdentifier(), "booleanValueArg");

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{value}");

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
    BooleanValueArgument a = new BooleanValueArgument('b',
         "booleanValueArg", true, "{value}", "foo", true);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertNotNull(a.getShortIdentifier());
    assertEquals(a.getShortIdentifier(), Character.valueOf('b'));

    assertNotNull(a.getLongIdentifier());
    assertEquals(a.getLongIdentifier(), "booleanValueArg");

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{value}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), Boolean.TRUE);

    assertNotNull(a.getDefaultValue());
    assertEquals(a.getDefaultValue(), Boolean.TRUE);

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
   * Tests the {@code addValue} method with valid Boolean values.
   *
   * @param  stringValue   The string value to be parsed.
   * @param  booleanValue  The expected boolean value for the given string
   *                       value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "validValues")
  public void testAddValueValid(final String stringValue,
                                final boolean booleanValue)
         throws Exception
  {
    BooleanValueArgument a = new BooleanValueArgument('b',
         "booleanValueArg", false, "{value}", "foo");
    a = a.getCleanCopy();
    assertNull(a.getValue());

    a.addValue(stringValue);

    assertNotNull(a.getValue());
    assertEquals(a.getValue(),  Boolean.valueOf(booleanValue));

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
    BooleanValueArgument a = new BooleanValueArgument('b',
         "booleanValueArg", false, "{value}", "foo");
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
      new Object[] { "true", true },
      new Object[] { "TRUE", true },
      new Object[] { "TrUe", true },
      new Object[] { "t", true },
      new Object[] { "t", true },
      new Object[] { "yes", true },
      new Object[] { "YES", true },
      new Object[] { "YeS", true },
      new Object[] { "y", true },
      new Object[] { "Y", true },
      new Object[] { "on", true },
      new Object[] { "ON", true },
      new Object[] { "oN", true },
      new Object[] { "1", true },

      new Object[] { "false", false },
      new Object[] { "FALSE", false },
      new Object[] { "FaLsE", false },
      new Object[] { "no", false },
      new Object[] { "NO", false },
      new Object[] { "No", false },
      new Object[] { "n", false },
      new Object[] { "N", false },
      new Object[] { "off", false },
      new Object[] { "OFF", false },
      new Object[] { "oFf", false },
      new Object[] { "0", false }
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
      new Object[] { " true" },
      new Object[] { "true " },
      new Object[] { " true " },
      new Object[] { "truea" },
      new Object[] { "ff" },
      new Object[] { "o" },
    };
  }
}
