/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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

import com.unboundid.util.UtilTestCase;



/**
 * This class provides test coverage for the Argument class.
 */
public class ArgumentTestCase
       extends UtilTestCase
{
  /**
   * Tests an attempt to create an argument with a short identifier but no long
   * identifier.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyShortIdentifier()
         throws Exception
  {
    BooleanArgument a = new BooleanArgument('b', null, "foo");

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('b'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('b'));

    assertFalse(a.hasLongIdentifier());

    assertNull(a.getLongIdentifier());

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 0);

    assertEquals(a.getIdentifierString(), "-b");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertFalse(a.takesValue());

    assertNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());
  }



  /**
   * Tests an attempt to create an argument with a long identifier but no short
   * identifier.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyLongIdentifier()
         throws Exception
  {
    BooleanArgument a = new BooleanArgument(null, "booleanArg", "foo");

    assertNotNull(a);

    assertFalse(a.hasShortIdentifier());

    assertNull(a.getShortIdentifier());

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 0);

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "booleanArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "booleanArg");

    assertEquals(a.getIdentifierString(), "--booleanArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertFalse(a.takesValue());

    assertNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());
  }



  /**
   * Tests an attempt to create an argument with neither short nor long
   * identifiers.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class})
  public void testNeitherShortNorLongIdentifier()
         throws Exception
  {
    new BooleanArgument(null, null, "foo");
  }



  /**
   * Tests ability to create a required argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateRequiredArgument()
         throws Exception
  {
    StringArgument a = new StringArgument('s', "stringArg", true, 1, "{value}",
                                          "foo");

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('s'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('s'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "stringArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "stringArg");

    assertEquals(a.getIdentifierString(), "--stringArg");

    assertTrue(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{value}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());
  }



  /**
   * Tests ability to create a non-required argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateNonRequiredArgument()
         throws Exception
  {
    StringArgument a = new StringArgument('s', "stringArg", false, 1, "{value}",
                                          "foo");

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('s'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('s'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "stringArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "stringArg");

    assertEquals(a.getIdentifierString(), "--stringArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{value}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());
  }



  /**
   * Tests ability to create an argument with a positive maxOccurrences.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateArgumentWithPositiveMaxOccurrences()
         throws Exception
  {
    StringArgument a = new StringArgument('s', "stringArg", true, 5, "{value}",
                                          "foo");

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('s'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('s'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "stringArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "stringArg");

    assertEquals(a.getIdentifierString(), "--stringArg");

    assertTrue(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 5);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{value}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());
  }



  /**
   * Tests ability to create an argument with zero maxOccurrences.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateArgumentWithZeroMaxOccurrences()
         throws Exception
  {
    StringArgument a = new StringArgument('s', "stringArg", true, 0, "{value}",
                                          "foo");

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('s'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('s'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "stringArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "stringArg");

    assertEquals(a.getIdentifierString(), "--stringArg");

    assertTrue(a.isRequired());

    assertEquals(a.getMaxOccurrences(), Integer.MAX_VALUE);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{value}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());
  }



  /**
   * Tests ability to create an argument with a negative maxOccurrences.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateArgumentWithNegativeMaxOccurrences()
         throws Exception
  {
    StringArgument a = new StringArgument('s', "stringArg", true, -1, "{value}",
                                          "foo");

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('s'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('s'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "stringArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "stringArg");

    assertEquals(a.getIdentifierString(), "--stringArg");

    assertTrue(a.isRequired());

    assertEquals(a.getMaxOccurrences(), Integer.MAX_VALUE);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{value}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());
  }



  /**
   * Tests ability to set a positive maxOccurrences value after the fact.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetPositiveMaxOccurrences()
         throws Exception
  {
    BooleanArgument a = new BooleanArgument('b', "booleanArg", "foo");

    assertEquals(a.getMaxOccurrences(), 1);

    a.setMaxOccurrences(5);

    assertEquals(a.getMaxOccurrences(), 5);
  }



  /**
   * Tests ability to set a zero maxOccurrences value after the fact.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetZeroMaxOccurrences()
         throws Exception
  {
    BooleanArgument a = new BooleanArgument('b', "booleanArg", "foo");

    assertEquals(a.getMaxOccurrences(), 1);

    a.setMaxOccurrences(0);

    assertEquals(a.getMaxOccurrences(), Integer.MAX_VALUE);
  }



  /**
   * Tests ability to set a negative maxOccurrences value after the fact.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetNegativeMaxOccurrences()
         throws Exception
  {
    BooleanArgument a = new BooleanArgument('b', "booleanArg", "foo");

    assertEquals(a.getMaxOccurrences(), 1);

    a.setMaxOccurrences(-1);

    assertEquals(a.getMaxOccurrences(), Integer.MAX_VALUE);
  }



  /**
   * Tests an attempt to create an argument with a {@code null} description.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class})
  public void testNullDescription()
         throws Exception
  {
    new BooleanArgument('b', "--booleanArg", null);
  }



  /**
   * Tests the ability to have multiple short identifiers.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleShortIdentifiers()
         throws Exception
  {
    BooleanArgument a = new BooleanArgument('b', "booleanArg", "foo");

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('b'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('b'));

    assertFalse(a.isRegistered());

    a.addShortIdentifier('B');

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('b'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 2);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('b'));
    assertEquals(a.getShortIdentifiers().get(1), Character.valueOf('B'));

    a.setRegistered();

    assertTrue(a.isRegistered());

    try
    {
      a.addShortIdentifier('x');
      fail("Expected an exception when adding an identifier to a registered " +
           "argument");
    } catch (ArgumentException ae) {}
  }



  /**
   * Tests the ability to have multiple long identifiers.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleLongIdentifiers()
         throws Exception
  {
    BooleanArgument a = new BooleanArgument('b', "booleanArg", "foo");

    assertNotNull(a);

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "booleanArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "booleanArg");

    assertEquals(a.getIdentifierString(), "--booleanArg");

    assertFalse(a.isRegistered());

    a.addLongIdentifier("booleanArg2");

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "booleanArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 2);
    assertEquals(a.getLongIdentifiers().get(0), "booleanArg");
    assertEquals(a.getLongIdentifiers().get(1), "booleanArg2");

    assertEquals(a.getIdentifierString(), "--booleanArg");

    a.setRegistered();

    assertTrue(a.isRegistered());

    try
    {
      a.addLongIdentifier("xxx");
      fail("Expected an exception when adding an identifier to a registered " +
           "argument");
    } catch (ArgumentException ae) {}
  }



  /**
   * Tests ability to set an argument to be hidden.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHidden()
         throws Exception
  {
    BooleanArgument a = new BooleanArgument('b', "booleanArg", "foo");

    assertFalse(a.isHidden());

    a.setHidden(true);

    assertTrue(a.isHidden());

    a.setHidden(false);

    assertFalse(a.isHidden());
  }



  /**
   * Tests ability to get and update the number of occurrences.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNumOccurrences()
         throws Exception
  {
    BooleanArgument a = new BooleanArgument('b', "booleanArg", "foo");

    assertEquals(a.getNumOccurrences(), 0);

    a.incrementOccurrences();

    assertEquals(a.getNumOccurrences(), 1);

    try
    {
      a.incrementOccurrences();
      fail("Expected an exception when setting num occurrences too high.");
    }
    catch (ArgumentException ae) {}
  }



  /**
   * Tests ability to handle registering arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRegister()
         throws Exception
  {
    BooleanArgument a = new BooleanArgument('b', "booleanArg", "foo");

    assertFalse(a.isRegistered());

    a.setRegistered();

    assertTrue(a.isRegistered());

    try
    {
      a.setRegistered();
      fail("Expected an exception when registering multiple times.");
    } catch (ArgumentException ae) {}
  }
}
