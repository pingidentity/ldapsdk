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
 * This class provides test coverage for the BooleanArgument class.
 */
public class BooleanArgumentTestCase
       extends UtilTestCase
{
  /**
   * Tests the first constructor with a valid invocation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Valid()
         throws Exception
  {
    BooleanArgument a = new BooleanArgument('b', "booleanArg", "foo");
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('b'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('b'));

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

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());

    final ArgumentParser newParser = new ArgumentParser("test", "test");
    newParser.addArgument(a);
    assertNotNull(newParser.getBooleanArgument(a.getIdentifierString()));

    assertNull(newParser.getBooleanArgument("--noSuchArgument"));
  }



  /**
   * Tests the second constructor with a valid invocation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Valid()
         throws Exception
  {
    BooleanArgument a = new BooleanArgument('b', "booleanArg", 3, "foo");
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('b'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('b'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "booleanArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "booleanArg");

    assertEquals(a.getIdentifierString(), "--booleanArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 3);

    assertFalse(a.takesValue());

    assertNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Ensures that attempts to call {@code addValue} will throw an exception.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddValue()
         throws Exception
  {
    BooleanArgument a = new BooleanArgument('b', "booleanArg", "foo");
    a = a.getCleanCopy();
    a.addValue("true");
  }
}
