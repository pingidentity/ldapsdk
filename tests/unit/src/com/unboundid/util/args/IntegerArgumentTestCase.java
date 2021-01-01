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



import java.util.ArrayList;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.util.UtilTestCase;



/**
 * This class provides test coverage for the IntegerArgument class.
 */
public class IntegerArgumentTestCase
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
    IntegerArgument a = new IntegerArgument('i', "intArg", "foo");
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('i'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('i'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "intArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "intArg");

    assertEquals(a.getIdentifierString(), "--intArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertEquals(a.getLowerBound(), Integer.MIN_VALUE);

    assertEquals(a.getUpperBound(), Integer.MAX_VALUE);

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());

    final ArgumentParser newParser = new ArgumentParser("test", "test");
    newParser.addArgument(a);
    assertNotNull(newParser.getIntegerArgument(a.getIdentifierString()));

    assertNull(newParser.getIntegerArgument("--noSuchArgument"));
  }



  /**
   * Tests the first constructor with a valid invocation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Valid()
         throws Exception
  {
    IntegerArgument a = new IntegerArgument('i', "intArg", false, 1,
                                            "{int}", "foo");
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('i'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('i'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "intArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "intArg");

    assertEquals(a.getIdentifierString(), "--intArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertEquals(a.getLowerBound(), Integer.MIN_VALUE);

    assertEquals(a.getUpperBound(), Integer.MAX_VALUE);

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
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
    IntegerArgument a = new IntegerArgument('i', "intArg", false, 1,
                                            "{int}", "foo", 0,
                                            Integer.MAX_VALUE);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('i'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('i'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "intArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "intArg");

    assertEquals(a.getIdentifierString(), "--intArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertEquals(a.getLowerBound(), 0);

    assertEquals(a.getUpperBound(), Integer.MAX_VALUE);

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the third constructor with a {@code null} default value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NullDefaultValue()
         throws Exception
  {
    IntegerArgument a = new IntegerArgument('i', "intArg", false, 1,
                                            "{int}", "foo", (Integer) null);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('i'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('i'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "intArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "intArg");

    assertEquals(a.getIdentifierString(), "--intArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertEquals(a.getLowerBound(), Integer.MIN_VALUE);

    assertEquals(a.getUpperBound(), Integer.MAX_VALUE);

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the third constructor with a non-{@code null} default value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NonNullDefaultValue()
         throws Exception
  {
    IntegerArgument a = new IntegerArgument('i', "intArg", false, 1,
                                            "{int}", "foo", 0);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('i'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('i'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "intArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "intArg");

    assertEquals(a.getIdentifierString(), "--intArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertTrue(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertTrue(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertEquals(a.getLowerBound(), Integer.MIN_VALUE);

    assertEquals(a.getUpperBound(), Integer.MAX_VALUE);

    assertNotNull(a.getDefaultValues());
    assertEquals(a.getDefaultValues().size(), 1);
    assertEquals(a.getDefaultValues().get(0), Integer.valueOf(0));

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), Integer.valueOf(0));

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), Integer.valueOf(0));

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the fourth constructor with a {@code null} set of default values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4NullDefaultValues()
         throws Exception
  {
    IntegerArgument a = new IntegerArgument('i', "intArg", false, 1,
                                            "{int}", "foo",
                                            (List<Integer>) null);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('i'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('i'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "intArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "intArg");

    assertEquals(a.getIdentifierString(), "--intArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertEquals(a.getLowerBound(), Integer.MIN_VALUE);

    assertEquals(a.getUpperBound(), Integer.MAX_VALUE);

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the fourth constructor with an empty set of default values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4EmptyDefaultValues()
         throws Exception
  {
    ArrayList<Integer> defaultValues = new ArrayList<Integer>();

    IntegerArgument a = new IntegerArgument('i', "intArg", false, 1,
                                            "{int}", "foo", defaultValues);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('i'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('i'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "intArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "intArg");

    assertEquals(a.getIdentifierString(), "--intArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertEquals(a.getLowerBound(), Integer.MIN_VALUE);

    assertEquals(a.getUpperBound(), Integer.MAX_VALUE);

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the fourth constructor with a non-empty set of default values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4NonEmptyDefaultValues()
         throws Exception
  {
    ArrayList<Integer> defaultValues = new ArrayList<Integer>();
    defaultValues.add(0);

    IntegerArgument a = new IntegerArgument('i', "intArg", false, 1,
                                            "{int}", "foo", defaultValues);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('i'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('i'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "intArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "intArg");

    assertEquals(a.getIdentifierString(), "--intArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertTrue(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertTrue(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertEquals(a.getLowerBound(), Integer.MIN_VALUE);

    assertEquals(a.getUpperBound(), Integer.MAX_VALUE);

    assertNotNull(a.getDefaultValues());
    assertEquals(a.getDefaultValues().size(), 1);
    assertEquals(a.getDefaultValues().get(0), Integer.valueOf(0));

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), Integer.valueOf(0));

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), Integer.valueOf(0));

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the fifth constructor with a {@code null} default value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5NullDefaultValue()
         throws Exception
  {
    IntegerArgument a = new IntegerArgument('i', "intArg", false, 1,
                                            "{int}", "foo", 0, 100,
                                            (Integer) null);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('i'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('i'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "intArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "intArg");

    assertEquals(a.getIdentifierString(), "--intArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertEquals(a.getLowerBound(), 0);

    assertEquals(a.getUpperBound(), 100);

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the fifth constructor with a non-{@code null} default value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5NonNullDefaultValue()
         throws Exception
  {
    IntegerArgument a = new IntegerArgument('i', "intArg", false, 1,
                                            "{int}", "foo", 0, 100, 0);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('i'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('i'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "intArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "intArg");

    assertEquals(a.getIdentifierString(), "--intArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertTrue(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertTrue(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertEquals(a.getLowerBound(), 0);

    assertEquals(a.getUpperBound(), 100);

    assertNotNull(a.getDefaultValues());
    assertEquals(a.getDefaultValues().size(), 1);
    assertEquals(a.getDefaultValues().get(0), Integer.valueOf(0));

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), Integer.valueOf(0));

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), Integer.valueOf(0));

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the sixth constructor with a {@code null} set of default values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6NullDefaultValues()
         throws Exception
  {
    IntegerArgument a = new IntegerArgument('i', "intArg", false, 1,
                                            "{int}", "foo", 0, 100,
                                            (List<Integer>) null);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('i'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('i'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "intArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "intArg");

    assertEquals(a.getIdentifierString(), "--intArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertEquals(a.getLowerBound(), 0);

    assertEquals(a.getUpperBound(), 100);

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the sixth constructor with an empty set of default values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6EmptyDefaultValues()
         throws Exception
  {
    ArrayList<Integer> defaultValues = new ArrayList<Integer>();

    IntegerArgument a = new IntegerArgument('i', "intArg", false, 1,
                                            "{int}", "foo", 0, 100,
                                            defaultValues);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('i'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('i'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "intArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "intArg");

    assertEquals(a.getIdentifierString(), "--intArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertEquals(a.getLowerBound(), 0);

    assertEquals(a.getUpperBound(), 100);

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the sixth constructor with a non-empty set of default values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6NonEmptyDefaultValues()
         throws Exception
  {
    ArrayList<Integer> defaultValues = new ArrayList<Integer>();
    defaultValues.add(0);

    IntegerArgument a = new IntegerArgument('i', "intArg", false, 1,
                                            "{int}", "foo", 0, 100,
                                            defaultValues);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('i'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('i'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "intArg");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "intArg");

    assertEquals(a.getIdentifierString(), "--intArg");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertTrue(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertTrue(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertEquals(a.getLowerBound(), 0);

    assertEquals(a.getUpperBound(), 100);

    assertNotNull(a.getDefaultValues());
    assertEquals(a.getDefaultValues().size(), 1);
    assertEquals(a.getDefaultValues().get(0), Integer.valueOf(0));

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), Integer.valueOf(0));

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), Integer.valueOf(0));

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the {@code addValue} method when there are no constraints.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddValueNoConstraints()
         throws Exception
  {
    IntegerArgument a = new IntegerArgument('i', "intArg", false, 1,
                                            "{int}", "foo", 0);
    a = a.getCleanCopy();

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), Integer.valueOf(0));

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), Integer.valueOf(0));

    a.addValue("5");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), Integer.valueOf(5));

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), Integer.valueOf(5));

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the {@code addValue} method when there are constraints.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddValueWithConstraints()
         throws Exception
  {
    IntegerArgument a = new IntegerArgument('i', "intArg", false, 1,
                                            "{int}", "foo", 0, 100, 0);
    a = a.getCleanCopy();

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), Integer.valueOf(0));

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), Integer.valueOf(0));

    a.addValue("5");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), Integer.valueOf(5));

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), Integer.valueOf(5));

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the {@code addValue} method when the provided value cannot be parsed
   * as an integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddValueInvalid()
         throws Exception
  {
    IntegerArgument a = new IntegerArgument('i', "intArg", false, 1,
                                            "{int}", "foo", 0, 10);
    a = a.getCleanCopy();
    a.addValue("invalid");
  }



  /**
   * Tests the {@code addValue} method when there are constraints and the new
   * value is below the lower bound.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddValueBelowLowerBound()
         throws Exception
  {
    IntegerArgument a = new IntegerArgument('i', "intArg", false, 1,
                                            "{int}", "foo", 0, 10);
    a = a.getCleanCopy();
    a.addValue("-5");
  }



  /**
   * Tests the {@code addValue} method when there are constraints and the new
   * value is above the lower bound.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddValueAboveUpperBound()
         throws Exception
  {
    IntegerArgument a = new IntegerArgument('i', "intArg", false, 1,
                                            "{int}", "foo", 0, 10);
    a = a.getCleanCopy();
    a.addValue("15");
  }



  /**
   * Tests the {@code addValue} method when there are too many values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddValueTooManyValues()
         throws Exception
  {
    IntegerArgument a = new IntegerArgument('i', "intArg", false, 1,
                                            "{int}", "foo", 0, 10);
    a = a.getCleanCopy();
    a.addValue("5");
    a.addValue("7");
  }



  /**
   * Tests the argument's behavior with an argument value validator.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithArgumentValueValidator()
         throws Exception
  {
    IntegerArgument a = new IntegerArgument('i', "intArg", false, 1,
                                            "{int}", "foo");
    a.addValueValidator(new TestArgumentValueValidator("1234"));

    assertNull(a.getValue());

    try
    {
      a.addValue("5678");
      fail("Expected an exception from an argument value validator.");
    }
    catch (final ArgumentException ae)
    {
      // This was expected
    }

    assertNull(a.getValue());

    a.addValue("1234");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), Integer.valueOf(1234));
  }
}
