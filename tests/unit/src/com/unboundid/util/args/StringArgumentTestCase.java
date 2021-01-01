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
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import org.testng.annotations.Test;

import com.unboundid.util.UtilTestCase;



/**
 * This class provides test coverage for the StringArgument class.
 */
public class StringArgumentTestCase
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
    StringArgument a = new StringArgument('s', "stringArg", "foo");
    a = a.getCleanCopy();

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

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertNull(a.getValueRegex());

    assertNull(a.getValueRegexExplanation());

    assertNull(a.getAllowedValues());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNull(a.getValueConstraints());

    assertNotNull(a.toString());

    final ArgumentParser newParser = new ArgumentParser("test", "test");
    newParser.addArgument(a);
    assertNotNull(newParser.getStringArgument(a.getIdentifierString()));

    assertNull(newParser.getStringArgument("--noSuchArgument"));
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
    StringArgument a = new StringArgument('s', "stringArg", false, 1,
                                          "{string}", "foo");
    a = a.getCleanCopy();

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

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertNull(a.getValueRegex());

    assertNull(a.getValueRegexExplanation());

    assertNull(a.getAllowedValues());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the second constructor with a {@code null} set of allowed values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NullAllowedValues()
         throws Exception
  {
    StringArgument a = new StringArgument('s', "stringArg", false, 1,
                                          "{string}", "foo",
                                          (Set<String>) null);
    a = a.getCleanCopy();

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

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertNull(a.getValueRegex());

    assertNull(a.getValueRegexExplanation());

    assertNull(a.getAllowedValues());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the second constructor with an empty set of allowed values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2EmptyAllowedValues()
         throws Exception
  {
    HashSet<String> allowedValues = new HashSet<String>();

    StringArgument a = new StringArgument('s', "stringArg", false, 1,
                                          "{string}", "foo", allowedValues);
    a = a.getCleanCopy();

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

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertNull(a.getValueRegex());

    assertNull(a.getValueRegexExplanation());

    assertNull(a.getAllowedValues());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the second constructor with non-empty set of allowed values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2WithAllowedValues()
         throws Exception
  {
    HashSet<String> allowedValues = new HashSet<String>();
    allowedValues.add("base");
    allowedValues.add("one");
    allowedValues.add("sub");
    allowedValues.add("subordinate");

    StringArgument a = new StringArgument('s', "stringArg", false, 1,
                                          "{string}", "foo", allowedValues);
    a = a.getCleanCopy();

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

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertNull(a.getValueRegex());

    assertNull(a.getValueRegexExplanation());

    assertNotNull(a.getAllowedValues());
    assertEquals(a.getAllowedValues().size(), 4);

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
    StringArgument a = new StringArgument('s', "stringArg", false, 1,
                                          "{string}", "foo", (String) null);
    a = a.getCleanCopy();

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

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertNull(a.getValueRegex());

    assertNull(a.getValueRegexExplanation());

    assertNull(a.getAllowedValues());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNull(a.getValueConstraints());

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
    StringArgument a = new StringArgument('s', "stringArg", false, 1,
                                          "{string}", "foo", "default");
    a = a.getCleanCopy();

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

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertTrue(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertTrue(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertNull(a.getValueRegex());

    assertNull(a.getValueRegexExplanation());

    assertNull(a.getAllowedValues());

    assertNotNull(a.getDefaultValues());
    assertEquals(a.getDefaultValues().size(), 1);
    assertEquals(a.getDefaultValues().get(0), "default");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), "default");

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), "default");

    assertNotNull(a.getDataTypeName());

    assertNull(a.getValueConstraints());

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
    StringArgument a = new StringArgument('s', "stringArg", false, 1,
                                          "{string}", "foo",
                                          (List<String>) null);
    a = a.getCleanCopy();

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

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertNull(a.getValueRegex());

    assertNull(a.getValueRegexExplanation());

    assertNull(a.getAllowedValues());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNull(a.getValueConstraints());

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
    ArrayList<String> defaultValues = new ArrayList<String>();

    StringArgument a = new StringArgument('s', "stringArg", false, 1,
                                          "{string}", "foo", defaultValues);
    a = a.getCleanCopy();

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

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertNull(a.getValueRegex());

    assertNull(a.getValueRegexExplanation());

    assertNull(a.getAllowedValues());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNull(a.getValueConstraints());

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
    ArrayList<String> defaultValues = new ArrayList<String>();
    defaultValues.add("default1");
    defaultValues.add("default2");

    StringArgument a = new StringArgument('s', "stringArg", false, 0,
                                          "{string}", "foo", defaultValues);
    a = a.getCleanCopy();

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

    assertEquals(a.getMaxOccurrences(), Integer.MAX_VALUE);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertTrue(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertTrue(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertNull(a.getValueRegex());

    assertNull(a.getValueRegexExplanation());

    assertNull(a.getAllowedValues());

    assertNotNull(a.getDefaultValues());
    assertEquals(a.getDefaultValues().size(), 2);
    assertEquals(a.getDefaultValues().get(0), "default1");
    assertEquals(a.getDefaultValues().get(1), "default2");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), "default1");

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 2);
    assertEquals(a.getValues().get(0), "default1");
    assertEquals(a.getValues().get(1), "default2");

    assertNotNull(a.getDataTypeName());

    assertNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the fifth constructor with a non-empty set of allowed values and a
   * {@code null} default value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5WithAllowedValuesNullDefaultValue()
         throws Exception
  {
    HashSet<String> allowedValues = new HashSet<String>();
    allowedValues.add("base");
    allowedValues.add("one");
    allowedValues.add("sub");
    allowedValues.add("subordinate");

    StringArgument a = new StringArgument('s', "stringArg", false, 1,
                                          "{string}", "foo", allowedValues,
                                          (String) null);
    a = a.getCleanCopy();

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

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertNull(a.getValueRegex());

    assertNull(a.getValueRegexExplanation());

    assertNotNull(a.getAllowedValues());
    assertEquals(a.getAllowedValues().size(), 4);

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the fifth constructor with a non-empty set of allowed values and a
   * non-{@code null} default value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5WithAllowedValuesNonNullDefaultValue()
         throws Exception
  {
    HashSet<String> allowedValues = new HashSet<String>();
    allowedValues.add("base");
    allowedValues.add("one");
    allowedValues.add("sub");
    allowedValues.add("subordinate");

    StringArgument a = new StringArgument('s', "stringArg", false, 1,
                                          "{string}", "foo", allowedValues,
                                          "sub");
    a = a.getCleanCopy();

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

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertTrue(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertTrue(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertNull(a.getValueRegex());

    assertNull(a.getValueRegexExplanation());

    assertNotNull(a.getAllowedValues());
    assertEquals(a.getAllowedValues().size(), 4);

    assertNotNull(a.getDefaultValues());
    assertEquals(a.getDefaultValues().size(), 1);
    assertEquals(a.getDefaultValues().get(0), "sub");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), "sub");

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), "sub");

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the sixth constructor with a non-empty set of allowed values and a
   * {@code null} set of default values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6WithAllowedValuesNullDefaultValues()
         throws Exception
  {
    HashSet<String> allowedValues = new HashSet<String>();
    allowedValues.add("base");
    allowedValues.add("one");
    allowedValues.add("sub");
    allowedValues.add("subordinate");

    StringArgument a = new StringArgument('s', "stringArg", false, 1,
                                          "{string}", "foo", allowedValues,
                                          (List<String>) null);
    a = a.getCleanCopy();

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

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertNull(a.getValueRegex());

    assertNull(a.getValueRegexExplanation());

    assertNotNull(a.getAllowedValues());
    assertEquals(a.getAllowedValues().size(), 4);

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the sixth constructor with a non-empty set of allowed values and an
   * empty set of default values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6WithAllowedValuesEmptyDefaultValues()
         throws Exception
  {
    HashSet<String> allowedValues = new HashSet<String>();
    allowedValues.add("base");
    allowedValues.add("one");
    allowedValues.add("sub");
    allowedValues.add("subordinate");

    ArrayList<String> defaultValues = new ArrayList<String>();

    StringArgument a = new StringArgument('s', "stringArg", false, 1,
                                          "{string}", "foo", allowedValues,
                                          defaultValues);
    a = a.getCleanCopy();

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

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertNull(a.getValueRegex());

    assertNull(a.getValueRegexExplanation());

    assertNotNull(a.getAllowedValues());
    assertEquals(a.getAllowedValues().size(), 4);

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the sixth constructor with a non-empty set of allowed values and a
   * non-empty set of default values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6WithAllowedValuesAndDefaultValues()
         throws Exception
  {
    HashSet<String> allowedValues = new HashSet<String>();
    allowedValues.add("base");
    allowedValues.add("one");
    allowedValues.add("sub");
    allowedValues.add("subordinate");

    ArrayList<String> defaultValues = new ArrayList<String>();
    defaultValues.add("base");
    defaultValues.add("one");

    StringArgument a = new StringArgument('s', "stringArg", false, 0,
                                          "{string}", "foo", allowedValues,
                                          defaultValues);
    a = a.getCleanCopy();

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

    assertEquals(a.getMaxOccurrences(), Integer.MAX_VALUE);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertTrue(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertTrue(a.hasDefaultValue());

    assertFalse(a.isRegistered());

    assertNull(a.getValueRegex());

    assertNull(a.getValueRegexExplanation());

    assertNotNull(a.getAllowedValues());
    assertEquals(a.getAllowedValues().size(), 4);

    assertNotNull(a.getDefaultValues());
    assertEquals(a.getDefaultValues().size(), 2);
    assertEquals(a.getDefaultValues().get(0), "base");
    assertEquals(a.getDefaultValues().get(1), "one");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), "base");

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 2);
    assertEquals(a.getValues().get(0), "base");
    assertEquals(a.getValues().get(1), "one");

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the {@code addValue} method with a valid value when there is no
   * set of allowed values and no default values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddValueNoAllowedValuesNoDefaultValues()
         throws Exception
  {
    StringArgument a = new StringArgument('s', "stringArg", false, 1,
                                          "{string}", "foo");
    a = a.getCleanCopy();

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    a.addValue("value");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), "value");

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), "value");

    assertNotNull(a.getDataTypeName());

    assertNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the {@code addValue} method with a valid value when there is no
   * set of allowed values but there is a default value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddValueNoAllowedValuesWithDefaultValues()
         throws Exception
  {
    StringArgument a = new StringArgument('s', "stringArg", false, 1,
                                          "{string}", "foo", "default");
    a = a.getCleanCopy();

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), "default");

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), "default");

    a.addValue("value");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), "value");

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), "value");

    assertNotNull(a.getDataTypeName());

    assertNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the {@code addValue} method with a valid value when there is a set of
   * allowed values and a default value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddValueWithAllowedAndDefaultValues()
         throws Exception
  {
    HashSet<String> allowedValues = new HashSet<String>();
    allowedValues.add("base");
    allowedValues.add("one");
    allowedValues.add("sub");
    allowedValues.add("subordinate");

    StringArgument a = new StringArgument('s', "stringArg", false, 1,
                                          "{string}", "foo", allowedValues,
                                          "sub");
    a = a.getCleanCopy();

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), "sub");

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), "sub");

    a.addValue("base");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), "base");

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), "base");

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the {@code addValue} method with a value not in the set of allowed
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddValueNotAllowed()
         throws Exception
  {
    HashSet<String> allowedValues = new HashSet<String>();
    allowedValues.add("base");
    allowedValues.add("one");
    allowedValues.add("sub");
    allowedValues.add("subordinate");

    StringArgument a = new StringArgument('s', "stringArg", false, 1,
                                          "{string}", "foo", allowedValues,
                                          "default");
    a = a.getCleanCopy();
    a.addValue("not allowed");
  }



  /**
   * Tests the {@code addValue} method with too many values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddValueTooManyValues()
         throws Exception
  {
    HashSet<String> allowedValues = new HashSet<String>();
    allowedValues.add("base");
    allowedValues.add("one");
    allowedValues.add("sub");
    allowedValues.add("subordinate");

    StringArgument a = new StringArgument('s', "stringArg", false, 1,
                                          "{string}", "foo", allowedValues,
                                          "default");
    a = a.getCleanCopy();
    a.addValue("base");
    a.addValue("one");
  }



  /**
   * Tests the {@code addValue} method when a value regex is defined with an
   * explanation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddValueWithRegexAndExplanation()
         throws Exception
  {
    HashSet<String> allowedValues = new HashSet<String>();
    allowedValues.add("valid");
    allowedValues.add("invalid1");

    StringArgument a =
         new StringArgument('s', "stringArg", false, 0, "{string}", "foo",
              allowedValues);
    a = a.getCleanCopy();
    a.setValueRegex(Pattern.compile("[a-z]+"), "This is the explanation.");

    assertNotNull(a.getValueRegex());

    assertNotNull(a.getValueRegexExplanation());

    assertNotNull(a.getAllowedValues());
    assertFalse(a.getAllowedValues().isEmpty());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    a.addValue("valid");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), "valid");

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), "valid");

    try
    {
      a.addValue("invalid1");
      fail("Expected an exception when trying to add a value that doesn't " +
           "match the regex.");
    }
    catch (final ArgumentException ae)
    {
      assertTrue(ae.getMessage().contains("[a-z]+"));
      assertTrue(ae.getMessage().contains("This is the explanation."));
    }

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), "valid");

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), "valid");

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the {@code addValue} method when a value regex is defined without an
   * explanation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddValueWithRegexAndNoExplanation()
         throws Exception
  {
    StringArgument a =
         new StringArgument('s', "stringArg", false, 0, "{string}", "foo");
    a = a.getCleanCopy();
    a.setValueRegex(Pattern.compile("[a-z]+"), null);

    assertNotNull(a.getValueRegex());

    assertNull(a.getValueRegexExplanation());

    assertNull(a.getAllowedValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 0);

    a.addValue("valid");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), "valid");

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), "valid");

    try
    {
      a.addValue("invalid1");
      fail("Expected an exception when trying to add a value that doesn't " +
           "match the regex.");
    }
    catch (final ArgumentException ae)
    {
      assertTrue(ae.getMessage().contains("[a-z]+"));
      assertFalse(ae.getMessage().contains("This is the explanation."));
    }

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), "valid");

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), "valid");

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
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
    StringArgument a = new StringArgument('s', "stringArg", false, 1,
                                          "{string}", "foo");
    a.addValueValidator(new TestArgumentValueValidator("abc"));

    assertNull(a.getValue());

    try
    {
      a.addValue("def");
      fail("Expected an exception from an argument value validator.");
    }
    catch (final ArgumentException ae)
    {
      // This was expected
    }

    assertNull(a.getValue());

    a.addValue("abc");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), "abc");
  }
}
