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

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.util.UtilTestCase;



/**
 * This class provides test coverage for the FilterArgument class.
 */
public class FilterArgumentTestCase
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
    FilterArgument a = new FilterArgument('f', "filter", "foo");
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('f'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('f'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "filter");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "filter");

    assertEquals(a.getIdentifierString(), "--filter");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{filter}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertTrue(a.getValues().isEmpty());

    assertFalse(a.isRegistered());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());

    final ArgumentParser newParser = new ArgumentParser("test", "test");
    newParser.addArgument(a);
    assertNotNull(newParser.getFilterArgument(a.getIdentifierString()));

    assertNull(newParser.getFilterArgument("--noSuchArgument"));
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
    FilterArgument a =
         new FilterArgument('f', "filter", false, 1, "{filter}", "foo");
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('f'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('f'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "filter");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "filter");

    assertEquals(a.getIdentifierString(), "--filter");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{filter}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertTrue(a.getValues().isEmpty());

    assertFalse(a.isRegistered());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the second constructor with a valid invocation with a {@code null}
   * default value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2ValidNullDefaultValue()
         throws Exception
  {
    FilterArgument a = new FilterArgument('f', "filter", false, 1, "{filter}",
                                          "foo", (Filter) null);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('f'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('f'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "filter");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "filter");

    assertEquals(a.getIdentifierString(), "--filter");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{filter}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertTrue(a.getValues().isEmpty());

    assertFalse(a.isRegistered());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the second constructor with a valid invocation including a default
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2ValidWithDefaultValue()
         throws Exception
  {
    FilterArgument a = new FilterArgument('f', "filter", false, 1, "{filter}",
                                          "foo",
                                          Filter.create("(objectClass=*)"));
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('f'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('f'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "filter");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "filter");

    assertEquals(a.getIdentifierString(), "--filter");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{filter}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertTrue(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertTrue(a.hasDefaultValue());

    assertFalse(a.getDefaultValues().isEmpty());
    assertEquals(a.getDefaultValues().size(), 1);
    assertEquals(a.getDefaultValues().get(0),
         Filter.create("(objectClass=*)"));

    assertNotNull(a.getValue());
    assertEquals(a.getValue(),
         Filter.create("(objectClass=*)"));

    assertFalse(a.getValues().isEmpty());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0),
         Filter.create("(objectClass=*)"));

    assertFalse(a.isRegistered());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the third constructor with a valid invocation with a {@code null}
   * default value list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3ValidNullDefaultValues()
         throws Exception
  {
    FilterArgument a = new FilterArgument('f', "filter", false, 1, "{filter}",
                                          "foo", (List<Filter>) null);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('f'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('f'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "filter");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "filter");

    assertEquals(a.getIdentifierString(), "--filter");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{filter}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertTrue(a.getValues().isEmpty());

    assertFalse(a.isRegistered());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the third constructor with a valid invocation with an empty default
   * value list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3ValidEmptyDefaultValues()
         throws Exception
  {
    ArrayList<Filter> filterList = new ArrayList<Filter>();

    FilterArgument a = new FilterArgument('f', "filter", false, 1, "{filter}",
                                          "foo", filterList);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('f'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('f'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "filter");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "filter");

    assertEquals(a.getIdentifierString(), "--filter");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{filter}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertTrue(a.getValues().isEmpty());

    assertFalse(a.isRegistered());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the third constructor with a valid invocation including a default
   * value list with a single element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3ValidWithSingleDefaultValue()
         throws Exception
  {
    ArrayList<Filter> filterList = new ArrayList<Filter>();
    filterList.add(Filter.create("(objectClass=*)"));

    FilterArgument a = new FilterArgument('f', "filter", false, 1, "{filter}",
                                          "foo", filterList);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('f'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('f'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "filter");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "filter");

    assertEquals(a.getIdentifierString(), "--filter");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{filter}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertTrue(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertTrue(a.hasDefaultValue());

    assertFalse(a.getDefaultValues().isEmpty());
    assertEquals(a.getDefaultValues().size(), 1);
    assertEquals(a.getDefaultValues().get(0),
         Filter.create("(objectClass=*)"));

    assertNotNull(a.getValue());
    assertEquals(a.getValue(),
         Filter.create("(objectClass=*)"));

    assertFalse(a.getValues().isEmpty());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0),
         Filter.create("(objectClass=*)"));

    assertFalse(a.isRegistered());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the third constructor with a valid invocation including a default
   * value list with a multiple elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3ValidWithMultipleDefaultValues()
         throws Exception
  {
    ArrayList<Filter> filterList = new ArrayList<Filter>();
    filterList.add(Filter.create("(objectClass=*)"));
    filterList.add(Filter.create("(dc=example)"));

    FilterArgument a = new FilterArgument('f', "filter", false, 0, "{filter}",
                                          "foo", filterList);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('f'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('f'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "filter");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "filter");

    assertEquals(a.getIdentifierString(), "--filter");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), Integer.MAX_VALUE);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{filter}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertTrue(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertTrue(a.hasDefaultValue());

    assertFalse(a.getDefaultValues().isEmpty());
    assertEquals(a.getDefaultValues().size(), 2);
    assertEquals(a.getDefaultValues().get(0),
         Filter.create("(objectClass=*)"));
    assertEquals(a.getDefaultValues().get(1),
                 Filter.create("(dc=example)"));

    assertNotNull(a.getValue());
    assertEquals(a.getValue(),
         Filter.create("(objectClass=*)"));

    assertFalse(a.getValues().isEmpty());
    assertEquals(a.getValues().size(), 2);
    assertEquals(a.getValues().get(0),
                 Filter.create("(objectClass=*)"));
    assertEquals(a.getValues().get(1),
                 Filter.create("(dc=example)"));

    assertFalse(a.isRegistered());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the {@code addValue} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddValue()
         throws Exception
  {
    FilterArgument a = new FilterArgument('f', "filter", false, 1, "{filter}",
                                          "foo",
                                          Filter.create("(objectClass=*)"));
    a = a.getCleanCopy();

    assertNotNull(a.getValue());
    assertEquals(a.getValue(),
                 Filter.create("(objectClass=*)"));

    assertFalse(a.getValues().isEmpty());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0),
                 Filter.create("(objectClass=*)"));

    a.addValue("(dc=example)");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(),
                 Filter.create("(dc=example)"));

    assertFalse(a.getValues().isEmpty());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0),
                 Filter.create("(dc=example)"));

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the {@code addValue} method with something that can't be decoded as a
   * filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddValueNotFilter()
         throws Exception
  {
    FilterArgument a = new FilterArgument('f', "filter", false, 1, "{filter}",
                                          "foo",
                                          Filter.create("(objectClass=*)"));
    a = a.getCleanCopy();
    a.addValue("not a filter");
  }



  /**
   * Tests the {@code addValue} method when exceeding the allowed number of
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddTooManyValues()
         throws Exception
  {
    FilterArgument a = new FilterArgument('f', "filter", false, 1, "{filter}",
                                          "foo",
                                          Filter.create("(objectClass=*)"));
    a = a.getCleanCopy();
    a.addValue("(objectClass=*)");
    a.addValue("(dc=example)");
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
    FilterArgument a =
         new FilterArgument('f', "filter", false, 1, "{filter}", "foo");
    a.addValueValidator(new TestArgumentValueValidator("(givenName=John)"));

    assertNull(a.getValue());

    try
    {
      a.addValue("(sn=Doe)");
      fail("Expected an exception from an argument value validator.");
    }
    catch (final ArgumentException ae)
    {
      // This was expected
    }

    assertNull(a.getValue());

    a.addValue("(givenName=John)");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(),
         Filter.createEqualityFilter("givenName", "John"));
  }
}
