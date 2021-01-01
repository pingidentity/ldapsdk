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

import com.unboundid.ldap.sdk.DN;
import com.unboundid.util.UtilTestCase;



/**
 * This class provides test coverage for the DNArgument class.
 */
public class DNArgumentTestCase
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
    DNArgument a = new DNArgument('d', "dn", "foo");
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('d'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('d'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "dn");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "dn");

    assertEquals(a.getIdentifierString(), "--dn");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{dn}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNull(a.getStringValue());

    assertTrue(a.getValues().isEmpty());

    assertFalse(a.isRegistered());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());

    final ArgumentParser newParser = new ArgumentParser("test", "test");
    newParser.addArgument(a);
    assertNotNull(newParser.getDNArgument(a.getIdentifierString()));

    assertNull(newParser.getDNArgument("--noSuchArgument"));
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
    DNArgument a = new DNArgument('d', "dn", false, 1, "{dn}", "foo");
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('d'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('d'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "dn");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "dn");

    assertEquals(a.getIdentifierString(), "--dn");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{dn}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNull(a.getStringValue());

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
    DNArgument a = new DNArgument('d', "dn", false, 1, "{dn}", "foo",
                                  (DN) null);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('d'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('d'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "dn");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "dn");

    assertEquals(a.getIdentifierString(), "--dn");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{dn}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNull(a.getStringValue());

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
    DNArgument a = new DNArgument('d', "dn", false, 1, "{dn}", "foo",
                                  new DN("dc=example,dc=com"));
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('d'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('d'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "dn");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "dn");

    assertEquals(a.getIdentifierString(), "--dn");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{dn}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertTrue(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertTrue(a.hasDefaultValue());

    assertFalse(a.getDefaultValues().isEmpty());
    assertEquals(a.getDefaultValues().size(), 1);
    assertEquals(a.getDefaultValues().get(0), new DN("dc=example,dc=com"));

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), new DN("dc=example,dc=com"));

    assertNotNull(a.getStringValue());
    assertEquals(new DN(a.getStringValue()), new DN("dc=example,dc=com"));

    assertFalse(a.getValues().isEmpty());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), new DN("dc=example,dc=com"));

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
    DNArgument a = new DNArgument('d', "dn", false, 1, "{dn}", "foo",
                                  (List<DN>) null);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('d'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('d'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "dn");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "dn");

    assertEquals(a.getIdentifierString(), "--dn");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{dn}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNull(a.getStringValue());

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
    ArrayList<DN> dnList = new ArrayList<DN>();

    DNArgument a = new DNArgument('d', "dn", false, 1, "{dn}", "foo", dnList);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('d'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('d'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "dn");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "dn");

    assertEquals(a.getIdentifierString(), "--dn");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{dn}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertFalse(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertFalse(a.hasDefaultValue());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNull(a.getStringValue());

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
    ArrayList<DN> dnList = new ArrayList<DN>();
    dnList.add(new DN("dc=example,dc=com"));

    DNArgument a = new DNArgument('d', "dn", false, 1, "{dn}", "foo", dnList);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('d'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('d'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "dn");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "dn");

    assertEquals(a.getIdentifierString(), "--dn");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), 1);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{dn}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertTrue(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertTrue(a.hasDefaultValue());

    assertFalse(a.getDefaultValues().isEmpty());
    assertEquals(a.getDefaultValues().size(), 1);
    assertEquals(a.getDefaultValues().get(0), new DN("dc=example,dc=com"));

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), new DN("dc=example,dc=com"));

    assertNotNull(a.getStringValue());
    assertEquals(new DN(a.getStringValue()), new DN("dc=example,dc=com"));

    assertFalse(a.getValues().isEmpty());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), new DN("dc=example,dc=com"));

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
    ArrayList<DN> dnList = new ArrayList<DN>();
    dnList.add(new DN("dc=example,dc=com"));
    dnList.add(new DN("o=example.com"));

    DNArgument a = new DNArgument('d', "dn", false, 0, "{dn}", "foo", dnList);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertTrue(a.hasShortIdentifier());

    assertEquals(a.getShortIdentifier(), Character.valueOf('d'));

    assertNotNull(a.getShortIdentifiers());
    assertEquals(a.getShortIdentifiers().size(), 1);
    assertEquals(a.getShortIdentifiers().get(0), Character.valueOf('d'));

    assertTrue(a.hasLongIdentifier());

    assertEquals(a.getLongIdentifier(), "dn");

    assertNotNull(a.getLongIdentifiers());
    assertEquals(a.getLongIdentifiers().size(), 1);
    assertEquals(a.getLongIdentifiers().get(0), "dn");

    assertEquals(a.getIdentifierString(), "--dn");

    assertFalse(a.isRequired());

    assertEquals(a.getMaxOccurrences(), Integer.MAX_VALUE);

    assertTrue(a.takesValue());

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{dn}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertFalse(a.isHidden());

    assertTrue(a.isPresent());

    assertEquals(a.getNumOccurrences(), 0);

    assertTrue(a.hasDefaultValue());

    assertFalse(a.getDefaultValues().isEmpty());
    assertEquals(a.getDefaultValues().size(), 2);
    assertEquals(a.getDefaultValues().get(0), new DN("dc=example,dc=com"));
    assertEquals(a.getDefaultValues().get(1), new DN("o=example.com"));

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), new DN("dc=example,dc=com"));

    assertNotNull(a.getStringValue());
    assertEquals(new DN(a.getStringValue()), new DN("dc=example,dc=com"));

    assertFalse(a.getValues().isEmpty());
    assertEquals(a.getValues().size(), 2);
    assertEquals(a.getValues().get(0), new DN("dc=example,dc=com"));
    assertEquals(a.getValues().get(1), new DN("o=example.com"));

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
    DNArgument a = new DNArgument('d', "dn", false, 1, "{dn}", "foo",
                                  new DN("dc=example,dc=com"));
    a = a.getCleanCopy();

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), new DN("dc=example,dc=com"));

    assertNotNull(a.getStringValue());
    assertEquals(new DN(a.getStringValue()), new DN("dc=example,dc=com"));

    assertFalse(a.getValues().isEmpty());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), new DN("dc=example,dc=com"));

    a.addValue("o=example.com");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), new DN("o=example.com"));

    assertNotNull(a.getStringValue());
    assertEquals(new DN(a.getStringValue()), new DN("o=example.com"));

    assertFalse(a.getValues().isEmpty());
    assertEquals(a.getValues().size(), 1);
    assertEquals(a.getValues().get(0), new DN("o=example.com"));

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the {@code addValue} method with something that can't be decoded as a
   * DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddValueNotDN()
         throws Exception
  {
    DNArgument a = new DNArgument('d', "dn", false, 1, "{dn}", "foo",
                                  new DN("dc=example,dc=com"));
    a = a.getCleanCopy();
    a.addValue("not a DN");
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
    DNArgument a = new DNArgument('d', "dn", false, 1, "{dn}", "foo",
                                  new DN("dc=example,dc=com"));
    a = a.getCleanCopy();
    a.addValue("dc=example,dc=com");
    a.addValue("o=example.com");
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
    DNArgument a = new DNArgument('d', "dn", false, 1, "{dn}", "foo");
    a.addValueValidator(new TestArgumentValueValidator("dc=example,dc=com"));

    assertNull(a.getValue());

    try
    {
      a.addValue("o=example.com");
      fail("Expected an exception from an argument value validator.");
    }
    catch (final ArgumentException ae)
    {
      // This was expected
    }

    assertNull(a.getValue());

    a.addValue("dc=example,dc=com");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), new DN("dc=example,dc=com"));
  }
}
