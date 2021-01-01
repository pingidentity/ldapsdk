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



import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.UtilTestCase;



/**
 * This class provides test coverage for the ArgumentParser class.
 */
public class ArgumentParserTestCase
       extends UtilTestCase
{
  /**
   * Tests the first constructor with valid arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    ArgumentParser p = new ArgumentParser("foo", "bar");

    assertNotNull(p.getCommandName());
    assertEquals(p.getCommandName(), "foo");

    assertNotNull(p.getCommandDescription());
    assertEquals(p.getCommandDescription(), "bar");

    assertNotNull(p.getAdditionalCommandDescriptionParagraphs());
    assertTrue(p.getAdditionalCommandDescriptionParagraphs().isEmpty());

    assertFalse(p.allowsTrailingArguments());
    assertFalse(p.requiresTrailingArguments());

    assertNull(p.getTrailingArgumentsPlaceholder());

    assertEquals(p.getMinTrailingArguments(), 0);

    assertEquals(p.getMaxTrailingArguments(), 0);

    assertNull(p.getNamedArgument('u'));

    assertNull(p.getNamedArgument("undefined"));

    assertNotNull(p.getNamedArguments());
    assertTrue(p.getNamedArguments().isEmpty());

    assertNotNull(p.getDependentArgumentSets());
    assertTrue(p.getDependentArgumentSets().isEmpty());

    assertNotNull(p.getExclusiveArgumentSets());
    assertTrue(p.getExclusiveArgumentSets().isEmpty());

    assertNotNull(p.getRequiredArgumentSets());
    assertTrue(p.getRequiredArgumentSets().isEmpty());

    assertNotNull(p.getTrailingArguments());
    assertTrue(p.getTrailingArguments().isEmpty());

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    p.getUsage(outputStream, 79);
    byte[] usageBytes = outputStream.toByteArray();
    assertNotNull(usageBytes);
    assertFalse(usageBytes.length == 0);

    assertNotNull(p.getUsageString(79));

    assertNotNull(p.toString());
  }



  /**
   * Tests the first constructor without a command name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = ArgumentException.class)
  public void testConstructor1NoCommandName()
         throws Exception
  {
    new ArgumentParser(null, "bar");
  }



  /**
   * Tests the first constructor without a command description.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = ArgumentException.class)
  public void testConstructor1NoCommandDescription()
         throws Exception
  {
    new ArgumentParser("foo", null);
  }



  /**
   * Tests the second constructor with a form that does not allow unnamed
   * trailing arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NoTrailingArgs()
         throws Exception
  {
    ArgumentParser p = new ArgumentParser("foo", "bar", 0, null);

    assertNotNull(p.getCommandName());
    assertEquals(p.getCommandName(), "foo");

    assertNotNull(p.getCommandDescription());
    assertEquals(p.getCommandDescription(), "bar");

    assertFalse(p.allowsTrailingArguments());
    assertFalse(p.requiresTrailingArguments());

    assertNull(p.getTrailingArgumentsPlaceholder());

    assertEquals(p.getMinTrailingArguments(), 0);

    assertEquals(p.getMaxTrailingArguments(), 0);

    assertNull(p.getNamedArgument('u'));

    assertNull(p.getNamedArgument("undefined"));

    assertNotNull(p.getNamedArguments());
    assertTrue(p.getNamedArguments().isEmpty());

    assertNotNull(p.getDependentArgumentSets());
    assertTrue(p.getDependentArgumentSets().isEmpty());

    assertNotNull(p.getExclusiveArgumentSets());
    assertTrue(p.getExclusiveArgumentSets().isEmpty());

    assertNotNull(p.getRequiredArgumentSets());
    assertTrue(p.getRequiredArgumentSets().isEmpty());

    assertNotNull(p.getTrailingArguments());
    assertTrue(p.getTrailingArguments().isEmpty());

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    p.getUsage(outputStream, 79);
    byte[] usageBytes = outputStream.toByteArray();
    assertNotNull(usageBytes);
    assertFalse(usageBytes.length == 0);

    assertNotNull(p.getUsageString(79));

    assertNotNull(p.toString());
  }



  /**
   * Tests the second constructor with a form that allows a limited number of
   * unnamed trailing arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2LimitedTrailingArgs()
         throws Exception
  {
    ArgumentParser p = new ArgumentParser("foo", "bar", 1, 5, "{args}");

    assertNotNull(p.getCommandName());
    assertEquals(p.getCommandName(), "foo");

    assertNotNull(p.getCommandDescription());
    assertEquals(p.getCommandDescription(), "bar");

    assertTrue(p.allowsTrailingArguments());
    assertTrue(p.requiresTrailingArguments());

    assertNotNull(p.getTrailingArgumentsPlaceholder());
    assertEquals(p.getTrailingArgumentsPlaceholder(), "{args}");

    assertEquals(p.getMinTrailingArguments(), 1);

    assertEquals(p.getMaxTrailingArguments(), 5);

    assertNull(p.getNamedArgument('u'));

    assertNull(p.getNamedArgument("undefined"));

    assertNotNull(p.getNamedArguments());
    assertTrue(p.getNamedArguments().isEmpty());

    assertNotNull(p.getDependentArgumentSets());
    assertTrue(p.getDependentArgumentSets().isEmpty());

    assertNotNull(p.getExclusiveArgumentSets());
    assertTrue(p.getExclusiveArgumentSets().isEmpty());

    assertNotNull(p.getRequiredArgumentSets());
    assertTrue(p.getRequiredArgumentSets().isEmpty());

    assertNotNull(p.getTrailingArguments());
    assertTrue(p.getTrailingArguments().isEmpty());

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    p.getUsage(outputStream, 79);
    byte[] usageBytes = outputStream.toByteArray();
    assertNotNull(usageBytes);
    assertFalse(usageBytes.length == 0);

    assertNotNull(p.getUsageString(79));

    assertNotNull(p.toString());
  }



  /**
   * Tests the second constructor with a form that allows unlimited unnamed
   * trailing arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2UnlimitedTrailingArgs()
         throws Exception
  {
    ArgumentParser p = new ArgumentParser("foo", "bar", -1, "{args}");

    assertNotNull(p.getCommandName());
    assertEquals(p.getCommandName(), "foo");

    assertNotNull(p.getCommandDescription());
    assertEquals(p.getCommandDescription(), "bar");

    assertTrue(p.allowsTrailingArguments());
    assertFalse(p.requiresTrailingArguments());

    assertNotNull(p.getTrailingArgumentsPlaceholder());
    assertEquals(p.getTrailingArgumentsPlaceholder(), "{args}");

    assertEquals(p.getMinTrailingArguments(), 0);

    assertEquals(p.getMaxTrailingArguments(), Integer.MAX_VALUE);

    assertNull(p.getNamedArgument('u'));

    assertNull(p.getNamedArgument("undefined"));

    assertNotNull(p.getNamedArguments());
    assertTrue(p.getNamedArguments().isEmpty());

    assertNotNull(p.getDependentArgumentSets());
    assertTrue(p.getDependentArgumentSets().isEmpty());

    assertNotNull(p.getExclusiveArgumentSets());
    assertTrue(p.getExclusiveArgumentSets().isEmpty());

    assertNotNull(p.getRequiredArgumentSets());
    assertTrue(p.getRequiredArgumentSets().isEmpty());

    assertNotNull(p.getTrailingArguments());
    assertTrue(p.getTrailingArguments().isEmpty());

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    p.getUsage(outputStream, 79);
    byte[] usageBytes = outputStream.toByteArray();
    assertNotNull(usageBytes);
    assertFalse(usageBytes.length == 0);

    assertNotNull(p.getUsageString(79));

    assertNotNull(p.toString());
  }



  /**
   * Tests the second constructor in a form that allows trailing arguments but
   * does not include a placeholder.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = ArgumentException.class)
  public void testConstructorTrailingArgsWithoutPlaceholder()
         throws Exception
  {
    new ArgumentParser("foo", "bar", -1, null);
  }



  /**
   * Tests the {@code addArgument} method with an argument containing both short
   * and long identifiers.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddArgumentBothIdentifiers()
         throws Exception
  {
    ArgumentParser p = new ArgumentParser("foo", "bar");

    assertNull(p.getNamedArgument('b'));

    assertNull(p.getNamedArgument("booleanArg"));

    assertNotNull(p.getNamedArguments());
    assertTrue(p.getNamedArguments().isEmpty());

    BooleanArgument a = new BooleanArgument('b', "booleanArg", "foo");
    p.addArgument(a);

    assertNotNull(p.getNamedArgument('b'));
    assertEquals(p.getNamedArgument('b'), a);

    assertNotNull(p.getNamedArgument("booleanArg"));
    assertEquals(p.getNamedArgument("booleanArg"), a);

    assertNotNull(p.getNamedArguments());
    assertEquals(p.getNamedArguments().size(), 1);
    assertEquals(p.getNamedArguments().get(0), a);

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    p.getUsage(outputStream, 79);
    byte[] usageBytes = outputStream.toByteArray();
    assertNotNull(usageBytes);
    assertFalse(usageBytes.length == 0);

    assertNotNull(p.getUsageString(79));

    assertNotNull(p.toString());
  }



  /**
   * Tests the {@code addArgument} method with an argument containing only a
   * short identifier.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddArgumentOnlyShortIdentifier()
         throws Exception
  {
    ArgumentParser p = new ArgumentParser("foo", "bar");

    assertNull(p.getNamedArgument('b'));

    assertNull(p.getNamedArgument("booleanArg"));

    assertNotNull(p.getNamedArguments());
    assertTrue(p.getNamedArguments().isEmpty());

    BooleanArgument a = new BooleanArgument('b', null, "foo");
    p.addArgument(a);

    assertNotNull(p.getNamedArgument('b'));
    assertEquals(p.getNamedArgument('b'), a);

    assertNull(p.getNamedArgument("booleanArg"));

    assertNotNull(p.getNamedArguments());
    assertEquals(p.getNamedArguments().size(), 1);
    assertEquals(p.getNamedArguments().get(0), a);

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    p.getUsage(outputStream, 79);
    byte[] usageBytes = outputStream.toByteArray();
    assertNotNull(usageBytes);
    assertFalse(usageBytes.length == 0);

    assertNotNull(p.getUsageString(79));

    assertNotNull(p.toString());
  }



  /**
   * Tests the {@code addArgument} method with an argument containing only a
   * long identifier.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddArgumentOnlyLongIdentifier()
         throws Exception
  {
    ArgumentParser p = new ArgumentParser("foo", "bar");

    assertNull(p.getNamedArgument('b'));

    assertNull(p.getNamedArgument("booleanArg"));

    assertNotNull(p.getNamedArguments());
    assertTrue(p.getNamedArguments().isEmpty());

    BooleanArgument a = new BooleanArgument(null, "booleanArg", "foo");
    p.addArgument(a);

    assertNull(p.getNamedArgument('b'));

    assertNotNull(p.getNamedArgument("booleanArg"));
    assertEquals(p.getNamedArgument("booleanArg"), a);

    assertNotNull(p.getNamedArguments());
    assertEquals(p.getNamedArguments().size(), 1);
    assertEquals(p.getNamedArguments().get(0), a);

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    p.getUsage(outputStream, 79);
    byte[] usageBytes = outputStream.toByteArray();
    assertNotNull(usageBytes);
    assertFalse(usageBytes.length == 0);

    assertNotNull(p.getUsageString(79));

    assertNotNull(p.toString());
  }



  /**
   * Tests the {@code addArgument} method with a conflicting short identifier.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddArgumentConflictingShortIdentifier()
         throws Exception
  {
    ArgumentParser p = new ArgumentParser("foo", "bar");
    p.addArgument(new BooleanArgument('b', "longArg1", "foo"));
    p.addArgument(new BooleanArgument('b', "longArg2", "bar"));
  }



  /**
   * Tests the {@code addArgument} method with a conflicting long identifier.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddArgumentConflictingLongIdentifier()
         throws Exception
  {
    ArgumentParser p = new ArgumentParser("foo", "bar");
    p.addArgument(new BooleanArgument('b', "longArg", "foo"));
    p.addArgument(new BooleanArgument('B', "longArg", "bar"));
  }



  /**
   * Tests the {@code addDependentArgumentSet} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddDependentArgumentSet()
         throws Exception
  {
    ArgumentParser p = new ArgumentParser("foo", "bar");

    assertNotNull(p.getDependentArgumentSets());
    assertTrue(p.getDependentArgumentSets().isEmpty());

    BooleanArgument a = new BooleanArgument('a', "argA", "argA");
    BooleanArgument b = new BooleanArgument('b', "argB", "argB");
    BooleanArgument c = new BooleanArgument('c', "argC", "argC");
    BooleanArgument d = new BooleanArgument('d', "argD", "argD");
    BooleanArgument e = new BooleanArgument('e', "argE", "argE");
    BooleanArgument f = new BooleanArgument('f', "argF", "argF");
    BooleanArgument g = new BooleanArgument('g', "argG", "argG");
    BooleanArgument h = new BooleanArgument('h', "argH", "argH");

    p.addArgument(a);
    p.addArgument(b);
    p.addArgument(c);
    p.addArgument(d);
    p.addArgument(e);
    p.addArgument(f);
    p.addArgument(g);
    p.addArgument(h);

    assertNotNull(p.getDependentArgumentSets());
    assertTrue(p.getDependentArgumentSets().isEmpty());

    p.addDependentArgumentSet(a, Arrays.<Argument>asList(b, c));

    assertNotNull(p.getDependentArgumentSets());
    assertFalse(p.getDependentArgumentSets().isEmpty());
    assertEquals(p.getDependentArgumentSets().size(), 1);

    p.addDependentArgumentSet(d, e);

    assertNotNull(p.getDependentArgumentSets());
    assertFalse(p.getDependentArgumentSets().isEmpty());
    assertEquals(p.getDependentArgumentSets().size(), 2);

    p.addDependentArgumentSet(f, g, h);

    assertNotNull(p.getDependentArgumentSets());
    assertFalse(p.getDependentArgumentSets().isEmpty());
    assertEquals(p.getDependentArgumentSets().size(), 3);

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    p.getUsage(outputStream, 79);
    byte[] usageBytes = outputStream.toByteArray();
    assertNotNull(usageBytes);
    assertFalse(usageBytes.length == 0);

    assertNotNull(p.getUsageString(79));

    assertNotNull(p.toString());
  }



  /**
   * Tests the {@code addMutuallyDependentArgumentSet} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddMutuallyDependentArgumentSet()
         throws Exception
  {
    ArgumentParser p = new ArgumentParser("foo", "bar");

    assertNotNull(p.getDependentArgumentSets());
    assertTrue(p.getDependentArgumentSets().isEmpty());

    BooleanArgument a = new BooleanArgument('a', "argA", "argA");
    BooleanArgument b = new BooleanArgument('b', "argB", "argB");
    BooleanArgument c = new BooleanArgument('c', "argC", "argC");
    BooleanArgument d = new BooleanArgument('d', "argD", "argD");
    BooleanArgument e = new BooleanArgument('e', "argE", "argE");
    BooleanArgument f = new BooleanArgument('f', "argF", "argF");
    BooleanArgument g = new BooleanArgument('g', "argG", "argG");
    BooleanArgument h = new BooleanArgument('h', "argH", "argH");

    p.addArgument(a);
    p.addArgument(b);
    p.addArgument(c);
    p.addArgument(d);
    p.addArgument(e);

    p.addMutuallyDependentArgumentSet(a, b);

    assertNotNull(p.getDependentArgumentSets());
    assertFalse(p.getDependentArgumentSets().isEmpty());
    assertEquals(p.getDependentArgumentSets().size(), 2);

    p.addMutuallyDependentArgumentSet(c, d, e);

    assertNotNull(p.getDependentArgumentSets());
    assertFalse(p.getDependentArgumentSets().isEmpty());
    assertEquals(p.getDependentArgumentSets().size(), 5);

    try
    {
      final List<Argument> nullList = null;
      p.addMutuallyDependentArgumentSet(nullList);
      fail("Expected an exception with a null argument list.");
    }
    catch (final LDAPSDKUsageException ex)
    {
      // This was expected.
    }

    try
    {
      p.addMutuallyDependentArgumentSet(Collections.<Argument>emptyList());
      fail("Expected an exception with an empty argument list.");
    }
    catch (final LDAPSDKUsageException ex)
    {
      // This was expected.
    }

    try
    {
      p.addMutuallyDependentArgumentSet(Collections.<Argument>singleton(a));
      fail("Expected an exception with a single-element argument list.");
    }
    catch (final LDAPSDKUsageException ex)
    {
      // This was expected.
    }

    try
    {
      p.addMutuallyDependentArgumentSet(null, c);
      fail("Expected an exception with a null first argument.");
    }
    catch (final LDAPSDKUsageException ex)
    {
      // This was expected.
    }

    try
    {
      p.addMutuallyDependentArgumentSet(a, null);
      fail("Expected an exception with a null second argument.");
    }
    catch (final LDAPSDKUsageException ex)
    {
      // This was expected.
    }

    try
    {
      p.addMutuallyDependentArgumentSet(f, a, b);
      fail("Expected an exception with an unregistered first argument.");
    }
    catch (final LDAPSDKUsageException ex)
    {
      // This was expected.
    }

    try
    {
      p.addMutuallyDependentArgumentSet(a, f, b);
      fail("Expected an exception with an unregistered second argument.");
    }
    catch (final LDAPSDKUsageException ex)
    {
      // This was expected.
    }

    try
    {
      p.addMutuallyDependentArgumentSet(a, b, f);
      fail("Expected an exception with an unregistered third argument.");
    }
    catch (final LDAPSDKUsageException ex)
    {
      // This was expected.
    }

    try
    {
      p.addMutuallyDependentArgumentSet(f, g, h);
      fail("Expected an exception with all unregistered arguments.");
    }
    catch (final LDAPSDKUsageException ex)
    {
      // This was expected.
    }
  }



  /**
   * Tests the {@code addExclusiveArgumentSet} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddExclusiveArgumentSet()
         throws Exception
  {
    ArgumentParser p = new ArgumentParser("foo", "bar");

    assertNotNull(p.getExclusiveArgumentSets());
    assertTrue(p.getExclusiveArgumentSets().isEmpty());

    BooleanArgument a = new BooleanArgument('a', "argA", "argA");
    BooleanArgument b = new BooleanArgument('b', "argB", "argB");
    BooleanArgument c = new BooleanArgument('c', "argC", "argC");
    BooleanArgument d = new BooleanArgument('d', "argD", "argD");
    BooleanArgument e = new BooleanArgument('e', "argE", "argE");
    BooleanArgument f = new BooleanArgument('f', "argF", "argF");
    BooleanArgument g = new BooleanArgument('g', "argG", "argG");

    p.addArgument(a);
    p.addArgument(b);
    p.addArgument(c);
    p.addArgument(d);
    p.addArgument(e);
    p.addArgument(f);
    p.addArgument(g);

    assertNotNull(p.getExclusiveArgumentSets());
    assertTrue(p.getExclusiveArgumentSets().isEmpty());

    p.addExclusiveArgumentSet(Arrays.<Argument>asList(a, b));

    assertNotNull(p.getExclusiveArgumentSets());
    assertFalse(p.getExclusiveArgumentSets().isEmpty());
    assertEquals(p.getExclusiveArgumentSets().size(), 1);

    p.addExclusiveArgumentSet(c, d);

    assertNotNull(p.getExclusiveArgumentSets());
    assertFalse(p.getExclusiveArgumentSets().isEmpty());
    assertEquals(p.getExclusiveArgumentSets().size(), 2);

    p.addExclusiveArgumentSet(e, f, g);

    assertNotNull(p.getExclusiveArgumentSets());
    assertFalse(p.getExclusiveArgumentSets().isEmpty());
    assertEquals(p.getExclusiveArgumentSets().size(), 3);

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    p.getUsage(outputStream, 79);
    byte[] usageBytes = outputStream.toByteArray();
    assertNotNull(usageBytes);
    assertFalse(usageBytes.length == 0);

    assertNotNull(p.getUsageString(79));

    assertNotNull(p.toString());
  }



  /**
   * Tests the {@code addRequiredArgumentSet} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddRequiredArgumentSet()
         throws Exception
  {
    ArgumentParser p = new ArgumentParser("foo", "bar");

    assertNotNull(p.getRequiredArgumentSets());
    assertTrue(p.getRequiredArgumentSets().isEmpty());

    BooleanArgument a = new BooleanArgument('a', "argA", "argA");
    BooleanArgument b = new BooleanArgument('b', "argB", "argB");
    BooleanArgument c = new BooleanArgument('c', "argC", "argC");
    BooleanArgument d = new BooleanArgument('d', "argD", "argD");
    BooleanArgument e = new BooleanArgument('e', "argE", "argE");
    BooleanArgument f = new BooleanArgument('f', "argF", "argF");
    BooleanArgument g = new BooleanArgument('g', "argG", "argG");

    p.addArgument(a);
    p.addArgument(b);
    p.addArgument(c);
    p.addArgument(d);
    p.addArgument(e);
    p.addArgument(f);
    p.addArgument(g);

    assertNotNull(p.getRequiredArgumentSets());
    assertTrue(p.getRequiredArgumentSets().isEmpty());

    p.addRequiredArgumentSet(Arrays.<Argument>asList(a, b));

    assertNotNull(p.getRequiredArgumentSets());
    assertFalse(p.getRequiredArgumentSets().isEmpty());
    assertEquals(p.getRequiredArgumentSets().size(), 1);

    p.addRequiredArgumentSet(c, d);

    assertNotNull(p.getRequiredArgumentSets());
    assertFalse(p.getRequiredArgumentSets().isEmpty());
    assertEquals(p.getRequiredArgumentSets().size(), 2);

    p.addRequiredArgumentSet(e, f, g);

    assertNotNull(p.getRequiredArgumentSets());
    assertFalse(p.getRequiredArgumentSets().isEmpty());
    assertEquals(p.getRequiredArgumentSets().size(), 3);

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    p.getUsage(outputStream, 79);
    byte[] usageBytes = outputStream.toByteArray();
    assertNotNull(usageBytes);
    assertFalse(usageBytes.length == 0);

    assertNotNull(p.getUsageString(79));

    assertNotNull(p.toString());
  }



  /**
   * Tests the {@code getUsage} method for the case in which there are no
   * named or trailing arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsageNoNamedOrTrailing()
         throws Exception
  {
    ArgumentParser p = new ArgumentParser("foo", "bar");

    List<String> usageLines = p.getUsage(79);
    assertNotNull(usageLines);

    // The first line should be the tool description.
    // The second should be blank.
    // The third line should be the general usage line.
    assertEquals(usageLines.size(), 3, p.getUsageString(79));

    assertNotNull(p.toString());
  }



  /**
   * Tests the {@code getUsage} method for the case in which there are no
   * named arguments but can be trailing arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsageNoNamed()
         throws Exception
  {
    ArgumentParser p = new ArgumentParser("foo", "bar", -1,
                                          "[file1 [file2 [...]]]");

    List<String> usageLines = p.getUsage(79);
    assertNotNull(usageLines);

    // The first line should be the tool description.
    // The second should be blank.
    // The third line should be the general usage line.
    assertEquals(usageLines.size(), 3, p.getUsageString(79));

    assertNotNull(p.toString());
  }



  /**
   * Tests the {@code getUsage} method for the case in which there are named
   * arguments but no trailing arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsageNoTrailing()
         throws Exception
  {
    ArgumentParser p = new ArgumentParser("foo", "bar");

    List<String> usageLines = p.getUsage(79);
    assertNotNull(usageLines);

    // The first line should be the tool description.
    // The second should be blank.
    // The third line should be the general usage line.
    assertEquals(usageLines.size(), 3, p.getUsageString(79));

    BooleanArgument a = new BooleanArgument('a', "argA", "argA");
    p.addArgument(a);

    usageLines = p.getUsage(79);
    assertNotNull(usageLines);

    // We should have added four more lines:
    // - A blank to separate the general usage from the named args.
    // - A header to indicate the beginning of the named args.
    // - The long and short identifiers for the argument.
    // - The description for the argument.
    assertEquals(usageLines.size(), 7, p.getUsageString(79));


    BooleanArgument b = new BooleanArgument('b', "argB", "argB");
    p.addArgument(b);

    usageLines = p.getUsage(79);
    assertNotNull(usageLines);

    // We should have added two more lines:
    // - The long and short identifiers for the argument.
    // - The description for the argument.
    assertEquals(usageLines.size(), 9, p.getUsageString(79));


    BooleanArgument c = new BooleanArgument('c', "argC", "argC");
    c.setHidden(true);
    p.addArgument(c);

    usageLines = p.getUsage(79);
    assertNotNull(usageLines);

    // We should not have added any more lines because it was a hidden argument.
    assertEquals(usageLines.size(), 9, p.getUsageString(79));


    BooleanArgument d = new BooleanArgument(null, "argD", "argD");
    p.addArgument(d);

    usageLines = p.getUsage(79);
    assertNotNull(usageLines);

    // We should have added two more lines:
    // - The long identifier for the argument.
    // - The description for the argument.
    assertEquals(usageLines.size(), 11, p.getUsageString(79));


    BooleanArgument e = new BooleanArgument('e', null, "argE");
    p.addArgument(e);

    usageLines = p.getUsage(79);
    assertNotNull(usageLines);

    // We should have added two more lines:
    // - The short identifier for the argument.
    // - The description for the argument.
    assertEquals(usageLines.size(), 13, p.getUsageString(79));


    StringArgument f = new StringArgument('f', "argF", false, 0, "{value}",
                                          "argF");
    f.addShortIdentifier('F');
    f.addLongIdentifier("argumentF");
    p.addArgument(f);

    usageLines = p.getUsage(79);
    assertNotNull(usageLines);

    // We should have added two more lines:
    // - The multiple short and long identifiers for the argument.
    // - The description for the argument.
    assertEquals(usageLines.size(), 15, p.getUsageString(79));
  }



  /**
   * Tests the {@code getUsage} method for the case in which there both named
   * and trailing arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsageNamedAndTrailing()
         throws Exception
  {
    ArgumentParser p = new ArgumentParser("foo", "bar", -1,
                                          "[file1 [file2 [...]]]");

    List<String> usageLines = p.getUsage(79);
    assertNotNull(usageLines);

    // The first line should be the tool description.
    // The second should be blank.
    // The third line should be the general usage line.
    assertEquals(usageLines.size(), 3, p.getUsageString(79));

    BooleanArgument a = new BooleanArgument('a', "argA", "argA");
    p.addArgument(a);

    usageLines = p.getUsage(79);
    assertNotNull(usageLines);

    // We should have added four more lines:
    // - A blank to separate the general usage from the named args.
    // - A header to indicate the beginning of the named args.
    // - The long and short identifiers for the argument.
    // - The description for the argument.
    assertEquals(usageLines.size(), 7, p.getUsageString(79));


    BooleanArgument b = new BooleanArgument('b', "argB", "argB");
    p.addArgument(b);

    usageLines = p.getUsage(79);
    assertNotNull(usageLines);

    // We should have added two more lines:
    // - The long and short identifiers for the argument.
    // - The description for the argument.
    assertEquals(usageLines.size(), 9, p.getUsageString(79));


    BooleanArgument c = new BooleanArgument('c', "argC", "argC");
    c.setHidden(true);
    p.addArgument(c);

    usageLines = p.getUsage(79);
    assertNotNull(usageLines);

    // We should not have added any more lines because it was a hidden argument.
    assertEquals(usageLines.size(), 9, p.getUsageString(79));


    BooleanArgument d = new BooleanArgument(null, "argD", "argD");
    p.addArgument(d);

    usageLines = p.getUsage(79);
    assertNotNull(usageLines);

    // We should have added two more lines:
    // - The long identifier for the argument.
    // - The description for the argument.
    assertEquals(usageLines.size(), 11, p.getUsageString(79));


    BooleanArgument e = new BooleanArgument('e', null, "argE");
    p.addArgument(e);

    usageLines = p.getUsage(79);
    assertNotNull(usageLines);

    // We should have added two more lines:
    // - The short identifier for the argument.
    // - The description for the argument.
    assertEquals(usageLines.size(), 13, p.getUsageString(79));


    StringArgument f = new StringArgument('f', "argF", false, 0, "{value}",
                                          "argF");
    f.addShortIdentifier('F');
    f.addLongIdentifier("argumentF");
    p.addArgument(f);

    usageLines = p.getUsage(79);
    assertNotNull(usageLines);

    // We should have added two more lines:
    // - The multiple short and long identifiers for the argument.
    // - The description for the argument.
    assertEquals(usageLines.size(), 15, p.getUsageString(79));
  }



  /**
   * Tests the {@code getUsage} method with an absurdly small max width.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsageTinyMaxWidth()
         throws Exception
  {
    ArgumentParser p = new ArgumentParser("foo", "bar", -1,
                                          "[file1 [file2 [...]]]");

    BooleanArgument a = new BooleanArgument('a', "argA", "argA");
    p.addArgument(a);

    BooleanArgument b = new BooleanArgument('b', "argB", "argB");
    p.addArgument(b);

    BooleanArgument c = new BooleanArgument('c', "argC", "argC");
    c.setHidden(true);
    p.addArgument(c);

    BooleanArgument d = new BooleanArgument(null, "argD", "argD");
    p.addArgument(d);

    BooleanArgument e = new BooleanArgument('e', null, "argE");
    p.addArgument(e);

    StringArgument f = new StringArgument('f', "argF", false, 0, "{value}",
                                          "argF");
    f.addShortIdentifier('F');
    f.addLongIdentifier("argumentF");
    p.addArgument(f);

    assertNotNull(p.getUsageString(3));
  }



  /**
   * Tests the argument parser with valid data.
   *
   * @param  args             The argument strings that should be parsed.
   * @param  counts           The number of times that each of the test
   *                          arguments should be present.
   * @param  numTrailingArgs  The number of trailing arguments that should be
   *                          present.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "validArgSets")
  public void testParseValidArgSets(String[] args, int[] counts,
                                    int numTrailingArgs)
         throws Exception
  {
    // Create the appropriate argument parser configuration.
    ArgumentParser p = new ArgumentParser("foo", "bar", 2,
                                          "[file1 [file2 [...]]]");

    BooleanArgument a = new BooleanArgument('a', "argA", "argA");
    p.addArgument(a);

    StringArgument b =
         new StringArgument('b', "argB", false, -1, "{value}", "argB");
    p.addArgument(b);

    LinkedHashSet<String> allowedValues = new LinkedHashSet<String>(4);
    allowedValues.add("base");
    allowedValues.add("one");
    allowedValues.add("sub");
    allowedValues.add("subordinate");
    StringArgument c = new StringArgument('c', "argC", true, 1, "{scope}",
                                          "argC", allowedValues, "sub");
    p.addArgument(c);

    IntegerArgument d =
         new IntegerArgument('d', "argD", false, 1, "{int}", "argD", 0, 100);
    p.addArgument(d);

    BooleanArgument e = new BooleanArgument('e', "argE", "argE");
    e.setMaxOccurrences(3);
    p.addArgument(e);

    BooleanArgument f = new BooleanArgument('f', "argF", "argF");
    p.addArgument(f);

    p.addDependentArgumentSet(a, b);
    p.addExclusiveArgumentSet(a, e);
    p.addRequiredArgumentSet(b, d);

    assertNotNull(p.toString());

    p.parse(args);

    assertEquals(a.getNumOccurrences(), counts[0]);
    assertEquals(b.getNumOccurrences(), counts[1]);
    assertEquals(c.getNumOccurrences(), counts[2]);
    assertEquals(d.getNumOccurrences(), counts[3]);
    assertEquals(e.getNumOccurrences(), counts[4]);
    assertEquals(f.getNumOccurrences(), counts[5]);

    assertEquals(p.getTrailingArguments().size(), numTrailingArgs,
                 String.valueOf(p.getTrailingArguments()));

    p = p.getCleanCopy();
    p.parse(args);

    assertEquals(p.getNamedArgument(a.getShortIdentifier()).getNumOccurrences(),
         counts[0]);
    assertEquals(p.getNamedArgument(b.getShortIdentifier()).getNumOccurrences(),
         counts[1]);
    assertEquals(p.getNamedArgument(c.getShortIdentifier()).getNumOccurrences(),
         counts[2]);
    assertEquals(p.getNamedArgument(d.getShortIdentifier()).getNumOccurrences(),
         counts[3]);
    assertEquals(p.getNamedArgument(e.getShortIdentifier()).getNumOccurrences(),
         counts[4]);
    assertEquals(p.getNamedArgument(f.getShortIdentifier()).getNumOccurrences(),
         counts[5]);

    assertEquals(p.getTrailingArguments().size(), numTrailingArgs,
                 String.valueOf(p.getTrailingArguments()));
  }



  /**
   * Retrieves a set of test data that may be used to test valid argument
   * expressions.  Each element of the returned array will be an array of three
   * objects:  a string array with the argument data to parse, an int array with
   * the expected number of times each argument was present, and an integer that
   * specifies the expected number of trailing arguments.
   *
   * @return  A set of test data that may be used to test valid argument
   *          expressions.
   */
  @DataProvider(name = "validArgSets")
  public Object[][] getValidArgSets()
  {
    return new Object[][]
    {
      new Object[]
      {
        new String[] { "-a", "-b", "valueB" },
        new int[] { 1, 1, 0, 0, 0, 0 },
        0
      },

      new Object[]
      {
        new String[] { "-eefe", "-b", "valueB", "-d50" },
        new int[] { 0, 1, 0, 1, 3, 1 },
        0
      },

      new Object[]
      {
        new String[] { "-eefe", "-d50" },
        new int[] { 0, 0, 0, 1, 3, 1 },
        0
      },

      new Object[]
      {
        new String[] { "--argA", "--argb", "valueB" },
        new int[] { 1, 1, 0, 0, 0, 0 },
        0
      },

      new Object[]
      {
        new String[] { "--arga", "--argF", "--argB=valueB", "--argd=50" },
        new int[] { 1, 1, 0, 1, 0, 1 },
        0
      },

      new Object[]
      {
        new String[] { "--arga", "-bvalueB", "trailing1", "-e" },
        new int[] { 1, 1, 0, 0, 0, 0 },
        2
      },

      new Object[]
      {
        new String[] { "--arga", "-bvalueB", "--", "-e" },
        new int[] { 1, 1, 0, 0, 0, 0 },
        1
      },

      new Object[]
      {
        new String[] { "--arga", "-bvalueB", "--", "--argE" },
        new int[] { 1, 1, 0, 0, 0, 0 },
        1
      },
    };
  }



  /**
   * Tests the argument parser with invalid data.
   *
   * @param  args           The argument strings that should be parsed.
   * @param  invalidReason  The reason the argument set is invalid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "invalidArgSets",
        expectedExceptions = { ArgumentException.class })
  public void testParseInvalidArgSets(String[] args, String invalidReason)
         throws Exception
  {
    // Create the appropriate argument parser configuration.
    ArgumentParser p = new ArgumentParser("foo", "bar", 2,
                                          "[file1 [file2 [...]]]");

    BooleanArgument a = new BooleanArgument('a', "argA", "argA");
    p.addArgument(a);

    StringArgument b =
         new StringArgument('b', "argB", false, -1, "{value}", "argB");
    p.addArgument(b);

    LinkedHashSet<String> allowedValues = new LinkedHashSet<String>(4);
    allowedValues.add("base");
    allowedValues.add("one");
    allowedValues.add("sub");
    allowedValues.add("subordinate");
    StringArgument c = new StringArgument('c', "argC", true, 1, "{scope}",
                                          "argC", allowedValues, "sub");
    p.addArgument(c);

    IntegerArgument d =
         new IntegerArgument('d', "argD", false, 1, "{int}", "argD", 0, 100);
    p.addArgument(d);

    BooleanArgument e = new BooleanArgument('e', "argE", "argE");
    e.setMaxOccurrences(3);
    p.addArgument(e);

    BooleanArgument f = new BooleanArgument('f', "argF", "argF");
    p.addArgument(f);

    StringArgument g = new StringArgument('g', "argG", true, 1, "{value}",
                                          "argG");
    p.addArgument(g);

    BooleanArgument h = new BooleanArgument('h', "argH", "argH");
    p.addArgument(h);

    BooleanArgument i = new BooleanArgument('i', "argI", "argI");
    p.addArgument(i);

    BooleanArgument j = new BooleanArgument('j', "argJ", "argJ");
    p.addArgument(j);

    BooleanArgument k = new BooleanArgument('k', "argK", "argK");
    p.addArgument(k);

    BooleanArgument l = new BooleanArgument('l', "argL", "argL");
    p.addArgument(l);

    p.addDependentArgumentSet(h, i, j);
    p.addDependentArgumentSet(k, l);
    p.addExclusiveArgumentSet(a, e);
    p.addRequiredArgumentSet(b, d);

    assertNotNull(p.toString());

    p = p.getCleanCopy();
    p.parse(args);
    fail("Expected an exception in parsing because:  " + invalidReason);
  }



  /**
   * Retrieves a set of test data that may be used to test invalid argument
   * expressions.  Each element of the returned array will be an array
   * containing two elements:  a string array with argument data, and a string
   * indicating what's wrong with that argument array.
   *
   * @return  A set of test data that may be used to test valid argument
   *          expressions.
   */
  @DataProvider(name = "invalidArgSets")
  public Object[][] getInvalidArgSets()
  {
    return new Object[][]
    {
      new Object[]
      {
        new String[] { "-I", },
        "Undefined short identifier"
      },

      new Object[]
      {
        new String[] { "--invalid", },
        "Undefined long identifier"
      },

      new Object[]
      {
        new String[] { "-Ia", },
        "Undefined leading short identifier"
      },

      new Object[]
      {
        new String[] { "-aI", },
        "Undefined subsequent short identifier"
      },

      new Object[]
      {
        new String[] { "-adoesnttakevalue", },
        "Unexpected value with short identifier"
      },

      new Object[]
      {
        new String[] { "--argA=doesnttakevalue", },
        "Unexpected value with long identifier"
      },

      new Object[]
      {
        new String[] { "-b", },
        "Missing value with short identifier"
      },

      new Object[]
      {
        new String[] { "--argB", },
        "Missing value with long identifier"
      },

      new Object[]
      {
        new String[] { "-ab50" },
        "Combining short args when one takes a value"
      },

      new Object[]
      {
        new String[] { "-a", "-b", "valueB" },
        "Missing required -g argument"
      },

      new Object[]
      {
        new String[] { "-a", "-" },
        "Unexpected '-'"
      },

      new Object[]
      {
        new String[] { "-a", "-bvalueB", "-gvalG", "too", "many", "trailing" },
        "Too many trailing arguments"
      },

      new Object[]
      {
        new String[] { "-a", "-bvalueB", "-e", "-g", "valueG" },
        "Conflicting exclusive args"
      },

      new Object[]
      {
        new String[] { "-a", "-g", "valueG" },
        "Unfulfilled required arg set"
      },

      new Object[]
      {
        new String[] { "-a", "-bvalueB", "-gvalG", "-h" },
        "Unfulfilled multi-element dependent arg set"
      },

      new Object[]
      {
        new String[] { "-a", "-bvalueB", "-gvalG", "-k" },
        "Unfulfilled single-element dependent arg set"
      },
    };
  }



  /**
   * Tests the argument parser with data containing disallowed trailing
   * arguments without a double dash.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testParseDisallowedTrailingWithoutDash()
         throws Exception
  {
    // Create the appropriate argument parser configuration.
    ArgumentParser p = new ArgumentParser("foo", "bar");
    p = p.getCleanCopy();
    p.parse(new String[] { "trailing" });
  }



  /**
   * Tests the argument parser with data containing disallowed trailing
   * arguments with a double dash.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testParseDisallowedTrailingWithDash()
         throws Exception
  {
    // Create the appropriate argument parser configuration.
    ArgumentParser p = new ArgumentParser("foo", "bar");
    p = p.getCleanCopy();
    p.parse(new String[] { "--", "trailing" });
  }



  /**
   * Provides test coverage for the {@code handleUnicodeEscapes} method.
   *
   * @param  inputString           The input string to use in testing the
   *                               method.
   * @param  expectedOutputString  The expected output from the method.  This
   *                               will be ignored if {@code inputIsValid} is
   *                               {@code false}.
   * @param  inputIsValid          Indicates whether the provided input string
   *                               is valid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testHandleUnicodeEscapesData")
  public void testHandleUnicodeEscapes(final String inputString,
                                       final String expectedOutputString,
                                       final boolean inputIsValid)
         throws Exception
  {
    final String path = "/path/to/properties.txt";
    final StringBuilder buffer = new StringBuilder(inputString);

    if (inputIsValid)
    {
      final String gotOutputString =
           ArgumentParser.handleUnicodeEscapes(path, 1, buffer);
      assertEquals(gotOutputString, expectedOutputString);
    }
    else
    {
      try
      {
        ArgumentParser.handleUnicodeEscapes(path, 1, buffer);
        fail("Expected an argument exception from an invalid input string");
      }
      catch (final ArgumentException e)
      {
        // This was expected.
      }
    }
  }



  /**
   * Retrieves a set of test data that can be used to test the
   * {@code handleUnicodeEscapes} method.
   *
   * @return  A set of test data that can be used to test the
   *          {@code handleUnicodeEscapes} method.
   */
  @DataProvider(name="testHandleUnicodeEscapesData")
  public Object[][] getTestHandleUnicodeEscapesData()
  {
    return new Object[][]
    {
      new Object[]
      {
        "",
        "",
        true
      },

      new Object[]
      {
        "\\u002a",
        "*",
        true
      },

      new Object[]
      {
        "\\U0000",
        "\u0000",
        true
      },

      new Object[]
      {
        "Jalape\\u00f1o",
        "Jalape\u00f1o",
        true
      },

      new Object[]
      {
        "Jalape\\u00F1o",
        "Jalape\u00f1o",
        true
      },

      new Object[]
      {
        "Latin Capital Letter OO \\uA74E",
        "Latin Capital Letter OO \uA74E",
        true
      },

      new Object[]
      {
        "Deseret Capital Letter Long I \\uD801\\uDC00",
        "Deseret Capital Letter Long I \uD801\uDC00",
        true
      },

      new Object[]
      {
        "Smiley face emoji \\uD83D\\uDE00",
        "Smiley face emoji \uD83D\uDE00",
        true
      },

      new Object[]
      {
        "United States Flag Emoji \\uD83C\\uDDFA\\uD83C\\uDDF8",
        "United States Flag Emoji \uD83C\uDDFA\uD83C\uDDF8",
        true
      },

      new Object[]
      {
        "Double \\\\ Backslash",
        "Double \\ Backslash",
        true
      },

      new Object[]
      {
        "cn\\=Directory Manager",
        "cn=Directory Manager",
        true
      },

      new Object[]
      {
        "Malformed \\uXXXX Escape",
        "",
        false
      },

      new Object[]
      {
        "Malformed \\UXXXX Escape",
        "",
        false
      },
    };
  }
}
