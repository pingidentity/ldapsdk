/*
 * Copyright 2011-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011-2017 Ping Identity Corporation
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
 * This class provides a set of test cases for the {@code ArgumentListArgument}
 * class.
 */
public final class ArgumentListArgumentTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides a set of test cases for the argument list argument with a minimal
   * constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalConstructor()
         throws Exception
  {
    final ArgumentParser parser = new ArgumentParser("test", "test");
    parser.addArgument(new BooleanArgument('b', "booleanArg",
         "boolean description"));
    parser.addArgument(new StringArgument('s', "stringArg", false, 1, "{value}",
         "string description"));

    ArgumentListArgument a = new ArgumentListArgument('a', "argList",
         "arg list description", parser);
    a = a.getCleanCopy();

    assertNotNull(a.getCleanParser());

    assertNotNull(a.getValueParsers());
    assertTrue(a.getValueParsers().isEmpty());

    assertNotNull(a.getValueStrings());
    assertTrue(a.getValueStrings().isEmpty());

    assertFalse(a.hasDefaultValue());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());

    a.addValue("");

    a.addValue("--booleanArg");

    a.addValue("--stringArg stringValue");

    a.addValue("--booleanArg --stringArg stringValue");

    try
    {
      a.addValue("--stringArg \"unmatchedQuote --booleanArg");
      fail("Expected an exception with an unmatched quote.");
    }
    catch (final ArgumentException ae)
    {
      // This was expected.
    }

    try
    {
      a.addValue("--stringArg stringValue --booleanArg --unsupported");
      fail("Expected an exception with an unsupported argument.");
    }
    catch (final ArgumentException ae)
    {
      // This was expected.
    }

    assertNotNull(a.getValueParsers());
    assertEquals(a.getValueParsers().size(), 4);

    assertNotNull(a.getValueStrings());
    assertEquals(a.getValueStrings().size(), 4);

    assertEquals(a.getValueStrings().get(0), "");
    assertEquals(a.getValueStrings().get(1), "--booleanArg");
    assertEquals(a.getValueStrings().get(2), "--stringArg stringValue");
    assertEquals(a.getValueStrings().get(3),
         "--booleanArg --stringArg stringValue");

    ArgumentParser p = a.getValueParsers().get(0);
    assertFalse(p.getNamedArgument('b').isPresent());
    assertFalse(p.getNamedArgument('s').isPresent());

    p = a.getValueParsers().get(1);
    assertTrue(p.getNamedArgument('b').isPresent());
    assertFalse(p.getNamedArgument('s').isPresent());

    p = a.getValueParsers().get(2);
    assertFalse(p.getNamedArgument('b').isPresent());
    assertTrue(p.getNamedArgument('s').isPresent());

    p = a.getValueParsers().get(3);
    assertTrue(p.getNamedArgument('b').isPresent());
    assertTrue(p.getNamedArgument('s').isPresent());

    final ArgumentParser newParser = new ArgumentParser("test", "test");
    newParser.addArgument(a);
    assertNotNull(newParser.getArgumentListArgument(a.getIdentifierString()));

    assertNull(newParser.getArgumentListArgument("--noSuchArgument"));
  }



  /**
   * Provides a set of test cases for the argument list argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testArgumentListArgument()
         throws Exception
  {
    final ArgumentParser parser = new ArgumentParser("test", "test");
    parser.addArgument(new BooleanArgument('b', "booleanArg",
         "boolean description"));
    parser.addArgument(new StringArgument('s', "stringArg", false, 1, "{value}",
         "string description"));

    ArgumentListArgument a = new ArgumentListArgument('a', "argList", true,
         0, "{argList}", "arg list description", parser);
    a = a.getCleanCopy();

    assertNotNull(a.getCleanParser());

    assertNotNull(a.getValueParsers());
    assertTrue(a.getValueParsers().isEmpty());

    assertNotNull(a.getValueStrings());
    assertTrue(a.getValueStrings().isEmpty());

    assertFalse(a.hasDefaultValue());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());

    a.addValue("");

    a.addValue("--booleanArg");

    a.addValue("--stringArg stringValue");

    a.addValue("--booleanArg --stringArg stringValue");

    try
    {
      a.addValue("--stringArg \"unmatchedQuote --booleanArg");
      fail("Expected an exception with an unmatched quote.");
    }
    catch (final ArgumentException ae)
    {
      // This was expected.
    }

    try
    {
      a.addValue("--stringArg stringValue --booleanArg --unsupported");
      fail("Expected an exception with an unsupported argument.");
    }
    catch (final ArgumentException ae)
    {
      // This was expected.
    }

    assertNotNull(a.getValueParsers());
    assertEquals(a.getValueParsers().size(), 4);

    assertNotNull(a.getValueStrings());
    assertEquals(a.getValueStrings().size(), 4);

    assertEquals(a.getValueStrings().get(0), "");
    assertEquals(a.getValueStrings().get(1), "--booleanArg");
    assertEquals(a.getValueStrings().get(2), "--stringArg stringValue");
    assertEquals(a.getValueStrings().get(3),
         "--booleanArg --stringArg stringValue");

    ArgumentParser p = a.getValueParsers().get(0);
    assertFalse(p.getNamedArgument('b').isPresent());
    assertFalse(p.getNamedArgument('s').isPresent());

    p = a.getValueParsers().get(1);
    assertTrue(p.getNamedArgument('b').isPresent());
    assertFalse(p.getNamedArgument('s').isPresent());

    p = a.getValueParsers().get(2);
    assertFalse(p.getNamedArgument('b').isPresent());
    assertTrue(p.getNamedArgument('s').isPresent());

    p = a.getValueParsers().get(3);
    assertTrue(p.getNamedArgument('b').isPresent());
    assertTrue(p.getNamedArgument('s').isPresent());
  }
}
