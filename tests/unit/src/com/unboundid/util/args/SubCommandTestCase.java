/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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



import java.util.LinkedHashMap;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the {@code SubCommand} class.
 */
public final class SubCommandTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when creating a subcommand without any examples.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithoutExamples()
         throws Exception
  {
    // Create the subcommand.
    final ArgumentParser parser = new ArgumentParser("subcommand",
         "subcommand parser description");

    SubCommand sc =
         new SubCommand("name", "subcommand description", parser, null);
    sc = sc.getCleanCopy();


    // Test the behavior of the created subcommand.
    assertNotNull(sc.getPrimaryName());
    assertEquals(sc.getPrimaryName(), "name");

    assertNotNull(sc.getNames());
    assertEquals(sc.getNames().size(), 1);
    assertEquals(sc.getNames().get(0), "name");

    assertTrue(sc.hasName("name"));
    assertFalse(sc.hasName("name2"));

    assertNotNull(sc.getDescription());
    assertEquals(sc.getDescription(), "subcommand description");

    assertNotNull(sc.getArgumentParser());

    assertFalse(sc.isPresent());

    assertNull(sc.getGlobalArgumentParser());

    assertNotNull(sc.getExampleUsages());
    assertTrue(sc.getExampleUsages().isEmpty());

    assertNotNull(sc.toString());


    // Add a name and re-test the name-related methods.
    sc.addName("name2");

    assertNotNull(sc.getPrimaryName());
    assertEquals(sc.getPrimaryName(), "name");

    assertNotNull(sc.getNames());
    assertEquals(sc.getNames().size(), 2);
    assertEquals(sc.getNames().get(0), "name");
    assertEquals(sc.getNames().get(1), "name2");

    assertTrue(sc.hasName("name"));
    assertTrue(sc.hasName("name2"));

    assertNotNull(sc.toString());


    // Update the presence state and re-test the related methods.
    assertFalse(sc.isPresent());
    sc.setPresent();
    assertTrue(sc.isPresent());

    assertNotNull(sc.toString());


    // Set a global argument parser and re-test the related methods.
    assertNull(sc.getGlobalArgumentParser());

    final ArgumentParser globalParser = new ArgumentParser("command",
         "command description");
    globalParser.addSubCommand(sc);

    assertNotNull(sc.getGlobalArgumentParser());

    assertNotNull(sc.toString());
  }



  /**
   * Tests the behavior when creating a subcommand with examples.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithExamples()
         throws Exception
  {
    // Create the subcommand.
    final ArgumentParser parser = new ArgumentParser("subcommand",
         "subcommand parser description");

    final LinkedHashMap<String[],String> examples =
         new LinkedHashMap<String[],String>(3);
    examples.put(
         new String[0],
         "Do the default thing");
    examples.put(
         new String[] { "--name1", "value1" },
         "Do something with one argument");
    examples.put(
         new String[] { "--name1", "value1", "--name2", "--name3", "value3" },
         "Do something with multiple arguments");

    SubCommand sc =
         new SubCommand("name", "subcommand description", parser, examples);
    sc = sc.getCleanCopy();


    // Test the behavior of the created subcommand.
    assertNotNull(sc.getPrimaryName());
    assertEquals(sc.getPrimaryName(), "name");

    assertNotNull(sc.getNames());
    assertEquals(sc.getNames().size(), 1);
    assertEquals(sc.getNames().get(0), "name");

    assertTrue(sc.hasName("name"));
    assertFalse(sc.hasName("name2"));

    assertNotNull(sc.getDescription());
    assertEquals(sc.getDescription(), "subcommand description");

    assertNotNull(sc.getArgumentParser());

    assertFalse(sc.isPresent());

    assertNull(sc.getGlobalArgumentParser());

    assertNotNull(sc.getExampleUsages());
    assertEquals(sc.getExampleUsages().size(), 3);

    assertNotNull(sc.toString());


    // Add a name and re-test the name-related methods.
    sc.addName("name2");

    assertNotNull(sc.getPrimaryName());
    assertEquals(sc.getPrimaryName(), "name");

    assertNotNull(sc.getNames());
    assertEquals(sc.getNames().size(), 2);
    assertEquals(sc.getNames().get(0), "name");
    assertEquals(sc.getNames().get(1), "name2");

    assertTrue(sc.hasName("name"));
    assertTrue(sc.hasName("name2"));

    assertNotNull(sc.toString());


    // Update the presence state and re-test the related methods.
    assertFalse(sc.isPresent());
    sc.setPresent();
    assertTrue(sc.isPresent());

    assertNotNull(sc.toString());


    // Set a global argument parser and re-test the related methods.
    assertNull(sc.getGlobalArgumentParser());

    final ArgumentParser globalParser = new ArgumentParser("command",
         "command description");
    globalParser.addSubCommand(sc);

    assertNotNull(sc.getGlobalArgumentParser());

    assertNotNull(sc.toString());
  }



  /**
   * Tests the behavior when trying to create a subcommand with a null name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testCreateNullName()
         throws Exception
  {
    final ArgumentParser parser = new ArgumentParser("subcommand",
         "subcommand parser description");

    new SubCommand(null, "subcommand description", parser, null);
  }



  /**
   * Tests the behavior when trying to create a subcommand with an empty name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testCreateEmptyName()
         throws Exception
  {
    final ArgumentParser parser = new ArgumentParser("subcommand",
         "subcommand parser description");

    new SubCommand("", "subcommand description", parser, null);
  }



  /**
   * Tests the behavior when trying to create a subcommand with a null
   * description.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testCreateNullDescription()
         throws Exception
  {
    final ArgumentParser parser = new ArgumentParser("subcommand",
         "subcommand parser description");

    new SubCommand("name", null, parser, null);
  }



  /**
   * Tests the behavior when trying to create a subcommand with an empty
   * description.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testCreateEmptyDescription()
         throws Exception
  {
    final ArgumentParser parser = new ArgumentParser("subcommand",
         "subcommand parser description");

    new SubCommand("name", "", parser, null);
  }



  /**
   * Tests the behavior when trying to create a subcommand with a null argument
   * parser.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testCreateNullParser()
         throws Exception
  {
    new SubCommand("name", "description", null, null);
  }



  /**
   * Tests the behavior when trying to create a subcommand with an argument
   * parser that allows trailing arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testCreateParserAllowsTrailingArguments()
         throws Exception
  {
    final ArgumentParser parser = new ArgumentParser("subcommand",
         "subcommand parser description", -1, "{trailing}");

    new SubCommand("name", "subcommand description", parser, null);
  }



  /**
   * Tests the behavior when trying to create a subcommand with an argument
   * parser that allows trailing arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testCreateParserNestedSubcommands()
         throws Exception
  {
    final ArgumentParser parser = new ArgumentParser("subcommand",
         "subcommand parser description");

    final SubCommand parserSubCommand =  new SubCommand("nested",
         "nested subcommand description", parser, null);
    parser.addSubCommand(parserSubCommand);

    new SubCommand("non-nested", "non-nested description", parser, null);
  }



  /**
   * Tests the behavior when trying to add a name that is null.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddNameNull()
         throws Exception
  {
    final ArgumentParser parser = new ArgumentParser("subcommand",
         "subcommand parser description");

    final SubCommand sc =
         new SubCommand("name", "subcommand description", parser, null);

    sc.addName(null);
  }



  /**
   * Tests the behavior when trying to add a name that is empty.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddNameEmpty()
         throws Exception
  {
    final ArgumentParser parser = new ArgumentParser("subcommand",
         "subcommand parser description");

    final SubCommand sc =
         new SubCommand("name", "subcommand description", parser, null);

    sc.addName("");
  }



  /**
   * Tests the behavior when trying to add a name that is a duplicate of an
   * already-registered name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddNameDuplicate()
         throws Exception
  {
    final ArgumentParser parser = new ArgumentParser("subcommand",
         "subcommand parser description");

    final SubCommand sc =
         new SubCommand("name", "subcommand description", parser, null);

    sc.addName("name");
  }



  /**
   * Tests the behavior when trying to add a name that is a duplicate of a name
   * for a different subcommand already registered with the global argument
   * parser.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddNameConflictsWithOtherSubCommand()
         throws Exception
  {
    final ArgumentParser parser1 = new ArgumentParser("subcommand1",
         "subcommand parser 1 description");

    final SubCommand sc1 =
         new SubCommand("name1", "subcommand description", parser1, null);

    final ArgumentParser globalParser = new ArgumentParser("command",
         "command description");
    globalParser.addSubCommand(sc1);

    final ArgumentParser parser2 = new ArgumentParser("subcommand2",
         "subcommand parser 2 description");

    final SubCommand sc2 =
         new SubCommand("name2", "subcommand description", parser2, null);
    globalParser.addSubCommand(sc2);

    sc1.addName("name");

    try
    {
      sc2.addName("name");
      fail("Expected an exception when trying to add a name that conflicts " +
           "with the name of a different subcommand.");
    }
    catch (final ArgumentException ae)
    {
      // This is expected.
    }
  }
}
