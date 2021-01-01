/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
package com.unboundid.util;

import java.util.List;
import java.util.ArrayList;

import org.testng.annotations.Test;
import org.testng.annotations.DataProvider;



/**
 * Tests ExampleCommandLineArgumentTestCase.
 */
public class ExampleCommandLineArgumentTestCase
       extends UtilTestCase
{

  /**
   * Return test parameters to testArgumentQuoting.
   *
   * @return  Test parameters to testArgumentQuoting.
   */
  @DataProvider()
  public Object[][] testArgumentQuotingValues()
  {
    return new String[][]{
         noQuotes("no-quotes-needed"),
         noQuotes("/no/quotes/needed"),
         noQuotes("=-_:.,"),

         // We prefer using "" for things that need to be quoted since it works
         // on either platform.

         bothDoubleQuoted(""),
         bothDoubleQuoted(" "),
         bothDoubleQuoted("two words"),
         bothDoubleQuoted("INCLUDES some CAPITAL letters"),
         bothDoubleQuoted(" surrounded by space "),
         bothDoubleQuoted("arg's"),
         bothDoubleQuoted("|"),
         bothDoubleQuoted("&"),
         bothDoubleQuoted(";"),
         bothDoubleQuoted("("),
         bothDoubleQuoted(")"),
         bothDoubleQuoted("'"),
         bothDoubleQuoted("<"),
         bothDoubleQuoted(">"),

         // These fall into the category of something that we don't know about
         // specifically, so we go ahead and quote it.
         bothDoubleQuoted("#"),
         bothDoubleQuoted("~"),

         // When we can't use "" to quote on Unix, we
         // fallback is to use '' to quote on Unix and "" to quote on
         // Windows since that makes it pretty easy to switch between
         // platforms.

         singleUnixDoubleWindows("*"),
         singleUnixDoubleWindows("@"),
         singleUnixDoubleWindows("$"),
         singleUnixDoubleWindows("`"),
         singleUnixDoubleWindows("\\"),
         singleUnixDoubleWindows("!"),

         // We could do "c:\\\\windows\\\\path" on Unix, but single quotes
         // is better because it's more portable.
         singleUnixDoubleWindows("c:\\windows\\path"),
         singleUnixDoubleWindows("c:\\windows\\path with space"),
         singleUnixDoubleWindows("`backticks`"),
         singleUnixDoubleWindows("Bang!"),

         // On Windows to include a ", you need to do "" inside of quotes, so
         // """" gets passed to the application as "

         {"\"",
          "'\"'",
          "\"\"\"\""},

         {"\"Best\" Test Case Ever",
          "'\"Best\" Test Case Ever'",
          "\"\"\"Best\"\" Test Case Ever\""},

         // The hardest thing to support is a string that needs to be quoted
         // with single quotes, but itself includes a single quote.  This is
         // especially difficult if it includes the ! character because this
         // cannot be escaped on Unix inside of "".  So what we have to do
         // is include the ' inside of "", which are outside of the larger
         // quoting.

         {"!'!'",
          "'!'\"'\"'!'\"'\"''",  // It would be nice if this didn't end with ''
          "\"!'!'\""},

         {"'!'!",
          "''\"'\"'!'\"'\"'!'",  // It would be nice if this didn't end with ''
          "\"'!'!\""},

         {"\"!'!'\"",
          "'\"!'\"'\"'!'\"'\"'\"'",
          "\"\"\"!'!'\"\"\""},
    };
  }



  /**
   * Tests the ExampleCommandLineArgument class, in particular the
   * getCleanArgument and parseExampleCommandLine methods.
   *
   * @param  argumentStr          The argument to test.
   * @param  expectedUnixForm     The expected clean form of the argument on
   *                              Unix.
   * @param  expectedWindowsForm  The expected clean form of the argument on
   *                              Windows.
   */
  @Test(dataProvider = "testArgumentQuotingValues")
  public void testArgumentQuoting(final String argumentStr,
                                  final String expectedUnixForm,
                                  final String expectedWindowsForm)
  {
    ExampleCommandLineArgument argument =
         ExampleCommandLineArgument.getCleanArgument(argumentStr);

    assertEquals(argument.getRawForm(), argumentStr);
    assertEquals(argument.getUnixForm(), expectedUnixForm);
    assertEquals(argument.getWindowsForm(), expectedWindowsForm);

    // StaticUtils.isWindows() has similar code, but don't depend on that here
    // since it's what getLocalForm() uses.
    final String osName = System.getProperty("os.name").toLowerCase();
    final boolean isWindows = (osName.indexOf("windows") >= 0);
    if (isWindows)
    {
      assertEquals(argument.getLocalForm(), expectedWindowsForm);
    }
    else
    {
      assertEquals(argument.getLocalForm(), expectedUnixForm);
    }

    // Existing clients might call this deprecated method.
    assertEquals(StaticUtils.cleanExampleCommandLineArgument(argumentStr),
                 argument.getLocalForm());

    // Make sure that when we parse the example argument, we get back
    // what we quoted to start with.  We should be able to parse the example
    // command line independent of the platform where it was generated.

    List<String> parsedArgs =
        ExampleCommandLineArgument.parseExampleCommandLine(expectedUnixForm);
    assertEquals(parsedArgs.size(), 1);
    assertEquals(parsedArgs.get(0), argumentStr);

    parsedArgs =
        ExampleCommandLineArgument.parseExampleCommandLine(expectedWindowsForm);
    assertEquals(parsedArgs.size(), 1);
    assertEquals(parsedArgs.get(0), argumentStr);

    testParseExampleMultipleArgs(expectedUnixForm, argumentStr);
    testParseExampleMultipleArgs(expectedWindowsForm, argumentStr);
  }



  /**
   * Tests that the exampleArgument is correctly parsed out of a multi-argument
   * command line String and ends up with rawArgument.
   *
   * @param  exampleArgument  The clean form rawArgument.
   * @param  rawArgument      The raw argument.
   */
  private void testParseExampleMultipleArgs(final String exampleArgument,
                                            final String rawArgument)
  {
    final List<String> extraRawArgs = new ArrayList<String>();
    final List<String> extraExampleArgs = new ArrayList<String>();

    extraExampleArgs.add("\"\"");
    extraRawArgs.add("");

    extraExampleArgs.add("unquoted-test-arg");
    extraRawArgs.add("unquoted-test-arg");

    extraExampleArgs.add("\" surrounded by space \"");
    extraRawArgs.add(" surrounded by space ");

    extraExampleArgs.add("\"c:\\windows\\path\"");
    extraRawArgs.add("c:\\windows\\path");

    extraExampleArgs.add("'\"!'\"'\"'!'\"'\"'\"'");
    extraRawArgs.add("\"!'!'\"");

    extraExampleArgs.add("\"\"\"!'!'\"\"\"");
    extraRawArgs.add("\"!'!'\"");

    // Iterates through the example arguments and tests inserting
    // exampleArgument at each potential place, adding extra spaces or using
    // tabs instead of spaces sometimes, and tests that the full command line
    // string is parsed properly.

    boolean extraSpaceInitializer = false;
    for (int insertAt = 0; insertAt <= extraExampleArgs.size(); insertAt++)
    {
      boolean extraSpace = extraSpaceInitializer;
      extraSpaceInitializer = !extraSpaceInitializer;

      final List<String> inputArgs = new ArrayList<String>(extraExampleArgs);
      inputArgs.add(insertAt, exampleArgument);

      final List<String> expectedArgs = new ArrayList<String>(extraRawArgs);
      expectedArgs.add(insertAt, rawArgument);

      StringBuilder combinedArgs = new StringBuilder();
      for (int i = 0; i < inputArgs.size(); i++)
      {
        // Include an extra space every other time.
        if (extraSpace)
        {
          combinedArgs.append(" ");
        }
        extraSpace = !extraSpace;

        combinedArgs.append(inputArgs.get(i));
        if (i < (inputArgs.size() - 1))
        {
          // If it's not the last argument, then follow it with either a space
          // or a tab.  Two out of every three times it will be a space.
          if ((i % 3) == 2)
          {
            combinedArgs.append('\t');
          }
          else
          {
            combinedArgs.append(' ');
          }
        }
      }

      // A space at the end every other time.
      if (extraSpace)
      {
        combinedArgs.append(" ");
      }
      extraSpace = !extraSpace;

      final String exampleCommandLine = combinedArgs.toString();

      final List<String> parsedArgs = ExampleCommandLineArgument.
                parseExampleCommandLine(exampleCommandLine);

      assertEquals(parsedArgs,
                   expectedArgs,
                   "Full Command Line: " + exampleCommandLine);
    }
  }



  /**
   * Convenience method to return parameters to testArgumentQuoting where
   * neither Unix nor Windows need to be quoted.
   *
   * @param  arg  The argument.
   *
   * @return  Args to testArgumentQuoting where neither form needs to be quoted.
   */
  private String[] noQuotes(String arg)
  {
    return new String[]{arg, arg, arg};
  }



  /**
   * Convenience method to return parameters to testArgumentQuoting where
   * both the Unix and Windows form need to be double-quoted.
   *
   * @param  arg  The argument.
   *
   * @return  Args to testArgumentQuoting where both forms need to be
   *          double-quoted.
   */
  private String[] bothDoubleQuoted(String arg)
  {
    return new String[]{arg, "\"" + arg + "\"", "\"" + arg + "\""};
  }



  /**
   * Convenience method to return parameters to testArgumentQuoting where
   * the Unix form needs to be single-quoted and the Windows form needs to be
   * double-quoted.
   *
   * @param  arg  The argument.
   *
   * @return  Args to testArgumentQuoting where both forms need to be quoted.
   */
  private String[] singleUnixDoubleWindows(String arg)
  {
    return new String[]{arg, "'" + arg + "'", "\"" + arg + "\""};
  }
}
