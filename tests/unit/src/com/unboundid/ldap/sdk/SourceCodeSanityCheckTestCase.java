/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.util.StaticUtils;



/**
 * This class provides a number of test cases to perform various sanity testing
 * on the LDAP SDK source code.  Even though checkstyle should be able to do
 * this, it doesn't seem to work properly and these checks are easy enough to
 * do in a unit test.
 */
public final class SourceCodeSanityCheckTestCase
       extends LDAPSDKTestCase
{
  /**
   * A string representation of the current year.
   */
  private static final String YEAR =
       new SimpleDateFormat("yyyy").format(new Date());



  /**
   * Invokes a set of tests that should be performed for all main source files.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="mainSourceFiles")
  public void testMainSourceFile(final File f)
         throws Exception
  {
    final List<String> fileLines = getFileLines(f);
    final ArrayList<String> errorMessages = new ArrayList<String>(10);

    ensureStartsWithCopyrightHeader(f, fileLines, errorMessages);
    ensureNoTrailingWhitespace(f, fileLines, errorMessages);
    ensureNoTabs(f, fileLines, errorMessages);

    failIfNecessary(f, errorMessages);
  }



  /**
   * Invokes a set of tests that should be performed for the unit test source
   * files.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="unitTestSourceFiles")
  public void testUnitTestSourceFile(final File f)
         throws Exception
  {
    final List<String> fileLines = getFileLines(f);
    final ArrayList<String> errorMessages = new ArrayList<String>(10);

    ensureStartsWithCopyrightHeader(f, fileLines, errorMessages);
    ensureNoTrailingWhitespace(f, fileLines, errorMessages);
    ensureNoTabs(f, fileLines, errorMessages);

    failIfNecessary(f, errorMessages);
  }



  /**
   * Invokes a set of tests that should be performed for the build source files.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="buildSourceFiles")
  public void testBuildSourceFile(final File f)
         throws Exception
  {
    final List<String> fileLines = getFileLines(f);
    final ArrayList<String> errorMessages = new ArrayList<String>(10);

    ensureStartsWithCopyrightHeader(f, fileLines, errorMessages);
    ensureNoTrailingWhitespace(f, fileLines, errorMessages);
    ensureNoTabs(f, fileLines, errorMessages);

    failIfNecessary(f, errorMessages);
  }



  /**
   * Invokes a set of tests that should be performed for the Android LDAP client
   * source files.
   *
   * @param  f  The source file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="androidLDAPClientSourceFiles")
  public void testAndroidLDAPClientSourceFile(final File f)
         throws Exception
  {
    final List<String> fileLines = getFileLines(f);
    final ArrayList<String> errorMessages = new ArrayList<String>(10);

    ensureStartsWithCopyrightHeader(f, fileLines, errorMessages);
    ensureNoTrailingWhitespace(f, fileLines, errorMessages);
    ensureNoTabs(f, fileLines, errorMessages);

    failIfNecessary(f, errorMessages);
  }



  /**
   * Retrieves a list of the lines that comprise the specified source file.
   *
   * @param  f  The file for which to retrieve the lines.
   *
   * @return  A list of the lines that comprise the specified source file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static List<String> getFileLines(final File f)
          throws Exception
  {
    final ArrayList<String> lines = new ArrayList<String>(100);

    final BufferedReader reader = new BufferedReader(new FileReader(f));

    try
    {
      while (true)
      {
        final String line = reader.readLine();
        if (line == null)
        {
          break;
        }

        lines.add(line);
      }
    }
    finally
    {
      reader.close();
    }

    return lines;
  }



  /**
   * Ensure that the specified file starts with the copyright header.
   *
   * @param  f              The file being processed.
   * @param  fileLines      The lines that make up the file.
   * @param  errorMessages  A list to which any error messages should be added.
   */
  private static void ensureStartsWithCopyrightHeader(final File f,
                           final List<String> fileLines,
                           final List<String> errorMessages)
  {
     ensureHasHeaderLine(f, fileLines, errorMessages, 0, "/*");
     ensureHasHeaderLine(f, fileLines, errorMessages, 1, " * Copyright ",
          YEAR + " Ping Identity Corporation");
     ensureHasHeaderLine(f, fileLines, errorMessages, 2,
          " * All Rights Reserved.");
     ensureHasHeaderLine(f, fileLines, errorMessages, 3, " */");

     ensureHasHeaderLine(f, fileLines, errorMessages, 4, "/*");
     ensureHasHeaderLine(f, fileLines, errorMessages, 5, " * Copyright ",
          YEAR + " Ping Identity Corporation");
     ensureHasHeaderLine(f, fileLines, errorMessages, 6, " *");
     ensureHasHeaderLine(f, fileLines, errorMessages, 7, " * Licensed under " +
          "the Apache License, Version 2.0 (the \"License\");");
     ensureHasHeaderLine(f, fileLines, errorMessages, 8, " * you may not use " +
          "this file except in compliance with the License.");
     ensureHasHeaderLine(f, fileLines, errorMessages, 9,
          " * You may obtain a copy of the License at");
     ensureHasHeaderLine(f, fileLines, errorMessages, 10, " *");
     ensureHasHeaderLine(f, fileLines, errorMessages, 11, " *    " +
          "http://www.apache.org/licenses/LICENSE-2.0");
     ensureHasHeaderLine(f, fileLines, errorMessages, 12, " *");
     ensureHasHeaderLine(f, fileLines, errorMessages, 13, " * Unless " +
          "required by applicable law or agreed to in writing, software");
     ensureHasHeaderLine(f, fileLines, errorMessages, 14, " * distributed " +
          "under the License is distributed on an \"AS IS\" BASIS,");
     ensureHasHeaderLine(f, fileLines, errorMessages, 15, " * WITHOUT " +
          "WARRANTIES OR CONDITIONS OF ANY KIND, either express or " +
          "implied.");
     ensureHasHeaderLine(f, fileLines, errorMessages, 16,
          " * See the License for the specific language governing " +
               "permissions and");
     ensureHasHeaderLine(f, fileLines, errorMessages, 17, " * limitations " +
          "under the License.");
     ensureHasHeaderLine(f, fileLines, errorMessages, 18, " */");
     ensureHasHeaderLine(f, fileLines, errorMessages, 19, "/*");
     ensureHasHeaderLine(f, fileLines, errorMessages, 20, " * Copyright (C) ",
          YEAR + " Ping Identity Corporation");
     ensureHasHeaderLine(f, fileLines, errorMessages, 21, " *");
     ensureHasHeaderLine(f, fileLines, errorMessages, 22,
          " * This program is free software; you can redistribute it " +
               "and/or modify");
     ensureHasHeaderLine(f, fileLines, errorMessages, 23,
          " * it under the terms of the GNU General Public License " +
               "(GPLv2 only)");
     ensureHasHeaderLine(f, fileLines, errorMessages, 24,
          " * or the terms of the GNU Lesser General Public License " +
               "(LGPLv2.1 only)");
     ensureHasHeaderLine(f, fileLines, errorMessages, 25,
          " * as published by the Free Software Foundation.");
     ensureHasHeaderLine(f, fileLines, errorMessages, 26, " *");
     ensureHasHeaderLine(f, fileLines, errorMessages, 27,
          " * This program is distributed in the hope that it will be " +
               "useful,");
     ensureHasHeaderLine(f, fileLines, errorMessages, 28,
          " * but WITHOUT ANY WARRANTY; without even the implied " +
               "warranty of");
     ensureHasHeaderLine(f, fileLines, errorMessages, 29,
          " * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See " +
               "the");
     ensureHasHeaderLine(f, fileLines, errorMessages, 30,
          " * GNU General Public License for more details.");
     ensureHasHeaderLine(f, fileLines, errorMessages, 31, " *");
     ensureHasHeaderLine(f, fileLines, errorMessages, 32,
          " * You should have received a copy of the GNU General Public " +
               "License");
     ensureHasHeaderLine(f, fileLines, errorMessages, 33,
          " * along with this program; if not, see " +
               "<http://www.gnu.org/licenses>.");
     ensureHasHeaderLine(f, fileLines, errorMessages, 34, " */");

    final String pingCopyrightRange = extractCopyrightRange(fileLines.get(1));
    final String apacheCopyrightRange = extractCopyrightRange(fileLines.get(5));
    final String gplCopyrightRange = extractCopyrightRange(fileLines.get(20));

    if (! pingCopyrightRange.equals(apacheCopyrightRange))
    {
      errorMessages.add(f.getAbsolutePath() +
           " Ping Identity copyright header has a year range of " +
           pingCopyrightRange + ", which does not match the year range of " +
           apacheCopyrightRange + " in the Apache copyright header.");
    }
    else if (! pingCopyrightRange.equals(gplCopyrightRange))
    {
      errorMessages.add(f.getAbsolutePath() +
           " Ping Identity copyright header has a year range of " +
           pingCopyrightRange + ", which does not match the year range of " +
           gplCopyrightRange + " in the GPL copyright header.");
    }
  }



  /**
   * Ensures that the specified file has the given header line.
   *
   * @param  f                The file being processed.
   * @param  fileLines        The lines that make up the source file.
   * @param  errorMessages    The list to which error messages will be added.
   * @param  lineNumber       The line number to check.
   * @param  expectedContent  The expected content for the line.  This array
   *                          must have either one or two strings.  If it
   *                          contains one string, then the line must exactly
   *                          match that string.  If it contains two strings,
   *                          then the line must start with the first string
   *                          and end with the last.  No check will be made for
   *                          what comes between those strings.
   */
  private static void ensureHasHeaderLine(final File f,
                                          final List<String> fileLines,
                                          final List<String> errorMessages,
                                          final int lineNumber,
                                          final String... expectedContent)
  {
    final String line = fileLines.get(lineNumber);
    if (expectedContent.length == 1)
    {
      if (! line.equals(expectedContent[0]))
      {
        errorMessages.add(f.getAbsolutePath() + " line " + (lineNumber + 1) +
             " was expected to be '" + expectedContent[0] + "' but was '" +
             line + '\'');
      }
    }
    else
    {
      if (! line.startsWith(expectedContent[0]))
      {
        errorMessages.add(f.getAbsolutePath() + " line " + (lineNumber + 1) +
             " was expected to start with " + expectedContent[0] +
             "' but was '" + line + '\'');
      }

      if (! line.endsWith(expectedContent[1]))
      {
        errorMessages.add(f.getAbsolutePath() + " line " + (lineNumber + 1) +
             " was expected to emd with " + expectedContent[1] +
             "' but was '" + line + '\'');
      }
    }
  }


  /**
   * Extract the copyright year range from the specified line from a source
   * file's license header.
   *
   * @param  s  The line from which to extract the copyright year.
   *
   * @return  The extracted copyright year range.
   */
  private static String extractCopyrightRange(final String s)
  {
    final int rangeStartPos;
    if (s.startsWith(" * Copyright (C) "))
    {
      rangeStartPos = 17;
    }
    else
    {
      rangeStartPos = 13;
    }

    final int rangeEndPos = s.indexOf(" Ping Identity Corporation");
    return s.substring(rangeStartPos, rangeEndPos);
  }



  /**
   * Ensure that the specified file does not contain any lines that end with
   * whitespace.
   *
   * @param  f              The file being processed.
   * @param  fileLines      The lines that make up the file.
   * @param  errorMessages  A list to which any error messages should be added.
   */
  private static void ensureNoTrailingWhitespace(final File f,
                           final List<String> fileLines,
                           final List<String> errorMessages)
  {
    int lineNumber=1;
    for (final String line : fileLines)
    {
      if (line.endsWith(" "))
      {
        errorMessages.add("Trailing space found on line " + lineNumber);
      }

      lineNumber++;
    }
  }



  /**
   * Ensure that the specified file does not contain any tabs.
   *
   * @param  f              The file being processed.
   * @param  fileLines      The lines that make up the file.
   * @param  errorMessages  A list to which any error messages should be added.
   */
  private static void ensureNoTabs(final File f, final List<String> fileLines,
                                   final List<String> errorMessages)
  {
    int lineNumber=1;
    for (final String line : fileLines)
    {
      if (line.indexOf('\t') >= 0)
      {
        errorMessages.add("Tab found on line " + lineNumber);
      }

      lineNumber++;
    }
  }



  /**
   * Throws an assertion error if the provided list of error messages is not
   * empty.
   *
   * @param  f              The file with which the error messages are
   *                        associated.
   * @param  errorMessages  A list of error messages generated by tests.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void failIfNecessary(final File f,
                                      final List<String> errorMessages)
          throws Exception
  {
    if (! errorMessages.isEmpty())
    {
      final StringBuilder buffer = new StringBuilder();
      buffer.append("One or more errors were found in source file ");
      buffer.append(f.getAbsolutePath());
      buffer.append(StaticUtils.EOL);
      for (final String msg : errorMessages)
      {
        buffer.append("- ");
        buffer.append(msg);
        buffer.append(StaticUtils.EOL);
      }
      buffer.append(StaticUtils.EOL);
      throw new AssertionError(buffer.toString());
    }
  }



  /**
   * Retrieves the Java source files that make up the main source code.
   *
   * @return  The Java source files that make up the main source code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="mainSourceFiles")
  public Iterator<Object[]> getMainSourceFiles()
         throws Exception
  {
    return getSourceFiles("src");
  }



  /**
   * Retrieves the Java source files that make up the LDAP SDK unit tests.
   *
   * @return  The Java source files that make up the LDAP SDK unit tests.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="unitTestSourceFiles")
  public Iterator<Object[]> getUnitTestSourceFiles()
         throws Exception
  {
    return getSourceFiles("tests", "unit", "src");
  }



  /**
   * Retrieves the Java source files for code used in the build process.
   *
   * @return  The Java source files for code used in the build process.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="buildSourceFiles")
  public Iterator<Object[]> getBuildSourceFiles()
         throws Exception
  {
    return getSourceFiles("build-src");
  }



  /**
   * Retrieves the Java source files that make up the Android LDAP client.
   *
   * @return  The Java source files that make up the Android LDaP client.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="androidLDAPClientSourceFiles")
  public Iterator<Object[]> getAndroidLDAPClientSourceFiles()
         throws Exception
  {
    return getSourceFiles("android-ldap-client", "src");
  }



  /**
   * Retrieves the Java source files that exist in the specified location
   * beneath the LDAP SDK base directory.
   *
   * @param  pathElements  The names of the directories that comprise the target
   *                       path.  The
   *
   * @return  The Java source files that exist in the specified location beneath
   *          the LDAP SDK base directory.
   */
  private static Iterator<Object[]> getSourceFiles(final String... pathElements)
  {
    File dir = new File(System.getProperty("basedir"));
    for (final String subdir : pathElements)
    {
      dir = new File(dir, subdir);
    }

    final ArrayList<Object[]> sourceFiles = new ArrayList<Object[]>(100);
    getSourceFiles(dir, sourceFiles);
    return sourceFiles.iterator();
  }



  /**
   * Recursively identifies all Java source files anywhere beneath the specified
   * directory.
   *
   * @param  dir       The directory to process.
   * @param  fileList  A list to which the source files will be added.
   */
  private static void getSourceFiles(final File dir,
                                     final List<Object[]> fileList)
  {
    if (dir == null)
    {
      return;
    }

    for (final File f : dir.listFiles())
    {
      if (f.isDirectory())
      {
        getSourceFiles(f, fileList);
      }
      else if (f.getName().endsWith(".java"))
      {
        fileList.add(new Object[] { f });
      }
    }
  }
}
