/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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
import java.util.ArrayList;
import java.util.List;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases that can help ensure that source
 * code javadoc examples are properly formatted.
 */
public final class JavadocFormattingTestCase
       extends LDAPSDKTestCase
{
  /**
   * Ensure that there are no source files with javadoc comments that contain
   * inappropriate angle brackets aren't used for HTML tags and therefore need
   * to be escaped.
   *
   * @param  sourceFile  The source file to be examined.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceFiles")
  public void testAngleBrackets(final File sourceFile)
         throws Exception
  {
    final BufferedReader reader =
         new BufferedReader(new FileReader(sourceFile));

    try
    {
      int lineNumber = 0;
      boolean inJavadoc = false;
      while (true)
      {
        final String line = reader.readLine();
        if (line == null)
        {
          return;
        }

        lineNumber++;
        if (line.trim().startsWith("/**"))
        {
          inJavadoc = true;
        }
        else if (line.trim().endsWith("*/"))
        {
          inJavadoc = false;
        }
        else if (inJavadoc)
        {
          final int openPos = line.indexOf('<');
          if (openPos >= 0)
          {
            // It's possible that the tag isn't closed on the same line on
            // which it's opened, but we'll assume the text of the tag is
            // always on the same line.
            final int closePos;
            final int closeBracketPos = line.indexOf('>', (openPos+1));
            if (closeBracketPos < 0)
            {
              final int spacePos = line.indexOf(' ', (openPos+1));
              if (spacePos < 0)
              {
                closePos = line.length();
              }
              else
              {
                closePos = spacePos;
              }
            }
            else
            {
              final int spacePos = line.indexOf(' ', (openPos+1));
              if ((spacePos > 0) && (spacePos < closeBracketPos))
              {
                closePos = spacePos;
              }
              else
              {
                closePos = closeBracketPos;
              }
            }

            final String lowerLine = line.toLowerCase();
            final String tagText =
                 lowerLine.substring(openPos+1, closePos).trim();
            if (tagText.startsWith("/"))
            {
              // This probably indicates that it's closing a tag on a previous
              // line.  We'll ignore this.
              continue;
            }
            else if (tagText.endsWith("/"))
            {
              // This probably indicates that it's shorthand for an open and
              // close tag all in one, like "<br/>".  We'll ignore this.
              continue;
            }

            if (lowerLine.indexOf("@param") >= 0)
            {
              // This probably references a generic parameter, like
              // @param  <T>  The type of whatever thing we're talking about.
              continue;
            }

            // Certain tags will always be allowed.
            if (tagText.equals("a") ||
                tagText.equals("b") ||
                tagText.equals("blockquote") ||
                tagText.equals("br") ||
                tagText.equals("center") ||
                tagText.equals("h1") ||
                tagText.equals("h2") ||
                tagText.equals("i") ||
                tagText.equals("li") ||
                tagText.equals("ol") ||
                tagText.equals("p") ||
                tagText.equals("pre") ||
                tagText.equals("table") ||
                tagText.equals("td") ||
                tagText.equals("th") ||
                tagText.equals("tr") ||
                tagText.equals("ul"))
            {
              continue;
            }

            final String closeTag = "</" + tagText + '>';
            assertTrue((lowerLine.indexOf(closeTag, closeBracketPos+1) > 0),
                 "Unexpected '<" + tagText + ">' found on line " + lineNumber +
                 " of source file '" + sourceFile.getAbsolutePath() +
                 "'.  If this is a valid HTML tag, then the " +
                 "testAngleBrackets test case should be updated to reflect " +
                 "that.  Otherwise, the angle brackets should probably be " +
                 "replaced with '&lt;' and '&gt;'.");
          }
          else
          {
            final int closePos = line.indexOf('>');
            if (closePos >= 0)
            {
              // This may indicate a greater-than sign that should be escaped,
              // but there are known exceptions (in which the angle bracket
              // closing a tag isn't on the same line as the angle bracket that
              // opens it).  If this isn't one of those known exceptions, them
              // fail.
              final String filename = sourceFile.getName();
              if (filename.equals("LDAPConnection.java") &&
                   (lineNumber == 136))
              {
                // This is a known exception.
              }
              else if (filename.equals("ResultCode.java") &&
                   (lineNumber == 64))
              {
                // This is a known exception.
              }
              else if (filename.equals("package-info.java") &&
                   ((lineNumber == 27) || (lineNumber == 43)))
              {
                // This is a known exception.
              }
              else
              {
                fail("Close angle bracket found without a corresponding open " +
                     "bracket on line " + lineNumber + " of file '" +
                     sourceFile.getAbsolutePath() + "'.  This should be " +
                     "escaped with '&gt;'.");
              }
            }
          }
        }
      }
    }
    finally
    {
      reader.close();
    }
  }



  /**
   * Ensures that all source files that are part of the Commercial Edition
   * include a note indicating that it is part of the Commercial Edition and
   * is not available in the Standard Edition and not supported for use in
   * conjunction with non-UnboundID servers.
   *
   * @param  sourceFile  The source file to be examined.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "sourceFiles")
  public void testCommercialEditionHeader(final File sourceFile)
         throws Exception
  {
    final String path = sourceFile.getAbsolutePath().replace('\\', '/');
    if (! path.contains("com/unboundid/ldap/sdk/unboundidds"))
    {
      return;
    }

    final String[] lines;
    if (path.contains("package-info.java"))
    {
      lines = new String[]
      {
        " * <BLOCKQUOTE>",
        " *   <B>NOTE:</B>  The classes within this package, and elsewhere " +
             "within the",
        " *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, " +
             "are only",
        " *   supported for use against Ping Identity, UnboundID, and",
        " *   Nokia/Alcatel-Lucent 8661 server products.  These classes " +
             "provide support",
        " *   for proprietary functionality or for external specifications " +
             "that are not",
        " *   considered stable or mature enough to be guaranteed to work in " +
             "an",
        " *   interoperable way with other types of LDAP servers.",
        " * </BLOCKQUOTE>"
      };
    }
    else
    {
      lines = new String[]
      {
        " * <BLOCKQUOTE>",
        " *   <B>NOTE:</B>  This class, and other classes within the",
        " *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, " +
             "are only",
        " *   supported for use against Ping Identity, UnboundID, and",
        " *   Nokia/Alcatel-Lucent 8661 server products.  These classes " +
             "provide support",
        " *   for proprietary functionality or for external specifications " +
             "that are not",
        " *   considered stable or mature enough to be guaranteed to work in " +
             "an",
        " *   interoperable way with other types of LDAP servers.",
        " * </BLOCKQUOTE>"
      };
    }

    final boolean[] foundLines = new boolean[lines.length];

    final BufferedReader reader =
         new BufferedReader(new FileReader(sourceFile));

    try
    {
      int lineNumber = 0;
      boolean inJavadoc = false;
      while (true)
      {
        final String line = reader.readLine();
        if (line == null)
        {
          break;
        }

        lineNumber++;
        if (line.trim().startsWith("/**"))
        {
          inJavadoc = true;
        }
        else if (line.trim().endsWith("*/"))
        {
          inJavadoc = false;
        }
        else if (inJavadoc)
        {
          for (int i=0; i < lines.length; i++)
          {
            if (line.equals(lines[i]))
            {
              foundLines[i] = true;
              break;
            }
          }
        }
      }
    }
    finally
    {
      reader.close();
    }

    final StringBuilder errorBuffer = new StringBuilder();
    errorBuffer.append("Missing the following Commercial Edition header " +
         "line(s) in file ");
    errorBuffer.append(sourceFile.getAbsolutePath());
    errorBuffer.append('\'');
    errorBuffer.append(StaticUtils.EOL);

    boolean reportError = false;
    for (int i=0; i < lines.length; i++)
    {
      if (! foundLines[i])
      {
        errorBuffer.append(lines[i]);
        errorBuffer.append(StaticUtils.EOL);
        reportError = true;
      }
    }

    if (reportError)
    {
      fail(errorBuffer.toString());
    }
  }



  /**
   * Retrieves an array with information about all LDAP SDK source files that
   * should be examined.
   *
   * @return  An array with information about all LDAP SDK source files that
   *          should be examined.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="sourceFiles")
  public Object[][] getSourceFiles()
         throws Exception
  {
    final File baseDir = new File(System.getProperty("basedir"));
    final File srcDir = new File(baseDir, "src");
    assertTrue(srcDir.exists());

    final ArrayList<File> sourceFileList = new ArrayList<File>(100);
    findSourceFiles(srcDir, sourceFileList);

    final Object[][] fileArray = new Object[sourceFileList.size()][1];
    for (int i=0; i < fileArray.length; i++)
    {
      fileArray[i][0] = sourceFileList.get(i);
    }

    return fileArray;
  }



  /**
   * Finds all source files at or below the specified directory.
   *
   * @param  dir       The directory to be processed.
   * @param  fileList  The list to which source files should be added.
   */
  private void findSourceFiles(final File dir, final List<File> fileList)
  {
    for (final File f : dir.listFiles())
    {
      if (f.isDirectory())
      {
        findSourceFiles(f, fileList);
      }
      else if (f.getName().endsWith(".java"))
      {
        fileList.add(f);
      }
    }
  }
}
