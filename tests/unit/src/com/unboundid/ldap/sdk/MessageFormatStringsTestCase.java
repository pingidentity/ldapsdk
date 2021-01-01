/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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



import java.io.File;
import java.io.FileInputStream;
import java.text.MessageFormat;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases to check for common mistakes made in
 * message format strings.
 */
public final class MessageFormatStringsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests to ensure that the specified properties file does not contain any
   * lines that are longer than 80 characters.
   *
   * @param  propertiesFile  The properties file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "propertiesFiles")
  public void testLineLength(final File propertiesFile)
         throws Exception
  {
    int lineNumber = 1;
    for (final String line : StaticUtils.readFileLines(propertiesFile))
    {
      if (line.length() > 80)
      {
        fail("Message properties file '" + propertiesFile.getName() +
             "' line " + lineNumber + " is longer than 80 characters:  " +
             line);
      }

      lineNumber++;
    }
  }



  /**
   * Tests to ensure that the specified properties file does not contain any
   * lines that end with a trailing space.
   *
   * @param  propertiesFile  The properties file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "propertiesFiles")
  public void testTrailingSpaces(final File propertiesFile)
         throws Exception
  {
    int lineNumber = 1;
    for (final String line : StaticUtils.readFileLines(propertiesFile))
    {
      if (line.endsWith(" "))
      {
        fail("Message properties file '" + propertiesFile.getName() +
             "' line " + lineNumber + " ends with a trailing space:  " + line);
      }

      lineNumber++;
    }
  }



  /**
   * Tests to ensure that the specified properties file does not contain any
   * lines that end with a backslash that is not preceded by a space, unless
   * that backslash follows an equal sign that follows a property name.
   *
   * @param  propertiesFile  The properties file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "propertiesFiles")
  public void testContinuationBackslash(final File propertiesFile)
         throws Exception
  {
    int lineNumber = 1;
    for (final String line : StaticUtils.readFileLines(propertiesFile))
    {
      if (line.endsWith("\\") &&
           (! (line.endsWith(" \\") || line.endsWith("=\\") ||
                line.endsWith("|\\"))))
      {
        fail("Message properties file '" + propertiesFile.getName() +
             "' line " + lineNumber + " ends with a trailing backslash that " +
             "is not preceded by space:  " + line);
      }

      lineNumber++;
    }
  }



  /**
   * Tests to ensure that property names are well-formed.
   *
   * @param  propertiesFile  The properties file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "propertiesFiles")
  public void testPropertyNameFormat(final File propertiesFile)
         throws Exception
  {
    int lineNumber = 1;
    for (final String line : StaticUtils.readFileLines(propertiesFile))
    {
      if (line.isEmpty() || line.startsWith(" ") || line.startsWith("#") ||
           line.startsWith("class.name="))
      {
        lineNumber++;
        continue;
      }

      final int equalPos = line.indexOf('=');
      assertTrue((equalPos > 0),
           "Message properties file '" + propertiesFile.getName() +
                " contains non-indented line " + lineNumber +
                " that does not contain an equal sign to separate the " +
                "property name from the value:  " + line);

      final String propertyName = line.substring(0, equalPos);
      assertFalse(propertyName.isEmpty(),
           "Message properties file '" + propertiesFile.getName() +
                " contains non-indented line " + lineNumber +
                " with an empty property name:  " + line);

      assertFalse(line.equals(propertyName + "="),
           "Message properties file '" + propertiesFile.getName() +
                " contains line " + lineNumber + " with property name " +
                propertyName + " that does not have a format string:  " + line);

      assertFalse((line.charAt(equalPos-1) == ' '),
           "Message properties file '" + propertiesFile.getName() +
                " contains non-indented line " + lineNumber +
                " that includes a space before the equal sign that separates " +
                "the property name from the format string:  " + line);

      assertFalse((line.charAt(equalPos+1) == ' '),
           "Message properties file '" + propertiesFile.getName() +
                " contains non-indented line " + lineNumber +
                " that includes a space after the equal sign that separates " +
                "the property name from the format string:  " + line);

      assertTrue(
           (propertyName.startsWith("ERR_") ||
                propertyName.startsWith("WARN_") ||
                propertyName.startsWith("WARN_") ||
                propertyName.startsWith("INFO_")),
           "Message properties file '" + propertiesFile.getName() +
                " contains line " + lineNumber + " with property name " +
                propertyName + " that does not start with ERR_, WARN_, or " +
                "INFO_:  " + line);

      assertFalse(propertyName.contains("__"),
           "Message properties file '" + propertiesFile.getName() +
                " contains line " + lineNumber + " with property name " +
                propertyName + " that has a double underscore:  " + line);

      for (final char c : propertyName.toCharArray())
      {
        assertTrue(
             (((c >= 'A') && (c <= 'Z')) ||
                  ((c >= '0') && (c <= '9')) ||
                  (c == '_')),
           "Message properties file '" + propertiesFile.getName() +
                " contains line " + lineNumber + " with property name " +
                propertyName + " that contains character '" + c +
                "' that is not an uppercase letter, digit, or underscore:  " +
                line);
      }

      lineNumber++;
    }
  }



  /**
   * Tests to ensure that any line that starts with a space starts with exactly
   * two spaces.
   *
   * @param  propertiesFile  The properties file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "propertiesFiles")
  public void testContinuationLinesStartWithTwoSpaces(final File propertiesFile)
         throws Exception
  {
    int lineNumber = 1;
    for (final String line : StaticUtils.readFileLines(propertiesFile))
    {
      if (line.startsWith(" "))
      {
        assertTrue(line.startsWith("  "),
             "Message properties file '" + propertiesFile.getName() +
                  " contains line " + lineNumber + " that starts wtih a " +
                  "space but does not start with two spaces:  " + line);
        assertFalse(line.startsWith("   "),
             "Message properties file '" + propertiesFile.getName() +
                  " contains line " + lineNumber + " that starts wtih a " +
                  "space but does not start with two spaces:  " + line);

      }

      lineNumber++;
    }
  }



  /**
   * Tests to ensure that format strings do not contain two consecutive spaces
   * unless they immediately follow a colon, period, question mark, or closing
   * curly brace.
   *
   * @param  propertiesFile  The properties file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "propertiesFiles")
  public void testMessageWithConsecutiveSpaces(final File propertiesFile)
         throws Exception
  {
    int lineNumber = 1;
    for (final String line : StaticUtils.readFileLines(propertiesFile))
    {
      if (line.isEmpty() || line.startsWith("#") ||
           line.startsWith("class.name="))
      {
        lineNumber++;
        continue;
      }

      assertFalse(line.contains("   "),
           "Message properties file '" + propertiesFile.getName() +
                " contains line " + lineNumber +
                " that has three consecutive spaces:  " + line);

      int doubleSpacePos = line.indexOf("  ",
           2); // Skip initial spaces on continuation lines.
      while (doubleSpacePos > 0)
      {
        final char previousCharacter = line.charAt(doubleSpacePos-1);
        assertTrue(
             ((previousCharacter == ':') || (previousCharacter == '.') ||
                  (previousCharacter == '?') || (previousCharacter == '}')),
             "Message properties file '" + propertiesFile.getName() +
                  " contains line " + lineNumber +
                  " that has consecutive spaces not following a colon, " +
                  "period, question mark, or closing curly brace:  " + line);

        doubleSpacePos = line.indexOf("  ", (doubleSpacePos+1));
      }

      lineNumber++;
    }
  }



  /**
   * Tests to ensure that format strings do not contain two consecutive periods.
   * Three consecutive periods will be acceptable.
   *
   * @param  propertiesFile  The properties file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "propertiesFiles")
  public void testMessageWithConsecutivePeriods(final File propertiesFile)
         throws Exception
  {
    int lineNumber = 1;
    for (final String line : StaticUtils.readFileLines(propertiesFile))
    {
      if (line.isEmpty() || line.startsWith("#") ||
           line.startsWith("class.name="))
      {
        lineNumber++;
        continue;
      }

      if (line.contains(".."))
      {
        assertTrue((line.contains("...") || line.contains(" .. ")),
           "Message properties file '" + propertiesFile.getName() +
                " contains line " + lineNumber +
                " that has two consecutive periods:  " + line);
      }

      assertFalse(line.contains("...."),
           "Message properties file '" + propertiesFile.getName() +
                " contains line " + lineNumber +
                " that has four or more consecutive periods:  " + line);

      lineNumber++;
    }
  }



  /**
   * Tests to ensure that format strings do not contain two consecutive
   * open curly braces or two consecutive close curly braces.
   *
   * @param  propertiesFile  The properties file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "propertiesFiles")
  public void testMessageWithConsecutiveBraces(final File propertiesFile)
         throws Exception
  {
    int lineNumber = 1;
    for (final String line : StaticUtils.readFileLines(propertiesFile))
    {
      if (line.isEmpty() || line.startsWith("#") ||
           line.startsWith("class.name="))
      {
        lineNumber++;
        continue;
      }

      assertFalse(line.contains("{{"),
           "Message properties file '" + propertiesFile.getName() +
                " contains line " + lineNumber +
                " that has consecutive open curly braces:  " + line);
      assertFalse(line.contains("}}"),
           "Message properties file '" + propertiesFile.getName() +
                " contains line " + lineNumber +
                " that has consecutive close curly braces:  " + line);

      lineNumber++;
    }
  }



  /**
   * Tests to ensure that format strings that contain replacements only use
   * consecutive ordering that start with zero.
   *
   * @param  propertiesFile  The properties file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "propertiesFiles")
  public void testPlaceholderOrdering(final File propertiesFile)
         throws Exception
  {
    final Properties properties = new Properties();
    try (FileInputStream inputStream = new FileInputStream(propertiesFile))
    {
      properties.load(inputStream);
    }

    for (final Map.Entry<Object,Object> e : properties.entrySet())
    {
      final String propertyName = (String) e.getKey();
      final String formatString = (String) e.getValue();

      int openBracePos = formatString.indexOf('{');
      Integer highestSeenReference = null;
      while (openBracePos >= 0)
      {
        final int closeBracePos = formatString.indexOf('}', openBracePos);
        assertTrue((closeBracePos > 0),
             "Message properties file '" + propertiesFile.getName() +
                  "' contains property " + propertyName  +
                  " with an opening curly brace but no corresponding close " +
                  "curly brace:  " + formatString);

        Integer referenceNumber = null;
        final String bracedContent =
             formatString.substring(openBracePos+1, closeBracePos);
        if (bracedContent.contains(",number,"))
        {
          assertTrue(bracedContent.endsWith(",number,0"),
               "Message properties file '" + propertiesFile.getName() +
                    "' contains property " + propertyName  +
                    " with braced content " + bracedContent +
                    " that contains ,number, but does not end with " +
                    " ,number,0:  " + formatString);

          final int commaPos = bracedContent.indexOf(',');
          referenceNumber = Integer.parseInt(
               bracedContent.substring(0, bracedContent.indexOf(',')));
        }
        else
        {
          try
          {
            referenceNumber = Integer.parseInt(bracedContent);
          }
          catch (final NumberFormatException nfe)
          {
            // This is fine.  It's just not a reference.  But make sure that
            // the opening curly brace is preceded by exactly one quote to
            // indicate that it's not a format string.
            assertTrue(
                 ((openBracePos > 0) &&
                      (formatString.charAt(openBracePos-1) == '\'')),
                 "Message properties file '" + propertiesFile.getName() +
                      "' contains property " + propertyName +
                      " with braced content '" + bracedContent +
                      "' that is not a reference and for which the open " +
                      "brace is not preceded by a single quote to indicate " +
                      "that the brace should be treated as a literal and " +
                      "not the start of a token:  " + formatString);
          }
        }

        if (referenceNumber != null)
        {
          if (highestSeenReference == null)
          {
            assertEquals(referenceNumber.intValue(), 0,
                 "Message properties file '" + propertiesFile.getName() +
                      "' contains property " + propertyName  +
                      " with braced content " + bracedContent +
                      " with reference number " + referenceNumber +
                      " that is the first reference but is also nonzero:  " +
                      formatString);

            highestSeenReference = referenceNumber;
          }
          else
          {
            assertTrue((referenceNumber >= 0),
                 "Message properties file '" + propertiesFile.getName() +
                      "' contains property " + propertyName  +
                      " with braced content " + bracedContent +
                      " with negative reference number " +
                      referenceNumber + ":  " + formatString);
            assertFalse((referenceNumber >  (highestSeenReference+1)),
                 "Message properties file '" + propertiesFile.getName() +
                      "' contains property " + propertyName  +
                      " with braced content " + bracedContent +
                      " with reference number " + referenceNumber +
                      " that is more than one higher than the previously " +
                      "highest seen reference number:  " + formatString);
            highestSeenReference =
                 Math.max(referenceNumber, highestSeenReference);
          }
        }

        openBracePos = formatString.indexOf('{', closeBracePos);
      }

      if (highestSeenReference != null)
      {
        assertTrue((highestSeenReference <= 10),
             "Message properties file '" + propertiesFile.getName() +
                  "' contains property " + propertyName +
                  " with more than ten references.  The code used to " +
                  "ensure that all references are properly replaced can't " +
                  "handle this:  " + formatString);
      }
    }
  }



  /**
   * Tests to ensure that formatted messages do not contain consecutive
   * quotation marks.
   *
   * @param  propertiesFile  The properties file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "propertiesFiles")
  public void testEnsureFormattedMessaagesDoNotHaveDoubleQuotes(
                   final File propertiesFile)
         throws Exception
  {
    final Properties properties = new Properties();
    try (FileInputStream inputStream = new FileInputStream(propertiesFile))
    {
      properties.load(inputStream);
    }

    for (final Map.Entry<Object,Object> e : properties.entrySet())
    {
      final String propertyName = (String) e.getKey();
      final String formatString = (String) e.getValue();

      int openBracePos = formatString.indexOf('{');
      Integer highestSeenReference = null;
      while (openBracePos >= 0)
      {
        final int closeBracePos = formatString.indexOf('}', openBracePos);

        Integer referenceNumber = null;
        final String bracedContent =
             formatString.substring(openBracePos+1, closeBracePos);
        if (bracedContent.contains(",number,"))
        {
          final int commaPos = bracedContent.indexOf(',');
          referenceNumber = Integer.parseInt(
               bracedContent.substring(0, bracedContent.indexOf(',')));
        }
        else
        {
          try
          {
            referenceNumber = Integer.parseInt(bracedContent);
          }
          catch (final NumberFormatException nfe)
          {
            // This is fine.  It's just not a reference.
          }
        }

        if (referenceNumber != null)
        {
          if (highestSeenReference == null)
          {
            highestSeenReference = referenceNumber;
          }
          else
          {
            highestSeenReference =
                 Math.max(referenceNumber, highestSeenReference);
          }
        }

        openBracePos = formatString.indexOf('{', closeBracePos);
      }

      final Object[] formatArgs;
      if (highestSeenReference == null)
      {
        formatArgs = new Object[0];
      }
      else
      {
        formatArgs = new Object[highestSeenReference + 1];
        for (int i=0; i <= highestSeenReference; i++)
        {
          formatArgs[i] = i;
        }
      }

      final String formattedMessage =
           MessageFormat.format(formatString, formatArgs);
      assertFalse(formattedMessage.contains("''"),
           "Message properties file '" + propertiesFile.getName() +
                "' contains property " + propertyName +
                " whose formatted message contains consecutive quotes:  " +
                formattedMessage);
    }
  }



  /**
   * Tests to ensure that format strings do not include double quote characters.
   *
   * Tests to ensure that single quotes are used properly.
   *
   * @param  propertiesFile  The properties file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "propertiesFiles")
  public void testDoubleQuoteUsage(final File propertiesFile)
         throws Exception
  {
    final Properties properties = new Properties();
    try (FileInputStream inputStream = new FileInputStream(propertiesFile))
    {
      properties.load(inputStream);
    }

    for (final Map.Entry<Object,Object> e : properties.entrySet())
    {
      final String propertyName = (String) e.getKey();
      final String formatString = (String) e.getValue();

      assertFalse(formatString.contains("\""),
           "Message properties file '" + propertiesFile.getName() +
                "' contains property " + propertyName +
                " whose format string contains a double quote character:  " +
                formatString);
    }
  }



  /**
   * Tests to ensure that single quotes are used properly.  Each single quote
   * should either be immediately followed by another single quote (which means
   * to include a single quote in the formatted message), or it should be
   * followed by an open or closed curly brace that is also followed by another
   * single quote.
   *
   * @param  propertiesFile  The properties file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "propertiesFiles")
  public void testSingleQuoteUsage(final File propertiesFile)
         throws Exception
  {
    final Properties properties = new Properties();
    try (FileInputStream inputStream = new FileInputStream(propertiesFile))
    {
      properties.load(inputStream);
    }

    for (final Map.Entry<Object,Object> e : properties.entrySet())
    {
      final String propertyName = (String) e.getKey();
      final String formatString = (String) e.getValue();

      int quotePos = formatString.indexOf('\'');
      while (quotePos >= 0)
      {
        assertTrue((quotePos < (formatString.length() - 1)),
             "Message properties file '" + propertiesFile.getName() +
                  "' contains property " + propertyName  +
                  " whose format string ends with a stray trailing single " +
                  "quote:  " + formatString);

        final int numToSkip;
        final char nextChar = formatString.charAt(quotePos + 1);
        if (nextChar == '\'')
        {
          // This is fine.  It's a single quote literal.
          numToSkip = 2;
        }
        else if ((nextChar == '{') || (nextChar == '}'))
        {
          // This is fine.  It's a curly brace literal, but the brace must be
          // immediately followed by another quote.
          assertTrue((formatString.charAt(quotePos + 2) == '\''),
               "Message properties file '" + propertiesFile.getName() +
                    "' contains property " + propertyName  +
                    " with a single quote in front of a curly brace that is " +
                    " whose format string ends with a stray trailing single " +
                    "quote:  " + formatString);
          numToSkip = 3;
        }
        else
        {
          numToSkip = 0;
          fail("Message properties file '" + propertiesFile.getName() +
               "' contains property " + propertyName  +
               " with a single quote that is not immediately followed by " +
               "either another single quote (to indicate that the formatted " +
               "message should include a literal single quote character) or " +
               "an open or close curly brace followed by another single " +
               "quote (to indicate that the formatted message should include " +
               "a literal curly brace):  " + formatString);
        }

        quotePos = formatString.indexOf('\'', quotePos + numToSkip);
      }
    }
  }



  /**
   * Tests to ensure that message format strings do not contain repeated words.
   *
   * @param  propertiesFile  The properties file to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "propertiesFiles")
  public void testRepeatedWords(final File propertiesFile)
         throws Exception
  {
    final Properties properties = new Properties();
    try (FileInputStream inputStream = new FileInputStream(propertiesFile))
    {
      properties.load(inputStream);
    }

    final StringBuilder currentWordBuffer = new StringBuilder();
    for (final Map.Entry<Object,Object> e : properties.entrySet())
    {
      final String propertyName = (String) e.getKey();
      if (propertyName.equals("class.name"))
      {
        continue;
      }

      final String formatString = (String) e.getValue();

      String lastWord = null;
      currentWordBuffer.setLength(0);
      for (final char c : formatString.toCharArray())
      {
        if (((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z')))
        {
          currentWordBuffer.append(c);
        }
        else if ((c == ' ') || (c == '.'))
        {
          if (currentWordBuffer.length() > 0)
          {
            final String currentWord = currentWordBuffer.toString();
            if (lastWord != null)
            {
              assertFalse(lastWord.equals(currentWord),
                   "Message properties file '" + propertiesFile.getName() +
                        "' contains property " + propertyName  +
                        " whose format string contains duplicate word '" +
                        currentWord + "':  " + formatString);
            }

            lastWord = currentWord;
            currentWordBuffer.setLength(0);
          }
        }
        else
        {
          lastWord = null;
          currentWordBuffer.setLength(0);
        }
      }
    }
  }



  /**
   * Retrieves the properties files that contain the message format strings.
   *
   * @return  The properties files that contain the message format strings.
   */
  @DataProvider(name="propertiesFiles")
  public Object[][] getPropertiesFiles()
  {
    final String baseDirPath = System.getProperty("basedir");
    assertNotNull(baseDirPath);

    final File baseDir = new File(baseDirPath);
    assertTrue(baseDir.exists() && baseDir.isDirectory());

    final File messageDir = new File(baseDir, "messages");
    assertTrue(messageDir.exists() && messageDir.isDirectory());

    final Map<String,Object[]> propertiesFileArrays = new TreeMap<>();
    for (final File f : messageDir.listFiles())
    {
      assertTrue(f.isFile());

      final String name = f.getName();
      assertTrue(name.startsWith("unboundid-ldapsdk-"));
      assertTrue(name.endsWith(".properties"));
      propertiesFileArrays.put(f.getName(), new Object[] { f });
    }

    final Object[][] returnArray = new Object[0][];
    return propertiesFileArrays.values().toArray(returnArray);
  }
}
