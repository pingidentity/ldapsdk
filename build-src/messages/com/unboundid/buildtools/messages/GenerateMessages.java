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
package com.unboundid.buildtools.messages;



import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.Properties;
import java.util.TreeSet;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;



/**
 * This class provides an Ant task that can be used to generate source code from
 * messages properties files.  For each properties file, it will generate an
 * enum whose elements are the property keys for the associated messages.
 */
public class GenerateMessages
       extends Task
{
  /**
   * The name of the property that specifies the fully-qualified name of the
   * class to create.
   */
  private static final String CLASS_NAME_PROPERTY = "class.name";



  // The path to the directory containing the properties files to be processed.
  private File propertiesDir;

  // The path to the base directory in which to place the generated source
  // files.
  private File generatedSourceDir;

  // The print writer that will be used to write the source file.
  private PrintWriter writer;



  /**
   * Creates a new instance of this task.
   */
  public GenerateMessages()
  {
    propertiesDir      = null;
    generatedSourceDir = null;
  }



  /**
   * Specifies the path to the directory containing the properties files.
   *
   * @param  propertiesDir  The path to the directory containing the properties
   *                        files.
   */
  public void setPropertiesDir(final File propertiesDir)
  {
    this.propertiesDir = propertiesDir;
  }



  /**
   * Specifies the path to the directory into which the generated source files
   * should be written.
   *
   * @param  generatedSourceDir  The path to the directory into which the
   *                             generated source files should be written.
   */
  public void setGeneratedSourceDir(final File generatedSourceDir)
  {
    this.generatedSourceDir = generatedSourceDir;
  }



  /**
   * Performs the appropriate processing for this Ant task.
   *
   * @throws  BuildException  If the configuration for this task is not
   *                          sufficient, or if a problem occurs during
   *                          processing.
   */
  @Override()
  public void execute()
         throws BuildException
  {
    // Make sure the configuration properties were set correctly.
    if (propertiesDir == null)
    {
      throw new BuildException("No value specified for the propertiesDir " +
                               "property.");
    }
    else if (! propertiesDir.exists())
    {
      throw new BuildException("The specified propertiesDir " +
                               propertiesDir.getAbsolutePath() +
                               " does not exist.");
    }

    if (generatedSourceDir == null)
    {
      throw new BuildException("No value specified for the " +
                               "generatedSourceDir property.");
    }
    else if (! generatedSourceDir.exists())
    {
      throw new BuildException("The specified generatedSourceDir " +
                               generatedSourceDir.getAbsolutePath() +
                               " does not exist.");
    }


    // Iterate through the properties files in the properties directory and
    // generate the appropriate source files for them.
    for (final File propertiesFile : propertiesDir.listFiles())
    {
      final String propertiesFileName = propertiesFile.getName();
      if (! propertiesFile.getName().endsWith(".properties"))
      {
        // It's not a properties file, so skip it.
        continue;
      }

      final String baseFileName = propertiesFileName.substring(0,
           propertiesFileName.lastIndexOf(".properties"));

      try
      {
        final FileInputStream inputStream = new FileInputStream(propertiesFile);

        final Properties p = new Properties();
        p.load(inputStream);
        inputStream.close();


        // The properties file must contain a property that defines the
        // fully-qualified class name.  Read it and derive the corresponding
        // source file path.  Make the parent directory if necessary, and open
        // the source file for writing.
        final String className = p.getProperty(CLASS_NAME_PROPERTY);
        if ((className == null) || (className.length() == 0))
        {
          throw new BuildException("Properties file " +
                                   propertiesFile.getName() +
                                   " does not include a value for the " +
                                   CLASS_NAME_PROPERTY + " property.");
        }

        final String baseName =
             className.substring(className.lastIndexOf('.') + 1);
        final String packageName =
             className.substring(0, className.lastIndexOf('.'));
        final String sourcePath = generatedSourceDir.getAbsolutePath() +
             File.separator + className.replace('.', File.separatorChar) +
             ".java";

        final File sourceFile = new File(sourcePath).getAbsoluteFile();
        final File sourceDir  = sourceFile.getParentFile();
        if (! sourceDir.exists())
        {
          sourceDir.mkdirs();
        }

        writer = new PrintWriter(new FileWriter(sourceFile));


        // Add the header to the source file.
        final String year = new SimpleDateFormat("yyyy").format(new Date());
        w("/*");
        w(" * Copyright ", year, " Ping Identity Corporation");
        w(" * All Rights Reserved.");
        w(" */");
        w("/*");
        w(" * Copyright 2020-2021 Ping Identity Corporation");
        w(" *");
        w(" * Licensed under the Apache License, Version 2.0 (the " +
             "\"License\");");
        w(" * you may not use this file except in compliance with the " +
             "License.");
        w(" * You may obtain a copy of the License at");
        w(" *");
        w(" *    http://www.apache.org/licenses/LICENSE-2.0");
        w(" *");
        w(" * Unless required by applicable law or agreed to in writing, " +
             "software");
        w(" * distributed under the License is distributed on an \"AS IS\" " +
             "BASIS,");
        w(" * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express " +
             "or implied.");
        w(" * See the License for the specific language governing " +
             "permissions and");
        w(" * limitations under the License.");
        w(" */");
        w("/*");
        w(" * Copyright (C) ", year, " Ping Identity Corporation");
        w(" *");
        w(" * This program is free software; you can redistribute it and/or " +
               "modify");
        w(" * it under the terms of the GNU General Public License (GPLv2 " +
               "only)");
        w(" * or the terms of the GNU Lesser General Public License " +
               "(LGPLv2.1 only)");
        w(" * as published by the Free Software Foundation.");
        w(" *");
        w(" * This program is distributed in the hope that it will be useful,");
        w(" * but WITHOUT ANY WARRANTY; without even the implied warranty of");
        w(" * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the");
        w(" * GNU General Public License for more details.");
        w(" *");
        w(" * You should have received a copy of the GNU General Public " +
               "License");
        w(" * along with this program; if not, see " +
               "<http://www.gnu.org/licenses>.");
        w(" */");
        w("package ", packageName, ";");
        w();
        w();
        w();
        w("import java.text.MessageFormat;");
        w("import java.util.ResourceBundle;");
        w("import java.util.concurrent.ConcurrentHashMap;");
        w();
        w();
        w();
        w("/**");
        w(" * This enum defines a set of message keys for messages in the");
        w(" * ", packageName, " package, which correspond to messages in the");
        w(" * ", propertiesFile.getName(), " properties file.");
        w(" * <BR><BR>");
        w(" * This source file was generated from the properties file.");
        w(" * Do not edit it directly.");
        w(" */");
        w("enum ", baseName);
        w("{");


        // Iterate through the properties and add them to the source file.
        final TreeSet<Object> nameSet = new TreeSet<>();
        nameSet.addAll(p.keySet());
        nameSet.remove(CLASS_NAME_PROPERTY);

        final Iterator<?> propertyNames = nameSet.iterator();
        while (propertyNames.hasNext())
        {
          final String propertyName = String.valueOf(propertyNames.next());
          final String formatString      = p.getProperty(propertyName);

          if (formatString.contains("%s"))
          {
            throw new BuildException("The format string for property " +
                 propertyName + " in file " + propertiesFileName +
                 " appears to contain %s instead of a positional indicator " +
                 "like {0}.");
          }
          else if (formatString.contains("%d"))
          {
            throw new BuildException("The format string for property " +
                 propertyName + " in file " + propertiesFileName +
                 " appears to contain %d instead of a positional indicator " +
                 "like {0}.");
          }


          // Validate the property name.
          if (! (propertyName.startsWith("ERR_") ||
               propertyName.startsWith("WARN_") ||
               propertyName.startsWith("INFO_")))
          {
            throw new BuildException("Properties file " + propertiesFileName +
                 " contains a property named '" + propertyName +
                 "' that does not start with one of ERR_, WARN_, or INFO_.  " +
                 "All property names must start with one of those prefixes.");
          }

          if (propertyName.contains("__"))
          {
            throw new BuildException("Properties file " + propertiesFileName +
                 " contains a property named '" + propertyName +
                 "' that has a double underscore.");
          }

          for (final char c : propertyName.toCharArray())
          {
            if (! (((c >= 'A') && (c <= 'Z')) ||
                 ((c >= '0') && (c <= '9')) ||
                 (c == '_')))
            {
              throw new BuildException("Properties file " + propertiesFileName +
                   " contains a property named '" + propertyName +
                   " that contains illegal character '" + c + "'.  Property " +
                   "names can only contain uppercase letters, digits, or " +
                   "underscores.");
            }
          }


          // Validate argument references in the format string.
          int pos = formatString.indexOf('{');
          while (pos >= 0)
          {
            if ((pos > 0) && (formatString.charAt(pos-1) == '\'') &&
                 (pos < (formatString.length()-2)) &&
                 (formatString.charAt(pos+1) == '\''))
            {
              pos = formatString.indexOf('{', pos+2);
              continue;
            }

            final int closePos = formatString.indexOf('}', pos);
            if (closePos > 0)
            {
              try
              {
                final int value;
                final int commaPos = formatString.indexOf(",number,0}", pos+1);
                if ((commaPos > 0) && (commaPos < closePos))
                {
                  value = Integer.parseInt(
                       formatString.substring(pos+1, commaPos));
                }
                else
                {
                  value = Integer.parseInt(formatString.substring(pos+1,
                       closePos));
                }

                for (int i=0; i < value; i++)
                {
                  if (! (formatString.contains("{" + i + '}') ||
                         formatString.contains("{" + i + ",number,0}")))
                  {
                    throw new BuildException("The format string for " +
                         "property " + propertyName + " in file " +
                         propertiesFileName + " appears to contain {" + value +
                         "} but not {" + i + "}.  The format string is " +
                         formatString);
                  }
                }
              }
              catch (final NumberFormatException nfe)
              {
                throw new BuildException("The format string for property " +
                     propertyName + " in file " + propertiesFileName +
                     " appears to contain " +
                     formatString.substring(pos, closePos+1) +
                     " with a non-numeric value within unquoted braces.  If " +
                     "you want to have curly braces containing static text " +
                     "(rather than a reference to a message parameter), " +
                     "place single quotes before and after each of the " +
                     "braces.  The format string is " + formatString);
              }
            }
            else
            {
              throw new BuildException("The format string for property " +
                   propertyName + " in file " + propertiesFileName +
                   " has an open curly brace without a corresponding " +
                   "close curly brace.  The format string is " + formatString);
            }

            pos = formatString.indexOf('{', pos+1);
          }


          // Validate single quote usage in the format string.
          pos = formatString.indexOf("'");
          while (pos >= 0)
          {
            if (pos == (formatString.length() - 1))
            {
              throw new BuildException("The format string for property " +
                   propertyName + " in file " + propertiesFileName +
                   " has a stray trailing single quote.  If you want the " +
                   "quote to be there, then use two consecutive single " +
                   "quote characters.  Otherwise, remove it.  The format " +
                   "string is " + formatString);
            }

            final int numToSkip;
            final char nextChar = formatString.charAt(pos+1);
            if (nextChar == '\'')
            {
              // This is fine.  It's a single quote literal.
              numToSkip = 2;
            }
            else if ((nextChar == '{') || (nextChar == '}'))
            {
              if (formatString.charAt(pos+2) != '\'')
              {
                throw new BuildException("The format string for property " +
                     propertyName + " in file " + propertiesFileName +
                     " has a curly brace that is preceded by a single quote " +
                     "but is not followed by one.  Curly braces that you " +
                     "want to actually appear in the formatted message must " +
                     "be enclosed in single quotes.  The format string is " +
                     formatString);
              }
              numToSkip = 3;
            }
            else
            {
              throw new BuildException("The format string for property " +
                   propertyName + " in file " + propertiesFileName +
                   " has a single quote that is not followed by another " +
                   "single quote or an open or close curly brace.  If you " +
                   "want a single quote to show up in the formatted messge, " +
                   "you need to use two consecutive quotes in the format " +
                   "string.  The format string is " + formatString);
            }

            pos = formatString.indexOf("'", (pos + numToSkip));
          }


          // Validate double quote usage in the format string.
          if (formatString.contains("\""))
          {
            throw new BuildException("The format string for property " +
                 propertyName + " in file " + propertiesFileName +
                 " contains a double quote character.  Message format " +
                 "strings should only include single quotes so that they can " +
                 "be enclosed in quoted strings with less hassle.  The " +
                 "format string is " + formatString);
          }


          // Check space usage in the format string.
          if (formatString.endsWith(" "))
          {
            throw new BuildException("The format string for property " +
                 propertyName + " in file " + propertiesFileName +
                 " contains one or more trailing spaces.  The format string " +
                 "is " + formatString);
          }

          if (formatString.contains("   "))
          {
            throw new BuildException("The format string for property " +
                 propertyName + " in file " + propertiesFileName +
                 " contains three or more consecutive spaces.  The format " +
                 "string is " + formatString);
          }

          pos = formatString.indexOf("  ");
          while (pos > 0)
          {
            final char previousCharacter = formatString.charAt(pos-1);
            if (! ((previousCharacter == ':') || (previousCharacter == '.') ||
               (previousCharacter == '?') || (previousCharacter == '}')))
            {
              throw new BuildException("The format string for property " +
                   propertyName + " in file " + propertiesFileName +
                   " contains consecutive spaces that do not immediately " +
                   "follow a colon, period, question mark, or closing curly " +
                   "brace.  The format string is " + formatString);
            }

            pos = formatString.indexOf("  ", (pos+1));
          }



          w("  /**");
          w("   * ", formatString);
          w("   */");

          final String quotedMessage = formatString.replace("\"", "\\\"");
          if (propertyNames.hasNext())
          {
            w("  ", propertyName, "(\"" + quotedMessage + "\"),");
          }
          else
          {
            w("  ", propertyName, "(\"" + quotedMessage + "\");");
          }
          w();
          w();
          w();
        }


        // Add a set of constants to the source file.
        w("  /**");
        w("   * Indicates whether the unit tests are currently running.");
        w("   */");
        w("  private static final boolean IS_WITHIN_UNIT_TESTS =");
        w("       Boolean.getBoolean(" +
             "\"com.unboundid.ldap.sdk.RunningUnitTests\") ||");
        w("       Boolean.getBoolean(" +
             "\"com.unboundid.directory.server.RunningUnitTests\");");
        w();
        w();
        w();
        w("  /**");
        w("   * A pre-allocated array of zero objects to use for messages");
        w("   * that do not require any arguments.");
        w("   */");
        w("  private static final Object[] NO_ARGS = new Object[0];");
        w();
        w();
        w();
        w("  /**");
        w("   * The resource bundle that will be used to load the properties ",
          "file.");
        w("   */");
        w("  private static final ResourceBundle RESOURCE_BUNDLE;");
        w("  static");
        w("  {");
        w("    ResourceBundle rb = null;");
        w("    try");
        w("    {");
        w("      rb = ResourceBundle.getBundle(\"", baseFileName, "\");");
        w("    } catch (final Exception e) {}");
        w("    RESOURCE_BUNDLE = rb;");
        w("  }");
        w();
        w();
        w();
        w("  /**");
        w("   * The map that will be used to hold the unformatted message ",
          "strings, indexed by property name.");
        w("   */");
        w("  private static final ConcurrentHashMap<", baseName,
          ",String> MESSAGE_STRINGS = new ConcurrentHashMap<>(100);");
        w();
        w();
        w();
        w("  /**");
        w("   * The map that will be used to hold the message format objects, ",
          "indexed by property name.");
        w("   */");
        w("  private static final ConcurrentHashMap<", baseName,
          ",MessageFormat> MESSAGES = new ConcurrentHashMap<>(100);");


        // Add a variable to hold the default text.
        w();
        w();
        w();
        w("  // The default text for this message");
        w("  private final String defaultText;");


        // Add the constructor for the enum.
        w();
        w();
        w();
        w("  /**");
        w("   * Creates a new message key.");
        w("   */");
        w("  private ", baseName, "(final String defaultText)");
        w("  {");
        w("    this.defaultText = defaultText;");
        w("  }");


        // Add a method that may be used to get the message string without any
        // arguments.
        w();
        w();
        w();
        w("  /**");
        w("   * Retrieves a localized version of the message.");
        w("   * This method should only be used for messages that do not ",
          "take any");
        w("   * arguments.");
        w("   *");
        w("   * @return  A localized version of the message.");
        w("   */");
        w("  public String get()");
        w("  {");
       w("    MessageFormat f = MESSAGES.get(this);");
        w("    if (f == null)");
        w("    {");
        w("      if (RESOURCE_BUNDLE == null)");
        w("      {");
        w("        f = new MessageFormat(defaultText);");
        w("      }");
        w("      else");
        w("      {");
        w("        try");
        w("        {");
        w("          f = new MessageFormat(RESOURCE_BUNDLE.getString(" +
             "name()));");
        w("        }");
        w("        catch (final Exception e)");
        w("        {");
        w("          f = new MessageFormat(defaultText);");
        w("        }");
        w("      }");
        w("      MESSAGES.putIfAbsent(this, f);");
        w("    }");
        w();
        w("    final String formattedMessage;");
        w("    synchronized (f)");
        w("    {");
        w("      formattedMessage = f.format(NO_ARGS);");
        w("    }");
        w();
        w("    if (IS_WITHIN_UNIT_TESTS)");
        w("    {");
        w("      if (formattedMessage.contains(\"{0}\") ||");
        w("          formattedMessage.contains(\"{0,number,0}\") ||");
        w("          formattedMessage.contains(\"{1}\") ||");
        w("          formattedMessage.contains(\"{1,number,0}\") ||");
        w("          formattedMessage.contains(\"{2}\") ||");
        w("          formattedMessage.contains(\"{2,number,0}\") ||");
        w("          formattedMessage.contains(\"{3}\") ||");
        w("          formattedMessage.contains(\"{3,number,0}\") ||");
        w("          formattedMessage.contains(\"{4}\") ||");
        w("          formattedMessage.contains(\"{4,number,0}\") ||");
        w("          formattedMessage.contains(\"{5}\") ||");
        w("          formattedMessage.contains(\"{5,number,0}\") ||");
        w("          formattedMessage.contains(\"{6}\") ||");
        w("          formattedMessage.contains(\"{6,number,0}\") ||");
        w("          formattedMessage.contains(\"{7}\") ||");
        w("          formattedMessage.contains(\"{7,number,0}\") ||");
        w("          formattedMessage.contains(\"{8}\") ||");
        w("          formattedMessage.contains(\"{8,number,0}\") ||");
        w("          formattedMessage.contains(\"{9}\") ||");
        w("          formattedMessage.contains(\"{9,number,0}\") ||");
        w("          formattedMessage.contains(\"{10}\") ||");
        w("          formattedMessage.contains(\"{10,number,0}\"))");
        w("      {");
        w("        throw new IllegalArgumentException(");
        w("             \"Message \" + getClass().getName() + '.' + name() +");
        w("                  \" contains an un-replaced token:  \" + " +
             "formattedMessage);");
        w("      }");
        w("    }");
        w();
        w("    return formattedMessage;");
         w("  }");


        // Add a method that may be used to get the message string formatted
        // with arguments.
        w();
        w();
        w();
        w("  /**");
        w("   * Retrieves a localized version of the message.");
        w("   *");
        w("   * @param  args  The arguments to use to format the message.");
        w("   *");
        w("   * @return  A localized version of the message.");
        w("   */");
        w("  public String get(final Object... args)");
        w("  {");
        w("    MessageFormat f = MESSAGES.get(this);");
        w("    if (f == null)");
        w("    {");
        w("      if (RESOURCE_BUNDLE == null)");
        w("      {");
        w("        f = new MessageFormat(defaultText);");
        w("      }");
        w("      else");
        w("      {");
        w("        try");
        w("        {");
        w("          f = new MessageFormat(RESOURCE_BUNDLE.getString(" +
             "name()));");
        w("        }");
        w("        catch (final Exception e)");
        w("        {");
        w("          f = new MessageFormat(defaultText);");
        w("        }");
        w("      }");
        w("      MESSAGES.putIfAbsent(this, f);");
        w("    }");
        w();
        w("    final String formattedMessage;");
        w("    synchronized (f)");
        w("    {");
        w("      formattedMessage = f.format(args);");
        w("    }");
        w();
        w("    if (IS_WITHIN_UNIT_TESTS)");
        w("    {");
        w("      if (formattedMessage.contains(\"{0}\") ||");
        w("          formattedMessage.contains(\"{0,number,0}\") ||");
        w("          formattedMessage.contains(\"{1}\") ||");
        w("          formattedMessage.contains(\"{1,number,0}\") ||");
        w("          formattedMessage.contains(\"{2}\") ||");
        w("          formattedMessage.contains(\"{2,number,0}\") ||");
        w("          formattedMessage.contains(\"{3}\") ||");
        w("          formattedMessage.contains(\"{3,number,0}\") ||");
        w("          formattedMessage.contains(\"{4}\") ||");
        w("          formattedMessage.contains(\"{4,number,0}\") ||");
        w("          formattedMessage.contains(\"{5}\") ||");
        w("          formattedMessage.contains(\"{5,number,0}\") ||");
        w("          formattedMessage.contains(\"{6}\") ||");
        w("          formattedMessage.contains(\"{6,number,0}\") ||");
        w("          formattedMessage.contains(\"{7}\") ||");
        w("          formattedMessage.contains(\"{7,number,0}\") ||");
        w("          formattedMessage.contains(\"{8}\") ||");
        w("          formattedMessage.contains(\"{8,number,0}\") ||");
        w("          formattedMessage.contains(\"{9}\") ||");
        w("          formattedMessage.contains(\"{9,number,0}\") ||");
        w("          formattedMessage.contains(\"{10}\") ||");
        w("          formattedMessage.contains(\"{10,number,0}\"))");
        w("      {");
        w("        throw new IllegalArgumentException(");
        w("             \"Message \" + getClass().getName() + '.' + name() +");
        w("                  \" contains an un-replaced token:  \" + " +
             "formattedMessage);");
        w("      }");
        w("    }");
        w();
        w("    return formattedMessage;");
        w("  }");


        // Add the toString() method.
        w();
        w();
        w();
        w("  /**");
        w("   * Retrieves a string representation of this message key.");
        w("   *");
        w("   * @return  A string representation of this message key.");
        w("   */");
        w("  @Override()");
        w("  public String toString()");
        w("  {");
        w("    String s = MESSAGE_STRINGS.get(this);");
        w("    if (s == null)");
        w("    {");
        w("      if (RESOURCE_BUNDLE == null)");
        w("      {");
        w("        s = defaultText;");
        w("      }");
        w("      else");
        w("      {");
        w("        try");
        w("        {");
        w("          s = RESOURCE_BUNDLE.getString(name());");
        w("        }");
        w("        catch (final Exception e)");
        w("        {");
        w("          s = defaultText;");
        w("        }");
        w("        MESSAGE_STRINGS.putIfAbsent(this, s);");
        w("      }");
        w("    }");
        w();
        w("    return s;");
        w("  }");


        // Add the footer to the source file and close the print writer.
        w("}");
        w();
        writer.close();
      }
      catch (final BuildException be)
      {
        throw be;
      }
      catch (final Exception e)
      {
        throw new BuildException("Error processing properties file " +
                                 propertiesFile.getName() + " -- " + e, e);
      }
    }
  }



  /**
   * Writes a line with the provided contents to the print writer.
   *
   * @param  args  The content to be written on the line.  String
   *               representations of each of the provided objects will be
   *               concatenated to form the line.
   */
  private void w(final Object... args)
  {
    for (final Object o : args)
    {
      writer.print(String.valueOf(o));
    }
    writer.println();
  }
}
