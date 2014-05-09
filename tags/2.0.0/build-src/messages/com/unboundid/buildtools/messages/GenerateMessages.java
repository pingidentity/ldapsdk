/*
 * Copyright 2008-2010 UnboundID Corp.
 * All Rights Reserved.
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
    for (File propertiesFile : propertiesDir.listFiles())
    {
      String propertiesFileName = propertiesFile.getName();
      if (! propertiesFile.getName().endsWith(".properties"))
      {
        // It's not a properties file, so skip it.
        continue;
      }

      String baseFileName = propertiesFileName.substring(0,
                                 propertiesFileName.lastIndexOf(".properties"));

      try
      {
        FileInputStream inputStream = new FileInputStream(propertiesFile);

        Properties p = new Properties();
        p.load(inputStream);
        inputStream.close();


        // The properties file must contain a property that defines the
        // fully-qualified class name.  Read it and derive the corresponding
        // source file path.  Make the parent directory if necessary, and open
        // the source file for writing.
        String className = p.getProperty(CLASS_NAME_PROPERTY);
        if ((className == null) || (className.length() == 0))
        {
          throw new BuildException("Properties file " +
                                   propertiesFile.getName() +
                                   " does not include a value for the " +
                                   CLASS_NAME_PROPERTY + " property.");
        }

        String baseName = className.substring(className.lastIndexOf('.') + 1);
        String packageName = className.substring(0, className.lastIndexOf('.'));
        String sourcePath = generatedSourceDir.getAbsolutePath() +
                            File.separator +
                            className.replace('.', File.separatorChar) +
                            ".java";

        File sourceFile = new File(sourcePath);
        File sourceDir  = sourceFile.getParentFile();
        if (! sourceDir.exists())
        {
          sourceDir.mkdirs();
        }

        writer = new PrintWriter(new FileWriter(sourceFile));


        // Add the header to the source file.
        String year = new SimpleDateFormat("yyyy").format(new Date());
        w("/*");
        w(" * Copyright ", year, " UnboundID Corp.");
        w(" * All Rights Reserved.");
        w(" */");
        w("/*");
        w(" * Copyright (C) ", year, " UnboundID Corp.");
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
        TreeSet<Object> nameSet = new TreeSet<Object>();
        nameSet.addAll(p.keySet());
        nameSet.remove(CLASS_NAME_PROPERTY);

        Iterator<?> propertyNames = nameSet.iterator();
        while (propertyNames.hasNext())
        {
          String propertyName = String.valueOf(propertyNames.next());
          String message      = p.getProperty(propertyName);

          if (message.contains("%s"))
          {
            throw new BuildException("The message string for property " +
                 propertyName + " in file " + propertiesFileName +
                 " appears to contain %s instead of a positional indicator " +
                 "like {0}.");
          }
          else if (message.contains("%d"))
          {
            throw new BuildException("The message string for property " +
                 propertyName + " in file " + propertiesFileName +
                 " appears to contain %d instead of a positional indicator " +
                 "like {0}.");
          }

          int pos = message.indexOf("'{");
          while (pos >= 0)
          {
            int closePos = message.indexOf('}', pos);
            if (closePos > 0)
            {
              int value;
              try
              {
                value = Integer.parseInt(message.substring(pos+2, closePos));
                if ((pos == 0) || (message.charAt(pos-1) != '\''))
                {
                  throw new BuildException("The message string for property " +
                       propertyName + " in file " + propertiesFileName +
                       " appears to contain '{" + value +
                       "}' rather than ''{" + value + "}''.  This will cause " +
                       "the raw string {" + value + "} to appear in the " +
                       "message rather than the expected replacement value.");
                }
              }
              catch (NumberFormatException nfe)
              {
                // This is acceptable.
              }
            }

            pos = message.indexOf("'{", pos+1);
          }

          w("  /**");
          w("   * ", message);
          w("   */");

          String quotedMessage = message.replace("\"", "\\\"");
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
        w("    } catch (Exception e) {}");
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
          ",String> MESSAGE_STRINGS = new ConcurrentHashMap<", baseName,
          ",String>();");
        w();
        w();
        w();
        w("  /**");
        w("   * The map that will be used to hold the message format objects, ",
          "indexed by property name.");
        w("   */");
        w("  private static final ConcurrentHashMap<", baseName,
          ",MessageFormat> MESSAGES = new ConcurrentHashMap<", baseName,
          ",MessageFormat>();");


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
        w("   * This method should only be used for messages which do not ",
          "take any arguments.");
        w("   *");
        w("   * @return  A localized version of the message.");
        w("   */");
        w("  public String get()");
        w("  {");
        w("    String s = MESSAGE_STRINGS.get(this);");
        w("    if (s == null)");
        w("    {");
        w("      if (RESOURCE_BUNDLE == null)");
        w("      {");
        w("        return defaultText;");
        w("      }");
        w("      else");
        w("      {");
        w("        s = RESOURCE_BUNDLE.getString(name());");
        w("        MESSAGE_STRINGS.putIfAbsent(this, s);");
        w("      }");
        w("    }");
        w("    return s;");
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
        w("        f = new MessageFormat(RESOURCE_BUNDLE.getString(name()));");
        w("      }");
        w("      MESSAGES.putIfAbsent(this, f);");
        w("    }");
        w("    synchronized (f)");
        w("    {");
        w("      return f.format(args);");
        w("    }");
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
        w("    return get();");
        w("  }");


        // Add the footer to the source file and close the print writer.
        w("}");
        w();
        writer.close();
      }
      catch (BuildException be)
      {
        throw be;
      }
      catch (Exception e)
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
  private void w(Object... args)
  {
    for (Object o : args)
    {
      writer.print(String.valueOf(o));
    }
    writer.println();
  }
}
