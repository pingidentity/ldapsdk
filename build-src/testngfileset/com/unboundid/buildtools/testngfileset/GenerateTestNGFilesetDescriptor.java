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
package com.unboundid.buildtools.testngfileset;



import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.LinkedHashSet;
import java.util.StringTokenizer;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;



/**
 * This class provides an Ant task that can be used to generate a TestNG XML
 * file that indicates which tests to invoke.
 */
public class GenerateTestNGFilesetDescriptor
       extends Task
{
  // The path to the file that will be written with the TestNG.
  private File file;



  /**
   * Creates a new instance of this task.
   */
  public GenerateTestNGFilesetDescriptor()
  {
    file = null;
  }



  /**
   * Specifies the path of the file for which to generate the digest.
   *
   * @param  file  The path of the file for which to generate the digest.
   */
  public void setFile(final File file)
  {
    this.file = file;
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
    // Make sure that the configuration property was set correctly.
    if (file == null)
    {
      throw new BuildException("Unable to generate the TestNG fileset " +
           "descriptor because no value specified for the file property.");
    }

    if (file.exists())
    {
      if (! file.isFile())
      {
        throw new BuildException("Unable to generate the TestNG fileset " +
             "descriptor because the path specified in the file property " +
             "exists but is not a file.");
      }
    }
    else
    {
      final File parentDir = file.getAbsoluteFile().getParentFile();
      if (parentDir.exists())
      {
        if (! parentDir.isDirectory())
        {
          throw new BuildException("Unable to generate the TestNG fileset " +
               "descriptor because parent directory '" +
               parentDir.getAbsolutePath() +
               "' exists but is not a directory.");
        }
      }
      else
      {
        throw new BuildException("Unable to generate the TestNG fileset " +
             "descriptor because parent directory '" +
             parentDir.getAbsolutePath() + "' does not exist.");
      }
    }


    // If the test.packages property is set, then get the target packages.
    final LinkedHashSet<String> testPackages = new LinkedHashSet<>(10);
    final String testPackagesProperty =
         getProject().getProperty("test.packages");
    if (testPackagesProperty != null)
    {
      final StringTokenizer tokenizer =
           new StringTokenizer(testPackagesProperty, ",");
      while (tokenizer.hasMoreTokens())
      {
        testPackages.add(tokenizer.nextToken().trim());
      }
    }


    // If the test.classes property is set, then get the target classes.
    final LinkedHashSet<String> testClasses = new LinkedHashSet<>(10);
    final String testClassesProperty = getProject().getProperty("test.classes");
    if (testClassesProperty != null)
    {
      final StringTokenizer tokenizer =
           new StringTokenizer(testClassesProperty, ",");
      while (tokenizer.hasMoreTokens())
      {
        testClasses.add(tokenizer.nextToken().trim());
      }
    }


    // Generate the descriptor file header.
    try (PrintWriter writer = new PrintWriter(new FileWriter(file)))
    {
      writer.println(
           "<!DOCTYPE suite SYSTEM \"http://testng.org/testng-1.0.dtd\" >");
      writer.println();
      writer.println(
           "<suite name=\"UnboundID LDAP SDK for Java\" verbose=\"1\">");
      writer.println("  <test name=\"default\">");

      if (testPackages.isEmpty() && testClasses.isEmpty())
      {
        writer.println("    <packages>");
        writer.println("      <package name=\"com.unboundid.*\" />");
        writer.println("    </packages>");
      }
      else
      {
        if (! testPackages.isEmpty())
        {
          writer.println("    <packages>");
          for (final String packageName : testPackages)
          {
            writer.println("      <package name=\"" + packageName + ".*\" />");
          }

          writer.println("    </packages>");
        }

        if (! testClasses.isEmpty())
        {
          writer.println("    <classes>");
          for (final String className : testClasses)
          {
            writer.println("      <class name=\"" + className + "\" />");
          }

          writer.println("    </classes>");
        }
      }

      writer.println("  </test>");
      writer.println("</suite>");
    }
    catch (final Exception e)
    {
      throw new BuildException(
           "An error occurred while trying to write the TestNG fileset " +
                "descriptor to file '" + file.getAbsolutePath() +
                "':  " + e,
           e);
    }
  }
}
